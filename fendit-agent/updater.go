package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ErrRestartRequired is returned by wazuhUpdate when msiexec exits with code 3010
// (success, but a system restart is required to complete the upgrade).
var ErrRestartRequired = errors.New("restart required")

const updateDownloadTimeout = 20 * time.Minute

// downloadAndVerify fetches url into a temp file, verifies sha256 (skipped when
// expectedHash is ""), and returns the temp path. The caller must remove it.
func downloadAndVerify(url, expectedHash string) (string, error) {
	client := &http.Client{Timeout: updateDownloadTimeout}
	resp, err := client.Get(url) //nolint:gosec — URL comes from Guardian manifest, operator-controlled
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download: http %d", resp.StatusCode)
	}

	f, err := os.CreateTemp("", "fendit-update-*")
	if err != nil {
		return "", fmt.Errorf("temp file: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("write temp: %w", err)
	}

	if expectedHash != "" {
		got := hex.EncodeToString(h.Sum(nil))
		if !strings.EqualFold(got, expectedHash) {
			os.Remove(f.Name())
			return "", fmt.Errorf("sha256 mismatch: expected %s got %s", expectedHash, got)
		}
	}
	return f.Name(), nil
}

// applyPendingUpdate is the top-level update orchestrator called by the daemon
// scheduler goroutine. It updates the on-disk status so the tray reflects progress.
//
// For "fendit_agent" updates, selfUpdate() spawns the swap process and terminates
// the current daemon — it does not return.
func applyPendingUpdate(state *UpdateState) {
	setUpdateStatus("downloading", "")

	for _, comp := range state.Components {
		switch comp {
		case "wazuh":
			if state.WazuhURL == "" {
				setUpdateStatus("failed", "wazuh_url missing in update state")
				return
			}
			logger.Info().Str("url", state.WazuhURL).Msg("updater: downloading Wazuh update")
			tmp, err := downloadAndVerifySHA512(state.WazuhURL, state.WazuhChecksumURL, updateDownloadTimeout)
			if err != nil {
				logger.Error().Err(err).Msg("updater: Wazuh download failed")
				setUpdateStatus("failed", "wazuh download: "+err.Error())
				return
			}
			setUpdateStatus("installing", "")
			if err := wazuhUpdate(tmp); err != nil {
				os.Remove(tmp)
				if errors.Is(err, ErrRestartRequired) {
					// msiexec 3010 — upgrade succeeded; OS restart needed.
					logger.Info().Msg("updater: Wazuh updated — restart required within 48h")
					clearUpdateState()
					writeRestartDeadline()
					return
				}
				logger.Error().Err(err).Msg("updater: Wazuh install failed")
				setUpdateStatus("failed", "wazuh install: "+err.Error())
				return
			}
			os.Remove(tmp)
			logger.Info().Msg("updater: Wazuh updated successfully")

		case "fendit_agent":
			if state.AgentURL == "" {
				setUpdateStatus("failed", "agent_url missing in update state")
				return
			}
			logger.Info().Str("url", state.AgentURL).Msg("updater: downloading agent update")
			tmp, err := downloadAndVerify(state.AgentURL, state.AgentSHA256)
			if err != nil {
				logger.Error().Err(err).Msg("updater: agent download failed")
				setUpdateStatus("failed", "agent download: "+err.Error())
				return
			}
			// selfUpdate does not return on success — the process is replaced by the swap.
			if err := selfUpdate(tmp); err != nil {
				os.Remove(tmp)
				logger.Error().Err(err).Msg("updater: agent self-update failed")
				setUpdateStatus("failed", "agent install: "+err.Error())
				return
			}
		}
	}

	clearUpdateState()
	logger.Info().Msg("updater: all components updated successfully")
}

// setUpdateStatus patches Status and ErrorMsg in the on-disk state file.
// Only ever called from the single scheduler goroutine — no lock needed.
func setUpdateStatus(status, errMsg string) {
	s, err := readUpdateState()
	if err != nil || s == nil {
		return
	}
	s.Status = status
	s.ErrorMsg = errMsg
	_ = writeUpdateState(s)
}
