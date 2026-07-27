package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const (
	heartbeatInterval  = 5 * time.Minute
	heartbeatTimeout   = 10 * time.Second
	crashReportTimeout = 5 * time.Second
	yaraDownloadTimeout = 2 * time.Minute

	pathHeartbeat = "/api/v1/telemetry/heartbeat"
	pathCrash     = "/api/v1/telemetry/crash"
	pathYaraRules = "/api/control/v1/rules/yara"
)

// heartbeatPayload is the body of POST /api/v1/telemetry/heartbeat.
// Zero PII: agent_id is SHA-256(reflex_token) — no hostname, no username,
// no hardware serial number.
type heartbeatPayload struct {
	AgentID             string `json:"agent_id"`
	Version             string `json:"version"`
	WazuhVersion        string `json:"wazuh_version,omitempty"`
	OS                  string `json:"os"`
	Arch                string `json:"arch"`
	Status              string `json:"status"`
	FilterEngineRunning bool   `json:"filter_engine_running"`
	UptimeSeconds       int64  `json:"uptime_seconds"`
	LastScanStatus      string `json:"last_scan_status,omitempty"`
	RulesUpdatedAt      string `json:"rules_updated_at,omitempty"` // ISO8601 mtime of mcp_rules.yarc
}

// heartbeatResponse is the parsed body of a successful heartbeat POST.
// Guardian returns an update signal when the agent or Wazuh is out of date,
// and a YaraHash so the agent can skip the download when rules are current.
type heartbeatResponse struct {
	Status             string   `json:"status"`
	UpdateAvailable    bool     `json:"update_available"`
	YaraHash           string   `json:"yara_hash"`
	Components         []string `json:"components"`
	AgentVersionLatest string   `json:"agent_version_latest"`
	WazuhVersionLatest string   `json:"wazuh_version_latest"`
	AgentURL           string   `json:"agent_url"`
	AgentSHA256        string   `json:"agent_sha256"`
	WazuhURL           string   `json:"wazuh_url"`
	WazuhChecksumURL   string   `json:"wazuh_checksum_url"`
}

// crashPayload is the body of POST /api/v1/telemetry/crash.
type crashPayload struct {
	AgentID    string   `json:"agent_id"`
	Version    string   `json:"version"`
	OS         string   `json:"os"`
	StackTrace string   `json:"stack_trace"`
	LogTail    []string `json:"log_tail"`
	Timestamp  string   `json:"ts"`
}

// daemonCfg is stored once by startDaemon after loadConfig() succeeds.
// Only read (never written after init), so no mutex is needed.
// handlePanic and sendCrashReport read it during panic recovery.
var daemonCfg *Config

// agentStartTime is set once at daemon start for uptime calculation.
var agentStartTime time.Time

// runHeartbeat replaces runHealthPinger. It sends a structured POST every
// heartbeatInterval and delegates to the existing pending-queue on failure.
func runHeartbeat(ctx context.Context, cfg *Config) {
	agentID := deriveAgentID(cfg.ReflexToken)
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	// Send one immediately so the SOC sees the agent right after startup.
	sendOrQueueHeartbeat(cfg, agentID)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sendOrQueueHeartbeat(cfg, agentID)
		}
	}
}

func sendOrQueueHeartbeat(cfg *Config, agentID string) {
	if err := sendHeartbeat(cfg, agentID); err != nil {
		logger.Warn().Err(err).Msg("heartbeat POST failed — queuing to disk")
		queueHeartbeat(cfg, agentID)
	} else {
		logger.Debug().Msg("heartbeat delivered")
	}
}

func sendHeartbeat(cfg *Config, agentID string) error {
	p := buildHeartbeatPayload(agentID)
	body, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal heartbeat: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), heartbeatTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.endpoint(pathHeartbeat), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.ReflexToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Fendit-Agent/"+version)

	resp, err := agentHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return fmt.Errorf("server error %d", resp.StatusCode)
	}

	// Parse the heartbeat response. Any parse error is swallowed — a missed
	// update notification or YARA sync is not fatal.
	var hbResp heartbeatResponse
	if jsonErr := json.NewDecoder(resp.Body).Decode(&hbResp); jsonErr == nil {
		if hbResp.UpdateAvailable {
			applyUpdateSignal(&hbResp)
		}
		if hbResp.YaraHash != "" {
			go maybeUpdateYara(cfg, hbResp.YaraHash)
		}
	}

	return nil
}

// queueHeartbeat serialises the current payload into the pending-events
// directory so runPendingFlusher replays it once connectivity is restored.
func queueHeartbeat(cfg *Config, agentID string) {
	p := buildHeartbeatPayload(agentID)
	body, _ := json.Marshal(p)
	persistPendingEvent(string(body))
}

func buildHeartbeatPayload(agentID string) heartbeatPayload {
	return heartbeatPayload{
		AgentID:             agentID,
		Version:             version,
		WazuhVersion:        wazuhVersion(),
		OS:                  runtime.GOOS,
		Arch:                runtime.GOARCH,
		Status:              "active",
		FilterEngineRunning: isFilterEngineRunning(),
		UptimeSeconds:       int64(time.Since(agentStartTime).Seconds()),
		LastScanStatus:      lastScanStatus(),
		RulesUpdatedAt:      yaraRulesUpdatedAt(),
	}
}

// applyUpdateSignal writes an update_state.json when Guardian signals that
// one or more components are out of date. Skips if an update is already in
// progress (status not empty and not "failed").
func applyUpdateSignal(resp *heartbeatResponse) {
	existing, _ := readUpdateState()
	if existing != nil && existing.Pending &&
		existing.Status != "" && existing.Status != "failed" {
		return
	}
	state := &UpdateState{
		Pending:     true,
		Components:  resp.Components,
		AgentURL:    resp.AgentURL,
		AgentSHA256:      resp.AgentSHA256,
		WazuhURL:         resp.WazuhURL,
		WazuhChecksumURL: resp.WazuhChecksumURL,
		Status:      "pending",
	}
	if err := writeUpdateState(state); err != nil {
		logger.Warn().Err(err).Msg("heartbeat: failed to write update state")
	} else {
		logger.Info().Strs("components", resp.Components).Msg("heartbeat: update available — state written")
	}
}

// ── YARA rule sync ────────────────────────────────────────────────────────────

var yaraDownloadMu sync.Mutex

// maybeUpdateYara compares the server-reported SHA-256 of mcp_rules.yarc with
// the local copy and downloads a fresh ruleset only when they differ.
// Runs in a goroutine — never blocks the heartbeat response path.
func maybeUpdateYara(cfg *Config, serverHash string) {
	if localYaraHash() == serverHash {
		return
	}
	if !yaraDownloadMu.TryLock() {
		return // download already in progress from a concurrent heartbeat
	}
	defer yaraDownloadMu.Unlock()
	// Re-check after acquiring the lock in case a concurrent goroutine just finished.
	if localYaraHash() == serverHash {
		return
	}
	logger.Info().Str("hash", serverHash[:8]).Msg("yara: rules changed — downloading")
	if err := downloadYaraRules(cfg, serverHash); err != nil {
		logger.Warn().Err(err).Msg("yara: download failed")
	} else {
		logger.Info().Msg("yara: rules updated")
	}
}

// localYaraHash returns the SHA-256 hex of the local mcp_rules.yarc, or ""
// when the file does not exist yet.
func localYaraHash() string {
	data, err := os.ReadFile(yaraRulesLocalPath())
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// downloadYaraRules fetches the compiled ruleset from Guardian, verifies the
// SHA-256, and atomically replaces the local copy.
func downloadYaraRules(cfg *Config, expectedHash string) error {
	ctx, cancel := context.WithTimeout(context.Background(), yaraDownloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.endpoint(pathYaraRules), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.ReflexToken)
	req.Header.Set("User-Agent", "Fendit-Agent/"+version)

	resp, err := agentHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != expectedHash {
		return fmt.Errorf("hash mismatch: got %s want %s", got[:8], expectedHash[:8])
	}

	dst := yaraRulesLocalPath()
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp) //nolint:errcheck
		return fmt.Errorf("atomic rename: %w", err)
	}
	return nil
}

// sendCrashReport is called from handlePanic. It has a hard 5-second deadline
// because the process is about to exit — delivery is best-effort, not guaranteed.
func sendCrashReport(cfg *Config, stack []byte) {
	agentID := deriveAgentID(cfg.ReflexToken)
	p := crashPayload{
		AgentID:    agentID,
		Version:    version,
		OS:         runtime.GOOS,
		StackTrace: string(stack),
		LogTail:    readTailLines(50),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(p)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), crashReportTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.endpoint(pathCrash), bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+cfg.ReflexToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Fendit-Agent/"+version)

	resp, err := agentHTTPClient.Do(req)
	if err != nil {
		logger.Error().Err(err).Msg("last-gasp crash report failed to deliver")
		return
	}
	resp.Body.Close()
	logger.Info().Msg("last-gasp crash report delivered")
}

// deriveAgentID hashes the reflex token to produce a stable, privacy-safe ID.
// No hostname, username, or hardware serial number is included.
func deriveAgentID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
