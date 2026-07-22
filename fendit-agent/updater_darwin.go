//go:build darwin

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	agentPlistPath = "/Library/LaunchDaemons/eu.fendit.agent.plist"
	agentBinPending = agentBin + ".pending"
)

// wazuhUpdate runs an in-place Wazuh PKG upgrade.
// installer -pkg on an already-installed Wazuh package upgrades it;
// agent registration (client.keys) survives.
func wazuhUpdate(pkgPath string) error {
	if err := os.Chmod(pkgPath, 0644); err != nil {
		return fmt.Errorf("chmod pkg: %w", err)
	}
	out, err := exec.Command("/usr/sbin/installer", "-pkg", pkgPath, "-target", "/").CombinedOutput()
	if err != nil {
		return fmt.Errorf("installer: %w\n%s", err, out)
	}
	return nil
}

// selfUpdate stages the new binary as .pending beside the installed binary,
// spawns it in --update-swap mode in a new session (Setsid) so it survives
// the launchd bootout that terminates this process.
// This function does NOT return on success.
func selfUpdate(newBinPath string) error {
	if err := copyFileDarwin(newBinPath, agentBinPending); err != nil {
		return fmt.Errorf("stage pending binary: %w", err)
	}
	if err := os.Chmod(agentBinPending, 0755); err != nil {
		os.Remove(agentBinPending)
		return fmt.Errorf("chmod pending: %w", err)
	}

	cmd := exec.Command(agentBinPending, "--update-swap", "--target", agentBin)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // new session — survives parent death
	if err := cmd.Start(); err != nil {
		os.Remove(agentBinPending)
		return fmt.Errorf("spawn update-swap: %w", err)
	}
	logger.Info().Int("pid", cmd.Process.Pid).Msg("updater: swap process spawned — stopping daemon")

	// Unloading the LaunchDaemon sends SIGTERM to this process and disables KeepAlive.
	// The swap process runs in its own session and is not affected.
	exec.Command("launchctl", "bootout", "system", agentPlistPath).Run() //nolint:errcheck
	return nil // not reached
}

// runUpdateSwap is called in --update-swap mode on the NEW binary (.pending).
// It waits for the old daemon to be unloaded, copies itself to the target path,
// and re-bootstraps the LaunchDaemon so the new version starts.
func runUpdateSwap(targetPath string) {
	logger.Info().Str("target", targetPath).Msg("update-swap: waiting for daemon to unload")

	if !waitForDaemonUnloaded(60 * time.Second) {
		logger.Error().Msg("update-swap: timed out waiting for eu.fendit.agent to unload")
		return
	}

	logger.Info().Msg("update-swap: daemon unloaded — installing new binary")

	self, err := os.Executable()
	if err != nil {
		logger.Error().Err(err).Msg("update-swap: os.Executable failed")
		return
	}

	bakPath := targetPath + ".bak"
	os.Rename(targetPath, bakPath) //nolint:errcheck

	if err := copyFileDarwin(self, targetPath); err != nil {
		logger.Error().Err(err).Msg("update-swap: copy to target failed — rolling back")
		os.Rename(bakPath, targetPath) //nolint:errcheck
		exec.Command("launchctl", "bootstrap", "system", agentPlistPath).Run() //nolint:errcheck
		return
	}
	os.Chmod(targetPath, 0755) //nolint:errcheck

	if out, err := exec.Command("launchctl", "bootstrap", "system", agentPlistPath).CombinedOutput(); err != nil {
		logger.Error().Err(err).Str("out", string(out)).Msg("update-swap: bootstrap failed")
	} else {
		logger.Info().Msg("update-swap: agent updated and daemon restarted")
	}

	os.Remove(self) //nolint:errcheck
}

// waitForDaemonUnloaded polls launchctl until eu.fendit.agent is no longer listed.
func waitForDaemonUnloaded(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("launchctl", "list", "eu.fendit.agent").CombinedOutput()
		if err != nil || strings.Contains(string(out), "Could not find service") {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

// copyFileDarwin copies src to dst, creating or overwriting dst.
// Named to avoid collision with copyFile in install_windows.go (different build tag).
func copyFileDarwin(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
