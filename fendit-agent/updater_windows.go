//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/kardianos/service"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// wazuhUpdate runs an in-place Wazuh MSI upgrade.
// msiexec /i on an already-installed product upgrades it in-place;
// agent registration (client.keys) survives.
func wazuhUpdate(msiPath string) error {
	cmd := exec.Command("msiexec.exe", "/i", msiPath, "/qn", "/norestart")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 3010 {
			return ErrRestartRequired // upgrade succeeded; restart pending
		}
		return fmt.Errorf("msiexec: %w\n%s", err, out)
	}
	return nil
}

// selfUpdate stages the new binary as .pending beside the installed binary,
// spawns it in --update-swap mode as a detached process, then stops the
// Windows service so the swap process can replace the binary.
// This function does NOT return on success — the SCM stop terminates this process.
func selfUpdate(newBinPath string) error {
	pendingPath := agentBinDst + ".pending"

	if err := copyFile(newBinPath, pendingPath); err != nil {
		return fmt.Errorf("stage pending binary: %w", err)
	}
	if err := os.Chmod(pendingPath, 0755); err != nil {
		return fmt.Errorf("chmod pending: %w", err)
	}

	// Spawn the new binary in swap mode — it waits for the service to stop,
	// copies itself to the target, re-registers and restarts the service.
	cmd := exec.Command(pendingPath, "--update-swap", "--target", agentBinDst)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		os.Remove(pendingPath)
		return fmt.Errorf("spawn update-swap: %w", err)
	}
	logger.Info().Int("pid", cmd.Process.Pid).Msg("updater: swap process spawned — stopping service")

	// Stop our own service. The SCM terminates this process after Stop returns.
	stopSelf()
	return nil // not reached
}

// runUpdateSwap is called in --update-swap mode on the NEW binary (.pending).
// It waits for the old service to stop, copies the new binary into place,
// re-registers the Windows service, and starts it.
func runUpdateSwap(targetPath string) {
	logger.Info().Str("target", targetPath).Msg("update-swap: waiting for old service to stop")

	if !waitForServiceStopped("FenditAgent", 60*time.Second) {
		logger.Error().Msg("update-swap: timed out waiting for FenditAgent to stop")
		return
	}

	logger.Info().Msg("update-swap: service stopped — installing new binary")

	bakPath := targetPath + ".bak"
	os.Rename(targetPath, bakPath) //nolint:errcheck — benign if first install

	self, err := os.Executable()
	if err != nil {
		logger.Error().Err(err).Msg("update-swap: os.Executable failed")
		rollback(targetPath, bakPath)
		return
	}
	if err := copyFile(self, targetPath); err != nil {
		logger.Error().Err(err).Msg("update-swap: copy to target failed")
		rollback(targetPath, bakPath)
		return
	}

	svcConfig := &service.Config{
		Name:        "FenditAgent",
		DisplayName: "Fendit Security Agent",
		Description: "Fendit endpoint protection daemon",
		Executable:  targetPath,
	}
	p, err := service.New(&program{}, svcConfig)
	if err != nil {
		logger.Error().Err(err).Msg("update-swap: service.New failed")
		rollback(targetPath, bakPath)
		return
	}
	p.Uninstall() //nolint:errcheck — idempotent
	if err := p.Install(); err != nil {
		logger.Error().Err(err).Msg("update-swap: service install failed")
		rollback(targetPath, bakPath)
		return
	}
	p.Start() //nolint:errcheck

	// Remove the .pending binary (self). The service now runs from targetPath.
	os.Remove(self) //nolint:errcheck
	logger.Info().Msg("update-swap: agent updated and service restarted")
}

// stopSelf requests an SCM stop of the FenditAgent service.
func stopSelf() {
	m, err := mgr.Connect()
	if err != nil {
		return
	}
	defer m.Disconnect()
	s, err := m.OpenService("FenditAgent")
	if err != nil {
		return
	}
	defer s.Close()
	s.Control(svc.Stop) //nolint:errcheck
}

// waitForServiceStopped polls the SCM until FenditAgent reaches the Stopped state.
func waitForServiceStopped(svcName string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if serviceIsStopped(svcName) {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

func serviceIsStopped(svcName string) bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		return false
	}
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return false
	}
	return status.State == svc.Stopped
}

// rollback restores the .bak binary and attempts to restart the old service.
func rollback(targetPath, bakPath string) {
	if err := os.Rename(bakPath, targetPath); err != nil {
		logger.Error().Err(err).Msg("update-swap: rollback rename also failed — service is stuck")
		return
	}
	m, err := mgr.Connect()
	if err != nil {
		return
	}
	defer m.Disconnect()
	s, err := m.OpenService("FenditAgent")
	if err != nil {
		return
	}
	defer s.Close()
	s.Start() //nolint:errcheck
	logger.Info().Msg("update-swap: rolled back to previous binary")
}
