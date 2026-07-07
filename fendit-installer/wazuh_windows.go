//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

const wazuhDisplayName = "Wazuh"

// uninstallPaths contains the two Windows Installer uninstall registry locations
// that together cover both 32-bit and 64-bit MSI packages.
var uninstallPaths = []string{
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
}

// findWazuhProductCode searches the Windows Installer uninstall registry for a
// Wazuh entry and returns its {GUID} product code. Uses the native registry API —
// no powershell.exe, no WMI, no Win32_Product query.
func findWazuhProductCode() (string, error) {
	for _, path := range uninstallPaths {
		if guid, err := searchUninstallPath(path); err == nil && guid != "" {
			return guid, nil
		}
	}
	return "", fmt.Errorf("Wazuh not found in Windows Installer registry")
}

func searchUninstallPath(regPath string) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, regPath, registry.READ)
	if err != nil {
		return "", err
	}
	defer k.Close()

	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return "", err
	}

	for _, sub := range subkeys {
		sk, err := registry.OpenKey(k, sub, registry.READ)
		if err != nil {
			continue
		}
		displayName, _, err := sk.GetStringValue("DisplayName")
		sk.Close()
		if err != nil {
			continue
		}
		if strings.Contains(displayName, wazuhDisplayName) {
			return sub, nil // sub is the {XXXXXXXX-XXXX-...} product code key name
		}
	}
	return "", nil
}

// isWazuhInstalled returns true when a Wazuh entry is found in the Windows
// Installer registry, which reliably reflects actual MSI installation state.
func isWazuhInstalled() bool {
	_, err := findWazuhProductCode()
	return err == nil
}

// uninstallWazuh stops the Wazuh service and removes the MSI package using
// msiexec.exe /x {GUID}. This avoids spawning powershell.exe or querying WMI,
// both of which are flagged by EDR behavioural heuristics.
func uninstallWazuh() error {
	guid, err := findWazuhProductCode()
	if err != nil {
		// Not installed — nothing to do.
		return nil
	}

	// Stop the service gracefully before uninstalling.
	stopCmd := exec.Command("sc.exe", "stop", "Wazuh")
	stopCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	stopCmd.Run() //nolint:errcheck
	time.Sleep(2 * time.Second)

	// msiexec /x uninstalls by product GUID, /qn is silent, /norestart prevents
	// an unwanted mid-install reboot prompt.
	uninstallCmd := exec.Command(
		"msiexec.exe",
		"/x", guid,
		"/qn",
		"/norestart",
	)
	uninstallCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := uninstallCmd.Run(); err != nil {
		return fmt.Errorf("msiexec uninstall (guid=%s): %w", guid, err)
	}
	return nil
}
