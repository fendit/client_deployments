//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"syscall"
)

// addDefenderExclusions configures Windows Defender to trust all Fendit and
// Wazuh paths before any files are downloaded or written to disk.
// Always non-fatal — logs result and returns.
func addDefenderExclusions() {
	fmt.Println("[*] Configuring Defender exclusions...")

	script := "" +
		"$ErrorActionPreference = 'SilentlyContinue'\n" +
		"foreach ($p in @('C:\\ProgramData\\Fendit','C:\\Program Files\\Fendit','C:\\Program Files (x86)\\ossec-agent','C:\\Users\\Public\\Documents\\Backup')) { Add-MpPreference -ExclusionPath $p }\n" +
		"foreach ($p in @('fendit-agent.exe','wazuh-agent.exe','ossec.exe','yr.exe')) { Add-MpPreference -ExclusionProcess $p }\n" +
		"Add-MpPreference -ControlledFolderAccessAllowedApplications 'C:\\Program Files\\Fendit\\fendit-agent.exe'\n" +
		"foreach ($p in @('C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe','C:\\Program Files (x86)\\ossec-agent\\ossec.exe')) { Add-MpPreference -AttackSurfaceReductionOnlyExclusions $p }\n" +
		"if (-not (Get-NetFirewallRule -DisplayName 'Fendit Wazuh Agent' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName 'Fendit Wazuh Agent' -Direction Outbound -Program 'C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe' -Action Allow -Profile Any | Out-Null }\n"

	cmd := exec.Command(
		"powershell.exe",
		"-NonInteractive", "-NoProfile",
		"-ExecutionPolicy", "Bypass",
		"-Command", script,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[!] Defender exclusions partial/failed (non-fatal): %v\n%s\n", err, out)
	} else {
		fmt.Println("[*] Defender exclusions configured.")
	}
}

// removeDefenderExclusions reverses addDefenderExclusions. Called on uninstall
// to restore Defender's full coverage after Fendit is removed.
func removeDefenderExclusions() {
	fmt.Println("[*] Removing Defender exclusions...")

	script := "" +
		"$ErrorActionPreference = 'SilentlyContinue'\n" +
		"foreach ($p in @('C:\\ProgramData\\Fendit','C:\\Program Files\\Fendit','C:\\Program Files (x86)\\ossec-agent','C:\\Users\\Public\\Documents\\Backup')) { Remove-MpPreference -ExclusionPath $p }\n" +
		"foreach ($p in @('fendit-agent.exe','wazuh-agent.exe','ossec.exe','yr.exe')) { Remove-MpPreference -ExclusionProcess $p }\n" +
		"Remove-MpPreference -ControlledFolderAccessAllowedApplications 'C:\\Program Files\\Fendit\\fendit-agent.exe'\n" +
		"foreach ($p in @('C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe','C:\\Program Files (x86)\\ossec-agent\\ossec.exe')) { Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $p }\n" +
		"Remove-NetFirewallRule -DisplayName 'Fendit Wazuh Agent' -ErrorAction SilentlyContinue\n"

	cmd := exec.Command(
		"powershell.exe",
		"-NonInteractive", "-NoProfile",
		"-ExecutionPolicy", "Bypass",
		"-Command", script,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.CombinedOutput() //nolint:errcheck — best-effort on uninstall
	fmt.Println("[*] Defender exclusions removed.")
}
