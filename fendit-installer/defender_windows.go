//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// addDefenderExclusions configures Windows Defender to trust all Fendit and
// Wazuh paths before any files are downloaded or written to disk.
//
// Uses Add-MpPreference, which works with Tamper Protection enabled on
// non-Intune-managed devices (the SME self-install target).
// $ErrorActionPreference = 'SilentlyContinue' ensures individual cmdlet
// failures (managed policy, Defender service stopped) never abort the install.
func addDefenderExclusions() {
	// PowerShell script — no backtick line continuations so the script can live
	// in a Go raw string without escaping conflicts.
	script := "" +
		"$ErrorActionPreference = 'SilentlyContinue'\n" +
		// Path exclusions
		"foreach ($p in @('C:\\ProgramData\\Fendit','C:\\Program Files\\Fendit','C:\\Program Files (x86)\\ossec-agent','C:\\Users\\Public\\Documents\\Backup')) { Add-MpPreference -ExclusionPath $p }\n" +
		// Process exclusions
		"foreach ($p in @('fendit-agent.exe','wazuh-agent.exe','ossec.exe','yr.exe')) { Add-MpPreference -ExclusionProcess $p }\n" +
		// Controlled Folder Access — allows agent to write honeypot decoy files
		"Add-MpPreference -ControlledFolderAccessAllowedApplications 'C:\\Program Files\\Fendit\\fendit-agent.exe'\n" +
		// ASR exclusions — covers LSASS and process creation origin rules
		"foreach ($p in @('C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe','C:\\Program Files (x86)\\ossec-agent\\ossec.exe')) { Add-MpPreference -AttackSurfaceReductionOnlyExclusions $p }\n" +
		// Firewall rule for Wazuh manager (TCP 1514 enroll, 1515 events)
		"if (-not (Get-NetFirewallRule -DisplayName 'Fendit Wazuh Agent' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName 'Fendit Wazuh Agent' -Direction Outbound -Program 'C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe' -Action Allow -Profile Any | Out-Null }\n"

	cmd := exec.Command(
		"powershell.exe",
		"-NonInteractive", "-NoProfile",
		"-ExecutionPolicy", "Bypass",
		"-Command", script,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	log.Info("defender exclusions", "output", string(out), "err", err)
}
