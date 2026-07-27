//go:build windows

package main

import (
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

// addDefenderExclusions configures Windows Defender to trust all Fendit and
// Wazuh paths.  Two methods are tried in order so at least one succeeds on
// every Windows configuration:
//
//  1. Add-MpPreference via PowerShell — the official WMI-backed API.
//     Respects Tamper Protection and works on all modern Windows 10/11 SME
//     machines where Defender is the active AV.
//
//  2. Direct registry write — native Go, no process spawn.
//     Works when the WMI provider is unavailable (HRESULT 0x80041013):
//     Defender service stopped, broken VM state, or another AV replaced
//     Defender.  Blocked by Tamper Protection, but if TP is on the WMI
//     path above will have succeeded anyway.
func addDefenderExclusions() {
	wmiOK := addDefenderExclusionsWMI()
	if !wmiOK {
		log.Info("defender exclusions: WMI path failed — trying registry fallback")
		addDefenderExclusionsRegistry()
	}
}

func addDefenderExclusionsWMI() bool {
	script := "" +
		"$ErrorActionPreference = 'SilentlyContinue'\n" +
		"foreach ($p in @('C:\\ProgramData\\Fendit','C:\\Program Files\\Fendit','C:\\Program Files (x86)\\ossec-agent')) { Add-MpPreference -ExclusionPath $p }\n" +
		"foreach ($p in @('fendit-agent.exe','wazuh-agent.exe','ossec.exe','yr.exe')) { Add-MpPreference -ExclusionProcess $p }\n" +
		"Add-MpPreference -ControlledFolderAccessAllowedApplications 'C:\\Program Files\\Fendit\\fendit-agent.exe'\n" +
		"foreach ($p in @('C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe','C:\\Program Files (x86)\\ossec-agent\\ossec.exe')) { Add-MpPreference -AttackSurfaceReductionOnlyExclusions $p }\n" +
		"if (-not (Get-NetFirewallRule -DisplayName 'Fendit Wazuh Agent' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName 'Fendit Wazuh Agent' -Direction Outbound -Program 'C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe' -Action Allow -Profile Any | Out-Null }\n"

	cmd := exec.Command(
		"powershell.exe",
		"-NonInteractive", "-NoProfile", "-NoLogo",
		"-WindowStyle", "Hidden",
		"-ExecutionPolicy", "Bypass",
		"-Command", script,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	out, err := cmd.CombinedOutput()
	outStr := string(out)
	// WMI provider failure manifests in the output even when PowerShell exits 0.
	failed := err != nil || strings.Contains(outStr, "0x80041013") || strings.Contains(outStr, "Provider load failure")
	log.Info("defender exclusions WMI", "output", outStr, "err", err, "ok", !failed)
	return !failed
}

// addDefenderExclusionsRegistry writes exclusions directly to the Defender
// registry keys.  No WMI or PowerShell process needed.
// Note: blocked by Tamper Protection — callers should treat failure as silent.
func addDefenderExclusionsRegistry() {
	paths := []string{
		`C:\ProgramData\Fendit`,
		`C:\Program Files\Fendit`,
		`C:\Program Files (x86)\ossec-agent`,
	}
	processes := []string{
		"fendit-agent.exe",
		"wazuh-agent.exe",
		"ossec.exe",
		"yr.exe",
	}

	writeExclusions := func(subKey string, values []string) {
		k, err := registry.OpenKey(
			registry.LOCAL_MACHINE,
			`SOFTWARE\Microsoft\Windows Defender\Exclusions\`+subKey,
			registry.SET_VALUE,
		)
		if err != nil {
			log.Info("defender registry exclusion: cannot open key", "subkey", subKey, "err", err)
			return
		}
		defer k.Close()
		for _, v := range values {
			if err := k.SetDWordValue(v, 0); err != nil {
				log.Info("defender registry exclusion: set value failed", "value", v, "err", err)
			}
		}
	}

	writeExclusions("Paths", paths)
	writeExclusions("Processes", processes)
	log.Info("defender exclusions registry: done")
}
