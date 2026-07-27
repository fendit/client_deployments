//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// isFilterEngineRunning queries the Windows Service Control Manager to check
// whether the Wazuh service is in the Running state. No shell process is spawned.
func isFilterEngineRunning() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()

	s, err := m.OpenService("Wazuh")
	if err != nil {
		return false
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return false
	}
	return status.State == svc.Running
}

// lastScanStatus reads the outcome of the most recent YARA/hash scan.
// Written by the scanner goroutine; returns "unknown" when no scan has run yet.
func lastScanStatus() string {
	b, err := os.ReadFile(filepath.Join(configDir(), "last_scan_status"))
	if err != nil || strings.TrimSpace(string(b)) == "" {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}

// yaraRulesUpdatedAt returns the mtime of the most recently updated mcp_rules.yar
// across all Wazuh shared group directories as RFC3339, or "".
//
// Wazuh places an agent in its tenant group (e.g. shared\vdpo_be\) rather than
// shared\default\ when registered with -G.  We scan all group subdirectories so
// this works regardless of which group the agent is assigned to.
func yaraRulesUpdatedAt() string {
	const base = `C:\Program Files (x86)\ossec-agent\shared`
	entries, err := os.ReadDir(base)
	if err != nil {
		return ""
	}
	var latest string // RFC3339 — lexicographically sortable
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := os.Stat(filepath.Join(base, e.Name(), "mcp_rules.yar"))
		if err != nil {
			continue
		}
		if t := info.ModTime().UTC().Format("2006-01-02T15:04:05Z"); t > latest {
			latest = t
		}
	}
	return latest
}

// wazuhVersion reads the installed Wazuh version from the Windows registry.
// Uses the native registry API — no shell process spawned.
func wazuhVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\WOW6432Node\ossec`, registry.QUERY_VALUE)
	if err != nil {
		// Try the non-WOW6432 path for 64-bit installs.
		k, err = registry.OpenKey(registry.LOCAL_MACHINE,
			`SOFTWARE\ossec`, registry.QUERY_VALUE)
		if err != nil {
			return ""
		}
	}
	defer k.Close()
	v, _, err := k.GetStringValue("Version")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}
