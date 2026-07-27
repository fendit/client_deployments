//go:build darwin

package main

import (
	"os/exec"
	"path/filepath"
	"strings"

	"os"
)

// isFilterEngineRunning checks whether the Wazuh agent daemon is active.
// Uses wazuh-control rather than pgrep so it works under launchd supervision.
func isFilterEngineRunning() bool {
	out, err := exec.Command("/Library/Ossec/bin/wazuh-control", "status").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "is running")
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
// Wazuh places an agent in its tenant group (e.g. etc/shared/vdpo_be/) rather than
// etc/shared/default/ when registered with -G.  We scan all group subdirectories so
// this works regardless of which group the agent is assigned to.
func yaraRulesUpdatedAt() string {
	const base = "/Library/Ossec/etc/shared"
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

// wazuhVersion reads the installed Wazuh version on macOS.
// Parses the VERSION file that Wazuh installs under /Library/Ossec.
func wazuhVersion() string {
	// Primary: Wazuh ships a VERSION file with just the version string.
	if b, err := os.ReadFile("/Library/Ossec/etc/version.txt"); err == nil {
		return strings.TrimSpace(string(b))
	}
	// Fallback: ask wazuh-control — slower but reliable.
	out, err := exec.Command("/Library/Ossec/bin/wazuh-control", "info", "-v").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
