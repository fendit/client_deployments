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

// yaraRulesUpdatedAt returns the mtime of mcp_rules.yarc as RFC3339, or "".
// Wazuh's remoted daemon writes this file whenever Guardian pushes updated rules,
// so its mtime is a reliable proxy for "when were detection rules last refreshed".
func yaraRulesUpdatedAt() string {
	const path = "/Library/Ossec/etc/shared/default/mcp_rules.yarc"
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return info.ModTime().UTC().Format("2006-01-02T15:04:05Z")
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
