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
