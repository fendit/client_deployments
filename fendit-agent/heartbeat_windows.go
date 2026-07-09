//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"

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
