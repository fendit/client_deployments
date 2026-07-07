//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
)

// isAdmin returns true when the process is running as root (UID 0).
func isAdmin() bool {
	return os.Getuid() == 0
}

// relaunchAsAdmin re-executes the current binary with administrator privileges
// via osascript, which presents the standard macOS credential dialog.
// The current (unprivileged) process exits immediately after spawning the
// elevated child so only one copy of the installer runs at a time.
func relaunchAsAdmin() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	// The executable path must be quoted in case it contains spaces.
	script := fmt.Sprintf(`do shell script "%s" with administrator privileges`, exe)
	cmd := exec.Command("osascript", "-e", script)
	if err := cmd.Start(); err != nil {
		return
	}
	os.Exit(0)
}
