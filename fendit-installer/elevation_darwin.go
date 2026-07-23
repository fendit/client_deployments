//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// isAdmin returns true when the process is running as root (UID 0).
// On macOS this is unambiguous — no UAC-style token filtering exists.
func isAdmin() bool {
	return os.Getuid() == 0
}

// relaunchAsAdmin re-executes the current binary with administrator privileges
// via osascript, which presents the standard macOS credential dialog.
// The current (unprivileged) process exits immediately after spawning the
// elevated child.  --elevated is passed so the child knows not to loop
// if isAdmin somehow returns false (e.g. sandbox/policy restriction).
func relaunchAsAdmin() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	// Shell-escape with POSIX single quotes so paths containing spaces
	// (e.g. /Applications/Fendit Security.app/...) are handled correctly.
	// The only character that cannot appear inside a single-quoted shell
	// string is a single quote itself — we use the '\'' idiom for that.
	shellExe := "'" + strings.ReplaceAll(exe, "'", "'\\''") + "'"
	script := fmt.Sprintf(
		`do shell script "%s --elevated" with administrator privileges`,
		shellExe,
	)
	cmd := exec.Command("osascript", "-e", script)
	if err := cmd.Start(); err != nil {
		return
	}
	os.Exit(0)
}
