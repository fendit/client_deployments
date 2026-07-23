//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// isAdmin reports whether the current process is running with elevated
// (administrator) privileges. Uses TokenElevation — the correct UAC-aware
// check. The older IsMember(adminSID) approach fails on UAC filtered tokens:
// the Administrators SID is present but disabled, so IsMember returns false
// even though the process was elevated. IsElevated queries the kernel directly.
func isAdmin() bool {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

// relaunchAsAdmin re-launches the current binary with UAC elevation using
// ShellExecuteW with the "runas" verb. Passes --elevated so the child process
// knows it is the elevated instance and must not loop if isAdmin still fails
// (e.g. policy restriction). On success the original process exits immediately.
func relaunchAsAdmin() {
	exe, err := os.Executable()
	if err != nil {
		return
	}

	exePtr, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return
	}
	verbPtr, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return
	}
	// Pass --elevated so the child process knows not to re-elevate if isAdmin
	// somehow still returns false (GP restriction, broken token API, etc.).
	argsPtr, err := windows.UTF16PtrFromString("--elevated")
	if err != nil {
		return
	}

	err = windows.ShellExecute(0, verbPtr, exePtr, argsPtr, nil, windows.SW_SHOWNORMAL)
	if err != nil {
		return
	}

	os.Exit(0)
}
