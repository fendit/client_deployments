//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// isAdmin reports whether the current process token belongs to the local
// Administrators group. Uses the native Windows token API — no child process.
func isAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()

	ok, err := token.IsMember(sid)
	return err == nil && ok
}

// relaunchAsAdmin re-launches the current binary with UAC elevation using
// ShellExecuteW with the "runas" verb. This triggers the native Windows UAC
// consent dialog without spawning an intermediate powershell.exe process.
// On success the original (unelevated) process exits immediately.
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

	// ShellExecuteW with "runas" is the documented Win32 mechanism for requesting
	// elevation. It does not spawn any intermediate process.
	err = windows.ShellExecute(0, verbPtr, exePtr, nil, nil, windows.SW_SHOWNORMAL)
	if err != nil {
		// UAC was denied or an error occurred — surface nothing, just return.
		// The caller (startup) will continue unelevated; operations requiring
		// elevation will fail with descriptive errors later.
		return
	}

	os.Exit(0)
}
