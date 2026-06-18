//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

var (
	user32          = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW = user32.NewProc("MessageBoxW")
)

// fatalDialog shows a native Windows MessageBox error dialog.
func fatalDialog(title, msg string) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", title, msg)
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(msg)
	// MB_OK | MB_ICONERROR = 0x00000010
	procMessageBoxW.Call(0,
		uintptr(unsafe.Pointer(m)),
		uintptr(unsafe.Pointer(t)),
		0x10,
	)
}

// inputDialog shows a Windows input prompt via PowerShell's VisualBasic InputBox
// and returns the trimmed text the user entered. Returns "" if the user cancels.
func inputDialog(title, prompt string) string {
	safe := func(s string) string {
		return strings.ReplaceAll(s, "'", "`'")
	}
	script := fmt.Sprintf(
		"[Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null;"+
			" [Microsoft.VisualBasic.Interaction]::InputBox('%s','%s','')",
		safe(prompt), safe(title),
	)
	out, err := exec.Command(
		"powershell", "-NonInteractive", "-Command", script,
	).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
