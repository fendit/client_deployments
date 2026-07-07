//go:build windows

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/gen2brain/dlgs"
)

var (
	user32          = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW = user32.NewProc("MessageBoxW")
)

// fatalDialog shows a native Windows MessageBox error dialog.
// Direct syscall to MessageBoxW — no child process.
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

// inputDialog shows a native Windows input dialog and returns the text the user
// entered. Returns "" if the user clicks Cancel or the dialog fails.
// Uses dlgs.Entry which calls CreateDialogParamW/DialogBoxParamW via Win32 API —
// no powershell.exe child process is spawned.
func inputDialog(title, prompt string) string {
	text, ok, err := dlgs.Entry(title, prompt, "")
	if err != nil || !ok {
		return ""
	}
	return text
}
