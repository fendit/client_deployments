//go:build windows

package main

import (
	"fmt"
	"os"
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
