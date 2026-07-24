//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modUser32       = windows.NewLazySystemDLL("user32.dll")
	modKernel32     = windows.NewLazySystemDLL("kernel32.dll")
	procGetModule   = modKernel32.NewProc("GetModuleHandleW")
	procLoadImage   = modUser32.NewProc("LoadImageW")
	procSendMessage = modUser32.NewProc("SendMessageW")
)

const (
	imageIcon      = 1
	lrDefaultColor = 0
	wmSetIcon      = 0x0080
	iconSmall      = 0
	iconBig        = 1
)

// setWindowIcon loads the EXE's embedded icon resource (goversioninfo places it
// at resource ID 1) and applies it to the WebView2 host window via WM_SETICON.
// go-webview2 does not propagate the module icon to its window class, so without
// this the title bar shows the default Windows grey icon.
//
// MAKEINTRESOURCE(1) in Win32 is simply uintptr(1) — a resource ID disguised
// as a pointer, which LoadImageW recognises as an integer resource handle.
func setWindowIcon(hwnd unsafe.Pointer) {
	hmod, _, _ := procGetModule.Call(0) // 0 = current process module
	hBig, _, _ := procLoadImage.Call(hmod, 1, imageIcon, 32, 32, lrDefaultColor)
	hSmall, _, _ := procLoadImage.Call(hmod, 1, imageIcon, 16, 16, lrDefaultColor)
	h := uintptr(hwnd)
	if hBig != 0 {
		procSendMessage.Call(h, wmSetIcon, iconBig, hBig)
	}
	if hSmall != 0 {
		procSendMessage.Call(h, wmSetIcon, iconSmall, hSmall)
	}
}
