//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modUser32            = windows.NewLazySystemDLL("user32.dll")
	modKernel32          = windows.NewLazySystemDLL("kernel32.dll")
	modGdi32             = windows.NewLazySystemDLL("gdi32.dll")
	procGetModule        = modKernel32.NewProc("GetModuleHandleW")
	procLoadImage        = modUser32.NewProc("LoadImageW")
	procSendMessage      = modUser32.NewProc("SendMessageW")
	procSetClassLongPtr  = modUser32.NewProc("SetClassLongPtrW")
	procCreateSolidBrush = modGdi32.NewProc("CreateSolidBrush")
)

const (
	imageIcon          = 1
	lrDefaultColor     = 0
	wmSetIcon          = 0x0080
	iconSmall          = 0
	iconBig            = 1
	gclpHbrBackground  = ^uintptr(9) // -10: replace window class background brush
)

// setWindowBackground sets the Win32 window class background brush to the
// Fendit brand dark colour (#0B0D14) before WebView2 paints its first frame.
// Without this the window shows a white flash between UAC approval and the
// first WebView2 paint because the default class brush is COLOR_WINDOW (white).
func setWindowBackground(hwnd unsafe.Pointer) {
	// COLORREF is 0x00BBGGRR — #0B0D14 → R=0x0B G=0x0D B=0x14
	colorref := uintptr(0x0B) | (uintptr(0x0D) << 8) | (uintptr(0x14) << 16)
	hbrush, _, _ := procCreateSolidBrush.Call(colorref)
	if hbrush != 0 {
		procSetClassLongPtr.Call(uintptr(hwnd), gclpHbrBackground, hbrush)
	}
}

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
