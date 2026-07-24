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
	modDwmapi            = windows.NewLazySystemDLL("dwmapi.dll")
	procGetModule        = modKernel32.NewProc("GetModuleHandleW")
	procLoadImage        = modUser32.NewProc("LoadImageW")
	procSendMessage      = modUser32.NewProc("SendMessageW")
	procSetClassLongPtr  = modUser32.NewProc("SetClassLongPtrW")
	procShowWindow       = modUser32.NewProc("ShowWindow")
	procCreateSolidBrush = modGdi32.NewProc("CreateSolidBrush")
	procDwmSetWindowAttr = modDwmapi.NewProc("DwmSetWindowAttribute")
)

const (
	imageIcon         = 1
	lrDefaultColor    = 0
	wmSetIcon         = 0x0080
	iconSmall         = 0
	iconBig           = 1
	gclpHbrBackground = ^uintptr(9) // GCLP_HBRBACKGROUND = -10
	swHide            = 0
	swShow            = 5
	dwmwaImmersiveDark    = 20 // Windows 11
	dwmwaImmersiveDarkOld = 19 // Windows 10 20H1+
)

// setWindowBackground sets the Win32 window class background brush to the
// Fendit dark colour so any uncovered area paints dark instead of white.
func setWindowBackground(hwnd unsafe.Pointer) {
	// COLORREF is 0x00BBGGRR — #0B0D14 → R=0x0B G=0x0D B=0x14
	colorref := uintptr(0x0B) | (uintptr(0x0D) << 8) | (uintptr(0x14) << 16)
	hbrush, _, _ := procCreateSolidBrush.Call(colorref)
	if hbrush != 0 {
		procSetClassLongPtr.Call(uintptr(hwnd), gclpHbrBackground, hbrush)
	}
}

// setDarkTitleBar switches the Windows title bar to dark mode, matching the
// dark UI body. Works on Windows 10 20H1+ and Windows 11.
func setDarkTitleBar(hwnd unsafe.Pointer) {
	val := uint32(1)
	ret, _, _ := procDwmSetWindowAttr.Call(
		uintptr(hwnd),
		dwmwaImmersiveDark,
		uintptr(unsafe.Pointer(&val)),
		unsafe.Sizeof(val),
	)
	if ret != 0 { // S_OK = 0; non-zero means unsupported — try Windows 10 index
		procDwmSetWindowAttr.Call(
			uintptr(hwnd),
			dwmwaImmersiveDarkOld,
			uintptr(unsafe.Pointer(&val)),
			unsafe.Sizeof(val),
		)
	}
}

// hideWindow hides the window without destroying it. Used to suppress the
// WebView2 white-flash: the window stays hidden until the HTML has painted.
func hideWindow(hwnd unsafe.Pointer) {
	procShowWindow.Call(uintptr(hwnd), swHide)
}

// showWindow makes the window visible and brings it to the foreground.
func showWindow(hwnd unsafe.Pointer) {
	procShowWindow.Call(uintptr(hwnd), swShow)
}

// setWindowIcon loads the EXE's embedded icon resource (goversioninfo places it
// at resource ID 1) and applies it to the WebView2 host window via WM_SETICON.
// go-webview2 does not propagate the module icon to its window class, so without
// this the title bar shows the default Windows grey icon.
func setWindowIcon(hwnd unsafe.Pointer) {
	hmod, _, _ := procGetModule.Call(0)
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
