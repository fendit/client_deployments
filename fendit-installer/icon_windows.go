//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modUser32           = windows.NewLazySystemDLL("user32.dll")
	modKernel32         = windows.NewLazySystemDLL("kernel32.dll")
	modGdi32            = windows.NewLazySystemDLL("gdi32.dll")
	modDwmapi           = windows.NewLazySystemDLL("dwmapi.dll")
	procGetModule       = modKernel32.NewProc("GetModuleHandleW")
	procLoadImage       = modUser32.NewProc("LoadImageW")
	procSendMessage     = modUser32.NewProc("SendMessageW")
	procSetClassLongPtr = modUser32.NewProc("SetClassLongPtrW")
	procShowWindow      = modUser32.NewProc("ShowWindow")
	procCreateSolidBrush = modGdi32.NewProc("CreateSolidBrush")
	procDwmSetWindowAttr = modDwmapi.NewProc("DwmSetWindowAttribute")
)

const (
	imageIcon         = 1
	lrDefaultColor    = 0
	wmSetIcon         = 0x0080
	iconSmall         = 0
	iconBig           = 1
	gclpHbrBackground = ^uintptr(9)  // GCLP_HBRBACKGROUND = -10
	swShowNA          = uintptr(8)   // SW_SHOWNA: show without activating
	dwmwaImmersiveDark    = 20       // Windows 11
	dwmwaImmersiveDarkOld = 19       // Windows 10 20H1+
)

// makeOpaque reveals the window for the first time. Called from JS after
// first-contentful-paint so the user only ever sees the fully-rendered UI.
// go-webview2-local omits the ShowWindow call in CreateWithOptions so the
// window is hidden until this function runs.
func makeOpaque(hwnd unsafe.Pointer) {
	procShowWindow.Call(uintptr(hwnd), swShowNA)
}

// setWindowBackground paints the window class background dark so any gap
// between the window edge and the WebView2 area shows the brand colour.
func setWindowBackground(hwnd unsafe.Pointer) {
	colorref := uintptr(0x0B) | (uintptr(0x0D) << 8) | (uintptr(0x14) << 16) // #0B0D14
	hbrush, _, _ := procCreateSolidBrush.Call(colorref)
	if hbrush != 0 {
		procSetClassLongPtr.Call(uintptr(hwnd), gclpHbrBackground, hbrush)
	}
}

// setDarkTitleBar enables immersive dark mode on the title bar (Win 10 20H1+/11).
func setDarkTitleBar(hwnd unsafe.Pointer) {
	val := uint32(1)
	ret, _, _ := procDwmSetWindowAttr.Call(
		uintptr(hwnd), dwmwaImmersiveDark,
		uintptr(unsafe.Pointer(&val)), unsafe.Sizeof(val),
	)
	if ret != 0 {
		procDwmSetWindowAttr.Call(
			uintptr(hwnd), dwmwaImmersiveDarkOld,
			uintptr(unsafe.Pointer(&val)), unsafe.Sizeof(val),
		)
	}
}

// setWindowIcon sends WM_SETICON to put the EXE's embedded icon into the
// title bar. go-webview2 sets it on the window class via IconId but
// WM_SETICON overrides it per-window instance.
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
