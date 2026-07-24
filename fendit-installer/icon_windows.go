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
	procGetWindowLongPtr = modUser32.NewProc("GetWindowLongPtrW")
	procSetWindowLongPtr = modUser32.NewProc("SetWindowLongPtrW")
	procSetLayeredWindow = modUser32.NewProc("SetLayeredWindowAttributes")
	procCreateSolidBrush = modGdi32.NewProc("CreateSolidBrush")
	procDwmSetWindowAttr = modDwmapi.NewProc("DwmSetWindowAttribute")
)

const (
	imageIcon         = 1
	lrDefaultColor    = 0
	wmSetIcon         = 0x0080
	iconSmall         = 0
	iconBig           = 1
	gclpHbrBackground = ^uintptr(9)        // GCLP_HBRBACKGROUND = -10
	gwlExStyle        = ^uintptr(19)       // GWL_EXSTYLE = -20
	wsExLayered       = uintptr(0x80000)   // WS_EX_LAYERED
	lwaAlpha          = uintptr(0x2)       // LWA_ALPHA
	dwmwaImmersiveDark    = 20             // Windows 11
	dwmwaImmersiveDarkOld = 19             // Windows 10 20H1+
)

// makeTransparent adds WS_EX_LAYERED and sets alpha=0 so the window is fully
// invisible even though Windows considers it "shown". This must be called before
// the first WM_PAINT so WebView2's white initial frame is never visible.
func makeTransparent(hwnd unsafe.Pointer) {
	h := uintptr(hwnd)
	exStyle, _, _ := procGetWindowLongPtr.Call(h, gwlExStyle)
	procSetWindowLongPtr.Call(h, gwlExStyle, exStyle|wsExLayered)
	procSetLayeredWindow.Call(h, 0, 0, lwaAlpha) // alpha=0: invisible
}

// makeOpaque sets the window to fully opaque. Called from JS after the first
// paint frame so the window is only ever seen with content already rendered.
func makeOpaque(hwnd unsafe.Pointer) {
	procSetLayeredWindow.Call(uintptr(hwnd), 0, 255, lwaAlpha)
}

// setWindowBackground sets the Win32 class background brush to the Fendit dark
// colour so any gap between the window edge and WebView2 paints dark.
func setWindowBackground(hwnd unsafe.Pointer) {
	colorref := uintptr(0x0B) | (uintptr(0x0D) << 8) | (uintptr(0x14) << 16) // #0B0D14 as COLORREF
	hbrush, _, _ := procCreateSolidBrush.Call(colorref)
	if hbrush != 0 {
		procSetClassLongPtr.Call(uintptr(hwnd), gclpHbrBackground, hbrush)
	}
}

// setDarkTitleBar switches the title bar to dark mode on Windows 10 20H1+ and 11.
func setDarkTitleBar(hwnd unsafe.Pointer) {
	val := uint32(1)
	ret, _, _ := procDwmSetWindowAttr.Call(
		uintptr(hwnd), dwmwaImmersiveDark,
		uintptr(unsafe.Pointer(&val)), unsafe.Sizeof(val),
	)
	if ret != 0 { // try Windows 10 attribute index
		procDwmSetWindowAttr.Call(
			uintptr(hwnd), dwmwaImmersiveDarkOld,
			uintptr(unsafe.Pointer(&val)), unsafe.Sizeof(val),
		)
	}
}

// setWindowIcon loads the EXE's embedded icon (resource ID 1 via goversioninfo)
// and applies it to the WebView2 host window via WM_SETICON. go-webview2 does
// not propagate the module icon to its window class automatically.
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
