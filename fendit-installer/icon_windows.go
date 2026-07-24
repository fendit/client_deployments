//go:build windows

package main

import (
	"syscall"
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
	procRegisterClassEx  = modUser32.NewProc("RegisterClassExW")
	procCreateWindowEx   = modUser32.NewProc("CreateWindowExW")
	procDefWindowProc    = modUser32.NewProc("DefWindowProcW")
	procGetSystemMetrics = modUser32.NewProc("GetSystemMetrics")
	procShowWindow       = modUser32.NewProc("ShowWindow")
)

const (
	imageIcon          = 1
	lrDefaultColor     = 0
	wmSetIcon          = 0x0080
	iconSmall          = 0
	iconBig            = 1
	gclpHbrBackground  = ^uintptr(9)        // GCLP_HBRBACKGROUND = -10
	gwlExStyle         = ^uintptr(19)       // GWL_EXSTYLE  = -20
	gwlStyle           = ^uintptr(15)       // GWL_STYLE    = -16
	wsExLayered        = uintptr(0x80000)   // WS_EX_LAYERED
	wsExAppWindow      = uintptr(0x40000)   // WS_EX_APPWINDOW
	wsOverlappedWindow = uintptr(0xCF0000)  // WS_OVERLAPPEDWINDOW
	wsThickFrame       = uintptr(0x40000)   // WS_THICKFRAME
	wsMaximizeBox      = uintptr(0x10000)   // WS_MAXIMIZEBOX
	lwaAlpha           = uintptr(0x2)       // LWA_ALPHA
	swShow             = uintptr(5)
	smCxScreen         = uintptr(0)
	smCyScreen         = uintptr(1)
	csHredraw          = uint32(0x0002)
	csVredraw          = uint32(0x0001)
	dwmwaImmersiveDark    = 20 // Windows 11
	dwmwaImmersiveDarkOld = 19 // Windows 10 20H1+
)

// wndClassEx mirrors Win32 WNDCLASSEXW (80 bytes on amd64).
type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  uintptr
	lpszClassName uintptr
	hIconSm       uintptr
}

// wndProcCallback is the Win32 window procedure for our host window.
// Delegates everything to DefWindowProcW — we only own the window, not its messages.
var wndProcCallback = syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
	ret, _, _ := procDefWindowProc.Call(hwnd, msg, wParam, lParam)
	return ret
})

// createAppWindow creates our own Win32 host window with WS_EX_LAYERED at alpha=0
// BEFORE showing it, so it is fully transparent at the OS level from the very first
// WM_PAINT. WebView2 is then embedded into this window via NewWithOptions — it never
// gets a chance to paint a white frame. makeOpaque() reveals the window after the
// first HTML paint.
func createAppWindow(width, height int) unsafe.Pointer {
	hmod, _, _ := procGetModule.Call(0)

	className, _ := windows.UTF16PtrFromString("FenditInstallerClass")
	wc := wndClassEx{
		cbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		style:         csHredraw | csVredraw,
		lpfnWndProc:   wndProcCallback,
		hInstance:     hmod,
		lpszClassName: uintptr(unsafe.Pointer(className)),
	}
	procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))

	// Center on primary monitor.
	sw, _, _ := procGetSystemMetrics.Call(smCxScreen)
	sh, _, _ := procGetSystemMetrics.Call(smCyScreen)
	x := (int(sw) - width) / 2
	y := (int(sh) - height) / 2

	hwnd, _, _ := procCreateWindowEx.Call(
		wsExLayered|wsExAppWindow,
		uintptr(unsafe.Pointer(className)),
		0, // title is set later by w.SetTitle()
		wsOverlappedWindow,
		uintptr(x), uintptr(y),
		uintptr(width), uintptr(height),
		0, 0, hmod, 0,
	)
	if hwnd == 0 {
		return nil
	}

	// alpha=0 must be set BEFORE ShowWindow so no frame is ever composited white.
	procSetLayeredWindow.Call(hwnd, 0, 0, lwaAlpha)
	procShowWindow.Call(hwnd, swShow)

	return unsafe.Pointer(hwnd)
}

// makeOpaque sets the window to fully visible. Called from JS after the first
// paint frame — the user only ever sees the fully rendered dark UI.
func makeOpaque(hwnd unsafe.Pointer) {
	procSetLayeredWindow.Call(uintptr(hwnd), 0, 255, lwaAlpha)
}

// setWindowBackground sets the Win32 class background brush to the Fendit dark
// colour so any gap between the window edge and WebView2 area paints dark.
func setWindowBackground(hwnd unsafe.Pointer) {
	colorref := uintptr(0x0B) | (uintptr(0x0D) << 8) | (uintptr(0x14) << 16) // #0B0D14
	hbrush, _, _ := procCreateSolidBrush.Call(colorref)
	if hbrush != 0 {
		procSetClassLongPtr.Call(uintptr(hwnd), gclpHbrBackground, hbrush)
	}
}

// setDarkTitleBar enables the Windows immersive dark mode title bar on Win 10 20H1+/11.
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
// and applies it to the window via WM_SETICON.
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
