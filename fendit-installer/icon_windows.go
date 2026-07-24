//go:build windows

package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modUser32               = windows.NewLazySystemDLL("user32.dll")
	modKernel32             = windows.NewLazySystemDLL("kernel32.dll")
	modGdi32                = windows.NewLazySystemDLL("gdi32.dll")
	modDwmapi               = windows.NewLazySystemDLL("dwmapi.dll")
	procGetModule           = modKernel32.NewProc("GetModuleHandleW")
	procGetCurrentThreadId  = modKernel32.NewProc("GetCurrentThreadId")
	procLoadImage           = modUser32.NewProc("LoadImageW")
	procSendMessage         = modUser32.NewProc("SendMessageW")
	procSetClassLongPtr     = modUser32.NewProc("SetClassLongPtrW")
	procGetWindowLongPtr    = modUser32.NewProc("GetWindowLongPtrW")
	procSetWindowLongPtr    = modUser32.NewProc("SetWindowLongPtrW")
	procSetLayeredWindow    = modUser32.NewProc("SetLayeredWindowAttributes")
	procSetWindowsHookEx    = modUser32.NewProc("SetWindowsHookExW")
	procUnhookWindowsHookEx = modUser32.NewProc("UnhookWindowsHookEx")
	procCallNextHookEx      = modUser32.NewProc("CallNextHookEx")
	procCreateSolidBrush    = modGdi32.NewProc("CreateSolidBrush")
	procDwmSetWindowAttr    = modDwmapi.NewProc("DwmSetWindowAttribute")
)

const (
	imageIcon         = 1
	lrDefaultColor    = 0
	wmSetIcon         = 0x0080
	iconSmall         = 0
	iconBig           = 1
	gclpHbrBackground = ^uintptr(9)      // GCLP_HBRBACKGROUND = -10
	gwlExStyle        = ^uintptr(19)     // GWL_EXSTYLE = -20
	wsExLayered       = uintptr(0x80000) // WS_EX_LAYERED
	lwaAlpha          = uintptr(0x2)     // LWA_ALPHA
	whCbt             = uintptr(5)       // WH_CBT
	dwmwaImmersiveDark    = 20           // Windows 11
	dwmwaImmersiveDarkOld = 19           // Windows 10 20H1+
)

// fenditCBTHook holds the HHOOK so the callback can chain to the next hook.
var fenditCBTHook uintptr

// fenditCBTProc is a thread-local WH_CBT hook that fires at HCBT_CREATEWND —
// inside CreateWindowExW, after the HWND is allocated but BEFORE ShowWindow.
// We set WS_EX_LAYERED + alpha=0 here so the window is invisible at the OS
// compositor level from the very first WM_PAINT. We only touch top-level windows
// (hwndParent == 0) to avoid interfering with WebView2's internal child windows.
//
// Pointer layout on amd64:
//   lParam → CBT_CREATEWND { lpcs *CREATESTRUCT (offset 0), ... }
//   CREATESTRUCT { lpCreateParams (0), hInstance (8), hMenu (16), hwndParent (24), ... }
var fenditCBTProc = syscall.NewCallback(func(nCode, wParam, lParam uintptr) uintptr {
	const hcbtCreateWnd = 3
	if nCode == hcbtCreateWnd && wParam != 0 && lParam != 0 {
		lpcs := *(*uintptr)(unsafe.Pointer(lParam))
		if lpcs != 0 {
			hwndParent := *(*uintptr)(unsafe.Pointer(lpcs + 24))
			if hwndParent == 0 {
				exStyle, _, _ := procGetWindowLongPtr.Call(wParam, gwlExStyle)
				procSetWindowLongPtr.Call(wParam, gwlExStyle, exStyle|wsExLayered)
				procSetLayeredWindow.Call(wParam, 0, 0, lwaAlpha)
			}
		}
	}
	ret, _, _ := procCallNextHookEx.Call(fenditCBTHook, nCode, wParam, lParam)
	return ret
})

// installCBTHook installs the hook on the current OS thread.
// Call runtime.LockOSThread() before this so the hook and webview.New() share the same thread.
func installCBTHook() {
	tid, _, _ := procGetCurrentThreadId.Call()
	fenditCBTHook, _, _ = procSetWindowsHookEx.Call(whCbt, fenditCBTProc, 0, tid)
}

func removeCBTHook() {
	if fenditCBTHook != 0 {
		procUnhookWindowsHookEx.Call(fenditCBTHook)
		fenditCBTHook = 0
	}
}

// makeOpaque reveals the window (alpha=255). Called from JS after first paint.
func makeOpaque(hwnd unsafe.Pointer) {
	procSetLayeredWindow.Call(uintptr(hwnd), 0, 255, lwaAlpha)
}

// setWindowBackground paints the window class background dark so any gap between
// the window edge and the WebView2 area shows the brand colour, not white.
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

// setWindowIcon sends WM_SETICON to put the EXE's embedded icon (resource ID 1
// from goversioninfo) into the title bar. go-webview2 sets it on the window
// class via IconId but WM_SETICON overrides it per-window instance.
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
