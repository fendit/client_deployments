//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// Log file locations — both in %TEMP% so they are always writable:
//   • before admin elevation
//   • before C:\ProgramData\Fendit is created
//   • even when Windows blocks writes to Program Files
//
// On a typical system:
//   C:\Users\<username>\AppData\Local\Temp\fendit-crash.log
//   C:\Users\<username>\AppData\Local\Temp\fendit-debug.log
var (
	crashLogPath = filepath.Join(os.TempDir(), "fendit-crash.log")
	debugLogPath = filepath.Join(os.TempDir(), "fendit-debug.log")
	crashLogFile *os.File
)

// initCrashGuard is the absolute first call in main() — before any defer,
// before isAdmin(), before NewApp(), before wails.Run().
//
// It establishes three layers of visibility:
//
//  1. Crash log (fendit-crash.log): structured checkpoints written at every
//     significant step.  If the process is killed at the OS level (missing DLL,
//     AV termination, access-denied abort), the last written line tells us exactly
//     where execution stopped.
//
//  2. Debug log (fendit-debug.log): stdout + stderr from the entire process are
//     redirected here at the Win32 handle level.  This captures:
//     - Go runtime fatal errors (concurrent-map-write, nil-deref in init, OOM)
//     - Wails internal logger output
//     - WebView2 / Edge loader diagnostic messages
//     These are normally silently discarded because a -H windowsgui binary
//     inherits NUL as its standard handles.
//
//  3. Truncate mode: each run overwrites the previous log — the file holds
//     exactly one run's data (a few KB), preventing disk bloat on end-user
//     machines.  Fatal panics are also sent to the backend API and Teams.
func initCrashGuard() {
	f, err := os.OpenFile(crashLogPath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		crashLogFile = f
	}

	writeCrashLog(fmt.Sprintf(
		"\n=== Process start | %s | %s/%s | pid=%d ===",
		time.Now().Format(time.RFC3339),
		runtime.GOOS, runtime.GOARCH,
		os.Getpid(),
	))

	if err := redirectStdioToFile(debugLogPath); err != nil {
		writeCrashLog("WARN  stdio redirect failed: " + err.Error())
	} else {
		writeCrashLog("OK    stdout+stderr → " + debugLogPath)
	}

	writeCrashLog("OK    crash log      → " + crashLogPath)
}

// writeCrashLog appends a single timestamped line to fendit-crash.log.
//
// Only uses primitives that are safe before any Go initialization has run and
// from inside panic handlers: no fmt.Sprintf on heap objects, no goroutines,
// no channels — just WriteString + Sync on an already-open *os.File.
func writeCrashLog(msg string) {
	if crashLogFile == nil {
		return
	}
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format("15:04:05.000"), msg)
	crashLogFile.WriteString(line) //nolint:errcheck
	crashLogFile.Sync()            //nolint:errcheck
}

// redirectStdioToFile wires both the Go-level os.Stdout / os.Stderr AND the
// underlying Win32 STD_OUTPUT_HANDLE / STD_ERROR_HANDLE to the file at dst.
//
// Why two layers?
//   Go layer  — caught by fmt.Println, log.Printf, slog, etc.
//   Win32 layer — caught by native code that calls WriteFile(GetStdHandle(...))
//                 directly, bypassing Go's runtime entirely.  This includes the
//                 WebView2 loader DLL and the Go runtime's own crash printer.
func redirectStdioToFile(dst string) error {
	f, err := os.OpenFile(dst, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setStdHandle := kernel32.NewProc("SetStdHandle")

	// Win32 DWORD constants (cast of negative ints):
	//   STD_OUTPUT_HANDLE = (DWORD)(-11) = 0xFFFFFFF5
	//   STD_ERROR_HANDLE  = (DWORD)(-12) = 0xFFFFFFF4
	const (
		stdOutput uintptr = 0xFFFFFFF5
		stdError  uintptr = 0xFFFFFFF4
	)
	handle := f.Fd()
	setStdHandle.Call(stdOutput, handle) //nolint:errcheck
	setStdHandle.Call(stdError, handle)  //nolint:errcheck

	// Go layer — takes effect for any Go code that runs after this call.
	os.Stdout = f
	os.Stderr = f

	fmt.Fprintf(f, "\n[%s] === debug log start | pid=%d ===\n",
		time.Now().Format(time.RFC3339), os.Getpid())
	return nil
}

// checkWebView2 is a no-op kept for build-tag symmetry with crash_darwin.go.
func checkWebView2() {}

// showCrashBox displays a synchronous Win32 MessageBoxW.
//
// This is the only user-visible signal when a panic fires before the Wails
// window initialises.  It blocks until the user clicks OK, which is intentional:
// the user needs time to read the log path before the process exits.
func showCrashBox(logPath string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	msgBoxW := user32.NewProc("MessageBoxW")

	title, _ := syscall.UTF16PtrFromString("Fendit — Fatal Error")
	text, _ := syscall.UTF16PtrFromString(
		"The Fendit installer encountered a fatal error and must close.\r\n\r\n" +
			"A crash log has been saved to:\r\n\r\n" +
			"    " + logPath + "\r\n\r\n" +
			"Please send this file to support@fendit.eu so we can investigate.",
	)
	// MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_SYSTEMMODAL
	const flags uintptr = 0x00000010 | 0x00040000 | 0x00001000
	msgBoxW.Call( //nolint:errcheck
		0,
		uintptr(unsafe.Pointer(text)),
		uintptr(unsafe.Pointer(title)),
		flags,
	)
}
