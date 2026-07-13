//go:build windows

package main

func main() {
	// Layer 1 — crash log + stdio redirect to %TEMP%\fendit-crash.log / fendit-debug.log.
	// Must be the absolute first call: before any defer, before elevation, before UI.
	// Opens both log files so we have a trace even for OS-level aborts that bypass recover().
	initCrashGuard()

	// Layer 2 — Go panic handler.
	// Registered after initCrashGuard so crashLogFile is already open when it fires.
	defer handleInstallerPanic()

	// Elevation must happen before the Fyne window opens.
	// os.Exit here is safe because no GUI has started yet — no window class to leak.
	writeCrashLog("checkpoint: elevation check")
	if !isAdmin() {
		relaunchAsAdmin()
		return
	}

	// Probe WebView2 / other heavy DLLs here if needed in the future.
	// Currently a no-op — Fyne has no WebView2 dependency.
	writeCrashLog("checkpoint: calling runUI")
	runUI()
	writeCrashLog("checkpoint: runUI returned (normal exit)")
}
