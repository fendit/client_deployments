//go:build windows

package main

import "os"

func main() {
	// Layer 1 — crash log + stdio redirect to %TEMP%\fendit-crash.log / fendit-debug.log.
	// Must be the absolute first call: before any defer, before elevation, before UI.
	initCrashGuard()

	// Layer 2 — Go panic handler.
	defer handleInstallerPanic()

	writeCrashLog("checkpoint: elevation check")
	if !isAdmin() {
		// --elevated means we are already the UAC-spawned child and isAdmin still
		// returned false (policy restriction / broken token API). Do not loop.
		for _, arg := range os.Args[1:] {
			if arg == "--elevated" {
				showCrashBox(crashLogPath)
				os.Exit(1)
			}
		}
		relaunchAsAdmin()
		return
	}

	writeCrashLog("checkpoint: calling runUI")
	runUI()
	writeCrashLog("checkpoint: runUI returned (normal exit)")
}
