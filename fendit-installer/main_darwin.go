//go:build darwin

package main

import "os"

func main() {
	// Network telemetry + macOS DiagnosticReports handle crash logging.
	defer handleInstallerPanic()

	if !isAdmin() {
		// --elevated means we are already the osascript-spawned root child
		// and isAdmin still returned false (sandbox / policy restriction).
		// Exit instead of looping — the user will see the process disappear.
		for _, arg := range os.Args[1:] {
			if arg == "--elevated" {
				os.Exit(1)
			}
		}
		relaunchAsAdmin()
		return
	}

	runUI()
}
