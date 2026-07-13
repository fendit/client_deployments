//go:build darwin

package main

func main() {
	// Network telemetry + local crash log are written by handleInstallerPanic.
	// On macOS the OS also writes its own crash report to
	// ~/Library/Logs/DiagnosticReports/ — check there for DLL-equivalent panics.
	defer handleInstallerPanic()

	// Elevation must happen before the Fyne window opens.
	if !isAdmin() {
		relaunchAsAdmin()
		return
	}

	runUI()
}
