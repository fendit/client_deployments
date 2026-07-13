//go:build darwin

package main

// crash_darwin.go — stubs so telemetry.go can reference the crash-guard
// symbols without a build tag.
//
// On macOS:
//   • stdout/stderr are real ttys when launched from Terminal.
//   • The OS writes its own crash report to ~/Library/Logs/DiagnosticReports/.
//   • handleInstallerPanic() still fires the network telemetry POST.
//
// If macOS-specific local logging is needed in the future, implement it here.

var crashLogPath string // empty — no local crash log on macOS

func initCrashGuard()        {}
func writeCrashLog(_ string) {}
func checkWebView2()         {}
func showCrashBox(_ string)  {}
