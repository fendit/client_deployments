//go:build darwin

package main

import "fmt"

// runUninstall removes Fendit from a macOS device.
// On macOS, uninstall is handled by the .pkg uninstaller or a dedicated
// script distributed by the SOC portal — not by the agent binary itself.
func runUninstall() {
	fmt.Println("To uninstall Fendit on macOS, run: sudo /Library/Fendit/uninstall.sh")
	fmt.Println("Or contact your IT administrator.")
}
