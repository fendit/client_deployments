//go:build windows

package main

import "fmt"

// On Windows, interactive installation is handled exclusively by fendit_base.exe
// (the Wails GUI installer). The agent binary runs as a system service or via
// RMM silent deployment (--code flag). These stubs keep the package buildable;
// they are only reached if someone invokes the agent binary interactively without
// a --code flag, which is an unsupported path on Windows.

func fatalDialog(_, msg string) {
	fmt.Println(msg)
}

func inputDialog(_, _ string) string {
	fmt.Println("Please use fendit_base.exe to install Fendit Security on Windows.")
	return "" // empty → runActivationSetup calls os.Exit(0) gracefully
}
