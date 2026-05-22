//go:build darwin

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// fatalDialog shows a native macOS error dialog and prints to stderr.
func fatalDialog(title, msg string) {
	safe := func(s string) string {
		return strings.ReplaceAll(s, `"`, `'`)
	}
	script := fmt.Sprintf(
		`display dialog "%s" buttons {"OK"} with title "%s" with icon stop`,
		safe(msg), safe(title),
	)
	exec.Command("osascript", "-e", script).Run() //nolint:errcheck
}
