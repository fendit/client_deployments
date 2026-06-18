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

// inputDialog shows a native macOS text-input dialog and returns the entered text.
// Returns "" if the user clicks Cancel or the dialog fails.
func inputDialog(title, prompt string) string {
	safe := func(s string) string {
		return strings.ReplaceAll(s, `"`, `'`)
	}
	script := fmt.Sprintf(
		`set r to display dialog "%s" default answer "" buttons {"Annuleren","OK"} `+
			`default button "OK" with title "%s"`+"\n"+
			`return text returned of r`,
		safe(prompt), safe(title),
	)
	out, err := exec.Command("osascript", "-e", script).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
