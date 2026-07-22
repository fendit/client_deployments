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

// scheduleUpdateDialog shows a native macOS list-picker for update scheduling.
// Returns "now", "tonight", "tomorrow", or "" (later / cancelled).
func scheduleUpdateDialog() string {
	script := `choose from list {"Update now", "Tonight at midnight", "Tomorrow at 7am", "Remind me later"} ` +
		`with prompt "A Fendit Security update is available." with title "Fendit Update" default items {"Update now"}`
	out, err := exec.Command("osascript", "-e", script).Output()
	if err != nil {
		return ""
	}
	switch strings.TrimSpace(string(out)) {
	case "Update now":
		return "now"
	case "Tonight at midnight":
		return "tonight"
	case "Tomorrow at 7am":
		return "tomorrow"
	default:
		return ""
	}
}

// notifyUpdateAvailable shows a macOS notification banner when an update is detected.
func notifyUpdateAvailable() {
	exec.Command("osascript", "-e",
		`display notification "A new version is ready to install." `+
			`with title "Fendit Security" subtitle "Update available"`,
	).Run() //nolint:errcheck
}

// restartDialog asks the user whether to restart now or postpone.
// urgent=true wording emphasises the 48-hour deadline has passed.
// Returns true if the user chose "Restart Now", false to postpone.
func restartDialog(urgent bool) bool {
	var msg string
	if urgent {
		msg = "URGENT: The 48-hour restart window has passed. " +
			"Your computer must restart to complete the Fendit security update. " +
			"This reminder will repeat every 10 minutes."
	} else {
		msg = "A Fendit security update requires a system restart to complete." +
			"Your computer will restart when you choose Restart Now."
	}
	safe := strings.ReplaceAll(msg, `"`, `'`)
	script := fmt.Sprintf(
		`display dialog "%s" buttons {"Later", "Restart Now"} `+
			`default button "Restart Now" with title "Fendit Security — Restart Required" with icon caution`,
		safe,
	)
	out, _ := exec.Command("osascript", "-e", script).Output()
	return strings.Contains(string(out), "Restart Now")
}

// notifyRestartRecommended shows a macOS notification banner when a restart
// becomes required after a Wazuh update.
func notifyRestartRecommended() {
	exec.Command("osascript", "-e",
		`display notification "A restart is required to complete the Fendit security update." `+
			`with title "Fendit Security" subtitle "Restart required"`,
	).Run() //nolint:errcheck
}

// executeRestart initiates a graceful macOS restart via System Events.
// macOS may show a confirmation sheet; the user can still cancel.
func executeRestart() {
	exec.Command("osascript", "-e", `tell application "System Events" to restart`).Run() //nolint:errcheck
}

// forceRestart signals the root daemon (via restart_state.json) to execute
// shutdown -r. The tray runs as the console user and cannot call shutdown
// directly; the daemon (LaunchDaemon, root) picks up ForceRequested within 5 min.
func forceRestart() {
	s, _ := readRestartState()
	if s == nil {
		s = &RestartState{}
	}
	s.ForceRequested = true
	_ = writeRestartState(s)
}

// inputDialog shows a native macOS text-input dialog and returns the entered text.
// Returns "" if the user clicks Cancel or the dialog fails.
func inputDialog(title, prompt string) string {
	safe := func(s string) string {
		return strings.ReplaceAll(s, `"`, `'`)
	}
	script := fmt.Sprintf(
		`set r to display dialog "%s" default answer "" buttons {"Cancel","OK"} `+
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
