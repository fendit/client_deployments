package main

import (
	"log"
	"os/exec"
	"runtime"
	"time"

	"github.com/getlantern/systray"
)

const portalURL = "https://portal.fendit.eu"

var (
	updateItem     *systray.MenuItem
	restartItem    *systray.MenuItem
	updateNotified bool // guards against repeated OS notifications on each 5-min tick
)

func runTray() {
	systray.Run(onReady, onExit)
}

func onReady() {
	setTrayIcon() // platform-specific: tray_darwin.go / tray_windows.go
	systray.SetTitle("Fendit")
	systray.SetTooltip("Fendit Security Agent — Protected")

	status := systray.AddMenuItem("Status: Protected", "Agent is active")
	status.Disable()

	interceptors := systray.AddMenuItem("Interceptors: Engaged", "Honeypot and downloads scanner are active")
	interceptors.Disable()

	systray.AddSeparator()

	// Update and restart items: hidden by default, shown when daemon signals pending state.
	updateItem = systray.AddMenuItem("Update available", "Click to schedule the update")
	updateItem.Hide()
	restartItem = systray.AddMenuItem("⚠ Restart required", "Click to restart now or postpone")
	restartItem.Hide()

	systray.AddSeparator()

	dashboard := systray.AddMenuItem("Open Security Dashboard…", "View your security events")

	systray.AddSeparator()

	quit := systray.AddMenuItem("Quit UI", "Close the Fendit tray icon")

	// Poll update_state.json every 5 minutes and restart_state.json every minute.
	go pollUpdateState()
	go pollRestartState()

	go func() {
		for {
			select {
			case <-updateItem.ClickedCh:
				go onUpdateClicked() // goroutine so dialog doesn't block other menu items
			case <-restartItem.ClickedCh:
				go onRestartClicked()
			case <-dashboard.ClickedCh:
				openBrowser(portalURL)
			case <-quit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

func onExit() {
	log.Println("Fendit tray exited")
}

func openBrowser(url string) {
	switch runtime.GOOS {
	case "darwin":
		exec.Command("open", url).Start() //nolint:errcheck
	case "windows":
		exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start() //nolint:errcheck
	}
}

// pollUpdateState refreshes the update menu item immediately and every 5 minutes.
func pollUpdateState() {
	refreshUpdateItem()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		refreshUpdateItem()
	}
}

// refreshUpdateItem reads update_state.json and updates the tray item accordingly.
func refreshUpdateItem() {
	state, err := readUpdateState()
	if err != nil || state == nil || !state.Pending {
		updateItem.Hide()
		return
	}
	switch state.Status {
	case "pending":
		updateItem.SetTitle("⬆ Update available — click to schedule")
		updateItem.Enable()
		updateItem.Show()
		if !updateNotified {
			updateNotified = true
			notifyUpdateAvailable() // platform-specific: dialog_darwin.go / dialog_windows.go
		}
	case "failed":
		updateItem.SetTitle("⚠ Update failed — click to retry")
		updateItem.Enable()
		updateItem.Show()
	case "downloading", "installing":
		updateItem.SetTitle("⟳ Updating…")
		updateItem.Disable()
		updateItem.Show()
	case "done":
		clearUpdateState()
		updateItem.Hide()
	default:
		updateItem.Hide()
	}
}

// pollRestartState refreshes the restart menu item immediately and every minute.
// Past the 48-hour deadline it also triggers an automatic popup every 10 minutes.
func pollRestartState() {
	refreshRestartItem()
	checkAndPromptRestart()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		refreshRestartItem()
		checkAndPromptRestart()
	}
}

// refreshRestartItem reads restart_state.json and updates the tray item label.
func refreshRestartItem() {
	state, err := readRestartState()
	if err != nil || state == nil || !state.Required {
		restartItem.Hide()
		return
	}
	deadline, _ := time.Parse(time.RFC3339, state.Deadline)
	if time.Now().After(deadline) {
		restartItem.SetTitle("🔴 Restart overdue — click to restart now")
	} else {
		restartItem.SetTitle("⚠ Restart required — click to schedule")
	}
	restartItem.Enable()
	restartItem.Show()
}

// checkAndPromptRestart auto-shows a restart dialog every 10 minutes once the
// 48-hour deadline has elapsed.
func checkAndPromptRestart() {
	state, err := readRestartState()
	if err != nil || state == nil || !state.Required {
		return
	}
	deadline, err := time.Parse(time.RFC3339, state.Deadline)
	if err != nil || time.Now().Before(deadline) {
		return
	}
	if state.LastPrompt != "" {
		last, err := time.Parse(time.RFC3339, state.LastPrompt)
		if err == nil && time.Since(last) < 10*time.Minute {
			return
		}
	}
	// Record the prompt time before showing the dialog (prevents double-firing
	// if the dialog blocks for a long time).
	state.LastPrompt = time.Now().UTC().Format(time.RFC3339)
	_ = writeRestartState(state)
	go showRestartPrompt(true)
}

// onRestartClicked handles a manual click on the restart tray item.
func onRestartClicked() {
	state, err := readRestartState()
	if err != nil || state == nil {
		return
	}
	deadline, _ := time.Parse(time.RFC3339, state.Deadline)
	overdue := time.Now().After(deadline)
	showRestartPrompt(overdue)
}

// showRestartPrompt shows the restart dialog and handles the user's response.
// urgent=true means the deadline has passed; repeated dismissals lead to forceRestart.
func showRestartPrompt(urgent bool) {
	if restartDialog(urgent) {
		clearRestartState()
		restartItem.Hide()
		executeRestart()
		return
	}
	if !urgent {
		return
	}
	// Past deadline: increment dismiss count and force restart after 5 dismissals.
	s, err := readRestartState()
	if err != nil || s == nil {
		return
	}
	s.DismissCount++
	_ = writeRestartState(s)
	if s.DismissCount >= 5 {
		clearRestartState()
		restartItem.Hide()
		forceRestart()
	}
}

// onUpdateClicked handles a click on the update menu item.
// Shows the schedule dialog and writes the chosen time to update_state.json.
func onUpdateClicked() {
	state, err := readUpdateState()
	if err != nil || state == nil {
		return
	}

	choice := scheduleUpdateDialog() // platform-specific: dialog_darwin.go / dialog_windows.go
	if choice == "" {
		return // user cancelled or chose "later"
	}

	state.Status = "pending"
	switch choice {
	case "now":
		state.ScheduledAt = ""
	case "tonight":
		now := time.Now()
		midnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
		state.ScheduledAt = midnight.Format(time.RFC3339)
	case "tomorrow":
		now := time.Now()
		morning := time.Date(now.Year(), now.Month(), now.Day()+1, 7, 0, 0, 0, now.Location())
		state.ScheduledAt = morning.Format(time.RFC3339)
	}
	_ = writeUpdateState(state)
	refreshUpdateItem()
}
