//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// On Windows, interactive installation is handled exclusively by fendit_base.exe
// (the Wails GUI installer). The agent binary runs as a system service or via
// RMM silent deployment (--code flag). fatalDialog/inputDialog keep the package
// buildable for that path.

func fatalDialog(_, msg string) {
	fmt.Println(msg)
}

func inputDialog(_, _ string) string {
	fmt.Println("Please use fendit_base.exe to install Fendit Security on Windows.")
	return "" // empty → runActivationSetup calls os.Exit(0) gracefully
}

// scheduleUpdateDialog shows a native Windows MessageBox asking whether to update now.
// Returns "now" if the user clicks Yes, "" otherwise (update remains pending).
func scheduleUpdateDialog() string {
	title, _ := windows.UTF16PtrFromString("Fendit Security Update")
	msg, _ := windows.UTF16PtrFromString(
		"A Fendit Security update is available.\n\n" +
			"Update now? The agent will restart briefly.\n\n" +
			"Click No to apply the update at your next convenient time.")

	const mbYesNo = 0x00000004
	const mbIconInformation = 0x00000040

	user32 := windows.NewLazyDLL("user32.dll")
	msgBoxW := user32.NewProc("MessageBoxW")
	ret, _, _ := msgBoxW.Call(
		0,
		uintptr(unsafe.Pointer(msg)),
		uintptr(unsafe.Pointer(title)),
		mbYesNo|mbIconInformation,
	)
	const idYes = 6
	if ret == idYes {
		return "now"
	}
	return ""
}

// notifyUpdateAvailable shows a Windows toast notification when a pending update
// is first detected. Registers the app AUMID so the notification system can
// attribute the toast correctly.
func notifyUpdateAvailable() {
	registerToastAppID()
	const script = `
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType=WindowsRuntime]
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml('<toast duration="long"><visual><binding template="ToastGeneric"><text>Fendit Security</text><text>A security update is available. Click the tray icon to schedule it.</text></binding></visual></toast>')
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('eu.fendit.agent').Show([Windows.UI.Notifications.ToastNotification]::new($xml))
`
	exec.Command("powershell", "-WindowStyle", "Hidden", "-NonInteractive", "-Command", script).Start() //nolint:errcheck
}

// registerToastAppID writes the AUMID needed for Windows to attribute toast
// notifications to Fendit. Called once per notification; idempotent.
func registerToastAppID() {
	k, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`SOFTWARE\Classes\AppUserModelId\eu.fendit.agent`,
		registry.WRITE,
	)
	if err != nil {
		return
	}
	defer k.Close()
	k.SetStringValue("DisplayName", "Fendit Security") //nolint:errcheck
	k.SetStringValue("IconUri", agentBinDst)           //nolint:errcheck
}

// restartDialog asks the user whether to restart now or postpone.
// urgent=true means the 48-hour deadline has passed; wording is more emphatic.
// Returns true if the user chose to restart, false to postpone.
func restartDialog(urgent bool) bool {
	var msgText string
	if urgent {
		msgText = "URGENT: The 48-hour restart window has passed.\n\n" +
			"Your computer must restart to complete the Fendit security update.\n\n" +
			"Click Yes to restart now. This reminder will repeat every 10 minutes."
	} else {
		msgText = "A Fendit security update requires a system restart to complete.\n\n" +
			"Click Yes to restart now, or No to be reminded later."
	}

	title, _ := windows.UTF16PtrFromString("Fendit Security — Restart Required")
	msg, _ := windows.UTF16PtrFromString(msgText)

	const mbYesNo       = 0x00000004
	const mbIconWarning = 0x00000030

	user32 := windows.NewLazyDLL("user32.dll")
	msgBoxW := user32.NewProc("MessageBoxW")
	ret, _, _ := msgBoxW.Call(
		0,
		uintptr(unsafe.Pointer(msg)),
		uintptr(unsafe.Pointer(title)),
		mbYesNo|mbIconWarning,
	)
	const idYes = 6
	return ret == idYes
}

// notifyRestartRecommended shows a toast banner when a restart becomes required.
func notifyRestartRecommended() {
	registerToastAppID()
	const script = `
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType=WindowsRuntime]
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml('<toast><visual><binding template="ToastGeneric"><text>Fendit Security</text><text>A restart is required to complete the Fendit security update.</text></binding></visual></toast>')
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('eu.fendit.agent').Show([Windows.UI.Notifications.ToastNotification]::new($xml))
`
	exec.Command("powershell", "-WindowStyle", "Hidden", "-NonInteractive", "-Command", script).Start() //nolint:errcheck
}

// executeRestart initiates a graceful restart with a 60-second countdown.
// The tray calls this after the user confirms.
func executeRestart() {
	exec.Command("shutdown", "/r", "/t", "60",
		"/c", "Fendit Security: restarting to complete a pending security update").Start() //nolint:errcheck
}

// forceRestart initiates a mandatory restart with a 5-minute countdown.
// Called after 5 tray dismissals past the 48-hour deadline.
func forceRestart() {
	exec.Command("shutdown", "/r", "/t", "300",
		"/c", "Fendit Security: restart required — security update pending. Computer restarts in 5 minutes.").Start() //nolint:errcheck
}
