package main

import (
	_ "embed"
	"log"
	"os/exec"
	"runtime"

	"github.com/getlantern/systray"
)

//go:embed icon.ico
var fenditIcon []byte

const portalURL = "https://portal.fendit.eu"

func runTray() {
	systray.Run(onReady, onExit)
}

func onReady() {
	systray.SetIcon(fenditIcon)
	systray.SetTitle("Fendit")
	systray.SetTooltip("Fendit Security Agent — Protected")

	status := systray.AddMenuItem("Status: Protected", "Agent is active")
	status.Disable()

	interceptors := systray.AddMenuItem("Interceptors: Engaged", "Honeypot and downloads scanner are active")
	interceptors.Disable()

	systray.AddSeparator()

	dashboard := systray.AddMenuItem("Open Security Dashboard…", "View your security events")

	systray.AddSeparator()

	quit := systray.AddMenuItem("Quit UI", "Close the Fendit tray icon")

	go func() {
		for {
			select {
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
