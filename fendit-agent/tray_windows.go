//go:build windows

package main

import (
	_ "embed"

	"github.com/getlantern/systray"
)

//go:embed icon.ico
var fenditIconICO []byte

func setTrayIcon() {
	systray.SetIcon(fenditIconICO)
}
