//go:build windows

package main

import (
	"embed"
	"io/fs"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

// daemonExe is the headless agent binary copied here by build_all.sh.
//
//go:embed fendit-agent-win.exe
var daemonExe []byte

func main() {
	sub, _ := fs.Sub(assets, "frontend/dist")
	app := NewApp()

	wails.Run(&options.App{ //nolint:errcheck
		Title:            "Fendit Security",
		Width:            450,
		Height:           600,
		DisableResize:    true,
		Frameless:        true,
		BackgroundColour: &options.RGBA{R: 15, G: 15, B: 24, A: 255},
		CSSDragProperty:  "--wails-draggable",
		CSSDragValue:     "drag",
		AssetServer: &assetserver.Options{
			Assets: sub,
		},
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
			DisableWindowIcon:    true,
		},
		OnStartup: app.startup,
		Bind:      []interface{}{app},
	})
}
