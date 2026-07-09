//go:build darwin

package main

import (
	"embed"
	"fmt"
	"io/fs"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
)

//go:embed all:frontend/dist
var assets embed.FS

// daemonExe holds the fendit-agent binary written to disk during installation.
// build_all.sh places fendit-agent-mac (macOS arm64) in embedded/ before wails build runs.
//
//go:embed embedded/fendit-agent-mac
var daemonExe []byte

func main() {
	// Panic handler must be the first defer so it wraps everything that follows,
	// including wails.Run(). It fires a last-gasp telemetry POST before os.Exit.
	defer handleInstallerPanic()

	// Same rule as Windows: check elevation before wails.Run() so that if
	// os.Exit is needed, the WebKit/WebView2 host window has not yet been
	// created and there is no cleanup race.
	if !isAdmin() {
		relaunchAsAdmin()
		return // unreachable on success — relaunchAsAdmin calls os.Exit(0)
	}

	sub, err := fs.Sub(assets, "frontend/dist")
	if err != nil {
		fmt.Fprintf(os.Stderr, "fendit-installer: assets: %v\n", err)
		os.Exit(1)
	}
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
		Mac: &mac.Options{
			TitleBar:             mac.TitleBarHiddenInset(),
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
		},
		OnStartup: app.startup,
		Bind:      []interface{}{app},
	})
}
