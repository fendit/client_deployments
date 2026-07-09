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

// daemonExe is the headless agent binary placed in embedded/ by build_all.sh.
//
//go:embed embedded/fendit-agent-win.exe
var daemonExe []byte

func main() {
	// Panic handler must be the first defer so it wraps everything that follows,
	// including wails.Run(). It fires a last-gasp telemetry POST before os.Exit.
	defer handleInstallerPanic()

	// Elevation MUST be checked before wails.Run(). If os.Exit is called after
	// WebView2 has started, Chrome_WidgetWin_0 remains registered while its
	// HWND still exists; UnregisterClass in the WebView2 DLL teardown then
	// fails with ERROR_CLASS_HAS_WINDOWS (Win32 error 1412).
	if !isAdmin() {
		relaunchAsAdmin()
		return // unreachable on success — relaunchAsAdmin calls os.Exit(0)
	}

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
