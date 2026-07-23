//go:build darwin

package main

import (
	_ "embed"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

//go:embed assets/fendit.png
var iconBytes []byte

// fixedImage wraps canvas.Image so that layouts honour a caller-specified
// minimum size rather than the raw image pixel dimensions.
type fixedImage struct {
	*canvas.Image
	minSz fyne.Size
}

func (i *fixedImage) MinSize() fyne.Size { return i.minSz }

// runUI creates the Fyne application window and blocks until it is closed.
// Must be called from the main goroutine (ShowAndRun is blocking).
func runUI() {
	fyneApp := app.NewWithID("eu.fendit.installer")
	fyneApp.Settings().SetTheme(fenditTheme{})

	iconRes := fyne.NewStaticResource("fendit.png", iconBytes)

	w := fyneApp.NewWindow("Fendit Security")
	w.SetIcon(iconRes)
	w.Resize(fyne.NewSize(500, 660))
	w.SetFixedSize(true)
	w.CenterOnScreen()

	installer := NewApp()

	// ── Logo ──────────────────────────────────────────────────────────────────
	logo := &fixedImage{
		Image: canvas.NewImageFromResource(iconRes),
		minSz: fyne.NewSize(72, 76),
	}
	logo.FillMode = canvas.ImageFillContain

	// ── Headings ──────────────────────────────────────────────────────────────
	// canvas.Text is used for non-standard font sizes; VBox gives it the full
	// window width so TextAlignCenter renders it centred.
	heading := canvas.NewText("FENDIT", colForeground)
	heading.TextSize = 28
	heading.TextStyle = fyne.TextStyle{Bold: true}
	heading.Alignment = fyne.TextAlignCenter

	tagline := canvas.NewText("Security Agent Installer", colMuted)
	tagline.TextSize = 13
	tagline.Alignment = fyne.TextAlignCenter

	// ── Code entry ────────────────────────────────────────────────────────────
	codeLabel := widget.NewLabel("Activation Code")
	codeLabel.TextStyle = fyne.TextStyle{Bold: true}

	codeEntry := widget.NewEntry()
	codeEntry.SetPlaceHolder("Enter 6-character code  (e.g. A1B2C3)")
	codeEntry.OnChanged = func(s string) {
		if up := strings.ToUpper(s); up != s {
			codeEntry.SetText(up)
		}
	}

	hintLabel := widget.NewLabel("Provided by your IT administrator")
	hintLabel.Importance = widget.LowImportance

	// ── Progress area ─────────────────────────────────────────────────────────
	spinner := widget.NewProgressBarInfinite()
	spinner.Hide()

	var logLines []string
	logLabel := widget.NewLabel("")
	logLabel.Wrapping = fyne.TextWrapWord
	logLabel.TextStyle = fyne.TextStyle{Monospace: true}
	logScroll := container.NewScroll(logLabel)
	logScroll.SetMinSize(fyne.NewSize(440, 140))
	logScroll.Hide()

	statusLabel := widget.NewLabel("")
	statusLabel.Wrapping = fyne.TextWrapWord
	statusLabel.Alignment = fyne.TextAlignCenter

	// macOS only: shown when Install() returns the "fda_required" sentinel.
	openSettingsBtn := widget.NewButton("Open Security & Privacy Settings", func() {
		installer.OpenMacSettings()
	})
	openSettingsBtn.Hide()

	// ── Install button ────────────────────────────────────────────────────────
	var installBtn *widget.Button
	installBtn = widget.NewButton("Activate & Install", func() {
		code := strings.TrimSpace(codeEntry.Text)
		if len(code) != 6 {
			statusLabel.SetText("Code must be exactly 6 characters.")
			statusLabel.Importance = widget.DangerImportance
			statusLabel.Refresh()
			return
		}

		// Reset UI for a fresh run.
		logLines = nil
		logLabel.SetText("")
		statusLabel.SetText("")
		statusLabel.Importance = widget.MediumImportance
		statusLabel.Refresh()
		openSettingsBtn.Hide()
		spinner.Show()
		logScroll.Show()
		installBtn.Disable()
		codeEntry.Disable()

		installer.onProgress = func(msg string) {
			logLines = append(logLines, "→  "+msg)
			logLabel.SetText(strings.Join(logLines, "\n"))
			logScroll.ScrollToBottom()
		}

		go func() {
			err := installer.Install(code)

			spinner.Hide()
			installBtn.Enable()
			codeEntry.Enable()

			if err != nil {
				logLines = append(logLines, "✗  Installation failed.")
				logLabel.SetText(strings.Join(logLines, "\n"))

				if err.Error() == "fda_required" {
					statusLabel.SetText(
						"Full Disk Access is required.\n" +
							"Please grant access in System Settings, then click Install again.",
					)
					statusLabel.Importance = widget.WarningImportance
					statusLabel.Refresh()
					openSettingsBtn.Show()
				} else {
					statusLabel.SetText(err.Error())
					statusLabel.Importance = widget.DangerImportance
					statusLabel.Refresh()
				}
				return
			}

			logLines = append(logLines, "✓  Installation complete!")
			logLabel.SetText(strings.Join(logLines, "\n"))
			logScroll.ScrollToBottom()
			statusLabel.SetText("Fendit Security Agent is now protecting this device.")
			statusLabel.Importance = widget.SuccessImportance
			statusLabel.Refresh()

			installBtn.SetText("Close")
			installBtn.Importance = widget.LowImportance
			installBtn.OnTapped = func() { fyneApp.Quit() }
			installBtn.Refresh()
		}()
	})
	installBtn.Importance = widget.HighImportance

	// ── Card: form with branded background ────────────────────────────────────
	cardBg := canvas.NewRectangle(colSurface)
	cardBg.CornerRadius = 12
	cardBg.StrokeColor = colBorder
	cardBg.StrokeWidth = 1

	formContent := container.NewVBox(
		codeLabel,
		codeEntry,
		hintLabel,
		widget.NewSeparator(),
		installBtn,
	)

	formCard := container.NewStack(
		cardBg,
		container.NewPadded(formContent),
	)

	// ── Full layout ───────────────────────────────────────────────────────────
	content := container.NewVBox(
		container.NewCenter(logo),
		heading,
		tagline,
		widget.NewSeparator(),
		container.NewPadded(formCard),
		container.NewVBox(
			spinner,
			logScroll,
			statusLabel,
			openSettingsBtn,
		),
	)

	w.SetContent(container.NewPadded(content))
	w.ShowAndRun()
}
