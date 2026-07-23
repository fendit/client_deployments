//go:build darwin

package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// fenditTheme is a custom Fyne theme with the Fendit brand palette:
// deep navy background, indigo primary, near-white text.
type fenditTheme struct{}

var _ fyne.Theme = fenditTheme{}

// Brand colour palette — shared with ui.go for canvas object colouring.
var (
	colBackground  = color.NRGBA{R: 0x0B, G: 0x0D, B: 0x14, A: 0xFF} // #0B0D14
	colSurface     = color.NRGBA{R: 0x13, G: 0x16, B: 0x1E, A: 0xFF} // #13161E
	colPrimary     = color.NRGBA{R: 0x4F, G: 0x46, B: 0xE5, A: 0xFF} // #4F46E5 indigo
	colPrimaryGlow = color.NRGBA{R: 0x4F, G: 0x46, B: 0xE5, A: 0x28} // #4F46E5 @ 16%
	colForeground  = color.NRGBA{R: 0xF0, G: 0xF2, B: 0xFF, A: 0xFF} // #F0F2FF
	colMuted       = color.NRGBA{R: 0x6B, G: 0x70, B: 0x85, A: 0xFF} // #6B7085
	colBorder      = color.NRGBA{R: 0x2A, G: 0x2D, B: 0x3E, A: 0xFF} // #2A2D3E
	colInputBg     = color.NRGBA{R: 0x1A, G: 0x1D, B: 0x28, A: 0xFF} // #1A1D28
	colSuccess     = color.NRGBA{R: 0x10, G: 0xB9, B: 0x81, A: 0xFF} // #10B981
	colError       = color.NRGBA{R: 0xEF, G: 0x44, B: 0x44, A: 0xFF} // #EF4444
	colWarning     = color.NRGBA{R: 0xF5, G: 0x9E, B: 0x0B, A: 0xFF} // #F59E0B
	colTransparent = color.NRGBA{A: 0x00}
)

func (fenditTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	switch n {
	case theme.ColorNameBackground:
		return colBackground
	case theme.ColorNameMenuBackground, theme.ColorNameOverlayBackground, theme.ColorNameHeaderBackground:
		return colSurface
	case theme.ColorNameButton, theme.ColorNameDisabledButton:
		return colSurface
	case theme.ColorNamePrimary, theme.ColorNameFocus:
		return colPrimary
	case theme.ColorNameHover:
		return colPrimaryGlow
	case theme.ColorNameForeground:
		return colForeground
	case theme.ColorNameDisabled:
		return colMuted
	case theme.ColorNamePlaceHolder:
		return colMuted
	case theme.ColorNameInputBackground:
		return colInputBg
	case theme.ColorNameInputBorder:
		return colBorder
	case theme.ColorNameSeparator:
		return colBorder
	case theme.ColorNameScrollBar:
		return colBorder
	case theme.ColorNameShadow:
		return colTransparent
	case theme.ColorNameSuccess:
		return colSuccess
	case theme.ColorNameError:
		return colError
	case theme.ColorNameWarning:
		return colWarning
	}
	return theme.DarkTheme().Color(n, v)
}

func (fenditTheme) Font(s fyne.TextStyle) fyne.Resource {
	return theme.DarkTheme().Font(s)
}

func (fenditTheme) Icon(n fyne.ThemeIconName) fyne.Resource {
	return theme.DarkTheme().Icon(n)
}

func (fenditTheme) Size(n fyne.ThemeSizeName) float32 {
	switch n {
	case theme.SizeNamePadding:
		return 10
	case theme.SizeNameInnerPadding:
		return 14
	case theme.SizeNameHeadingText:
		return 26
	case theme.SizeNameSubHeadingText:
		return 16
	case theme.SizeNameScrollBar:
		return 4
	}
	return theme.DarkTheme().Size(n)
}
