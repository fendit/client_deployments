package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	trayMode := flag.Bool("tray", false, "Run in system tray mode")
	reflexTrigger := flag.String("reflex", "", "Fire a local reflex (honeypot)")
	dnsGuard := flag.Bool("dns-guard", false, "Re-apply DNS sinkhole settings")
	installDomain := flag.String("install-domain", "", "Domain slug (set by macOS postinstall)")
	installToken := flag.String("install-token", "", "One-time install token (set by macOS postinstall)")
	flag.Parse()

	switch {
	case *trayMode:
		runTray()

	case *reflexTrigger != "":
		runReflex(*reflexTrigger)

	case *dnsGuard:
		runDNSGuard()

	case *installDomain != "" && *installToken != "":
		// Explicit flags — macOS PKG postinstall calls us this way.
		if err := install(*installDomain, *installToken); err != nil {
			fatalDialog("Fendit Setup Error", err.Error())
			os.Exit(1)
		}

	case configExists():
		// Config already on disk → this is a daemon/service invocation.
		runDaemon()

	default:
		// No config yet → parse own filename to get domain + token.
		// This path is hit when the user double-clicks the renamed .exe on Windows.
		domain, token, err := parseInstallTarget()
		if err != nil {
			fatalDialog("Fendit Setup Error", err.Error())
			os.Exit(1)
		}
		if err := install(domain, token); err != nil {
			fatalDialog("Fendit Setup Error", fmt.Sprintf("Installation failed: %v", err))
			os.Exit(1)
		}
	}
}

// parseInstallTarget reads the binary's own filename to extract domain + session token.
// Expected format: fendit_setup_<domain_slug>_<session_id>[.ext]
// Uses LastIndex so domain slugs with underscores (e.g. "co_uk") parse correctly.
func parseInstallTarget() (domain, token string, err error) {
	exe, err := os.Executable()
	if err != nil {
		return "", "", fmt.Errorf("cannot resolve executable path: %w", err)
	}
	base := filepath.Base(exe)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	base = strings.ToLower(base)

	const prefix = "fendit_setup_"
	if !strings.HasPrefix(base, prefix) {
		return "", "", fmt.Errorf(
			"this file must be named fendit_setup_<domain>_<token> — re-download from the portal")
	}
	rest := base[len(prefix):]
	idx := strings.LastIndex(rest, "_")
	if idx < 1 || idx == len(rest)-1 {
		return "", "", fmt.Errorf("cannot find domain/token separator — re-download from the portal")
	}
	domain = rest[:idx]
	token = rest[idx+1:]
	if len(token) < 8 {
		return "", "", fmt.Errorf("token is too short — re-download from the portal")
	}
	return domain, token, nil
}
