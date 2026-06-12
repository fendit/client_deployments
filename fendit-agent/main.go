package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
)

func main() {
	trayMode     := flag.Bool("tray",      false, "Run in system tray mode")
	reflexTrigger := flag.String("reflex", "",    "Fire a local reflex (honeypot)")
	dnsGuard     := flag.Bool("dns-guard", false, "Re-apply DNS sinkhole settings")
	flag.Parse()

	switch {
	case *trayMode:
		runTray()

	case *reflexTrigger != "":
		runReflex(*reflexTrigger)

	case *dnsGuard:
		runDNSGuard()

	case len(flag.Args()) > 0 && strings.HasPrefix(flag.Args()[0], "fendit://"):
		// Deep-link invocation — OS passes the URL as the first positional argument.
		// macOS: launched by LaunchServices when user clicks fendit:// link.
		// Windows: launched by the shell handler registered in HKEY_CLASSES_ROOT\fendit.
		// Expected format: fendit://onboard?domain=<domain>&session=<token>
		domain, session, err := parseDeepLink(flag.Args()[0])
		if err != nil {
			fatalDialog("Fendit Setup Error", err.Error())
			os.Exit(1)
		}
		if err := install(domain, session); err != nil {
			fatalDialog("Fendit Setup Error", fmt.Sprintf("Installation failed: %v", err))
			os.Exit(1)
		}

	case configExists():
		// Config already on disk — daemon/service invocation.
		runDaemon()

	default:
		fatalDialog("Fendit Setup", "Open the Fendit customer portal to start the installation.")
		os.Exit(1)
	}
}

// parseDeepLink extracts domain and session from a fendit:// deep-link URL.
// Expected format: fendit://onboard?domain=<domain>&session=<token>
func parseDeepLink(rawURL string) (domain, session string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid deep-link URL: %w", err)
	}
	if u.Scheme != "fendit" {
		return "", "", fmt.Errorf("unexpected URL scheme %q — expected fendit://", u.Scheme)
	}
	q := u.Query()
	domain = q.Get("domain")
	session = q.Get("session")
	if domain == "" {
		return "", "", fmt.Errorf("deep-link is missing the 'domain' parameter — re-open from the portal")
	}
	if len(session) < 8 {
		return "", "", fmt.Errorf("deep-link has an invalid 'session' parameter — re-open from the portal")
	}
	return domain, session, nil
}
