package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	trayMode      := flag.Bool("tray",      false, "Run in system tray mode")
	reflexTrigger := flag.String("reflex",   "",    "Fire a local reflex (honeypot)")
	dnsGuard      := flag.Bool("dns-guard", false, "Re-apply DNS sinkhole settings")
	codeFlag      := flag.String("code",    "",    "Activation code for silent/RMM deployments (skips GUI dialog)")
	silentFlag    := flag.Bool("silent",    false, "Suppress non-critical console output (useful for RMM deployments)")
	flag.Parse()

	switch {
	case *trayMode:
		runTray()

	case *reflexTrigger != "":
		runReflex(*reflexTrigger)

	case *dnsGuard:
		runDNSGuard()

	case configExists():
		// Config already on disk — service/daemon invocation after successful install.
		runDaemon()

	case *codeFlag != "":
		// Silent mode: activation code supplied on the CLI (RMM/enterprise deployments).
		runSilentActivation(*codeFlag, *silentFlag)

	default:
		// No config, no --code flag — first run. Launch the interactive setup dialog.
		runActivationSetup()
	}
}

// runSilentActivation handles RMM and enterprise deployments where the activation
// code is passed directly via --code. No GUI dialogs are shown at any point.
// Any failure writes to stderr and exits with code 1 so the RMM tool can detect it.
func runSilentActivation(code string, silent bool) {
	hostname, _ := os.Hostname()
	code = strings.TrimSpace(strings.ToUpper(code))

	if len(code) != 6 {
		fmt.Fprintf(os.Stderr, "[ERROR] --code must be exactly 6 characters, got %d\n", len(code))
		os.Exit(1)
	}

	if !silent {
		fmt.Printf("[*] Fendit silent activation starting (code: %s, host: %s)\n", code, hostname)
	}

	act, err := activateAgent(code, hostname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Activation failed: %v\n", err)
		os.Exit(1)
	}

	if !silent {
		fmt.Printf("[*] Activation succeeded for organization: %s\n", act.OrganizationName)
	}

	if err := install(act); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Installation failed: %v\n", err)
		os.Exit(1)
	}
}

// runActivationSetup prompts the user interactively for a 6-character activation
// code, exchanges it with Guardian for a persistent agent token, then runs the
// platform installer. Allows up to 3 attempts so the user can correct a mistyped
// code without re-running the installer.
func runActivationSetup() {
	hostname, _ := os.Hostname()

	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		code := inputDialog(
			"Fendit Activation",
			"Enter your 6-character activation code.\n\n"+
				"Generate a code at portal.fendit.eu → Devices → Add Device.",
		)
		code = strings.TrimSpace(strings.ToUpper(code))

		if code == "" {
			// User cancelled the dialog — exit gracefully without error.
			os.Exit(0)
		}

		if len(code) != 6 {
			fatalDialog(
				"Invalid activation code",
				"An activation code is exactly 6 characters.\n"+
					"Check the code in the Fendit portal and try again.",
			)
			continue
		}

		act, err := activateAgent(code, hostname)
		if err != nil {
			fatalDialog(
				"Activation Failed",
				fmt.Sprintf(
					"Could not activate this device.\n\nError: %v\n\n"+
						"Generate a new code at portal.fendit.eu and try again.",
					err,
				),
			)
			continue
		}

		if err := install(act); err != nil {
			fatalDialog(
				"Fendit Installation Failed",
				fmt.Sprintf(
					"Installation could not be completed.\n\nError: %v\n\n"+
						"Contact support@fendit.eu for assistance.",
					err,
				),
			)
			os.Exit(1)
		}
		return
	}

	fatalDialog(
		"Too many attempts",
		"The maximum number of activation attempts has been reached.\n"+
			"Please restart the installer.",
	)
	os.Exit(1)
}
