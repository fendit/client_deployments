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
			"Fendit Activatie",
			"Voer uw 6-tekens activatiecode in.\n\n"+
				"Genereer een code via portal.fendit.eu → Apparaten → Apparaat Toevoegen.",
		)
		code = strings.TrimSpace(strings.ToUpper(code))

		if code == "" {
			// User cancelled the dialog — exit gracefully without error.
			os.Exit(0)
		}

		if len(code) != 6 {
			fatalDialog(
				"Ongeldige activatiecode",
				"Een activatiecode bestaat uit precies 6 tekens.\n"+
					"Controleer de code in het Fendit portaal en probeer opnieuw.",
			)
			continue
		}

		act, err := activateAgent(code, hostname)
		if err != nil {
			fatalDialog(
				"Activatie Mislukt",
				fmt.Sprintf(
					"Kon het apparaat niet activeren.\n\nFout: %v\n\n"+
						"Genereer een nieuwe code via portal.fendit.eu en probeer opnieuw.",
					err,
				),
			)
			continue
		}

		if err := install(act); err != nil {
			fatalDialog(
				"Fendit Installatie Mislukt",
				fmt.Sprintf(
					"Installatie kon niet worden voltooid.\n\nFout: %v\n\n"+
						"Neem contact op met support@fendit.eu",
					err,
				),
			)
			os.Exit(1)
		}
		return
	}

	fatalDialog(
		"Te veel pogingen",
		"Het maximum aantal activatiepogingen is bereikt.\n"+
			"Start het installatieprogramma opnieuw.",
	)
	os.Exit(1)
}
