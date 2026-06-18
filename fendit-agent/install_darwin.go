//go:build darwin

package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	fenditDir   = "/Library/Fendit"
	launchdDir  = "/Library/LaunchDaemons"
	launchAgDir = "/Library/LaunchAgents"
	agentBin    = "/usr/local/bin/fendit-agent"

	wazuhAuthBin    = "/Library/Ossec/bin/agent-auth"
	wazuhControlBin = "/Library/Ossec/bin/wazuh-control"
)

// install runs the full macOS onboarding sequence.
// act is the response from POST /api/v1/agent/activate — all credentials are
// already resolved; no network call is made from within install().
func install(act *ActivateResponse) error {
	fmt.Println("[*] Fendit onboarding gestart...")

	apiBase := act.APIBase
	if apiBase == "" {
		apiBase = defaultAPIBase
	}

	// 1. Download Wazuh package.
	wazuhPkg := "/tmp/fendit_agent.pkg"
	fmt.Printf("[*] Downloaden Fendit Agent van %s...\n", act.AgentURL)
	if err := downloadFile(wazuhPkg, act.AgentURL); err != nil {
		return fmt.Errorf("download wazuh: %w", err)
	}
	defer os.Remove(wazuhPkg)

	// 2. Base install — credentials are never passed as env/CLI args to the
	//    installer; agent-auth handles secure Wazuh manager registration below.
	fmt.Println("[*] Starten basisinstallatie...")
	if out, err := exec.Command("/usr/sbin/installer", "-pkg", wazuhPkg, "-target", "/").
		CombinedOutput(); err != nil {
		return fmt.Errorf("wazuh install: %w\n%s", err, out)
	}

	// 2a. Register the agent with the Wazuh manager via agent-auth.
	if act.WazuhManager != "" {
		fmt.Printf("[*] Registreren bij Wazuh manager %s (groep: %s)...\n",
			act.WazuhManager, act.InstallGroup)
		authArgs := []string{"-m", act.WazuhManager}
		if act.InstallGroup != "" {
			authArgs = append(authArgs, "-G", act.InstallGroup)
		}
		if out, err := exec.Command(wazuhAuthBin, authArgs...).CombinedOutput(); err != nil {
			fmt.Printf("[!] agent-auth mislukt (niet-fataal): %v\n%s\n", err, out)
		} else {
			fmt.Println("[*] Wazuh agent succesvol geregistreerd.")
		}
	}

	// 3. Save encrypted config.
	if err := os.MkdirAll(filepath.Join(fenditDir, "config"), 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := saveConfig(&Config{
		ReflexToken: act.AgentToken,
		APIBase:     apiBase,
		OrgName:     act.OrganizationName,
	}); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	exec.Command("chmod", "750", fenditDir).Run()             //nolint:errcheck
	exec.Command("chown", "-R", "root:wheel", fenditDir).Run() //nolint:errcheck

	// 5. Honeypot + instant network severance reflex.
	fmt.Println("[*] Configureren Honeypot & Local Trigger...")
	if err := setupHoneypot(); err != nil {
		fmt.Printf("[!] Honeypot setup gefaald (niet-fataal): %v\n", err)
	}

	// 6. Register the Go binary as the main agent daemon + tray agent.
	if err := installLaunchDaemons(); err != nil {
		return fmt.Errorf("install launch daemons: %w", err)
	}

	// 7. Start Wazuh (telemetry ingest only — no active-response scripts deployed).
	exec.Command(wazuhControlBin, "start").Run() //nolint:errcheck

	fmt.Println("[SUCCESS] Mac Onboarding afgerond.")
	openBrowser(portalURL)
	return nil
}

// downloadFile streams url to dst path.
func downloadFile(dst, url string) error {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func setupHoneypot() error {
	honeypotDir := "/Users/Shared/Confidential_Passwords"
	if err := os.MkdirAll(honeypotDir, 0777); err != nil {
		return err
	}
	os.WriteFile(honeypotDir+"/database_credentials.txt", //nolint:errcheck
		[]byte("admin_db: supersecret123\n"), 0644)
	exec.Command("chmod", "-R", "777", honeypotDir).Run() //nolint:errcheck

	// LaunchDaemon watching the honeypot dir.
	// On trigger launchd calls the Go binary --reflex honeypot, which severs the
	// network and posts telemetry — no bash script ever touches the token.
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>eu.fendit.honeypot</string>
  <key>ProgramArguments</key><array>
    <string>%s</string>
    <string>--reflex</string>
    <string>honeypot</string>
  </array>
  <key>WatchPaths</key><array>
    <string>/Users/Shared/Confidential_Passwords</string>
  </array>
  <key>RunAtLoad</key><false/>
</dict></plist>`, agentBin)

	plistPath := filepath.Join(launchdDir, "eu.fendit.honeypot.plist")
	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return err
	}
	exec.Command("launchctl", "load", plistPath).Run() //nolint:errcheck
	return nil
}

// installLaunchDaemons installs the main agent LaunchDaemon and the tray LaunchAgent.
// The PKG payload already copied the binary to agentBin before postinstall runs.
func installLaunchDaemons() error {
	// Main daemon — runs as root at boot, KeepAlive.
	agentPlist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>eu.fendit.agent</string>
  <key>ProgramArguments</key><array>
    <string>%s</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/Library/Fendit/agent.log</string>
  <key>StandardErrorPath</key><string>/Library/Fendit/agent.log</string>
</dict></plist>`, agentBin)

	agentPlistPath := filepath.Join(launchdDir, "eu.fendit.agent.plist")
	if err := os.WriteFile(agentPlistPath, []byte(agentPlist), 0644); err != nil {
		return fmt.Errorf("write agent plist: %w", err)
	}
	exec.Command("launchctl", "load", agentPlistPath).Run() //nolint:errcheck

	// Tray agent — runs as the console user, shows menu-bar icon.
	os.MkdirAll(launchAgDir, 0755) //nolint:errcheck
	trayPlist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>eu.fendit.tray</string>
  <key>ProgramArguments</key><array>
    <string>%s</string>
    <string>--tray</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>`, agentBin)

	trayPlistPath := filepath.Join(launchAgDir, "eu.fendit.tray.plist")
	if err := os.WriteFile(trayPlistPath, []byte(trayPlist), 0644); err != nil {
		return fmt.Errorf("write tray plist: %w", err)
	}
	exec.Command("launchctl", "load", trayPlistPath).Run() //nolint:errcheck

	return nil
}
