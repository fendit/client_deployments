//go:build darwin

package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	fenditDir   = "/Library/Fendit"
	launchdDir  = "/Library/LaunchDaemons"
	launchAgDir = "/Library/LaunchAgents"
	agentBin    = "/usr/local/bin/fendit-agent"
	yaraExec    = "/Library/Fendit/yara"

	wazuhAuthBin    = "/Library/Ossec/bin/agent-auth"
	wazuhControlBin = "/Library/Ossec/bin/wazuh-control"
)

func yaraExecPath() string { return yaraExec }

// install runs the full macOS onboarding sequence.
// act is the response from POST /api/v1/agent/activate — all credentials are
// already resolved; no network call is made from within install().
func install(act *ActivateResponse) error {
	apiBase := act.APIBase
	if apiBase == "" {
		apiBase = defaultAPIBase
	}

	rollback := func(err error) error {
		rollbackInstall(apiBase, act.SessionID)
		return err
	}

	// 1. Download Wazuh package.
	wazuhPkg := "/tmp/fendit_agent.pkg"
	fmt.Printf("[*] Downloading Fendit Agent from %s...\n", act.AgentURL)
	if err := downloadFile(wazuhPkg, act.AgentURL); err != nil {
		return rollback(fmt.Errorf("download wazuh: %w", err))
	}
	defer os.Remove(wazuhPkg)

	// 1a. Verify download integrity against Wazuh's published SHA512 checksum.
	if act.AgentChecksumURL != "" {
		fmt.Println("[*] Verifying package integrity (SHA512)...")
		if err := verifySHA512(wazuhPkg, act.AgentChecksumURL); err != nil {
			return rollback(fmt.Errorf("integrity check failed: %w", err))
		}
		fmt.Println("[*] Integrity check passed.")
	}

	// 2. Silent PKG install — credentials are never passed as env/CLI args.
	//    agent-auth handles secure Wazuh manager registration below.
	fmt.Println("[*] Running silent installer...")
	if out, err := exec.Command("/usr/sbin/installer", "-pkg", wazuhPkg, "-target", "/").
		CombinedOutput(); err != nil {
		return rollback(fmt.Errorf("wazuh install: %w\n%s", err, out))
	}

	// 2a. Register the agent with the Wazuh manager via agent-auth.
	if act.WazuhManager != "" {
		fmt.Printf("[*] Registering with Wazuh manager %s (group: %s)...\n",
			act.WazuhManager, act.InstallGroup)
		authArgs := []string{"-m", act.WazuhManager}
		if act.InstallGroup != "" {
			authArgs = append(authArgs, "-G", act.InstallGroup)
		}
		if out, err := exec.Command(wazuhAuthBin, authArgs...).CombinedOutput(); err != nil {
			fmt.Printf("[!] agent-auth failed (non-fatal): %v\n%s\n", err, out)
		} else {
			fmt.Println("[*] Wazuh agent registered.")
		}
	}

	// 2b. Download YARA scanning engine if the activation response includes a URL.
	//     Non-fatal: missing YARA disables local scanning but does not block onboarding.
	if act.YaraURL != "" {
		fmt.Println("[*] Downloading YARA scanning engine...")
		if err := downloadFile(yaraExec, act.YaraURL); err != nil {
			fmt.Printf("[!] YARA download failed (non-fatal): %v\n", err)
		} else {
			os.Chmod(yaraExec, 0755) //nolint:errcheck
			fmt.Println("[*] YARA engine installed.")
		}
	}

	// 3. Save encrypted config and lock down the config directory.
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
	// Lock fenditDir to root:wheel 750 via native Go calls — no exec.Command("chmod").
	os.Chmod(fenditDir, 0750)   //nolint:errcheck
	os.Chown(fenditDir, 0, 0)   //nolint:errcheck (root:wheel — GID 0 on macOS)

	// 4. Create honeypot decoy files in the watchable directory.
	fmt.Println("[*] Setting up honeypot...")
	if err := createHoneypotDecoys(); err != nil {
		fmt.Printf("[!] Honeypot decoy creation failed (non-fatal): %v\n", err)
	}

	// 5. Install launchd WatchPaths plist as a secondary honeypot trigger.
	//    The daemon's fsnotify watcher (runHoneypotWatcher) is the primary path;
	//    this plist re-invokes the binary if the daemon is restarting at trigger time.
	if err := setupHoneypotPlist(); err != nil {
		fmt.Printf("[!] Honeypot plist install failed (non-fatal): %v\n", err)
	}

	// 6. Install the agent LaunchDaemon and tray LaunchAgent.
	if err := installLaunchDaemons(); err != nil {
		return rollback(fmt.Errorf("install launch daemons: %w", err))
	}

	// 7. Start Wazuh (telemetry ingest only — no active-response scripts deployed).
	exec.Command(wazuhControlBin, "start").Run() //nolint:errcheck

	// 8. Mark endpoint active in the portal immediately (don't wait for first heartbeat).
	confirmInstall(apiBase, act.SessionID)

	fmt.Println("[SUCCESS] macOS installation complete.")
	openBrowser(portalURL)
	return nil
}

// downloadFile streams url to dst using a long timeout for large packages.
func downloadFile(dst, url string) error {
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url) //nolint:gosec
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

// setupHoneypotPlist installs a launchd WatchPaths daemon that invokes the
// agent with --reflex honeypot when the decoy directory is touched.
// This is the backup/secondary trigger; the primary is runHoneypotWatcher.
func setupHoneypotPlist() error {
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
    <string>%s</string>
  </array>
  <key>RunAtLoad</key><false/>
</dict></plist>`, agentBin, honeypotDir)

	plistPath := filepath.Join(launchdDir, "eu.fendit.honeypot.plist")
	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return err
	}
	exec.Command("launchctl", "bootstrap", "system", plistPath).Run() //nolint:errcheck
	return nil
}

// installLaunchDaemons installs the main agent LaunchDaemon (system, runs as
// root at boot) and the tray LaunchAgent (user-session, shows menu-bar icon).
func installLaunchDaemons() error {
	// Main daemon — runs as root at boot, KeepAlive restarts it if it exits.
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
	// Unload any stale instance (ignore error — may not be loaded).
	exec.Command("launchctl", "bootout", "system", agentPlistPath).Run() //nolint:errcheck
	exec.Command("launchctl", "bootstrap", "system", agentPlistPath).Run() //nolint:errcheck

	// Tray agent — runs in the logged-in user's session.
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

	// Bootstrap the tray agent in the current console user's session.
	consoleUser := consoleUsername()
	if consoleUser != "" && consoleUser != "root" {
		uid := consoleUID(consoleUser)
		if uid != "" {
			exec.Command("launchctl", "bootstrap", "user/"+uid, trayPlistPath).Run() //nolint:errcheck
		}
	}

	return nil
}

// consoleUsername returns the username of the currently logged-in console user.
func consoleUsername() string {
	out, err := exec.Command("stat", "-f", "%Su", "/dev/console").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// consoleUID returns the numeric UID string for a given username.
func consoleUID(username string) string {
	out, err := exec.Command("id", "-u", username).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
