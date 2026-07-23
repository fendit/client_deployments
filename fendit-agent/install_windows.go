//go:build windows

package main

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kardianos/service"
	"golang.org/x/sys/windows/registry"
)

const (
	fenditDir   = `C:\ProgramData\Fendit`
	agentBinDst = `C:\Program Files\Fendit\fendit-agent.exe`
	yaraExec    = `C:\Program Files\Fendit\yr.exe`

	wazuhAuthBin = `C:\Program Files (x86)\ossec-agent\agent-auth.exe`
	wazuhSvcName = "Wazuh"
)

func yaraExecPath() string { return yaraExec }

// install runs the full Windows onboarding sequence.
// act is the response from POST /api/v1/agent/activate — all credentials are
// already resolved; no network call is made from within install().
func install(act *ActivateResponse) error {
	fmt.Println("[*] Fendit onboarding gestart...")

	apiBase := act.APIBase
	if apiBase == "" {
		apiBase = defaultAPIBase
	}

	// rollback resets the activation code and removes the ghost endpoint record
	// when installation fails after the code has been burned.
	rollback := func(err error) error {
		rollbackInstall(apiBase, act.SessionID)
		return err
	}

	// 0. Configure Defender exclusions before anything touches disk.
	addDefenderExclusions()

	// 1. Download Wazuh MSI into the already-excluded fenditDir so Defender
	//    never scans it as it lands (os.TempDir() is unexcluded and gets scanned).
	os.MkdirAll(fenditDir, 0700) //nolint:errcheck
	msiPath := filepath.Join(fenditDir, "fendit_agent.msi")
	fmt.Printf("[*] Downloaden Fendit Agent van %s...\n", act.AgentURL)
	if err := downloadFileWin(msiPath, act.AgentURL); err != nil {
		return rollback(fmt.Errorf("download wazuh: %w", err))
	}
	defer os.Remove(msiPath)

	// 1a. Verify download integrity against Wazuh's published SHA512 checksum.
	if act.AgentChecksumURL != "" {
		fmt.Println("[*] Verificeren pakket integriteit (SHA512)...")
		if err := verifySHA512(msiPath, act.AgentChecksumURL); err != nil {
			return rollback(fmt.Errorf("integriteitscontrole mislukt: %w", err))
		}
		fmt.Println("[*] Integriteitscontrole geslaagd.")
	}

	// 2. Silent base install — credentials are passed via agent-auth so they
	//    never appear in the Event Log or process argument lists.
	fmt.Println("[*] Starten stille installatie...")
	msiCmd := exec.Command("msiexec.exe", "/i", msiPath, "/qn", "/norestart")
	msiCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := msiCmd.CombinedOutput(); err != nil {
		return rollback(fmt.Errorf("wazuh install: %w\n%s", err, out))
	}

	// 2a. Register with the Wazuh manager via agent-auth.exe.
	if act.WazuhManager != "" {
		fmt.Printf("[*] Registreren bij Wazuh manager %s (groep: %s)...\n",
			act.WazuhManager, act.InstallGroup)
		authArgs := []string{"-m", act.WazuhManager}
		if act.InstallGroup != "" {
			authArgs = append(authArgs, "-G", act.InstallGroup)
		}
		authCmd := exec.Command(wazuhAuthBin, authArgs...)
		authCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if out, err := authCmd.CombinedOutput(); err != nil {
			fmt.Printf("[!] agent-auth mislukt (niet-fataal): %v\n%s\n", err, out)
		} else {
			fmt.Println("[*] Wazuh agent succesvol geregistreerd.")
		}
	}

	// 2b. Download and install YARA scanning engine.
	//     Non-fatal: missing YARA disables local scanning but does not block onboarding.
	//     Windows release is a ZIP — extract the named binary from it.
	if act.YaraURL != "" {
		fmt.Println("[*] Downloaden YARA scan engine...")
		yaraTemp, err := downloadAndVerify(act.YaraURL, act.YaraSHA256)
		if err != nil {
			fmt.Printf("[!] YARA download mislukt (niet-fataal): %v\n", err)
		} else {
			os.MkdirAll(filepath.Dir(yaraExec), 0755) //nolint:errcheck
			var installErr error
			if strings.HasSuffix(strings.ToLower(act.YaraURL), ".zip") {
				extract := act.YaraExtract
				if extract == "" {
					extract = "yr.exe"
				}
				installErr = extractFromZip(yaraTemp, extract, yaraExec)
			} else {
				installErr = copyFile(yaraTemp, yaraExec)
			}
			os.Remove(yaraTemp) //nolint:errcheck
			if installErr != nil {
				fmt.Printf("[!] YARA installatie mislukt (niet-fataal): %v\n", installErr)
			} else {
				fmt.Println("[*] YARA scan engine geinstalleerd.")
			}
		}
	}

	// 3. Save encrypted config.
	os.MkdirAll(filepath.Join(fenditDir, "config"), 0700) //nolint:errcheck
	if err := saveConfig(&Config{
		ReflexToken: act.AgentToken,
		APIBase:     apiBase,
		OrgName:     act.OrganizationName,
	}); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	// 4. Lock down the Fendit data directory via the native Windows ACL API.
	//    No powershell.exe or icacls.exe is spawned (acl_windows.go).
	setFenditACL()

	// 5. Create decoy files for the honeypot watcher.
	//    No .ps1 scripts or scheduled tasks — the daemon's fsnotify goroutine
	//    provides persistent detection (honeypot_windows.go + daemon.go).
	fmt.Println("[*] Configureren Honeypot & Local Trigger...")
	if err := createHoneypotDecoys(); err != nil {
		fmt.Printf("[!] Honeypot decoy setup gefaald (niet-fataal): %v\n", err)
	}

	// 6. Copy binary to stable path, register as a Windows service, add Run key.
	if err := installSelf(); err != nil {
		return rollback(fmt.Errorf("install self: %w", err))
	}

	// 7. Register the fendit:// protocol handler.
	if err := registerProtocolHandler(); err != nil {
		fmt.Printf("[!] Protocol handler registration failed (niet-fataal): %v\n", err)
	}

	// 8. Start Wazuh (telemetry ingest only — no active-response scripts deployed).
	startWazuh := exec.Command("sc.exe", "start", wazuhSvcName)
	startWazuh.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	startWazuh.Run() //nolint:errcheck

	// 9. Mark endpoint active in the portal immediately (don't wait for first heartbeat).
	confirmInstall(apiBase, act.SessionID)

	fmt.Println("[SUCCESS] Windows Onboarding afgerond.")
	openBrowser(portalURL)
	return nil
}

// installSelf copies the agent binary to its permanent location, registers it
// as a Windows service via kardianos/service (SCM API — no sc.exe child
// process), and adds the tray Run key via the native registry API.
func installSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(agentBinDst), 0755) //nolint:errcheck
	if err := copyFile(exe, agentBinDst); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}

	// Register and start the Windows service using kardianos/service which
	// calls CreateService / StartService from advapi32.dll internally.
	svcConfig := &service.Config{
		Name:        "FenditAgent",
		DisplayName: "Fendit Security Agent",
		Description: "Fendit endpoint protection daemon",
		Executable:  agentBinDst,
	}
	s, err := service.New(&program{}, svcConfig)
	if err != nil {
		return fmt.Errorf("service init: %w", err)
	}
	s.Uninstall() //nolint:errcheck — idempotent; fails silently if not installed
	if err := s.Install(); err != nil {
		return fmt.Errorf("service install: %w", err)
	}
	s.Start() //nolint:errcheck

	// Write the Run key using the native registry API — no powershell.exe.
	if err := setFenditRunKey(agentBinDst); err != nil {
		fmt.Printf("[!] Run key registration failed (niet-fataal): %v\n", err)
	}

	// Launch the tray immediately for the current interactive session.
	// HideWindow is intentionally false — the tray icon is expected to appear.
	exec.Command(agentBinDst, "--tray").Start() //nolint:errcheck
	return nil
}

// setFenditRunKey adds FenditTray to HKCU\...\Run using the native Windows
// registry API. No powershell.exe or reg.exe child process is spawned.
func setFenditRunKey(exePath string) error {
	k, err := registry.OpenKey(
		registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE,
	)
	if err != nil {
		return fmt.Errorf("open Run key: %w", err)
	}
	defer k.Close()
	return k.SetStringValue("FenditTray", fmt.Sprintf(`"%s" --tray`, exePath))
}

// registerProtocolHandler writes the fendit:// URI scheme to HKEY_CLASSES_ROOT
// using the native registry API. No reg.exe child process is spawned.
func registerProtocolHandler() error {
	root, _, err := registry.CreateKey(registry.CLASSES_ROOT, `fendit`, registry.WRITE)
	if err != nil {
		return fmt.Errorf("create fendit key: %w", err)
	}
	defer root.Close()
	if err := root.SetStringValue("", "URL:Fendit Protocol"); err != nil {
		return err
	}
	if err := root.SetStringValue("URL Protocol", ""); err != nil {
		return err
	}

	cmd, _, err := registry.CreateKey(registry.CLASSES_ROOT, `fendit\shell\open\command`, registry.WRITE)
	if err != nil {
		return fmt.Errorf("create command key: %w", err)
	}
	defer cmd.Close()
	return cmd.SetStringValue("", fmt.Sprintf(`"%s" "%%1"`, agentBinDst))
}

// downloadFileWin streams url into dst using a long timeout suitable for large MSI packages.
func downloadFileWin(dst, url string) error {
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

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// extractFromZip extracts a single file by name from a ZIP archive into dst.
// Matches on the base filename so it works regardless of directory nesting inside the ZIP.
func extractFromZip(zipPath, filename, dst string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		if strings.EqualFold(filepath.Base(f.Name), filename) {
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("open zip entry: %w", err)
			}
			defer rc.Close()
			out, err := os.Create(dst)
			if err != nil {
				return fmt.Errorf("create dst: %w", err)
			}
			defer out.Close()
			_, err = io.Copy(out, rc)
			return err
		}
	}
	return fmt.Errorf("%s not found in zip", filename)
}
