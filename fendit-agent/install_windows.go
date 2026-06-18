//go:build windows

package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/kardianos/service"
)

const (
	fenditDir   = `C:\ProgramData\Fendit`
	agentBinDst = `C:\Program Files\Fendit\fendit-agent.exe`

	// Wazuh 4.x installs to the (x86) path on both 32- and 64-bit Windows.
	wazuhAuthBin = `C:\Program Files (x86)\ossec-agent\agent-auth.exe`
	wazuhSvcName = "Wazuh"
)

// install runs the full Windows onboarding sequence.
// act is the response from POST /api/v1/agent/activate — all credentials are
// already resolved; no network call is made from within install().
func install(act *ActivateResponse) error {
	fmt.Println("[*] Fendit onboarding gestart...")

	apiBase := act.APIBase
	if apiBase == "" {
		apiBase = "https://api.fendit.eu"
	}

	// 1. Download Wazuh MSI.
	msiPath := filepath.Join(os.TempDir(), "fendit_agent.msi")
	fmt.Printf("[*] Downloaden Fendit Agent van %s...\n", act.AgentURL)
	if err := downloadFileWin(msiPath, act.AgentURL); err != nil {
		return fmt.Errorf("download wazuh: %w", err)
	}
	defer os.Remove(msiPath)

	// 2. Silent base install — no WAZUH_MANAGER or WAZUH_AGENT_GROUP MSI properties.
	//    Credentials are passed via agent-auth so they never appear in Event Log
	//    or process argument lists.
	fmt.Println("[*] Starten stille installatie...")
	if out, err := exec.Command("msiexec.exe", "/i", msiPath, "/qn").
		CombinedOutput(); err != nil {
		return fmt.Errorf("wazuh install: %w\n%s", err, out)
	}

	// 2a. Register the agent with the Wazuh manager via agent-auth.exe.
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

	// 3. Save encrypted config + restrict ACL.
	os.MkdirAll(filepath.Join(fenditDir, "config"), 0700) //nolint:errcheck
	if err := saveConfig(&Config{
		ReflexToken: act.AgentToken,
		APIBase:     apiBase,
		OrgName:     act.OrganizationName,
	}); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	restrictFenditACL()

	// 5. Honeypot + instant network severance reflex.
	fmt.Println("[*] Configureren Honeypot & Local Trigger...")
	if err := setupHoneypot(); err != nil {
		fmt.Printf("[!] Honeypot setup gefaald (niet-fataal): %v\n", err)
	}

	// 6. Copy binary to stable location + register as Windows service + tray Run key.
	if err := installSelf(); err != nil {
		return fmt.Errorf("install self: %w", err)
	}

	// 6a. Register fendit:// protocol handler so the portal deep-link works on this machine.
	if err := registerProtocolHandler(); err != nil {
		fmt.Printf("[!] Protocol handler registration failed (niet-fataal): %v\n", err)
	}

	// 7. Start Wazuh service (telemetry ingest only — no active-response scripts deployed).
	exec.Command("sc.exe", "start", wazuhSvcName).Run() //nolint:errcheck

	fmt.Println("[SUCCESS] Windows Onboarding afgerond.")
	openBrowser(portalURL)
	return nil
}

func downloadFileWin(dst, url string) error {
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

func restrictFenditACL() {
	// SYSTEM + Administrators full control, deny others.
	script := fmt.Sprintf(`
$acl = Get-Acl '%s'
$acl.SetAccessRuleProtection($true, $false)
foreach ($p in @("SYSTEM","Administrators")) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $p,"FullControl","ContainerInherit,ObjectInherit","None","Allow")
    $acl.AddAccessRule($rule)
}
Set-Acl -Path '%s' -AclObject $acl`, fenditDir, fenditDir)
	exec.Command("powershell", "-NonInteractive", "-Command", script).Run() //nolint:errcheck
}

func setupHoneypot() error {
	honeypotDir := `C:\Users\Public\Documents\Confidential_Passwords`
	os.MkdirAll(honeypotDir, 0755) //nolint:errcheck
	os.WriteFile(honeypotDir+`\database_credentials.txt`, //nolint:errcheck
		[]byte("admin_db: supersecret123\n"), 0644)

	// Scheduled task calls the Go binary --reflex honeypot via FileSystemWatcher.
	// A minimal PowerShell watcher calls the binary on file events — the token
	// is never exposed in the watcher script because the binary reads it from disk.
	guardScript := fmt.Sprintf(`
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path   = '%s'
$watcher.NotifyFilter = [IO.NotifyFilters]'LastAccess,LastWrite,FileName'
$watcher.IncludeSubdirectories = $false
$watcher.EnableRaisingEvents   = $true
$action = { & '%s' --reflex honeypot }
Register-ObjectEvent $watcher Changed -Action $action | Out-Null
Register-ObjectEvent $watcher Created -Action $action | Out-Null
while ($true) { Start-Sleep -Seconds 3600 }`, honeypotDir, agentBinDst)

	guardPath := fenditDir + `\honeypot_guard.ps1`
	os.WriteFile(guardPath, []byte(guardScript), 0600) //nolint:errcheck

	taskScript := fmt.Sprintf(
		`Register-ScheduledTask -TaskName 'Fendit-HoneypotGuard' -Force `+
			`-Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NonInteractive -WindowStyle Hidden -File "%s"') `+
			`-Trigger (New-ScheduledTaskTrigger -AtStartup) `+
			`-Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `+
			`-Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Days 365))`,
		guardPath,
	)
	exec.Command("powershell", "-NonInteractive", "-Command", taskScript).Run()         //nolint:errcheck
	exec.Command("powershell", "-NonInteractive", "-Command",                            //nolint:errcheck
		"Start-ScheduledTask -TaskName 'Fendit-HoneypotGuard'").Run()
	return nil
}

// installSelf copies the binary to its permanent location and registers it as a
// Windows Service (for the daemon) and a Run key entry (for the tray).
func installSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(agentBinDst), 0755) //nolint:errcheck
	if err := copyFile(exe, agentBinDst); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}

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
	s.Uninstall() //nolint:errcheck
	if err := s.Install(); err != nil {
		return fmt.Errorf("service install: %w", err)
	}
	s.Start() //nolint:errcheck

	regScript := fmt.Sprintf(
		`Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' `+
			`-Name 'FenditTray' -Value '"%s" --tray'`, agentBinDst)
	exec.Command("powershell", "-NonInteractive", "-Command", regScript).Run() //nolint:errcheck
	exec.Command(agentBinDst, "--tray").Start()                                //nolint:errcheck
	return nil
}

// registerProtocolHandler writes the HKEY_CLASSES_ROOT\fendit registry keys that
// tell Windows to invoke this binary with the URL as "%1" when a fendit:// link
// is clicked.  Must run after installSelf() so agentBinDst already exists.
func registerProtocolHandler() error {
	base := `HKEY_CLASSES_ROOT\fendit`
	openCmd := fmt.Sprintf(`"%s" "%%1"`, agentBinDst)

	// reg.exe creates intermediate keys automatically, so shell\open\command
	// in one call is sufficient; we add the root keys explicitly for clarity.
	cmds := [][]string{
		{"reg", "add", base, "/ve", "/d", "URL:Fendit Protocol", "/f"},
		{"reg", "add", base, "/v", "URL Protocol", "/d", "", "/f"},
		{"reg", "add", base + `\shell\open\command`, "/ve", "/d", openCmd, "/f"},
	}
	for _, args := range cmds {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("reg add %q: %w\n%s", args[2], err, out)
		}
	}
	return nil
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
