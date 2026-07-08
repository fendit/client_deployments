//go:build darwin

package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// ── Constants ──────────────────────────────────────────────────────────────────

const (
	defaultAPIBase = "https://api.fendit.eu"
	pathActivate   = "/api/v1/agent/activate"
	pathConfirm    = "/api/v1/agent/confirm"
	pathRollback   = "/api/v1/agent/rollback"

	fenditDir    = "/Library/Fendit"
	fenditConfig = "/Library/Fendit/config"
	agentBinDst  = "/usr/local/bin/fendit-agent"
	launchdDir   = "/Library/LaunchDaemons"
	launchAgDir  = "/Library/LaunchAgents"
	honeypotDir  = "/Users/Shared/Backup"

	wazuhAuthBin = "/Library/Ossec/bin/agent-auth"
	wazuhCtlBin  = "/Library/Ossec/bin/wazuh-control"
	installLog   = "/Library/Fendit/install.log"
)

var (
	log            *slog.Logger
	apiClient      = &http.Client{Timeout: 30 * time.Second}
	downloadClient = &http.Client{Timeout: 10 * time.Minute}
)

// ── Wails App ─────────────────────────────────────────────────────────────────

type App struct {
	ctx context.Context
}

type ActivationResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type ActivateResponse struct {
	AgentToken       string `json:"agent_token"`
	SessionID        string `json:"session_id"`
	OrganizationName string `json:"organization_name"`
	WazuhManager     string `json:"agent_wazuh_manager"`
	InstallGroup     string `json:"install_group"`
	AgentURL         string `json:"agent_url"`
	APIBase          string `json:"api_base_url"`
}

func NewApp() *App {
	os.MkdirAll(fenditDir, 0700) //nolint:errcheck
	f, err := os.OpenFile(installLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		log = slog.New(slog.NewJSONHandler(f, &slog.HandlerOptions{Level: slog.LevelDebug}))
	} else {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	if !isAdmin() {
		log.Warn("not root — requesting elevation via osascript")
		relaunchAsAdmin() // elevation_darwin.go — standard macOS credential dialog
	}
}

func (a *App) emit(msg string) {
	log.Info("phase", "msg", msg)
	runtime.EventsEmit(a.ctx, "phase", msg)
}

// ── Activate — single entry point called from the frontend ───────────────────

// hasFDA probes the TCC database, which is readable only when Full Disk Access
// has been granted. Even root cannot open this file without FDA.
func hasFDA() bool {
	f, err := os.Open("/Library/Application Support/com.apple.TCC/TCC.db")
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func (a *App) Activate(code string) ActivationResult {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 6 {
		return ActivationResult{Error: "Code must be exactly 6 characters."}
	}

	// Full Disk Access is required for the agent to monitor protected paths.
	// Open the exact settings pane and let the frontend show the guidance screen.
	if !hasFDA() {
		exec.Command("open", "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles").Start() //nolint:errcheck
		return ActivationResult{Error: "fda_required"}
	}

	hostname, _ := os.Hostname()
	log.Info("activation started", "code", code, "hostname", hostname)

	// ── Phase 1: API activation ───────────────────────────────────────────────
	a.emit("Connecting to Fendit cloud...")
	act, err := a.callActivate(code, hostname)
	if err != nil {
		log.Error("API activation failed", "err", err)
		return ActivationResult{Error: "Activation failed: " + err.Error()}
	}
	log.Info("activation OK", "org", act.OrganizationName, "session", act.SessionID)

	// ── Phase 2: Download Wazuh PKG ───────────────────────────────────────────
	a.emit("Downloading security components...")
	pkgPath := filepath.Join(os.TempDir(), "fendit_wazuh.pkg")
	if err := a.downloadPKG(pkgPath, act.AgentURL); err != nil {
		log.Error("download failed", "err", err)
		a.rollback(act)
		return ActivationResult{Error: "Download failed: " + err.Error()}
	}
	defer os.Remove(pkgPath)

	// ── Phase 3: Remove stale Wazuh install if present ───────────────────────
	if isWazuhInstalled() { // wazuh_darwin.go — checks /Library/Ossec
		a.emit("Removing previous installation...")
		if err := uninstallWazuh(); err != nil { // wazuh_darwin.go — uninstall.sh or pkgutil
			log.Warn("prior Wazuh uninstall failed (continuing)", "err", err)
		}
	}

	// ── Phase 4: Silent PKG install ───────────────────────────────────────────
	a.emit("Installing security agent...")
	if err := a.installPKG(pkgPath); err != nil {
		log.Error("PKG install failed", "err", err)
		a.rollback(act)
		return ActivationResult{Error: fmt.Sprintf(
			"Installation failed.\n\nPlease send the log at:\n%s\nto support@fendit.eu\n\nDetails: %v",
			installLog, err,
		)}
	}

	// ── Phase 5: Register with Wazuh manager ─────────────────────────────────
	a.emit("Registering with security cloud...")
	if act.WazuhManager != "" {
		a.registerWazuhAgent(act)
	}

	// ── Phase 6: Save config + deploy daemon ──────────────────────────────────
	a.emit("Finalising setup...")
	apiBase := act.APIBase
	if apiBase == "" {
		apiBase = defaultAPIBase
	}
	if err := saveConfig(act.AgentToken, apiBase, act.OrganizationName); err != nil {
		log.Error("config save failed", "err", err)
		a.rollback(act)
		return ActivationResult{Error: "Setup failed: " + err.Error()}
	}
	if err := a.deployDaemon(); err != nil {
		log.Warn("daemon deploy failed (non-fatal)", "err", err)
	}

	// ── Phase 7: Confirm success to backend + start Wazuh ────────────────────
	a.emit("Activating protection...")
	a.confirm(act)
	exec.Command(wazuhCtlBin, "start").Run() //nolint:errcheck

	log.Info("installation complete")
	return ActivationResult{Success: true}
}

// OpenMacSettings opens the Full Disk Access pane in System Settings.
// Called from the frontend FDA screen as a fail-safe when the user closes the
// settings window that was auto-opened by the fda_required gate in Activate().
func (a *App) OpenMacSettings() {
	exec.Command("open", "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles").Start() //nolint:errcheck
}

// ── API calls ─────────────────────────────────────────────────────────────────

func (a *App) callActivate(code, hostname string) (*ActivateResponse, error) {
	body, _ := json.Marshal(map[string]string{
		"code": code, "hostname": hostname, "os": "darwin", "arch": goruntime.GOARCH,
	})
	resp, err := apiClient.Post(defaultAPIBase+pathActivate, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server %d: %s", resp.StatusCode, raw)
	}
	var act ActivateResponse
	if err := json.NewDecoder(resp.Body).Decode(&act); err != nil {
		return nil, fmt.Errorf("invalid response: %w", err)
	}
	log.Debug("activate response", "status", resp.StatusCode, "session", act.SessionID)
	return &act, nil
}

func (a *App) confirm(act *ActivateResponse) {
	if act.SessionID == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{"session_id": act.SessionID})
	resp, err := apiClient.Post(defaultAPIBase+pathConfirm, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Warn("confirm failed", "err", err)
		return
	}
	defer resp.Body.Close()
	log.Info("confirm OK", "status", resp.StatusCode)
}

func (a *App) rollback(act *ActivateResponse) {
	if act.SessionID == "" {
		return
	}
	log.Info("rolling back", "session_id", act.SessionID)
	body, _ := json.Marshal(map[string]string{"session_id": act.SessionID})
	resp, err := apiClient.Post(defaultAPIBase+pathRollback, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Warn("rollback request failed", "err", err)
		return
	}
	defer resp.Body.Close()
	log.Info("rollback OK", "status", resp.StatusCode)
}

// ── Install helpers ───────────────────────────────────────────────────────────

func (a *App) downloadPKG(dst, url string) error {
	resp, err := downloadClient.Get(url) //nolint:gosec
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, resp.Body)
	log.Debug("download complete", "bytes", n)
	return err
}

// installPKG runs /usr/sbin/installer for a fully silent PKG install.
// Equivalent to msiexec /qn on Windows — the process runs synchronously and
// the caller blocks until the installation is complete.
func (a *App) installPKG(pkgPath string) error {
	cmd := exec.Command("/usr/sbin/installer", "-pkg", pkgPath, "-target", "/")
	out, err := cmd.CombinedOutput()
	exitCode := -1
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	log.Info("installer finished", "exit_code", exitCode, "output", string(out))
	if err != nil {
		return fmt.Errorf("installer exit %d: %w", exitCode, err)
	}
	return nil
}

// registerWazuhAgent calls agent-auth to enrol this endpoint with the Wazuh manager.
func (a *App) registerWazuhAgent(act *ActivateResponse) {
	args := []string{"-m", act.WazuhManager}
	if act.InstallGroup != "" {
		args = append(args, "-G", act.InstallGroup)
	}
	out, err := exec.Command(wazuhAuthBin, args...).CombinedOutput()
	if err != nil {
		log.Warn("agent-auth failed (non-fatal)", "err", err, "output", string(out))
	} else {
		log.Info("agent-auth OK", "manager", act.WazuhManager)
	}
}

// deployDaemon writes the embedded agent binary, creates honeypot decoys,
// installs the launchd LaunchDaemon and LaunchAgent plists, and bootstraps the
// service — all without spawning shell scripts or sudo invocations.
// The installer already runs as root (relaunchAsAdmin in startup()).
func (a *App) deployDaemon() error {
	// Write the embedded agent binary.
	if err := os.MkdirAll(filepath.Dir(agentBinDst), 0755); err != nil {
		return fmt.Errorf("create agent dir: %w", err)
	}
	if err := os.WriteFile(agentBinDst, daemonExe, 0755); err != nil {
		return fmt.Errorf("write agent binary: %w", err)
	}

	// Create honeypot decoy files.
	if err := a.createHoneypotDecoys(); err != nil {
		log.Warn("honeypot decoy creation failed (non-fatal)", "err", err)
	}

	// Install the main agent LaunchDaemon.
	if err := a.installAgentPlist(); err != nil {
		return fmt.Errorf("install agent launchd: %w", err)
	}

	// Install the honeypot WatchPaths plist (secondary trigger).
	if err := a.installHoneypotPlist(); err != nil {
		log.Warn("honeypot plist install failed (non-fatal)", "err", err)
	}

	// Install and bootstrap the tray LaunchAgent for the console user.
	if err := a.installTrayPlist(); err != nil {
		log.Warn("tray plist install failed (non-fatal)", "err", err)
	}

	return nil
}

func (a *App) createHoneypotDecoys() error {
	if err := os.MkdirAll(honeypotDir, 0755); err != nil {
		return err
	}
	credsPayload := []byte(
		"AgBEAAAAA3NlY3JldAxrZXk6ZmVuZGl0LXNlY3VyZS1hcGkta2V5LTIwMjQtdjE" +
			"9b3BzLWJhY2t1cDpiYWNrdXAtcGFzc3dvcmQtc2VjdXJl",
	)
	os.WriteFile(honeypotDir+"/credentials.dat", credsPayload, 0644) //nolint:errcheck
	keysPayload := []byte(
		"[access_keys]\n" +
			"account=ops-backup\n" +
			"api_key=sk-live-x7f9Kp2mNqR4tJ8vBwL3eZ5\n" +
			"secret=dGhpcyBpcyBhIGZha2Ugc2VjcmV0IGtleQ==\n" +
			"created=2024-01-15\n",
	)
	os.WriteFile(honeypotDir+"/access_keys.txt", keysPayload, 0644) //nolint:errcheck
	return nil
}

func (a *App) installAgentPlist() error {
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
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
</dict></plist>`, agentBinDst)

	os.MkdirAll(launchdDir, 0755) //nolint:errcheck
	plistPath := filepath.Join(launchdDir, "eu.fendit.agent.plist")
	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return fmt.Errorf("write agent plist: %w", err)
	}
	exec.Command("launchctl", "bootout", "system", plistPath).Run() //nolint:errcheck — unload any stale instance
	return exec.Command("launchctl", "bootstrap", "system", plistPath).Run()
}

func (a *App) installHoneypotPlist() error {
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
</dict></plist>`, agentBinDst, honeypotDir)

	plistPath := filepath.Join(launchdDir, "eu.fendit.honeypot.plist")
	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return fmt.Errorf("write honeypot plist: %w", err)
	}
	exec.Command("launchctl", "bootstrap", "system", plistPath).Run() //nolint:errcheck
	return nil
}

func (a *App) installTrayPlist() error {
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
</dict></plist>`, agentBinDst)

	os.MkdirAll(launchAgDir, 0755) //nolint:errcheck
	plistPath := filepath.Join(launchAgDir, "eu.fendit.tray.plist")
	if err := os.WriteFile(plistPath, []byte(trayPlist), 0644); err != nil {
		return fmt.Errorf("write tray plist: %w", err)
	}
	// Bootstrap the tray in the console user's graphical session.
	if user := consoleUsername(); user != "" && user != "root" {
		if uid := consoleUID(user); uid != "" {
			exec.Command("launchctl", "bootstrap", "user/"+uid, plistPath).Run() //nolint:errcheck
		}
	}
	return nil
}

// consoleUsername returns the name of the currently logged-in console user.
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

// ── Config persistence ────────────────────────────────────────────────────────

// saveConfig persists the agent token (AES-256-GCM encrypted with the
// machine-derived key), API base URL, and organization name to disk.
// Writes to /Library/Fendit/config — the same path loadConfig() reads in the
// fendit-agent binary.
func saveConfig(token, apiBase, orgName string) error {
	if err := os.MkdirAll(fenditConfig, 0700); err != nil {
		return err
	}
	// Lock the config directory to root:wheel.
	os.Chmod(fenditConfig, 0700) //nolint:errcheck
	os.Chown(fenditConfig, 0, 0) //nolint:errcheck

	enc, err := encryptToken(token)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	writes := map[string]string{
		filepath.Join(fenditConfig, "token"):    enc,
		filepath.Join(fenditConfig, "api_base"): apiBase,
		filepath.Join(fenditConfig, "org"):      orgName,
	}
	for path, val := range writes {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		_, err = f.WriteString(val)
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func encryptToken(plaintext string) (string, error) {
	key := machineKey() // config_key_darwin.go — ioreg IOPlatformUUID
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}
