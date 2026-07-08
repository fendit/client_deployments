//go:build windows

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
	"strings"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// ── Constants ──────────────────────────────────────────────────────────────────

const (
	defaultAPIBase = "https://api.fendit.eu"
	pathActivate   = "/api/v1/agent/activate"
	pathConfirm    = "/api/v1/agent/confirm"
	pathRollback   = "/api/v1/agent/rollback"

	fenditDir    = `C:\ProgramData\Fendit`
	fenditConfig = `C:\ProgramData\Fendit\config`
	agentBinDst  = `C:\Program Files\Fendit\fendit-agent.exe`
	wazuhAuthBin = `C:\Program Files (x86)\ossec-agent\agent-auth.exe`
	installLog   = `C:\ProgramData\Fendit\install.log`
	msiLog       = `C:\Windows\Temp\fendit_wazuh_install.log`
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

// startup is called by Wails immediately after the window is created.
// If the process is not elevated we re-launch with UAC and exit; otherwise
// the installer continues normally.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	if !isAdmin() {
		log.Warn("not administrator — requesting elevation via ShellExecuteW runas")
		relaunchAsAdmin() // elevation_windows.go — no powershell.exe spawned
	}
}

func (a *App) emit(msg string) {
	log.Info("phase", "msg", msg)
	runtime.EventsEmit(a.ctx, "phase", msg)
}

// ── Activate — single entry point called from the frontend ───────────────────

func (a *App) Activate(code string) ActivationResult {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 6 {
		return ActivationResult{Error: "Code must be exactly 6 characters."}
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

	// ── Phase 2: Download Wazuh MSI ───────────────────────────────────────────
	a.emit("Downloading security components...")
	msiPath := filepath.Join(os.TempDir(), "fendit_wazuh.msi")
	if err := a.downloadMSI(msiPath, act.AgentURL); err != nil {
		log.Error("download failed", "err", err)
		a.rollback(act)
		return ActivationResult{Error: "Download failed: " + err.Error()}
	}
	defer os.Remove(msiPath)

	// ── Phase 3: Remove stale Wazuh install (prevents msiexec error 1603) ────
	if isWazuhInstalled() { // wazuh_windows.go — registry-based detection
		a.emit("Removing previous installation...")
		if err := uninstallWazuh(); err != nil { // wazuh_windows.go — no WMI/PS1
			log.Warn("prior Wazuh uninstall failed (continuing)", "err", err)
		}
	}

	// ── Phase 4: Silent MSI install ───────────────────────────────────────────
	a.emit("Installing security agent...")
	if err := a.installMSI(msiPath); err != nil {
		log.Error("MSI install failed", "err", err)
		a.rollback(act)
		return ActivationResult{Error: fmt.Sprintf(
			"Installation failed.\n\nPlease send the log file at:\n%s\nto support@fendit.eu\n\nDetails: %v",
			msiLog, err,
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

	startWazuh := exec.Command("sc.exe", "start", "Wazuh")
	startWazuh.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	startWazuh.Run() //nolint:errcheck

	log.Info("installation complete")
	return ActivationResult{Success: true}
}

// OpenMacSettings is a no-op on Windows; exists so Wails generates the JS
// binding for the darwin build where it opens the Full Disk Access settings pane.
func (a *App) OpenMacSettings() {}

// ── API calls ─────────────────────────────────────────────────────────────────

func (a *App) callActivate(code, hostname string) (*ActivateResponse, error) {
	body, _ := json.Marshal(map[string]string{
		"code": code, "hostname": hostname, "os": "windows", "arch": "amd64",
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

func (a *App) downloadMSI(dst, url string) error {
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

// installMSI runs a fully silent msiexec install. HideWindow: true prevents any
// CMD or progress window from flashing — a common EDR behavioural trigger.
func (a *App) installMSI(msiPath string) error {
	cmd := exec.Command(
		"msiexec.exe",
		"/i", msiPath,
		"/qn",
		"/norestart",
		"/L*V", msiLog,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	exitCode := -1
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	log.Info("msiexec finished", "exit_code", exitCode, "output", string(out), "log", msiLog)
	if err != nil {
		return fmt.Errorf("exit code %d (log: %s)", exitCode, msiLog)
	}
	return nil
}

// registerWazuhAgent calls agent-auth.exe to enroll the endpoint with the Wazuh
// manager. HideWindow: true prevents a console window from appearing.
func (a *App) registerWazuhAgent(act *ActivateResponse) {
	args := []string{"-m", act.WazuhManager}
	if act.InstallGroup != "" {
		args = append(args, "-G", act.InstallGroup)
	}
	cmd := exec.Command(wazuhAuthBin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Warn("agent-auth failed (non-fatal)", "err", err, "output", string(out))
	} else {
		log.Info("agent-auth OK", "manager", act.WazuhManager)
	}
}

// deployDaemon writes the embedded agent binary, registers it as a Windows
// service via the SCM API, and adds it to the current user's Run key — all
// without spawning powershell.exe, cmd.exe, or any shell script.
func (a *App) deployDaemon() error {
	dest := agentBinDst
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return fmt.Errorf("create agent dir: %w", err)
	}
	if err := os.WriteFile(dest, daemonExe, 0755); err != nil {
		return fmt.Errorf("write agent binary: %w", err)
	}

	// Register as a Windows service via the SCM API (registry_windows.go).
	// Non-fatal: a reboot will complete service registration on most failure modes.
	if err := installWindowsService(dest); err != nil {
		log.Warn("service registration failed (non-fatal)", "err", err)
	}

	// Register the fendit:// protocol handler (registry_windows.go).
	if err := registerProtocolHandler(dest); err != nil {
		log.Warn("protocol handler registration failed (non-fatal)", "err", err)
	}

	// Add FenditTray to the current user's Run key (registry_windows.go).
	if err := setRunKey(dest); err != nil {
		log.Warn("Run key registration failed (non-fatal)", "err", err)
	}

	// Launch the tray for the current interactive session immediately.
	// HideWindow is intentionally false — the tray icon is expected to appear.
	tray := exec.Command(dest, "--tray")
	tray.SysProcAttr = &syscall.SysProcAttr{HideWindow: false}
	tray.Start() //nolint:errcheck

	return nil
}

// ── Config persistence ────────────────────────────────────────────────────────

// saveConfig persists the agent token (AES-256-GCM encrypted with the
// machine-derived key), API base URL, and organization name to disk.
func saveConfig(token, apiBase, orgName string) error {
	if err := os.MkdirAll(fenditConfig, 0700); err != nil {
		return err
	}
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
	key := machineKey() // config_key_windows.go
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
