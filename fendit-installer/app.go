//go:build windows

package main

import (
	_ "embed"

	"bytes"
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
	"runtime/debug"
	"strings"
	"syscall"
	"time"
)

//go:embed embedded/fendit-agent-win.exe
var daemonExe []byte

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

// ── App ────────────────────────────────────────────────────────────────────────

type App struct {
	// onProgress is called on every installation phase so the Fyne UI can update
	// its progress display in real time.  Set by runUI before calling Install.
	// Safe to call from any goroutine — Fyne widget updates are goroutine-safe.
	onProgress func(string)
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
	f, err := os.OpenFile(installLog, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		log = slog.New(slog.NewJSONHandler(f, &slog.HandlerOptions{Level: slog.LevelDebug}))
	} else {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &App{}
}

func (a *App) setProgress(msg string) {
	log.Info("phase", "msg", msg)
	writeCrashLog("phase: " + msg)
	if a.onProgress != nil {
		a.onProgress(msg)
	}
}

// OpenMacSettings is a no-op on Windows; mirrored in app_darwin.go where it
// opens the Full Disk Access pane.  Called from ui.go cross-platform.
func (a *App) OpenMacSettings() {}

// ── Install — single entry point called from the Fyne UI goroutine ────────────

// Install runs all seven installation phases and reports each to a.onProgress.
// Must be called in a goroutine — it blocks for several minutes on slow networks.
// Returns nil on success, a user-visible error on any failure.
func (a *App) Install(code string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			go ReportInstallFailure("panic in Install", fmt.Errorf("%v\n%s", r, stack))
			err = fmt.Errorf("unexpected internal error — our team has been notified")
		}
	}()

	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 6 {
		return fmt.Errorf("code must be exactly 6 characters")
	}

	hostname, _ := os.Hostname()
	log.Info("installation started", "code", code, "hostname", hostname)
	writeCrashLog("Install() entered, code=" + code)

	// ── Phase 0: Defender exclusions — must run before any file writes ────────
	a.setProgress("Configuring security co-existence...")
	addDefenderExclusions()

	// ── Phase 1: API activation ───────────────────────────────────────────────
	a.setProgress("Connecting to Fendit cloud...")
	act, err := a.callActivate(code, hostname)
	if err != nil {
		log.Error("API activation failed", "err", err)
		return fmt.Errorf("activation failed: %w", err)
	}
	log.Info("activation OK", "org", act.OrganizationName, "session", act.SessionID)

	// ── Phase 2: Download Wazuh MSI ───────────────────────────────────────────
	a.setProgress("Downloading security components...")
	// Download into the already-excluded fenditDir so Defender never scans the
	// MSI as it lands on disk (os.TempDir() is unexcluded and gets scanned).
	msiPath := filepath.Join(fenditDir, "fendit_wazuh.msi")
	if err := a.downloadMSI(msiPath, act.AgentURL); err != nil {
		log.Error("download failed", "err", err)
		a.rollback(act)
		go ReportInstallFailure("Wazuh MSI download failed", err)
		return fmt.Errorf("download failed: %w", err)
	}
	defer os.Remove(msiPath)

	// ── Phase 3: Remove stale Wazuh install ──────────────────────────────────
	if isWazuhInstalled() {
		a.setProgress("Removing previous installation...")
		if err := uninstallWazuh(); err != nil {
			log.Warn("prior Wazuh uninstall failed (continuing)", "err", err)
		}
	}

	// ── Phase 4: Silent MSI install ───────────────────────────────────────────
	a.setProgress("Installing security agent...")
	if err := a.installMSI(msiPath); err != nil {
		log.Error("MSI install failed", "err", err)
		a.rollback(act)
		go ReportInstallFailure("Wazuh MSI install failed (msiexec)", err)
		return fmt.Errorf("installation failed\nLog: %s\n\nDetails: %w", msiLog, err)
	}

	// ── Phase 5: Register with Wazuh manager ─────────────────────────────────
	a.setProgress("Registering with security cloud...")
	if act.WazuhManager != "" {
		a.registerWazuhAgent(act)
	}

	// ── Phase 6: Save config + deploy daemon ──────────────────────────────────
	a.setProgress("Finalising setup...")
	apiBase := act.APIBase
	if apiBase == "" {
		apiBase = defaultAPIBase
	}
	if err := saveConfig(act.AgentToken, apiBase, act.OrganizationName); err != nil {
		log.Error("config save failed", "err", err)
		a.rollback(act)
		go ReportInstallFailure("config persistence failed", err)
		return fmt.Errorf("setup failed: %w", err)
	}
	if err := a.deployDaemon(); err != nil {
		log.Warn("daemon deploy failed (non-fatal)", "err", err)
	}

	// ── Phase 7: Confirm success to backend + start Wazuh ────────────────────
	a.setProgress("Activating protection...")
	a.confirm(act)

	startWazuh := exec.Command("sc.exe", "start", "Wazuh")
	startWazuh.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	startWazuh.Run() //nolint:errcheck

	log.Info("installation complete")
	writeCrashLog("Install() complete — success")
	return nil
}

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

func (a *App) deployDaemon() error {
	dest := agentBinDst
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return fmt.Errorf("create agent dir: %w", err)
	}
	if err := os.WriteFile(dest, daemonExe, 0755); err != nil {
		return fmt.Errorf("write agent binary: %w", err)
	}
	if err := installWindowsService(dest); err != nil {
		log.Warn("service registration failed (non-fatal)", "err", err)
	}
	if err := registerProtocolHandler(dest); err != nil {
		log.Warn("protocol handler registration failed (non-fatal)", "err", err)
	}
	if err := setRunKey(dest); err != nil {
		log.Warn("Run key registration failed (non-fatal)", "err", err)
	}
	tray := exec.Command(dest, "--tray")
	tray.SysProcAttr = &syscall.SysProcAttr{HideWindow: false}
	tray.Start() //nolint:errcheck
	return nil
}

// ── Config persistence ────────────────────────────────────────────────────────

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
	key := machineKey()
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
