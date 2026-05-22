package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// runReflex severs all network adapters immediately, then posts async telemetry.
// Called by launchd WatchPaths (macOS) or PowerShell FileSystemWatcher (Windows)
// when the honeypot directory is touched.
func runReflex(triggerType string) {
	cfg, err := loadConfig()
	if err != nil {
		log.Printf("reflex: cannot load config: %v", err)
		// Still sever the network even if config is unreadable.
	}

	host, _ := os.Hostname()
	ts := time.Now().UTC().Format(time.RFC3339)

	severNetwork()
	log.Printf("REFLEX: %s triggered — network severed on %s at %s", triggerType, host, ts)

	if cfg == nil {
		return
	}
	go func() {
		body := fmt.Sprintf(`{"trigger":%q,"host":%q,"ts":%q}`, triggerType, host, ts)
		req, err := http.NewRequest("POST", cfg.endpoint(pathReflex), strings.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Authorization", "Bearer "+cfg.ReflexToken)
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}()
	time.Sleep(3 * time.Second)
}

// severNetwork kills all active network adapters instantly.
func severNetwork() {
	switch runtime.GOOS {
	case "darwin":
		out, _ := exec.Command("networksetup", "-listallnetworkservices").Output()
		for _, svc := range strings.Split(string(out), "\n")[1:] {
			svc = strings.TrimSpace(svc)
			if svc != "" {
				exec.Command("networksetup", "-setnetworkserviceenabled", svc, "off").Run() //nolint:errcheck
			}
		}
	case "windows":
		exec.Command("powershell", "-NonInteractive", "-Command",
			`Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue`).Run() //nolint:errcheck
	}
}

// runDNSGuard re-applies the sinkhole DNS to all adapters.
func runDNSGuard() {
	cfg, err := loadConfig()
	if err != nil || cfg.MCPDnsIP == "" {
		return
	}
	switch runtime.GOOS {
	case "darwin":
		out, _ := exec.Command("networksetup", "-listallnetworkservices").Output()
		for _, svc := range strings.Split(string(out), "\n")[1:] {
			svc = strings.TrimSpace(svc)
			if svc != "" {
				exec.Command("networksetup", "-setdnsservers", svc, cfg.MCPDnsIP).Run() //nolint:errcheck
			}
		}
	case "windows":
		script := fmt.Sprintf(
			`Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses '%s' -ErrorAction SilentlyContinue }`,
			cfg.MCPDnsIP,
		)
		exec.Command("powershell", "-NonInteractive", "-Command", script).Run() //nolint:errcheck
	}
}

// runActionPoller polls /api/control/v1/actions/pending every 5 seconds and
// executes each intent via the safe ExecutionEngine (no shell eval, fixed arg lists).
// Runs as a persistent goroutine launched from daemonLoop.
func runActionPoller(cfg *Config) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	log.Println("action poller: started")

	for range ticker.C {
		intents, err := fetchPendingActions(cfg)
		if err != nil {
			log.Printf("action poller: fetch error: %v", err)
			continue
		}
		for _, intent := range intents {
			log.Printf("action poller: executing %s (id=%s)", intent.Action, intent.ID)
			result := intent.Execute()
			if result.Success {
				log.Printf("action poller: %s succeeded: %s", intent.Action, result.Output)
			} else {
				log.Printf("action poller: %s failed: %s", intent.Action, result.Error)
			}
			if err := postActionResult(cfg, result); err != nil {
				log.Printf("action poller: result post failed for %s: %v", intent.ID, err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Local YARA Watcher — "The Double Net"
//
// Watches every user's Downloads directory for new executables.
// When a file drops, runs the compiled mcp_rules.yarc (shipped via Wazuh
// shared folder) against it using the local yara binary.
// On a match: severs the network immediately and posts a yara_reflex alert.
// ---------------------------------------------------------------------------

// runLocalYaraWatcher starts fsnotify watchers on all user Downloads directories
// and dispatches YARA checks for any newly created executable-like file.
// Runs as a persistent goroutine launched from daemonLoop.
func runLocalYaraWatcher(cfg *Config) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("yara watcher: init failed: %v", err)
		return
	}
	defer watcher.Close()

	addDownloadsDirs(watcher)

	if len(watcher.WatchList()) == 0 {
		log.Println("yara watcher: no Downloads directories found — watcher idle")
		return
	}

	log.Printf("yara watcher: watching %d directories", len(watcher.WatchList()))

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			// Only react to file creation events for executable-like files.
			if event.Has(fsnotify.Create) && isExecutableLike(event.Name) {
				go handleYaraCheck(cfg, event.Name)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("yara watcher: error: %v", err)
		}
	}
}

// addDownloadsDirs enumerates user home directories and watches their Downloads folder.
func addDownloadsDirs(watcher *fsnotify.Watcher) {
	usersRoot := "/Users"
	if runtime.GOOS == "windows" {
		usersRoot = `C:\Users`
	}

	entries, err := os.ReadDir(usersRoot)
	if err != nil {
		log.Printf("yara watcher: cannot read %s: %v", usersRoot, err)
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Skip hidden dirs and well-known system accounts.
		if strings.HasPrefix(name, ".") || name == "Shared" || name == "Public" ||
			name == "Default" || name == "Default User" || name == "All Users" {
			continue
		}
		dlDir := filepath.Join(usersRoot, name, "Downloads")
		if _, err := os.Stat(dlDir); err == nil {
			if err := watcher.Add(dlDir); err != nil {
				log.Printf("yara watcher: cannot watch %s: %v", dlDir, err)
			} else {
				log.Printf("yara watcher: watching %s", dlDir)
			}
		}
	}
}

// handleYaraCheck runs yara against a newly created file and triggers network
// severance if a rule matches. Called in its own goroutine per file event.
func handleYaraCheck(cfg *Config, filePath string) {
	// Give the file writer a moment to finish flushing before we scan.
	time.Sleep(750 * time.Millisecond)

	rulesPath, compiled := yaraRulesPath()
	if rulesPath == "" {
		log.Printf("yara watcher: no rules file found — skipping %s", filePath)
		return
	}

	args := []string{rulesPath, filePath}
	if compiled {
		args = []string{"-C", rulesPath, filePath}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "yara", args...).CombinedOutput()

	result := strings.TrimSpace(string(out))

	// yara exits 0 with output on match, 0 with no output on clean.
	// Non-zero exit can mean an error (file unreadable, bad rules, etc.) — don't act.
	if err != nil || result == "" {
		return
	}

	log.Printf("yara watcher: MATCH in %s: %s", filePath, result)

	// Immediate response — sever network before the file can call home.
	severNetwork()

	host, _ := os.Hostname()
	ts := time.Now().UTC().Format(time.RFC3339)

	if cfg == nil {
		return
	}
	go func() {
		body := fmt.Sprintf(
			`{"trigger":"yara_reflex","host":%q,"ts":%q,"file":%q,"match":%q}`,
			host, ts, filePath, result,
		)
		req, err := http.NewRequest("POST", cfg.endpoint(pathReflex), strings.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Authorization", "Bearer "+cfg.ReflexToken)
		req.Header.Set("Content-Type", "application/json")
		(&http.Client{Timeout: 5 * time.Second}).Do(req) //nolint:errcheck
	}()
}

// yaraRulesPath returns the path to the YARA rules file (preferring compiled .yarc)
// and whether it is a compiled rules file (requiring yara -C flag).
func yaraRulesPath() (path string, compiled bool) {
	var base string
	switch runtime.GOOS {
	case "windows":
		base = `C:\Program Files (x86)\ossec-agent\shared\default\mcp_rules`
	default:
		base = "/Library/Ossec/etc/shared/default/mcp_rules"
	}
	if _, err := os.Stat(base + ".yarc"); err == nil {
		return base + ".yarc", true
	}
	if _, err := os.Stat(base + ".yar"); err == nil {
		return base + ".yar", false
	}
	return "", false
}

// isExecutableLike returns true for file extensions commonly used by malicious payloads.
func isExecutableLike(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".exe", ".dll", ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".js",
		".sh", ".py", ".rb", ".pl", ".jar", ".app", ".dmg", ".pkg":
		return true
	}
	// On Unix, also honour the executable bit (covers scripts with no extension).
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err == nil && info.Mode()&0111 != 0 {
			return true
		}
	}
	return false
}
