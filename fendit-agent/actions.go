package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	actionPollInterval = 5 * time.Second
	actionPollJitter   = 500 * time.Millisecond // random spread to avoid thundering herd
	backoffMin         = 10 * time.Second
	backoffMax         = 5 * time.Minute
	maxConcurrentActs  = 3 // semaphore cap for parallel intent execution
)

// runReflex is the CLI entry point for the --reflex flag, used when launchd
// WatchPaths (macOS) invokes the binary with "--reflex honeypot" on file-system
// activity. The trigger string is kept for future extensibility.
func runReflex(_ string) {
	cfg, _ := loadConfig() // nil cfg is handled gracefully by triggerHoneypotReflex
	triggerHoneypotReflex(cfg)
}

// triggerHoneypotReflex is the Code Red response to a confirmed honeypot access.
// It applies smart firewall isolation (all traffic blocked except outbound TCP 443)
// and then immediately sends telemetry to Guardian over the preserved control plane.
// smartIsolate() is defined per-platform in network_windows.go / network_darwin.go.
func triggerHoneypotReflex(cfg *Config) {
	host, _ := os.Hostname()
	ts := time.Now().UTC().Format(time.RFC3339)
	log.Printf("HONEYPOT REFLEX: triggered on %s at %s — activating smart isolation", host, ts)

	smartIsolate()

	// Bridge event to Wazuh via the local events.log (no hostname — Wazuh
	// already knows the agent identity from its own enrollment).
	appendEventToLog(fmt.Sprintf(`{"trigger":"honeypot","ts":%q}`, ts))
	appendEventToLog(fmt.Sprintf(`{"trigger":"isolate","reason":"honeypot","ts":%q}`, ts))

	if cfg == nil {
		return
	}
	postReflexTelemetry(cfg, fmt.Sprintf(
		`{"trigger":"honeypot","host":%q,"ts":%q}`,
		host, ts,
	))
}

// quarantineMatchedFile moves a YARA-matched file to the quarantine directory and
// locks it to SYSTEM-only access. The caller's network connection is not affected,
// so telemetry can be sent immediately after this call returns.
//
// The rename is retried every 100 ms for up to 2 s to handle the race where the
// OS holds an execution lock (ERROR_SHARING_VIOLATION / EBUSY) because the user
// double-clicked the file before the watcher fired.
func quarantineMatchedFile(path string) error {
	qDir := quarantineDir()
	if err := os.MkdirAll(qDir, 0700); err != nil {
		return fmt.Errorf("create quarantine dir: %w", err)
	}
	dst := filepath.Join(qDir, filepath.Base(path))

	var moveErr error
	deadline := time.Now().Add(2 * time.Second)
	for attempt := 1; time.Now().Before(deadline); attempt++ {
		if moveErr = os.Rename(path, dst); moveErr == nil {
			break
		}
		log.Printf("yara: quarantine rename attempt %d failed (retrying): %v", attempt, moveErr)
		time.Sleep(100 * time.Millisecond)
	}
	if moveErr != nil {
		return fmt.Errorf("move to quarantine (gave up after 2s): %w", moveErr)
	}

	if err := lockFilePermissions(dst); err != nil {
		return fmt.Errorf("lock permissions: %w", err)
	}
	return nil
}

// runActionPoller polls /api/control/v1/actions/pending on a jittered 5-second
// interval with exponential backoff on errors and a concurrency semaphore to
// prevent unbounded goroutine accumulation when actions are slow.
func runActionPoller(ctx context.Context, cfg *Config) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	sem := make(chan struct{}, maxConcurrentActs)
	var wg sync.WaitGroup
	backoff := backoffMin

	defer wg.Wait() // drain in-flight actions before returning

	log.Println("action poller: started")

	for {
		jitter := time.Duration(rng.Int63n(int64(actionPollJitter)))
		select {
		case <-ctx.Done():
			return
		case <-time.After(actionPollInterval + jitter):
		}

		intents, err := fetchPendingActions(cfg)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			log.Printf("action poller: fetch error (backoff %s): %v", backoff, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > backoffMax {
				backoff = backoffMax
			}
			continue
		}
		backoff = backoffMin // reset on success

		for _, intent := range intents {
			select {
			case sem <- struct{}{}: // acquire concurrency slot
			case <-ctx.Done():
				return
			}
			wg.Add(1)
			go func(i Intent) {
				defer func() {
					<-sem
					wg.Done()
					if r := recover(); r != nil {
						log.Printf("action poller: PANIC on intent %s: %v", i.ID, r)
					}
				}()
				log.Printf("action poller: executing %s (id=%s)", i.Action, i.ID)
				result := i.Execute()
				if result.Success {
					log.Printf("action poller: %s succeeded: %s", i.Action, result.Output)
				} else {
					log.Printf("action poller: %s failed: %s", i.Action, result.Error)
				}
				if err := postActionResult(cfg, result); err != nil {
					log.Printf("action poller: result post failed for %s: %v", i.ID, err)
				}
			}(intent)
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
// Runs as a persistent goroutine launched from startDaemon.
func runLocalYaraWatcher(ctx context.Context, cfg *Config) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("yara watcher: init failed: %v", err)
		return
	}
	defer watcher.Close()

	addWatchDirs(watcher)

	if len(watcher.WatchList()) == 0 {
		log.Println("yara watcher: no Downloads directories found — watcher idle")
		return
	}

	log.Printf("yara watcher: watching %d directories", len(watcher.WatchList()))

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			// Only react to file creation events for executable-like files.
			if event.Has(fsnotify.Create) && isExecutableLike(event.Name) {
				go handleYaraCheck(ctx, cfg, event.Name)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("yara watcher: error: %v", err)
		}
	}
}

// addWatchDirs enumerates per-user and system drop zones known to be used by
// phishing payloads and browser-triggered downloads, and registers each with
// the fsnotify watcher. Only the directory itself is watched (not recursive);
// fsnotify.Create events fire for any new file written directly inside.
func addWatchDirs(watcher *fsnotify.Watcher) {
	usersRoot := "/Users"
	sysTmp := "/tmp"
	if runtime.GOOS == "windows" {
		usersRoot = `C:\Users`
		sysTmp = `C:\Windows\Temp`
	}

	// System-wide temp — common landing zone for msiexec droppers and loaders.
	watchOne(watcher, sysTmp)

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
		if strings.HasPrefix(name, ".") || name == "Shared" || name == "Public" ||
			name == "Default" || name == "Default User" || name == "All Users" {
			continue
		}
		base := filepath.Join(usersRoot, name)

		var dirs []string
		if runtime.GOOS == "windows" {
			dirs = []string{
				filepath.Join(base, "Downloads"),
				filepath.Join(base, "Desktop"),
				// Browser and loader temp paths — the most common off-Downloads
				// drop zones for phishing payloads and drive-by downloads.
				filepath.Join(base, `AppData\Local\Temp`),
				filepath.Join(base, `AppData\Local\Microsoft\Windows\INetCache\IE`),
			}
		} else {
			dirs = []string{
				filepath.Join(base, "Downloads"),
				filepath.Join(base, "Desktop"),
				filepath.Join(base, "Library", "Caches"),
			}
		}

		for _, d := range dirs {
			watchOne(watcher, d)
		}
	}
}

// watchOne adds a single directory to the watcher, logging the outcome.
func watchOne(watcher *fsnotify.Watcher, dir string) {
	if _, err := os.Stat(dir); err != nil {
		return // does not exist — skip silently
	}
	if err := watcher.Add(dir); err != nil {
		log.Printf("yara watcher: cannot watch %s: %v", dir, err)
	} else {
		log.Printf("yara watcher: watching %s", dir)
	}
}

// handleYaraCheck runs yara against a newly created file and triggers network
// severance if a rule matches. Called in its own goroutine per file event.
func handleYaraCheck(ctx context.Context, cfg *Config, filePath string) {
	// Give the file writer a moment to finish flushing before we scan.
	time.Sleep(750 * time.Millisecond)

	rulesPath := yaraRulesPath()
	if rulesPath == "" {
		log.Printf("yara watcher: no rules file found — skipping %s", filePath)
		return
	}

	// yr scan <rules> <target> — auto-detects compiled (.yarc) vs source (.yar) format.
	args := []string{"scan", rulesPath, filePath}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, yaraExecPath(), args...).CombinedOutput()

	result := strings.TrimSpace(string(out))

	// yr exits 0 with output on match, 0 with no output on clean.
	// Non-zero exit can mean an error (file unreadable, bad rules, etc.) — don't act.
	if err != nil || result == "" {
		return
	}

	log.Printf("yara watcher: MATCH in %s: %s", filePath, result)

	// Quarantine the matched file immediately. The network stays up so that
	// telemetry reaches Guardian without delay — only the specific file is
	// neutralised, not the endpoint's connectivity.
	if err := quarantineMatchedFile(filePath); err != nil {
		log.Printf("yara watcher: quarantine failed for %s: %v", filePath, err)
	} else {
		log.Printf("yara watcher: quarantined %s → %s", filePath, quarantineDir())
	}

	ts := time.Now().UTC().Format(time.RFC3339)

	// Bridge each matched rule to Wazuh as an individual JSON event so that
	// local_rules.xml rule 110001/110002 can fire per-rule rather than once
	// for the full match block. No hostname — Wazuh supplies agent identity.
	for _, ruleName := range parseYrMatches(result) {
		appendEventToLog(fmt.Sprintf(
			`{"trigger":"yara_reflex","yara_rule":%q,"yara_file":%q,"ts":%q}`,
			ruleName, filePath, ts,
		))
	}

	if cfg == nil {
		return
	}

	host, _ := os.Hostname()
	postReflexTelemetry(cfg, fmt.Sprintf(
		`{"trigger":"yara_reflex","host":%q,"ts":%q,"file":%q,"match":%q}`,
		host, ts, filePath, result,
	))
}

// yaraRulesPath returns the path to the YARA-X rules file (preferring compiled .yarc).
// yr auto-detects compiled vs source format — no flag needed.
func yaraRulesPath() string {
	var base string
	switch runtime.GOOS {
	case "windows":
		base = `C:\Program Files (x86)\ossec-agent\shared\default\mcp_rules`
	default:
		base = "/Library/Ossec/etc/shared/default/mcp_rules"
	}
	if _, err := os.Stat(base + ".yarc"); err == nil {
		return base + ".yarc"
	}
	if _, err := os.Stat(base + ".yar"); err == nil {
		return base + ".yar"
	}
	return ""
}

// parseYrMatches extracts the rule name from each line of yr scan output.
// yr prints one line per matching rule: "<RuleName> <filePath>".
// Lines that don't conform to that format are skipped.
func parseYrMatches(output string) []string {
	var rules []string
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Rule name is the first space-delimited token.
		if idx := strings.IndexByte(line, ' '); idx > 0 {
			rules = append(rules, line[:idx])
		} else {
			rules = append(rules, line)
		}
	}
	return rules
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
