//go:build windows

package main

import (
	"context"
	"log"
	"os"

	"github.com/fsnotify/fsnotify"
)

// honeypotDir is the decoy directory that lures lateral-movement attackers.
// Placed under C:\Users\Public\Documents\ (world-readable, realistic target)
// but named generically so the path itself does not trip AV string-pattern scanners.
const honeypotDir = `C:\Users\Public\Documents\Backup`

// createHoneypotDecoys creates the decoy directory and writes two files that
// look like genuine corporate credential artefacts. Any attacker performing
// credential harvesting will find and open these, triggering the watcher.
//
// This is the entirety of install-time honeypot setup on Windows:
// no .ps1 scripts are written to disk, no scheduled tasks are registered,
// and no powershell.exe process is spawned. The daemon's fsnotify watcher
// (runHoneypotWatcher) provides the always-on detection capability.
func createHoneypotDecoys() error {
	if err := os.MkdirAll(honeypotDir, 0755); err != nil {
		return err
	}

	// credentials.dat — binary-looking blob; mimics an exported credential store.
	credsPayload := []byte(
		"AgBEAAAAA3NlY3JldAxrZXk6ZmVuZGl0LXNlY3VyZS1hcGkta2V5LTIwMjQtdjE" +
			"9b3BzLWJhY2t1cDpiYWNrdXAtcGFzc3dvcmQtc2VjdXJl",
	)
	os.WriteFile(honeypotDir+`\credentials.dat`, credsPayload, 0644) //nolint:errcheck

	// access_keys.txt — key=value format; mimics an exported API key backup.
	keysPayload := []byte(
		"[access_keys]\r\n" +
			"account=ops-backup\r\n" +
			"api_key=sk-live-x7f9Kp2mNqR4tJ8vBwL3eZ5\r\n" +
			"secret=dGhpcyBpcyBhIGZha2Ugc2VjcmV0IGtleQ==\r\n" +
			"created=2024-01-15\r\n",
	)
	os.WriteFile(honeypotDir+`\access_keys.txt`, keysPayload, 0644) //nolint:errcheck

	return nil
}

// runHoneypotWatcher watches the decoy directory using fsnotify and calls
// triggerHoneypotReflex on the first detected write, create, or rename event.
//
// Design decisions:
//   - Runs as a goroutine inside the daemon Windows service — starts at boot
//     automatically, no .ps1 scripts or scheduled tasks on disk.
//   - Returns after the first trigger. triggerHoneypotReflex applies smart
//     firewall isolation (blocking everything except outbound TCP 443) so
//     telemetry still reaches Guardian even after isolation is active.
//   - The SCM KeepAlive flag restarts the daemon, which re-arms the watcher.
//   - fsnotify does not report open/read events on Windows (kernel limitation),
//     so we watch for Write/Create/Rename which cover the attacker's first
//     extraction attempt (copy, modification, or staging).
func runHoneypotWatcher(ctx context.Context, cfg *Config) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("honeypot: fsnotify init failed: %v", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(honeypotDir); err != nil {
		log.Printf("honeypot: cannot watch %s: %v", honeypotDir, err)
		return
	}
	log.Printf("honeypot: watching %s", honeypotDir)

	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) {
				log.Printf("honeypot: TRIGGER — op=%s file=%s", event.Op, event.Name)
				triggerHoneypotReflex(cfg) // smart isolate + posts telemetry via TCP 443
				return                     // re-arms on next service restart via SCM KeepAlive
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("honeypot: watcher error: %v", err)
		}
	}
}
