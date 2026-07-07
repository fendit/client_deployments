//go:build darwin

package main

import (
	"context"
	"log"
	"os"

	"github.com/fsnotify/fsnotify"
)

// honeypotDir is the decoy directory that lures lateral-movement attackers.
// /Users/Shared is world-readable and a realistic target on macOS — the
// equivalent of C:\Users\Public\Documents\Backup on Windows.
const honeypotDir = "/Users/Shared/Backup"

// createHoneypotDecoys creates the decoy directory and writes two files that
// look like genuine corporate credential artefacts. Any attacker performing
// credential harvesting will find and open these, triggering the watcher.
//
// The same decoy payloads are used on both platforms so rule sets and threat
// intelligence match across Windows and macOS incidents.
func createHoneypotDecoys() error {
	if err := os.MkdirAll(honeypotDir, 0755); err != nil {
		return err
	}

	// credentials.dat — binary-looking blob; mimics an exported credential store.
	credsPayload := []byte(
		"AgBEAAAAA3NlY3JldAxrZXk6ZmVuZGl0LXNlY3VyZS1hcGkta2V5LTIwMjQtdjE" +
			"9b3BzLWJhY2t1cDpiYWNrdXAtcGFzc3dvcmQtc2VjdXJl",
	)
	os.WriteFile(honeypotDir+"/credentials.dat", credsPayload, 0644) //nolint:errcheck

	// access_keys.txt — key=value format; mimics an exported API key backup.
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

// runHoneypotWatcher watches the decoy directory using fsnotify and calls
// triggerHoneypotReflex on the first detected write, create, or rename event.
//
// Mirrors honeypot_windows.go exactly: same event mask, same reflex call,
// same re-arm-on-restart design. The launchd WatchPaths plist installed by
// install_darwin.go provides secondary coverage when the daemon is restarting.
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
				triggerHoneypotReflex(cfg) // smart pfctl isolation + telemetry via TCP 443
				return                     // re-arms on next daemon restart via launchd KeepAlive
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("honeypot: watcher error: %v", err)
		}
	}
}
