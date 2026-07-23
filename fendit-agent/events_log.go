package main

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// maxEventLogBytes is the size threshold at which events.log is rotated.
// One event is ~200-400 bytes, so 5 MB holds ~12 000–25 000 events.
// Combined with one backup (.old), peak disk use is always under 10 MB.
const maxEventLogBytes = 5 * 1024 * 1024

var eventLogMu sync.Mutex

// eventsLogPath returns the platform-specific path for the Wazuh event bridge
// log. Wazuh's <localfile log_format="json"> in the group agent.conf points here.
func eventsLogPath() string {
	switch runtime.GOOS {
	case "windows":
		return `C:\ProgramData\Fendit\events.log`
	default:
		return "/Library/Fendit/events.log"
	}
}

// appendEventToLog writes a single JSON line to events.log so that the local
// Wazuh agent picks it up and routes it through the detection rule engine.
//
// Rotation strategy: when the active file reaches maxEventLogBytes it is
// renamed to events.log.old (overwriting any previous backup) and a fresh
// events.log is created. Wazuh detects the rename via inotify / FSEvents /
// ReadDirectoryChangesW and seamlessly continues reading the new file.
// This keeps disk usage bounded at ~10 MB regardless of event volume.
func appendEventToLog(jsonLine string) {
	eventLogMu.Lock()
	defer eventLogMu.Unlock()

	path := eventsLogPath()

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return // cannot create Fendit data directory — fail silently
	}

	if info, err := os.Stat(path); err == nil && info.Size() >= maxEventLogBytes {
		old := path + ".old"
		os.Remove(old)       //nolint:errcheck
		os.Rename(path, old) //nolint:errcheck
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(jsonLine + "\n")
}
