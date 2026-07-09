package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"time"
)

const (
	// installFailEndpoint is the Fendit telemetry ingest for installer failures.
	// Lives under /api/v1/telemetry/ — the same path prefix Traefik already routes
	// to the guardian service, so no extra routing rule is required.
	installFailEndpoint = "https://api.fendit.eu/api/v1/telemetry/install-fail"

	// reportDeadline is the hard wall-clock limit for a telemetry POST.
	// Must never block the user's machine longer than this.
	reportDeadline = 3 * time.Second

	logTailLines = 50
)

// installFailPayload is the JSON body sent to installFailEndpoint.
// Keep fields stable — the backend schema is pinned to this layout.
type installFailPayload struct {
	Timestamp    string   `json:"timestamp"`
	OS           string   `json:"os"`
	ErrorContext string   `json:"error_context"`
	ErrorMessage string   `json:"error_message"`
	LogTail      []string `json:"log_tail"`
}

// tailLog returns the last n lines of the file at path using an in-memory ring
// buffer — O(n) memory regardless of file size.
// Returns nil when the file does not exist (e.g. a very early panic before NewApp
// opens the log file).
func tailLog(path string, n int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	ring := make([]string, 0, n+1)
	s := bufio.NewScanner(f)
	for s.Scan() {
		ring = append(ring, s.Text())
		if len(ring) > n {
			ring = ring[1:]
		}
	}
	return ring
}

// ReportInstallFailure sends a synchronous POST to installFailEndpoint.
// It enforces a strict 3-second deadline: if the request times out or the network
// is unavailable the function returns silently — it must never hang the installer.
//
// For non-blocking use from within the Activate() critical path, wrap in a goroutine:
//
//	go ReportInstallFailure("Wazuh MSI install failed", err)
//
// For the panic handler, call it directly so the report lands before os.Exit.
func ReportInstallFailure(errorContext string, cause error) {
	errMsg := ""
	if cause != nil {
		errMsg = cause.Error()
	}

	body, err := json.Marshal(installFailPayload{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		OS:           runtime.GOOS,
		ErrorContext: errorContext,
		ErrorMessage: errMsg,
		// installLog is the platform-specific constant defined in app.go / app_darwin.go.
		// slog writes synchronously to os.File so the tail is current at call time.
		LogTail: tailLog(installLog, logTailLines),
	})
	if err != nil {
		return
	}

	client := &http.Client{Timeout: reportDeadline}
	req, err := http.NewRequest(http.MethodPost, installFailEndpoint, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return // offline / timed out — fail silently, never retry
	}
	resp.Body.Close()
}

// handleInstallerPanic must be called as the very first defer in main().
// It catches any unhandled panic that escapes wails.Run(), fires a synchronous
// last-gasp telemetry report (capped at reportDeadline), then exits with code 2.
func handleInstallerPanic() {
	r := recover()
	if r == nil {
		return
	}
	ReportInstallFailure(
		"unhandled panic",
		fmt.Errorf("%v\n%s", r, debug.Stack()),
	)
	os.Exit(2)
}
