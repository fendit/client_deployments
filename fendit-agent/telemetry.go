package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const pendingFlushInterval = 30 * time.Second

func pendingEventsDir() string {
	switch runtime.GOOS {
	case "windows":
		return `C:\ProgramData\Fendit\pending_events`
	default:
		return "/Library/Fendit/pending_events"
	}
}

// postReflexTelemetry fires an async POST to Guardian's reflex endpoint.
// On any network failure the event is serialised to disk; runPendingFlusher
// replays it once connectivity is restored.
func postReflexTelemetry(cfg *Config, jsonBody string) {
	go func() {
		if err := sendReflexEvent(cfg, jsonBody); err != nil {
			logger.Warn().Err(err).Msg("telemetry: POST failed — queuing to disk")
			persistPendingEvent(jsonBody)
		}
	}()
}

// sendReflexEvent executes one synchronous HTTPS POST.
// A 5xx response is treated as a transient failure so the event is retried.
func sendReflexEvent(cfg *Config, jsonBody string) error {
	req, err := http.NewRequest("POST", cfg.endpoint(pathReflex), strings.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.ReflexToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := agentHTTPClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("guardian %d", resp.StatusCode)
	}
	return nil
}

// persistPendingEvent writes jsonBody to a nanosecond-timestamped file in the
// pending events directory. Files survive process restarts and OS reboots.
func persistPendingEvent(jsonBody string) {
	dir := pendingEventsDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		logger.Error().Err(err).Msg("telemetry: cannot create pending dir")
		return
	}
	name := fmt.Sprintf("%d.json", time.Now().UnixNano())
	if err := os.WriteFile(filepath.Join(dir, name), []byte(jsonBody), 0600); err != nil {
		logger.Error().Err(err).Str("file", name).Msg("telemetry: cannot persist event")
	}
}

// runPendingFlusher ticks every 30 seconds and replays events that were
// written to disk during a connectivity outage. Successfully delivered events
// are removed immediately; failed events stay on disk for the next tick.
func runPendingFlusher(ctx context.Context, cfg *Config) {
	ticker := time.NewTicker(pendingFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			flushPendingEvents(cfg)
		}
	}
}

func flushPendingEvents(cfg *Config) {
	dir := pendingEventsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // directory absent — nothing queued
	}
	flushed := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if err := sendReflexEvent(cfg, string(data)); err != nil {
			logger.Warn().Err(err).Str("file", entry.Name()).Msg("telemetry: flush retry failed")
			continue // leave on disk; retry next tick
		}
		os.Remove(path) //nolint:errcheck
		flushed++
	}
	if flushed > 0 {
		logger.Info().Int("count", flushed).Msg("telemetry: flushed pending events to Guardian")
	}
}
