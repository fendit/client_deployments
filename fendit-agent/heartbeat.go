package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"
)

const (
	heartbeatInterval  = 5 * time.Minute
	heartbeatTimeout   = 10 * time.Second
	crashReportTimeout = 5 * time.Second

	pathHeartbeat = "/api/v1/telemetry/heartbeat"
	pathCrash     = "/api/v1/telemetry/crash"
)

// heartbeatPayload is the body of POST /api/v1/telemetry/heartbeat.
// Zero PII: agent_id is SHA-256(reflex_token) — no hostname, no username,
// no hardware serial number.
type heartbeatPayload struct {
	AgentID             string `json:"agent_id"`
	Version             string `json:"version"`
	OS                  string `json:"os"`
	Status              string `json:"status"`
	FilterEngineRunning bool   `json:"filter_engine_running"`
	UptimeSeconds       int64  `json:"uptime_seconds"`
	LastScanStatus      string `json:"last_scan_status,omitempty"`
}

// crashPayload is the body of POST /api/v1/telemetry/crash.
type crashPayload struct {
	AgentID    string   `json:"agent_id"`
	Version    string   `json:"version"`
	OS         string   `json:"os"`
	StackTrace string   `json:"stack_trace"`
	LogTail    []string `json:"log_tail"`
	Timestamp  string   `json:"ts"`
}

// daemonCfg is stored once by startDaemon after loadConfig() succeeds.
// Only read (never written after init), so no mutex is needed.
// handlePanic and sendCrashReport read it during panic recovery.
var daemonCfg *Config

// agentStartTime is set once at daemon start for uptime calculation.
var agentStartTime time.Time

// runHeartbeat replaces runHealthPinger. It sends a structured POST every
// heartbeatInterval and delegates to the existing pending-queue on failure.
func runHeartbeat(ctx context.Context, cfg *Config) {
	agentID := deriveAgentID(cfg.ReflexToken)
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	// Send one immediately so the SOC sees the agent right after startup.
	sendOrQueueHeartbeat(cfg, agentID)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sendOrQueueHeartbeat(cfg, agentID)
		}
	}
}

func sendOrQueueHeartbeat(cfg *Config, agentID string) {
	if err := sendHeartbeat(cfg, agentID); err != nil {
		logger.Warn().Err(err).Msg("heartbeat POST failed — queuing to disk")
		queueHeartbeat(cfg, agentID)
	} else {
		logger.Debug().Msg("heartbeat delivered")
	}
}

func sendHeartbeat(cfg *Config, agentID string) error {
	p := buildHeartbeatPayload(agentID)
	body, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal heartbeat: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), heartbeatTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.endpoint(pathHeartbeat), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.ReflexToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Fendit-Agent/"+version)

	resp, err := agentHTTPClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("server error %d", resp.StatusCode)
	}
	return nil
}

// queueHeartbeat serialises the current payload into the pending-events
// directory so runPendingFlusher replays it once connectivity is restored.
func queueHeartbeat(cfg *Config, agentID string) {
	p := buildHeartbeatPayload(agentID)
	body, _ := json.Marshal(p)
	persistPendingEvent(string(body))
}

func buildHeartbeatPayload(agentID string) heartbeatPayload {
	return heartbeatPayload{
		AgentID:             agentID,
		Version:             version,
		OS:                  runtime.GOOS,
		Status:              "active",
		FilterEngineRunning: isFilterEngineRunning(),
		UptimeSeconds:       int64(time.Since(agentStartTime).Seconds()),
		LastScanStatus:      lastScanStatus(),
	}
}

// sendCrashReport is called from handlePanic. It has a hard 5-second deadline
// because the process is about to exit — delivery is best-effort, not guaranteed.
func sendCrashReport(cfg *Config, stack []byte) {
	agentID := deriveAgentID(cfg.ReflexToken)
	p := crashPayload{
		AgentID:    agentID,
		Version:    version,
		OS:         runtime.GOOS,
		StackTrace: string(stack),
		LogTail:    readTailLines(50),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(p)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), crashReportTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.endpoint(pathCrash), bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+cfg.ReflexToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Fendit-Agent/"+version)

	resp, err := agentHTTPClient.Do(req)
	if err != nil {
		logger.Error().Err(err).Msg("last-gasp crash report failed to deliver")
		return
	}
	resp.Body.Close()
	logger.Info().Msg("last-gasp crash report delivered")
}

// deriveAgentID hashes the reflex token to produce a stable, privacy-safe ID.
// No hostname, username, or hardware serial number is included.
func deriveAgentID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
