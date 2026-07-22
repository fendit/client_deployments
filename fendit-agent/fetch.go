package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"
)

// agentHTTPClient is the shared transport for all outbound API calls.
// A single client reuses TCP connections and avoids per-call TLS handshakes.
// Minimum TLS 1.2 is enforced; TLS 1.3 is preferred automatically by Go's stack.
var agentHTTPClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:    &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:       10,
		IdleConnTimeout:    90 * time.Second,
		ForceAttemptHTTP2:  true,
		DisableCompression: false,
	},
}

// ActivateResponse is the response from POST /api/v1/agent/activate.
// Fields map 1:1 to what the Go agent needs for Wazuh install + config persistence.
type ActivateResponse struct {
	AgentToken       string `json:"agent_token"`
	SessionID        string `json:"session_id"`    // two-phase install commit; used for rollback
	OrganizationName string `json:"organization_name"`
	WazuhManager     string `json:"agent_wazuh_manager"`
	InstallGroup     string `json:"install_group"`
	AgentURL         string `json:"agent_url"`
	APIBase          string `json:"api_base_url"`
	AgentChecksumURL string `json:"agent_checksum_url,omitempty"` // Wazuh CDN .sha512 URL for install-time verification
	YaraURL          string `json:"yara_url,omitempty"`
	YaraSHA256       string `json:"yara_sha256,omitempty"`
	YaraExtract      string `json:"yara_extract,omitempty"` // filename to extract when yara_url is a .zip
}

// activateAgent sends the 6-character code to Guardian and, on success, returns
// the persistent ActivateResponse the agent uses to install Wazuh and store config.
// GOOS and GOARCH are passed so Guardian can return the correct Wazuh package URL.
func activateAgent(code, hostname string) (*ActivateResponse, error) {
	body, err := json.Marshal(map[string]string{
		"code":     code,
		"hostname": hostname,
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", defaultAPIBase+pathActivate, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Fendit-Agent/2.0")

	resp, err := agentHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("activation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("activation failed (%d): %s", resp.StatusCode, raw)
	}

	var act ActivateResponse
	if err := json.NewDecoder(resp.Body).Decode(&act); err != nil {
		return nil, fmt.Errorf("decode activation response: %w", err)
	}
	if act.AgentToken == "" {
		return nil, fmt.Errorf("server returned empty agent token")
	}
	return &act, nil
}

// confirmInstall calls Guardian to flip the provisional endpoint from "installing" to "active".
// Non-fatal — the first heartbeat will correct status within 5 minutes if this fails.
func confirmInstall(apiBase, sessionID string) {
	if sessionID == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{"session_id": sessionID})
	req, err := http.NewRequest("POST", apiBase+pathConfirm, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Fendit-Agent/2.0")
	resp, err := agentHTTPClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

// rollbackInstall calls Guardian to reset the activation code and remove the ghost
// endpoint record when installation fails after the code has been burned.
func rollbackInstall(apiBase, sessionID string) {
	if sessionID == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{"session_id": sessionID})
	req, err := http.NewRequest("POST", apiBase+pathRollback, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Fendit-Agent/2.0")
	resp, err := agentHTTPClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

// fetchPendingActions retrieves 'approved' action intents for this agent from Guardian.
// Retries up to 3 times with 2 s backoff on transient network errors.
// Returns an empty slice (not an error) when there is nothing to execute.
func fetchPendingActions(cfg *Config) ([]Intent, error) {
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*2) * time.Second)
		}
		intents, err := tryFetchPendingActions(cfg)
		if err == nil {
			return intents, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func tryFetchPendingActions(cfg *Config) ([]Intent, error) {
	req, err := http.NewRequest("GET", cfg.endpoint(pathActionsPending), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.ReflexToken)
	req.Header.Set("User-Agent", "Fendit-Agent/2.0")

	resp, err := agentHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("actions poll: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("actions poll %d: %s", resp.StatusCode, body)
	}

	var intents []Intent
	if err := json.NewDecoder(resp.Body).Decode(&intents); err != nil {
		return nil, fmt.Errorf("actions decode: %w", err)
	}
	return intents, nil
}

// postActionResult sends execution feedback to Guardian after the ExecutionEngine finishes.
func postActionResult(cfg *Config, result ActionResult) error {
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", cfg.endpoint(pathActionsResult), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.ReflexToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Fendit-Agent/2.0")

	resp, err := agentHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("action result post: %w", err)
	}
	resp.Body.Close()
	return nil
}
