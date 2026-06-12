package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"
)

// AgentConfig is the response from /api/control/v1/agent-config.
type AgentConfig struct {
	WazuhManager string `json:"agent_wazuh_manager"`
	AgentURL     string `json:"agent_url"`
	InstallGroup string `json:"install_group"`
	MCPDnsIP     string `json:"mcp_dns_ip"`
	ReflexToken  string `json:"reflex_token"`
	APIBaseURL   string `json:"api_base_url"`
}

// fetchPendingActions retrieves 'approved' action intents for this agent from guardian.
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
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", cfg.endpoint(pathActionsPending), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.ReflexToken)
	req.Header.Set("User-Agent", "Fendit-Agent/2.0")

	resp, err := client.Do(req)
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

// postActionResult sends execution feedback to guardian after the ExecutionEngine finishes.
func postActionResult(cfg *Config, result ActionResult) error {
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", cfg.endpoint(pathActionsResult), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.ReflexToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Fendit-Agent/2.0")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("action result post: %w", err)
	}
	resp.Body.Close()
	return nil
}

// fetchAgentConfig calls /api/control/v1/agent-config with the install domain + one-time session token.
// The server burns the token on first successful call.
func fetchAgentConfig(domain, sessionToken string) (*AgentConfig, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", defaultAPIBase+pathAgentConfig, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-install-domain", domain)
	req.Header.Set("x-install-arch", runtime.GOARCH)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	req.Header.Set("User-Agent", "Fendit-Agent/2.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, body)
	}

	var cfg AgentConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if cfg.ReflexToken == "" || cfg.WazuhManager == "" {
		return nil, fmt.Errorf("API response missing required fields (reflex_token / agent_wazuh_manager)")
	}
	return &cfg, nil
}
