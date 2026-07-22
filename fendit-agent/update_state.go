package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// UpdateState is the shared coordination file between the daemon and the tray
// process. Written by the daemon heartbeat handler (and later by the tray
// schedule dialog). Read by the daemon update scheduler goroutine every 5 min.
//
// Path: <configDir>/update_state.json
// Write is atomic (write to .tmp then rename) so neither process sees a partial file.
type UpdateState struct {
	// Pending is true when an update is queued and not yet applied.
	Pending bool `json:"pending"`

	// ScheduledAt is an RFC3339 timestamp; empty means "apply as soon as possible".
	ScheduledAt string `json:"scheduled_at,omitempty"`

	// Components lists which components need updating: "fendit_agent", "wazuh".
	Components []string `json:"components"`

	// Download info populated by the heartbeat signal or manifest poll.
	// Fendit agent: SHA256 hash (we publish it ourselves alongside the binary).
	// Wazuh: checksum_url points at Wazuh's official .sha512 CDN file so the
	// agent always verifies against the authoritative hash without pre-computation.
	AgentURL         string `json:"agent_url,omitempty"`
	AgentSHA256      string `json:"agent_sha256,omitempty"`
	WazuhURL         string `json:"wazuh_url,omitempty"`
	WazuhChecksumURL string `json:"wazuh_checksum_url,omitempty"`

	// Status tracks execution: "pending" → "downloading" → "swapping" → "done" | "failed"
	Status   string `json:"status,omitempty"`
	ErrorMsg string `json:"error,omitempty"`
}

func updateStatePath() string {
	return filepath.Join(configDir(), "update_state.json")
}

// readUpdateState returns nil, nil when the file does not exist.
func readUpdateState() (*UpdateState, error) {
	data, err := os.ReadFile(updateStatePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var s UpdateState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// writeUpdateState atomically writes the state file.
func writeUpdateState(s *UpdateState) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := updateStatePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, updateStatePath())
}

// clearUpdateState removes the state file (called after a successful update).
func clearUpdateState() {
	_ = os.Remove(updateStatePath())
}
