package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const restartStateFile = "restart_state.json"

// RestartState tracks a pending system restart after a component update.
// Written by the daemon updater (via writeRestartDeadline); read and written
// by the tray (user-session). Atomic writes via .tmp + rename.
type RestartState struct {
	Required       bool   `json:"required"`
	Deadline       string `json:"deadline"`        // RFC3339 — 48h after the update completed
	DismissCount   int    `json:"dismiss_count"`   // tray dismissals past the deadline
	LastPrompt     string `json:"last_prompt"`     // RFC3339 — time of last automatic popup
	ForceRequested bool   `json:"force_requested"` // macOS: tray sets this; root daemon executes shutdown
}

func restartStatePath() string {
	return filepath.Join(configDir(), restartStateFile)
}

func readRestartState() (*RestartState, error) {
	data, err := os.ReadFile(restartStatePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var s RestartState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func writeRestartState(s *RestartState) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := restartStatePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, restartStatePath())
}

func clearRestartState() {
	_ = os.Remove(restartStatePath())
}

// writeRestartDeadline creates a fresh restart state with a 48-hour deadline.
// Called by the updater when wazuhUpdate returns ErrRestartRequired.
func writeRestartDeadline() {
	deadline := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	_ = writeRestartState(&RestartState{Required: true, Deadline: deadline})
}
