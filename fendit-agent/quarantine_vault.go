package main

// quarantine_vault.go — persistent vault index for quarantined files.
//
// Every quarantine operation appends a QuarantineRecord to a JSON index
// stored alongside the quarantine directory so that:
//   - Restore commands can find the original path from a quarantine_id.
//   - Guardian can display the vault contents in the portal.
//   - The vault survives agent restarts.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// QuarantineRecord describes one quarantined file.
type QuarantineRecord struct {
	ID            string    `json:"id"`
	OriginalPath  string    `json:"original_path"`
	VaultPath     string    `json:"vault_path"`
	SHA256        string    `json:"sha256"`
	QuarantinedAt time.Time `json:"quarantined_at"`
	IntentID      string    `json:"intent_id"`
}

var vaultMu sync.Mutex // protects concurrent read-modify-write on the index file

func vaultIndexPath() string {
	return filepath.Join(quarantineDir(), "vault_index.json")
}

func loadVaultIndex() ([]QuarantineRecord, error) {
	data, err := os.ReadFile(vaultIndexPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var records []QuarantineRecord
	return records, json.Unmarshal(data, &records)
}

func saveVaultIndex(records []QuarantineRecord) error {
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	// Write atomically: temp file → rename, so a crash never corrupts the index.
	tmp := vaultIndexPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, vaultIndexPath())
}

// recordQuarantine appends a new entry to the vault index.
// sha256Hex may be empty if hashing failed — the entry is still recorded.
func recordQuarantine(intentID, origPath, vaultPath, sha256Hex string) (QuarantineRecord, error) {
	vaultMu.Lock()
	defer vaultMu.Unlock()

	record := QuarantineRecord{
		ID:            intentID,
		OriginalPath:  origPath,
		VaultPath:     vaultPath,
		SHA256:        sha256Hex,
		QuarantinedAt: time.Now().UTC(),
		IntentID:      intentID,
	}

	records, err := loadVaultIndex()
	if err != nil {
		return record, fmt.Errorf("load vault index: %w", err)
	}
	records = append(records, record)
	if err := saveVaultIndex(records); err != nil {
		return record, fmt.Errorf("save vault index: %w", err)
	}
	return record, nil
}

// findInVault looks up a quarantine record by intent_id / quarantine_id.
func findInVault(quarantineID string) (*QuarantineRecord, error) {
	vaultMu.Lock()
	defer vaultMu.Unlock()

	records, err := loadVaultIndex()
	if err != nil {
		return nil, err
	}
	for i := range records {
		if records[i].ID == quarantineID {
			return &records[i], nil
		}
	}
	return nil, fmt.Errorf("quarantine ID %q not found in vault", quarantineID)
}

// removeFromVault deletes a record from the vault index after a successful restore.
func removeFromVault(quarantineID string) error {
	vaultMu.Lock()
	defer vaultMu.Unlock()

	records, err := loadVaultIndex()
	if err != nil {
		return err
	}
	updated := records[:0]
	for _, r := range records {
		if r.ID != quarantineID {
			updated = append(updated, r)
		}
	}
	return saveVaultIndex(updated)
}

// hashFileSHA256 returns the hex-encoded SHA-256 digest of a file.
// Returns empty string on error — callers must handle the miss gracefully.
func hashFileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
