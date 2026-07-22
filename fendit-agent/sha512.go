package main

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// fetchChecksumURL downloads a Wazuh-style ".sha512" file and returns the hash.
// Expected file format: "HASH  filename\n" — only the first whitespace-delimited
// field is used, so both variants ("HASH  name" and "HASH *name") are accepted.
func fetchChecksumURL(checksumURL string) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(checksumURL) //nolint:gosec — operator-controlled URL from manifest
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(strings.TrimSpace(string(raw)))
	if len(fields) == 0 {
		return "", fmt.Errorf("empty checksum file at %s", checksumURL)
	}
	return strings.ToLower(fields[0]), nil
}

// verifySHA512 computes SHA512 of the file at path and compares it against the
// hash published at checksumURL.  If checksumURL is empty, this is a no-op.
// Used by the initial installer (file already on disk before verification).
func verifySHA512(path, checksumURL string) error {
	if checksumURL == "" {
		return nil
	}
	expected, err := fetchChecksumURL(checksumURL)
	if err != nil {
		return fmt.Errorf("fetch checksum: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open for sha512: %w", err)
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("compute sha512: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, expected) {
		return fmt.Errorf("SHA512 mismatch (expected %.16s… got %.16s…)", expected, got)
	}
	return nil
}

// downloadAndVerifySHA512 downloads url to a temp file while streaming the
// SHA512 hash.  After download it fetches checksumURL and compares.
// If checksumURL is empty, the hash check is skipped (download still happens).
// Returns the temp file path; caller is responsible for removing it.
// Used by the updater for Wazuh package updates.
func downloadAndVerifySHA512(url, checksumURL string, timeout time.Duration) (string, error) {
	// Fetch the expected hash before the large download so a CDN hiccup fails fast.
	var expected string
	if checksumURL != "" {
		var err error
		expected, err = fetchChecksumURL(checksumURL)
		if err != nil {
			return "", fmt.Errorf("fetch checksum: %w", err)
		}
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url) //nolint:gosec
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download: http %d", resp.StatusCode)
	}

	f, err := os.CreateTemp("", "fendit-update-*")
	if err != nil {
		return "", fmt.Errorf("temp file: %w", err)
	}
	defer f.Close()

	h := sha512.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("write temp: %w", err)
	}

	if expected != "" {
		got := hex.EncodeToString(h.Sum(nil))
		if !strings.EqualFold(got, expected) {
			os.Remove(f.Name())
			return "", fmt.Errorf("SHA512 mismatch (expected %.16s… got %.16s…)", expected, got)
		}
	}
	return f.Name(), nil
}
