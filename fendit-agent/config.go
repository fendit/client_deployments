package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// defaultAPIBase is the fallback when no api_base is persisted on disk.
const defaultAPIBase = "https://api.fendit.eu"

// Centralized API path definitions — update here when routing changes.
const (
	pathActivate       = "/api/v1/agent/activate"           // activation-code handshake (universal installer)
	pathReflex         = "/api/control/v1/reflex"
	pathScanHash       = "/api/control/v1/scan-hash"
	pathHealth         = "/health"
	pathActionsPending = "/api/control/v1/actions/pending"  // polled every 5 s by runActionPoller
	pathActionsResult  = "/api/control/v1/actions/result"   // execution feedback from ExecutionEngine
	pathDirectSocket   = "/api/control/ws"                  // persistent WebSocket for instant dispatch
)

// endpoint builds a fully-qualified URL from the config's stored base URL.
func (c *Config) endpoint(path string) string {
	return c.APIBase + path
}

// Config holds runtime state written to disk during installation.
type Config struct {
	ReflexToken string
	APIBase     string
	OrgName     string
	MCPDnsIP    string
}

// configDir returns the platform-specific Fendit config directory.
func configDir() string {
	if runtime.GOOS == "darwin" {
		return "/Library/Fendit/config"
	}
	return `C:\ProgramData\Fendit\config`
}

func tokenPath() string    { return filepath.Join(configDir(), "token") }
func apiBasePath() string  { return filepath.Join(configDir(), "api_base") }
func dnsIPPath() string    { return filepath.Join(configDir(), "dns_ip") }
func orgNamePath() string  { return filepath.Join(configDir(), "org") }

// configExists returns true when the sentinel token file is present.
func configExists() bool {
	_, err := os.Stat(tokenPath())
	return err == nil
}

// saveConfig persists config to disk. Token is AES-256-GCM encrypted with
// a machine-derived key; other fields are plaintext (non-sensitive).
func saveConfig(c *Config) error {
	dir := configDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	enc, err := encryptToken(c.ReflexToken)
	if err != nil {
		return fmt.Errorf("encrypt token: %w", err)
	}
	if err := writeProtected(tokenPath(), []byte(enc)); err != nil {
		return fmt.Errorf("write token: %w", err)
	}
	if err := writeProtected(apiBasePath(), []byte(c.APIBase)); err != nil {
		return fmt.Errorf("write api_base: %w", err)
	}
	if c.MCPDnsIP != "" {
		if err := writeProtected(dnsIPPath(), []byte(c.MCPDnsIP)); err != nil {
			return fmt.Errorf("write dns_ip: %w", err)
		}
	}
	if c.OrgName != "" {
		if err := writeProtected(orgNamePath(), []byte(c.OrgName)); err != nil {
			return fmt.Errorf("write org: %w", err)
		}
	}
	return nil
}

// loadConfig decrypts and returns the stored config.
func loadConfig() (*Config, error) {
	encData, err := os.ReadFile(tokenPath())
	if err != nil {
		return nil, fmt.Errorf("read token: %w", err)
	}
	token, err := decryptToken(strings.TrimSpace(string(encData)))
	if err != nil {
		return nil, fmt.Errorf("decrypt token: %w", err)
	}

	apiBase := readOptional(apiBasePath(), defaultAPIBase)
	dnsIP := readOptional(dnsIPPath(), "")
	org := readOptional(orgNamePath(), "")

	return &Config{
		ReflexToken: token,
		APIBase:     apiBase,
		MCPDnsIP:    dnsIP,
		OrgName:     org,
	}, nil
}

func readOptional(path, fallback string) string {
	b, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(b)) == "" {
		return fallback
	}
	return strings.TrimSpace(string(b))
}

// writeProtected creates (or truncates) a file with 0600 permissions.
func writeProtected(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

// encryptToken encrypts plaintext with AES-256-GCM using the machine-derived key.
// Output: base64(nonce || ciphertext+tag)
func encryptToken(plaintext string) (string, error) {
	key := machineKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// decryptToken reverses encryptToken.
func decryptToken(encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	key := machineKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return "", fmt.Errorf("ciphertext too short")
	}
	pt, err := gcm.Open(nil, data[:ns], data[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(pt), nil
}

// machineKey() is implemented per-platform in config_key_darwin.go / config_key_windows.go.
