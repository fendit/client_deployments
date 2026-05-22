//go:build darwin

package main

import (
	"crypto/sha256"
	"os"
	"os/exec"
	"strings"
)

// machineKey derives a 32-byte AES key from the hardware's IOPlatformUUID.
// Falls back to hostname if ioreg is unavailable.
func machineKey() []byte {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "IOPlatformUUID") {
				// Line: | "IOPlatformUUID" = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
				parts := strings.Split(line, "\"")
				for i, p := range parts {
					if p == "IOPlatformUUID" && i+2 < len(parts) {
						uuid := strings.TrimSpace(parts[i+2])
						if uuid != "" {
							h := sha256.Sum256([]byte("fendit:" + uuid))
							return h[:]
						}
					}
				}
			}
		}
	}
	hostname, _ := os.Hostname()
	h := sha256.Sum256([]byte("fendit:fallback:" + hostname))
	return h[:]
}
