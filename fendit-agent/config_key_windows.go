//go:build windows

package main

import (
	"crypto/sha256"
	"os"
	"os/exec"
	"strings"
)

// machineKey derives a 32-byte AES key from the Windows MachineGuid registry value.
// Falls back to hostname if the registry query fails.
func machineKey() []byte {
	out, err := exec.Command(
		"reg", "query",
		`HKLM\SOFTWARE\Microsoft\Cryptography`,
		"/v", "MachineGuid",
	).Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "MachineGuid") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					guid := strings.TrimSpace(fields[len(fields)-1])
					if guid != "" {
						h := sha256.Sum256([]byte("fendit:" + guid))
						return h[:]
					}
				}
			}
		}
	}
	hostname, _ := os.Hostname()
	h := sha256.Sum256([]byte("fendit:fallback:" + hostname))
	return h[:]
}
