//go:build windows

package main

import (
	"crypto/sha256"
	"os"

	"golang.org/x/sys/windows/registry"
)

// machineKey derives a deterministic 32-byte AES key from the Windows MachineGuid
// registry value. Uses the native registry API — no reg.exe child process.
// Falls back to hostname if the registry read fails.
func machineKey() []byte {
	// WOW64_64KEY ensures we always read from the 64-bit registry hive even when
	// the installer binary is compiled as 32-bit.
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err == nil {
		defer k.Close()
		if guid, _, err := k.GetStringValue("MachineGuid"); err == nil && guid != "" {
			h := sha256.Sum256([]byte("fendit:" + guid))
			return h[:]
		}
	}

	hostname, _ := os.Hostname()
	h := sha256.Sum256([]byte("fendit:fallback:" + hostname))
	return h[:]
}
