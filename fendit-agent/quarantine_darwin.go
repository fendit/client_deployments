//go:build darwin

package main

import "os"

// lockFilePermissions strips all mode bits from path using the Go stdlib.
// No child process is spawned.
func lockFilePermissions(path string) error {
	return os.Chmod(path, 0)
}
