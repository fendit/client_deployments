//go:build darwin

package main

import (
	"os"
	"os/exec"
	"strings"
)

// wazuhRoot is the standard macOS installation directory for the Wazuh OSSEC agent.
const wazuhRoot = "/Library/Ossec"

// isWazuhInstalled checks for the presence of the Wazuh installation root.
// The PKG installs to /Library/Ossec; the absence of this directory means
// no Wazuh agent is currently installed.
func isWazuhInstalled() bool {
	_, err := os.Stat(wazuhRoot)
	return err == nil
}

// uninstallWazuh removes an existing Wazuh installation.
// Prefers the bundled uninstall.sh script; falls back to pkgutil + rm if absent.
func uninstallWazuh() error {
	script := wazuhRoot + "/bin/uninstall.sh"
	if _, err := os.Stat(script); err == nil {
		cmd := exec.Command("/bin/bash", script)
		cmd.Stdin = strings.NewReader("y\n") // confirm the interactive prompt
		return cmd.Run()
	}
	// Fallback: forget the package record and remove files.
	exec.Command("pkgutil", "--forget", "com.wazuh.pkg.wazuh-agent").Run() //nolint:errcheck
	exec.Command("rm", "-rf", wazuhRoot).Run()                             //nolint:errcheck
	return nil
}
