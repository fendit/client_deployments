//go:build darwin

package main

import (
	"log"
	"os"
	"os/exec"
	"strings"
)

// severNetwork disables every active network service on macOS using
// networksetup — the canonical macOS CLI for network configuration.
// Called by runReflex when the honeypot is triggered.
func severNetwork() {
	out, _ := exec.Command("networksetup", "-listallnetworkservices").Output()
	for _, svc := range strings.Split(string(out), "\n")[1:] {
		svc = strings.TrimSpace(svc)
		if svc != "" {
			exec.Command("networksetup", "-setnetworkserviceenabled", svc, "off").Run() //nolint:errcheck
		}
	}
}

// runDNSGuard re-applies the sinkhole DNS address to all active macOS network
// services. Called when the binary is invoked with --dns-guard.
func runDNSGuard() {
	cfg, err := loadConfig()
	if err != nil || cfg.MCPDnsIP == "" {
		return
	}
	out, _ := exec.Command("networksetup", "-listallnetworkservices").Output()
	for _, svc := range strings.Split(string(out), "\n")[1:] {
		svc = strings.TrimSpace(svc)
		if svc != "" {
			exec.Command("networksetup", "-setdnsservers", svc, cfg.MCPDnsIP).Run() //nolint:errcheck
		}
	}
}

// smartIsolate applies a pfctl anchor that blocks all traffic except outbound
// TCP 443, preserving the Guardian control plane after a honeypot trigger.
// Mirrors the Windows netsh advfirewall smart isolation in network_windows.go.
func smartIsolate() {
	rules := "block drop all\npass out proto tcp to any port 443\n"
	anchorPath := "/etc/pf.anchors/fendit-reflex"
	if err := os.WriteFile(anchorPath, []byte(rules), 0600); err != nil {
		log.Printf("network: smartIsolate: write anchor: %v", err)
		return
	}
	exec.Command("/sbin/pfctl", "-a", "fendit/reflex", "-f", anchorPath).Run() //nolint:errcheck
	log.Printf("network: smart isolation active — all traffic blocked except outbound TCP 443 (pfctl)")
}
