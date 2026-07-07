//go:build windows

package main

import (
	"bufio"
	"bytes"
	"log"
	"os/exec"
	"strings"
	"syscall"
)

// netshExe is the absolute path to avoid any PATH manipulation attacks.
const netshExe = `C:\Windows\System32\netsh.exe`

// listActiveAdapters calls netsh.exe directly to enumerate all network interfaces
// whose Admin State is "Enabled" and connection State is "Connected".
// No powershell.exe or cmd.exe is spawned.
//
// Typical netsh output (fixed-width columns):
//
//	Admin State    State          Type             Interface Name
//	--------------------------------------------------------------------
//	Enabled        Connected      Dedicated        Ethernet
//	Enabled        Connected      Dedicated        Wi-Fi
//	Enabled        Disconnected   Dedicated        Bluetooth Network
func listActiveAdapters() []string {
	cmd := exec.Command(netshExe, "interface", "show", "interface")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		log.Printf("network: netsh show interface failed: %v", err)
		return nil
	}

	var adapters []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		// Skip header, separator, and empty lines.
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "---") ||
			strings.Contains(trimmed, "Admin State") {
			continue
		}
		// Skip anything that is Disabled or Disconnected.
		if strings.Contains(line, "Disabled") || strings.Contains(line, "Disconnected") {
			continue
		}
		if !strings.Contains(line, "Connected") {
			continue
		}
		// Interface Name is field index 3 onwards (fields[3:]) — join with
		// spaces to handle multi-word names like "Wi-Fi" or "Local Area Connection".
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			adapters = append(adapters, strings.Join(fields[3:], " "))
		}
	}
	return adapters
}

// severNetwork disables every active network adapter using direct netsh.exe
// calls. This is the Windows implementation called by runReflex.
//
// Replaces the previous PowerShell "Get-NetAdapter | Disable-NetAdapter"
// chain which is a primary behavioural indicator in enterprise EDRs.
func severNetwork() {
	adapters := listActiveAdapters()
	if len(adapters) == 0 {
		log.Println("network: severNetwork — no active adapters found")
		return
	}
	for _, name := range adapters {
		cmd := exec.Command(netshExe, "interface", "set", "interface", name, "disabled")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Run(); err != nil {
			log.Printf("network: disable %q failed: %v", name, err)
		} else {
			log.Printf("network: disabled adapter %q", name)
		}
	}
}

// smartIsolate applies a firewall lockdown via Windows Firewall (advfirewall)
// that blocks all inbound and outbound traffic except outbound TCP 443.
// Unlike severNetwork (which disables adapters and cuts all connectivity),
// smartIsolate preserves the Guardian control plane so the agent can still
// send reflex telemetry and receive remote SOC commands after a trigger.
//
// This is a one-way emergency reflex. Restoration requires the SOC to issue
// an "unisolate" action through Guardian.
func smartIsolate() {
	// Block all inbound and outbound by default.
	netshRun("advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound")
	// Carve out a single outbound TCP 443 exception for the Guardian control plane.
	netshRun("advfirewall", "firewall", "add", "rule",
		"name=FENDIT-REFLEX-CTRL",
		"dir=out", "action=allow",
		"protocol=TCP", "remoteport=443",
		"enable=yes", "profile=any",
	)
	log.Printf("network: smart isolation active — all traffic blocked except outbound TCP 443")
}

// netshRun executes netsh.exe with the supplied arguments synchronously.
// Using HideWindow:true prevents any console window from flashing. Logging the
// error rather than returning it keeps call sites clean — a failed rule is still
// better than a crash, and the log captures the failure for Guardian ingestion.
func netshRun(args ...string) {
	cmd := exec.Command(netshExe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		log.Printf("network: netsh %s: %v", strings.Join(args, " "), err)
	}
}

// runDNSGuard re-applies the sinkhole DNS address to all active adapters using
// direct netsh.exe calls. Called when the binary is invoked with --dns-guard.
//
// Replaces the previous PowerShell "Set-DnsClientServerAddress" chain.
func runDNSGuard() {
	cfg, err := loadConfig()
	if err != nil || cfg.MCPDnsIP == "" {
		return
	}
	adapters := listActiveAdapters()
	for _, name := range adapters {
		cmd := exec.Command(netshExe,
			"interface", "ip", "set", "dns", name, "static", cfg.MCPDnsIP)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Run(); err != nil {
			log.Printf("network: set DNS on %q failed: %v", name, err)
		} else {
			log.Printf("network: DNS sinkhole applied to %q → %s", name, cfg.MCPDnsIP)
		}
	}
}
