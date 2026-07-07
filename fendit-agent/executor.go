package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const intentExecTimeout = 30 * time.Second

// Intent is a structured action received from the /v1/actions/pending endpoint.
// All fields map 1-to-1 with the action_intents PostgreSQL table columns.
type Intent struct {
	ID     string                 `json:"id"`
	Action string                 `json:"action"`
	Args   map[string]interface{} `json:"args"`
	OSName string                 `json:"os_name"`
}

// ActionResult is posted back to /v1/actions/result after execution.
type ActionResult struct {
	IntentID string `json:"intent_id"`
	Success  bool   `json:"success"`
	Output   string `json:"output,omitempty"`
	Error    string `json:"error,omitempty"`
}

// allowedActions is the hard-coded allowlist. Any action not in this set is
// rejected before it reaches any OS call.
var allowedActions = map[string]bool{
	"kill_process":    true,
	"suspend_process": true,
	"block_ip":        true,
	"unblock_ip":      true,
	"isolate":         true,
	"unisolate":       true,
	"quarantine":      true,
}

// Execute dispatches the intent using OS-native commands.
// No shell interpreter is ever invoked — every case calls exec.CommandContext
// with a fixed argument list, eliminating shell injection entirely.
func (i *Intent) Execute() ActionResult {
	if !allowedActions[i.Action] {
		return ActionResult{
			IntentID: i.ID,
			Success:  false,
			Error:    fmt.Sprintf("action %q is not in the allowlist", i.Action),
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), intentExecTimeout)
	defer cancel()

	switch i.Action {
	case "kill_process":
		cmd, err := buildKillCmd(ctx, i.Args)
		return i.execCmd(cmd, err)
	case "suspend_process":
		cmd, err := buildSuspendCmd(ctx, i.Args)
		return i.execCmd(cmd, err)
	case "block_ip":
		cmd, err := buildBlockIPCmd(ctx, i.Args)
		return i.execCmd(cmd, err)
	case "unblock_ip":
		cmd, err := buildUnblockIPCmd(ctx, i.Args)
		return i.execCmd(cmd, err)
	case "isolate":
		// Firewall-based isolation: blocks all traffic except the Fendit control
		// plane (TCP 443) and DNS (UDP 53), so the agent can still receive
		// an unisolate command from the SOC.
		// NOTE: this is distinct from severNetwork() which is the emergency honeypot
		// reflex — that one intentionally cuts everything including the control plane.
		return i.executeIsolate(ctx)
	case "unisolate":
		return i.executeUnisolate(ctx)
	case "quarantine":
		return i.executeQuarantine()
	default:
		return ActionResult{
			IntentID: i.ID,
			Success:  false,
			Error:    fmt.Sprintf("unsupported action: %s", i.Action),
		}
	}
}

// execCmd runs a pre-built command and captures combined stdout/stderr.
// buildErr is from the builder functions — if non-nil the command is never run.
func (i *Intent) execCmd(cmd *exec.Cmd, buildErr error) ActionResult {
	if buildErr != nil {
		return ActionResult{IntentID: i.ID, Success: false, Error: buildErr.Error()}
	}
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		return ActionResult{IntentID: i.ID, Success: false, Output: output, Error: err.Error()}
	}
	return ActionResult{IntentID: i.ID, Success: true, Output: output}
}

// ── Argument helpers ──────────────────────────────────────────────────────────

// argStr safely extracts a non-empty string from the intent args map.
func argStr(args map[string]interface{}, key string) (string, error) {
	v, ok := args[key]
	if !ok || v == nil {
		return "", fmt.Errorf("missing required argument: %s", key)
	}
	s := strings.TrimSpace(fmt.Sprintf("%v", v))
	if s == "" {
		return "", fmt.Errorf("empty argument: %s", key)
	}
	return s, nil
}

// validatedPID extracts "pid" and ensures it is a positive integer.
func validatedPID(args map[string]interface{}) (string, error) {
	raw, err := argStr(args, "pid")
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 || n > 4_194_304 {
		return "", fmt.Errorf("invalid pid %q — must be a positive integer", raw)
	}
	return raw, nil
}

// validatedIP extracts "ip" and ensures it is a valid, non-loopback IP address.
func validatedIP(args map[string]interface{}) (string, error) {
	raw, err := argStr(args, "ip")
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address %q", raw)
	}
	if ip.IsLoopback() {
		return "", fmt.Errorf("refusing to block loopback address %q", raw)
	}
	return raw, nil
}

// sanitizeIPLabel replaces non-alphanumeric characters with dashes so an IP
// can appear safely in a firewall rule name or routing label.
func sanitizeIPLabel(ip string) string {
	out := make([]byte, len(ip))
	for i, b := range []byte(ip) {
		if (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
			out[i] = b
		} else {
			out[i] = '-'
		}
	}
	return string(out)
}

// ── Command builders ──────────────────────────────────────────────────────────

func buildKillCmd(ctx context.Context, args map[string]interface{}) (*exec.Cmd, error) {
	pid, err := validatedPID(args)
	if err != nil {
		return nil, err
	}
	switch runtime.GOOS {
	case "windows":
		// /T kills the entire process tree, preventing child processes from surviving.
		return exec.CommandContext(ctx,
			`C:\Windows\System32\taskkill.exe`, "/F", "/T", "/PID", pid), nil
	default:
		return exec.CommandContext(ctx, "/bin/kill", "-9", pid), nil
	}
}

func buildSuspendCmd(ctx context.Context, args map[string]interface{}) (*exec.Cmd, error) {
	pid, err := validatedPID(args)
	if err != nil {
		return nil, err
	}
	switch runtime.GOOS {
	case "windows":
		// No built-in Windows CLI for SIGSTOP-equivalent without extra tooling.
		// Falling back to kill is the safe production choice.
		return exec.CommandContext(ctx,
			`C:\Windows\System32\taskkill.exe`, "/F", "/T", "/PID", pid), nil
	default:
		return exec.CommandContext(ctx, "/bin/kill", "-STOP", pid), nil
	}
}

func buildBlockIPCmd(ctx context.Context, args map[string]interface{}) (*exec.Cmd, error) {
	ip, err := validatedIP(args)
	if err != nil {
		return nil, err
	}
	switch runtime.GOOS {
	case "windows":
		return exec.CommandContext(ctx,
			`C:\Windows\System32\netsh.exe`, "advfirewall", "firewall", "add", "rule",
			"name=FenditBlock-"+sanitizeIPLabel(ip),
			"dir=both", "action=block", "remoteip="+ip,
			"enable=yes", "profile=any",
		), nil
	case "darwin":
		// Null-route via the kernel routing table — no pf rule file editing required.
		return exec.CommandContext(ctx, "/sbin/route", "add", "-host", ip, "127.0.0.1"), nil
	default:
		return exec.CommandContext(ctx, "/sbin/iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"), nil
	}
}

func buildUnblockIPCmd(ctx context.Context, args map[string]interface{}) (*exec.Cmd, error) {
	ip, err := validatedIP(args)
	if err != nil {
		return nil, err
	}
	switch runtime.GOOS {
	case "windows":
		return exec.CommandContext(ctx,
			`C:\Windows\System32\netsh.exe`, "advfirewall", "firewall", "delete", "rule",
			"name=FenditBlock-"+sanitizeIPLabel(ip),
		), nil
	case "darwin":
		return exec.CommandContext(ctx, "/sbin/route", "delete", "-host", ip), nil
	default:
		return exec.CommandContext(ctx, "/sbin/iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"), nil
	}
}

// ── Isolate / unisolate ───────────────────────────────────────────────────────

// executeIsolate uses the platform firewall to block all traffic except
// outbound DNS (UDP 53) and the Fendit control plane (TCP 443).
// The agent remains reachable by the SOC and can receive an unisolate command.
func (i *Intent) executeIsolate(ctx context.Context) ActionResult {
	var cmds [][]string
	switch runtime.GOOS {
	case "windows":
		cmds = [][]string{
			// 1. Block all inbound and outbound by default.
			{`C:\Windows\System32\netsh.exe`, "advfirewall", "set", "allprofiles",
				"firewallpolicy", "blockinbound,blockoutbound"},
			// 2. Allow outbound DNS so we can resolve api.fendit.eu.
			{`C:\Windows\System32\netsh.exe`, "advfirewall", "firewall", "add", "rule",
				"name=FENDIT-ISO-DNS", "dir=out", "action=allow",
				"protocol=UDP", "remoteport=53", "enable=yes", "profile=any"},
			// 3. Allow outbound HTTPS to the Fendit control plane.
			{`C:\Windows\System32\netsh.exe`, "advfirewall", "firewall", "add", "rule",
				"name=FENDIT-ISO-CTRL", "dir=out", "action=allow",
				"protocol=TCP", "remoteport=443", "enable=yes", "profile=any"},
		}
	case "darwin":
		// Write a pfctl anchor that blocks everything except DNS + control plane.
		rules := "block drop all\n" +
			"pass out proto udp to any port 53\n" +
			"pass out proto tcp to any port 443\n"
		anchorFile := "/etc/pf.anchors/fendit-isolate"
		if err := os.WriteFile(anchorFile, []byte(rules), 0600); err != nil {
			return ActionResult{IntentID: i.ID, Success: false, Error: err.Error()}
		}
		cmds = [][]string{
			{"/sbin/pfctl", "-a", "fendit/isolate", "-f", anchorFile},
		}
	}
	return i.runSequential(ctx, cmds)
}

// executeUnisolate removes the isolation firewall rules applied by executeIsolate.
func (i *Intent) executeUnisolate(ctx context.Context) ActionResult {
	var cmds [][]string
	switch runtime.GOOS {
	case "windows":
		cmds = [][]string{
			{`C:\Windows\System32\netsh.exe`, "advfirewall", "firewall", "delete", "rule",
				"name=FENDIT-ISO-DNS"},
			{`C:\Windows\System32\netsh.exe`, "advfirewall", "firewall", "delete", "rule",
				"name=FENDIT-ISO-CTRL"},
			// Restore to default-allow-outbound policy.
			{`C:\Windows\System32\netsh.exe`, "advfirewall", "set", "allprofiles",
				"firewallpolicy", "blockinbound,allowoutbound"},
		}
	case "darwin":
		cmds = [][]string{
			{"/sbin/pfctl", "-a", "fendit/isolate", "-F", "rules"},
		}
	}
	return i.runSequential(ctx, cmds)
}

// runSequential executes a list of commands in order, stopping on first error.
// Combined output of all commands is joined into the result's Output field.
func (i *Intent) runSequential(ctx context.Context, cmds [][]string) ActionResult {
	var allOut []byte
	for _, args := range cmds {
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		allOut = append(allOut, out...)
		if err != nil {
			return ActionResult{
				IntentID: i.ID,
				Success:  false,
				Output:   strings.TrimSpace(string(allOut)),
				Error:    err.Error(),
			}
		}
	}
	return ActionResult{
		IntentID: i.ID,
		Success:  true,
		Output:   strings.TrimSpace(string(allOut)),
	}
}

// ── Quarantine ────────────────────────────────────────────────────────────────

// executeQuarantine moves a file to the platform quarantine directory and strips
// all permissions so it cannot be executed or read without elevated rights.
func (i *Intent) executeQuarantine() ActionResult {
	src, err := argStr(i.Args, "filepath")
	if err != nil {
		return ActionResult{IntentID: i.ID, Success: false, Error: err.Error()}
	}
	// Reject traversal attempts before any filesystem operation.
	if strings.Contains(src, "..") || strings.ContainsRune(src, 0) {
		return ActionResult{IntentID: i.ID, Success: false, Error: "invalid filepath"}
	}

	qDir := quarantineDir()
	if err := os.MkdirAll(qDir, 0700); err != nil {
		return ActionResult{
			IntentID: i.ID, Success: false,
			Error: "cannot create quarantine dir: " + err.Error(),
		}
	}

	dst := filepath.Join(qDir, filepath.Base(src))
	if err := os.Rename(src, dst); err != nil {
		return ActionResult{
			IntentID: i.ID, Success: false,
			Error: "move to quarantine failed: " + err.Error(),
		}
	}

	// Strip all permissions so the file cannot be re-executed.
	// Windows: SetNamedSecurityInfoW via go-acl (quarantine_windows.go) — no icacls.exe.
	// macOS:   os.Chmod(path, 0) via stdlib (quarantine_darwin.go) — no chmod child process.
	if err := lockFilePermissions(dst); err != nil {
		return ActionResult{
			IntentID: i.ID,
			Success:  true,
			Output:   fmt.Sprintf("quarantined: %s (permission lock failed: %v)", dst, err),
		}
	}
	return ActionResult{
		IntentID: i.ID,
		Success:  true,
		Output:   fmt.Sprintf("quarantined: %s", dst),
	}
}

func quarantineDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Fendit/Quarantine"
	case "windows":
		return `C:\ProgramData\Fendit\Quarantine`
	default:
		return "/var/lib/fendit/quarantine"
	}
}
