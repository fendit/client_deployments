package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const intentExecTimeout = 10 * time.Second

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

// Execute dispatches the intent using OS-native commands.
// No shell interpreter is invoked — every case calls exec.CommandContext with a fixed
// argument list, eliminating shell injection entirely.
func (i *Intent) Execute() ActionResult {
	ctx, cancel := context.WithTimeout(context.Background(), intentExecTimeout)
	defer cancel()

	switch i.Action {
	case "kill_process":
		cmd, err := buildKillCmd(ctx, i.Args)
		return i.execCmd(cmd, err)
	case "isolate":
		// Reuse the proven severNetwork() path — handles all adapters per-platform.
		severNetwork()
		return ActionResult{IntentID: i.ID, Success: true, Output: "network severed"}
	case "block_ip":
		cmd, err := buildBlockIPCmd(ctx, i.Args)
		return i.execCmd(cmd, err)
	case "suspend_process":
		cmd, err := buildSuspendCmd(ctx, i.Args)
		return i.execCmd(cmd, err)
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
// buildErr is from the builder functions — if it's non-nil the command is never run.
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

func buildKillCmd(ctx context.Context, args map[string]interface{}) (*exec.Cmd, error) {
	pid, err := argStr(args, "pid")
	if err != nil {
		return nil, err
	}
	switch runtime.GOOS {
	case "windows":
		return exec.CommandContext(ctx, "taskkill.exe", "/F", "/PID", pid), nil
	default:
		return exec.CommandContext(ctx, "kill", "-9", pid), nil
	}
}

func buildBlockIPCmd(ctx context.Context, args map[string]interface{}) (*exec.Cmd, error) {
	ip, err := argStr(args, "ip")
	if err != nil {
		return nil, err
	}
	switch runtime.GOOS {
	case "windows":
		// Windows Defender Firewall — fixed arg list, no shell.
		return exec.CommandContext(ctx,
			"netsh", "advfirewall", "firewall", "add", "rule",
			"name=FenditBlock-"+ip,
			"dir=both",
			"action=block",
			"remoteip="+ip,
			"enable=yes",
			"profile=any",
		), nil
	case "darwin":
		// Null-route via the kernel routing table (no pf rule editing needed).
		return exec.CommandContext(ctx, "route", "add", "-host", ip, "127.0.0.1"), nil
	default:
		return exec.CommandContext(ctx, "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"), nil
	}
}

func buildSuspendCmd(ctx context.Context, args map[string]interface{}) (*exec.Cmd, error) {
	pid, err := argStr(args, "pid")
	if err != nil {
		return nil, err
	}
	switch runtime.GOOS {
	case "windows":
		// No native Windows CLI for process suspension without extra tooling; kill is the safe fallback.
		return exec.CommandContext(ctx, "taskkill.exe", "/F", "/PID", pid), nil
	default:
		return exec.CommandContext(ctx, "kill", "-STOP", pid), nil
	}
}

// executeQuarantine moves a file to the platform quarantine directory and strips
// all permissions so it cannot be executed or read without elevated rights.
// Uses os.Rename (no exec) for the move, then a native permission command.
func (i *Intent) executeQuarantine() ActionResult {
	src, err := argStr(i.Args, "filepath")
	if err != nil {
		return ActionResult{IntentID: i.ID, Success: false, Error: err.Error()}
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var permCmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// Deny everyone read+execute access via icacls.
		permCmd = exec.CommandContext(ctx, "icacls", dst, "/deny", "Everyone:(RX)")
	default:
		permCmd = exec.CommandContext(ctx, "chmod", "000", dst)
	}
	permOut, _ := permCmd.CombinedOutput()

	return ActionResult{
		IntentID: i.ID,
		Success:  true,
		Output:   fmt.Sprintf("quarantined: %s\n%s", dst, strings.TrimSpace(string(permOut))),
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
