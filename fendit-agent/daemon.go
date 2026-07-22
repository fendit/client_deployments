package main

import (
	"context"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

// runUpdateScheduler ticks every 5 minutes and applies any pending update whose
// ScheduledAt time has elapsed (or is empty, meaning apply as soon as possible).
func runUpdateScheduler(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkAndApplyUpdate()
		}
	}
}

func checkAndApplyUpdate() {
	// On macOS the daemon runs as root; handle force-restart requests written by
	// the tray (user session, no shutdown privilege) to restart_state.json.
	if runtime.GOOS == "darwin" {
		if rs, _ := readRestartState(); rs != nil && rs.ForceRequested {
			clearRestartState()
			logger.Info().Msg("daemon: executing force restart requested by tray")
			exec.Command("shutdown", "-r", "+1", //nolint:errcheck
				"Fendit Security: completing a pending security update").Run()
			return
		}
	}

	state, err := readUpdateState()
	if err != nil || state == nil || !state.Pending {
		return
	}
	// Only act on "pending" — skip if already downloading, installing, done, or failed.
	if state.Status != "pending" {
		return
	}
	// Honour the scheduled time when set.
	if state.ScheduledAt != "" {
		t, err := time.Parse(time.RFC3339, state.ScheduledAt)
		if err != nil || time.Now().Before(t) {
			return
		}
	}
	logger.Info().Strs("components", state.Components).Msg("scheduler: triggering pending update")
	applyPendingUpdate(state)
}

// cancelDaemon is set once by startDaemon and called by OS-specific shutdown
// handlers (daemon_windows.go Stop, daemon_darwin.go signal handler).
var cancelDaemon context.CancelFunc

// startDaemon loads config, creates the root context, and runs all background
// goroutines until the context is cancelled. It blocks until every goroutine
// returns — the OS-specific wrappers launch it in a goroutine and then wait for
// an OS signal or SCM Stop before calling cancelDaemon().
func startDaemon() {
	ctx, cancel := context.WithCancel(context.Background())
	cancelDaemon = cancel
	defer cancel()

	cfg, err := loadConfig()
	if err != nil {
		logger.Fatal().Err(err).Msg("daemon: cannot load config")
	}

	// Make cfg and start time available to the panic handler / crash reporter.
	daemonCfg = cfg
	agentStartTime = time.Now()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		runActionPoller(ctx, cfg)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		runLocalYaraWatcher(ctx, cfg)
	}()

	// runHeartbeat replaces runHealthPinger: sends a structured POST payload
	// every 5 minutes and queues to disk on any network failure.
	wg.Add(1)
	go func() {
		defer wg.Done()
		runHeartbeat(ctx, cfg)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		runHoneypotWatcher(ctx, cfg)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		runPendingFlusher(ctx, cfg)
	}()

	// Direct Socket: instant command dispatch from Guardian via persistent WebSocket.
	// The HTTP poll path (runActionPoller) remains active as a fallback when the
	// socket is reconnecting.
	wg.Add(1)
	go func() {
		defer wg.Done()
		runDirectSocket(ctx, cfg)
	}()

	// Update scheduler: reads update_state.json every 5 minutes and applies
	// any pending update whose ScheduledAt time has passed (or is empty = ASAP).
	wg.Add(1)
	go func() {
		defer wg.Done()
		runUpdateScheduler(ctx)
	}()

	logger.Info().Str("org", cfg.OrgName).Str("api", cfg.APIBase).Msg("daemon: started")
	wg.Wait()
	logger.Info().Msg("daemon: all goroutines stopped — clean shutdown complete")
}
