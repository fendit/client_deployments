package main

import (
	"context"
	"sync"
	"time"
)

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

	logger.Info().Str("org", cfg.OrgName).Str("api", cfg.APIBase).Msg("daemon: started")
	wg.Wait()
	logger.Info().Msg("daemon: all goroutines stopped — clean shutdown complete")
}
