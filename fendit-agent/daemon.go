package main

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"
)

// cancelDaemon is set once by startDaemon and called by OS-specific shutdown handlers
// (daemon_windows.go Stop, daemon_darwin.go signal handler).
var cancelDaemon context.CancelFunc

// startDaemon loads config, creates the root context, and runs all background
// goroutines until the context is cancelled.  It blocks until every goroutine
// returns — the OS-specific wrappers launch it in a goroutine and then wait for
// an OS signal or SCM Stop before calling cancelDaemon().
func startDaemon() {
	ctx, cancel := context.WithCancel(context.Background())
	cancelDaemon = cancel
	defer cancel()

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("daemon: cannot load config: %v", err)
	}

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

	wg.Add(1)
	go func() {
		defer wg.Done()
		runHealthPinger(ctx, cfg)
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

	log.Printf("daemon: started (org=%s api=%s)", cfg.OrgName, cfg.APIBase)
	wg.Wait()
	log.Println("daemon: all goroutines stopped — clean shutdown complete")
}

// runHealthPinger sends a keep-alive ping to Guardian every 5 minutes.
func runHealthPinger(ctx context.Context, cfg *Config) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pingHealthAPI(cfg)
		}
	}
}

func pingHealthAPI(cfg *Config) {
	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet, cfg.endpoint(pathHealth), nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+cfg.ReflexToken)
	req.Header.Set("User-Agent", "Fendit-Agent/2.0")
	resp, err := agentHTTPClient.Do(req)
	if err != nil {
		log.Printf("daemon: health ping failed: %v", err)
		return
	}
	resp.Body.Close()
}
