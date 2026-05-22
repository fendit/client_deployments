package main

import (
	"log"
	"net/http"
	"time"
)

// daemonLoop is the main body of the background service on both platforms.
// It launches the action poller and runs a periodic health-ping.
func daemonLoop() {
	log.Println("Fendit daemon started")

	cfg, err := loadConfig()
	if err != nil {
		log.Printf("daemon: cannot load config: %v", err)
		return
	}

	// Launch the intent poller — polls /api/control/v1/actions/pending every 5 s.
	go runActionPoller(cfg)

	// Local YARA watcher — scans new executables in user Downloads directories.
	go runLocalYaraWatcher(cfg)

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		pingHealthAPI(cfg)
	}
}

func pingHealthAPI(cfg *Config) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", cfg.endpoint(pathHealth), nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+cfg.ReflexToken)
	req.Header.Set("User-Agent", "Fendit-Agent/2.0")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("daemon: health ping failed: %v", err)
		return
	}
	resp.Body.Close()
}
