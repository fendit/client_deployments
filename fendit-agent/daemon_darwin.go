//go:build darwin

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// runDaemon is called when the binary is launched by the eu.fendit.agent LaunchDaemon.
// launchd manages process lifecycle; we run startDaemon and block on SIGTERM/SIGINT.
func runDaemon() {
	log.SetFlags(log.Ldate | log.Ltime)
	log.SetOutput(os.Stdout) // launchd redirects stdout to the log file defined in the plist.

	go startDaemon()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit

	log.Println("daemon: signal received — cancelling context")
	if cancelDaemon != nil {
		cancelDaemon()
	}
	// Give goroutines a brief window to drain before launchd kills us.
	time.Sleep(4 * time.Second)
	log.Println("daemon: shutdown complete")
}
