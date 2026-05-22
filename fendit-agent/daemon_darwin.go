//go:build darwin

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

// runDaemon is called when the binary is launched by the eu.fendit.agent LaunchDaemon.
// launchd manages process lifecycle; we just run the loop and handle SIGTERM cleanly.
func runDaemon() {
	log.SetFlags(log.Ldate | log.Ltime)
	log.SetOutput(os.Stdout) // launchd redirects stdout to the log file in the plist.

	go daemonLoop()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit
	log.Println("Fendit daemon stopping")
}
