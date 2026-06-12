//go:build windows

package main

import (
	"log"

	"github.com/kardianos/service"
)

// program satisfies service.Interface for the Windows Service Control Manager.
type program struct{}

func (p *program) Start(_ service.Service) error {
	go startDaemon()
	return nil
}

// Stop is called by the SCM when the service is being stopped.
// It cancels the shared context so all goroutines in startDaemon drain cleanly.
// The SCM grants a default 30-second window before killing the process.
func (p *program) Stop(_ service.Service) error {
	log.Println("daemon: Stop called by SCM — draining goroutines")
	if cancelDaemon != nil {
		cancelDaemon()
	}
	return nil
}

// runDaemon is called by main when the binary is invoked by the Windows SCM.
func runDaemon() {
	svcConfig := &service.Config{
		Name:        "FenditAgent",
		DisplayName: "Fendit Security Agent",
		Description: "Fendit endpoint protection daemon",
	}
	s, err := service.New(&program{}, svcConfig)
	if err != nil {
		log.Fatalf("daemon: service init: %v", err)
	}
	if err := s.Run(); err != nil {
		log.Fatalf("daemon: run: %v", err)
	}
}
