//go:build windows

package main

import (
	"log"

	"github.com/kardianos/service"
)

// program satisfies service.Interface for Windows Service Control Manager.
type program struct{}

func (p *program) Start(_ service.Service) error {
	go daemonLoop()
	return nil
}

func (p *program) Stop(_ service.Service) error {
	log.Println("Fendit daemon stopping")
	return nil
}

// runDaemon is called when the binary is invoked by the Windows SCM.
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
