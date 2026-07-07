//go:build windows

package main

import (
	"log"

	"github.com/hectane/go-acl"
	"golang.org/x/sys/windows"
)

// setFenditACL locks down the Fendit data directory so that only SYSTEM and
// the local Administrators group have access. All inherited ACEs are removed.
//
// Uses SetNamedSecurityInfoW via go-acl — no powershell.exe or icacls.exe
// child process is spawned at any point.
func setFenditACL() {
	err := acl.Apply(
		fenditDir,
		true,  // disableInheritance: break the inheritance chain so parent ACEs don't bleed in
		false, // keepInherited: discard any currently inherited ACEs entirely
		acl.GrantName(windows.GENERIC_ALL, "SYSTEM"),
		acl.GrantName(windows.GENERIC_ALL, "Administrators"),
	)
	if err != nil {
		// Non-fatal: log and continue. A failed ACL restricts visibility but
		// does not prevent the agent from functioning.
		log.Printf("acl: setFenditACL failed (non-fatal): %v", err)
	}
}
