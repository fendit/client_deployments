//go:build windows

package main

import (
	"github.com/hectane/go-acl"
	"golang.org/x/sys/windows"
)

// lockFilePermissions removes all access to path except for SYSTEM (full control).
// Inheritance is disabled so the quarantine directory's permissive ACL does not
// flow into the file. Uses SetNamedSecurityInfoW via go-acl — no icacls.exe
// child process is spawned.
func lockFilePermissions(path string) error {
	return acl.Apply(
		path,
		true,  // disable inheritance
		false, // discard inherited ACEs rather than copying them
		acl.GrantName(windows.GENERIC_ALL, "SYSTEM"),
	)
}
