//go:build windows

package main

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// setRunKey writes the FenditTray entry to the current user's Run key using the
// native Windows registry API. No powershell.exe or reg.exe is spawned.
func setRunKey(exePath string) error {
	k, err := registry.OpenKey(
		registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE,
	)
	if err != nil {
		return fmt.Errorf("open Run key: %w", err)
	}
	defer k.Close()

	return k.SetStringValue("FenditTray", fmt.Sprintf(`"%s" --tray`, exePath))
}

// registerProtocolHandler writes the fendit:// URI scheme into HKEY_CLASSES_ROOT
// using the native registry API. Requires the process to be elevated (called
// after relaunchAsAdmin succeeds). No reg.exe child process is spawned.
func registerProtocolHandler(exePath string) error {
	root, _, err := registry.CreateKey(registry.CLASSES_ROOT, `fendit`, registry.WRITE)
	if err != nil {
		return fmt.Errorf("create fendit key: %w", err)
	}
	defer root.Close()

	if err := root.SetStringValue("", "URL:Fendit Protocol"); err != nil {
		return fmt.Errorf("set fendit default value: %w", err)
	}
	if err := root.SetStringValue("URL Protocol", ""); err != nil {
		return fmt.Errorf("set URL Protocol: %w", err)
	}

	cmd, _, err := registry.CreateKey(registry.CLASSES_ROOT, `fendit\shell\open\command`, registry.WRITE)
	if err != nil {
		return fmt.Errorf("create fendit command key: %w", err)
	}
	defer cmd.Close()

	// %1 is the URL passed by the shell when the protocol is activated.
	return cmd.SetStringValue("", fmt.Sprintf(`"%s" "%%1"`, exePath))
}

// installWindowsService registers agentBinDst as an auto-start Windows service
// using the Service Control Manager API directly. No sc.exe or cmd.exe is spawned.
//
// If a previous FenditAgent service exists it is stopped and deleted first so
// the installer is idempotent across re-installs and upgrades.
func installWindowsService(exePath string) error {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("OpenSCManager: %w", err)
	}
	defer windows.CloseServiceHandle(scm) //nolint:errcheck

	svcNamePtr, err := windows.UTF16PtrFromString("FenditAgent")
	if err != nil {
		return err
	}

	// Remove stale registration so re-install is always clean.
	existing, err := windows.OpenService(scm, svcNamePtr, windows.SERVICE_STOP|windows.DELETE)
	if err == nil {
		var status windows.SERVICE_STATUS
		windows.ControlService(existing, windows.SERVICE_CONTROL_STOP, &status) //nolint:errcheck
		time.Sleep(500 * time.Millisecond)
		windows.DeleteService(existing) //nolint:errcheck
		windows.CloseServiceHandle(existing) //nolint:errcheck
		time.Sleep(500 * time.Millisecond)
	}

	displayNamePtr, err := windows.UTF16PtrFromString("Fendit Security Agent")
	if err != nil {
		return err
	}

	// The binary path passed to the SCM must be quoted when it contains spaces
	// (e.g. "C:\Program Files\...") so that the SCM can locate the executable
	// unambiguously when starting the service.
	quotedPath := `"` + exePath + `"`
	exePathPtr, err := windows.UTF16PtrFromString(quotedPath)
	if err != nil {
		return err
	}

	svcHandle, err := windows.CreateService(
		scm,
		svcNamePtr,
		displayNamePtr,
		windows.SERVICE_ALL_ACCESS,
		windows.SERVICE_WIN32_OWN_PROCESS,
		windows.SERVICE_AUTO_START,
		windows.SERVICE_ERROR_NORMAL,
		exePathPtr,
		nil, nil, nil, nil, nil,
	)
	if err != nil {
		return fmt.Errorf("CreateService: %w", err)
	}
	defer windows.CloseServiceHandle(svcHandle) //nolint:errcheck

	if err := windows.StartService(svcHandle, 0, nil); err != nil {
		// Non-fatal: the service is registered and will start on next boot.
		// A common cause is another Wazuh/Fendit process holding a port.
		return fmt.Errorf("StartService (service registered, will start on reboot): %w", err)
	}
	return nil
}
