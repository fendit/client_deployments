//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"github.com/kardianos/service"
	"golang.org/x/sys/windows/registry"
)

// runUninstall removes all Fendit components from the device:
//  1. Stops and unregisters the Windows service
//  2. Removes Defender exclusions (restores full Defender coverage)
//  3. Removes the Run key and protocol handler from the registry
//  4. Deletes the Fendit binary and data directory
//
// Invoked via: fendit-agent.exe --uninstall (requires elevation)
func runUninstall() {
	fmt.Println("[*] Fendit uninstall started...")

	// 1. Stop and remove the Windows service.
	svcConfig := &service.Config{
		Name:       "FenditAgent",
		Executable: agentBinDst,
	}
	s, err := service.New(&program{}, svcConfig)
	if err == nil {
		s.Stop()     //nolint:errcheck
		time.Sleep(2 * time.Second)
		s.Uninstall() //nolint:errcheck
	}
	fmt.Println("[*] Service removed.")

	// 2. Remove Defender exclusions — restore full Defender coverage.
	removeDefenderExclusions()

	// 3. Remove tray Run key.
	k, err := registry.OpenKey(
		registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE,
	)
	if err == nil {
		k.DeleteValue("FenditTray") //nolint:errcheck
		k.Close()
	}

	// 4. Remove fendit:// protocol handler from registry.
	registry.DeleteKey(registry.CLASSES_ROOT, `fendit\shell\open\command`) //nolint:errcheck
	registry.DeleteKey(registry.CLASSES_ROOT, `fendit\shell\open`)         //nolint:errcheck
	registry.DeleteKey(registry.CLASSES_ROOT, `fendit\shell`)              //nolint:errcheck
	registry.DeleteKey(registry.CLASSES_ROOT, `fendit`)                    //nolint:errcheck

	// 5. Remove data directory (logs, config, events, quarantine).
	//    The binary cannot delete itself while running, so we schedule
	//    deletion at next boot via MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT.
	os.RemoveAll(fenditDir) //nolint:errcheck
	scheduleFileDeleteOnReboot(agentBinDst)

	fmt.Println("[SUCCESS] Fendit removed. The agent binary will be deleted on next restart.")
}

// scheduleFileDeleteOnReboot uses MoveFileExW with MOVEFILE_DELAY_UNTIL_REBOOT
// to delete a file the next time Windows starts. This is the standard pattern
// for deleting the running binary during uninstall.
func scheduleFileDeleteOnReboot(path string) {
	const moveFileDelayUntilReboot = 0x4
	dll, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return
	}
	defer dll.Release()
	proc, err := dll.FindProc("MoveFileExW")
	if err != nil {
		return
	}
	from, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	proc.Call(uintptr(unsafe.Pointer(from)), 0, moveFileDelayUntilReboot) //nolint:errcheck
}

// stopWazuh stops the Wazuh service as part of uninstall.
func stopWazuh() {
	cmd := exec.Command("sc.exe", "stop", wazuhSvcName)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Run() //nolint:errcheck
}
