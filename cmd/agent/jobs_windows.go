//go:build windows

package main

import (
	"os/exec"
	"strconv"

	"golang.org/x/sys/windows"
)

// pidAlive returns true if a process with the given PID currently exists.
func pidAlive(pid int32) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var exitCode uint32
	if err := windows.GetExitCodeProcess(h, &exitCode); err != nil {
		return false
	}
	// STILL_ACTIVE = 259; anything else means the process has exited.
	return exitCode == 259
}

// killProcessTree kills a process and all its descendants.
// taskkill /T walks the descendant tree; /F force-terminates.
func killProcessTree(pid int32, force bool) error {
	args := []string{"/T", "/PID", strconv.Itoa(int(pid))}
	if force {
		args = append([]string{"/F"}, args...)
	}
	cmd := exec.Command("taskkill.exe", args...)
	// Best-effort: taskkill returns non-zero when the PID is already gone.
	_ = cmd.Run()
	return nil
}
