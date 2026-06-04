//go:build !windows

package main

import (
	"syscall"
)

// pidAlive returns true if a process with the given PID currently exists.
// Uses kill(pid, 0) which succeeds when the process is accessible.
func pidAlive(pid int32) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(int(pid), 0)
	if err == nil {
		return true
	}
	// EPERM means the process exists but we can't signal it — still alive.
	if err == syscall.EPERM {
		return true
	}
	return false
}

// killProcessTree kills the process group. setDetachedPlatform establishes
// the child as the leader of a new process group (pgid=pid), so signalling
// -pid reaches every descendant that hasn't escaped the group.
func killProcessTree(pid int32, force bool) error {
	sig := syscall.SIGTERM
	if force {
		sig = syscall.SIGKILL
	}
	// Try the group first; fall back to the single process.
	if err := syscall.Kill(-int(pid), sig); err == nil {
		return nil
	}
	return syscall.Kill(int(pid), sig)
}
