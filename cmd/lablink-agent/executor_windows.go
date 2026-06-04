//go:build windows

package main

import "syscall"

const createNoWindow = 0x08000000

func setDetachedPlatform(attr *syscall.SysProcAttr) {
	// CREATE_NEW_PROCESS_GROUP detaches from the parent's console group.
	// CREATE_NO_WINDOW provides a hidden console so stdout/stderr still work
	// (unlike DETACHED_PROCESS which gives no console at all, causing
	// console apps to crash or silently exit).
	attr.CreationFlags = syscall.CREATE_NEW_PROCESS_GROUP | createNoWindow
}
