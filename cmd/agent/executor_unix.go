//go:build !windows

package main

import "syscall"

func setDetachedPlatform(attr *syscall.SysProcAttr) {
	attr.Setsid = true
}
