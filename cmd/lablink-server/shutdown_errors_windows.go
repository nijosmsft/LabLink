//go:build windows

package main

import (
	"errors"
	"syscall"
)

const (
	windowsErrBrokenPipe       = syscall.Errno(109)
	windowsErrNoData           = syscall.Errno(232)
	windowsErrOperationAborted = syscall.Errno(995)
)

func isPlatformExpectedStdioShutdownError(err error) bool {
	return errors.Is(err, windowsErrBrokenPipe) ||
		errors.Is(err, windowsErrNoData) ||
		errors.Is(err, windowsErrOperationAborted)
}
