//go:build !windows

package main

import (
	"errors"
	"syscall"
)

func isPlatformExpectedStdioShutdownError(err error) bool {
	return errors.Is(err, syscall.EPIPE)
}
