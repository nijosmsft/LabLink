package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
)

func isExpectedStdioShutdownError(err error) bool {
	if err == nil {
		return false
	}

	return errors.Is(err, context.Canceled) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, os.ErrClosed) ||
		errors.Is(err, net.ErrClosed) ||
		isPlatformExpectedStdioShutdownError(err)
}
