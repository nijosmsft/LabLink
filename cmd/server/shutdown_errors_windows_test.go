//go:build windows

package main

import (
	"syscall"
	"testing"
)

func TestIsExpectedStdioShutdownErrorWindowsPipeCases(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "broken pipe", err: windowsErrBrokenPipe},
		{name: "no data", err: windowsErrNoData},
		{name: "operation aborted", err: windowsErrOperationAborted},
		{name: "other errno", err: syscall.Errno(5)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isExpectedStdioShutdownError(tt.err)
			want := tt.name != "other errno"
			if got != want {
				t.Fatalf("isExpectedStdioShutdownError(%v) = %v, want %v", tt.err, got, want)
			}
		})
	}
}
