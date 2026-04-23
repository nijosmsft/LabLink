package main

import (
	"context"
	"io"
	"net"
	"os"
	"testing"
)

func TestIsExpectedStdioShutdownErrorCommonCases(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "context canceled", err: context.Canceled, want: true},
		{name: "eof", err: io.EOF, want: true},
		{name: "os closed", err: os.ErrClosed, want: true},
		{name: "net closed", err: net.ErrClosed, want: true},
		{name: "other", err: context.DeadlineExceeded, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isExpectedStdioShutdownError(tt.err); got != tt.want {
				t.Fatalf("isExpectedStdioShutdownError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
