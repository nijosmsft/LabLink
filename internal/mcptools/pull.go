package mcptools

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/nijosmsft/lablink/internal/ops"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

type pullFileClient interface {
	Recv() (*pb.PullFileResponse, error)
}

// heartbeatInterval is the wall-clock spacing of progress heartbeats published
// to the ops registry during a streaming transfer. ~5s is a deliberate
// trade-off: frequent enough to keep MCP transports' liveness checks happy
// (Copilot CLI's default tool-call budget is ~60s) without spamming the
// registry once per 1 MB chunk.
const heartbeatInterval = 5 * time.Second

// progressReporter is the minimal subset of *ops.Handle the transfer functions
// need. Tests substitute a recording fake.
type progressReporter interface {
	Progress(bytesDone, bytesTotal int64)
}

// progressNotifier is called from the heartbeat goroutine to send an MCP
// notifications/progress message to the MCP client during a long-running
// transfer. done and total are byte counts. The function must be safe to call
// from any goroutine. A nil value is treated as a no-op.
type progressNotifier func(done, total int64)

// nopProgressReporter is used when callers don't supply a handle (e.g. the
// pulltest CLI). It avoids nil-check noise in the streaming loop.
type nopProgressReporter struct{}

func (nopProgressReporter) Progress(int64, int64) {}

var _ progressReporter = (*ops.Handle)(nil)
var _ progressReporter = nopProgressReporter{}

func pullRemoteFileToPath(stream pullFileClient, localPath string) (int64, error) {
	return pullRemoteFileToPathWithProgress(context.Background(), stream, localPath, nopProgressReporter{}, nil)
}

// pullRemoteFileToPathWithProgress is the heartbeat-aware variant used by the
// MCP handler. A ticker goroutine reads an atomic byte counter the streaming
// loop updates and forwards (bytesDone, bytesTotal) to the progress reporter
// every ~5s. If notifier is non-nil it also sends a notifications/progress
// message to the MCP client on each tick and once more on success. The ticker
// is stopped on function return.
func pullRemoteFileToPathWithProgress(ctx context.Context, stream pullFileClient, localPath string, reporter progressReporter, notifier progressNotifier) (int64, error) {
	if reporter == nil {
		reporter = nopProgressReporter{}
	}

	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return 0, fmt.Errorf("mkdir: %w", err)
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(localPath), ".di-download-*")
	if err != nil {
		return 0, fmt.Errorf("create temp: %w", err)
	}

	cleanup := func() {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
	}

	var (
		written      int64
		expectedSize int64
		haveSize     bool

		bytesDone  atomic.Int64
		totalSize  atomic.Int64
		hbCtx, hbCancel = context.WithCancel(ctx)
		hbDone     = make(chan struct{})
	)
	defer hbCancel()

	go func() {
		defer close(hbDone)
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-ticker.C:
				d, t := bytesDone.Load(), totalSize.Load()
				reporter.Progress(d, t)
				if notifier != nil {
					notifier(d, t)
				}
			}
		}
	}()

	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			cleanup()
			hbCancel()
			<-hbDone
			return 0, fmt.Errorf("recv: %w", err)
		}
		if !haveSize {
			expectedSize = resp.TotalSize
			haveSize = true
			totalSize.Store(resp.TotalSize)
		}
		if len(resp.Chunk) == 0 {
			continue
		}
		n, err := tmpFile.Write(resp.Chunk)
		if err != nil {
			cleanup()
			hbCancel()
			<-hbDone
			return 0, fmt.Errorf("write: %w", err)
		}
		if n != len(resp.Chunk) {
			cleanup()
			hbCancel()
			<-hbDone
			return 0, fmt.Errorf("short write: wrote %d of %d bytes", n, len(resp.Chunk))
		}
		written += int64(n)
		bytesDone.Store(written)
	}

	hbCancel()
	<-hbDone

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpFile.Name())
		return 0, fmt.Errorf("close temp: %w", err)
	}

	if haveSize && written != expectedSize {
		os.Remove(tmpFile.Name())
		return 0, fmt.Errorf("size mismatch: wrote %d of %d bytes", written, expectedSize)
	}

	if err := os.Rename(tmpFile.Name(), localPath); err != nil {
		os.Remove(tmpFile.Name())
		return 0, fmt.Errorf("rename: %w", err)
	}

	// Publish one final progress so observers see the terminal byte count
	// before the op transitions to "finished".
	reporter.Progress(written, totalSize.Load())
	if notifier != nil {
		notifier(written, totalSize.Load())
	}

	return written, nil
}
