package mcptools

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/nijosmsft/lablink/internal/ops"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

type pullFileClient interface {
	Recv() (*pb.PullFileResponse, error)
}

var _ progressReporter = (*ops.Handle)(nil)
var _ progressReporter = nopProgressReporter{}

func pullRemoteFileToPath(stream pullFileClient, localPath string) (int64, error) {
	return pullRemoteFileToPathWithProgress(context.Background(), stream, localPath, nil, nil)
}

// pullRemoteFileToPathWithProgress is the heartbeat-aware variant used by the
// MCP handler. The shared transfer heartbeat publishes byte progress to the
// operations registry and MCP client every ~5s and once more on success.
func pullRemoteFileToPathWithProgress(ctx context.Context, stream pullFileClient, localPath string, reporter progressReporter, notifier progressNotifier) (int64, error) {
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
	)
	progress := newTransferProgress(0)
	stopHeartbeat := startTransferProgressHeartbeat(ctx, reporter, notifier, progress)
	defer stopHeartbeat()

	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			cleanup()
			return 0, fmt.Errorf("recv: %w", err)
		}
		if !haveSize {
			expectedSize = resp.TotalSize
			haveSize = true
			progress.SetTotal(resp.TotalSize)
		}
		if len(resp.Chunk) == 0 {
			continue
		}
		n, err := tmpFile.Write(resp.Chunk)
		if err != nil {
			cleanup()
			return 0, fmt.Errorf("write: %w", err)
		}
		if n != len(resp.Chunk) {
			cleanup()
			return 0, fmt.Errorf("short write: wrote %d of %d bytes", n, len(resp.Chunk))
		}
		written += int64(n)
		progress.Add(int64(n))
	}

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
	publishTransferProgress(reporter, notifier, progress)

	return written, nil
}
