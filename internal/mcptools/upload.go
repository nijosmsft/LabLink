package mcptools

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	pb "github.com/nijosmsft/lablink/proto/agent"
)

type pushFileClient interface {
	Send(*pb.PushFileRequest) error
	CloseAndRecv() (*pb.PushFileResponse, error)
}

func sendLocalFile(stream pushFileClient, r io.Reader, fileSize int64, remotePath string) (*pb.PushFileResponse, error) {
	return sendLocalFileWithProgress(context.Background(), stream, r, fileSize, remotePath, nopProgressReporter{}, nil)
}

// sendLocalFileWithProgress is the heartbeat-aware variant used by the MCP
// handler. Mirrors pullRemoteFileToPathWithProgress: a ticker goroutine
// publishes (bytesSent, fileSize) every ~5s while the streaming loop updates
// an atomic counter. If notifier is non-nil it also sends a
// notifications/progress message to the MCP client on each tick and once more
// on success.
func sendLocalFileWithProgress(ctx context.Context, stream pushFileClient, r io.Reader, fileSize int64, remotePath string, reporter progressReporter, notifier progressNotifier) (*pb.PushFileResponse, error) {
	if reporter == nil {
		reporter = nopProgressReporter{}
	}

	var (
		bytesSent       atomic.Int64
		hbCtx, hbCancel = context.WithCancel(ctx)
		hbDone          = make(chan struct{})
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
				s := bytesSent.Load()
				reporter.Progress(s, fileSize)
				if notifier != nil {
					notifier(s, fileSize)
				}
			}
		}
	}()

	stopHeartbeat := func() {
		hbCancel()
		<-hbDone
	}

	buf := make([]byte, transferChunkSize)
	sentAny := false
	sentLast := false

	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			msg := &pb.PushFileRequest{
				RemotePath: remotePath,
				FileSize:   fileSize,
				Chunk:      buf[:n],
				IsLast:     readErr == io.EOF,
			}
			if err := stream.Send(msg); err != nil {
				stopHeartbeat()
				return nil, fmt.Errorf("send chunk: %w", err)
			}
			sentAny = true
			sentLast = msg.IsLast
			bytesSent.Add(int64(n))
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			stopHeartbeat()
			return nil, readErr
		}
	}

	if !sentLast {
		msg := &pb.PushFileRequest{
			RemotePath: remotePath,
			FileSize:   fileSize,
			IsLast:     true,
		}
		if err := stream.Send(msg); err != nil {
			stopHeartbeat()
			return nil, fmt.Errorf("send final chunk: %w", err)
		}
		if !sentAny {
			sentAny = true
		}
	}

	if !sentAny {
		stopHeartbeat()
		return nil, fmt.Errorf("no data sent")
	}

	resp, err := stream.CloseAndRecv()
	stopHeartbeat()
	if err == nil {
		reporter.Progress(bytesSent.Load(), fileSize)
		if notifier != nil {
			notifier(bytesSent.Load(), fileSize)
		}
	}
	return resp, err
}
