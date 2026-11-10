package mcptools

import (
	"context"
	"fmt"
	"io"

	pb "github.com/nijosmsft/lablink/proto/agent"
)

type pushFileClient interface {
	Send(*pb.PushFileRequest) error
	CloseAndRecv() (*pb.PushFileResponse, error)
}

func sendLocalFile(stream pushFileClient, r io.Reader, fileSize int64, remotePath string) (*pb.PushFileResponse, error) {
	return sendLocalFileWithProgress(context.Background(), stream, r, fileSize, remotePath, nil, nil)
}

// sendLocalFileWithProgress is the heartbeat-aware variant used by the MCP
// handler. The shared transfer heartbeat publishes byte progress to the
// operations registry and MCP client every ~5s and once more on success.
func sendLocalFileWithProgress(ctx context.Context, stream pushFileClient, r io.Reader, fileSize int64, remotePath string, reporter progressReporter, notifier progressNotifier) (*pb.PushFileResponse, error) {
	progress := newTransferProgress(fileSize)
	stopHeartbeat := startTransferProgressHeartbeat(ctx, reporter, notifier, progress)
	defer stopHeartbeat()

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
				return nil, fmt.Errorf("send chunk: %w", err)
			}
			sentAny = true
			sentLast = msg.IsLast
			progress.Add(int64(n))
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
			return nil, fmt.Errorf("send final chunk: %w", err)
		}
		if !sentAny {
			sentAny = true
		}
	}

	if !sentAny {
		return nil, fmt.Errorf("no data sent")
	}

	resp, err := stream.CloseAndRecv()
	if err == nil {
		publishTransferProgress(reporter, notifier, progress)
	}
	return resp, err
}
