package mcptools

import (
	"fmt"
	"io"

	pb "github.com/nijosmsft/lablink/proto/agent"
)

type pushFileClient interface {
	Send(*pb.PushFileRequest) error
	CloseAndRecv() (*pb.PushFileResponse, error)
}

func sendLocalFile(stream pushFileClient, r io.Reader, fileSize int64, remotePath string) (*pb.PushFileResponse, error) {
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
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
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

	return stream.CloseAndRecv()
}
