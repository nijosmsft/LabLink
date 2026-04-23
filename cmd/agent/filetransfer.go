package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	pb "github.com/nijosmsft/lablink/proto/agent"
)

const chunkSize = 1024 * 1024 // 1MB

type pushFileServer interface {
	Recv() (*pb.PushFileRequest, error)
	SendAndClose(*pb.PushFileResponse) error
}

func handlePushFile(stream pb.NodeAgent_PushFileServer) error {
	return handlePushFileStream(stream)
}

func handlePushFileStream(stream pushFileServer) error {
	var (
		remotePath   string
		tmpFile      *os.File
		written      int64
		expectedSize int64 = -1
		sawLast      bool
	)

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			if tmpFile != nil {
				tmpFile.Close()
				os.Remove(tmpFile.Name())
			}
			if !sawLast {
				return fmt.Errorf("upload terminated without final chunk")
			}
			break
		}
		if err != nil {
			if tmpFile != nil {
				tmpFile.Close()
				os.Remove(tmpFile.Name())
			}
			return fmt.Errorf("recv error: %w", err)
		}

		if tmpFile == nil {
			remotePath = msg.RemotePath
			expectedSize = msg.FileSize
			if remotePath == "" {
				return fmt.Errorf("remote_path is required in first message")
			}
			// Create temp file in the same directory for atomic rename.
			dir := filepath.Dir(remotePath)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("mkdir %s: %w", dir, err)
			}
			tmpFile, err = os.CreateTemp(dir, ".di-upload-*")
			if err != nil {
				return fmt.Errorf("create temp file: %w", err)
			}
		}

		if len(msg.Chunk) > 0 {
			n, err := tmpFile.Write(msg.Chunk)
			if err != nil {
				tmpFile.Close()
				os.Remove(tmpFile.Name())
				return fmt.Errorf("write: %w", err)
			}
			if n != len(msg.Chunk) {
				tmpFile.Close()
				os.Remove(tmpFile.Name())
				return fmt.Errorf("short write: wrote %d of %d bytes", n, len(msg.Chunk))
			}
			written += int64(n)
		}

		if msg.IsLast {
			sawLast = true
			break
		}
	}

	if tmpFile == nil {
		return fmt.Errorf("no data received")
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpFile.Name())
		return fmt.Errorf("close temp file: %w", err)
	}

	if expectedSize >= 0 && written != expectedSize {
		os.Remove(tmpFile.Name())
		return fmt.Errorf("upload incomplete: wrote %d of %d bytes", written, expectedSize)
	}

	// Atomic rename.
	if err := os.Rename(tmpFile.Name(), remotePath); err != nil {
		os.Remove(tmpFile.Name())
		return fmt.Errorf("rename to %s: %w", remotePath, err)
	}

	return stream.SendAndClose(&pb.PushFileResponse{
		BytesWritten: written,
		RemotePath:   remotePath,
	})
}

func handlePullFile(remotePath string, stream pb.NodeAgent_PullFileServer) error {
	f, err := os.Open(remotePath)
	if err != nil {
		return fmt.Errorf("open %s: %w", remotePath, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", remotePath, err)
	}

	buf := make([]byte, chunkSize)
	first := true
	for {
		n, err := f.Read(buf)
		if n > 0 {
			resp := &pb.PullFileResponse{
				Chunk: buf[:n],
			}
			if first {
				resp.TotalSize = info.Size()
				first = false
			}
			if sendErr := stream.Send(resp); sendErr != nil {
				return sendErr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
	}

	return nil
}
