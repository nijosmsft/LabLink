package mcptools

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	pb "github.com/nijosmsft/lablink/proto/agent"
)

type pullFileClient interface {
	Recv() (*pb.PullFileResponse, error)
}

func pullRemoteFileToPath(stream pullFileClient, localPath string) (int64, error) {
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

	return written, nil
}
