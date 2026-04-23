package mcptools

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/nijosmsft/lablink/proto/agent"
)

type mockPullFileClient struct {
	responses []*pb.PullFileResponse
	errors    []error
	index     int
}

func (m *mockPullFileClient) Recv() (*pb.PullFileResponse, error) {
	if m.index < len(m.errors) && m.errors[m.index] != nil {
		err := m.errors[m.index]
		m.index++
		return nil, err
	}
	if m.index < len(m.responses) {
		resp := m.responses[m.index]
		m.index++
		return resp, nil
	}
	return nil, io.EOF
}

func TestPullRemoteFileToPathRemovesPartialFileOnRecvError(t *testing.T) {
	localPath := filepath.Join(t.TempDir(), "trace.etl")
	stream := &mockPullFileClient{
		responses: []*pb.PullFileResponse{
			{Chunk: []byte("ab"), TotalSize: 4},
		},
		errors: []error{nil, io.ErrUnexpectedEOF},
	}

	if _, err := pullRemoteFileToPath(stream, localPath); err == nil {
		t.Fatal("expected pull failure")
	}
	if _, err := os.Stat(localPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no output file, got stat err=%v", err)
	}
}

func TestPullRemoteFileToPathWritesEmptyFile(t *testing.T) {
	localPath := filepath.Join(t.TempDir(), "empty.bin")
	stream := &mockPullFileClient{}

	written, err := pullRemoteFileToPath(stream, localPath)
	if err != nil {
		t.Fatalf("pullRemoteFileToPath failed: %v", err)
	}
	if written != 0 {
		t.Fatalf("written = %d, want 0", written)
	}
	info, err := os.Stat(localPath)
	if err != nil {
		t.Fatalf("expected file to exist: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("expected empty file, got %d bytes", info.Size())
	}
}

func TestPullRemoteFileToPathValidatesSize(t *testing.T) {
	localPath := filepath.Join(t.TempDir(), "bad.bin")
	stream := &mockPullFileClient{
		responses: []*pb.PullFileResponse{
			{Chunk: []byte("ab"), TotalSize: 4},
		},
	}

	if _, err := pullRemoteFileToPath(stream, localPath); err == nil {
		t.Fatal("expected size mismatch")
	}
}
