package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/nijosmsft/lablink/proto/agent"
)

type mockPushFileServer struct {
	messages []*pb.PushFileRequest
	index    int
	resp     *pb.PushFileResponse
}

func (m *mockPushFileServer) Recv() (*pb.PushFileRequest, error) {
	if m.index >= len(m.messages) {
		return nil, io.EOF
	}
	msg := m.messages[m.index]
	m.index++
	return msg, nil
}

func (m *mockPushFileServer) SendAndClose(resp *pb.PushFileResponse) error {
	m.resp = resp
	return nil
}

func TestHandlePushFileRejectsIncompleteUpload(t *testing.T) {
	tempDir := t.TempDir()
	remotePath := filepath.Join(tempDir, "partial.bin")
	stream := &mockPushFileServer{
		messages: []*pb.PushFileRequest{
			{
				RemotePath: remotePath,
				FileSize:   4,
				Chunk:      []byte("ab"),
			},
		},
	}

	err := handlePushFileStream(stream)
	if err == nil {
		t.Fatal("expected truncated upload to fail")
	}
	if _, statErr := os.Stat(remotePath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected no committed file, got stat err=%v", statErr)
	}
}

func TestHandlePushFileAcceptsEmptyUpload(t *testing.T) {
	tempDir := t.TempDir()
	remotePath := filepath.Join(tempDir, "empty.bin")
	stream := &mockPushFileServer{
		messages: []*pb.PushFileRequest{
			{
				RemotePath: remotePath,
				FileSize:   0,
				IsLast:     true,
			},
		},
	}

	if err := handlePushFileStream(stream); err != nil {
		t.Fatalf("expected empty upload to succeed: %v", err)
	}
	info, err := os.Stat(remotePath)
	if err != nil {
		t.Fatalf("expected uploaded file to exist: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("expected empty file, got %d bytes", info.Size())
	}
	if stream.resp == nil || stream.resp.BytesWritten != 0 {
		t.Fatalf("expected response bytes_written=0, got %+v", stream.resp)
	}
}
