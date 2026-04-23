package mcptools

import (
	"bytes"
	"io"
	"testing"

	pb "github.com/nijosmsft/lablink/proto/agent"
)

type mockPushFileClient struct {
	messages []*pb.PushFileRequest
	resp     *pb.PushFileResponse
}

func (m *mockPushFileClient) Send(msg *pb.PushFileRequest) error {
	clone := &pb.PushFileRequest{
		RemotePath: msg.RemotePath,
		IsLast:     msg.IsLast,
		FileSize:   msg.FileSize,
	}
	if len(msg.Chunk) > 0 {
		clone.Chunk = append([]byte(nil), msg.Chunk...)
	}
	m.messages = append(m.messages, clone)
	return nil
}

func (m *mockPushFileClient) CloseAndRecv() (*pb.PushFileResponse, error) {
	if m.resp == nil {
		m.resp = &pb.PushFileResponse{}
	}
	return m.resp, nil
}

func TestSendLocalFileSendsTerminalChunkForEmptyFile(t *testing.T) {
	stream := &mockPushFileClient{}

	if _, err := sendLocalFile(stream, bytes.NewReader(nil), 0, `C:\temp\empty.bin`); err != nil {
		t.Fatalf("sendLocalFile failed: %v", err)
	}

	if len(stream.messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(stream.messages))
	}
	if !stream.messages[0].IsLast || len(stream.messages[0].Chunk) != 0 {
		t.Fatalf("expected empty terminal message, got %+v", stream.messages[0])
	}
}

func TestSendLocalFileSendsTerminalChunkForAlignedFile(t *testing.T) {
	stream := &mockPushFileClient{}
	payload := bytes.Repeat([]byte("a"), transferChunkSize)

	if _, err := sendLocalFile(stream, bytes.NewReader(payload), int64(len(payload)), `C:\temp\aligned.bin`); err != nil {
		t.Fatalf("sendLocalFile failed: %v", err)
	}

	if len(stream.messages) != 2 {
		t.Fatalf("expected data chunk plus terminal chunk, got %d messages", len(stream.messages))
	}
	if stream.messages[0].IsLast {
		t.Fatal("expected first chunk to be non-terminal for aligned file")
	}
	if !stream.messages[1].IsLast || len(stream.messages[1].Chunk) != 0 {
		t.Fatalf("expected final terminal chunk, got %+v", stream.messages[1])
	}
}

func TestSendLocalFilePropagatesReadErrors(t *testing.T) {
	stream := &mockPushFileClient{}
	reader := io.MultiReader(bytes.NewReader([]byte("ok")), errReader{})

	if _, err := sendLocalFile(stream, reader, 2, `C:\temp\bad.bin`); err == nil {
		t.Fatal("expected read error")
	}
}

type errReader struct{}

func (errReader) Read(_ []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}
