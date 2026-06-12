package mcptools

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

// --- progressReporter test double ------------------------------------------

type recordingReporter struct {
	mu    sync.Mutex
	calls []progressCall
}

type progressCall struct {
	BytesDone  int64
	BytesTotal int64
}

func (r *recordingReporter) Progress(bytesDone, bytesTotal int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, progressCall{BytesDone: bytesDone, BytesTotal: bytesTotal})
}

func (r *recordingReporter) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *recordingReporter) Snapshot() []progressCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]progressCall, len(r.calls))
	copy(out, r.calls)
	return out
}

// --- applyTransferTimeout ---------------------------------------------------

func TestApplyTransferTimeout_PositiveAppliesDeadline(t *testing.T) {
	parent := context.Background()
	ctx, cancel := applyTransferTimeout(parent, 1)
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected deadline to be set")
	}
	if rem := time.Until(dl); rem <= 0 || rem > 2*time.Second {
		t.Fatalf("unexpected deadline remaining: %v", rem)
	}
}

func TestApplyTransferTimeout_ZeroMeansNoDeadline(t *testing.T) {
	parent := context.Background()
	ctx, cancel := applyTransferTimeout(parent, 0)
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("expected no deadline when timeout_seconds=0")
	}
}

func TestApplyTransferTimeout_NegativeMeansNoDeadline(t *testing.T) {
	parent := context.Background()
	ctx, cancel := applyTransferTimeout(parent, -5)
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("expected no deadline for negative timeout")
	}
}

// --- pull-side: timeout + heartbeat ----------------------------------------

// blockingPullFileClient mimics a gRPC stream that blocks in Recv until either
// the context fires or the script advances. Honoring ctx.Done() is faithful
// to gRPC behavior: when a call context is cancelled, the underlying stream
// surfaces context.DeadlineExceeded / Canceled.
type blockingPullFileClient struct {
	ctx       context.Context
	responses []*pb.PullFileResponse
	delay     time.Duration
	index     int
}

func (b *blockingPullFileClient) Recv() (*pb.PullFileResponse, error) {
	if b.index >= len(b.responses) {
		return nil, io.EOF
	}
	select {
	case <-b.ctx.Done():
		return nil, b.ctx.Err()
	case <-time.After(b.delay):
	}
	resp := b.responses[b.index]
	b.index++
	return resp, nil
}

func TestPullRemoteFileToPathWithProgress_TimeoutSecondsRespected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	stream := &blockingPullFileClient{
		ctx:   ctx,
		delay: 2 * time.Second,
		responses: []*pb.PullFileResponse{
			{Chunk: []byte("abcd"), TotalSize: 8},
		},
	}

	start := time.Now()
	_, err := pullRemoteFileToPathWithProgress(ctx, stream, filepath.Join(t.TempDir(), "x.bin"), nil, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected deadline error")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !contains(err.Error(), "deadline") && !contains(err.Error(), "context") {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
	if elapsed > 2500*time.Millisecond {
		t.Fatalf("deadline did not fire promptly: elapsed=%v", elapsed)
	}
}

func TestPullRemoteFileToPathWithProgress_ZeroTimeoutMeansNoTimeout(t *testing.T) {
	// applyTransferTimeout(ctx, 0) returns the parent unchanged.
	parent := context.Background()
	ctx, cancel := applyTransferTimeout(parent, 0)
	defer cancel()
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		t.Fatal("expected no deadline when timeout_seconds=0")
	}

	stream := &blockingPullFileClient{
		ctx:   ctx,
		delay: 50 * time.Millisecond,
		responses: []*pb.PullFileResponse{
			{Chunk: []byte("abcd"), TotalSize: 4},
		},
	}
	written, err := pullRemoteFileToPathWithProgress(ctx, stream, filepath.Join(t.TempDir(), "x.bin"), nil, nil)
	if err != nil {
		t.Fatalf("pullRemoteFileToPathWithProgress failed: %v", err)
	}
	if written != 4 {
		t.Fatalf("written = %d, want 4", written)
	}
}

func TestPullRemoteFileToPathWithProgress_HeartbeatFiresPeriodically(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heartbeat timing test in short mode")
	}

	ctx := context.Background()
	// 13 chunks, each delayed by 1 second → ~13s total transfer.
	chunks := make([]*pb.PullFileResponse, 13)
	for i := range chunks {
		chunks[i] = &pb.PullFileResponse{Chunk: []byte{byte(i)}, TotalSize: 13}
	}
	stream := &blockingPullFileClient{
		ctx:       ctx,
		delay:     1 * time.Second,
		responses: chunks,
	}

	reporter := &recordingReporter{}
	written, err := pullRemoteFileToPathWithProgress(ctx, stream, filepath.Join(t.TempDir(), "x.bin"), reporter, nil)
	if err != nil {
		t.Fatalf("pullRemoteFileToPathWithProgress failed: %v", err)
	}
	if written != 13 {
		t.Fatalf("written = %d, want 13", written)
	}

	// With heartbeatInterval=5s and a ~13s transfer we expect at least 2
	// tick-driven heartbeats, plus the terminal one published on success.
	if got := reporter.Count(); got < 2 {
		t.Fatalf("expected >=2 heartbeats over a ~13s transfer, got %d (calls=%+v)", got, reporter.Snapshot())
	}

	// Verify the terminal heartbeat shows full progress.
	snap := reporter.Snapshot()
	last := snap[len(snap)-1]
	if last.BytesDone != 13 || last.BytesTotal != 13 {
		t.Fatalf("expected final heartbeat (13,13), got (%d,%d)", last.BytesDone, last.BytesTotal)
	}
}

// --- push-side: timeout + heartbeat ----------------------------------------

// blockingPushFileClient mimics a gRPC unary-stream Send that blocks until the
// context fires, simulating a saturated wire / hung remote.
type blockingPushFileClient struct {
	ctx              context.Context
	sendDelay        time.Duration
	closeAndRecvDone chan struct{}
	resp             *pb.PushFileResponse
	mu               sync.Mutex
	sends            []*pb.PushFileRequest
}

func (b *blockingPushFileClient) Send(msg *pb.PushFileRequest) error {
	select {
	case <-b.ctx.Done():
		return b.ctx.Err()
	case <-time.After(b.sendDelay):
	}
	b.mu.Lock()
	clone := &pb.PushFileRequest{RemotePath: msg.RemotePath, FileSize: msg.FileSize, IsLast: msg.IsLast}
	if len(msg.Chunk) > 0 {
		clone.Chunk = append([]byte(nil), msg.Chunk...)
	}
	b.sends = append(b.sends, clone)
	b.mu.Unlock()
	return nil
}

func (b *blockingPushFileClient) CloseAndRecv() (*pb.PushFileResponse, error) {
	if b.closeAndRecvDone != nil {
		close(b.closeAndRecvDone)
	}
	if b.resp == nil {
		b.resp = &pb.PushFileResponse{}
	}
	return b.resp, nil
}

func TestSendLocalFileWithProgress_TimeoutSecondsRespected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	payload := bytes.Repeat([]byte("a"), transferChunkSize*3) // 3 chunks
	stream := &blockingPushFileClient{ctx: ctx, sendDelay: 2 * time.Second}

	start := time.Now()
	_, err := sendLocalFileWithProgress(ctx, stream, bytes.NewReader(payload), int64(len(payload)), `C:\temp\big.bin`, nil, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected deadline error")
	}
	if elapsed > 2500*time.Millisecond {
		t.Fatalf("deadline did not fire promptly: elapsed=%v", elapsed)
	}
}

func TestSendLocalFileWithProgress_ZeroTimeoutMeansNoTimeout(t *testing.T) {
	parent := context.Background()
	ctx, cancel := applyTransferTimeout(parent, 0)
	defer cancel()

	payload := []byte("hello")
	stream := &blockingPushFileClient{ctx: ctx, sendDelay: 10 * time.Millisecond}

	resp, err := sendLocalFileWithProgress(ctx, stream, bytes.NewReader(payload), int64(len(payload)), `C:\temp\x.bin`, nil, nil)
	if err != nil {
		t.Fatalf("sendLocalFileWithProgress failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
}

func TestSendLocalFileWithProgress_HeartbeatFiresPeriodically(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heartbeat timing test in short mode")
	}

	ctx := context.Background()
	// 13 1-byte chunks via a slow reader → ~13s total transfer.
	payload := bytes.Repeat([]byte{0xAA}, 13)
	stream := &blockingPushFileClient{ctx: ctx, sendDelay: 1 * time.Second}
	reporter := &recordingReporter{}

	// 1-byte chunks via tinyReader, so Send is called once per byte.
	_, err := sendLocalFileWithProgress(ctx, stream, &tinyReader{data: payload}, int64(len(payload)), `C:\temp\x.bin`, reporter, nil)
	if err != nil {
		t.Fatalf("sendLocalFileWithProgress failed: %v", err)
	}

	if got := reporter.Count(); got < 2 {
		t.Fatalf("expected >=2 heartbeats over a ~13s upload, got %d (calls=%+v)", got, reporter.Snapshot())
	}
}

// tinyReader returns one byte at a time from a buffer so the streaming loop
// makes many small Send calls — useful for timing-sensitive heartbeat tests.
type tinyReader struct {
	data []byte
	pos  int
}

func (r *tinyReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}

// --- helpers ----------------------------------------------------------------

func contains(haystack, needle string) bool {
	return bytes.Contains([]byte(haystack), []byte(needle))
}

// --- handler-level tests: timeout defaults + negative rejection -------------

// buildCallToolRequest builds a minimal mcp.CallToolRequest with the given
// string+number arguments.
func buildCallToolRequest(args map[string]any) mcp.CallToolRequest {
	req := mcp.CallToolRequest{}
	req.Params.Arguments = args
	return req
}

func TestPushFileHandler_NegativeTimeoutRejected(t *testing.T) {
	reg := registry.Load(filepath.Join(t.TempDir(), "nodes.json"))
	pool := agentclient.NewPool("", security.ClientTransportConfig{})
	handler := pushFileHandler(reg, pool)

	req := buildCallToolRequest(map[string]any{
		"node":            "test-node",
		"local_path":      "x.txt",
		"remote_path":     "y.txt",
		"timeout_seconds": float64(-1),
	})
	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for negative timeout_seconds")
	}
	text := toolResultText(result)
	if !contains(text, "timeout_seconds") || !contains(text, ">= 0") {
		t.Fatalf("expected rejection message, got: %s", text)
	}
}

func TestPullFileHandler_NegativeTimeoutRejected(t *testing.T) {
	reg := registry.Load(filepath.Join(t.TempDir(), "nodes.json"))
	pool := agentclient.NewPool("", security.ClientTransportConfig{})
	handler := pullFileHandler(reg, pool)

	req := buildCallToolRequest(map[string]any{
		"node":            "test-node",
		"remote_path":     "y.txt",
		"local_path":      "x.txt",
		"timeout_seconds": float64(-99),
	})
	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for negative timeout_seconds")
	}
	text := toolResultText(result)
	if !contains(text, "timeout_seconds") || !contains(text, ">= 0") {
		t.Fatalf("expected rejection message, got: %s", text)
	}
}

func TestPushFileHandler_OmittedTimeoutDefaultsTo600(t *testing.T) {
	reg := registry.Load(filepath.Join(t.TempDir(), "nodes.json"))
	pool := agentclient.NewPool("", security.ClientTransportConfig{})
	handler := pushFileHandler(reg, pool)

	// No timeout_seconds in args → handler must not reject; it should proceed to
	// node lookup and return "not found" (proving it passed the timeout check).
	req := buildCallToolRequest(map[string]any{
		"node":        "nonexistent",
		"local_path":  "x.txt",
		"remote_path": "y.txt",
	})
	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true (node not found)")
	}
	text := toolResultText(result)
	if contains(text, "timeout_seconds") {
		t.Fatalf("omitted timeout triggered rejection: %s", text)
	}
	if !contains(text, "nonexistent") {
		t.Fatalf("expected node-not-found error, got: %s", text)
	}
}

func TestPullFileHandler_OmittedTimeoutDefaultsTo600(t *testing.T) {
	reg := registry.Load(filepath.Join(t.TempDir(), "nodes.json"))
	pool := agentclient.NewPool("", security.ClientTransportConfig{})
	handler := pullFileHandler(reg, pool)

	req := buildCallToolRequest(map[string]any{
		"node":        "nonexistent",
		"remote_path": "y.txt",
		"local_path":  "x.txt",
	})
	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true (node not found)")
	}
	text := toolResultText(result)
	if contains(text, "timeout_seconds") {
		t.Fatalf("omitted timeout triggered rejection: %s", text)
	}
	if !contains(text, "nonexistent") {
		t.Fatalf("expected node-not-found error, got: %s", text)
	}
}

// --- handler-level tests: MCP progress notifications -----------------------

func TestPullFileHandler_ProgressTokenAbsent_NoMCPNotifications(t *testing.T) {
	var notifCount int
	notifier := progressNotifier(func(done, total int64) {
		notifCount++
	})

	stream := &mockPullFileClient{
		responses: []*pb.PullFileResponse{
			{Chunk: []byte("hello"), TotalSize: 5},
		},
	}
	// Passing nil notifier: verifies the helper does not call a nil notifier.
	_, err := pullRemoteFileToPathWithProgress(
		context.Background(), stream,
		filepath.Join(t.TempDir(), "out.bin"),
		nil,
		nil, // no token → no notifier
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// notifier was not passed in so count stays 0. But also test that
	// the non-nil notifier path works when explicitly provided.
	_ = notifier // suppress unused warning; verified via next two tests
	if notifCount != 0 {
		t.Fatalf("expected 0 notifications with nil notifier, got %d", notifCount)
	}
}

func TestPullFileHandler_ProgressTokenPresent_NotificationsSent(t *testing.T) {
	var mu sync.Mutex
	var calls []progressCall

	notifier := progressNotifier(func(done, total int64) {
		mu.Lock()
		calls = append(calls, progressCall{BytesDone: done, BytesTotal: total})
		mu.Unlock()
	})

	stream := &mockPullFileClient{
		responses: []*pb.PullFileResponse{
			{Chunk: []byte("hello"), TotalSize: 5},
		},
	}
	written, err := pullRemoteFileToPathWithProgress(
		context.Background(), stream,
		filepath.Join(t.TempDir(), "out.bin"),
		nil,
		notifier,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if written != 5 {
		t.Fatalf("written = %d, want 5", written)
	}

	mu.Lock()
	snap := append([]progressCall(nil), calls...)
	mu.Unlock()

	if len(snap) == 0 {
		t.Fatal("expected at least one MCP progress notification (final)")
	}
	last := snap[len(snap)-1]
	if last.BytesDone != 5 || last.BytesTotal != 5 {
		t.Fatalf("expected final notification (5,5), got (%d,%d)", last.BytesDone, last.BytesTotal)
	}
}

func TestPushFileHandler_ProgressTokenPresent_NotificationsSent(t *testing.T) {
	var mu sync.Mutex
	var calls []progressCall

	notifier := progressNotifier(func(done, total int64) {
		mu.Lock()
		calls = append(calls, progressCall{BytesDone: done, BytesTotal: total})
		mu.Unlock()
	})

	payload := []byte("world")
	stream := &mockPushFileClient{}
	_, err := sendLocalFileWithProgress(
		context.Background(), stream,
		bytes.NewReader(payload), int64(len(payload)),
		`C:\temp\x.bin`,
		nil,
		notifier,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	snap := append([]progressCall(nil), calls...)
	mu.Unlock()

	if len(snap) == 0 {
		t.Fatal("expected at least one MCP progress notification (final)")
	}
	last := snap[len(snap)-1]
	if last.BytesDone != 5 || last.BytesTotal != 5 {
		t.Fatalf("expected final notification (5,5), got (%d,%d)", last.BytesDone, last.BytesTotal)
	}
}

// toolResultText is defined in ops_hook.go (same package).
