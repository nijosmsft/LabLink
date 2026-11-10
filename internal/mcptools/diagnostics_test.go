package mcptools

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	internalsec "github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"

	"google.golang.org/grpc"
)

// etwMockAgent is a minimal NodeAgent that returns success for every Execute
// call and delivers a 2-byte payload from PullFile.
type etwMockAgent struct {
	pb.UnimplementedNodeAgentServer
	delay time.Duration
}

func (a *etwMockAgent) Execute(_ *pb.ExecuteRequest, stream grpc.ServerStreamingServer[pb.ExecuteResponse]) error {
	time.Sleep(a.delay)
	if err := stream.Send(&pb.ExecuteResponse{Pid: 1}); err != nil {
		return err
	}
	return stream.Send(&pb.ExecuteResponse{Done: true, ExitCode: 0})
}

func (a *etwMockAgent) PullFile(_ *pb.PullFileRequest, stream grpc.ServerStreamingServer[pb.PullFileResponse]) error {
	return stream.Send(&pb.PullFileResponse{Chunk: []byte{0xAB, 0xCD}, TotalSize: 2})
}

func startEtwMockAgent(t *testing.T, delay time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	pb.RegisterNodeAgentServer(srv, &etwMockAgent{delay: delay})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Stop(); ln.Close() })
	return ln.Addr().String()
}

func TestCollectEtwTrace_UsesSinglePhaseHeartbeatAcrossFinalization(t *testing.T) {
	shrinkHeartbeatInterval(t)
	var mu sync.Mutex
	var messages []string
	heartbeatDetailNotifierOverride = func(_, _ int64, message string) {
		mu.Lock()
		messages = append(messages, message)
		mu.Unlock()
	}
	t.Cleanup(func() { heartbeatDetailNotifierOverride = nil })

	addr := startEtwMockAgent(t, 75*time.Millisecond)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	h := collectEtwTraceHandler(reg, pool, log)
	localEtl := filepath.Join(t.TempDir(), "trace.etl")

	req := reqWithToken(map[string]any{
		"node":         "node1",
		"profile":      "CPU",
		"duration":     float64(0),
		"local_output": localEtl,
	})

	res, err := h(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("expected success result, got: %#v", res)
	}

	mu.Lock()
	joined := strings.Join(messages, "\n")
	mu.Unlock()
	if !strings.Contains(joined, "phase=finalize; status=stopping WPR and finalizing the ETL") {
		t.Fatalf("expected finalization heartbeat, got: %q", joined)
	}
}
