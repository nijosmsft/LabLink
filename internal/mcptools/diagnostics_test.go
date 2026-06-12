package mcptools

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	internalsec "github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"

	"google.golang.org/grpc"
)

// etwMockAgent is a minimal NodeAgent that returns success for every Execute
// call and delivers a 2-byte payload from PullFile. It is used to assert that
// collect_etw_trace wires the Stage-2 byte-progress notifier.
type etwMockAgent struct {
	pb.UnimplementedNodeAgentServer
}

func (a *etwMockAgent) Execute(_ *pb.ExecuteRequest, stream grpc.ServerStreamingServer[pb.ExecuteResponse]) error {
	if err := stream.Send(&pb.ExecuteResponse{Pid: 1}); err != nil {
		return err
	}
	return stream.Send(&pb.ExecuteResponse{Done: true, ExitCode: 0})
}

func (a *etwMockAgent) PullFile(_ *pb.PullFileRequest, stream grpc.ServerStreamingServer[pb.PullFileResponse]) error {
	return stream.Send(&pb.PullFileResponse{Chunk: []byte{0xAB, 0xCD}, TotalSize: 2})
}

func startEtwMockAgent(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	pb.RegisterNodeAgentServer(srv, &etwMockAgent{})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Stop(); ln.Close() })
	return ln.Addr().String()
}

func TestCollectEtwTrace_Stage2NotifierIsWired(t *testing.T) {
	shrinkHeartbeatInterval(t)
	rec := withNotifRecorder(t)

	addr := startEtwMockAgent(t)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	h := collectEtwTraceHandler(reg, pool, log)
	localEtl := filepath.Join(t.TempDir(), "trace.etl")

	// duration=0 so Start-Sleep 0 returns instantly; the mock Execute completes
	// before a single 50 ms tick fires. Any notification in rec therefore comes
	// from the Stage-2 pull, not Stage-1.
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

	// pullRemoteFileToPathWithProgress calls notifier(written, total) once at
	// transfer completion. heartbeatNotifierOverride is the test seam wired by
	// withNotifRecorder; it must have been passed as the Stage-2 notifier.
	if n := rec.count(); n < 1 {
		t.Fatalf("expected >=1 Stage-2 progress notification (Stage-2 notifier not wired?), got %d", n)
	}
}
