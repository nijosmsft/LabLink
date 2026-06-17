package mcptools

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/leasing"
	internalsec "github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"

	"google.golang.org/grpc"
)

// --- test helpers -----------------------------------------------------------

// notifRecorder records (done, total) pairs sent by the heartbeat.
type notifRecorder struct {
	mu    sync.Mutex
	calls [][2]int64
}

func (r *notifRecorder) record(done, total int64) {
	r.mu.Lock()
	r.calls = append(r.calls, [2]int64{done, total})
	r.mu.Unlock()
}

func (r *notifRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// reqWithToken returns a CallToolRequest with the given args and a
// non-nil progressToken so StartMCPHeartbeat will start its goroutine.
func reqWithToken(args map[string]any) mcp.CallToolRequest {
	req := mcp.CallToolRequest{}
	req.Params.Arguments = args
	req.Params.Meta = &mcp.Meta{ProgressToken: "test-token"}
	return req
}

// reqNoToken returns a CallToolRequest with the given args and NO progressToken.
func reqNoToken(args map[string]any) mcp.CallToolRequest {
	req := mcp.CallToolRequest{}
	req.Params.Arguments = args
	return req
}

// shrinkHeartbeatInterval reduces defaultHeartbeatInterval to 50ms for the
// duration of the test.  Must NOT be used with t.Parallel.
func shrinkHeartbeatInterval(t *testing.T) {
	t.Helper()
	orig := defaultHeartbeatInterval
	defaultHeartbeatInterval = 50 * time.Millisecond
	t.Cleanup(func() { defaultHeartbeatInterval = orig })
}

// withNotifRecorder installs rec as the heartbeatNotifierOverride and
// returns rec.  Restored via t.Cleanup.  Must NOT be used with t.Parallel.
func withNotifRecorder(t *testing.T) *notifRecorder {
	t.Helper()
	rec := &notifRecorder{}
	heartbeatNotifierOverride = rec.record
	t.Cleanup(func() { heartbeatNotifierOverride = nil })
	return rec
}

// slowExecAgent is a NodeAgent that delays by delay before completing a
// command, so heartbeat tests can observe notifications during execution.
type slowExecAgent struct {
	pb.UnimplementedNodeAgentServer
	delay time.Duration
}

func (a *slowExecAgent) Execute(_ *pb.ExecuteRequest, stream grpc.ServerStreamingServer[pb.ExecuteResponse]) error {
	if err := stream.Send(&pb.ExecuteResponse{Pid: 1}); err != nil {
		return err
	}
	time.Sleep(a.delay)
	return stream.Send(&pb.ExecuteResponse{Done: true, ExitCode: 0})
}

func (a *slowExecAgent) ExecuteScript(_ *pb.ExecuteScriptRequest, stream grpc.ServerStreamingServer[pb.ExecuteResponse]) error {
	if err := stream.Send(&pb.ExecuteResponse{Pid: 2}); err != nil {
		return err
	}
	time.Sleep(a.delay)
	return stream.Send(&pb.ExecuteResponse{Done: true, ExitCode: 0})
}

// startSlowExecAgent stands up an in-process gRPC server backed by slowExecAgent.
func startSlowExecAgent(t *testing.T, delay time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	pb.RegisterNodeAgentServer(srv, &slowExecAgent{delay: delay})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Stop(); ln.Close() })
	return ln.Addr().String()
}

// --- StartMCPHeartbeat unit tests -------------------------------------------

func TestStartMCPHeartbeat_NoToken_NoFire(t *testing.T) {
	shrinkHeartbeatInterval(t)
	rec := withNotifRecorder(t)

	stop := StartMCPHeartbeat(context.Background(), reqNoToken(nil), defaultHeartbeatInterval, func() (int64, int64) {
		return 1, 10
	})
	time.Sleep(150 * time.Millisecond)
	stop()

	if n := rec.count(); n != 0 {
		t.Fatalf("expected 0 notifications without progressToken, got %d", n)
	}
}

func TestStartMCPHeartbeat_WithToken_Fires(t *testing.T) {
	shrinkHeartbeatInterval(t)
	rec := withNotifRecorder(t)

	stop := StartMCPHeartbeat(context.Background(), reqWithToken(nil), defaultHeartbeatInterval, func() (int64, int64) {
		return 1, 10
	})
	time.Sleep(200 * time.Millisecond)
	stop()

	if n := rec.count(); n < 1 {
		t.Fatalf("expected >=1 notifications with progressToken, got %d", n)
	}
}

// --- rebootNodesHandler heartbeat tests -------------------------------------

func TestRebootNodesHandler_NoToken_NoNotification(t *testing.T) {
	shrinkRebootTunings(t)
	withScriptedRebootDial(t, false, false, true)
	shrinkHeartbeatInterval(t)
	rec := withNotifRecorder(t)

	addr, _ := startExecAgent(t)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	h := rebootNodesHandler(reg, pool, log)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := reqNoToken(map[string]any{"nodes": []string{"node1"}, "wait_seconds": 5})
	res, err := h(ctx, req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("want success, got: %#v", res)
	}

	if n := rec.count(); n != 0 {
		t.Fatalf("expected 0 notifications without progressToken, got %d", n)
	}
}

func TestRebootNodesHandler_WithToken_Fires(t *testing.T) {
	shrinkRebootTunings(t)
	withScriptedRebootDial(t, true, false, false, true)
	shrinkHeartbeatInterval(t)
	rec := withNotifRecorder(t)

	addr, _ := startExecAgent(t)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	h := rebootNodesHandler(reg, pool, log)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := reqWithToken(map[string]any{"nodes": []string{"node1"}, "wait_seconds": 5})
	res, err := h(ctx, req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("want success, got: %#v", res)
	}

	// The handler sleeps rebootNodesInitialDownSleep (50ms) before polling.
	// With defaultHeartbeatInterval=50ms, at least one tick fires.
	if n := rec.count(); n < 1 {
		t.Fatalf("expected >=1 notifications with progressToken, got %d", n)
	}
}

// --- executeCommandHandler heartbeat tests ----------------------------------

func TestExecuteCommandHandler_NoToken_NoNotification(t *testing.T) {
	shrinkHeartbeatInterval(t)
	rec := withNotifRecorder(t)

	addr := startSlowExecAgent(t, 150*time.Millisecond)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	h := executeCommandHandler(reg, pool, log)

	req := reqNoToken(map[string]any{"node": "node1", "command": "echo hello"})
	res, err := h(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("want success, got: %#v", res)
	}

	if n := rec.count(); n != 0 {
		t.Fatalf("expected 0 notifications without progressToken, got %d", n)
	}
}

func TestExecuteCommandHandler_WithToken_Fires(t *testing.T) {
	shrinkHeartbeatInterval(t)
	rec := withNotifRecorder(t)

	// The slow agent waits 200ms before Done. With interval=50ms, >=2 ticks fire.
	addr := startSlowExecAgent(t, 200*time.Millisecond)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	h := executeCommandHandler(reg, pool, log)

	req := reqWithToken(map[string]any{"node": "node1", "command": "echo hello"})
	res, err := h(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("want success, got: %#v", res)
	}

	if n := rec.count(); n < 1 {
		t.Fatalf("expected >=1 notifications with progressToken, got %d", n)
	}
}

// --- waitForReleaseHandler heartbeat tests ----------------------------------

func shrinkLeasePollTunings(t *testing.T) {
	t.Helper()
	origMax, origMin := leaseWaitPollMax, leaseWaitPollMin
	leaseWaitPollMax = 50 * time.Millisecond
	leaseWaitPollMin = 10 * time.Millisecond
	t.Cleanup(func() { leaseWaitPollMax = origMax; leaseWaitPollMin = origMin })
}

func TestWaitForReleaseHandler_NoToken_NoNotification(t *testing.T) {
	shrinkLeasePollTunings(t)
	shrinkHeartbeatInterval(t)
	rec := withNotifRecorder(t)

	store := newLeaseTestStore(t)
	lease, err := store.Acquire(context.Background(), leasing.AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 30 * time.Minute,
		AgentID:  "alice",
		Identity: leasing.Identity{EffectiveID: "alice", Hostname: "h", PID: 1, Cookie: "c"},
	})
	if err != nil {
		t.Fatalf("seed acquire: %v", err)
	}

	go func() {
		time.Sleep(120 * time.Millisecond)
		_ = store.Release(context.Background(), lease.ID, "alice")
	}()

	h := waitForReleaseHandler(store)
	req := reqNoToken(map[string]any{
		"nodes":           []string{"server-25"},
		"timeout_seconds": 5,
	})
	res, err := h(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("want success, got: %#v", res)
	}

	if n := rec.count(); n != 0 {
		t.Fatalf("expected 0 notifications without progressToken, got %d", n)
	}
}

func TestWaitForReleaseHandler_WithToken_Fires(t *testing.T) {
	shrinkLeasePollTunings(t)
	shrinkHeartbeatInterval(t)
	rec := withNotifRecorder(t)

	store := newLeaseTestStore(t)
	lease, err := store.Acquire(context.Background(), leasing.AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 30 * time.Minute,
		AgentID:  "alice",
		Identity: leasing.Identity{EffectiveID: "alice", Hostname: "h", PID: 1, Cookie: "c"},
	})
	if err != nil {
		t.Fatalf("seed acquire: %v", err)
	}

	// Release after 120ms so the handler polls at least twice before returning.
	go func() {
		time.Sleep(120 * time.Millisecond)
		_ = store.Release(context.Background(), lease.ID, "alice")
	}()

	h := waitForReleaseHandler(store)
	req := reqWithToken(map[string]any{
		"nodes":           []string{"server-25"},
		"timeout_seconds": 5,
	})
	res, err := h(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("want success, got: %#v", res)
	}

	if n := rec.count(); n < 1 {
		t.Fatalf("expected >=1 notifications with progressToken, got %d", n)
	}
}
