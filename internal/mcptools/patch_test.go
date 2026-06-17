package mcptools

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/registry"
	internalsec "github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"

	"google.golang.org/grpc"
)

type fakeRebootConn struct{}

func (fakeRebootConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (fakeRebootConn) Write(b []byte) (int, error)        { return len(b), nil }
func (fakeRebootConn) Close() error                       { return nil }
func (fakeRebootConn) LocalAddr() net.Addr                { return fakeAddr("local") }
func (fakeRebootConn) RemoteAddr() net.Addr               { return fakeAddr("remote") }
func (fakeRebootConn) SetDeadline(_ time.Time) error      { return nil }
func (fakeRebootConn) SetReadDeadline(_ time.Time) error  { return nil }
func (fakeRebootConn) SetWriteDeadline(_ time.Time) error { return nil }

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

// execRecordAgent is a minimal NodeAgent that records every Execute call so
// reboot_nodes tests can assert which nodes were actually kicked.
type execRecordAgent struct {
	pb.UnimplementedNodeAgentServer
	mu    sync.Mutex
	calls []*pb.ExecuteRequest
}

func (a *execRecordAgent) Execute(req *pb.ExecuteRequest, stream grpc.ServerStreamingServer[pb.ExecuteResponse]) error {
	a.mu.Lock()
	a.calls = append(a.calls, req)
	a.mu.Unlock()
	// Mimic the real agent: first message carries Pid, terminal message carries Done+ExitCode.
	if err := stream.Send(&pb.ExecuteResponse{Pid: 1234}); err != nil {
		return err
	}
	return stream.Send(&pb.ExecuteResponse{Done: true, ExitCode: 0})
}

func (a *execRecordAgent) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.calls)
}

func (a *execRecordAgent) callAt(i int) *pb.ExecuteRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls[i]
}

// startExecAgent stands up an in-process gRPC server backed by execRecordAgent
// on a random localhost port and returns (address, agent).
func startExecAgent(t *testing.T) (string, *execRecordAgent) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	agent := &execRecordAgent{}
	pb.RegisterNodeAgentServer(srv, agent)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Stop(); ln.Close() })
	return ln.Addr().String(), agent
}

// newRebootTestRegistry seeds the registry with the supplied (name, addr) pairs
// over the insecure transport. Returns the loaded registry.
func newRebootTestRegistry(t *testing.T, nodes map[string]string) *registry.Registry {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nodes.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write nodes.json: %v", err)
	}
	reg := registry.Load(path)
	for name, addr := range nodes {
		if err := reg.SetNode(&registry.Node{
			Name:          name,
			Address:       addr,
			TransportMode: string(internalsec.TransportModeInsecure),
		}); err != nil {
			t.Fatalf("SetNode %s: %v", name, err)
		}
	}
	return reg
}

// shrinkRebootTunings collapses the timing knobs so tests finish in
// milliseconds instead of tens of seconds. Restored via t.Cleanup. Tests using
// this MUST NOT run t.Parallel because the knobs are package-level.
func shrinkRebootTunings(t *testing.T) {
	t.Helper()
	origDown := rebootNodesInitialDownSleep
	origPoll := rebootNodesPollInterval
	origConn := rebootNodesConnectTimeout
	origConfirmations := rebootNodesDownConfirmations
	rebootNodesInitialDownSleep = 50 * time.Millisecond
	rebootNodesPollInterval = 50 * time.Millisecond
	rebootNodesConnectTimeout = 100 * time.Millisecond
	rebootNodesDownConfirmations = 2
	t.Cleanup(func() {
		rebootNodesInitialDownSleep = origDown
		rebootNodesPollInterval = origPoll
		rebootNodesConnectTimeout = origConn
		rebootNodesDownConfirmations = origConfirmations
	})
}

func withScriptedRebootDial(t *testing.T, reachable ...bool) {
	t.Helper()
	orig := rebootNodesDial
	var mu sync.Mutex
	calls := 0
	rebootNodesDial = func(_ string, _ time.Duration) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if len(reachable) == 0 {
			return nil, os.ErrDeadlineExceeded
		}
		idx := calls
		calls++
		if idx >= len(reachable) {
			idx = len(reachable) - 1
		}
		if reachable[idx] {
			return fakeRebootConn{}, nil
		}
		return nil, os.ErrDeadlineExceeded
	}
	t.Cleanup(func() { rebootNodesDial = orig })
}

func TestRebootNodesEmptyList(t *testing.T) {
	reg := newRebootTestRegistry(t, nil)
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	h := rebootNodesHandler(reg, pool, log)

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"nodes": []string{}}

	res, err := h(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want IsError=true, got res=%#v", res)
	}
	if !strings.Contains(toolResultText(res), "empty") {
		t.Fatalf("error text should mention empty list, got: %s", toolResultText(res))
	}
}

func TestRebootNodesUnknownNodeRejectsWholeCall(t *testing.T) {
	addr, agent := startExecAgent(t)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	h := rebootNodesHandler(reg, pool, log)

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"nodes": []string{"node1", "ghost"}}

	res, err := h(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want IsError=true for unknown node, got res=%#v", res)
	}
	body := toolResultText(res)
	if !strings.Contains(body, "ghost") {
		t.Fatalf("error text should name the unknown node, got: %s", body)
	}
	if !strings.Contains(body, "atomic") {
		t.Fatalf("error text should mention atomic validation, got: %s", body)
	}
	// Atomicity: node1 must NOT have been kicked.
	if got := agent.callCount(); got != 0 {
		t.Fatalf("agent received %d Execute calls; want 0 (validation should be atomic)", got)
	}
}

func TestRebootNodesSingleNodeRoundTrip(t *testing.T) {
	shrinkRebootTunings(t)
	withScriptedRebootDial(t, true, false, false, true)

	addr, agent := startExecAgent(t)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	h := rebootNodesHandler(reg, pool, log)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"nodes": []string{"node1"}, "wait_seconds": 5}

	res, err := h(ctx, req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("want success, got res=%#v", res)
	}

	// Exactly one Execute call, with the reboot command.
	if got := agent.callCount(); got != 1 {
		t.Fatalf("agent received %d Execute calls; want 1", got)
	}
	call := agent.callAt(0)
	if call.Command != "shutdown /r /t 2 /f" {
		t.Fatalf("wrong reboot command: %q", call.Command)
	}
	if call.Shell != "cmd" {
		t.Fatalf("wrong shell: %q (want cmd)", call.Shell)
	}

	body := toolResultText(res)
	if !strings.Contains(body, "node1") {
		t.Fatalf("table should mention node1, got: %s", body)
	}
	if !strings.Contains(body, "1/1 kicked") {
		t.Fatalf("headline should report 1/1 kicked, got: %s", body)
	}
	if !strings.Contains(body, "1/1 went offline") {
		t.Fatalf("headline should report 1/1 went offline, got: %s", body)
	}
	if !strings.Contains(body, "1/1 back") {
		t.Fatalf("headline should report 1/1 back, got: %s", body)
	}
}

func TestRebootNodesDeduplicatesInput(t *testing.T) {
	shrinkRebootTunings(t)
	withScriptedRebootDial(t, false, false, true)

	addr, agent := startExecAgent(t)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	h := rebootNodesHandler(reg, pool, log)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"nodes": []string{"node1", "node1", "node1"}, "wait_seconds": 5}

	res, err := h(ctx, req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("want success, got res=%#v", res)
	}
	if got := agent.callCount(); got != 1 {
		t.Fatalf("dedupe failed: agent received %d Execute calls; want 1", got)
	}
}

func TestRebootNodesNeverWentDown_IsNotBackOnline(t *testing.T) {
	shrinkRebootTunings(t)
	withScriptedRebootDial(t, true, true, true, true)

	addr, _ := startExecAgent(t)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	h := rebootNodesHandler(reg, pool, log)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"nodes": []string{"node1"}, "wait_seconds": 1}

	res, err := h(ctx, req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("plural handler should render incomplete table, got res=%#v", res)
	}
	body := toolResultText(res)
	for _, want := range []string{
		"Reboot incomplete",
		"0/1 went offline",
		"0/1 back",
		"NO (never observed offline)",
		"reboot may not have taken effect",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("result missing %q\nbody:\n%s", want, body)
		}
	}
	if strings.Contains(body, "All nodes rebooted and back online") {
		t.Fatalf("must not report all back online before observing down\nbody:\n%s", body)
	}
}

func TestRebootNodeNeverWentDown_ReturnsError(t *testing.T) {
	shrinkRebootTunings(t)
	withScriptedRebootDial(t, true, true, true, true)

	addr, _ := startExecAgent(t)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	h := rebootNodeHandler(reg, pool, log)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"node": "node1", "wait_seconds": 1}

	res, err := h(ctx, req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want error when node never goes offline, got res=%#v", res)
	}
	body := toolResultText(res)
	if !strings.Contains(body, "never went offline") || !strings.Contains(body, "reboot may not have taken effect") {
		t.Fatalf("wrong error text: %s", body)
	}
}

func TestRebootNodesDownThenUp_IsBackOnline(t *testing.T) {
	shrinkRebootTunings(t)
	withScriptedRebootDial(t, true, false, false, true)

	addr, _ := startExecAgent(t)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	h := rebootNodesHandler(reg, pool, log)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"nodes": []string{"node1"}, "wait_seconds": 1}

	res, err := h(ctx, req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("want success, got res=%#v", res)
	}
	body := toolResultText(res)
	for _, want := range []string{
		"All nodes rebooted and back online",
		"1/1 went offline",
		"1/1 back",
		"| node1 | yes | yes | yes |",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("result missing %q\nbody:\n%s", want, body)
		}
	}
}

func TestRebootNodeDownThenUp_IsBackOnline(t *testing.T) {
	shrinkRebootTunings(t)
	withScriptedRebootDial(t, true, false, false, true)

	addr, _ := startExecAgent(t)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	h := rebootNodeHandler(reg, pool, log)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"node": "node1", "wait_seconds": 1}

	res, err := h(ctx, req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("want success, got res=%#v text=%q", res, toolResultText(res))
	}
	body := toolResultText(res)
	if !strings.Contains(body, "went offline") || !strings.Contains(body, "back online") {
		t.Fatalf("success text should mention down->up verification, got: %s", body)
	}
}

func TestRebootNodesTransientBlipDoesNotCountAsDown(t *testing.T) {
	shrinkRebootTunings(t)
	withScriptedRebootDial(t, true, false, true, true, true)

	addr, _ := startExecAgent(t)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	h := rebootNodesHandler(reg, pool, log)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"nodes": []string{"node1"}, "wait_seconds": 1}

	res, err := h(ctx, req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("plural handler should render incomplete table, got res=%#v", res)
	}
	body := toolResultText(res)
	if !strings.Contains(body, "0/1 went offline") || !strings.Contains(body, "0/1 back") {
		t.Fatalf("transient single failure should not count as down\nbody:\n%s", body)
	}
	if strings.Contains(body, "All nodes rebooted and back online") {
		t.Fatalf("must not report all back online after transient blip\nbody:\n%s", body)
	}
}

func TestRenderRebootNodesTableShape(t *testing.T) {
	statuses := []rebootNodeStatus{
		{NodeName: "a", Kicked: true, WentDown: true, BackOnline: true, WallTime: 12 * time.Second},
		{NodeName: "b", Kicked: true, WentDown: true, BackOnline: false, WallTime: 30 * time.Second},
	}
	out := renderRebootNodesTable(statuses, 30)

	for _, want := range []string{
		"| Node | Shutdown kicked? | Went offline? | Came back online? | Wall time |",
		"|---|---|---|---|---|",
		"| a | yes | yes | yes |",
		"| b | yes | yes | NO (went offline; timeout 30s) |",
		"Reboot incomplete",
		"2/2 kicked",
		"2/2 went offline",
		"1/2 back",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q\nrendered:\n%s", want, out)
		}
	}

	// All-green path.
	statuses2 := []rebootNodeStatus{
		{NodeName: "a", Kicked: true, WentDown: true, BackOnline: true, WallTime: 5 * time.Second},
	}
	out2 := renderRebootNodesTable(statuses2, 60)
	if !strings.Contains(out2, "All nodes rebooted") {
		t.Errorf("all-green headline missing\nrendered:\n%s", out2)
	}
}
