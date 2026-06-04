package mcptools

import (
	"context"
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

// shrinkRebootTunings collapses the three timing knobs so tests finish in
// milliseconds instead of tens of seconds. Restored via t.Cleanup. Tests using
// this MUST NOT run t.Parallel because the knobs are package-level.
func shrinkRebootTunings(t *testing.T) {
	t.Helper()
	origDown := rebootNodesInitialDownSleep
	origPoll := rebootNodesPollInterval
	origConn := rebootNodesConnectTimeout
	rebootNodesInitialDownSleep = 50 * time.Millisecond
	rebootNodesPollInterval = 50 * time.Millisecond
	rebootNodesConnectTimeout = 100 * time.Millisecond
	t.Cleanup(func() {
		rebootNodesInitialDownSleep = origDown
		rebootNodesPollInterval = origPoll
		rebootNodesConnectTimeout = origConn
	})
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
	if !strings.Contains(body, "1/1 back") {
		t.Fatalf("headline should report 1/1 back, got: %s", body)
	}
}

func TestRebootNodesDeduplicatesInput(t *testing.T) {
	shrinkRebootTunings(t)

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

func TestRenderRebootNodesTableShape(t *testing.T) {
	statuses := []rebootNodeStatus{
		{NodeName: "a", Kicked: true, BackOnline: true, WallTime: 12 * time.Second},
		{NodeName: "b", Kicked: true, BackOnline: false, WallTime: 30 * time.Second},
	}
	out := renderRebootNodesTable(statuses, 30)

	for _, want := range []string{
		"| Node | Shutdown kicked? | Came back online? | Wall time |",
		"|---|---|---|---|",
		"| a | yes | yes |",
		"| b | yes | NO (timeout 30s) |",
		"Some nodes did not return",
		"2/2 kicked",
		"1/2 back",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q\nrendered:\n%s", want, out)
		}
	}

	// All-green path.
	statuses2 := []rebootNodeStatus{
		{NodeName: "a", Kicked: true, BackOnline: true, WallTime: 5 * time.Second},
	}
	out2 := renderRebootNodesTable(statuses2, 60)
	if !strings.Contains(out2, "All nodes rebooted") {
		t.Errorf("all-green headline missing\nrendered:\n%s", out2)
	}
}
