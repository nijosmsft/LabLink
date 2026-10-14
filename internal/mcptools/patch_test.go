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
	"github.com/nijosmsft/lablink/internal/healthmon"
	"github.com/nijosmsft/lablink/internal/registry"
	internalsec "github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testWindowsBootBefore = "2026-10-14T10:00:00.0000000Z"
	testWindowsBootAfter  = "2026-10-14T11:00:00.0000000Z"
	testLinuxBootBefore   = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	testLinuxBootAfter    = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
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

type execRecordAgent struct {
	pb.UnimplementedNodeAgentServer

	mu sync.Mutex

	calls []*pb.ExecuteRequest

	windowsBefore string
	windowsAfter  string
	linuxBefore   string
	linuxAfter    string

	rebooted                 bool
	rebootExitCode           int32
	rebootErrorBeforePID     bool
	rebootDisconnectAfterPID bool
	probeFailures            int
	postRebootProbeFailures  int
}

func newExecRecordAgent() *execRecordAgent {
	return &execRecordAgent{
		windowsBefore: testWindowsBootBefore,
		windowsAfter:  testWindowsBootAfter,
		linuxBefore:   testLinuxBootBefore,
		linuxAfter:    testLinuxBootAfter,
	}
}

func (a *execRecordAgent) Execute(req *pb.ExecuteRequest, stream grpc.ServerStreamingServer[pb.ExecuteResponse]) error {
	a.mu.Lock()
	a.calls = append(a.calls, req)
	isReboot := req.Command == windowsRebootCommand || req.Command == linuxRebootCommand
	if isReboot && a.rebootErrorBeforePID {
		a.mu.Unlock()
		return status.Error(codes.Internal, "launch failed")
	}
	if isReboot {
		exitCode := a.rebootExitCode
		disconnect := a.rebootDisconnectAfterPID
		if exitCode == 0 {
			a.rebooted = true
		}
		a.mu.Unlock()
		if err := stream.Send(&pb.ExecuteResponse{Pid: 1234}); err != nil {
			return err
		}
		if disconnect {
			return status.Error(codes.Unavailable, "agent stopped during reboot")
		}
		return stream.Send(&pb.ExecuteResponse{Done: true, ExitCode: exitCode})
	}

	rebooted := a.rebooted
	output := ""
	switch req.Command {
	case windowsBootIDCommand:
		output = a.windowsBefore
		if rebooted {
			output = a.windowsAfter
		}
	case linuxBootIDCommand:
		output = a.linuxBefore
		if rebooted {
			output = a.linuxAfter
		}
	}
	a.mu.Unlock()

	if err := stream.Send(&pb.ExecuteResponse{Pid: 1234, Data: []byte(output + "\n")}); err != nil {
		return err
	}
	return stream.Send(&pb.ExecuteResponse{Done: true, ExitCode: 0})
}

func (a *execRecordAgent) GetInfo(context.Context, *pb.GetInfoRequest) (*pb.GetInfoResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.probeFailures > 0 {
		a.probeFailures--
		return nil, status.Error(codes.Unavailable, "probe failed")
	}
	if a.rebooted && a.postRebootProbeFailures > 0 {
		a.postRebootProbeFailures--
		return nil, status.Error(codes.Unavailable, "node rebooting")
	}
	return &pb.GetInfoResponse{Hostname: "test-node", Os: "windows"}, nil
}

func (a *execRecordAgent) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.calls)
}

func (a *execRecordAgent) callsSnapshot() []*pb.ExecuteRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]*pb.ExecuteRequest(nil), a.calls...)
}

func startExecAgent(t *testing.T) (string, *execRecordAgent) {
	t.Helper()
	return startConfiguredExecAgent(t, newExecRecordAgent())
}

func startConfiguredExecAgent(t *testing.T, agent *execRecordAgent) (string, *execRecordAgent) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	pb.RegisterNodeAgentServer(srv, agent)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		srv.Stop()
		_ = ln.Close()
	})
	return ln.Addr().String(), agent
}

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
			OS:            "windows",
			TransportMode: string(internalsec.TransportModeInsecure),
		}); err != nil {
			t.Fatalf("SetNode %s: %v", name, err)
		}
	}
	return reg
}

func setRebootNodeOS(t *testing.T, reg *registry.Registry, name, osName string) {
	t.Helper()
	node, ok := reg.GetNode(name)
	if !ok {
		t.Fatalf("node %q not found", name)
	}
	node.OS = osName
	if err := reg.SetNode(node); err != nil {
		t.Fatalf("set node OS: %v", err)
	}
}

func shrinkRebootTunings(t *testing.T) {
	t.Helper()
	origDown := rebootNodesInitialDownSleep
	origPoll := rebootNodesPollInterval
	origConn := rebootNodesConnectTimeout
	origConfirmations := rebootNodesDownConfirmations
	rebootNodesInitialDownSleep = 75 * time.Millisecond
	rebootNodesPollInterval = 20 * time.Millisecond
	rebootNodesConnectTimeout = 200 * time.Millisecond
	rebootNodesDownConfirmations = 2
	t.Cleanup(func() {
		rebootNodesInitialDownSleep = origDown
		rebootNodesPollInterval = origPoll
		rebootNodesConnectTimeout = origConn
		rebootNodesDownConfirmations = origConfirmations
	})
}

// The Linux image builder still uses the TCP reboot observation seam.
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

func runSingleReboot(t *testing.T, reg *registry.Registry, pool *agentclient.Pool, waitSeconds int) *mcp.CallToolResult {
	t.Helper()
	log := audit.NewLog(t.TempDir())
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"node": "node1", "wait_seconds": waitSeconds}
	result, err := rebootNodeHandler(reg, pool, log)(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	return result
}

func offlineRebootMonitor(t *testing.T, reg *registry.Registry, pool *agentclient.Pool, nodeName string) (*healthmon.Monitor, context.Context) {
	t.Helper()
	t.Setenv("DEAD_THRESHOLD", "1")
	t.Setenv("HEALTH_CHECK_INTERVAL", "1h")
	t.Setenv("HEALTH_CHECK_TIMEOUT", "200ms")
	monitor := healthmon.New(reg, pool)
	staleCtx := monitor.NodeContext(nodeName)
	monitor.Start()

	deadline := time.Now().Add(2 * time.Second)
	for monitor.GetStatus(nodeName).Status != "offline" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	monitor.Stop()
	if state := monitor.GetStatus(nodeName); state.Status != "offline" {
		t.Fatalf("health state = %+v, want offline", state)
	}
	select {
	case <-staleCtx.Done():
	default:
		t.Fatal("offline health context was not cancelled")
	}
	return monitor, staleCtx
}

func findCall(t *testing.T, calls []*pb.ExecuteRequest, command string) *pb.ExecuteRequest {
	t.Helper()
	for _, call := range calls {
		if call.Command == command {
			return call
		}
	}
	t.Fatalf("command %q not found in calls: %+v", command, calls)
	return nil
}

func TestRebootNodeWindowsCommandAndFastIdentityChange(t *testing.T) {
	shrinkRebootTunings(t)
	addr, agent := startExecAgent(t)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()

	result := runSingleReboot(t, reg, pool, 2)
	if result == nil || result.IsError {
		t.Fatalf("reboot failed: %#v text=%q", result, toolResultText(result))
	}
	call := findCall(t, agent.callsSnapshot(), windowsRebootCommand)
	if call.Shell != "cmd" {
		t.Fatalf("Windows reboot shell = %q, want cmd", call.Shell)
	}
	identityCall := findCall(t, agent.callsSnapshot(), windowsBootIDCommand)
	if identityCall.Shell != "powershell" {
		t.Fatalf("Windows identity shell = %q, want powershell", identityCall.Shell)
	}
	body := toolResultText(result)
	if !strings.Contains(body, "changed boot identity") || !strings.Contains(body, "without a sampled offline interval") {
		t.Fatalf("fast reboot diagnostics missing: %s", body)
	}
}

func TestRebootIdentityChangeImmediatelyRevivesHealthContext(t *testing.T) {
	for _, fleet := range []bool{false, true} {
		name := "reboot_node"
		if fleet {
			name = "reboot_nodes"
		}
		t.Run(name, func(t *testing.T) {
			shrinkRebootTunings(t)
			agent := newExecRecordAgent()
			agent.probeFailures = 1
			addr, agent := startConfiguredExecAgent(t, agent)
			reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
			pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
			defer pool.Close()
			monitor, staleCtx := offlineRebootMonitor(t, reg, pool, "node1")

			oldMonitor := hmon
			hmon = monitor
			t.Cleanup(func() { hmon = oldMonitor })

			log := audit.NewLog(t.TempDir())
			req := mcp.CallToolRequest{}
			var result *mcp.CallToolResult
			var err error
			if fleet {
				req.Params.Arguments = map[string]any{"nodes": []string{"node1"}, "wait_seconds": 2}
				result, err = rebootNodesHandler(reg, pool, log)(context.Background(), req)
			} else {
				req.Params.Arguments = map[string]any{"node": "node1", "wait_seconds": 2}
				result, err = rebootNodeHandler(reg, pool, log)(context.Background(), req)
			}
			if err != nil || result == nil || result.IsError {
				t.Fatalf("%s failed: err=%v result=%#v text=%q", name, err, result, toolResultText(result))
			}

			state := monitor.GetStatus("node1")
			if state.Status != "online" || state.ConsecutiveFails != 0 {
				t.Fatalf("health state was not revived immediately: %+v", state)
			}
			freshCtx := monitor.NodeContext("node1")
			if freshCtx == staleCtx {
				t.Fatal("reboot recovery retained the stale health context")
			}
			select {
			case <-freshCtx.Done():
				t.Fatal("reboot recovery left the fresh health context cancelled")
			default:
			}

			execReq := mcp.CallToolRequest{}
			execReq.Params.Arguments = map[string]any{
				"node":    "node1",
				"command": "echo ready",
				"shell":   "cmd",
			}
			execResult, execErr := executeCommandHandler(reg, pool, nil, log)(context.Background(), execReq)
			if execErr != nil || execResult == nil || execResult.IsError {
				t.Fatalf("immediate health-aware execute failed: err=%v result=%#v text=%q", execErr, execResult, toolResultText(execResult))
			}
			findCall(t, agent.callsSnapshot(), "echo ready")
		})
	}
}

func TestRebootSameIdentityDoesNotReviveHealthContext(t *testing.T) {
	shrinkRebootTunings(t)
	agent := newExecRecordAgent()
	agent.probeFailures = 1
	agent.windowsAfter = agent.windowsBefore
	addr, _ := startConfiguredExecAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	monitor, staleCtx := offlineRebootMonitor(t, reg, pool, "node1")

	oldMonitor := hmon
	hmon = monitor
	t.Cleanup(func() { hmon = oldMonitor })

	result := runSingleReboot(t, reg, pool, 1)
	if result == nil || !result.IsError {
		t.Fatalf("expected same-identity failure, got %#v text=%q", result, toolResultText(result))
	}
	if state := monitor.GetStatus("node1"); state.Status != "offline" {
		t.Fatalf("same identity revived health state: %+v", state)
	}
	if monitor.NodeContext("node1") != staleCtx {
		t.Fatal("same identity replaced the stale health context")
	}
	select {
	case <-staleCtx.Done():
	default:
		t.Fatal("same identity revived the cancelled health context")
	}
}

func TestRebootNodeLinuxUsesSystemctlAndBash(t *testing.T) {
	shrinkRebootTunings(t)
	addr, agent := startExecAgent(t)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	setRebootNodeOS(t, reg, "node1", "linux")
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()

	result := runSingleReboot(t, reg, pool, 2)
	if result == nil || result.IsError {
		t.Fatalf("reboot failed: %#v text=%q", result, toolResultText(result))
	}
	rebootCall := findCall(t, agent.callsSnapshot(), linuxRebootCommand)
	if rebootCall.Shell != "bash" {
		t.Fatalf("Linux reboot shell = %q, want bash", rebootCall.Shell)
	}
	identityCall := findCall(t, agent.callsSnapshot(), linuxBootIDCommand)
	if identityCall.Shell != "bash" {
		t.Fatalf("Linux identity shell = %q, want bash", identityCall.Shell)
	}
}

func TestRebootNodeUnsupportedOSFailsBeforeMutation(t *testing.T) {
	addr, agent := startExecAgent(t)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	setRebootNodeOS(t, reg, "node1", "freebsd")
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()

	result := runSingleReboot(t, reg, pool, 1)
	if result == nil || !result.IsError || !strings.Contains(toolResultText(result), "unsupported OS") {
		t.Fatalf("expected unsupported OS error, got %#v text=%q", result, toolResultText(result))
	}
	if got := agent.callCount(); got != 0 {
		t.Fatalf("unsupported OS made %d Execute calls; want zero", got)
	}
}

func TestRebootNodeInitiationNonzeroIsSurfaced(t *testing.T) {
	shrinkRebootTunings(t)
	agent := newExecRecordAgent()
	agent.rebootExitCode = 5
	addr, agent := startConfiguredExecAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()

	result := runSingleReboot(t, reg, pool, 1)
	if result == nil || !result.IsError {
		t.Fatalf("expected initiation error, got %#v", result)
	}
	body := toolResultText(result)
	if !strings.Contains(body, "failed to initiate") || !strings.Contains(body, "exited 5") {
		t.Fatalf("nonzero exit not surfaced: %s", body)
	}
}

func TestRebootNodeDisconnectRequiresLaunchEvidence(t *testing.T) {
	t.Run("pid then unavailable is allowed and verified by identity", func(t *testing.T) {
		shrinkRebootTunings(t)
		agent := newExecRecordAgent()
		agent.rebootDisconnectAfterPID = true
		addr, _ := startConfiguredExecAgent(t, agent)
		reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
		pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
		defer pool.Close()

		result := runSingleReboot(t, reg, pool, 2)
		if result == nil || result.IsError {
			t.Fatalf("expected verified reboot success, got %#v text=%q", result, toolResultText(result))
		}
	})

	t.Run("error before pid is rejected", func(t *testing.T) {
		shrinkRebootTunings(t)
		agent := newExecRecordAgent()
		agent.rebootErrorBeforePID = true
		addr, _ := startConfiguredExecAgent(t, agent)
		reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
		pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
		defer pool.Close()

		result := runSingleReboot(t, reg, pool, 1)
		if result == nil || !result.IsError || !strings.Contains(toolResultText(result), "launch failed") {
			t.Fatalf("expected launch error, got %#v text=%q", result, toolResultText(result))
		}
	})
}

func TestRebootNodeDownThenUpWithChangedIdentity(t *testing.T) {
	shrinkRebootTunings(t)
	agent := newExecRecordAgent()
	agent.postRebootProbeFailures = 2
	addr, _ := startConfiguredExecAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()

	result := runSingleReboot(t, reg, pool, 2)
	if result == nil || result.IsError {
		t.Fatalf("reboot failed: %#v text=%q", result, toolResultText(result))
	}
	if !strings.Contains(toolResultText(result), "after going offline") {
		t.Fatalf("down/up timing diagnostic missing: %s", toolResultText(result))
	}
}

func TestRebootNodeSameIdentityTimesOutAsNotObserved(t *testing.T) {
	shrinkRebootTunings(t)
	agent := newExecRecordAgent()
	agent.windowsAfter = agent.windowsBefore
	addr, _ := startConfiguredExecAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()

	result := runSingleReboot(t, reg, pool, 1)
	if result == nil || !result.IsError {
		t.Fatalf("expected reboot-not-observed error, got %#v", result)
	}
	body := toolResultText(result)
	if !strings.Contains(body, "reboot not observed") || !strings.Contains(body, "same boot identity") {
		t.Fatalf("wrong timeout diagnostic: %s", body)
	}
}

func TestRebootNodeRejectsMalformedOrEmptyInitialIdentity(t *testing.T) {
	tests := []struct {
		name      string
		osName    string
		configure func(*execRecordAgent)
	}{
		{
			name:   "empty windows timestamp",
			osName: "windows",
			configure: func(a *execRecordAgent) {
				a.windowsBefore = ""
			},
		},
		{
			name:   "malformed linux boot id",
			osName: "linux",
			configure: func(a *execRecordAgent) {
				a.linuxBefore = "not-a-uuid"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shrinkRebootTunings(t)
			agent := newExecRecordAgent()
			tt.configure(agent)
			addr, agent := startConfiguredExecAgent(t, agent)
			reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
			setRebootNodeOS(t, reg, "node1", tt.osName)
			pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
			defer pool.Close()

			result := runSingleReboot(t, reg, pool, 1)
			if result == nil || !result.IsError {
				t.Fatalf("expected identity validation error, got %#v", result)
			}
			body := toolResultText(result)
			if !strings.Contains(body, "boot identity") && !strings.Contains(body, "last-boot timestamp") {
				t.Fatalf("identity error missing: %s", body)
			}
			for _, call := range agent.callsSnapshot() {
				if call.Command == windowsRebootCommand || call.Command == linuxRebootCommand {
					t.Fatalf("reboot command ran after invalid initial identity: %+v", call)
				}
			}
		})
	}
}

func TestRebootNodeMalformedRecoveredIdentityIsExplicit(t *testing.T) {
	shrinkRebootTunings(t)
	agent := newExecRecordAgent()
	agent.linuxAfter = "malformed"
	addr, _ := startConfiguredExecAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	setRebootNodeOS(t, reg, "node1", "linux")
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()

	result := runSingleReboot(t, reg, pool, 1)
	if result == nil || !result.IsError {
		t.Fatalf("expected recovered identity validation error, got %#v", result)
	}
	body := toolResultText(result)
	if !strings.Contains(body, "could not be validated") || !strings.Contains(body, "malformed Linux boot_id") {
		t.Fatalf("malformed recovery identity not surfaced: %s", body)
	}
}

func TestRebootNodesSharedPathSupportsWindowsAndLinux(t *testing.T) {
	shrinkRebootTunings(t)
	winAddr, winAgent := startExecAgent(t)
	linuxAddr, linuxAgent := startExecAgent(t)
	reg := newRebootTestRegistry(t, map[string]string{"win": winAddr, "linux": linuxAddr})
	setRebootNodeOS(t, reg, "linux", "linux")
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"nodes": []string{"win", "linux"}, "wait_seconds": 2}
	result, err := rebootNodesHandler(reg, pool, log)(context.Background(), req)
	if err != nil || result == nil || result.IsError {
		t.Fatalf("fleet reboot failed: err=%v result=%#v text=%q", err, result, toolResultText(result))
	}
	findCall(t, winAgent.callsSnapshot(), windowsRebootCommand)
	findCall(t, linuxAgent.callsSnapshot(), linuxRebootCommand)
	body := toolResultText(result)
	if !strings.Contains(body, "2/2 boot identities changed") || !strings.Contains(body, "All nodes rebooted and authenticated") {
		t.Fatalf("fleet result missing identity verification: %s", body)
	}
}

func TestRebootNodesUnknownNodeRejectsWholeCall(t *testing.T) {
	addr, agent := startExecAgent(t)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"nodes": []string{"node1", "ghost"}}
	result, err := rebootNodesHandler(reg, pool, log)(context.Background(), req)
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("expected atomic validation error: err=%v result=%#v", err, result)
	}
	if !strings.Contains(toolResultText(result), "ghost") || !strings.Contains(toolResultText(result), "atomic") {
		t.Fatalf("wrong validation error: %s", toolResultText(result))
	}
	if got := agent.callCount(); got != 0 {
		t.Fatalf("agent received %d Execute calls; want zero", got)
	}
}

func TestRebootNodesUnsupportedOSRejectsWholeCall(t *testing.T) {
	winAddr, winAgent := startExecAgent(t)
	otherAddr, otherAgent := startExecAgent(t)
	reg := newRebootTestRegistry(t, map[string]string{"win": winAddr, "other": otherAddr})
	setRebootNodeOS(t, reg, "other", "freebsd")
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"nodes": []string{"win", "other"}}
	result, err := rebootNodesHandler(reg, pool, log)(context.Background(), req)
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("expected unsupported OS error: err=%v result=%#v", err, result)
	}
	if !strings.Contains(toolResultText(result), "unsupported OS") {
		t.Fatalf("wrong unsupported OS error: %s", toolResultText(result))
	}
	if winAgent.callCount() != 0 || otherAgent.callCount() != 0 {
		t.Fatalf("fleet validation performed Execute calls before rejecting unsupported OS")
	}
}

func TestRebootNodesEmptyList(t *testing.T) {
	reg := newRebootTestRegistry(t, nil)
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"nodes": []string{}}
	result, err := rebootNodesHandler(reg, pool, log)(context.Background(), req)
	if err != nil || result == nil || !result.IsError || !strings.Contains(toolResultText(result), "empty") {
		t.Fatalf("expected empty-list error: err=%v result=%#v", err, result)
	}
}

func TestRebootNodesDeduplicatesInput(t *testing.T) {
	shrinkRebootTunings(t)
	addr, agent := startExecAgent(t)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"nodes": []string{"node1", "node1", "node1"}, "wait_seconds": 2}
	result, err := rebootNodesHandler(reg, pool, log)(context.Background(), req)
	if err != nil || result == nil || result.IsError {
		t.Fatalf("deduplicated reboot failed: err=%v result=%#v", err, result)
	}
	reboots := 0
	for _, call := range agent.callsSnapshot() {
		if call.Command == windowsRebootCommand {
			reboots++
		}
	}
	if reboots != 1 {
		t.Fatalf("reboot command count = %d, want 1", reboots)
	}
}

func TestRenderRebootNodesTableShape(t *testing.T) {
	statuses := []rebootNodeStatus{
		{
			NodeName:              "fast",
			Kicked:                true,
			AuthenticatedRecovery: true,
			IdentityChanged:       true,
			WallTime:              2 * time.Second,
		},
		{
			NodeName:              "same",
			Kicked:                true,
			AuthenticatedRecovery: true,
			WallTime:              30 * time.Second,
		},
	}
	output := renderRebootNodesTable(statuses, 30)
	for _, want := range []string{
		"| Node | Reboot kicked? | Sampled offline? | Authenticated recovery? | Boot identity changed? | Wall time |",
		"| fast | yes | no (not required) | yes | yes |",
		"| same | yes | no (not required) | yes | NO (same identity; reboot not observed) |",
		"Reboot incomplete",
		"2/2 kicked",
		"2/2 authenticated",
		"1/2 boot identities changed",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("table missing %q\nrendered:\n%s", want, output)
		}
	}
}
