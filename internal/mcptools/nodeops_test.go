package mcptools

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/registry"
	internalsec "github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"

	"google.golang.org/grpc"
)

type nodeInfoMockAgent struct {
	pb.UnimplementedNodeAgentServer

	mu       sync.Mutex
	requests []*pb.ExecuteRequest
	output   string
}

func (a *nodeInfoMockAgent) Execute(req *pb.ExecuteRequest, stream grpc.ServerStreamingServer[pb.ExecuteResponse]) error {
	a.mu.Lock()
	a.requests = append(a.requests, req)
	a.mu.Unlock()
	if err := stream.Send(&pb.ExecuteResponse{Pid: 1, Data: []byte(a.output)}); err != nil {
		return err
	}
	return stream.Send(&pb.ExecuteResponse{Done: true, ExitCode: 0})
}

func (a *nodeInfoMockAgent) Requests() []*pb.ExecuteRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]*pb.ExecuteRequest(nil), a.requests...)
}

func nodeInfoTestRegistry(t *testing.T, name, address, osName string) *registry.Registry {
	t.Helper()
	reg := newRebootTestRegistry(t, map[string]string{name: address})
	node, ok := reg.GetNode(name)
	if !ok {
		t.Fatalf("node %q missing after registration", name)
	}
	node.OS = osName
	if err := reg.SetNode(node); err != nil {
		t.Fatalf("set node OS: %v", err)
	}
	return reg
}

func TestGetNodeInfoHandlerWindowsUsesPowerShell(t *testing.T) {
	oldMonitor := hmon
	hmon = nil
	t.Cleanup(func() { hmon = oldMonitor })

	agent := &nodeInfoMockAgent{output: "windows info\n"}
	addr := startNodeAgent(t, agent)
	reg := nodeInfoTestRegistry(t, "win-node", addr, "Windows")
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()

	result, err := getNodeInfoHandler(reg, pool)(context.Background(), reqNoToken(map[string]any{"node": "win-node"}))
	if err != nil || result == nil || result.IsError {
		t.Fatalf("get_node_info failed: err=%v result=%#v", err, result)
	}
	requests := agent.Requests()
	if len(requests) != 1 {
		t.Fatalf("Execute calls = %d, want 1", len(requests))
	}
	if requests[0].Shell != "powershell" {
		t.Fatalf("shell = %q, want powershell", requests[0].Shell)
	}
	if requests[0].Command != windowsNodeInfoCommand {
		t.Fatal("Windows command changed from the preserved PowerShell probe")
	}
	if !strings.Contains(requests[0].Command, "--- Test Signing ---") {
		t.Fatal("Windows probe no longer contains test-signing output")
	}
}

func TestGetNodeInfoHandlerLinuxUsesBashAndReturnsOutput(t *testing.T) {
	oldMonitor := hmon
	hmon = nil
	t.Cleanup(func() { hmon = oldMonitor })

	const linuxOutput = "Hostname: bld-01\nOS: Ubuntu 24.04.3 LTS\nVersion: 24.04 (kernel 6.8.0)\n"
	agent := &nodeInfoMockAgent{output: linuxOutput}
	addr := startNodeAgent(t, agent)
	reg := nodeInfoTestRegistry(t, "linux-node", addr, "linux")
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()

	result, err := getNodeInfoHandler(reg, pool)(context.Background(), reqNoToken(map[string]any{"node": "linux-node"}))
	if err != nil || result == nil || result.IsError {
		t.Fatalf("get_node_info failed: err=%v result=%#v", err, result)
	}
	requests := agent.Requests()
	if len(requests) != 1 {
		t.Fatalf("Execute calls = %d, want 1", len(requests))
	}
	if requests[0].Shell != "bash" {
		t.Fatalf("shell = %q, want bash", requests[0].Shell)
	}
	if strings.Contains(strings.ToLower(requests[0].Command), "powershell.exe") {
		t.Fatal("Linux probe references powershell.exe")
	}
	for _, section := range []string{"--- Networking Modules ---", "--- NICs ---", "/etc/os-release", "/proc/uptime"} {
		if !strings.Contains(requests[0].Command, section) {
			t.Fatalf("Linux probe missing %q", section)
		}
	}
	if text := toolResultText(result); !strings.Contains(text, strings.TrimSpace(linuxOutput)) {
		t.Fatalf("Linux output not returned:\n%s", text)
	}
}

func TestGetNodeInfoHandlerUnknownOSFailsBeforeExecution(t *testing.T) {
	oldMonitor := hmon
	hmon = nil
	t.Cleanup(func() { hmon = oldMonitor })

	agent := &nodeInfoMockAgent{output: "must not run"}
	addr := startNodeAgent(t, agent)
	reg := nodeInfoTestRegistry(t, "unknown-node", addr, "freebsd")
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()

	result, err := getNodeInfoHandler(reg, pool)(context.Background(), reqNoToken(map[string]any{"node": "unknown-node"}))
	if err != nil {
		t.Fatalf("handler returned transport error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("expected tool error, got %#v", result)
	}
	if text := toolResultText(result); !strings.Contains(text, `unsupported OS "freebsd"`) {
		t.Fatalf("unexpected error: %s", text)
	}
	if calls := len(agent.Requests()); calls != 0 {
		t.Fatalf("Execute calls = %d, want 0", calls)
	}
}
