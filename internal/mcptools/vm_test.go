package mcptools

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/credentials"
	internalsec "github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"

	"google.golang.org/grpc"
)

// vmRoutingMockAgent returns a canned ExecuteScript stream so the remote target
// routing and result shaping can be verified without a hypervisor. It records
// the shell the handler requested.
type vmRoutingMockAgent struct {
	pb.UnimplementedNodeAgentServer
	payload  string
	gotShell string
	exitCode int32
}

func (a *vmRoutingMockAgent) ExecuteScript(req *pb.ExecuteScriptRequest, stream grpc.ServerStreamingServer[pb.ExecuteResponse]) error {
	a.gotShell = req.Shell
	if err := stream.Send(&pb.ExecuteResponse{Pid: 1, Data: []byte(a.payload)}); err != nil {
		return err
	}
	return stream.Send(&pb.ExecuteResponse{Done: true, ExitCode: a.exitCode})
}

func startVMMockAgent(t *testing.T, agent *vmRoutingMockAgent) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	pb.RegisterNodeAgentServer(srv, agent)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Stop(); ln.Close() })
	return ln.Addr().String()
}

func TestResolveTarget(t *testing.T) {
	reg := newRebootTestRegistry(t, map[string]string{"node1": "127.0.0.1:1"})

	for _, v := range []string{"", "localhost", "LOCAL"} {
		req := reqNoToken(map[string]any{"target": v})
		got, err := resolveTarget(req, reg)
		if err != nil || !got.IsLocal || got.Name != "localhost" {
			t.Errorf("resolveTarget(%q) = %+v, %v; want local", v, got, err)
		}
	}

	got, err := resolveTarget(reqNoToken(map[string]any{"target": "node1"}), reg)
	if err != nil || got.IsLocal || got.Node == nil {
		t.Errorf("resolveTarget(node1) = %+v, %v; want remote", got, err)
	}

	if _, err := resolveTarget(reqNoToken(map[string]any{"target": "ghost"}), reg); err == nil {
		t.Errorf("expected error for unknown node")
	}
}

func TestExtractTarget(t *testing.T) {
	ex := extractTarget("target")
	if nodes := ex(reqNoToken(map[string]any{"target": "localhost"}), nil); nodes != nil {
		t.Errorf("local target should yield no lease nodes, got %v", nodes)
	}
	if nodes := ex(reqNoToken(map[string]any{}), nil); nodes != nil {
		t.Errorf("default (local) target should yield no lease nodes, got %v", nodes)
	}
	nodes := ex(reqNoToken(map[string]any{"target": "node1"}), nil)
	if len(nodes) != 1 || nodes[0] != "node1" {
		t.Errorf("remote target should require a lease on the node, got %v", nodes)
	}
}

func TestRunPS_RemoteRoutingUsesPowershell(t *testing.T) {
	agent := &vmRoutingMockAgent{payload: `[{"name":"S","type":"External"}]`}
	addr := startVMMockAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()

	tgt, _ := resolveTarget(reqNoToken(map[string]any{"target": "node1"}), reg)
	out, exit, err := runPS(context.Background(), reg, pool, tgt, "Get-VMSwitch", 30)
	if err != nil || exit != 0 {
		t.Fatalf("runPS remote: exit=%d err=%v", exit, err)
	}
	if agent.gotShell != "powershell" {
		t.Errorf("remote runPS must request powershell shell, got %q", agent.gotShell)
	}
	if out == "" {
		t.Errorf("expected payload output")
	}
}

func TestRunPS_RemoteNonzeroExitIsFailure(t *testing.T) {
	agent := &vmRoutingMockAgent{payload: "LABLINK_ERROR: boom", exitCode: 1}
	addr := startVMMockAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()

	tgt, _ := resolveTarget(reqNoToken(map[string]any{"target": "node1"}), reg)
	_, exit, err := runPS(context.Background(), reg, pool, tgt, "throw", 30)
	if err == nil {
		t.Fatalf("nonzero exit must be a failure")
	}
	if exit != 1 {
		t.Errorf("expected exit 1, got %d", exit)
	}
	if got := firstTaggedError("noise\nLABLINK_ERROR: boom\nmore"); got != "boom" {
		t.Errorf("firstTaggedError = %q, want boom", got)
	}
}

func TestListVSwitchesHandler_RemoteShapesJSON(t *testing.T) {
	agent := &vmRoutingMockAgent{payload: `[{"name":"ExternalSwitch","type":"External","net_adapter":"Intel","allow_management_os":true}]`}
	addr := startVMMockAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()

	h := listVSwitchesHandler(reg, pool)
	res, err := h(context.Background(), reqNoToken(map[string]any{"target": "node1"}))
	if err != nil || res == nil || res.IsError {
		t.Fatalf("handler error: %v res=%#v", err, res)
	}
	text := toolResultText(res)
	if !strings.Contains(text, "```json") || !strings.Contains(text, "ExternalSwitch") {
		t.Errorf("expected fenced json with vswitch, got:\n%s", text)
	}
}

func TestResolveAdminPassword(t *testing.T) {
	store := credentials.LoadStore(t.TempDir() + "\\creds.json")
	_ = store.Set(&credentials.Profile{Name: "vmadmin", Username: "Administrator", Password: "s3cret"})

	pw, err := resolveAdminPassword(reqNoToken(map[string]any{"admin_password_credential": "vmadmin"}), store)
	if err != nil || pw != "s3cret" {
		t.Errorf("credential password = %q, %v", pw, err)
	}
	pw, err = resolveAdminPassword(reqNoToken(map[string]any{"admin_password": "inline"}), store)
	if err != nil || pw != "inline" {
		t.Errorf("inline password = %q, %v", pw, err)
	}
	if _, err := resolveAdminPassword(reqNoToken(map[string]any{}), store); err == nil {
		t.Errorf("expected error when no password source")
	}
	if _, err := resolveAdminPassword(reqNoToken(map[string]any{"admin_password_credential": "ghost"}), store); err == nil {
		t.Errorf("expected error for unknown credential")
	}
}

func TestJsonExtract(t *testing.T) {
	if got := jsonExtract("noise\n{\"a\":1}\ntail"); got != `{"a":1}` {
		t.Errorf("jsonExtract object = %q", got)
	}
	if got := jsonExtract("no json here"); got != "{}" {
		t.Errorf("jsonExtract empty = %q", got)
	}
}

func TestVMResultHasFencedJSON(t *testing.T) {
	res := vmResult("**header**", `{"ok":true}`)
	text := toolResultText(res)
	if !strings.Contains(text, "**header**") || !strings.Contains(text, "```json") || !strings.Contains(text, `{"ok":true}`) {
		t.Errorf("vmResult missing parts:\n%s", text)
	}
}
