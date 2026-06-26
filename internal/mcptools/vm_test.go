package mcptools

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
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
	return startNodeAgent(t, agent)
}

// startNodeAgent boots a gRPC NodeAgent server backed by any implementation and
// returns its address. Used by both the routing mock and the provision mock.
func startNodeAgent(t *testing.T, agent pb.NodeAgentServer) string {
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

// provisionMockAgent implements BOTH PushFile and ExecuteScript so the
// provision_unattend handler can be exercised end-to-end against a fake node.
// It records every script it was asked to run and every file it was pushed,
// and can be configured to FAIL the injection (nonzero exit) so the failure
// path can be observed.
type provisionMockAgent struct {
	pb.UnimplementedNodeAgentServer

	mu          sync.Mutex
	scripts     []string          // every ExecuteScript body, in order
	pushed      map[string]string // remote path -> received content
	execExit    int32             // exit code returned for ExecuteScript
	execPayload string            // optional stdout payload for ExecuteScript
}

func (a *provisionMockAgent) ExecuteScript(req *pb.ExecuteScriptRequest, stream grpc.ServerStreamingServer[pb.ExecuteResponse]) error {
	a.mu.Lock()
	a.scripts = append(a.scripts, req.ScriptBody)
	exit := a.execExit
	payload := a.execPayload
	a.mu.Unlock()
	if payload != "" {
		if err := stream.Send(&pb.ExecuteResponse{Pid: 1, Data: []byte(payload)}); err != nil {
			return err
		}
	}
	return stream.Send(&pb.ExecuteResponse{Done: true, ExitCode: exit})
}

func (a *provisionMockAgent) PushFile(stream grpc.ClientStreamingServer[pb.PushFileRequest, pb.PushFileResponse]) error {
	var remote string
	var buf []byte
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if msg.RemotePath != "" {
			remote = msg.RemotePath
		}
		buf = append(buf, msg.Chunk...)
	}
	a.mu.Lock()
	if a.pushed == nil {
		a.pushed = map[string]string{}
	}
	a.pushed[remote] = string(buf)
	a.mu.Unlock()
	return stream.SendAndClose(&pb.PushFileResponse{BytesWritten: int64(len(buf)), RemotePath: remote})
}

func (a *provisionMockAgent) recordedScripts() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, len(a.scripts))
	copy(out, a.scripts)
	return out
}

func (a *provisionMockAgent) pushedFiles() map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[string]string{}
	for k, v := range a.pushed {
		out[k] = v
	}
	return out
}

// TestProvisionUnattend_ScrubsCleartextOnFailurePath covers rejection finding
// #2: a FAILURE mid-provision must NEVER leave the staged cleartext password
// file on the target host. We push the answer file successfully, then make the
// injection ExecuteScript fail (nonzero exit). The handler must still issue a
// remote scrub (Remove-Item) for the exact staged path, and the plaintext
// password must never travel through any executed script.
func TestProvisionUnattend_ScrubsCleartextOnFailurePath(t *testing.T) {
	const secret = "Sup3r-S3cret-PLAINTEXT!"

	agent := &provisionMockAgent{
		execExit:    1, // injection fails
		execPayload: "LABLINK_ERROR: injection blew up mid-provision",
	}
	addr := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()

	store := credentials.LoadStore(t.TempDir() + "\\creds.json")
	if err := store.Set(&credentials.Profile{Name: "vmadmin", Username: "Administrator", Password: secret}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	log := audit.NewLog(t.TempDir())

	h := provisionUnattendHandler(reg, pool, store, log)
	res, err := h(context.Background(), reqNoToken(map[string]any{
		"target":                    "node1",
		"vm_name":                   "win01",
		"admin_password_credential": "vmadmin",
		"vhd_path":                  `D:\VMs\win01.vhdx`,
		"injection_method":          "mount-vhd",
	}))
	if err != nil {
		t.Fatalf("handler returned transport error: %v", err)
	}
	// The provision must have FAILED (the injection script errored).
	if res == nil || !res.IsError {
		t.Fatalf("expected the provision to fail on the injection error, got res=%#v", res)
	}

	// The cleartext answer file must have been staged on the target...
	pushed := agent.pushedFiles()
	var stagedRemotePath, stagedContent string
	for path, content := range pushed {
		if strings.Contains(path, "lablink-unattend-") {
			stagedRemotePath, stagedContent = path, content
		}
	}
	if stagedRemotePath == "" {
		t.Fatalf("expected the unattend answer file to be pushed to the target; pushed=%v", pushed)
	}
	if !strings.Contains(stagedContent, secret) {
		t.Fatalf("staged answer file should contain the cleartext password (the thing we must scrub)")
	}

	// ...and despite the failure, a remote scrub (Remove-Item) for THAT exact
	// staged path must have been issued. This is the core of finding #2.
	scripts := agent.recordedScripts()
	scrubbed := false
	for _, s := range scripts {
		if strings.Contains(s, "Remove-Item") && strings.Contains(s, stagedRemotePath) {
			scrubbed = true
		}
	}
	if !scrubbed {
		t.Errorf("failure path did NOT scrub the staged cleartext file %q; scripts=%v", stagedRemotePath, scripts)
	}

	// Defense in depth: the injection script's finally block also removes the
	// staged file regardless of where it fails.
	injectScript := ""
	for _, s := range scripts {
		if strings.Contains(s, "WINDOWS_VOLUME_NOT_FOUND") {
			injectScript = s
		}
	}
	if injectScript == "" {
		t.Fatalf("expected the injection script to have been executed")
	}
	finallyIdx := strings.Index(injectScript, "finally {")
	if finallyIdx < 0 {
		t.Fatalf("injection script missing finally block")
	}
	if !strings.Contains(injectScript[finallyIdx:], "Remove-Item $unattendSrc") {
		t.Errorf("injection script must scrub the staged unattend in its finally block (all-paths)")
	}

	// The plaintext password must NEVER travel through an executed script.
	for _, s := range scripts {
		if strings.Contains(s, secret) {
			t.Fatalf("plaintext password leaked into an executed script")
		}
	}
}
