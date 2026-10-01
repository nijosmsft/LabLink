package mcptools

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/secretstore"
	internalsec "github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"
	"google.golang.org/grpc"
)

// closedPortAddr creates a TCP listener, records its address, then immediately
// closes it. Connections to this address will fail (connection refused), causing
// gRPC RPCs to return a transport error so the handler exits via the error path.
func closedPortAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("closedPortAddr: listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func TestExecuteCommand_HeartbeatGoroutineStopsOnError(t *testing.T) {
	shrinkHeartbeatInterval(t)
	rec := withNotifRecorder(t)

	// Point the node at a closed port so client.Execute returns a transport error.
	addr := closedPortAddr(t)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	h := executeCommandHandler(reg, pool, nil, log)
	req := reqWithToken(map[string]any{"node": "node1", "command": "echo hello"})

	done := make(chan struct{})
	go func() {
		defer close(done)
		h(context.Background(), req) //nolint:errcheck
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return within 5s; gRPC may not be failing fast on closed port")
	}

	// context.Background() never cancels, so a leaked heartbeat goroutine would
	// tick indefinitely. With defer stopHB() in place the goroutine stops as soon
	// as the handler returns and the count must plateau.
	countAtReturn := rec.count()
	time.Sleep(3 * defaultHeartbeatInterval)
	if got := rec.count(); got > countAtReturn {
		t.Fatalf("heartbeat goroutine still ticking %v after handler returned (defer stopHB missing?): count %d -> %d",
			3*defaultHeartbeatInterval, countAtReturn, got)
	}
}

func TestExecuteScript_HeartbeatGoroutineStopsOnError(t *testing.T) {
	shrinkHeartbeatInterval(t)
	rec := withNotifRecorder(t)

	addr := closedPortAddr(t)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	log := audit.NewLog(t.TempDir())

	h := executeScriptHandler(reg, pool, nil, log)
	req := reqWithToken(map[string]any{"node": "node1", "script_body": "Write-Output hello"})

	done := make(chan struct{})
	go func() {
		defer close(done)
		h(context.Background(), req) //nolint:errcheck
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return within 5s; gRPC may not be failing fast on closed port")
	}

	countAtReturn := rec.count()
	time.Sleep(3 * defaultHeartbeatInterval)
	if got := rec.count(); got > countAtReturn {
		t.Fatalf("heartbeat goroutine still ticking %v after handler returned (defer stopHB missing?): count %d -> %d",
			3*defaultHeartbeatInterval, countAtReturn, got)
	}
}

type secretExecAgent struct {
	pb.UnimplementedNodeAgentServer
	env map[string]string
}

func (a *secretExecAgent) Execute(req *pb.ExecuteRequest, stream grpc.ServerStreamingServer[pb.ExecuteResponse]) error {
	a.env = req.Env
	return stream.Send(&pb.ExecuteResponse{
		Pid: 1, Data: []byte("value=" + req.Env["ARCHIVE_PASSWORD"]), Done: true, ExitCode: 0,
	})
}

func (a *secretExecAgent) ExecuteScript(req *pb.ExecuteScriptRequest, stream grpc.ServerStreamingServer[pb.ExecuteResponse]) error {
	a.env = req.Env
	return stream.Send(&pb.ExecuteResponse{
		Pid: 1, Data: []byte("value=" + req.Env["ARCHIVE_PASSWORD"]), Done: true, ExitCode: 0,
	})
}

func TestExecuteSecretEnvIsInjectedAndOutputRedacted(t *testing.T) {
	const secret = "do-not-leak-this-value"
	agent := &secretExecAgent{}
	addr := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	store := secretstore.Open(filepath.Join(t.TempDir(), "secrets.json"))
	if err := store.Set("archive", secret); err != nil {
		t.Fatal(err)
	}

	h := executeCommandHandler(reg, pool, store, audit.NewLog(t.TempDir()))
	res, err := h(context.Background(), reqNoToken(map[string]any{
		"node":    "node1",
		"command": "echo secret",
		"secret_env": map[string]any{
			"ARCHIVE_PASSWORD": "archive",
		},
	}))
	if err != nil || res == nil || res.IsError {
		t.Fatalf("execute result: %#v, %v", res, err)
	}
	if agent.env["ARCHIVE_PASSWORD"] != secret {
		t.Fatal("secret was not injected into the remote environment")
	}
	text := toolResultText(res)
	if strings.Contains(text, secret) || !strings.Contains(text, passwordMask) {
		t.Fatalf("secret output was not redacted: %q", text)
	}
}

func TestExecuteSecretEnvRejectsDetachedJobs(t *testing.T) {
	store := secretstore.Open(filepath.Join(t.TempDir(), "secrets.json"))
	if err := store.Set("archive", "secret"); err != nil {
		t.Fatal(err)
	}
	reg := newRebootTestRegistry(t, map[string]string{"node1": "127.0.0.1:1"})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	h := executeCommandHandler(reg, pool, store, audit.NewLog(t.TempDir()))
	res, err := h(context.Background(), reqNoToken(map[string]any{
		"node": "node1", "command": "work", "detach": true,
		"secret_env": map[string]any{"PASSWORD": "archive"},
	}))
	if err != nil || res == nil || !res.IsError {
		t.Fatalf("expected detached secret_env rejection: %#v, %v", res, err)
	}
	if !strings.Contains(toolResultText(res), "not supported with detach=true") {
		t.Fatalf("unexpected rejection: %s", toolResultText(res))
	}
}
