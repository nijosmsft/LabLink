package mcptools

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	internalsec "github.com/nijosmsft/lablink/internal/security"
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

	h := executeCommandHandler(reg, pool, log)
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

	h := executeScriptHandler(reg, pool, log)
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
