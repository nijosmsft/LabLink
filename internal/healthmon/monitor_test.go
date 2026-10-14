package healthmon

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/security"
)

func TestRecordAuthenticatedProbeSuccessRevivesOfflineNode(t *testing.T) {
	reg := registry.Load(filepath.Join(t.TempDir(), "nodes.json"))
	pool := agentclient.NewPool("", security.ClientTransportConfig{Mode: security.TransportModeInsecure})
	defer pool.Close()

	monitor := New(reg, pool)
	monitor.deadThreshold = 1
	node := &registry.Node{
		Name:          "builder",
		Address:       "127.0.0.1:9091",
		TLSServerName: "builder",
	}

	staleCtx := monitor.NodeContext(node.Name)
	monitor.recordFailure(node)
	select {
	case <-staleCtx.Done():
	default:
		t.Fatal("offline node context was not cancelled")
	}

	before := time.Now()
	monitor.RecordAuthenticatedProbeSuccess(node)

	state := monitor.GetStatus(node.Name)
	if state.Status != "online" || state.ConsecutiveFails != 0 || state.LastSeen.Before(before) {
		t.Fatalf("unexpected recovered state: %+v", state)
	}
	freshCtx := monitor.NodeContext(node.Name)
	if freshCtx == staleCtx {
		t.Fatal("offline node context was not replaced")
	}
	select {
	case <-freshCtx.Done():
		t.Fatal("recovered node context is still cancelled")
	default:
	}
}
