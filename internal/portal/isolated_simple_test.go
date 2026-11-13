package portal

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/nijosmsft/lablink/internal/isolatedstate"
)

func TestSimpleIsolatedPortalReadsInventory(t *testing.T) {
	store, err := isolatedstate.Open(filepath.Join(t.TempDir(), "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := isolatedstate.UnixSeconds(1)
	if err := store.PutOrchestrator(context.Background(), isolatedstate.Orchestrator{
		ID: "orch-1", DisplayName: "orchestrator", PhysicalHostID: "host-1",
		HostNode: "host", HyperVName: "orch-vm", NodeName: "orch-node",
		ProfileName: "profile", MainVSwitch: "main", AgentPort: 9091,
		LifecycleState: isolatedstate.OrchestratorReady, HealthState: "ready",
		MaxNetworks: 16, MaxVMs: 100, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	view := &isolatedPortal{state: store}
	snapshot := (&Server{isolated: view}).loadIsolatedSnapshot(
		context.Background(), store, 10, 0)
	if len(snapshot.Orchestrators) != 1 ||
		snapshot.Orchestrators[0].ID != "orch-1" {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
}
