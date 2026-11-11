package isolatedstate

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestOperationIdempotentReplayAndHashConflict(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "isolated.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	initial, err := first.BeginOperation(ctx, BeginOperationRequest{
		ID: "OP-1", Kind: "create", ResourceType: "vm", ResourceID: "VM-1",
		CanonicalInputs: map[string]any{
			"profile": "small",
			"network": map[string]any{"id": "network-1", "generation": 2},
		},
		CreatedAt: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if initial.Replay {
		t.Fatal("initial operation reported replay")
	}
	_, err = second.BeginOperation(ctx, BeginOperationRequest{
		ID: "op-1", Kind: "create", ResourceType: "vm", ResourceID: "vm-1",
		CanonicalInputs: map[string]any{
			"network": map[string]any{"generation": 2, "id": "network-1"},
			"profile": "small",
		},
	})
	if !errors.Is(err, ErrResumeExactRequired) {
		t.Fatalf("error=%v, want resume_exact required", err)
	}
	replay, err := second.BeginOperation(ctx, BeginOperationRequest{
		ID: "op-1", Kind: "create", ResourceType: "vm", ResourceID: "vm-1",
		CanonicalInputs: map[string]any{
			"network": map[string]any{"generation": 2, "id": "network-1"},
			"profile": "small",
		},
		ResumeExact: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replay || replay.Operation.ArgumentHash != initial.Operation.ArgumentHash {
		t.Fatalf("unexpected replay: %+v", replay)
	}
	_, err = first.BeginOperation(ctx, BeginOperationRequest{
		ID: "op-1", Kind: "create", ResourceType: "vm", ResourceID: "vm-1",
		CanonicalInputs: map[string]any{"profile": "large"},
		ResumeExact:     true,
	})
	var mismatch *ResumeArgumentMismatchError
	if !errors.As(err, &mismatch) || mismatch.StoredHash == mismatch.RequestHash {
		t.Fatalf("error=%v, want hash mismatch diagnostic", err)
	}
}

func TestStableMutationIDAndCanonicalHash(t *testing.T) {
	first, err := SemanticHash(map[string]any{"b": 2, "a": []any{"x", 1}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := SemanticHash(map[string]any{"a": []any{"x", 1}, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("semantic hashes differ: %s vs %s", first, second)
	}
	id := StableMutationID("OP", "VM", "CREATE", "host-create")
	if id != StableMutationID("op", "vm", "create", "host-create") {
		t.Fatal("mutation ID is not stable over canonical IDs")
	}
	if id == StableMutationID("op", "vm", "create", "relay-bind") {
		t.Fatal("different phases aliased")
	}
}

func TestDurableOperationPhasesEventsAndCompletion(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "isolated.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := first.BeginOperation(ctx, BeginOperationRequest{
		ID: "op", Kind: "create", ResourceType: "network", ResourceID: "network-1",
		CanonicalInputs: map[string]any{"cidr": "10.0.0.0/26"}, CreatedAt: 10,
	}); err != nil {
		t.Fatal(err)
	}
	generation := Generation(1)
	phase, err := first.StartOperationPhase(ctx, PhaseStart{
		OperationID: "op", PhaseIndex: 0, PhaseName: "allocate",
		Generation: &generation, StartedAt: 11,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := second.FinishOperationPhase(ctx, PhaseFinish{
		OperationID: "op", PhaseIndex: 0, Attempt: phase.Attempt,
		Status: PhaseSucceeded, Detail: map[string]any{"reservation": "r1"},
		FinishedAt: 12,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := second.AppendOperationEvent(ctx, OperationEventInput{
		OperationID: "op", At: 12, PhaseName: stringPointer("allocate"),
		Level: "info", Message: "allocation committed",
	}); err != nil {
		t.Fatal(err)
	}
	operation, err := first.UpdateOperation(ctx, OperationUpdate{
		OperationID: "op", Status: OperationSucceeded, CurrentPhase: "ready",
		Result: map[string]any{"generation": 1}, UpdatedAt: 13,
	})
	if err != nil {
		t.Fatal(err)
	}
	if operation.Status != OperationSucceeded || operation.FinishedAt == nil ||
		*operation.FinishedAt != 13 {
		t.Fatalf("unexpected completed operation: %+v", operation)
	}
	var phaseStatus OperationPhaseStatus
	if err := first.QueryRowContext(ctx, `
		SELECT status FROM operation_phases
		WHERE operation_id='op' AND phase_index=0 AND attempt=1`,
	).Scan(&phaseStatus); err != nil {
		t.Fatal(err)
	}
	if phaseStatus != PhaseSucceeded {
		t.Fatalf("phase status=%q, want succeeded", phaseStatus)
	}
}

func TestGenerationConflictFenceAndProgress(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedGenerationRows(t, store, OrchestratorReady, 7)

	_, err = store.AdvanceDesiredGeneration(ctx, GenerationMutation{
		ResourceType: "network", ResourceID: "network-1",
		ExpectedGeneration: 0, NewGeneration: 1, ExpectedFence: 7,
		UpdatedAt: 20,
	})
	var conflict *MutationConflictError
	if !errors.As(err, &conflict) || conflict.Code != ConflictGeneration ||
		conflict.Current.DesiredGeneration != 1 {
		t.Fatalf("error=%v, want generation conflict with current state", err)
	}
	_, err = store.AdvanceDesiredGeneration(ctx, GenerationMutation{
		ResourceType: "network", ResourceID: "network-1",
		ExpectedGeneration: 1, NewGeneration: 2, ExpectedFence: 6,
		UpdatedAt: 20,
	})
	if !errors.As(err, &conflict) || conflict.Code != ConflictFence ||
		conflict.CurrentFence != 7 {
		t.Fatalf("error=%v, want fence diagnostic", err)
	}
	state, err := store.AdvanceDesiredGeneration(ctx, GenerationMutation{
		ResourceType: "network", ResourceID: "network-1",
		ExpectedGeneration: 1, NewGeneration: 2, ExpectedFence: 7,
		UpdatedAt: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredGeneration != 2 || state.AppliedGeneration != 0 ||
		state.ObservedGeneration != 0 {
		t.Fatalf("unexpected desired state: %+v", state)
	}
	state, err = store.RecordAppliedGeneration(ctx, GenerationRecord{
		ResourceType: "network", ResourceID: "network-1", Generation: 2, UpdatedAt: 21,
	})
	if err != nil {
		t.Fatal(err)
	}
	state, err = store.RecordObservedGeneration(ctx, GenerationRecord{
		ResourceType: "network", ResourceID: "network-1", Generation: 2, UpdatedAt: 22,
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.AppliedGeneration != 2 || state.ObservedGeneration != 2 {
		t.Fatalf("unexpected generation progress: %+v", state)
	}
	_, err = store.RecordObservedGeneration(ctx, GenerationRecord{
		ResourceType: "network", ResourceID: "network-1", Generation: 1,
	})
	if !errors.As(err, &conflict) || conflict.Code != ConflictGeneration {
		t.Fatalf("error=%v, want stale observed generation", err)
	}
}

func TestFrozenParentRequiresExactCascadeAuthority(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedGenerationRows(t, store, OrchestratorFrozen, 9)
	if _, err := store.BeginOperation(ctx, BeginOperationRequest{
		ID: "delete-op", Kind: "delete", ResourceType: "orchestrator",
		ResourceID: "orch", CanonicalInputs: map[string]any{"cascade": true},
		CreatedAt: 10,
	}); err != nil {
		t.Fatal(err)
	}
	authority := CascadeAuthority{
		OrchestratorID: "orch", FrozenGeneration: 5, OperationID: "delete-op",
		PlanRevision: "revision-1", PlanHash: "abc123", HostFence: 9,
		LeaseID: "lease-1", InstalledAt: 11,
		Items: []CascadeAuthorityItem{{
			MutationID: "mutation-1", Action: "remove_network",
			ResourceType: "network", ResourceID: "network-1",
			ExpectedGeneration: 1,
		}},
	}
	if err := store.InstallCascadeAuthority(ctx, authority); err != nil {
		t.Fatal(err)
	}
	_, err = store.AdvanceDesiredGeneration(ctx, GenerationMutation{
		ResourceType: "network", ResourceID: "network-1",
		ExpectedGeneration: 1, NewGeneration: 2, ExpectedFence: 9,
	})
	var conflict *MutationConflictError
	if !errors.As(err, &conflict) || conflict.Code != ConflictParentFrozen {
		t.Fatalf("error=%v, want parent frozen", err)
	}
	authorization := &MutationAuthorization{
		OrchestratorID: "orch", OperationID: "delete-op",
		PlanRevision: "revision-1", PlanHash: "abc123", MutationID: "mutation-1",
		Action: "remove_network", ResourceType: "network", ResourceID: "network-1",
		HostFence: 9, LeaseID: "lease-1",
	}
	if _, err := store.AdvanceDesiredGeneration(ctx, GenerationMutation{
		ResourceType: "network", ResourceID: "network-1",
		ExpectedGeneration: 1, NewGeneration: 2, ExpectedFence: 9,
		Authorization: authorization,
	}); err != nil {
		t.Fatalf("authorized cleanup: %v", err)
	}
	if err := store.CompleteCascadeItem(ctx, "orch", "mutation-1", 30); err != nil {
		t.Fatal(err)
	}
	if err := store.InstallCascadeAuthority(ctx, authority); err != nil {
		t.Fatalf("idempotent authority replay: %v", err)
	}
	_, err = store.AdvanceDesiredGeneration(ctx, GenerationMutation{
		ResourceType: "network", ResourceID: "network-1",
		ExpectedGeneration: 2, NewGeneration: 3, ExpectedFence: 9,
		Authorization: authorization,
	})
	if !errors.As(err, &conflict) || conflict.Code != ConflictParentFrozen {
		t.Fatalf("completed authority reused: %v", err)
	}
}

func seedGenerationRows(
	t *testing.T,
	store *Store,
	state OrchestratorLifecycleState,
	fence int64,
) {
	t.Helper()
	ctx := context.Background()
	mustExec(t, store, ctx, `
		INSERT INTO orchestrators (
			id, display_name, physical_host_id, host_node, hyperv_name,
			node_name, profile_name, main_vswitch, desired_generation,
			host_fence, lifecycle_state, created_at_unix, updated_at_unix
		) VALUES ('orch', 'display', 'host-id', 'host-node', 'orch-hv',
		          'orch-node', 'profile', 'main-switch', 5, ?, ?, 1, 1)`,
		fence, state,
	)
	mustExec(t, store, ctx, `
		INSERT INTO private_networks (
			id, orchestrator_id, display_name, hyperv_switch_name, subnet_index,
			cidr, gateway_ipv4, orchestrator_mac, dns_servers_json,
			desired_generation, lifecycle_state, created_at_unix, updated_at_unix
		) VALUES ('network-1', 'orch', 'network', 'switch-1', 1,
		          '10.0.0.0/26', '10.0.0.1', '00155d000001', '[]',
		          1, 'ready', 1, 1)`)
}

func stringPointer(value string) *string {
	return &value
}
