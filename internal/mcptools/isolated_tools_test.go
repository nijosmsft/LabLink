package mcptools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/cascadeauth"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/isolated"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/vmconfig"
)

const (
	testOperationID    = "11111111-1111-4111-8111-111111111111"
	testOrchestratorID = "22222222-2222-4222-8222-222222222222"
	testResourceID     = "22222222-2222-4222-8222-222222222222"
)

type releaseAuditHost struct {
	orderedGuestHost
	acquireCalls int
	releaseCalls int
}

func (h *releaseAuditHost) AcquireFence(
	ctx context.Context,
	target Target,
	request isolated.HostCreateFenceRequest,
) (isolated.HostFenceLease, error) {
	h.acquireCalls++
	return h.orderedGuestHost.AcquireFence(ctx, target, request)
}

func (h *releaseAuditHost) ReleaseFenceChecked(
	context.Context,
	Target,
	isolated.HostFenceLease,
) error {
	h.releaseCalls++
	return nil
}

type failingAuthorityReleaseAppliance struct {
	*orderedGuestAppliance
	releaseErr error
}

func (a *failingAuthorityReleaseAppliance) ReleaseAuthority(
	context.Context,
	string,
	isolated.MutationEnvelope,
) error {
	return a.releaseErr
}

type v1ReadinessAppliance struct {
	*orderedGuestAppliance
}

func (a *v1ReadinessAppliance) CheckReadiness(
	context.Context,
	string,
) (isolated.ApplianceReadiness, error) {
	return isolated.ApplianceReadiness{ProtocolVersion: 1}, &isolated.CompatibilityError{
		Code:              "AGENT_UPGRADE_REQUIRED",
		ProtocolVersion:   1,
		SupportedProtocol: isolated.ProtocolRange{Minimum: 2, Maximum: 2},
	}
}

func TestIsolatedLifecycleToolRegistrationAndApprovalSchema(t *testing.T) {
	s := server.NewMCPServer("test", "1.0", server.WithElicitation())
	RegisterIsolatedLifecycleTools(s, &isolatedLifecycleDeps{})
	tools := s.ListTools()
	expected := []string{
		"create_isolated_orchestrator", "list_isolated_orchestrators",
		"get_isolated_orchestrator", "reconcile_isolated_orchestrator",
		"delete_isolated_orchestrator", "add_isolated_network",
		"remove_isolated_network", "create_isolated_relay",
		"remove_isolated_relay", "list_isolated_relays",
		"get_isolated_relay_stats", "rebind_isolated_relays",
		"validate_isolated_relay", "adopt_isolated_relay",
		"create_isolated_vm", "delete_isolated_vm", "list_isolated_vms",
		"get_isolated_vm", "repair_isolated_vm", "rename_isolated_display_name",
		"enable_isolated_vm_nat", "disable_isolated_vm_nat",
		"get_isolated_vm_nat", "list_isolated_vm_nat",
		"reconcile_isolated_vm_nat",
	}

	if len(tools) != len(expected) {
		t.Fatalf("registered %d tools, want %d", len(tools), len(expected))
	}
	for _, name := range expected {
		if tools[name] == nil {
			t.Errorf("tool %q was not registered", name)
		}
	}
	for _, name := range []string{"create_isolated_orchestrator", "delete_isolated_orchestrator"} {
		if _, ok := tools[name].Tool.InputSchema.Properties["approved_plan_revision"]; !ok {
			t.Errorf("%s must expose approved_plan_revision", name)
		}
	}
	for _, name := range []string{
		"add_isolated_network", "remove_isolated_network",
		"create_isolated_relay", "remove_isolated_relay",
		"rebind_isolated_relays", "adopt_isolated_relay",
		"create_isolated_vm", "delete_isolated_vm", "repair_isolated_vm",
		"rename_isolated_display_name",
		"enable_isolated_vm_nat", "disable_isolated_vm_nat",
		"reconcile_isolated_vm_nat",
	} {
		if _, ok := tools[name].Tool.InputSchema.Properties["approved_plan_revision"]; ok {
			t.Errorf("%s must not request approval", name)
		}
	}
	createRelay := tools["create_isolated_relay"].Tool.InputSchema
	if _, ok := createRelay.Properties["target_port"]; ok {
		t.Fatal("relay target_port must not be caller-controlled")
	}
}

func TestDependencySafeCascadeOrderIsGuestsThenNetworksAndStable(t *testing.T) {
	vms := []isolatedstate.IsolatedVM{
		{ID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"},
		{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
	}
	networks := []isolatedstate.PrivateNetwork{
		{ID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd"},
		{ID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc"},
	}
	orderedVMs, orderedNetworks := dependencySafeCascadeOrder(vms, networks)
	got := []string{
		"vm:" + orderedVMs[0].ID,
		"vm:" + orderedVMs[1].ID,
		"network:" + orderedNetworks[0].ID,
		"network:" + orderedNetworks[1].ID,
	}
	want := []string{
		"vm:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"vm:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		"network:cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		"network:dddddddd-dddd-4ddd-8ddd-dddddddddddd",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("cascade order = %v, want %v", got, want)
		}
	}
	if vms[0].ID != "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" ||
		networks[0].ID != "dddddddd-dddd-4ddd-8ddd-dddddddddddd" {
		t.Fatal("execution ordering mutated approved-plan enumeration")
	}
}

func TestApprovedCascadeResumeKeepsOriginalPlanAfterCompletedChildren(t *testing.T) {
	store, err := isolatedstate.Open(filepath.Join(t.TempDir(), "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	operationID := "11111111-1111-4111-8111-111111111111"
	orchestratorID := "22222222-2222-4222-8222-222222222222"
	orchestrator := isolatedstate.Orchestrator{
		ID: orchestratorID, PhysicalHostID: strings.Repeat("a", 64),
		DesiredGeneration: 1,
	}
	approvedChildren := []isolated.CascadeChild{
		{ResourceType: "network", ResourceID: "33333333-3333-4333-8333-333333333333", Action: cascadeauth.ActionNetworkRemove, ExpectedGeneration: 1},
		{ResourceType: "vm", ResourceID: "44444444-4444-4444-8444-444444444444", Action: cascadeauth.ActionGuestDeleteExact, ExpectedGeneration: 1},
		{ResourceType: "vm", ResourceID: "55555555-5555-4555-8555-555555555555", Action: cascadeauth.ActionGuestDeleteExact, ExpectedGeneration: 2},
	}
	full, err := isolated.BuildOrchestratorDeletePlan(isolated.DeleteOrchestratorRequest{
		OperationID: operationID, Orchestrator: orchestrator, Cascade: true,
		Children: approvedChildren, ExpectedGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginOperation(context.Background(), isolatedstate.BeginOperationRequest{
		ID: operationID, Kind: "delete_isolated_orchestrator",
		ResourceType: "orchestrator", ResourceID: orchestratorID,
		CanonicalInputs: map[string]any{
			"orchestrator_id": orchestratorID, "cascade": true,
			"expected_generation": 1,
		},
	}); err != nil {
		t.Fatal(err)
	}
	planJSON, err := isolatedstate.CanonicalJSON(full.Plan)
	if err != nil {
		t.Fatal(err)
	}
	now := isolatedstate.UnixSeconds(10)
	if err := store.PutApprovalPlan(context.Background(), isolatedstate.ApprovalPlan{
		Revision: full.Plan.Revision, OperationID: operationID,
		Action: "delete_isolated_orchestrator", PlanJSON: string(planJSON),
		PlanHash: full.Plan.PlanHash, State: isolatedstate.ApprovalConsumed,
		ApprovedAt: &now, ConsumedAt: &now,
	}); err != nil {
		t.Fatal(err)
	}
	remaining := []isolated.CascadeChild{approvedChildren[0], approvedChildren[2]}
	reduced, err := isolated.BuildOrchestratorDeletePlan(isolated.DeleteOrchestratorRequest{
		OperationID: operationID, Orchestrator: orchestrator, Cascade: true,
		Children: remaining, ExpectedGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{
		"approved_plan_revision": full.Plan.Revision,
		"resume_exact":           true,
	}}}
	resumed, err := approvedCascadeResumePlan(
		context.Background(), store, req, operationID, reduced.Plan, remaining)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Revision != full.Plan.Revision || resumed.PlanHash != full.Plan.PlanHash {
		t.Fatalf("resume plan = %+v, want original approved plan", resumed)
	}
}

func TestBoundedRelayRetirementCancelsBlockedChildCall(t *testing.T) {
	previous := isolatedRelayRetirementTimeout
	isolatedRelayRetirementTimeout = 25 * time.Millisecond
	t.Cleanup(func() { isolatedRelayRetirementTimeout = previous })
	started := time.Now()
	_, err := boundedRelayRetirement(context.Background(),
		func(ctx context.Context) (isolated.RelayMutationResult, error) {
			<-ctx.Done()
			return isolated.RelayMutationResult{}, ctx.Err()
		})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bounded retirement error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded retirement took %s", elapsed)
	}
}

func TestApproveRevisionRequiredExactAndConsumedOnce(t *testing.T) {
	store, err := isolatedstate.Open(t.TempDir() + `\isolated.db`)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_, err = store.BeginOperation(context.Background(), isolatedstate.BeginOperationRequest{
		ID: testOperationID, Kind: "create_isolated_orchestrator",
		ResourceType: "orchestrator", ResourceID: testResourceID,
		CanonicalInputs: map[string]any{"profile": "isolated"},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := isolated.RevisionedPlan{
		Kind: "create_isolated_orchestrator", OperationID: testOperationID,
		ResourceID: testResourceID, SemanticHash: strings.Repeat("a", 64),
		PlanHash: strings.Repeat("b", 64), Revision: "r1-" + strings.Repeat("b", 16),
	}
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{
		Arguments: map[string]any{},
	}}
	approved, result, err := approveRevision(
		context.Background(), nil, store, req, testOperationID,
		"create_isolated_orchestrator", plan, "approve", "")
	if err != nil || approved || result == nil || result.IsError {
		t.Fatalf("missing approval = (%v, %#v, %v)", approved, result, err)
	}

	req.Params.Arguments = map[string]any{"approved_plan_revision": "wrong"}
	if _, _, err := approveRevision(
		context.Background(), nil, store, req, testOperationID,
		"create_isolated_orchestrator", plan, "approve", ""); err == nil {
		t.Fatal("wrong revision was accepted")
	}

	req.Params.Arguments = map[string]any{"approved_plan_revision": plan.Revision}
	approved, _, err = approveRevision(
		context.Background(), nil, store, req, testOperationID,
		"create_isolated_orchestrator", plan, "approve", "")
	if err != nil || !approved {
		t.Fatalf("exact approval = (%v, %v)", approved, err)
	}
	if _, _, err := approveRevision(
		context.Background(), nil, store, req, testOperationID,
		"create_isolated_orchestrator", plan, "approve", ""); err == nil {
		t.Fatal("consumed approval was reusable")
	}
	req.Params.Arguments = map[string]any{
		"approved_plan_revision": plan.Revision,
		"resume_exact":           true,
	}
	approved, _, err = approveRevision(
		context.Background(), nil, store, req, testOperationID,
		"create_isolated_orchestrator", plan, "approve", "")
	if err != nil || !approved {
		t.Fatalf("exact durable resume = (%v, %v)", approved, err)
	}
}

func TestDurableWorkflowResumeSkipsSucceededPhaseAndReportsProgress(t *testing.T) {
	store, err := isolatedstate.Open(t.TempDir() + `\isolated.db`)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	progress := NewMCPProgressState(time.Minute, "resolve", "starting")
	workflow, err := beginIsolatedWorkflow(context.Background(), store, progress,
		isolatedstate.BeginOperationRequest{
			ID: testOperationID, Kind: "test", ResourceType: "orchestrator",
			ResourceID: testResourceID, CanonicalInputs: map[string]any{"x": 1},
		})
	if err != nil {
		t.Fatal(err)
	}
	runs := 0
	run := func() (any, error) {
		runs++
		return map[string]any{"run": runs}, nil
	}
	if err := workflow.phase(context.Background(), 0, "preflight", "checking exact resources", run); err != nil {
		t.Fatal(err)
	}
	replayed, err := beginIsolatedWorkflow(context.Background(), store, progress,
		isolatedstate.BeginOperationRequest{
			ID: testOperationID, Kind: "test", ResourceType: "orchestrator",
			ResourceID: testResourceID, CanonicalInputs: map[string]any{"x": 1},
			ResumeExact: true,
		})
	if err != nil {
		t.Fatal(err)
	}
	if err := replayed.phase(context.Background(), 0, "preflight", "checking exact resources", run); err != nil {
		t.Fatal(err)
	}
	if runs != 1 {
		t.Fatalf("phase executed %d times, want one", runs)
	}
	_, _, message := progress.snapshot()
	if !strings.Contains(message, "phase=preflight") ||
		!strings.Contains(message, "checking exact resources") {
		t.Fatalf("unexpected progress detail %q", message)
	}
}

func TestDurableWorkflowPreservesPartialFailureDiagnostics(t *testing.T) {
	store, err := isolatedstate.Open(t.TempDir() + `\isolated.db`)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	workflow, err := beginIsolatedWorkflow(context.Background(), store, nil,
		isolatedstate.BeginOperationRequest{
			ID: testOperationID, Kind: "test", ResourceType: "network",
			ResourceID: testResourceID, CanonicalInputs: map[string]any{"x": 1},
		})
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("remote result uncertain")
	if err := workflow.phase(context.Background(), 2, "create_private_switch", "creating", func() (any, error) {
		return map[string]any{"switch_may_exist": true}, want
	}); !errors.Is(err, want) {
		t.Fatalf("phase error = %v", err)
	}
	operation, err := store.GetOperation(context.Background(), testOperationID)
	if err != nil {
		t.Fatal(err)
	}
	if operation.Status != isolatedstate.OperationPaused ||
		operation.CurrentPhase != "create_private_switch" ||
		operation.ErrorText == nil ||
		!strings.Contains(*operation.ErrorText, want.Error()) {
		t.Fatalf("partial failure was not preserved: %#v", operation)
	}
}

type isolatedDryRunHost struct {
	preflightCalls      int
	releaseCheckedCalls int
}

type approvalPlanningHost struct{}

func (approvalPlanningHost) AcquireOrchestratorCreateFence(
	_ context.Context,
	request isolated.HostCreateFenceRequest,
) (isolated.HostFenceLease, error) {
	return isolated.HostFenceLease{
		LeaseID:       "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		LeaseSecret:   strings.Repeat("a", 64),
		ExpiresAtUnix: time.Now().Add(time.Hour).Unix(),
		Fence:         22,
		LockKey:       request.LockKey,
	}, nil
}

func (approvalPlanningHost) ReleaseOrchestratorCreateFence(
	context.Context,
	isolated.HostCreateFenceRequest,
	isolated.HostFenceLease,
) error {
	return nil
}

func (approvalPlanningHost) ReconcileStaleOrchestratorMetadata(
	context.Context,
	isolated.StaleOrchestratorMetadataRequest,
) error {
	return nil
}

func (approvalPlanningHost) PreflightOrchestrator(
	context.Context,
	isolated.ResourcePreflightInput,
) (isolated.ResourcePreflightResult, error) {
	return isolated.ResourcePreflightResult{
		Allowed: true, EffectivePrivateAdapterSlots: 15, AvailableSwitchSlots: 16,
	}, nil
}

type approvalProbe struct{}

func (approvalProbe) ObserveOrchestrator(
	context.Context,
	isolatedstate.Orchestrator,
) (isolated.OrchestratorObservation, error) {
	return isolated.OrchestratorObservation{}, errors.New("unexpected orchestrator probe")
}

func (approvalProbe) RecoverOrchestrator(
	context.Context,
	isolatedstate.Orchestrator,
) (isolated.RecoveryResult, error) {
	return isolated.RecoveryResult{}, errors.New("unexpected orchestrator recovery")
}

type countingCascadeHost struct {
	orderedGuestHost
	acquireCalls int
	claimCalls   int
	claimedFence int64
}

type deletedOrchestratorResumeHost struct {
	orderedGuestHost
	claimCalls   int
	cleanupCalls int
}

type lateCascadeChildHost struct {
	orderedGuestHost
	store          *isolatedstate.Store
	orchestratorID string
	inserted       bool
}

type freezeDuringAcquireHost struct {
	orderedGuestHost
	store          *isolatedstate.Store
	orchestratorID string
}

func (h *freezeDuringAcquireHost) AcquireFence(
	ctx context.Context,
	target Target,
	request isolated.HostCreateFenceRequest,
) (isolated.HostFenceLease, error) {
	lease, err := h.orderedGuestHost.AcquireFence(ctx, target, request)
	if err != nil {
		return lease, err
	}
	_, err = h.store.FreezeOrchestrator(ctx, h.orchestratorID, 1, isolatedNow())
	return lease, err
}

func (h *lateCascadeChildHost) AcquireFence(
	ctx context.Context,
	target Target,
	request isolated.HostCreateFenceRequest,
) (isolated.HostFenceLease, error) {
	if !h.inserted {
		h.inserted = true
		err := h.store.PutNetwork(ctx, isolatedstate.PrivateNetwork{
			ID:             "22222222-2222-4222-8222-222222222222",
			OrchestratorID: h.orchestratorID, HyperVSwitchName: "late-network",
			CIDR: "192.168.240.0/26", GatewayIPv4: "192.168.240.1",
			OrchestratorMAC: "02155D010200", DNSServersJSON: "[]",
			DesiredGeneration: 1, LifecycleState: isolatedstate.NetworkReady,
			CreatedAt: 1, UpdatedAt: 1,
		})
		if err != nil {
			return isolated.HostFenceLease{}, err
		}
	}
	return h.orderedGuestHost.AcquireFence(ctx, target, request)
}

func (h *deletedOrchestratorResumeHost) ClaimOrchestrator(
	context.Context,
	Target,
	isolatedstate.Orchestrator,
	isolated.HostFenceLease,
) (hyperv.IsolatedVMObservation, error) {
	h.claimCalls++
	return hyperv.IsolatedVMObservation{}, errors.New("deleted VM must not be claimed")
}

func (h *deletedOrchestratorResumeHost) CleanupOrchestratorMetadata(
	context.Context,
	Target,
	hyperv.CleanupIsolatedOrchestratorMetadataParams,
) (hyperv.IsolatedMetadataCleanupResult, error) {
	h.cleanupCalls++
	return hyperv.IsolatedMetadataCleanupResult{Action: "orchestrator_metadata_cleaned"}, nil
}

func (h *countingCascadeHost) AcquireFence(
	ctx context.Context,
	target Target,
	request isolated.HostCreateFenceRequest,
) (isolated.HostFenceLease, error) {
	h.acquireCalls++
	return h.orderedGuestHost.AcquireFence(ctx, target, request)
}

func (h *countingCascadeHost) ClaimOrchestrator(
	ctx context.Context,
	target Target,
	orchestrator isolatedstate.Orchestrator,
	lease isolated.HostFenceLease,
) (hyperv.IsolatedVMObservation, error) {
	h.claimCalls++
	h.claimedFence = lease.Fence
	return h.orderedGuestHost.ClaimOrchestrator(ctx, target, orchestrator, lease)
}

func (h *isolatedDryRunHost) PhysicalIdentity(context.Context, Target) (hyperv.IsolatedPhysicalHostObservation, error) {
	return hyperv.IsolatedPhysicalHostObservation{
		PhysicalHostID:  strings.Repeat("a", 64),
		HyperVAvailable: true,
	}, nil
}

func (h *isolatedDryRunHost) Discover(context.Context, Target, string, string) (hyperv.IsolatedHostDiscovery, error) {
	return hyperv.IsolatedHostDiscovery{}, nil
}

func (h *isolatedDryRunHost) AcquireFence(context.Context, Target, isolated.HostCreateFenceRequest) (isolated.HostFenceLease, error) {
	return isolated.HostFenceLease{}, errors.New("dry run acquired a fence")
}

func (h *isolatedDryRunHost) ReleaseFence(context.Context, Target, isolated.HostFenceLease) {}

func (h *isolatedDryRunHost) ReleaseFenceChecked(context.Context, Target, isolated.HostFenceLease) error {
	h.releaseCheckedCalls++
	return nil
}

func (h *isolatedDryRunHost) Preflight(
	_ context.Context,
	_ Target,
	_ isolated.ResourcePreflightInput,
	_ vmconfig.Profile,
) (isolated.ResourcePreflightResult, error) {
	h.preflightCalls++
	return isolated.ResourcePreflightResult{
		Allowed: true, EffectivePrivateAdapterSlots: 15, AvailableSwitchSlots: 16,
	}, nil
}

func (h *isolatedDryRunHost) ClaimOrchestrator(context.Context, Target, isolatedstate.Orchestrator, isolated.HostFenceLease) (hyperv.IsolatedVMObservation, error) {
	return hyperv.IsolatedVMObservation{}, errors.New("dry run claimed a VM")
}

func (h *isolatedDryRunHost) CreateSwitch(context.Context, Target, hyperv.CreateIsolatedPrivateSwitchParams) (hyperv.IsolatedSwitchMutationResult, error) {
	return hyperv.IsolatedSwitchMutationResult{}, errors.New("dry run created a switch")
}

func (h *isolatedDryRunHost) AttachNIC(context.Context, Target, hyperv.AttachIsolatedNICParams) (hyperv.IsolatedAdapterMutationResult, error) {
	return hyperv.IsolatedAdapterMutationResult{}, errors.New("dry run attached a NIC")
}

func (h *isolatedDryRunHost) ReconcileNICMetadata(context.Context, Target, hyperv.ReconcileIsolatedAdapterMetadataParams) (hyperv.IsolatedAdapterMutationResult, error) {
	return hyperv.IsolatedAdapterMutationResult{}, errors.New("dry run reconciled NIC metadata")
}

func (h *isolatedDryRunHost) RemoveNIC(context.Context, Target, hyperv.RemoveIsolatedNICParams) (hyperv.IsolatedAdapterMutationResult, error) {
	return hyperv.IsolatedAdapterMutationResult{}, errors.New("dry run removed a NIC")
}

func (h *isolatedDryRunHost) DeleteSwitch(context.Context, Target, hyperv.DeleteIsolatedPrivateSwitchParams) (hyperv.IsolatedSwitchMutationResult, error) {
	return hyperv.IsolatedSwitchMutationResult{}, errors.New("dry run deleted a switch")
}

func (h *isolatedDryRunHost) CleanupNetworkMetadata(context.Context, Target, hyperv.CleanupIsolatedNetworkMetadataParams) (hyperv.IsolatedMetadataCleanupResult, error) {
	return hyperv.IsolatedMetadataCleanupResult{}, errors.New("dry run cleaned network metadata")
}

func (h *isolatedDryRunHost) CleanupOrchestratorMetadata(context.Context, Target, hyperv.CleanupIsolatedOrchestratorMetadataParams) (hyperv.IsolatedMetadataCleanupResult, error) {
	return hyperv.IsolatedMetadataCleanupResult{}, errors.New("dry run cleaned orchestrator metadata")
}

func (h *isolatedDryRunHost) DeleteOrchestratorVM(
	context.Context,
	Target,
	hyperv.DeleteIsolatedOrchestratorVMParams,
) (map[string]any, error) {
	return nil, errors.New("dry run deleted orchestrator VM")
}

func TestCreateIsolatedOrchestratorDryRunPreflightsWithoutMutationOrApproval(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "vm-defaults.json")
	if err := os.WriteFile(configPath, []byte(`{
  "default_linux_profile":"ubuntu",
  "default_isolated_orchestrator_profile":"isolated",
  "profiles":{
    "ubuntu":{
      "guest_os":"linux","target":"localhost",
      "distribution":"ubuntu","release":"24.04","architecture":"amd64",
      "vswitch":"main-switch","vm_root":"C:\\VMs",
      "image_cache_root":"C:\\Images","memory_mb":4096,"cpu_count":2,
      "disk_size_gb":64
    }

  },
  "isolated_orchestrator_profiles":{"isolated":{"linux_profile":"ubuntu"}}
}`), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := isolatedstate.Open(filepath.Join(root, "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host := &isolatedDryRunHost{}
	deps := &isolatedLifecycleDeps{
		state: store, host: host, registry: registry.Load(filepath.Join(root, "nodes.json")),
		defaults: vmconfig.Load(configPath), serverVersion: "v1.0.0",
	}
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{
		"target": "localhost", "dry_run": true,
	}}}
	result, err := createIsolatedOrchestratorHandler(deps)(context.Background(), req)
	if err != nil || result == nil || result.IsError {
		t.Fatalf("dry run = %#v, %v", result, err)
	}
	if host.preflightCalls != 1 {
		t.Fatalf("preflight calls = %d, want one", host.preflightCalls)
	}
	if !strings.Contains(toolResultText(result), `"approval_required_if_created": true`) {
		t.Fatalf("dry-run plan missing approval annotation: %s", toolResultText(result))
	}
}

func TestCreateIsolatedOrchestratorReturnsApprovalAfterReleasingPlanningFence(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "vm-defaults.json")
	if err := os.WriteFile(configPath, []byte(`{
  "default_linux_profile":"ubuntu",
  "default_isolated_orchestrator_profile":"isolated",
  "profiles":{
    "ubuntu":{
      "guest_os":"linux","target":"localhost",
      "distribution":"ubuntu","release":"24.04","architecture":"amd64",
      "generation":2,"cpu_count":4,"memory_mb":8192,"disk_size_gb":64,
      "vswitch":"extswitch","vm_root":"C:\\VMs"
    }
  },
  "isolated_orchestrator_profiles":{
    "isolated":{
      "target":"localhost","linux_profile":"ubuntu","main_vswitch":"extswitch",
      "cpu_count":4,"memory_mb":8192,"max_networks":16,"max_vms":100
    }
  }
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	defaults := vmconfig.Load(configPath)
	store, err := isolatedstate.Open(filepath.Join(root, "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	locks, err := isolatedstate.NewLockManager(store, isolatedstate.LockManagerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.Load(filepath.Join(root, "nodes.json"))
	if err := reg.SetNode(&registry.Node{Name: "localhost", Address: "127.0.0.1:9090"}); err != nil {
		t.Fatal(err)
	}
	host := &isolatedDryRunHost{}
	deps := &isolatedLifecycleDeps{
		state: store, locks: locks, host: host,
		orchestrators: isolatedStateAdapter{store: store},
		planner:       approvalPlanningHost{}, probe: approvalProbe{},
		registry: reg, defaults: defaults, serverVersion: "v1.0.0",
	}
	operationID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	orchestratorID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{
		"target": "localhost", "profile": "isolated",
		"display_name": "Approval Probe", "operation_id": operationID,
		"orchestrator_id": orchestratorID,
	}}}
	result, err := createIsolatedOrchestratorHandler(deps)(context.Background(), req)
	if err != nil || result == nil || result.IsError {
		t.Fatalf("create approval result = %#v, %v", result, err)
	}
	text := toolResultText(result)
	if !strings.Contains(text, `"status": "approval_required"`) ||
		!strings.Contains(text, `"phase": "approval_required"`) {
		t.Fatalf("create did not return approval promptly: %s", text)
	}
	if host.releaseCheckedCalls != 1 {
		t.Fatalf("planning fence releases = %d, want 1", host.releaseCheckedCalls)
	}
	operation, err := store.GetOperation(context.Background(), operationID)
	if err != nil {
		t.Fatal(err)
	}
	if operation.Status != isolatedstate.OperationApprovalRequired ||
		operation.CurrentPhase != "approval_required" {
		t.Fatalf("operation = %+v", operation)
	}
}

func TestClaimAndPersistOrchestratorFenceAdvancesParentForNetworkDeletion(t *testing.T) {
	store, err := isolatedstate.Open(filepath.Join(t.TempDir(), "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	orchestratorID := "11111111-1111-4111-8111-111111111111"
	oldGUID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	record := isolatedstate.Orchestrator{
		ID: orchestratorID, PhysicalHostID: strings.Repeat("a", 64),
		HostNode: "localhost", HyperVName: "orchestrator", HyperVVMID: &oldGUID,
		NodeName: "orchestrator-node", AgentPort: 9091,
		DesiredGeneration: 1, AppliedGeneration: 1, ObservedGeneration: 1,
		HostFence: 134, LifecycleState: isolatedstate.OrchestratorReady,
		CreatedAt: 1, UpdatedAt: 1,
	}
	if err := store.PutOrchestrator(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	host := &countingCascadeHost{}
	deps := &isolatedLifecycleDeps{state: store, host: host}
	updated, err := claimAndPersistOrchestratorFence(
		context.Background(), deps, Target{Name: "localhost"}, record,
		isolated.HostFenceLease{Fence: 136},
	)
	if err != nil {
		t.Fatal(err)
	}
	if updated.HostFence != 136 || host.claimCalls != 1 || host.claimedFence != 136 {
		t.Fatalf("updated parent = %+v, host = %+v", updated, host)
	}
	persisted, err := store.GetOrchestrator(context.Background(), orchestratorID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.HostFence != 136 ||
		valueOrEmpty(persisted.HyperVVMID) != "77777777-7777-4777-8777-777777777777" {
		t.Fatalf("persisted parent fence = %+v", persisted)
	}
}

func TestDeleteOrchestratorExactResumeAfterVMDeletionSkipsClaim(t *testing.T) {
	root := t.TempDir()
	store, err := isolatedstate.Open(filepath.Join(root, "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	orchestratorID := "11111111-1111-4111-8111-111111111111"
	operationID := "22222222-2222-4222-8222-222222222222"
	vmGUID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	record := isolatedstate.Orchestrator{
		ID: orchestratorID, PhysicalHostID: strings.Repeat("a", 64),
		HostNode: "localhost", HyperVName: "orchestrator", HyperVVMID: &vmGUID,
		NodeName: "orchestrator-node", AgentPort: 9091,
		DesiredGeneration: 2, AppliedGeneration: 1, ObservedGeneration: 1,
		HostFence: 8, LifecycleState: isolatedstate.OrchestratorDeleting,
		HealthState: "deleting", CreatedAt: 1, UpdatedAt: 1,
	}
	if err := store.PutOrchestrator(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	begin, err := store.BeginOperation(context.Background(), isolatedstate.BeginOperationRequest{
		ID: operationID, Kind: "delete_isolated_orchestrator",
		ResourceType: "orchestrator", ResourceID: orchestratorID,
		HostNode: &record.HostNode, OrchestratorID: optionalTrimmed(orchestratorID),
		CanonicalInputs: map[string]any{
			"orchestrator_id": orchestratorID, "cascade": false,
			"expected_generation": 1,
		},
	})
	if err != nil || begin.Replay {
		t.Fatalf("begin operation = %+v, %v", begin, err)
	}
	phase, err := store.StartOperationPhase(context.Background(), isolatedstate.PhaseStart{
		OperationID: operationID, PhaseIndex: 0, PhaseName: "delete_linux_vm",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.FinishOperationPhase(context.Background(), isolatedstate.PhaseFinish{
		OperationID: operationID, PhaseIndex: 0, Attempt: phase.Attempt,
		Status: isolatedstate.PhaseSucceeded,
	}); err != nil {
		t.Fatal(err)
	}
	preFreeze := record
	preFreeze.DesiredGeneration = 1
	preFreeze.LifecycleState = isolatedstate.OrchestratorReady
	deletePlan, err := isolated.BuildOrchestratorDeletePlan(isolated.DeleteOrchestratorRequest{
		OperationID: operationID, Orchestrator: preFreeze,
		ExpectedGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	planJSON, err := isolatedstate.CanonicalJSON(deletePlan.Plan)
	if err != nil {
		t.Fatal(err)
	}
	now := isolatedstate.UnixSeconds(time.Now().Unix())
	if err := store.PutApprovalPlan(context.Background(), isolatedstate.ApprovalPlan{
		Revision: deletePlan.Plan.Revision, OperationID: operationID,
		Action: "delete_isolated_orchestrator", PlanJSON: string(planJSON),
		PlanHash: deletePlan.Plan.PlanHash, State: isolatedstate.ApprovalConsumed,
		ApprovedAt: &now, ConsumedAt: &now,
	}); err != nil {
		t.Fatal(err)
	}
	reg := registry.Load(filepath.Join(root, "nodes.json"))
	if err := reg.SetNode(&registry.Node{
		Name: "localhost", Address: "127.0.0.1:9090",
	}); err != nil {
		t.Fatal(err)
	}
	host := &deletedOrchestratorResumeHost{}
	deps := &isolatedLifecycleDeps{state: store, host: host, registry: reg}
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{
		"orchestrator_id": orchestratorID, "operation_id": operationID,
		"approved_plan_revision": deletePlan.Plan.Revision, "resume_exact": true,
	}}}
	result, err := deleteIsolatedOrchestratorHandler(deps)(context.Background(), req)
	if err != nil || result == nil || result.IsError {
		t.Fatalf("exact resume = %#v, %v", result, err)
	}
	if host.claimCalls != 0 || host.cleanupCalls != 1 {
		t.Fatalf("host calls: claim=%d cleanup=%d", host.claimCalls, host.cleanupCalls)
	}
	persisted, err := store.GetOrchestrator(context.Background(), orchestratorID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.LifecycleState != isolatedstate.OrchestratorDeleted {
		t.Fatalf("orchestrator state = %s", persisted.LifecycleState)
	}
}

func TestDeleteOrchestratorExactResumeAfterFreezeUsesStoredGeneration(t *testing.T) {
	root := t.TempDir()
	store, err := isolatedstate.Open(filepath.Join(root, "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	orchestratorID := "11111111-1111-4111-8111-111111111111"
	operationID := "22222222-2222-4222-8222-222222222222"
	vmGUID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	preFreeze := isolatedstate.Orchestrator{
		ID: orchestratorID, PhysicalHostID: strings.Repeat("a", 64),
		HostNode: "localhost", HyperVName: "orchestrator", HyperVVMID: &vmGUID,
		NodeName: "orchestrator-node", AgentPort: 9091,
		DesiredGeneration: 1, AppliedGeneration: 1, ObservedGeneration: 1,
		HostFence: 8, LifecycleState: isolatedstate.OrchestratorReady,
		HealthState: "ready", CreatedAt: 1, UpdatedAt: 1,
	}
	frozen := preFreeze
	frozen.DesiredGeneration = 2
	frozen.LifecycleState = isolatedstate.OrchestratorFrozen
	frozen.HealthState = "frozen"
	if err := store.PutOrchestrator(context.Background(), frozen); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginOperation(context.Background(), isolatedstate.BeginOperationRequest{
		ID: operationID, Kind: "delete_isolated_orchestrator",
		ResourceType: "orchestrator", ResourceID: orchestratorID,
		HostNode: &preFreeze.HostNode, OrchestratorID: optionalTrimmed(orchestratorID),
		CanonicalInputs: map[string]any{
			"orchestrator_id": orchestratorID, "cascade": false,
			"expected_generation": 1,
		},
	}); err != nil {
		t.Fatal(err)
	}
	deletePlan, err := isolated.BuildOrchestratorDeletePlan(isolated.DeleteOrchestratorRequest{
		OperationID: operationID, Orchestrator: preFreeze, ExpectedGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	planJSON, err := isolatedstate.CanonicalJSON(deletePlan.Plan)
	if err != nil {
		t.Fatal(err)
	}
	now := isolatedstate.UnixSeconds(time.Now().Unix())
	if err := store.PutApprovalPlan(context.Background(), isolatedstate.ApprovalPlan{
		Revision: deletePlan.Plan.Revision, OperationID: operationID,
		Action: "delete_isolated_orchestrator", PlanJSON: string(planJSON),
		PlanHash: deletePlan.Plan.PlanHash, State: isolatedstate.ApprovalConsumed,
		ApprovedAt: &now, ConsumedAt: &now,
	}); err != nil {
		t.Fatal(err)
	}
	reg := registry.Load(filepath.Join(root, "nodes.json"))
	if err := reg.SetNode(&registry.Node{
		Name: "localhost", Address: "127.0.0.1:9090",
	}); err != nil {
		t.Fatal(err)
	}
	host := &deletedOrchestratorResumeHost{}
	deps := &isolatedLifecycleDeps{
		state: store, host: host, appliance: &orderedGuestAppliance{},
		registry: reg,
		deleteOrchestratorVM: func(
			context.Context, isolatedstate.Orchestrator,
		) (any, error) {
			return map[string]any{"deleted": true}, nil
		},
	}
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{
		"orchestrator_id": orchestratorID, "operation_id": operationID,
		"approved_plan_revision": deletePlan.Plan.Revision, "resume_exact": true,
	}}}
	result, err := deleteIsolatedOrchestratorHandler(deps)(context.Background(), req)
	if err != nil || result == nil || result.IsError {
		t.Fatalf("exact resume after freeze = %#v, %v", result, err)
	}
	persisted, err := store.GetOrchestrator(context.Background(), orchestratorID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.LifecycleState != isolatedstate.OrchestratorDeleted ||
		persisted.DesiredGeneration != 3 {
		t.Fatalf("orchestrator after resumed delete = %+v", persisted)
	}
}

func TestCascadeCoordinatorDoesNotAcquireChildHostFence(t *testing.T) {
	root := t.TempDir()
	store, err := isolatedstate.Open(filepath.Join(root, "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer store.Close()
	orchestratorID := "11111111-1111-4111-8111-111111111111"
	networkID := "22222222-2222-4222-8222-222222222222"
	vmID := "33333333-3333-4333-8333-333333333333"
	orchestratorGUID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	vmGUID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	adapterID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	if err := store.PutOrchestrator(context.Background(), isolatedstate.Orchestrator{
		ID: orchestratorID, PhysicalHostID: strings.Repeat("a", 64),
		HostNode: "localhost", HyperVName: "orchestrator", HyperVVMID: &orchestratorGUID,
		NodeName: "orchestrator-node", AgentPort: 9091,
		DesiredGeneration: 1, AppliedGeneration: 1, ObservedGeneration: 1,
		LifecycleState: isolatedstate.OrchestratorReady, CreatedAt: 1, UpdatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutNetwork(context.Background(), isolatedstate.PrivateNetwork{
		ID: networkID, OrchestratorID: orchestratorID, HyperVSwitchName: "private",
		CIDR: "192.168.240.0/26", GatewayIPv4: "192.168.240.1",
		OrchestratorMAC: "02155D010200", DNSServersJSON: "[]",
		DesiredGeneration: 1, AppliedGeneration: 1, ObservedGeneration: 1,
		LifecycleState: isolatedstate.NetworkReady, CreatedAt: 1, UpdatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutVM(context.Background(), isolatedstate.IsolatedVM{
		ID: vmID, OrchestratorID: orchestratorID, NetworkID: networkID,
		HyperVName: "guest", HyperVVMID: &vmGUID, HyperVAdapterID: &adapterID,
		Incarnation: 1, NodeName: "guest-node", GuestOS: isolatedstate.GuestWindows,
		ProfileName: "windows", IPv4: "192.168.240.10", MAC: "02155D010201",
		PrefixLength: 26, GatewayIPv4: "192.168.240.1", DNSServersJSON: "[]",
		StorageRoot: `E:\VM`, VMPath: `E:\VM\guest`, VHDPath: `E:\VM\guest\guest.vhdx`,
		DesiredGeneration: 1, AppliedGeneration: 1, ObservedGeneration: 1,
		LifecycleState: isolatedstate.VMReady, CreatedAt: 1, UpdatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutNAT(context.Background(), isolatedstate.NATAllocation{
		VMID: vmID, OrchestratorID: orchestratorID,
		DesiredState: isolatedstate.NATDesiredEnabled, ObservedState: isolatedstate.NATObservedEnabled,
		ConntrackMark: 101, DesiredGeneration: 1, AppliedGeneration: 1,
		ObservedGeneration: 1, UpdatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	host := &countingCascadeHost{}
	order := []string{}
	deps := &isolatedLifecycleDeps{
		state: store, host: host, appliance: &orderedGuestAppliance{order: &order},
		registry: registry.Load(filepath.Join(root, "nodes.json")),
	}
	operationID := "44444444-4444-4444-8444-444444444444"
	baseArgs := map[string]any{
		"orchestrator_id": orchestratorID, "cascade": true,
		"operation_id": operationID,
	}
	firstReq := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: baseArgs}}
	first, err := deleteIsolatedOrchestratorHandler(deps)(context.Background(), firstReq)
	if err != nil || first == nil || first.IsError {
		t.Fatalf("initial cascade plan = %#v, %v", first, err)
	}
	planNetworks, err := store.ListNetworks(context.Background(), orchestratorID)
	if err != nil {
		t.Fatal(err)
	}
	planVMs, err := store.ListVMs(context.Background(), orchestratorID, "")
	if err != nil {
		t.Fatal(err)
	}
	planNAT, err := store.ListNAT(context.Background(), orchestratorID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := isolated.BuildOrchestratorDeletePlan(isolated.DeleteOrchestratorRequest{
		OperationID: operationID,
		Orchestrator: isolatedstate.Orchestrator{
			ID: orchestratorID, PhysicalHostID: strings.Repeat("a", 64),
			HyperVVMID: &orchestratorGUID, DesiredGeneration: 1,
		},
		Cascade:            true,
		Children:           cascadeChildren(planNetworks, planVMs, nil, planNAT),
		ExpectedGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	resumeArgs := map[string]any{}
	for key, value := range baseArgs {
		resumeArgs[key] = value
	}
	resumeArgs["approved_plan_revision"] = plan.Plan.Revision
	resumeArgs["resume_exact"] = true
	resumeReq := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: resumeArgs}}
	result, err := deleteIsolatedOrchestratorHandler(deps)(context.Background(), resumeReq)
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("cascade child failure = %#v, %v; want surfaced child error", result, err)
	}
	if host.acquireCalls != 2 {
		t.Fatalf("host fence acquisitions = %d, want freeze plus child acquisition", host.acquireCalls)
	}
}

func TestFinalCascadeInventoryRejectsChildInsertedAfterPlan(t *testing.T) {
	root := t.TempDir()
	store, err := isolatedstate.Open(filepath.Join(root, "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	orchestratorID := "11111111-1111-4111-8111-111111111111"
	networkID := "22222222-2222-4222-8222-222222222222"
	vmID := "33333333-3333-4333-8333-333333333333"
	orchestrator := isolatedstate.Orchestrator{
		ID: orchestratorID, PhysicalHostID: strings.Repeat("a", 64),
		HostNode: "localhost", HyperVName: "orchestrator",
		NodeName: "orchestrator-node", AgentPort: 9091,
		DesiredGeneration: 2, LifecycleState: isolatedstate.OrchestratorFrozen,
		CreatedAt: 1, UpdatedAt: 1,
	}
	if err := store.PutOrchestrator(context.Background(), orchestrator); err != nil {
		t.Fatal(err)
	}
	if err := store.PutNetwork(context.Background(), isolatedstate.PrivateNetwork{
		ID: networkID, OrchestratorID: orchestratorID, HyperVSwitchName: "private",
		CIDR: "192.168.240.0/26", GatewayIPv4: "192.168.240.1",
		OrchestratorMAC: "02155D010200", DNSServersJSON: "[]",
		DesiredGeneration: 1, LifecycleState: isolatedstate.NetworkReady,
		CreatedAt: 1, UpdatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutVM(context.Background(), isolatedstate.IsolatedVM{
		ID: vmID, OrchestratorID: orchestratorID, NetworkID: networkID,
		HyperVName: "late-guest", Incarnation: 1, NodeName: "late-guest",
		GuestOS: isolatedstate.GuestLinux, ProfileName: "linux",
		IPv4: "192.168.240.10", MAC: "02155D010201", PrefixLength: 26,
		GatewayIPv4: "192.168.240.1", DNSServersJSON: "[]",
		StorageRoot: `E:\VM`, VMPath: `E:\VM\late-guest`,
		VHDPath:           `E:\VM\late-guest\late-guest.vhdx`,
		DesiredGeneration: 1, LifecycleState: isolatedstate.VMReady,
		CreatedAt: 1, UpdatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	_, err = verifyFinalCascadeInventory(context.Background(), &isolatedLifecycleDeps{
		state: store, appliance: &orderedGuestAppliance{},
	}, orchestrator)
	if err == nil || !strings.Contains(err.Error(), "CASCADE_INVENTORY_CHANGED") {
		t.Fatalf("late child verification error = %v", err)
	}
}

func TestFinalCascadeInventoryRejectsLateReservation(t *testing.T) {
	store, err := isolatedstate.Open(filepath.Join(t.TempDir(), "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	orchestratorID := "11111111-1111-4111-8111-111111111111"
	orchestrator := isolatedstate.Orchestrator{
		ID: orchestratorID, PhysicalHostID: strings.Repeat("a", 64),
		HostNode: "localhost", HyperVName: "orchestrator",
		NodeName: "orchestrator-node", AgentPort: 9091,
		DesiredGeneration: 2, LifecycleState: isolatedstate.OrchestratorFrozen,
		CreatedAt: 1, UpdatedAt: 1,
	}
	if err := store.PutOrchestrator(context.Background(), orchestrator); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAllocations(context.Background(), []isolatedstate.ActiveResourceAllocation{{
		Kind: "relay_port", ScopeID: orchestratorID, Value: "20000",
		ResourceID:             "22222222-2222-4222-8222-222222222222",
		ApplianceReservationID: "reservation-1", AllocatedAt: 1,
	}}); err != nil {
		t.Fatal(err)
	}
	_, err = verifyFinalCascadeInventory(context.Background(), &isolatedLifecycleDeps{
		state: store, appliance: &orderedGuestAppliance{},
	}, orchestrator)
	if err == nil || !strings.Contains(err.Error(), "active reservations") {
		t.Fatalf("late reservation verification error = %v", err)
	}
}

func TestChildAdmissionRereadsParentAfterHostFence(t *testing.T) {
	store, err := isolatedstate.Open(filepath.Join(t.TempDir(), "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	orchestratorID := "11111111-1111-4111-8111-111111111111"
	stale := isolatedstate.Orchestrator{
		ID: orchestratorID, PhysicalHostID: strings.Repeat("a", 64),
		HostNode: "localhost", HyperVName: "orchestrator",
		NodeName: "orchestrator-node", AgentPort: 9091,
		DesiredGeneration: 1, AppliedGeneration: 1, ObservedGeneration: 1,
		LifecycleState: isolatedstate.OrchestratorReady,
		HealthState:    "ready", CreatedAt: 1, UpdatedAt: 1,
	}
	if err := store.PutOrchestrator(context.Background(), stale); err != nil {
		t.Fatal(err)
	}
	host := &freezeDuringAcquireHost{store: store, orchestratorID: orchestratorID}
	deps := &isolatedLifecycleDeps{
		state: store, host: host, appliance: &orderedGuestAppliance{},
	}
	lease, err := host.AcquireFence(
		context.Background(), Target{Name: "localhost"},
		isolated.HostCreateFenceRequest{
			PhysicalHostID: stale.PhysicalHostID, HostNode: stale.HostNode,
			OperationID: "22222222-2222-4222-8222-222222222222",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = admitChildMutationAfterFence(
		context.Background(), deps, Target{Name: "localhost"}, stale, lease,
		"vm", "33333333-3333-4333-8333-333333333333", "repair",
	)
	if err == nil || !strings.Contains(err.Error(), "PARENT_FROZEN") {
		t.Fatalf("child admission error = %v, want parent frozen", err)
	}
	persisted, err := store.GetOrchestrator(context.Background(), orchestratorID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.LifecycleState != isolatedstate.OrchestratorFrozen ||
		persisted.DesiredGeneration != 2 {
		t.Fatalf("parent after blocked child = %+v", persisted)
	}
}

func TestApprovedCascadeVMIncarnationRaceFailsClosed(t *testing.T) {
	store, err := isolatedstate.Open(filepath.Join(t.TempDir(), "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	orchestratorID := "11111111-1111-4111-8111-111111111111"
	networkID := "22222222-2222-4222-8222-222222222222"
	vmID := "33333333-3333-4333-8333-333333333333"
	vmGUID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	adapterID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if err := store.PutOrchestrator(context.Background(), isolatedstate.Orchestrator{
		ID: orchestratorID, PhysicalHostID: strings.Repeat("a", 64),
		HostNode: "localhost", HyperVName: "orchestrator",
		NodeName: "orchestrator-node", AgentPort: 9091,
		DesiredGeneration: 1, LifecycleState: isolatedstate.OrchestratorReady,
		CreatedAt: 1, UpdatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutNetwork(context.Background(), isolatedstate.PrivateNetwork{
		ID: networkID, OrchestratorID: orchestratorID,
		HyperVSwitchName: "private", CIDR: "192.168.240.0/26",
		GatewayIPv4: "192.168.240.1", OrchestratorMAC: "02155D010200",
		DNSServersJSON: "[]", DesiredGeneration: 1,
		LifecycleState: isolatedstate.NetworkReady, CreatedAt: 1, UpdatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	vm := isolatedstate.IsolatedVM{
		ID: vmID, OrchestratorID: orchestratorID, NetworkID: networkID,
		HyperVName: "guest", HyperVVMID: &vmGUID, HyperVAdapterID: &adapterID,
		Incarnation: 1, NodeName: "guest-node", GuestOS: isolatedstate.GuestWindows,
		ProfileName: "windows", IPv4: "192.168.240.10", MAC: "02155D010201",
		PrefixLength: 26, GatewayIPv4: "192.168.240.1", DNSServersJSON: "[]",
		StorageRoot: `E:\VM`, VMPath: `E:\VM\guest`, VHDPath: `E:\VM\guest\guest.vhdx`,
		DesiredGeneration: 1, AppliedGeneration: 1, ObservedGeneration: 1,
		LifecycleState: isolatedstate.VMReady, CreatedAt: 1, UpdatedAt: 1,
	}
	if err := store.PutVM(context.Background(), vm); err != nil {
		t.Fatal(err)
	}
	plan, err := isolated.BuildOrchestratorDeletePlan(isolated.DeleteOrchestratorRequest{
		OperationID: "44444444-4444-4444-8444-444444444444",
		Orchestrator: isolatedstate.Orchestrator{
			ID: orchestratorID, PhysicalHostID: strings.Repeat("a", 64),
			DesiredGeneration: 1,
		},
		Cascade: true, Children: cascadeChildren(nil, []isolatedstate.IsolatedVM{vm}, nil, nil),
		ExpectedGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	vm.Incarnation = 2
	vm.DesiredGeneration = 2
	if err := store.PutVM(context.Background(), vm); err != nil {
		t.Fatal(err)
	}
	err = validateApprovedCascadeChild(
		context.Background(), store, plan.Plan, "vm", vmID,
	)
	if err == nil || !strings.Contains(err.Error(), "incarnation") {
		t.Fatalf("incarnation race error = %v", err)
	}
}

func TestDeleteOrchestratorFailsClosedWhenChildCompletesAtFinalFence(t *testing.T) {
	root := t.TempDir()
	store, err := isolatedstate.Open(filepath.Join(root, "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	orchestratorID := "11111111-1111-4111-8111-111111111111"
	operationID := "33333333-3333-4333-8333-333333333333"
	vmGUID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	record := isolatedstate.Orchestrator{
		ID: orchestratorID, PhysicalHostID: strings.Repeat("a", 64),
		HostNode: "localhost", HyperVName: "orchestrator", HyperVVMID: &vmGUID,
		NodeName: "orchestrator-node", AgentPort: 9091,
		DesiredGeneration: 1, AppliedGeneration: 1, ObservedGeneration: 1,
		LifecycleState: isolatedstate.OrchestratorReady,
		CreatedAt:      1, UpdatedAt: 1,
	}
	if err := store.PutOrchestrator(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	reg := registry.Load(filepath.Join(root, "nodes.json"))
	if err := reg.SetNode(&registry.Node{
		Name: "localhost", Address: "127.0.0.1:9090",
	}); err != nil {
		t.Fatal(err)
	}
	host := &lateCascadeChildHost{store: store, orchestratorID: orchestratorID}
	deps := &isolatedLifecycleDeps{
		state: store, host: host, appliance: &orderedGuestAppliance{},
		registry: reg,
	}
	baseArgs := map[string]any{
		"orchestrator_id": orchestratorID, "operation_id": operationID,
	}
	first, err := deleteIsolatedOrchestratorHandler(deps)(
		context.Background(),
		mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: baseArgs}},
	)
	if err != nil || first == nil || first.IsError {
		t.Fatalf("initial delete plan = %#v, %v", first, err)
	}
	plan, err := isolated.BuildOrchestratorDeletePlan(isolated.DeleteOrchestratorRequest{
		OperationID: operationID, Orchestrator: record,
		ExpectedGeneration: record.DesiredGeneration,
	})
	if err != nil {
		t.Fatal(err)
	}
	resumeArgs := map[string]any{
		"orchestrator_id": orchestratorID, "operation_id": operationID,
		"approved_plan_revision": plan.Plan.Revision, "resume_exact": true,
	}
	result, err := deleteIsolatedOrchestratorHandler(deps)(
		context.Background(),
		mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: resumeArgs}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.IsError ||
		!strings.Contains(toolResultText(result), "CASCADE_INVENTORY_CHANGED") {
		t.Fatalf("late child result = %#v", result)
	}
	if !host.inserted {
		t.Fatal("late child was not inserted at final host fence")
	}
}

func TestAuthorityReleaseFailureStillReleasesPhysicalHostFence(t *testing.T) {
	order := []string{}
	applianceClient := &failingAuthorityReleaseAppliance{
		orderedGuestAppliance: &orderedGuestAppliance{order: &order},
		releaseErr:            errors.New("release RPC unavailable"),
	}
	host := &releaseAuditHost{}
	deps := &isolatedLifecycleDeps{appliance: applianceClient, host: host}
	orchestrator := isolatedstate.Orchestrator{
		ID:                testOrchestratorID,
		PhysicalHostID:    strings.Repeat("a", 64),
		DesiredGeneration: 3,
	}
	lease := isolated.HostFenceLease{
		LeaseID:       "55555555-5555-4555-8555-555555555555",
		LeaseSecret:   strings.Repeat("a", 64),
		ExpiresAtUnix: time.Now().Add(time.Hour).Unix(),
		Fence:         9,
	}
	err := releaseOrchestratorFence(
		deps, Target{Name: "host"}, orchestrator, lease)
	if err == nil || !strings.Contains(err.Error(), "APPLIANCE_AUTHORITY_RELEASE_FAILED") {
		t.Fatalf("release error = %v", err)
	}
	if host.releaseCalls != 1 {
		t.Fatalf("physical host release calls = %d, want 1", host.releaseCalls)
	}
}

func TestProtocolV1RejectedBeforePhysicalHostFence(t *testing.T) {
	order := []string{}
	host := &releaseAuditHost{}
	deps := &isolatedLifecycleDeps{
		appliance: &v1ReadinessAppliance{
			orderedGuestAppliance: &orderedGuestAppliance{order: &order},
		},
		host: host,
	}
	_, err := acquireCompatibleOrchestratorFence(
		context.Background(), deps, Target{Name: "host"},
		isolatedstate.Orchestrator{
			ID:             testOrchestratorID,
			PhysicalHostID: strings.Repeat("a", 64),
			HostNode:       "host",
		},
		testOperationID,
	)
	if err == nil || !strings.Contains(err.Error(), "AGENT_UPGRADE_REQUIRED") {
		t.Fatalf("compatibility error = %v", err)
	}
	if host.acquireCalls != 0 {
		t.Fatalf("physical host fence acquired %d times", host.acquireCalls)
	}
}
