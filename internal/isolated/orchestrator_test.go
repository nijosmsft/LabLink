package isolated

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
)

const (
	testHostID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	orchAID    = "11111111-1111-4111-8111-111111111111"
	orchBID    = "22222222-2222-4222-8222-222222222222"
	networkAID = "33333333-3333-4333-8333-333333333333"
	networkBID = "44444444-4444-4444-8444-444444444444"
	operationA = "55555555-5555-4555-8555-555555555555"
)

type fakeOrchestratorState struct {
	records  []isolatedstate.Orchestrator
	get      map[string]isolatedstate.Orchestrator
	listFn   func() []isolatedstate.Orchestrator
	imported []ServerCacheImport
	events   *[]string
}

func (f *fakeOrchestratorState) ListOrchestrators(
	context.Context,
	string,
) ([]isolatedstate.Orchestrator, error) {
	if f.events != nil {
		*f.events = append(*f.events, "list")
	}
	if f.listFn != nil {
		return append([]isolatedstate.Orchestrator(nil), f.listFn()...), nil
	}
	return append([]isolatedstate.Orchestrator(nil), f.records...), nil
}

func (f *fakeOrchestratorState) GetOrchestrator(
	_ context.Context,
	id string,
) (isolatedstate.Orchestrator, error) {
	record, ok := f.get[id]
	if !ok {
		return isolatedstate.Orchestrator{}, errors.New("not found")
	}
	return record, nil
}

func (f *fakeOrchestratorState) ImportApplianceCache(
	_ context.Context,
	value ServerCacheImport,
) error {
	f.imported = append(f.imported, value)
	return nil
}

type fakeProbe struct {
	observations map[string]OrchestratorObservation
	recoveries   map[string]RecoveryResult
	observeErr   map[string]error
	recoverErr   map[string]error
	recovered    []string
}

func (f *fakeProbe) ObserveOrchestrator(
	_ context.Context,
	record isolatedstate.Orchestrator,
) (OrchestratorObservation, error) {
	if err := f.observeErr[record.ID]; err != nil {
		return OrchestratorObservation{}, err
	}
	return f.observations[record.ID], nil
}

func (f *fakeProbe) RecoverOrchestrator(
	_ context.Context,
	record isolatedstate.Orchestrator,
) (RecoveryResult, error) {
	f.recovered = append(f.recovered, record.ID)
	if err := f.recoverErr[record.ID]; err != nil {
		return RecoveryResult{}, err
	}
	return f.recoveries[record.ID], nil
}

type fakeHostPlanner struct {
	lease     HostFenceLease
	preflight ResourcePreflightResult
	events    *[]string
}

func (f *fakeHostPlanner) AcquireOrchestratorCreateFence(
	_ context.Context,
	_ HostCreateFenceRequest,
) (HostFenceLease, error) {
	if f.events != nil {
		*f.events = append(*f.events, "fence")
	}
	return f.lease, nil
}

func (f *fakeHostPlanner) PreflightOrchestrator(
	_ context.Context,
	_ ResourcePreflightInput,
) (ResourcePreflightResult, error) {
	if f.events != nil {
		*f.events = append(*f.events, "preflight")
	}
	return f.preflight, nil
}

type fakeApplianceClient struct {
	snapshotFn func() appliance.DesiredSnapshot
	reserveFn  func(appliance.ReserveRequest) (appliance.ReserveResult, error)
	reserves   int
}

func (f *fakeApplianceClient) GetApplianceState(
	context.Context,
	string,
) (appliance.DesiredSnapshot, error) {
	if f.snapshotFn == nil {
		return appliance.DesiredSnapshot{}, nil
	}
	return f.snapshotFn(), nil
}

func (f *fakeApplianceClient) ReserveResources(
	_ context.Context,
	_ string,
	request appliance.ReserveRequest,
) (appliance.ReserveResult, error) {
	f.reserves++
	return f.reserveFn(request)
}

func readyObservation(record isolatedstate.Orchestrator) OrchestratorObservation {
	return OrchestratorObservation{
		Record:             record,
		HostReachable:      true,
		VMState:            "Running",
		MainNICHealthy:     true,
		AgentAuthenticated: true,
		Agent: AgentCompatibility{
			Node: "orch-node", AgentVersion: "v1.0.0",
			Capabilities: []string{
				string(CapabilityApplianceV1),
				string(CapabilityNetworkV1),
				string(CapabilityRelayV1),
				string(CapabilityNATV1),
				string(CapabilityStatsV1),
			},
			ProtocolVersion: 1,
		},
		ApplianceReady:          true,
		AppliancePolicyVerified: true,
		ApplianceSchema:         1,
		ImmutableIdentityMatch:  true,
		Capacity: OperationCapacity{
			FreeSubnets: 10, PrivateAdapterSlots: 10, SwitchSlots: 10,
			HostResourcesAvailable: true,
			FreeGuestIPs:           10, FreeMACs: 10, FreeRelayPorts: 10,
			FreeConntrackMarks: 10, GuestSlots: 10,
			NATSupported: true, ReservedConntrackMark: true,
		},
	}
}

func orchestrator(id string, created int64) isolatedstate.Orchestrator {
	return isolatedstate.Orchestrator{
		ID: id, PhysicalHostID: testHostID, HostNode: "host",
		HyperVName: "orchestrator", NodeName: "node",
		DesiredGeneration: 1, AppliedGeneration: 1, ObservedGeneration: 1,
		LifecycleState: isolatedstate.OrchestratorReady,
		MaxNetworks:    MaxNetworksPerOrchestrator, MaxVMs: MaxVMsPerOrchestrator,
		CreatedAt: isolatedstate.UnixSeconds(created),
	}
}

func TestSelectionUsesOldestHealthyCompatibleOrchestrator(t *testing.T) {
	oldest := orchestrator(orchAID, 10)
	newest := orchestrator(orchBID, 20)
	state := &fakeOrchestratorState{records: []isolatedstate.Orchestrator{newest, oldest}}
	probe := &fakeProbe{observations: map[string]OrchestratorObservation{
		oldest.ID: readyObservation(oldest),
		newest.ID: readyObservation(newest),
	}}
	result, err := (OrchestratorDomain{State: state, Probe: probe}).Select(
		context.Background(),
		SelectionRequest{
			PhysicalHostID: testHostID,
			Operation:      OperationAddNetwork,
			ServerVersion:  "v1.0.0",
		},
	)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if result.Orchestrator.ID != oldest.ID {
		t.Fatalf("selected %s, want oldest %s", result.Orchestrator.ID, oldest.ID)
	}
}

func TestExplicitIncompatibleTargetIsNotSubstituted(t *testing.T) {
	explicit := orchestrator(orchAID, 10)
	compatible := orchestrator(orchBID, 20)
	observation := readyObservation(explicit)
	observation.Agent.Capabilities = []string{string(CapabilityApplianceV1)}
	state := &fakeOrchestratorState{
		records: []isolatedstate.Orchestrator{explicit, compatible},
		get:     map[string]isolatedstate.Orchestrator{explicit.ID: explicit},
	}
	probe := &fakeProbe{observations: map[string]OrchestratorObservation{
		explicit.ID:   observation,
		compatible.ID: readyObservation(compatible),
	}}
	_, err := (OrchestratorDomain{State: state, Probe: probe}).Select(
		context.Background(),
		SelectionRequest{
			PhysicalHostID:       testHostID,
			ExplicitOrchestrator: explicit.ID,
			Operation:            OperationAddNetwork,
			ServerVersion:        "server-v2",
		},
	)
	if ErrorCode(err) != "AGENT_CAPABILITY_MISSING" {
		t.Fatalf("error = %v, want AGENT_CAPABILITY_MISSING", err)
	}
	if !strings.Contains(err.Error(), "update_agent(node=orch-node)") {
		t.Fatalf("error lacks update guidance: %v", err)
	}
}

func TestCapacityChecksOnlyRequestedOperation(t *testing.T) {
	record := orchestrator(orchAID, 10)
	observation := readyObservation(record)
	observation.Capacity.FreeSubnets = 0
	observation.Capacity.PrivateAdapterSlots = 0
	state := &fakeOrchestratorState{records: []isolatedstate.Orchestrator{record}}
	probe := &fakeProbe{observations: map[string]OrchestratorObservation{record.ID: observation}}
	domain := OrchestratorDomain{State: state, Probe: probe}

	if _, err := domain.Select(context.Background(), SelectionRequest{
		PhysicalHostID: testHostID, Operation: OperationAddGuest, ServerVersion: "v1",
	}); err != nil {
		t.Fatalf("guest selection incorrectly required network capacity: %v", err)
	}
	if _, err := domain.Select(context.Background(), SelectionRequest{
		PhysicalHostID: testHostID, Operation: OperationAddNetwork, ServerVersion: "v1",
	}); ErrorCode(err) != "NO_USABLE_ORCHESTRATOR" {
		t.Fatalf("network selection error = %v", err)
	}
}

func TestOfflineCandidateIsRecoveredBeforeSelection(t *testing.T) {
	record := orchestrator(orchAID, 10)
	offline := readyObservation(record)
	offline.VMState = "Off"
	offline.AgentAuthenticated = false
	recovered := readyObservation(record)
	probe := &fakeProbe{
		observations: map[string]OrchestratorObservation{record.ID: offline},
		recoveries: map[string]RecoveryResult{
			record.ID: {
				Observation: recovered,
				Steps:       []RecoveryStep{{Action: "start_vm"}, {Action: "verify_mtls"}},
			},
		},
	}
	result, err := (OrchestratorDomain{
		State: &fakeOrchestratorState{records: []isolatedstate.Orchestrator{record}},
		Probe: probe,
	}).Select(context.Background(), SelectionRequest{
		PhysicalHostID: testHostID, Operation: OperationReconcile, ServerVersion: "v1",
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if len(probe.recovered) != 1 || probe.recovered[0] != record.ID {
		t.Fatalf("recovery attempts = %v", probe.recovered)
	}
	if len(result.Recovery) != 2 {
		t.Fatalf("recovery steps = %+v", result.Recovery)
	}
}

func TestCreateFenceRecheckReusesConcurrentWinner(t *testing.T) {
	record := orchestrator(orchAID, 10)
	var events []string
	state := &fakeOrchestratorState{
		events: &events,
		listFn: func() []isolatedstate.Orchestrator {
			return []isolatedstate.Orchestrator{record}
		},
	}
	probe := &fakeProbe{observations: map[string]OrchestratorObservation{
		record.ID: readyObservation(record),
	}}
	lock, err := hyperv.HostOrchestratorCreateLockKey(testHostID)
	if err != nil {
		t.Fatal(err)
	}
	host := &fakeHostPlanner{
		events: &events,
		lease: HostFenceLease{
			LeaseID: "99999999-9999-4999-8999-999999999999", LeaseSecret: strings.Repeat("a", 64),
			Fence: 7, LockKey: lock,
		},
		preflight: ResourcePreflightResult{Allowed: true},
	}
	plan, err := (OrchestratorDomain{State: state, Probe: probe, Host: host}).
		PlanCreateOrReuse(context.Background(), OrchestratorCreateRequest{
			OperationID: operationA, PhysicalHostID: testHostID, HostNode: "host",
			ProfileName: "ubuntu", MainVSwitch: "main",
			OrchestratorID: OrchestratorID(orchBID), ServerVersion: "v1",
		})
	if err != nil {
		t.Fatalf("PlanCreateOrReuse: %v", err)
	}
	if plan.Reused == nil || plan.Reused.Orchestrator.ID != record.ID {
		t.Fatalf("plan did not reuse concurrent winner: %+v", plan)
	}
	if strings.Join(events, ",") != "fence,list" {
		t.Fatalf("events = %v, want fence before reuse recheck", events)
	}
}

func TestCreatePlanHasImmutableNamesAndPreflightInputs(t *testing.T) {
	var listed bool
	state := &fakeOrchestratorState{listFn: func() []isolatedstate.Orchestrator {
		if !listed {
			listed = true
		}
		return nil
	}}
	probe := &fakeProbe{observations: map[string]OrchestratorObservation{}}
	lock, _ := hyperv.HostOrchestratorCreateLockKey(testHostID)
	host := &fakeHostPlanner{
		lease: HostFenceLease{
			LeaseID: "99999999-9999-4999-8999-999999999999", LeaseSecret: strings.Repeat("b", 64),
			Fence: 1, LockKey: lock,
		},
		preflight: ResourcePreflightResult{
			Allowed: true, EffectivePrivateAdapterSlots: 8,
		},
	}
	request := OrchestratorCreateRequest{
		OperationID: operationA, PhysicalHostID: testHostID, HostNode: "host",
		ProfileName: "ubuntu-24.04", MainVSwitch: "main",
		OrchestratorID: OrchestratorID(orchAID), ProjectedStorageBytes: 64 << 30,
	}
	first, err := (OrchestratorDomain{State: state, Probe: probe, Host: host}).
		PlanCreateOrReuse(context.Background(), request)
	if err != nil {
		t.Fatalf("first plan: %v", err)
	}
	second, err := (OrchestratorDomain{State: state, Probe: probe, Host: host}).
		PlanCreateOrReuse(context.Background(), request)
	if err != nil {
		t.Fatalf("second plan: %v", err)
	}
	if first.Names != second.Names || first.Plan.SemanticHash != second.Plan.SemanticHash {
		t.Fatalf("create plan is not deterministic: %+v / %+v", first, second)
	}
	if first.Plan.Inputs["memory_mb"] != 8192 || first.Plan.Inputs["vcpu"] != 4 {
		t.Fatalf("default resources = %+v", first.Plan.Inputs)
	}
}

func TestResumeExactUsesSemanticHash(t *testing.T) {
	inputs := map[string]any{"resource_id": orchAID, "profile": "ubuntu", "memory_mb": 8192}
	plan, err := newRevisionedPlan("create", operationA, orchAID, inputs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateResumeExact(plan, operationA, true, map[string]any{
		"memory_mb": 8192, "profile": "ubuntu", "resource_id": orchAID,
	}); err != nil {
		t.Fatalf("canonical retry rejected: %v", err)
	}
	if err := ValidateResumeExact(plan, operationA, true, map[string]any{
		"resource_id": orchAID, "profile": "ubuntu", "memory_mb": 4096,
	}); ErrorCode(err) != "RESUME_ARGUMENT_MISMATCH" {
		t.Fatalf("changed semantic input error = %v", err)
	}
}

func TestCascadeRevisionMismatchAndInventoryDrift(t *testing.T) {
	vmID := "66666666-6666-4666-8666-666666666666"
	record := orchestrator(orchAID, 10)
	record.HostFence = 9
	vmGUID := "77777777-7777-4777-8777-777777777777"
	record.HyperVVMID = &vmGUID
	children := []CascadeChild{{
		ResourceType: "vm", ResourceID: vmID, Action: "delete_vm",
		ExpectedHostIdentity: "88888888-8888-4888-8888-888888888888",
		ExpectedGeneration:   3,
	}}
	plan, err := BuildOrchestratorDeletePlan(DeleteOrchestratorRequest{
		OperationID: operationA, Orchestrator: record, Cascade: true,
		Children: children, ExpectedGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCascadeResume(plan, operationA, "wrong", children); ErrorCode(err) != "CASCADE_REVISION_MISMATCH" {
		t.Fatalf("revision error = %v", err)
	}
	drifted := append([]CascadeChild(nil), children...)
	drifted[0].ExpectedGeneration = 4
	if err := ValidateCascadeResume(plan, operationA, plan.Plan.Revision, drifted); ErrorCode(err) != "CASCADE_INVENTORY_CHANGED" {
		t.Fatalf("drift error = %v", err)
	}
}

func TestServerCacheImportUsesApplianceInventory(t *testing.T) {
	state := &fakeOrchestratorState{}
	client := &fakeApplianceClient{snapshotFn: func() appliance.DesiredSnapshot {
		return appliance.DesiredSnapshot{
			Status:    appliance.Status{InventoryGeneration: 12},
			Authority: appliance.Authority{ParentGeneration: 7},
			Networks: []appliance.Network{{
				ID: networkAID, CIDR: "192.168.240.192/26",
				DesiredGeneration: 4, AppliedGeneration: 4, ObservedGeneration: 4,
			}},
			Reservations: []appliance.Reservation{{
				ID: "reservation", ResourceKind: "network", ResourceID: networkAID,
			}},
		}
	}}
	result, err := (OrchestratorDomain{State: state, Appliance: client}).
		ImportServerCache(context.Background(), orchAID)
	if err != nil {
		t.Fatalf("ImportServerCache: %v", err)
	}
	if result.InventoryGeneration != 12 || len(state.imported) != 1 ||
		state.imported[0].Networks[0].CIDR != "192.168.240.192/26" {
		t.Fatalf("import = %+v, captured = %+v", result, state.imported)
	}
}

func TestAuthoritativeReservationRetriesPortCollision(t *testing.T) {
	var occupied int64
	client := &fakeApplianceClient{
		snapshotFn: func() appliance.DesiredSnapshot {
			snapshot := appliance.DesiredSnapshot{}
			if occupied != 0 {
				snapshot.Reservations = []appliance.Reservation{{
					ID: "other", ResourceKind: "relay", ResourceID: orchBID,
					ListenPort: &occupied,
				}}
			}
			return snapshot
		},
	}
	client.reserveFn = func(request appliance.ReserveRequest) (appliance.ReserveResult, error) {
		if client.reserves == 1 {
			occupied = *request.Reservations[0].ListenPort
			return appliance.ReserveResult{}, &appliance.CollisionError{
				Code: appliance.CodePortInUse,
			}
		}
		return appliance.ReserveResult{Reservations: request.Reservations}, nil
	}
	result, err := ReserveAuthoritativeResources(context.Background(), client,
		AuthoritativeReservationRequest{
			OrchestratorID: orchAID,
			MaxAttempts:    3,
			Build: func(snapshot appliance.DesiredSnapshot, _ int) (appliance.ReserveRequest, error) {
				port := int64(appliance.RelayPortMin)
				if len(snapshot.Reservations) != 0 {
					port++
				}
				return appliance.ReserveRequest{Reservations: []appliance.Reservation{{
					ID: "relay-reservation", ResourceKind: "relay",
					ResourceID: networkAID, ListenPort: &port,
				}}}, nil
			},
		})
	if err != nil {
		t.Fatalf("ReserveAuthoritativeResources: %v", err)
	}
	if result.Attempts != 2 ||
		*result.Result.Reservations[0].ListenPort != appliance.RelayPortMin+1 {
		t.Fatalf("result = %+v", result)
	}
}
