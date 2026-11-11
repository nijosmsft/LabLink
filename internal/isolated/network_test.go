package isolated

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
)

type fakeNetworkState struct {
	networks []isolatedstate.PrivateNetwork
	guests   int
	imports  []NetworkReservationImport
}

func (f *fakeNetworkState) ListNetworks(
	context.Context,
	string,
) ([]isolatedstate.PrivateNetwork, error) {
	return append([]isolatedstate.PrivateNetwork(nil), f.networks...), nil
}

func (f *fakeNetworkState) CountActiveVMs(context.Context, string) (int, error) {
	return f.guests, nil
}

func (f *fakeNetworkState) ImportNetworkReservation(
	_ context.Context,
	value NetworkReservationImport,
) error {
	f.imports = append(f.imports, value)
	return nil
}

type fakeHostNetwork struct {
	observation NetworkHostObservation
}

func (f *fakeHostNetwork) ObserveNetwork(
	context.Context,
	NetworkHostQuery,
) (NetworkHostObservation, error) {
	return f.observation, nil
}

func networkOrchestrator() isolatedstate.Orchestrator {
	record := orchestrator(orchAID, 10)
	vmGUID := "77777777-7777-4777-8777-777777777777"
	record.HyperVVMID = &vmGUID
	record.HostFence = 4
	return record
}

func addNetworkRequest() AddNetworkRequest {
	return AddNetworkRequest{
		OperationID:              operationA,
		Orchestrator:             networkOrchestrator(),
		NetworkID:                NetworkID(networkAID),
		DisplayName:              "private",
		ExpectedParentGeneration: 1,
		HostFence:                4,
	}
}

func TestNetworkAllocationUsesBaseGatewayAndGuestRange(t *testing.T) {
	first, err := PrivateSubnet(0)
	if err != nil {
		t.Fatal(err)
	}
	if first.String() != "192.168.240.0/26" ||
		PrivateGateway(first).String() != "192.168.240.1" {
		t.Fatalf("first subnet/gateway = %s/%s", first, PrivateGateway(first))
	}
	last, err := PrivateSubnet(PrivateSubnetCount - 1)
	if err != nil {
		t.Fatal(err)
	}
	if last.String() != "192.168.255.192/26" {
		t.Fatalf("last subnet = %s", last)
	}
	firstGuest, err := GuestAddress(first, FirstGuestAddressOffset)
	if err != nil {
		t.Fatal(err)
	}
	lastGuest, err := GuestAddress(first, LastGuestAddressOffset)
	if err != nil {
		t.Fatal(err)
	}
	if firstGuest.String() != "192.168.240.10" ||
		lastGuest.String() != "192.168.240.62" {
		t.Fatalf("guest range = %s-%s", firstGuest, lastGuest)
	}
	if _, err := GuestAddress(first, 9); ErrorCode(err) != "INVALID_GUEST_ADDRESS" {
		t.Fatalf("reserved address error = %v", err)
	}
}

func TestAutomaticReservationRetriesConcurrentCollision(t *testing.T) {
	var snapshot appliance.DesiredSnapshot
	client := &fakeApplianceClient{
		snapshotFn: func() appliance.DesiredSnapshot { return snapshot },
	}
	client.reserveFn = func(request appliance.ReserveRequest) (appliance.ReserveResult, error) {
		if request.Reservations[0].CapacityKind != "network" {
			t.Fatalf("capacity kind = %q", request.Reservations[0].CapacityKind)
		}
		index := *request.Reservations[0].SubnetIndex
		if client.reserves == 1 {
			used := int64(0)
			snapshot.Reservations = []appliance.Reservation{{
				ID: "other", ResourceKind: "network", ResourceID: networkBID,
				SubnetIndex: &used,
			}}
			return appliance.ReserveResult{}, &appliance.CollisionError{
				Code:                appliance.CodeSubnetInUse,
				InventoryGeneration: 1,
			}
		}
		if index != 1 {
			t.Fatalf("retry index = %d, want 1", index)
		}
		accepted := request.Reservations[0]
		accepted.ParentGeneration = 2
		return appliance.ReserveResult{
			Reservations:     []appliance.Reservation{accepted},
			ParentGeneration: 2, InventoryGeneration: 2,
		}, nil
	}
	state := &fakeNetworkState{}
	plan, err := (NetworkDomain{
		State: state, Appliance: client, Host: &fakeHostNetwork{},
	}).ReserveAndPlan(context.Background(), addNetworkRequest())
	if err != nil {
		t.Fatalf("ReserveAndPlan: %v", err)
	}
	if plan.CollisionRetries != 1 || plan.Network.SubnetIndex != 1 ||
		plan.Network.CIDR != "192.168.240.64/26" {
		t.Fatalf("plan after collision = %+v", plan)
	}
	if len(state.imports) != 1 || state.imports[0].SubnetIndex != 1 {
		t.Fatalf("local import = %+v", state.imports)
	}
}

func TestApplianceAcceptedValuesWinLocalImport(t *testing.T) {
	client := &fakeApplianceClient{
		snapshotFn: func() appliance.DesiredSnapshot { return appliance.DesiredSnapshot{} },
	}
	client.reserveFn = func(request appliance.ReserveRequest) (appliance.ReserveResult, error) {
		accepted := request.Reservations[0]
		index := int64(3)
		accepted.SubnetIndex = &index
		accepted.MAC = "02155DABCDEF"
		accepted.ID = "appliance-reservation"
		return appliance.ReserveResult{
			Reservations:     []appliance.Reservation{accepted},
			ParentGeneration: 2, InventoryGeneration: 4,
		}, nil
	}
	state := &fakeNetworkState{}
	plan, err := (NetworkDomain{
		State: state, Appliance: client, Host: &fakeHostNetwork{},
	}).ReserveAndPlan(context.Background(), addNetworkRequest())
	if err != nil {
		t.Fatalf("ReserveAndPlan: %v", err)
	}
	if plan.Network.SubnetIndex != 3 ||
		plan.Network.CIDR != "192.168.240.192/26" ||
		plan.Network.OrchestratorMAC != "02155DABCDEF" {
		t.Fatalf("appliance values not used: %+v", plan.Network)
	}
	if got := state.imports[0]; got.ReservationID != "appliance-reservation" ||
		got.SubnetIndex != 3 || got.OrchestratorMAC != "02155DABCDEF" {
		t.Fatalf("cache import = %+v", got)
	}
}

func TestSubnetAllocationExhaustionAcrossEntire20(t *testing.T) {
	reservations := make([]appliance.Reservation, 0, PrivateSubnetCount)
	for index := 0; index < PrivateSubnetCount; index++ {
		value := int64(index)
		reservations = append(reservations, appliance.Reservation{
			ID: "reservation", ResourceKind: "network",
			ResourceID: networkBID, SubnetIndex: &value,
		})
	}
	_, _, err := chooseSubnet(appliance.DesiredSnapshot{Reservations: reservations}, nil, nil)
	if ErrorCode(err) != "NETWORK_CAPACITY_EXHAUSTED" {
		t.Fatalf("exhaustion error = %v", err)
	}
}

func TestSeventeenthNetworkFailsProductCapacity(t *testing.T) {
	networks := make([]isolatedstate.PrivateNetwork, MaxNetworksPerOrchestrator)
	for index := range networks {
		networks[index] = isolatedstate.PrivateNetwork{
			ID:             networkBID,
			OrchestratorID: orchAID,
			LifecycleState: isolatedstate.NetworkReady,
		}
	}
	client := &fakeApplianceClient{
		snapshotFn: func() appliance.DesiredSnapshot {
			t.Fatal("appliance should not be queried after product capacity failure")
			return appliance.DesiredSnapshot{}
		},
	}
	_, err := (NetworkDomain{
		State:     &fakeNetworkState{networks: networks},
		Appliance: client,
		Host:      &fakeHostNetwork{},
	}).ReserveAndPlan(context.Background(), addNetworkRequest())
	if ErrorCode(err) != "NETWORK_CAPACITY_EXHAUSTED" {
		t.Fatalf("17th network error = %v", err)
	}
}

func TestManagementRouteConflictBlocksCandidate(t *testing.T) {
	routes := []hyperv.IsolatedRouteObservation{{
		DestinationPrefix: "192.168.240.0/20",
		InterfaceAlias:    "Management",
	}}
	_, _, err := chooseSubnet(appliance.DesiredSnapshot{}, nil, routes)
	if ErrorCode(err) != "ROUTE_CONFLICT" {
		t.Fatalf("route conflict error = %v", err)
	}
	defaultOnly := []hyperv.IsolatedRouteObservation{{
		DestinationPrefix: "0.0.0.0/0",
		InterfaceAlias:    "Management",
	}}
	index, _, err := chooseSubnet(appliance.DesiredSnapshot{}, nil, defaultOnly)
	if err != nil || index != 0 {
		t.Fatalf("literal default route blocked allocation: index=%d err=%v", index, err)
	}
}

func TestHostObjectCollisionRequiresExactOwnership(t *testing.T) {
	client := &fakeApplianceClient{
		snapshotFn: func() appliance.DesiredSnapshot { return appliance.DesiredSnapshot{} },
		reserveFn: func(appliance.ReserveRequest) (appliance.ReserveResult, error) {
			t.Fatal("reservation should not be attempted after host collision")
			return appliance.ReserveResult{}, nil
		},
	}
	_, err := (NetworkDomain{
		State: &fakeNetworkState{}, Appliance: client,
		Host: &fakeHostNetwork{observation: NetworkHostObservation{
			SwitchExists: true, SwitchName: "isolated-network-333333333333",
			SwitchPrivate: true, SwitchOwned: false,
		}},
	}).ReserveAndPlan(context.Background(), addNetworkRequest())
	if ErrorCode(err) != "SWITCH_OWNERSHIP_MISMATCH" {
		t.Fatalf("collision error = %v", err)
	}
}

func TestRemoveNonemptyNetworkRefuses(t *testing.T) {
	switchGUID := "77777777-7777-4777-8777-777777777777"
	adapterID := "88888888-8888-4888-8888-888888888888"
	network := isolatedstate.PrivateNetwork{
		ID: networkAID, OrchestratorID: orchAID,
		HyperVSwitchGUID: &switchGUID, OrchestratorAdapterID: &adapterID,
		DesiredGeneration: 2, LifecycleState: isolatedstate.NetworkReady,
	}
	_, err := (NetworkDomain{State: &fakeNetworkState{guests: 1}}).
		BuildRemovePlan(context.Background(), RemoveNetworkRequest{
			OperationID: operationA, Network: network, ExpectedGeneration: 2,
			Host: NetworkHostObservation{SwitchGUID: switchGUID, AdapterID: adapterID},
		})
	if ErrorCode(err) != "NETWORK_NOT_EMPTY" {
		t.Fatalf("remove error = %v", err)
	}
}

func TestRemovePlanUsesExactSwitchAndAdapterIdentities(t *testing.T) {
	switchGUID := "77777777-7777-4777-8777-777777777777"
	adapterID := "88888888-8888-4888-8888-888888888888"
	network := isolatedstate.PrivateNetwork{
		ID: networkAID, OrchestratorID: orchAID,
		HyperVSwitchName: "isolated-network-333333333333",
		HyperVSwitchGUID: &switchGUID, OrchestratorAdapterID: &adapterID,
		CIDR: "192.168.240.0/26", OrchestratorMAC: "02155DABCDEF",
		DesiredGeneration: 2, AppliedGeneration: 2, ObservedGeneration: 2,
		LifecycleState: isolatedstate.NetworkReady,
	}
	plan, err := (NetworkDomain{State: &fakeNetworkState{}}).
		BuildRemovePlan(context.Background(), RemoveNetworkRequest{
			OperationID: operationA, Network: network, ExpectedGeneration: 2,
			Host: NetworkHostObservation{SwitchGUID: switchGUID, AdapterID: adapterID},
		})
	if err != nil {
		t.Fatalf("BuildRemovePlan: %v", err)
	}
	if len(plan.Actions) != 4 ||
		plan.Actions[1].ExpectedIdentity != adapterID ||
		plan.Actions[2].ExpectedIdentity != switchGUID {
		t.Fatalf("remove actions = %+v", plan.Actions)
	}
}

func TestStaleGenerationIsRejected(t *testing.T) {
	network := isolatedstate.PrivateNetwork{
		ID: networkAID, OrchestratorID: orchAID, DesiredGeneration: 4,
	}
	_, err := (NetworkDomain{State: &fakeNetworkState{}}).
		BuildRemovePlan(context.Background(), RemoveNetworkRequest{
			OperationID: operationA, Network: network, ExpectedGeneration: 3,
		})
	if ErrorCode(err) != "GENERATION_CONFLICT" {
		t.Fatalf("generation error = %v", err)
	}
	if err := ValidateGenerationConvergence(4, 4, 3); ErrorCode(err) != "STALE_GENERATION" {
		t.Fatalf("convergence error = %v", err)
	}
}

func TestLostNetworkCleanupPlanRequiresRevisionBoundAuthority(t *testing.T) {
	switchGUID := "77777777-7777-4777-8777-777777777777"
	adapterID := "88888888-8888-4888-8888-888888888888"
	network := isolatedstate.PrivateNetwork{
		ID: networkAID, OrchestratorID: orchAID,
		HyperVSwitchGUID: &switchGUID, OrchestratorAdapterID: &adapterID,
		DesiredGeneration: 2,
	}
	items := []isolatedstate.CascadeAuthorityItem{
		{Action: "remove_orchestrator_nic", ResourceType: "network", ResourceID: networkAID},
		{Action: "remove_private_switch", ResourceType: "network", ResourceID: networkAID},
		{Action: "release_subnet", ResourceType: "network", ResourceID: networkAID},
	}
	plan, err := BuildLostNetworkCleanupPlan(LostNetworkCleanupRequest{
		OperationID: operationA, Network: network,
		Authority: isolatedstate.CascadeAuthority{
			OrchestratorID: orchAID, PlanRevision: "r1-approved",
			PlanHash: "hash", Items: items,
		},
	})
	if err != nil {
		t.Fatalf("BuildLostNetworkCleanupPlan: %v", err)
	}
	if len(plan.Actions) != 3 ||
		plan.Inputs["plan_revision"] != "r1-approved" {
		t.Fatalf("lost cleanup plan = %+v", plan)
	}
	items = items[:2]
	_, err = BuildLostNetworkCleanupPlan(LostNetworkCleanupRequest{
		OperationID: operationA, Network: network,
		Authority: isolatedstate.CascadeAuthority{
			OrchestratorID: orchAID, PlanRevision: "r1-approved",
			PlanHash: "hash", Items: items,
		},
	})
	if ErrorCode(err) != "CASCADE_ITEM_NOT_AUTHORIZED" {
		t.Fatalf("missing authority error = %v", err)
	}
}

func TestIdempotentNetworkRetryImportsExistingReservation(t *testing.T) {
	index := int64(2)
	reservation := appliance.Reservation{
		ID: "existing", ResourceKind: "network", ResourceID: networkAID,
		NetworkID: networkAID, SubnetIndex: &index, MAC: "02155DABCDEF",
		ParentGeneration: 2,
	}
	client := &fakeApplianceClient{
		snapshotFn: func() appliance.DesiredSnapshot {
			return appliance.DesiredSnapshot{
				Status:       appliance.Status{InventoryGeneration: 9},
				Reservations: []appliance.Reservation{reservation},
			}
		},
		reserveFn: func(appliance.ReserveRequest) (appliance.ReserveResult, error) {
			return appliance.ReserveResult{}, errors.New("reserve must not run for exact retry")
		},
	}
	state := &fakeNetworkState{}
	domain := NetworkDomain{State: state, Appliance: client, Host: &fakeHostNetwork{}}
	first, err := domain.ReserveAndPlan(context.Background(), addNetworkRequest())
	if err != nil {
		t.Fatalf("first retry: %v", err)
	}
	second, err := domain.ReserveAndPlan(context.Background(), addNetworkRequest())
	if err != nil {
		t.Fatalf("second retry: %v", err)
	}
	if client.reserves != 0 || !first.Imported || !second.Imported ||
		first.Plan.SemanticHash != second.Plan.SemanticHash ||
		first.Network.CIDR != "192.168.240.128/26" {
		t.Fatalf("idempotent plans differ: first=%+v second=%+v", first, second)
	}
}

func TestSpecificHostRouteInsideCandidateConflicts(t *testing.T) {
	candidate := netip.MustParsePrefix("192.168.240.0/26")
	conflicts := FindPrivateRouteConflicts(candidate, []hyperv.IsolatedRouteObservation{{
		DestinationPrefix: "192.168.240.12/32",
		InterfaceAlias:    "Management",
	}})
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %+v", conflicts)
	}
}

func TestNetworkCapacityReportsRouteConflicts(t *testing.T) {
	index := int64(1)
	observation := ObserveNetworkCapacity(
		appliance.DesiredSnapshot{Reservations: []appliance.Reservation{{
			SubnetIndex: &index,
		}}},
		[]hyperv.IsolatedRouteObservation{{
			DestinationPrefix: "192.168.240.0/26",
			InterfaceAlias:    "Management",
		}},
	)
	if observation.Used != 1 || observation.AvailableNetworkSlots != 15 ||
		len(observation.RouteConflicts) != 1 ||
		len(observation.AvailableSubnetIndexes) != PrivateSubnetCount-2 {
		t.Fatalf("capacity observation = %+v", observation)
	}
}

func TestNetworkReconcilePlanAndApplianceWinsMerge(t *testing.T) {
	switchGUID := "77777777-7777-4777-8777-777777777777"
	adapterID := "88888888-8888-4888-8888-888888888888"
	local := isolatedstate.PrivateNetwork{
		ID: networkAID, OrchestratorID: orchAID,
		HyperVSwitchName: "isolated-network-333333333333",
		HyperVSwitchGUID: &switchGUID, OrchestratorAdapterID: &adapterID,
		CIDR: "192.168.240.0/26", GatewayIPv4: "192.168.240.1",
		OrchestratorMAC:   "02155D000001",
		DesiredGeneration: 2, AppliedGeneration: 2, ObservedGeneration: 2,
		LifecycleState: isolatedstate.NetworkReady,
	}
	index := int64(3)
	merged, err := MergeApplianceNetworkCache(local, appliance.Network{
		ID: networkAID, CIDR: "192.168.240.192/26",
		GatewayIPv4: "192.168.240.193", NICMAC: "02155DABCDEF",
		DesiredGeneration: 5, AppliedGeneration: 4, ObservedGeneration: 4,
		State: "degraded",
	}, appliance.Reservation{
		ResourceID: networkAID, SubnetIndex: &index, MAC: "ignored",
	})
	if err != nil {
		t.Fatalf("MergeApplianceNetworkCache: %v", err)
	}
	if merged.HyperVSwitchGUID == nil || *merged.HyperVSwitchGUID != switchGUID ||
		merged.OrchestratorAdapterID == nil || *merged.OrchestratorAdapterID != adapterID {
		t.Fatalf("host identity was not preserved: %+v", merged)
	}
	if merged.CIDR != "192.168.240.192/26" ||
		merged.OrchestratorMAC != "02155DABCDEF" ||
		merged.DesiredGeneration != 5 {
		t.Fatalf("appliance state did not win: %+v", merged)
	}
	merged.AppliedGeneration = 5
	merged.ObservedGeneration = 5
	plan, err := BuildNetworkReconcilePlan(ReconcileNetworkRequest{
		OperationID: operationA, Network: merged,
		ExpectedGeneration: 5, RefreshDNS: true,
		Host: NetworkHostObservation{SwitchGUID: switchGUID, AdapterID: adapterID},
	})
	if err != nil {
		t.Fatalf("BuildNetworkReconcilePlan: %v", err)
	}
	if len(plan.Actions) != 3 || plan.Actions[2].NewGeneration != 6 {
		t.Fatalf("reconcile plan = %+v", plan)
	}
}
