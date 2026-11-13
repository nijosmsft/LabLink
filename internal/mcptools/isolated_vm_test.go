package mcptools

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/isolated"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/secretstore"
	"github.com/nijosmsft/lablink/internal/vmconfig"
)

type orderedGuestAppliance struct {
	isolatedAppliance
	order           *[]string
	reservations    []appliance.Reservation
	natInputs       []isolated.NATInput
	releaseRequests []appliance.ReleaseRequest
	releaseFailures int
	natStates       []appliance.NATState
	guests          []appliance.Guest
	relays          []appliance.Relay
	guestInputs     []isolated.MutationEnvelope
	guestFailures   int
}

func (a *orderedGuestAppliance) CheckReadiness(
	context.Context,
	string,
) (isolated.ApplianceReadiness, error) {
	return isolated.ApplianceReadiness{
		ProtocolVersion: isolated.MaximumProtocolVersion,
		Capabilities: []string{
			string(isolated.CapabilityApplianceV1),
			string(isolated.CapabilityNetworkV1),
			string(isolated.CapabilityRelayV1),
			string(isolated.CapabilityNATV1),
			string(isolated.CapabilityStatsV1),
			string(isolated.CapabilityAuthorityReleaseV1),
			string(isolated.CapabilityParentLifecycleV1),
		},
		Ready: true,
	}, nil
}

func (a *orderedGuestAppliance) SetParentLifecycle(
	context.Context,
	string,
	isolated.MutationEnvelope,
	string,
	uint64,
) error {
	return nil
}

func (a *orderedGuestAppliance) ReleaseAuthority(
	context.Context,
	string,
	isolated.MutationEnvelope,
) error {
	return nil
}

func (a *orderedGuestAppliance) GetApplianceState(context.Context, string) (appliance.DesiredSnapshot, error) {
	return appliance.DesiredSnapshot{
		Reservations: append([]appliance.Reservation(nil), a.reservations...),
		NAT:          append([]appliance.NATState(nil), a.natStates...),
		Guests:       append([]appliance.Guest(nil), a.guests...),
		Relays:       append([]appliance.Relay(nil), a.relays...),
	}, nil
}

func (a *orderedGuestAppliance) ReserveResources(_ context.Context, _ string, request appliance.ReserveRequest) (appliance.ReserveResult, error) {
	a.reservations = append([]appliance.Reservation(nil), request.Reservations...)
	return appliance.ReserveResult{Reservations: request.Reservations, ParentGeneration: 2}, nil
}

func (a *orderedGuestAppliance) RegisterIsolatedGuest(context.Context, string, isolated.RegisterGuestInput) (isolated.GuestMutationResult, error) {
	*a.order = append(*a.order, "register_guest")
	return isolated.GuestMutationResult{}, nil
}

func (a *orderedGuestAppliance) ApplyRelay(context.Context, string, isolated.RelayInput) (isolated.RelayMutationResult, error) {
	*a.order = append(*a.order, "relay")
	return isolated.RelayMutationResult{}, nil
}

func (a *orderedGuestAppliance) SetNATState(_ context.Context, _ string, input isolated.NATInput) (isolated.NATMutationResult, error) {
	*a.order = append(*a.order, "nat")
	a.natInputs = append(a.natInputs, input)
	return isolated.NATMutationResult{NAT: appliance.NATState{
		VMID: input.Header.Header.ResourceID, State: input.DesiredState,
		ConntrackMark:      int64(input.ConntrackMark),
		DesiredGeneration:  input.Header.Header.NewGeneration,
		AppliedGeneration:  input.Header.Header.NewGeneration,
		ObservedGeneration: input.Header.Header.NewGeneration,
	}}, nil
}

func (a *orderedGuestAppliance) RemoveRelay(_ context.Context, _ string, envelope isolated.MutationEnvelope, _, _ string) (isolated.RelayMutationResult, error) {
	*a.order = append(*a.order, "remove_relay")
	retired := int64(1)
	for i := range a.reservations {
		if a.reservations[i].ResourceKind == "relay" {
			a.reservations[i].RetiredAtUnix = &retired
		}
	}
	for i := range a.relays {
		if a.relays[i].ID == envelope.Header.ResourceID {
			a.relays[i].State = "removed"
			a.relays[i].DesiredGeneration = envelope.Header.NewGeneration
			a.relays[i].AppliedGeneration = envelope.Header.NewGeneration
			a.relays[i].ObservedGeneration = envelope.Header.NewGeneration
			a.relays[i].RetiredAtUnix = &retired
		}
	}
	return isolated.RelayMutationResult{}, nil
}

func (a *orderedGuestAppliance) RemoveIsolatedGuest(_ context.Context, _ string, envelope isolated.MutationEnvelope, _ string) (isolated.GuestMutationResult, error) {
	*a.order = append(*a.order, "remove_guest")
	a.guestInputs = append(a.guestInputs, envelope)
	retired := int64(1)
	for i := range a.guests {
		if a.guests[i].ID == envelope.Header.ResourceID {
			a.guests[i].State = "retiring"
			a.guests[i].DesiredGeneration = envelope.Header.NewGeneration
			a.guests[i].AppliedGeneration = envelope.Header.NewGeneration
			a.guests[i].ObservedGeneration = envelope.Header.NewGeneration
			a.guests[i].RetiredAtUnix = &retired
		}
	}
	if a.guestFailures > 0 {
		a.guestFailures--
		return isolated.GuestMutationResult{}, errors.New("injected guest response loss")
	}
	return isolated.GuestMutationResult{}, nil
}

func (a *orderedGuestAppliance) ReleaseResources(_ context.Context, _ string, request appliance.ReleaseRequest) (appliance.ReleaseResult, error) {
	*a.order = append(*a.order, "release_resources")
	a.releaseRequests = append(a.releaseRequests, request)
	if a.releaseFailures > 0 {
		a.releaseFailures--
		return appliance.ReleaseResult{}, errors.New("injected release failure")
	}
	return appliance.ReleaseResult{RetiredIDs: append([]string(nil), request.ReservationIDs...)}, nil
}

func (a *orderedGuestAppliance) InspectApplianceState(context.Context, string) (isolated.ApplianceSnapshot, error) {
	return isolated.ApplianceSnapshot{MainIPv4: "10.0.0.10"}, nil
}

type orderedGuestHost struct {
	isolatedHost
}

func (orderedGuestHost) AcquireFence(context.Context, Target, isolated.HostCreateFenceRequest) (isolated.HostFenceLease, error) {
	return isolated.HostFenceLease{
		LeaseID:       "55555555-5555-4555-8555-555555555555",
		LeaseSecret:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExpiresAtUnix: time.Now().Add(time.Hour).Unix(),
		Fence:         9,
	}, nil
}

func (orderedGuestHost) ReleaseFence(context.Context, Target, isolated.HostFenceLease) {}

func (orderedGuestHost) ReleaseFenceChecked(context.Context, Target, isolated.HostFenceLease) error {
	return nil
}

func (orderedGuestHost) SetParentLifecycle(
	context.Context,
	Target,
	isolatedstate.Orchestrator,
	isolated.HostFenceLease,
	isolatedstate.CascadeAuthority,
	string,
) error {
	return nil
}

func (orderedGuestHost) RebindParentFence(
	context.Context,
	Target,
	isolatedstate.Orchestrator,
	isolated.HostFenceLease,
	isolatedstate.CascadeAuthority,
) error {
	return nil
}

func (orderedGuestHost) CleanupNetworkMetadata(
	context.Context,
	Target,
	hyperv.CleanupIsolatedNetworkMetadataParams,
) (hyperv.IsolatedMetadataCleanupResult, error) {
	return hyperv.IsolatedMetadataCleanupResult{Action: "network_metadata_cleaned"}, nil
}

func (orderedGuestHost) CleanupOrchestratorMetadata(
	context.Context,
	Target,
	hyperv.CleanupIsolatedOrchestratorMetadataParams,
) (hyperv.IsolatedMetadataCleanupResult, error) {
	return hyperv.IsolatedMetadataCleanupResult{Action: "orchestrator_metadata_cleaned"}, nil
}

func (orderedGuestHost) ClaimOrchestrator(
	context.Context,
	Target,
	isolatedstate.Orchestrator,
	isolated.HostFenceLease,
) (hyperv.IsolatedVMObservation, error) {
	return hyperv.IsolatedVMObservation{VMGUID: "77777777-7777-4777-8777-777777777777"}, nil
}

type orderedGuestRuntime struct {
	order *[]string
	reg   *registry.Registry
}

func (r orderedGuestRuntime) Provision(
	_ context.Context, vm isolatedstate.IsolatedVM, _ isolatedstate.PrivateNetwork,
	_ isolatedstate.Orchestrator, _ Target, _ isolated.HostFenceLease, _ string,
	_ *MCPProgressState,
) (isolatedstate.IsolatedVM, hyperv.IsolatedVMMutationResult, error) {
	*r.order = append(*r.order, "provision")
	vmGUID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	adapterID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	vm.HyperVVMID, vm.HyperVAdapterID = &vmGUID, &adapterID
	vm.StorageRoot, vm.VMPath, vm.VHDPath = `E:\VM`, `E:\VM\guest`, `E:\VM\guest\guest.vhdx`
	return vm, hyperv.IsolatedVMMutationResult{
		VMGUID: vmGUID, AdapterID: adapterID, TimeSyncEnabled: true,
	}, nil
}

func (r orderedGuestRuntime) StartAndEnroll(
	_ context.Context, vm isolatedstate.IsolatedVM, relay isolatedstate.RelayAllocation,
	orchestrator isolatedstate.Orchestrator, _ Target, _ *MCPProgressState,
) error {
	*r.order = append(*r.order, "start_enroll")
	return r.reg.SetNode(&registry.Node{
		Name: vm.NodeName, Address: "10.0.0.10:" + fmt.Sprint(relay.ListenPort),
		Role: "isolated-vm", TransportMode: "mtls", TLSServerName: vm.NodeName,
	})
}

func (r orderedGuestRuntime) Inspect(context.Context, isolatedstate.IsolatedVM, Target) (hyperv.IsolatedVMMutationResult, error) {
	*r.order = append(*r.order, "inspect_time")
	return hyperv.IsolatedVMMutationResult{TimeSyncEnabled: true}, nil
}

func (orderedGuestRuntime) Reconcile(context.Context, isolatedstate.IsolatedVM, isolatedstate.PrivateNetwork, isolatedstate.Orchestrator, Target, isolated.HostFenceLease, string) (hyperv.IsolatedVMMutationResult, error) {
	return hyperv.IsolatedVMMutationResult{}, nil
}

func (r orderedGuestRuntime) Delete(context.Context, isolatedstate.IsolatedVM, isolatedstate.Orchestrator, Target, isolated.HostFenceLease, string, bool) (hyperv.IsolatedVMMutationResult, error) {
	*r.order = append(*r.order, "delete_vm")
	return hyperv.IsolatedVMMutationResult{}, nil
}

func TestCreateIsolatedVMOrdersRelayNATEnrollmentAndDomain(t *testing.T) {
	root := t.TempDir()
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
	orchestratorID := "11111111-1111-4111-8111-111111111111"
	networkID := "22222222-2222-4222-8222-222222222222"
	vmID := "33333333-3333-4333-8333-333333333333"
	orchestratorGUID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	mainIP := "10.0.0.10"
	if err := store.PutOrchestrator(context.Background(), isolatedstate.Orchestrator{
		ID: orchestratorID, PhysicalHostID: strings.Repeat("a", 64),
		HostNode: "localhost", HyperVName: "orchestrator", HyperVVMID: &orchestratorGUID,
		NodeName: "orchestrator-node", MainIP: &mainIP, AgentPort: 9091,
		DesiredGeneration: 1, AppliedGeneration: 1, ObservedGeneration: 1,
		LifecycleState: isolatedstate.OrchestratorReady, CreatedAt: 1, UpdatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	switchGUID := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	if err := store.PutNetwork(context.Background(), isolatedstate.PrivateNetwork{
		ID: networkID, OrchestratorID: orchestratorID, HyperVSwitchName: "private",
		HyperVSwitchGUID: &switchGUID, CIDR: "192.168.240.0/26",
		GatewayIPv4: "192.168.240.1", OrchestratorMAC: "02155D010200",
		DNSServersJSON: `["10.0.0.53"]`, DesiredGeneration: 1,
		AppliedGeneration: 1, ObservedGeneration: 1,
		LifecycleState: isolatedstate.NetworkReady, CreatedAt: 1, UpdatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	var order []string
	applianceClient := &orderedGuestAppliance{order: &order}
	deps := &isolatedLifecycleDeps{
		state: store, locks: locks, host: orderedGuestHost{},
		appliance: applianceClient, registry: reg,
		guests: orderedGuestRuntime{order: &order, reg: reg},
	}
	deps.joinDomain = func(context.Context, string, vmconfig.WindowsDomainJoin, int, *registry.Registry, *agentclient.Pool, *secretstore.Store, *audit.Log) (windowsDomainJoinResult, error) {
		order = append(order, "domain")
		return windowsDomainJoinResult{}, nil
	}
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{
		"network_id": networkID, "isolated_vm_id": vmID,
		"display_name": "mutable label", "guest_os": "windows", "profile": "windows",
		"nat_enabled": true, "bootstrap_network_requirement": "nat_enabled",
		"reachable_services": []any{
			map[string]any{"kind": "dns", "address": "10.0.0.53"},
			map[string]any{"kind": "domain_controller", "address": "10.0.0.54"},
		},
		"domain_join": map[string]any{
			"domain": "example.test", "username": "EXAMPLE\\join",
			"password_secret": "domain-password",
		},
	}}}
	result, err := createIsolatedVMHandler(deps)(context.Background(), req)
	if err != nil || result == nil || result.IsError {
		t.Fatalf("create isolated VM = %#v, %v", result, err)
	}
	want := []string{"register_guest", "relay", "provision", "inspect_time", "nat", "start_enroll", "domain"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("lifecycle order = %v, want %v", order, want)
	}
	vm, err := store.GetVM(context.Background(), vmID)
	if err != nil || vm.LifecycleState != isolatedstate.VMReady {
		t.Fatalf("ready VM = %+v, %v", vm, err)
	}
	node, ok := reg.GetNode(vm.NodeName)
	if !ok || node.Address != "10.0.0.10:20000" || node.TLSServerName != vm.NodeName ||
		node.Labels["lablink.isolated_vm_id"] != vm.ID {
		t.Fatalf("strict relay registry identity = %+v, %v", node, ok)
	}
}

func TestNetworkBootstrapDetection(t *testing.T) {
	if !detectsNetworkBootstrap(map[string]any{"first_boot_script": "curl https://example.test/a"}) {
		t.Fatal("known internet download was not detected")
	}
	if detectsNetworkBootstrap(map[string]any{"first_boot_script": "Write-Host offline"}) {
		t.Fatal("offline bootstrap was misclassified")
	}
}

func TestDeleteIsolatedVMUsesExactReservationsAndDoesNotReleaseRelayTwice(t *testing.T) {
	root := t.TempDir()
	store, err := isolatedstate.Open(filepath.Join(root, "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reg := registry.Load(filepath.Join(root, "nodes.json"))
	orchestratorID := "11111111-1111-4111-8111-111111111111"
	networkID := "22222222-2222-4222-8222-222222222222"
	vmID := "33333333-3333-4333-8333-333333333333"
	relayID := "44444444-4444-4444-8444-444444444444"
	orchestratorGUID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	vmGUID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	adapterID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	mainIP := "10.0.0.10"
	if err := store.PutOrchestrator(context.Background(), isolatedstate.Orchestrator{
		ID: orchestratorID, PhysicalHostID: strings.Repeat("a", 64),
		HostNode: "localhost", HyperVName: "orchestrator", HyperVVMID: &orchestratorGUID,
		NodeName: "orchestrator-node", MainIP: &mainIP, AgentPort: 9091,
		DesiredGeneration: 3, AppliedGeneration: 3, ObservedGeneration: 3,
		LifecycleState: isolatedstate.OrchestratorReady, CreatedAt: 1, UpdatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutNetwork(context.Background(), isolatedstate.PrivateNetwork{
		ID: networkID, OrchestratorID: orchestratorID, HyperVSwitchName: "private",
		CIDR: "192.168.240.0/26", GatewayIPv4: "192.168.240.1",
		OrchestratorMAC: "02155D010200", DNSServersJSON: `["10.0.0.53"]`,
		DesiredGeneration: 1, AppliedGeneration: 1, ObservedGeneration: 1,
		LifecycleState: isolatedstate.NetworkReady, CreatedAt: 1, UpdatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	vm := isolatedstate.IsolatedVM{
		ID: vmID, OrchestratorID: orchestratorID, NetworkID: networkID,
		HyperVName: "guest", HyperVVMID: &vmGUID, HyperVAdapterID: &adapterID,
		Incarnation: 1,
		NodeName:    "guest-node", GuestOS: isolatedstate.GuestWindows, ProfileName: "windows",
		IPv4: "192.168.240.10", MAC: "02155D010201", PrefixLength: 26,
		GatewayIPv4: "192.168.240.1", DNSServersJSON: `["10.0.0.53"]`,
		StorageRoot: `E:\VM`, VMPath: `E:\VM\guest`, VHDPath: `E:\VM\guest\guest.vhdx`,
		DesiredGeneration: 2, AppliedGeneration: 2, ObservedGeneration: 2,
		LifecycleState: isolatedstate.VMReady, CreatedAt: 1, UpdatedAt: 1,
	}
	if err := store.PutVM(context.Background(), vm); err != nil {
		t.Fatal(err)
	}
	if err := store.PutRelay(context.Background(), isolatedstate.RelayAllocation{
		ID: relayID, VMID: vmID, OrchestratorID: orchestratorID,
		ListenPort: 20000, TargetIPv4: vm.IPv4, TargetPort: 9091,
		DesiredGeneration: 1, AppliedGeneration: 1, ObservedGeneration: 1,
		LifecycleState: isolatedstate.RelayReady, CreatedAt: 1, UpdatedAt: 1,
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
	port := int64(20000)
	mark := int64(101)
	reservations := []appliance.Reservation{
		{ID: "wrong-mark", ResourceKind: "conntrack_mark", ResourceID: "55555555-5555-4555-8555-555555555555", ConntrackMark: &mark},
		{ID: "guest-ip", ResourceKind: "guest_ip", ResourceID: vmID, IPv4: vm.IPv4},
		{ID: "guest-mac", ResourceKind: "guest_mac", ResourceID: vmID, MAC: vm.MAC},
		{ID: "relay-port", ResourceKind: "relay", ResourceID: relayID, ListenPort: &port},
		{ID: "guest-mark", ResourceKind: "conntrack_mark", ResourceID: vmID, ConntrackMark: &mark},
	}
	var mirrors []isolatedstate.ActiveResourceAllocation
	for _, reservation := range reservations[1:] {
		value := reservation.IPv4
		if reservation.MAC != "" {
			value = reservation.MAC
		}
		if reservation.ListenPort != nil {
			value = fmt.Sprint(*reservation.ListenPort)
		}
		if reservation.ConntrackMark != nil {
			value = fmt.Sprint(*reservation.ConntrackMark)
		}
		mirrors = append(mirrors, isolatedstate.ActiveResourceAllocation{
			Kind: reservation.ResourceKind, ScopeID: orchestratorID, Value: value,
			ResourceID: reservation.ResourceID, ApplianceReservationID: reservation.ID,
			AllocatedAt: 1,
		})
	}
	if err := store.CommitAllocations(context.Background(), mirrors); err != nil {
		t.Fatal(err)
	}
	if err := reg.SetNode(&registry.Node{
		Name: vm.NodeName, Address: "10.0.0.10:20000", Role: "isolated-vm",
		TransportMode: "mtls", TLSServerName: vm.NodeName,
	}); err != nil {
		t.Fatal(err)
	}
	var order []string
	applianceClient := &orderedGuestAppliance{
		order: &order, reservations: reservations, releaseFailures: 1,
		guestFailures: 1,
		natStates: []appliance.NATState{{
			VMID: vmID, State: string(isolatedstate.NATObservedEnabled),
			ConntrackMark: 101, DesiredGeneration: 1,
			AppliedGeneration: 1, ObservedGeneration: 1,
		}},
		guests: []appliance.Guest{{
			ID: vmID, NetworkID: networkID, State: "ready",
			DesiredGeneration: 1, AppliedGeneration: 1, ObservedGeneration: 1,
		}},
		relays: []appliance.Relay{{
			ID: relayID, VMID: vmID, State: "ready",
			DesiredGeneration: 1, AppliedGeneration: 1, ObservedGeneration: 1,
		}},
	}
	deps := &isolatedLifecycleDeps{
		state: store, host: orderedGuestHost{}, appliance: applianceClient,
		registry: reg, guests: orderedGuestRuntime{order: &order, reg: reg},
	}
	operationID := "66666666-6666-4666-8666-666666666666"
	arguments := map[string]any{
		"isolated_vm_id": vmID, "delete_storage": true, "operation_id": operationID,
	}
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: arguments}}
	result, err := deleteIsolatedVMHandler(deps)(context.Background(), req)
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("first delete isolated VM = %#v, %v; want interrupted guest failure", result, err)
	}
	arguments["resume_exact"] = true
	result, err = deleteIsolatedVMHandler(deps)(context.Background(), req)
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("second delete isolated VM = %#v, %v; want release failure", result, err)
	}
	result, err = deleteIsolatedVMHandler(deps)(context.Background(), req)
	if err != nil || result == nil || result.IsError {
		t.Fatalf("exact-resume delete isolated VM = %#v, %v", result, err)
	}
	if len(applianceClient.natInputs) != 1 ||
		applianceClient.natInputs[0].ReservationID != "guest-mark" {
		t.Fatalf("NAT reservation = %+v, want guest-mark", applianceClient.natInputs)
	}
	if parentID := applianceClient.natInputs[0].Header.Header.ParentResourceID; parentID != vmID {
		t.Fatalf("NAT parent resource = %q, want guest %q", parentID, vmID)
	}
	if parentGeneration := applianceClient.natInputs[0].Header.Header.ExpectedParentGeneration; parentGeneration != 2 {
		t.Fatalf("NAT parent generation = %d, want guest generation 2", parentGeneration)
	}
	if len(applianceClient.guestInputs) != 1 {
		t.Fatalf("guest retirement calls = %d, want one replay-safe call", len(applianceClient.guestInputs))
	}
	guestHeader := applianceClient.guestInputs[0].Header
	if guestHeader.ExpectedGeneration != 1 || guestHeader.NewGeneration != 2 {
		t.Fatalf("guest appliance generation = %d -> %d, want 1 -> 2 with local VM generation 2",
			guestHeader.ExpectedGeneration, guestHeader.NewGeneration)
	}
	if guestHeader.ExpectedParentGeneration != 1 {
		t.Fatalf("guest parent generation = %d, want network generation 1",
			guestHeader.ExpectedParentGeneration)
	}
	if len(applianceClient.releaseRequests) != 2 {
		t.Fatalf("release requests = %+v", applianceClient.releaseRequests)
	}
	if got := applianceClient.releaseRequests[1].ReservationIDs; !reflect.DeepEqual(
		got, []string{"guest-ip", "guest-mac", "guest-mark"},
	) {
		t.Fatalf("released reservations = %v, want guest resources without relay", got)
	}
	if _, err := store.GetActiveAllocation(context.Background(), "relay", orchestratorID, "20000"); !errors.Is(err, isolatedstate.ErrAllocationNotFound) {
		t.Fatalf("relay mirror remains: %v", err)
	}
	if want := []string{"nat", "remove_relay", "remove_guest", "delete_vm", "release_resources", "release_resources"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("deletion order = %v, want %v", order, want)
	}
}
