package mcptools

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

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
	order        *[]string
	reservations []appliance.Reservation
}

func (a *orderedGuestAppliance) GetApplianceState(context.Context, string) (appliance.DesiredSnapshot, error) {
	return appliance.DesiredSnapshot{Reservations: append([]appliance.Reservation(nil), a.reservations...)}, nil
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
	return isolated.NATMutationResult{NAT: appliance.NATState{
		VMID: input.Header.Header.ResourceID, State: input.DesiredState,
		ConntrackMark: int64(input.ConntrackMark), AppliedGeneration: 1, ObservedGeneration: 1,
	}}, nil
}

func (a *orderedGuestAppliance) InspectApplianceState(context.Context, string) (isolated.ApplianceSnapshot, error) {
	return isolated.ApplianceSnapshot{MainIPv4: "10.0.0.10"}, nil
}

type orderedGuestHost struct {
	isolatedHost
}

func (orderedGuestHost) AcquireFence(context.Context, Target, isolated.HostCreateFenceRequest) (isolated.HostFenceLease, error) {
	return isolated.HostFenceLease{
		LeaseID:     "55555555-5555-4555-8555-555555555555",
		LeaseSecret: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Fence:       9,
	}, nil
}

func (orderedGuestHost) ReleaseFence(context.Context, Target, isolated.HostFenceLease) {}

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

func (orderedGuestRuntime) Delete(context.Context, isolatedstate.IsolatedVM, isolatedstate.Orchestrator, Target, isolated.HostFenceLease, string, bool) (hyperv.IsolatedVMMutationResult, error) {
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
