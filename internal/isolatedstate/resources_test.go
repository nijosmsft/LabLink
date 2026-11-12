package isolatedstate

import (
	"context"
	"testing"
)

func TestResourceStoreRoundTripAndNonemptyCount(t *testing.T) {
	store, err := Open(t.TempDir() + `\isolated.db`)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	orchestrator := Orchestrator{
		ID:          "11111111-1111-4111-8111-111111111111",
		DisplayName: "orchestrator", PhysicalHostID: "host-id",
		HostNode: "host", HyperVName: "orch", NodeName: "orch-node",
		ProfileName: "isolated", MainVSwitch: "main", AgentPort: 9091,
		LifecycleState: OrchestratorReady, HealthState: "ready",
		MaxNetworks: 16, MaxVMs: 100,
	}
	if err := store.PutOrchestrator(ctx, orchestrator); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetOrchestrator(ctx, orchestrator.ID)
	if err != nil || got.NodeName != orchestrator.NodeName {
		t.Fatalf("GetOrchestrator = %#v, %v", got, err)
	}
	network := PrivateNetwork{
		ID:             "22222222-2222-4222-8222-222222222222",
		OrchestratorID: orchestrator.ID, DisplayName: "network",
		HyperVSwitchName: "switch", SubnetIndex: 0,
		CIDR: "192.168.240.0/26", GatewayIPv4: "192.168.240.1",
		OrchestratorMAC: "00155D010203", DNSServersJSON: "[]",
		DesiredGeneration: 1, LifecycleState: NetworkReady,
	}
	if err := store.PutNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}
	count, err := store.CountActiveVMs(ctx, network.ID)
	if err != nil || count != 0 {
		t.Fatalf("empty network count = %d, %v", count, err)
	}
	_, err = store.ExecContext(ctx, `
		INSERT INTO isolated_vms (
			id, orchestrator_id, network_id, display_name, hyperv_name,
			incarnation, node_name, guest_os, profile_name, ipv4, mac,
			prefix_length, gateway_ipv4, dns_servers_json, storage_root,
			vm_path, vhd_path, desired_generation, lifecycle_state,
			created_at_unix, updated_at_unix
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"33333333-3333-4333-8333-333333333333", orchestrator.ID, network.ID,
		"vm", "vm", 1, "vm-node", GuestLinux, "linux",
		"192.168.240.10", "00155D010204", 26, "192.168.240.1", "[]",
		`C:\VMs`, `C:\VMs\vm`, `C:\VMs\vm\vm.vhdx`, 1, VMReady, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	count, err = store.CountActiveVMs(ctx, network.ID)
	if err != nil || count != 1 {
		t.Fatalf("nonempty network count = %d, %v", count, err)
	}
}

func TestRelayStoreEnforcesManagedTargetPort(t *testing.T) {
	store, err := Open(t.TempDir() + `\isolated.db`)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	err = store.PutRelay(context.Background(), RelayAllocation{
		ID:             "44444444-4444-4444-8444-444444444444",
		VMID:           "33333333-3333-4333-8333-333333333333",
		OrchestratorID: "11111111-1111-4111-8111-111111111111",
		ListenPort:     20000, TargetIPv4: "192.168.240.10",
		TargetPort: 22, LifecycleState: RelayAllocated,
	})
	if err == nil {
		t.Fatal("relay target port other than 9091 was accepted")
	}
}
