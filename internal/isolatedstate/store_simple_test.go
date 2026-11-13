package isolatedstate

import (
	"context"
	"path/filepath"
	"testing"
)

func TestSimpleInventoryRoundTrip(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	now := UnixSeconds(1)
	orchestrator := Orchestrator{
		ID: "orch-1", DisplayName: "orchestrator",
		PhysicalHostID: "host-1", HostNode: "host",
		HyperVName: "orch-vm", NodeName: "orch-node",
		ProfileName: "profile", MainVSwitch: "main",
		AgentPort: 9091, ApplianceSchema: 5,
		LifecycleState: OrchestratorReady, HealthState: "ready",
		MaxNetworks: 16, MaxVMs: 100,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := store.PutOrchestrator(ctx, orchestrator); err != nil {
		t.Fatal(err)
	}
	network := PrivateNetwork{
		ID: "network-1", OrchestratorID: orchestrator.ID,
		DisplayName: "network", HyperVSwitchName: "private-switch",
		SubnetIndex: 0, CIDR: "192.168.240.0/26",
		GatewayIPv4:     "192.168.240.1",
		OrchestratorMAC: "02155D000001",
		DNSServersJSON:  `["10.0.0.53"]`,
		LifecycleState:  NetworkReady, CreatedAt: now, UpdatedAt: now,
	}
	if err := store.PutNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}
	vm := IsolatedVM{
		ID: "vm-1", OrchestratorID: orchestrator.ID,
		NetworkID: network.ID, DisplayName: "vm",
		HyperVName: "vm", NodeName: "vm-node",
		GuestOS: GuestLinux, ProfileName: "linux",
		IPv4: "192.168.240.10", MAC: "02155D000002",
		PrefixLength: 26, GatewayIPv4: network.GatewayIPv4,
		DNSServersJSON: network.DNSServersJSON,
		StorageRoot:    `E:\VM`, VMPath: `E:\VM\vm`,
		VHDPath:        `E:\VM\vm\vm.vhdx`,
		LifecycleState: VMReady, CreatedAt: now, UpdatedAt: now,
	}
	if err := store.PutVM(ctx, vm); err != nil {
		t.Fatal(err)
	}
	if err := store.PutRelay(ctx, RelayAllocation{
		ID: "relay-1", VMID: vm.ID, OrchestratorID: orchestrator.ID,
		ListenPort: 20000, TargetIPv4: vm.IPv4, TargetPort: 9091,
		LifecycleState: RelayReady, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutNAT(ctx, NATAllocation{
		VMID: vm.ID, OrchestratorID: orchestrator.ID,
		State: NATEnabled, ConntrackMark: 1, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetVM(ctx, vm.ID)
	if err != nil || got.HyperVName != vm.HyperVName {
		t.Fatalf("VM round trip = %+v, %v", got, err)
	}
	nat, err := store.GetNAT(ctx, vm.ID)
	if err != nil || nat.State != NATEnabled || nat.ConntrackMark != 1 {
		t.Fatalf("NAT round trip = %+v, %v", nat, err)
	}
}

func TestOldSchemaIsRejectedWithoutMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "isolated.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(
		`UPDATE schema_meta SET value='2' WHERE key='schema_version'`,
	); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	if _, err := Open(path); err == nil {
		t.Fatal("old isolated schema was accepted")
	}
}
