package isolatedstate

import (
	"context"
	"errors"
	"testing"
)

func TestNATStoreRoundTripFiltersAndPendingDNS(t *testing.T) {
	store, err := Open(t.TempDir() + `\isolated.db`)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	const (
		orchestratorID = "11111111-1111-4111-8111-111111111111"
		networkID      = "22222222-2222-4222-8222-222222222222"
		vmID           = "33333333-3333-4333-8333-333333333333"
	)
	if _, err := store.db.ExecContext(ctx, `
		INSERT INTO orchestrators (
			id, display_name, physical_host_id, host_node, hyperv_name,
			node_name, profile_name, main_vswitch, lifecycle_state,
			created_at_unix, updated_at_unix
		) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		orchestratorID, "orch", "host", "host-node", "orch-vm",
		"orch-node", "profile", "main", OrchestratorReady, 1, 1,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `
		INSERT INTO private_networks (
			id, orchestrator_id, display_name, hyperv_switch_name, subnet_index,
			cidr, gateway_ipv4, orchestrator_mac, dns_servers_json,
			desired_generation, lifecycle_state, created_at_unix, updated_at_unix
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		networkID, orchestratorID, "network", "private-switch", 0,
		"192.168.240.0/26", "192.168.240.1", "02155D000001", `["10.0.0.1"]`,
		1, NetworkReady, 1, 1,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `
		INSERT INTO isolated_vms (
			id, orchestrator_id, network_id, display_name, hyperv_name,
			node_name, guest_os, profile_name, ipv4, mac, gateway_ipv4,
			dns_servers_json, storage_root, vm_path, vhd_path,
			desired_generation, lifecycle_state, created_at_unix, updated_at_unix
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		vmID, orchestratorID, networkID, "guest", "guest-vm",
		"guest-node", GuestLinux, "linux", "192.168.240.10", "02155D000002",
		"192.168.240.1", `["10.0.0.1"]`, `C:\VMs`, `C:\VMs\guest`,
		`C:\VMs\guest\disk.vhdx`, 1, VMReady, 1, 1,
	); err != nil {
		t.Fatal(err)
	}
	started := UnixSeconds(20)
	want := NATAllocation{
		VMID: vmID, OrchestratorID: orchestratorID,
		DesiredState:  NATDesiredDisabled,
		ObservedState: NATObservedDraining,
		ConntrackMark: 101, DesiredGeneration: 3,
		AppliedGeneration: 3, ObservedGeneration: 3,
		DrainStartedAt: &started, UpdatedAt: 21,
	}
	if err := store.PutNAT(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetNAT(ctx, vmID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ObservedState != NATObservedDraining ||
		got.DrainStartedAt == nil || *got.DrainStartedAt != started {
		t.Fatalf("NAT round trip = %+v", got)
	}
	foreign := want
	foreign.ConntrackMark++
	if err := store.PutNAT(ctx, foreign); err == nil {
		t.Fatal("conntrack-mark identity change was accepted")
	}
	values, err := store.ListNAT(ctx, orchestratorID, networkID, "draining")
	if err != nil || len(values) != 1 || values[0].VMID != vmID {
		t.Fatalf("NAT filtered list = %+v, %v", values, err)
	}
	if _, err := store.db.ExecContext(ctx, `
		INSERT INTO guest_pending_updates (
			vm_id, update_kind, desired_generation, payload_json, created_at_unix
		) VALUES (?,?,?,?,?)`, vmID, "dns", 4, `["10.0.0.2"]`, 22); err != nil {
		t.Fatal(err)
	}
	pending, err := store.GetGuestPendingUpdate(ctx, vmID, "dns")
	if err != nil || pending.DesiredGeneration != 4 {
		t.Fatalf("pending DNS = %+v, %v", pending, err)
	}
	if _, err := store.GetGuestPendingUpdate(ctx, vmID, "routes"); !errors.Is(err, ErrGuestPendingUpdateNotFound) {
		t.Fatalf("missing pending update error = %v", err)
	}
}
