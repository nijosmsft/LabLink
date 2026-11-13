package isolated

import (
	"strings"
	"testing"

	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
)

const (
	natOrchestratorID = "11111111-1111-4111-8111-111111111111"
	natNetworkID      = "22222222-2222-4222-8222-222222222222"
	natVMID           = "33333333-3333-4333-8333-333333333333"
)

func validNATFixture() (
	isolatedstate.Orchestrator,
	isolatedstate.PrivateNetwork,
	isolatedstate.IsolatedVM,
	isolatedstate.NATAllocation,
	ApplianceSnapshot,
) {
	orchestrator := isolatedstate.Orchestrator{
		ID: natOrchestratorID, PhysicalHostID: strings.Repeat("a", 64),
		DesiredGeneration: 4, HostFence: 7,
		LifecycleState: isolatedstate.OrchestratorReady,
	}
	network := isolatedstate.PrivateNetwork{
		ID: natNetworkID, OrchestratorID: natOrchestratorID,
		DNSServersJSON: `["10.0.0.1","10.0.0.2"]`,
		LifecycleState: isolatedstate.NetworkReady,
	}
	vm := isolatedstate.IsolatedVM{
		ID: natVMID, OrchestratorID: natOrchestratorID,
		NetworkID: natNetworkID, IPv4: "192.168.240.10",
		MAC: "02-15-5D-AA-BB-CC", DesiredGeneration: 4,
		DNSServersJSON: `["10.0.0.1", "10.0.0.2"]`,
		LifecycleState: isolatedstate.VMReady,
	}
	local := isolatedstate.NATAllocation{
		VMID: natVMID, OrchestratorID: natOrchestratorID,
		DesiredState:  isolatedstate.NATDesiredDisabled,
		ObservedState: isolatedstate.NATObservedDisabled,
		ConntrackMark: 101, DesiredGeneration: 2,
		AppliedGeneration: 2, ObservedGeneration: 2,
	}
	mark := int64(101)
	snapshot := ApplianceSnapshot{
		Fence: FenceState{
			PhysicalHostID: orchestrator.PhysicalHostID,
			HostFence:      7, ParentGeneration: 4,
		},
		Desired: appliance.DesiredSnapshot{
			Guests: []appliance.Guest{{
				ID: natVMID, NetworkID: natNetworkID,
				IPv4: vm.IPv4, MAC: "02155DAABBCC",
				DesiredGeneration: 4,
			}},
			Reservations: []appliance.Reservation{{
				ID: "guest-reservation", ResourceKind: "conntrack_mark",
				ResourceID: natVMID, NetworkID: natNetworkID,
				ConntrackMark: &mark,
			}},
			NAT: []appliance.NATState{{
				VMID: natVMID, State: "disabled", ConntrackMark: mark,
				DesiredGeneration: 2, AppliedGeneration: 2,
				ObservedGeneration: 2, ParentGeneration: 4,
			}},
		},
	}
	return orchestrator, network, vm, local, snapshot
}

func TestValidateNATIdentityRequiresExactFenceGuestAndReservation(t *testing.T) {
	orchestrator, network, vm, local, snapshot := validNATFixture()
	validated, err := ValidateNATIdentity(
		orchestrator, network, vm, &local, snapshot, NATValidateMutation,
	)
	if err != nil {
		t.Fatal(err)
	}
	if validated.Reservation.ID != "guest-reservation" ||
		validated.Live.ConntrackMark != local.ConntrackMark {
		t.Fatalf("validated NAT = %+v", validated)
	}

	snapshot.Fence.HostFence++
	if _, err := ValidateNATIdentity(
		orchestrator, network, vm, &local, snapshot, NATValidateMutation,
	); ErrorCode(err) != "FENCE_REJECTED" {
		t.Fatalf("fence mismatch error = %v", err)
	}
}

func TestValidateNATIdentityAllowsHostOnlyGuestRepairGeneration(t *testing.T) {
	orchestrator, network, vm, local, snapshot := validNATFixture()
	vm.DesiredGeneration++
	if _, err := ValidateNATIdentity(
		orchestrator, network, vm, &local, snapshot, NATValidateMutation,
	); err != nil {
		t.Fatalf("host-only repair generation should not stale appliance allocation: %v", err)
	}
	snapshot.Desired.Guests[0].DesiredGeneration = uint64(vm.DesiredGeneration + 1)
	if _, err := ValidateNATIdentity(
		orchestrator, network, vm, &local, snapshot, NATValidateMutation,
	); ErrorCode(err) != "GENERATION_CONFLICT" {
		t.Fatalf("newer appliance guest generation error = %v", err)
	}
}

func TestValidateNATIdentityRejectsForeignAndStaleApplianceState(t *testing.T) {
	orchestrator, network, vm, local, snapshot := validNATFixture()
	snapshot.Desired.Guests[0].NetworkID = "44444444-4444-4444-8444-444444444444"
	if _, err := ValidateNATIdentity(
		orchestrator, network, vm, &local, snapshot, NATValidateMutation,
	); ErrorCode(err) != "FOREIGN_APPLIANCE_STATE" {
		t.Fatalf("foreign guest error = %v", err)
	}

	_, _, _, local, snapshot = validNATFixture()
	snapshot.Desired.NAT[0].DesiredGeneration = 3
	snapshot.Desired.NAT[0].AppliedGeneration = 3
	snapshot.Desired.NAT[0].ObservedGeneration = 3
	if _, err := ValidateNATIdentity(
		orchestrator, network, vm, &local, snapshot, NATValidateMutation,
	); ErrorCode(err) != "GENERATION_CONFLICT" {
		t.Fatalf("strict stale generation error = %v", err)
	}
	if _, err := ValidateNATIdentity(
		orchestrator, network, vm, &local, snapshot, NATValidateImport,
	); err != nil {
		t.Fatalf("newer appliance truth should be importable: %v", err)
	}
}

func TestMergeApplianceNATNormalizesDrainAndRestartState(t *testing.T) {
	started := int64(99)
	draining, err := MergeApplianceNAT(nil, natOrchestratorID, appliance.NATState{
		VMID: natVMID, State: "draining", ConntrackMark: 101,
		DesiredGeneration: 3, AppliedGeneration: 3, ObservedGeneration: 3,
		DrainStartedUnix: &started,
	})
	if err != nil {
		t.Fatal(err)
	}
	if draining.DesiredState != isolatedstate.NATDesiredDisabled ||
		draining.ObservedState != isolatedstate.NATObservedDraining ||
		draining.DrainStartedAt == nil {
		t.Fatalf("draining import = %+v", draining)
	}

	disabled, err := MergeApplianceNAT(&draining, natOrchestratorID, appliance.NATState{
		VMID: natVMID, State: "disabled", ConntrackMark: 101,
		DesiredGeneration: 3, AppliedGeneration: 3, ObservedGeneration: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if disabled.ObservedState != isolatedstate.NATObservedDisabled ||
		disabled.DrainStartedAt != nil {
		t.Fatalf("restart-normalized disabled import = %+v", disabled)
	}
}

func TestBuildNATDNSStatusSurfacesCopiedAndPendingDrift(t *testing.T) {
	_, network, vm, _, _ := validNATFixture()
	status := BuildNATDNSStatus(network, vm, nil)
	if status.CopyDrift {
		t.Fatalf("equivalent DNS JSON reported drift: %+v", status)
	}
	pending := &isolatedstate.GuestPendingUpdate{
		VMID: natVMID, UpdateKind: "dns", DesiredGeneration: 5,
		PayloadJSON: `["10.0.0.3"]`,
	}
	vm.DNSServersJSON = `["10.0.0.9"]`
	status = BuildNATDNSStatus(network, vm, pending)
	if !status.CopyDrift || status.Pending != pending {
		t.Fatalf("DNS drift status = %+v", status)
	}
}
