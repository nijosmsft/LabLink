package mcptools

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/isolated"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
)

func TestSimpleIsolatedToolSurfaceMatchesNormalLifecycle(t *testing.T) {
	s := server.NewMCPServer("test", "1.0")
	RegisterIsolatedLifecycleTools(s, &isolatedLifecycleDeps{})
	tools := s.ListTools()
	expected := []string{
		"create_isolated_orchestrator", "list_isolated_orchestrators",
		"get_isolated_orchestrator", "delete_isolated_orchestrator",
		"add_isolated_network", "remove_isolated_network",
		"create_isolated_vm", "delete_isolated_vm",
		"list_isolated_vms", "get_isolated_vm",
		"rename_isolated_display_name",
		"enable_isolated_vm_nat", "disable_isolated_vm_nat",
		"get_isolated_vm_nat", "list_isolated_vm_nat",
		"list_isolated_relays", "get_isolated_relay_stats",
		"validate_isolated_relay", "rebind_isolated_relays",
	}
	if len(tools) != len(expected) {
		t.Fatalf("registered %d tools, want %d", len(tools), len(expected))
	}
	for _, name := range expected {
		registered := tools[name]
		if registered == nil {
			t.Fatalf("tool %q was not registered", name)
		}
		for _, removed := range []string{
			"expected_generation", "operation_id", "resume_exact",
			"approved_plan_revision",
		} {
			if _, ok := registered.Tool.InputSchema.Properties[removed]; ok {
				t.Errorf("%s exposes removed field %s", name, removed)
			}
		}
	}
	if _, ok := tools["create_isolated_vm"].Tool.InputSchema.Properties["name"]; !ok {
		t.Fatal("create_isolated_vm must use the normal VM name")
	}
	for _, removed := range []string{
		"repair_isolated_vm", "reconcile_isolated_orchestrator",
		"reconcile_isolated_vm_nat", "create_isolated_relay",
		"adopt_isolated_relay", "remove_isolated_relay",
	} {
		if tools[removed] != nil {
			t.Errorf("removed HA-style tool %q is still registered", removed)
		}
	}
}

func TestConfigureStaticAfterPrivateNICReadyRetriesHotPlugRace(t *testing.T) {
	attempts := 0
	snapshot, err := configureStaticAfterPrivateNICReady(
		context.Background(), time.Second, time.Millisecond,
		func() (isolated.ApplianceSnapshot, error) {
			attempts++
			if attempts < 3 {
				return isolated.ApplianceSnapshot{},
					errors.New("no interface has MAC 02155d7dfe8e")
			}
			return isolated.ApplianceSnapshot{Ready: true}, nil
		},
	)
	if err != nil {
		t.Fatalf("configure after hot-plug: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
	if !snapshot.Ready {
		t.Fatal("successful snapshot was not returned")
	}
}

func TestConfigureStaticAfterPrivateNICReadyDoesNotRetryPermanentError(t *testing.T) {
	attempts := 0
	_, err := configureStaticAfterPrivateNICReady(
		context.Background(), time.Second, time.Millisecond,
		func() (isolated.ApplianceSnapshot, error) {
			attempts++
			return isolated.ApplianceSnapshot{}, errors.New("invalid CIDR")
		},
	)
	if err == nil {
		t.Fatal("expected permanent error")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

func TestSimpleWaitProgressStartsHeartbeat(t *testing.T) {
	shrinkHeartbeatInterval(t)
	messages := make(chan string, 1)
	heartbeatDetailNotifierOverride = func(_, _ int64, message string) {
		select {
		case messages <- message:
		default:
		}
	}
	t.Cleanup(func() { heartbeatDetailNotifierOverride = nil })

	progress, stop := simpleWaitProgress(
		context.Background(), reqWithToken(nil))
	progress.Update("enrollment", "waiting for isolated guest agent")
	defer stop()

	select {
	case message := <-messages:
		if message == "" {
			t.Fatal("heartbeat message is empty")
		}
	case <-time.After(time.Second):
		t.Fatal("isolated lifecycle did not emit a progress heartbeat")
	}
}

func TestListSimpleIsolatedRelaysAndNATOmitDeletedVMs(t *testing.T) {
	ctx := context.Background()
	store, err := isolatedstate.Open(filepath.Join(t.TempDir(), "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := isolatedstate.UnixSeconds(1700000000)
	retired := isolatedstate.UnixSeconds(1700000010)
	if err := store.PutOrchestrator(ctx, isolatedstate.Orchestrator{
		ID: "orch-1", DisplayName: "orch", PhysicalHostID: "host-1",
		HostNode: "node1", HyperVName: "orch-vm", NodeName: "orch-node",
		ProfileName: "prof", MainVSwitch: "extswitch", AgentPort: 9091,
		ApplianceSchema: 3, LifecycleState: isolatedstate.OrchestratorReady,
		HealthState: "ready", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutNetwork(ctx, isolatedstate.PrivateNetwork{
		ID: "net-1", OrchestratorID: "orch-1", DisplayName: "net",
		HyperVSwitchName: "sw-1", CIDR: "192.168.240.0/26",
		GatewayIPv4: "192.168.240.1", OrchestratorMAC: "02155D000001",
		DNSServersJSON: "[]", LifecycleState: isolatedstate.NetworkReady,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutVM(ctx, isolatedstate.IsolatedVM{
		ID: "vm-active", OrchestratorID: "orch-1", NetworkID: "net-1",
		DisplayName: "active", HyperVName: "vm-active", NodeName: "vm-active",
		GuestOS: isolatedstate.GuestLinux, ProfileName: "prof",
		IPv4: "192.168.240.10", MAC: "02155D000010", PrefixLength: 26,
		GatewayIPv4: "192.168.240.1", DNSServersJSON: "[]",
		LifecycleState: isolatedstate.VMReady, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutVM(ctx, isolatedstate.IsolatedVM{
		ID: "vm-deleted", OrchestratorID: "orch-1", NetworkID: "net-1",
		DisplayName: "deleted", HyperVName: "vm-deleted", NodeName: "vm-deleted",
		GuestOS: isolatedstate.GuestLinux, ProfileName: "prof",
		IPv4: "192.168.240.11", MAC: "02155D000011", PrefixLength: 26,
		GatewayIPv4: "192.168.240.1", DNSServersJSON: "[]",
		LifecycleState: isolatedstate.VMDeleted, CreatedAt: now, UpdatedAt: retired,
		RetiredAt: &retired,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutRelay(ctx, isolatedstate.RelayAllocation{
		ID: "relay-active", VMID: "vm-active", OrchestratorID: "orch-1",
		ListenPort: 20000, TargetIPv4: "192.168.240.10", TargetPort: 9091,
		LifecycleState: isolatedstate.RelayReady, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutRelay(ctx, isolatedstate.RelayAllocation{
		ID: "relay-removed", VMID: "vm-deleted", OrchestratorID: "orch-1",
		ListenPort: 20001, TargetIPv4: "192.168.240.11", TargetPort: 9091,
		LifecycleState: isolatedstate.RelayRemoved, CreatedAt: now, UpdatedAt: retired,
		RetiredAt: &retired,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutNAT(ctx, isolatedstate.NATAllocation{
		VMID: "vm-active", OrchestratorID: "orch-1",
		State: isolatedstate.NATEnabled, ConntrackMark: 1, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutNAT(ctx, isolatedstate.NATAllocation{
		VMID: "vm-deleted", OrchestratorID: "orch-1",
		State: isolatedstate.NATDisabled, ConntrackMark: 2, UpdatedAt: retired,
	}); err != nil {
		t.Fatal(err)
	}

	deps := &isolatedLifecycleDeps{state: store}
	relayRes, err := listSimpleIsolatedRelaysHandler(deps)(ctx, mcp.CallToolRequest{})
	if err != nil || relayRes.IsError {
		t.Fatalf("list relays failed: err=%v res=%+v", err, relayRes)
	}
	relayText := relayRes.Content[0].(mcp.TextContent).Text
	if !strings.Contains(relayText, "relay-active") || strings.Contains(relayText, "relay-removed") {
		t.Fatalf("unexpected relay list output: %s", relayText)
	}

	natRes, err := listSimpleIsolatedNATHandler(deps)(ctx, mcp.CallToolRequest{})
	if err != nil || natRes.IsError {
		t.Fatalf("list NAT failed: err=%v res=%+v", err, natRes)
	}
	natText := natRes.Content[0].(mcp.TextContent).Text
	if !strings.Contains(natText, "vm-active") || strings.Contains(natText, "vm-deleted") {
		t.Fatalf("unexpected NAT list output: %s", natText)
	}
}
