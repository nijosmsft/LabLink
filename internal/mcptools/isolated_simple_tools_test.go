package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/isolated"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
	internalsec "github.com/nijosmsft/lablink/internal/security"
	"github.com/nijosmsft/lablink/internal/vmconfig"
)

type simpleLinuxCreatorFunc func(context.Context, mcp.CallToolRequest, linuxVMPlan, Target, *MCPProgressState) (*mcp.CallToolResult, error)

func (f simpleLinuxCreatorFunc) Create(
	ctx context.Context, req mcp.CallToolRequest, plan linuxVMPlan,
	target Target, progress *MCPProgressState,
) (*mcp.CallToolResult, error) {
	return f(ctx, req, plan, target, progress)
}

func TestOrchestratorRequiresCompletedLinuxProvisioningBeforeHostLookup(t *testing.T) {
	for _, tt := range []struct {
		name       string
		result     *mcp.CallToolResult
		wantLookup bool
	}{
		{
			name: "image-preparing",
			result: vmResult("Linux image is preparing",
				`{"status":"image_preparing","vm_created":false}`),
		},
		{
			name: "retained-for-diagnosis",
			result: retainedLinuxVMError(linuxVMPlan{}, "",
				errors.New("guest enrollment failed")),
		},
		{
			name:   "provisioned-but-not-registered",
			result: provisionedLinuxVMResult("VM retained off", linuxVMPlan{}),
		},
		{
			name:       "created-and-registered",
			result:     provisionedLinuxVMResult("VM verified", linuxVMPlan{Registered: true}),
			wantLookup: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			agent := &linuxImageMockAgent{failAt: 1, failure: "host lookup reached"}
			addr := startNodeAgent(t, agent)
			reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
			pool := agentclient.NewPool("", internalsec.ClientTransportConfig{
				Mode: internalsec.TransportModeInsecure,
			})
			defer pool.Close()
			store, err := isolatedstate.Open(filepath.Join(t.TempDir(), "isolated.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			deps := &isolatedLifecycleDeps{
				state: store, registry: reg, pool: pool,
				defaults: linuxDefaultsStore(t, `{
  "default_linux_profile":"ubuntu",
  "profiles":{"ubuntu":{
    "guest_os":"linux","target":"node1","image_cache_root":"E:\\Images",
    "distribution":"ubuntu","release":"24.04","architecture":"amd64",
    "vm_root":"E:\\VM","vswitch":"ext","linux_username":"lab",
    "ssh_public_key":"`+linuxTestKey()+`"
  }}
}`),
			}
			calls := 0
			deps.linux = simpleLinuxCreatorFunc(func(
				_ context.Context, _ mcp.CallToolRequest, plan linuxVMPlan,
				_ Target, _ *MCPProgressState,
			) (*mcp.CallToolResult, error) {
				calls++
				if plan.Orchestrator == nil || !plan.RegisterWithLabLink {
					t.Fatal("orchestrator provisioning was not requested")
				}
				return tt.result, nil
			})
			result, err := createSimpleIsolatedOrchestratorHandler(deps)(
				context.Background(), reqNoToken(nil))
			if err != nil || result == nil {
				t.Fatalf("create: result=%+v err=%v", result, err)
			}
			if calls != 1 {
				t.Fatalf("Linux create calls = %d, want 1: %s", calls, toolResultText(result))
			}
			if tt.wantLookup {
				if !result.IsError || len(agent.Scripts()) != 1 ||
					!strings.Contains(toolResultText(result), "host lookup reached") {
					t.Fatalf("verified creation did not reach host lookup: %+v", result)
				}
			} else if result != tt.result || len(agent.Scripts()) != 0 {
				t.Fatalf("incomplete creation was not returned before host lookup: %+v", result)
			}
			records, err := store.ListOrchestrators(context.Background(), "")
			if err != nil || len(records) != 0 {
				t.Fatalf("unexpected orchestrator persistence: records=%+v err=%v", records, err)
			}
		})
	}
}

func TestOrchestratorDryRunInheritsOrdinaryLinuxProfileTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vm-defaults.json")
	if err := os.WriteFile(path, []byte(`{
  "default_linux_profile":"ubuntu",
  "linux_target_defaults":{"node2":"ubuntu2"},
  "profiles":{
    "ubuntu":{"guest_os":"linux","target":"node1","distribution":"ubuntu","release":"24.04","architecture":"amd64","vswitch":"main"},
    "ubuntu2":{"guest_os":"linux","target":"node2","distribution":"ubuntu","release":"24.04","architecture":"amd64","vswitch":"main2"}
  }
}`), 0600); err != nil {
		t.Fatal(err)
	}
	deps := &isolatedLifecycleDeps{
		defaults: vmconfig.Load(path),
		registry: newRebootTestRegistry(t, map[string]string{
			"node1": "127.0.0.1:1", "node2": "127.0.0.1:2",
		}),
	}
	for _, tt := range []struct {
		name, profile, target, mainSwitch, wantTarget, wantProfile, wantSwitch string
	}{
		{"inherited-target", "ubuntu", "", "", "node1", "ubuntu", "main"},
		{"global-default", "", "", "", "node1", "ubuntu", "main"},
		{"explicit-target", "ubuntu", "node2", "", "node2", "ubuntu", "main"},
		{"target-default", "", "node2", "", "node2", "ubuntu2", "main2"},
		{"switch-override", "ubuntu", "", "override", "node1", "ubuntu", "override"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := reqNoToken(map[string]any{
				"profile": tt.profile, "target": tt.target,
				"main_vswitch": tt.mainSwitch, "dry_run": true,
			})
			result, err := createSimpleIsolatedOrchestratorHandler(deps)(context.Background(), req)
			if err != nil || result == nil || result.IsError {
				t.Fatalf("dry run failed: %+v, %v", result, err)
			}
			var plan struct {
				Target       string `json:"target"`
				Profile      string `json:"profile"`
				LinuxProfile string `json:"linux_profile"`
				MainVSwitch  string `json:"main_vswitch"`
			}
			if err := json.Unmarshal([]byte(jsonExtract(result.Content[0].(mcp.TextContent).Text)), &plan); err != nil {
				t.Fatal(err)
			}
			if plan.Target != tt.wantTarget || plan.Profile != tt.wantProfile ||
				plan.LinuxProfile != tt.wantProfile || plan.MainVSwitch != tt.wantSwitch {
				t.Fatalf("unexpected dry run: %+v", plan)
			}
		})
	}
}

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
