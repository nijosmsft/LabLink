package mcptools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/isolated"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/vmconfig"
)

const (
	testOperationID = "11111111-1111-4111-8111-111111111111"
	testResourceID  = "22222222-2222-4222-8222-222222222222"
)

func TestIsolatedLifecycleToolRegistrationAndApprovalSchema(t *testing.T) {
	s := server.NewMCPServer("test", "1.0", server.WithElicitation())
	RegisterIsolatedLifecycleTools(s, &isolatedLifecycleDeps{})
	tools := s.ListTools()
	expected := []string{
		"create_isolated_orchestrator", "list_isolated_orchestrators",
		"get_isolated_orchestrator", "reconcile_isolated_orchestrator",
		"delete_isolated_orchestrator", "add_isolated_network",
		"remove_isolated_network", "create_isolated_relay",
		"remove_isolated_relay", "list_isolated_relays",
		"get_isolated_relay_stats", "rebind_isolated_relays",
		"validate_isolated_relay", "adopt_isolated_relay",
		"create_isolated_vm", "delete_isolated_vm", "list_isolated_vms",
		"get_isolated_vm", "repair_isolated_vm", "rename_isolated_display_name",
		"enable_isolated_vm_nat", "disable_isolated_vm_nat",
		"get_isolated_vm_nat", "list_isolated_vm_nat",
		"reconcile_isolated_vm_nat",
	}
	if len(tools) != len(expected) {
		t.Fatalf("registered %d tools, want %d", len(tools), len(expected))
	}
	for _, name := range expected {
		if tools[name] == nil {
			t.Errorf("tool %q was not registered", name)
		}
	}
	for _, name := range []string{"create_isolated_orchestrator", "delete_isolated_orchestrator"} {
		if _, ok := tools[name].Tool.InputSchema.Properties["approved_plan_revision"]; !ok {
			t.Errorf("%s must expose approved_plan_revision", name)
		}
	}
	for _, name := range []string{
		"add_isolated_network", "remove_isolated_network",
		"create_isolated_relay", "remove_isolated_relay",
		"rebind_isolated_relays", "adopt_isolated_relay",
		"create_isolated_vm", "delete_isolated_vm", "repair_isolated_vm",
		"rename_isolated_display_name",
		"enable_isolated_vm_nat", "disable_isolated_vm_nat",
		"reconcile_isolated_vm_nat",
	} {
		if _, ok := tools[name].Tool.InputSchema.Properties["approved_plan_revision"]; ok {
			t.Errorf("%s must not request approval", name)
		}
	}
	createRelay := tools["create_isolated_relay"].Tool.InputSchema
	if _, ok := createRelay.Properties["target_port"]; ok {
		t.Fatal("relay target_port must not be caller-controlled")
	}
}

func TestApproveRevisionRequiredExactAndConsumedOnce(t *testing.T) {
	store, err := isolatedstate.Open(t.TempDir() + `\isolated.db`)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_, err = store.BeginOperation(context.Background(), isolatedstate.BeginOperationRequest{
		ID: testOperationID, Kind: "create_isolated_orchestrator",
		ResourceType: "orchestrator", ResourceID: testResourceID,
		CanonicalInputs: map[string]any{"profile": "isolated"},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := isolated.RevisionedPlan{
		Kind: "create_isolated_orchestrator", OperationID: testOperationID,
		ResourceID: testResourceID, SemanticHash: strings.Repeat("a", 64),
		PlanHash: strings.Repeat("b", 64), Revision: "r1-" + strings.Repeat("b", 16),
	}
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{
		Arguments: map[string]any{},
	}}
	approved, result, err := approveRevision(
		context.Background(), nil, store, req, testOperationID,
		"create_isolated_orchestrator", plan, "approve", "")
	if err != nil || approved || result == nil || result.IsError {
		t.Fatalf("missing approval = (%v, %#v, %v)", approved, result, err)
	}

	req.Params.Arguments = map[string]any{"approved_plan_revision": "wrong"}
	if _, _, err := approveRevision(
		context.Background(), nil, store, req, testOperationID,
		"create_isolated_orchestrator", plan, "approve", ""); err == nil {
		t.Fatal("wrong revision was accepted")
	}

	req.Params.Arguments = map[string]any{"approved_plan_revision": plan.Revision}
	approved, _, err = approveRevision(
		context.Background(), nil, store, req, testOperationID,
		"create_isolated_orchestrator", plan, "approve", "")
	if err != nil || !approved {
		t.Fatalf("exact approval = (%v, %v)", approved, err)
	}
	if _, _, err := approveRevision(
		context.Background(), nil, store, req, testOperationID,
		"create_isolated_orchestrator", plan, "approve", ""); err == nil {
		t.Fatal("consumed approval was reusable")
	}
}

func TestDurableWorkflowResumeSkipsSucceededPhaseAndReportsProgress(t *testing.T) {
	store, err := isolatedstate.Open(t.TempDir() + `\isolated.db`)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	progress := NewMCPProgressState(time.Minute, "resolve", "starting")
	workflow, err := beginIsolatedWorkflow(context.Background(), store, progress,
		isolatedstate.BeginOperationRequest{
			ID: testOperationID, Kind: "test", ResourceType: "orchestrator",
			ResourceID: testResourceID, CanonicalInputs: map[string]any{"x": 1},
		})
	if err != nil {
		t.Fatal(err)
	}
	runs := 0
	run := func() (any, error) {
		runs++
		return map[string]any{"run": runs}, nil
	}
	if err := workflow.phase(context.Background(), 0, "preflight", "checking exact resources", run); err != nil {
		t.Fatal(err)
	}
	replayed, err := beginIsolatedWorkflow(context.Background(), store, progress,
		isolatedstate.BeginOperationRequest{
			ID: testOperationID, Kind: "test", ResourceType: "orchestrator",
			ResourceID: testResourceID, CanonicalInputs: map[string]any{"x": 1},
			ResumeExact: true,
		})
	if err != nil {
		t.Fatal(err)
	}
	if err := replayed.phase(context.Background(), 0, "preflight", "checking exact resources", run); err != nil {
		t.Fatal(err)
	}
	if runs != 1 {
		t.Fatalf("phase executed %d times, want one", runs)
	}
	_, _, message := progress.snapshot()
	if !strings.Contains(message, "phase=preflight") ||
		!strings.Contains(message, "checking exact resources") {
		t.Fatalf("unexpected progress detail %q", message)
	}
}

func TestDurableWorkflowPreservesPartialFailureDiagnostics(t *testing.T) {
	store, err := isolatedstate.Open(t.TempDir() + `\isolated.db`)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	workflow, err := beginIsolatedWorkflow(context.Background(), store, nil,
		isolatedstate.BeginOperationRequest{
			ID: testOperationID, Kind: "test", ResourceType: "network",
			ResourceID: testResourceID, CanonicalInputs: map[string]any{"x": 1},
		})
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("remote result uncertain")
	if err := workflow.phase(context.Background(), 2, "create_private_switch", "creating", func() (any, error) {
		return map[string]any{"switch_may_exist": true}, want
	}); !errors.Is(err, want) {
		t.Fatalf("phase error = %v", err)
	}
	operation, err := store.GetOperation(context.Background(), testOperationID)
	if err != nil {
		t.Fatal(err)
	}
	if operation.Status != isolatedstate.OperationPaused ||
		operation.CurrentPhase != "create_private_switch" ||
		operation.ErrorText == nil ||
		!strings.Contains(*operation.ErrorText, want.Error()) {
		t.Fatalf("partial failure was not preserved: %#v", operation)
	}
}

type isolatedDryRunHost struct {
	preflightCalls int
}

func (h *isolatedDryRunHost) PhysicalIdentity(context.Context, Target) (hyperv.IsolatedPhysicalHostObservation, error) {
	return hyperv.IsolatedPhysicalHostObservation{
		PhysicalHostID:  strings.Repeat("a", 64),
		HyperVAvailable: true,
	}, nil
}

func (h *isolatedDryRunHost) Discover(context.Context, Target, string, string) (hyperv.IsolatedHostDiscovery, error) {
	return hyperv.IsolatedHostDiscovery{}, nil
}

func (h *isolatedDryRunHost) AcquireFence(context.Context, Target, isolated.HostCreateFenceRequest) (isolated.HostFenceLease, error) {
	return isolated.HostFenceLease{}, errors.New("dry run acquired a fence")
}

func (h *isolatedDryRunHost) ReleaseFence(context.Context, Target, isolated.HostFenceLease) {}

func (h *isolatedDryRunHost) Preflight(
	_ context.Context,
	_ Target,
	_ isolated.ResourcePreflightInput,
	_ vmconfig.Profile,
) (isolated.ResourcePreflightResult, error) {
	h.preflightCalls++
	return isolated.ResourcePreflightResult{
		Allowed: true, EffectivePrivateAdapterSlots: 15, AvailableSwitchSlots: 16,
	}, nil
}

func (h *isolatedDryRunHost) ClaimOrchestrator(context.Context, Target, isolatedstate.Orchestrator, isolated.HostFenceLease) (hyperv.IsolatedVMObservation, error) {
	return hyperv.IsolatedVMObservation{}, errors.New("dry run claimed a VM")
}

func (h *isolatedDryRunHost) CreateSwitch(context.Context, Target, hyperv.CreateIsolatedPrivateSwitchParams) (hyperv.IsolatedSwitchMutationResult, error) {
	return hyperv.IsolatedSwitchMutationResult{}, errors.New("dry run created a switch")
}

func (h *isolatedDryRunHost) AttachNIC(context.Context, Target, hyperv.AttachIsolatedNICParams) (hyperv.IsolatedAdapterMutationResult, error) {
	return hyperv.IsolatedAdapterMutationResult{}, errors.New("dry run attached a NIC")
}

func (h *isolatedDryRunHost) RemoveNIC(context.Context, Target, hyperv.RemoveIsolatedNICParams) (hyperv.IsolatedAdapterMutationResult, error) {
	return hyperv.IsolatedAdapterMutationResult{}, errors.New("dry run removed a NIC")
}

func (h *isolatedDryRunHost) DeleteSwitch(context.Context, Target, hyperv.DeleteIsolatedPrivateSwitchParams) (hyperv.IsolatedSwitchMutationResult, error) {
	return hyperv.IsolatedSwitchMutationResult{}, errors.New("dry run deleted a switch")
}

func TestCreateIsolatedOrchestratorDryRunPreflightsWithoutMutationOrApproval(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "vm-defaults.json")
	if err := os.WriteFile(configPath, []byte(`{
  "default_linux_profile":"ubuntu",
  "default_isolated_orchestrator_profile":"isolated",
  "profiles":{
    "ubuntu":{
      "guest_os":"linux","target":"localhost",
      "distribution":"ubuntu","release":"24.04","architecture":"amd64",
      "vswitch":"main-switch","vm_root":"C:\\VMs",
      "image_cache_root":"C:\\Images","memory_mb":4096,"cpu_count":2,
      "disk_size_gb":64
    }
  },
  "isolated_orchestrator_profiles":{"isolated":{"linux_profile":"ubuntu"}}
}`), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := isolatedstate.Open(filepath.Join(root, "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host := &isolatedDryRunHost{}
	deps := &isolatedLifecycleDeps{
		state: store, host: host, registry: registry.Load(filepath.Join(root, "nodes.json")),
		defaults: vmconfig.Load(configPath), serverVersion: "v1.0.0",
	}
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{
		"target": "localhost", "dry_run": true,
	}}}
	result, err := createIsolatedOrchestratorHandler(deps)(context.Background(), req)
	if err != nil || result == nil || result.IsError {
		t.Fatalf("dry run = %#v, %v", result, err)
	}
	if host.preflightCalls != 1 {
		t.Fatalf("preflight calls = %d, want one", host.preflightCalls)
	}
	if !strings.Contains(toolResultText(result), `"approval_required_if_created": true`) {
		t.Fatalf("dry-run plan missing approval annotation: %s", toolResultText(result))
	}
}
