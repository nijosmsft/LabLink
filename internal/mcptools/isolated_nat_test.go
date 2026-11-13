package mcptools

import (
	"context"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/isolated"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
)

func TestRegisterIsolatedNATExposesExactApprovalFreeSchemas(t *testing.T) {
	s := server.NewMCPServer("test", "1.0")
	RegisterIsolatedNAT(s, &isolatedLifecycleDeps{})
	tools := s.ListTools()
	expected := []string{
		"enable_isolated_vm_nat", "disable_isolated_vm_nat",
		"get_isolated_vm_nat", "list_isolated_vm_nat",
		"reconcile_isolated_vm_nat",
	}
	if len(tools) != len(expected) {
		t.Fatalf("registered %d NAT tools, want %d", len(tools), len(expected))
	}
	for _, name := range expected {
		tool := tools[name]
		if tool == nil {
			t.Fatalf("tool %q was not registered", name)
		}
		if _, ok := tool.Tool.InputSchema.Properties["approved_plan_revision"]; ok {
			t.Errorf("%s must not elicit approval", name)
		}
	}
	for _, name := range []string{
		"enable_isolated_vm_nat",
		"disable_isolated_vm_nat",
		"reconcile_isolated_vm_nat",
	} {
		schema := tools[name].Tool.InputSchema
		for _, field := range []string{
			"isolated_vm_id", "operation_id", "resume_exact",
			"expected_generation",
		} {
			if _, ok := schema.Properties[field]; !ok {
				t.Errorf("%s missing %s", name, field)
			}
		}
	}
	if _, ok := tools["get_isolated_vm_nat"].Tool.InputSchema.Properties["live"]; !ok {
		t.Fatal("get_isolated_vm_nat missing live")
	}
	for _, field := range []string{"orchestrator_id", "network_id", "state", "live"} {
		if _, ok := tools["list_isolated_vm_nat"].Tool.InputSchema.Properties[field]; !ok {
			t.Errorf("list_isolated_vm_nat missing %s", field)
		}
	}
}

type natWaitAppliance struct {
	isolatedNATAppliance
	states []appliance.NATState
}

func (a *natWaitAppliance) ReleaseAuthority(
	context.Context,
	string,
	isolated.MutationEnvelope,
) error {
	return nil
}

func (f *natWaitAppliance) ListNATState(
	context.Context,
	string, string, string, string,
	uint32,
	string,
) (isolated.NATList, error) {
	return isolated.NATList{States: append([]appliance.NATState(nil), f.states...)}, nil
}

func TestWaitForNATAcceptsDrainingWithoutWaitingForConntrackZero(t *testing.T) {
	client := &natWaitAppliance{states: []appliance.NATState{{
		VMID:  "33333333-3333-4333-8333-333333333333",
		State: "draining", ConntrackMark: 101,
		DesiredGeneration: 3, AppliedGeneration: 3, ObservedGeneration: 3,
	}}}
	value, err := waitForNAT(
		context.Background(), client,
		"11111111-1111-4111-8111-111111111111",
		"22222222-2222-4222-8222-222222222222",
		"33333333-3333-4333-8333-333333333333",
		101, 3, isolatedstate.NATDesiredDisabled,
	)
	if err != nil {
		t.Fatal(err)
	}
	if value.State != "draining" {
		t.Fatalf("verified state = %q", value.State)
	}
}

func TestWaitForNATRejectsConcurrentGenerationAdvance(t *testing.T) {
	client := &natWaitAppliance{states: []appliance.NATState{{
		VMID:  "33333333-3333-4333-8333-333333333333",
		State: "enabled", ConntrackMark: 101,
		DesiredGeneration: 4, AppliedGeneration: 4, ObservedGeneration: 4,
	}}}
	_, err := waitForNAT(
		context.Background(), client,
		"11111111-1111-4111-8111-111111111111",
		"22222222-2222-4222-8222-222222222222",
		"33333333-3333-4333-8333-333333333333",
		101, 3, isolatedstate.NATDesiredEnabled,
	)
	if err == nil || !strings.Contains(err.Error(), "GENERATION_CONFLICT") {
		t.Fatalf("generation advance error = %v", err)
	}
}

func TestNATResumeUsesDurableExpectedGenerationAfterCacheAdvance(t *testing.T) {
	store, err := isolatedstate.Open(t.TempDir() + `\isolated.db`)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const operationID = "11111111-1111-4111-8111-111111111111"
	if _, err := store.BeginOperation(
		context.Background(), isolatedstate.BeginOperationRequest{
			ID: operationID, Kind: "enable_isolated_vm_nat",
			ResourceType:    "nat",
			ResourceID:      "33333333-3333-4333-8333-333333333333",
			CanonicalInputs: map[string]any{"expected_generation": 2},
		},
	); err != nil {
		t.Fatal(err)
	}
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{
		"operation_id": operationID, "resume_exact": true,
		"expected_generation": 2,
	}}}
	expected, replay, err := natOperationExpectedGeneration(
		context.Background(), store, req, operationID, 3,
	)
	if err != nil || !replay || expected != 2 {
		t.Fatalf("durable generation = %d, replay=%v, err=%v", expected, replay, err)
	}
}

func TestFinishNATWorkflowPersistsDrainingOperationAndResumeAction(t *testing.T) {
	store, err := isolatedstate.Open(t.TempDir() + `\isolated.db`)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	workflow, err := beginIsolatedWorkflow(
		context.Background(), store, nil,
		isolatedstate.BeginOperationRequest{
			ID:   "11111111-1111-4111-8111-111111111111",
			Kind: "disable_isolated_vm_nat", ResourceType: "nat",
			ResourceID:      "33333333-3333-4333-8333-333333333333",
			CanonicalInputs: map[string]any{"desired_state": "disabled"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	records := natRecords{
		orchestrator: isolatedstate.Orchestrator{
			ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		},
		network: isolatedstate.PrivateNetwork{
			ID:             "22222222-2222-4222-8222-222222222222",
			DNSServersJSON: `["10.0.0.1"]`,
		},
		vm: isolatedstate.IsolatedVM{
			ID:             "33333333-3333-4333-8333-333333333333",
			DNSServersJSON: `["10.0.0.1"]`,
		},
	}
	value := isolatedstate.NATAllocation{
		VMID: records.vm.ID, OrchestratorID: records.orchestrator.ID,
		DesiredState:  isolatedstate.NATDesiredDisabled,
		ObservedState: isolatedstate.NATObservedDraining,
		ConntrackMark: 101, DesiredGeneration: 3,
		AppliedGeneration: 3, ObservedGeneration: 3,
	}
	result, err := finishNATWorkflow(
		context.Background(), workflow, records, value, nil,
	)
	if err != nil || result == nil || result.IsError {
		t.Fatalf("finish draining = %#v, %v", result, err)
	}
	text := toolResultText(result)
	if !strings.Contains(text, `"status": "draining"`) ||
		!strings.Contains(text, `"tool": "reconcile_isolated_vm_nat"`) ||
		!strings.Contains(text, `"relay_unaffected": true`) {
		t.Fatalf("draining result = %s", text)
	}
	operation, err := store.GetOperation(
		context.Background(), "11111111-1111-4111-8111-111111111111",
	)
	if err != nil {
		t.Fatal(err)
	}
	if operation.Status != isolatedstate.OperationPaused ||
		operation.CurrentPhase != "draining" {
		t.Fatalf("draining operation = %+v", operation)
	}
}
