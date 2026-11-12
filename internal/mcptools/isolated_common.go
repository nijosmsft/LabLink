package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/isolated"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/vmconfig"
)

const isolatedOperationTTL = 2 * time.Minute

type isolatedState interface {
	BeginOperation(context.Context, isolatedstate.BeginOperationRequest) (isolatedstate.BeginOperationResult, error)
	GetOperation(context.Context, string) (isolatedstate.Operation, error)
	UpdateOperation(context.Context, isolatedstate.OperationUpdate) (isolatedstate.Operation, error)
	StartOperationPhase(context.Context, isolatedstate.PhaseStart) (isolatedstate.OperationPhase, error)
	FinishOperationPhase(context.Context, isolatedstate.PhaseFinish) error
	AppendOperationEvent(context.Context, isolatedstate.OperationEventInput) (isolatedstate.OperationEvent, error)
	OperationPhaseSucceeded(context.Context, string, int, string) (bool, error)
	LoadSucceededPhaseDetail(context.Context, string, int, string, any) (bool, error)
	PutApprovalPlan(context.Context, isolatedstate.ApprovalPlan) error
	ApprovePlan(context.Context, string, string, string) error
	ConsumePlan(context.Context, string, string, string) error
	PutOrchestrator(context.Context, isolatedstate.Orchestrator) error
	GetOrchestrator(context.Context, string) (isolatedstate.Orchestrator, error)
	ListOrchestrators(context.Context, string) ([]isolatedstate.Orchestrator, error)
	PutNetwork(context.Context, isolatedstate.PrivateNetwork) error
	GetNetwork(context.Context, string) (isolatedstate.PrivateNetwork, error)
	ListNetworks(context.Context, string) ([]isolatedstate.PrivateNetwork, error)
	CountActiveVMs(context.Context, string) (int, error)
	GetVM(context.Context, string) (isolatedstate.IsolatedVM, error)
	ListVMs(context.Context, string, string) ([]isolatedstate.IsolatedVM, error)
	PutRelay(context.Context, isolatedstate.RelayAllocation) error
	GetRelay(context.Context, string) (isolatedstate.RelayAllocation, error)
	GetRelayForVM(context.Context, string) (isolatedstate.RelayAllocation, error)
	ListRelays(context.Context, string, string) ([]isolatedstate.RelayAllocation, error)
	CommitAllocations(context.Context, []isolatedstate.ActiveResourceAllocation) error
	ReleaseAllocation(context.Context, isolatedstate.ReleaseAllocationRequest) (isolatedstate.ResourceAllocationHistory, error)
}

type isolatedAppliance interface {
	CheckReadiness(context.Context, string) (isolated.ApplianceReadiness, error)
	InspectApplianceState(context.Context, string) (isolated.ApplianceSnapshot, error)
	GetApplianceState(context.Context, string) (appliance.DesiredSnapshot, error)
	ReserveResources(context.Context, string, appliance.ReserveRequest) (appliance.ReserveResult, error)
	ReleaseResources(context.Context, string, appliance.ReleaseRequest) (appliance.ReleaseResult, error)
	ApplyPrivateNetwork(context.Context, string, isolated.ApplyPrivateNetworkInput) (isolated.NetworkMutationResult, error)
	RemovePrivateNetwork(context.Context, string, isolated.MutationEnvelope) (isolated.NetworkMutationResult, error)
	ApplyRelay(context.Context, string, isolated.RelayInput) (isolated.RelayMutationResult, error)
	AdoptRelay(context.Context, string, isolated.RelayInput) (isolated.RelayMutationResult, error)
	RemoveRelay(context.Context, string, isolated.MutationEnvelope, string, string) (isolated.RelayMutationResult, error)
	ListRelays(context.Context, string, string, string, bool, uint32, string) (isolated.RelayList, error)
	GetRelayStats(context.Context, string, string) (appliance.RelayStats, error)
	RebindRelays(context.Context, string, isolated.MutationEnvelope) ([]appliance.Relay, isolated.MutationResult, error)
	ValidateRelay(context.Context, string, string, bool) (isolated.RelayValidation, error)
}

type isolatedHost interface {
	PhysicalIdentity(context.Context, Target) (hyperv.IsolatedPhysicalHostObservation, error)
	Discover(context.Context, Target, string, string) (hyperv.IsolatedHostDiscovery, error)
	AcquireFence(context.Context, Target, isolated.HostCreateFenceRequest) (isolated.HostFenceLease, error)
	ReleaseFence(context.Context, Target, isolated.HostFenceLease)
	Preflight(context.Context, Target, isolated.ResourcePreflightInput, vmconfig.Profile) (isolated.ResourcePreflightResult, error)
	ClaimOrchestrator(context.Context, Target, isolatedstate.Orchestrator, isolated.HostFenceLease) (hyperv.IsolatedVMObservation, error)
	CreateSwitch(context.Context, Target, hyperv.CreateIsolatedPrivateSwitchParams) (hyperv.IsolatedSwitchMutationResult, error)
	AttachNIC(context.Context, Target, hyperv.AttachIsolatedNICParams) (hyperv.IsolatedAdapterMutationResult, error)
	RemoveNIC(context.Context, Target, hyperv.RemoveIsolatedNICParams) (hyperv.IsolatedAdapterMutationResult, error)
	DeleteSwitch(context.Context, Target, hyperv.DeleteIsolatedPrivateSwitchParams) (hyperv.IsolatedSwitchMutationResult, error)
}

type isolatedLinuxCreator interface {
	Create(context.Context, mcp.CallToolRequest, linuxVMPlan, Target, *MCPProgressState) (*mcp.CallToolResult, error)
}

type isolatedLifecycleDeps struct {
	server        *server.MCPServer
	state         isolatedState
	locks         *isolatedstate.LockManager
	host          isolatedHost
	orchestrators isolated.OrchestratorStateClient
	planner       isolated.HostPlanningClient
	probe         isolated.OrchestratorProbeClient
	networks      isolated.NetworkStateClient
	networkHost   isolated.HostNetworkClient
	appliance     isolatedAppliance
	linux         isolatedLinuxCreator
	registry      *registry.Registry
	pool          *agentclient.Pool
	defaults      *vmconfig.Store
	credentials   *credentials.Store
	audit         *audit.Log
	enrollment    VMEnrollmentConfig
	lease         LeaseGateConfig
	serverVersion string
}

type productionLinuxCreator struct {
	deps *isolatedLifecycleDeps
}

func (c productionLinuxCreator) Create(
	ctx context.Context,
	req mcp.CallToolRequest,
	plan linuxVMPlan,
	target Target,
	progress *MCPProgressState,
) (*mcp.CallToolResult, error) {
	d := c.deps
	return executeLinuxVMPlan(ctx, req, plan, target, d.registry, d.pool,
		d.defaults, d.credentials, d.audit, d.enrollment, d.lease, progress)
}

type isolatedToolResult struct {
	OperationID string `json:"operation_id"`
	Status      string `json:"status"`
	Phase       string `json:"phase"`
	ResourceID  string `json:"resource_id"`
	Generation  int64  `json:"generation,omitempty"`
	Progress    []any  `json:"progress"`
	NextAction  any    `json:"next_action"`
	Plan        any    `json:"plan,omitempty"`
	Resource    any    `json:"resource,omitempty"`
	Detail      any    `json:"detail,omitempty"`
}

func isolatedResult(value isolatedToolResult) *mcp.CallToolResult {
	if value.Progress == nil {
		value.Progress = []any{}
	}
	data, _ := json.MarshalIndent(value, "", "  ")
	return mcp.NewToolResultText("```json\n" + string(data) + "\n```")
}

func isolatedError(err error) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultError(err.Error()), nil
}

func isolatedOperationID(req mcp.CallToolRequest) (string, error) {
	raw := strings.TrimSpace(req.GetString("operation_id", ""))
	if raw == "" {
		value, err := isolated.NewOperationID()
		return value.String(), err
	}
	value, err := isolated.ParseOperationID(raw)
	return value.String(), err
}

func resumeResourceID(
	ctx context.Context,
	state isolatedState,
	operationID, resourceType string,
) (string, error) {
	operation, err := state.GetOperation(ctx, operationID)
	if errors.Is(err, isolatedstate.ErrOperationNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if operation.ResourceType != resourceType {
		return "", fmt.Errorf("OPERATION_RESOURCE_MISMATCH: operation %s owns %s %s",
			operationID, operation.ResourceType, operation.ResourceID)
	}
	return operation.ResourceID, nil
}

func expectedGeneration(req mcp.CallToolRequest, current isolatedstate.Generation) (isolatedstate.Generation, error) {
	value, ok := numericArgument(req.GetArguments()["expected_generation"])
	if !ok {
		return current, nil
	}
	expected := isolatedstate.Generation(int64(value))
	if expected != current {
		return 0, fmt.Errorf("GENERATION_CONFLICT: expected generation %d, current generation %d", expected, current)
	}
	return expected, nil
}

type durableWorkflow struct {
	state      isolatedState
	operation  isolatedstate.Operation
	progress   *MCPProgressState
	lastPhase  string
	resourceID string
}

func beginIsolatedWorkflow(
	ctx context.Context,
	state isolatedState,
	progress *MCPProgressState,
	request isolatedstate.BeginOperationRequest,
) (*durableWorkflow, error) {
	result, err := state.BeginOperation(ctx, request)
	if err != nil {
		return nil, err
	}
	return &durableWorkflow{
		state: state, operation: result.Operation, progress: progress,
		lastPhase: result.Operation.CurrentPhase, resourceID: request.ResourceID,
	}, nil
}

func (w *durableWorkflow) event(ctx context.Context, phase, level, message string, detail any) {
	if w == nil || w.state == nil {
		return
	}
	_, _ = w.state.AppendOperationEvent(ctx, isolatedstate.OperationEventInput{
		OperationID: w.operation.ID, PhaseName: optionalTrimmed(phase),
		Level: level, Message: message, Detail: detail,
	})
}

func (w *durableWorkflow) phase(
	ctx context.Context,
	index int,
	name, status string,
	run func() (any, error),
) error {
	return w.runPhase(ctx, index, name, status, true, run)
}

func (w *durableWorkflow) phaseAlways(
	ctx context.Context,
	index int,
	name, status string,
	run func() (any, error),
) error {
	return w.runPhase(ctx, index, name, status, false, run)
}

func (w *durableWorkflow) runPhase(
	ctx context.Context,
	index int,
	name, status string,
	skipSucceeded bool,
	run func() (any, error),
) error {
	if w.progress != nil {
		w.progress.Update(name, status)
	}

	w.lastPhase = name
	succeeded, err := w.state.OperationPhaseSucceeded(ctx, w.operation.ID, index, name)
	if err != nil {
		return err
	}
	if succeeded && skipSucceeded {
		w.event(ctx, name, "info", "resume skipped already-succeeded phase", nil)
		return nil
	}
	started, err := w.state.StartOperationPhase(ctx, isolatedstate.PhaseStart{
		OperationID: w.operation.ID, PhaseIndex: index, PhaseName: name,
	})
	if err != nil {
		return err
	}
	w.event(ctx, name, "info", status, nil)
	detail, runErr := run()
	finish := isolatedstate.PhaseFinish{
		OperationID: w.operation.ID, PhaseIndex: index, Attempt: started.Attempt,
		Status: isolatedstate.PhaseSucceeded, Detail: detail,
	}
	if runErr != nil {
		message := runErr.Error()
		finish.Status = isolatedstate.PhaseFailed
		finish.ErrorText = &message
	}
	if finishErr := w.state.FinishOperationPhase(ctx, finish); finishErr != nil {
		if runErr != nil {
			return errors.Join(runErr, finishErr)
		}
		return finishErr
	}
	if runErr != nil {
		code := isolated.ErrorCode(runErr)
		if code == "" {
			code = "PHASE_FAILED"
		}
		text := runErr.Error()
		_, _ = w.state.UpdateOperation(ctx, isolatedstate.OperationUpdate{
			OperationID: w.operation.ID, Status: isolatedstate.OperationPaused,
			CurrentPhase: name, ErrorCode: &code, ErrorText: &text,
		})
		w.event(ctx, name, "error", "phase failed; partial resources were preserved", detail)
		return runErr
	}
	w.event(ctx, name, "info", "phase succeeded", detail)
	return nil
}

func (w *durableWorkflow) loadPhase(
	ctx context.Context,
	index int,
	name string,
	target any,
) (bool, error) {
	return w.state.LoadSucceededPhaseDetail(ctx, w.operation.ID, index, name, target)
}

func (w *durableWorkflow) finish(
	ctx context.Context,
	status isolatedstate.OperationStatus,
	result isolatedToolResult,
) (*mcp.CallToolResult, error) {
	result.OperationID = w.operation.ID
	if result.ResourceID == "" {
		result.ResourceID = w.resourceID
	}
	if result.Phase == "" {
		result.Phase = w.lastPhase
	}
	_, err := w.state.UpdateOperation(ctx, isolatedstate.OperationUpdate{
		OperationID: w.operation.ID, Status: status,
		CurrentPhase: result.Phase, Result: result,
	})
	if err != nil {
		return isolatedError(err)
	}
	return isolatedResult(result), nil
}

func optionalTrimmed(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

func approveRevision(
	ctx context.Context,
	s *server.MCPServer,
	state isolatedState,
	req mcp.CallToolRequest,
	operationID, action string,
	plan isolated.RevisionedPlan,
	message string,
	extraProperty string,
) (bool, *mcp.CallToolResult, error) {
	planJSON, err := isolatedstate.CanonicalJSON(plan)
	if err != nil {
		return false, nil, err
	}
	if err := state.PutApprovalPlan(ctx, isolatedstate.ApprovalPlan{
		Revision: plan.Revision, OperationID: operationID, Action: action,
		PlanJSON: string(planJSON), PlanHash: plan.PlanHash,
		State: isolatedstate.ApprovalPending,
	}); err != nil {
		return false, nil, err
	}
	approved := strings.TrimSpace(req.GetString("approved_plan_revision", ""))
	if approved != "" {
		if approved != plan.Revision {
			return false, nil, fmt.Errorf("PLAN_REVISION_MISMATCH: approved revision %q does not match %q", approved, plan.Revision)
		}
		if err := state.ApprovePlan(ctx, operationID, plan.Revision, plan.PlanHash); err != nil {
			return false, nil, err
		}
		if err := state.ConsumePlan(ctx, operationID, plan.Revision, plan.PlanHash); err != nil {
			return false, nil, err
		}
		return true, nil, nil
	}
	properties := map[string]any{
		"plan_revision": map[string]any{
			"type": "string", "const": plan.Revision,
			"description": "Exact immutable plan revision",
		},
		"approve": map[string]any{
			"type": "boolean", "description": "Approve this exact plan",
		},
	}
	required := []string{"plan_revision", "approve"}
	if extraProperty != "" {
		properties[extraProperty] = map[string]any{
			"type": "boolean", "description": "Acknowledge this exact destructive action",
		}
		required = append(required, extraProperty)
	}
	if s != nil {
		response, elicitErr := s.RequestElicitation(ctx, mcp.ElicitationRequest{Params: mcp.ElicitationParams{
			Message: message + "\n\n" + string(planJSON),
			RequestedSchema: map[string]any{
				"type": "object", "properties": properties, "required": required,
				"additionalProperties": false,
			},
		}})
		if elicitErr == nil && response.Action == mcp.ElicitationResponseActionAccept {
			content, ok := response.Content.(map[string]any)
			ack, _ := content["approve"].(bool)
			extraOK := true
			if extraProperty != "" {
				extraOK, _ = content[extraProperty].(bool)
			}
			if ok && ack && extraOK && strings.TrimSpace(fmt.Sprint(content["plan_revision"])) == plan.Revision {
				if err := state.ApprovePlan(ctx, operationID, plan.Revision, plan.PlanHash); err != nil {
					return false, nil, err
				}
				if err := state.ConsumePlan(ctx, operationID, plan.Revision, plan.PlanHash); err != nil {
					return false, nil, err
				}
				return true, nil, nil
			}
		} else if elicitErr != nil && !errors.Is(elicitErr, server.ErrElicitationNotSupported) {
			return false, nil, elicitErr
		}
	}
	return false, isolatedResult(isolatedToolResult{
		OperationID: operationID, Status: "approval_required",
		Phase: "approval_required", ResourceID: plan.ResourceID,
		Plan: plan, NextAction: map[string]any{
			"retry_with": map[string]any{
				"operation_id": operationID, "resume_exact": true,
				"approved_plan_revision": plan.Revision,
			},
		},
	}), nil
}
