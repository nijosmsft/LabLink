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
	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/isolated"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
)

const natApplyVerificationTimeout = 30 * time.Second

type isolatedNATState interface {
	PutNAT(context.Context, isolatedstate.NATAllocation) error
	GetNAT(context.Context, string) (isolatedstate.NATAllocation, error)
	ListNAT(context.Context, string, string, string) ([]isolatedstate.NATAllocation, error)
	GetGuestPendingUpdate(context.Context, string, string) (isolatedstate.GuestPendingUpdate, error)
}

type isolatedNATAppliance interface {
	InspectApplianceState(context.Context, string) (isolated.ApplianceSnapshot, error)
	SetNATState(context.Context, string, isolated.NATInput) (isolated.NATMutationResult, error)
	ListNATState(context.Context, string, string, string, string, uint32, string) (isolated.NATList, error)
	ReconcileNAT(context.Context, string, isolated.MutationEnvelope, string) (isolated.NATMutationResult, error)
}

type isolatedNATView struct {
	NAT             isolatedstate.NATAllocation `json:"nat"`
	Live            *appliance.NATState         `json:"live,omitempty"`
	DNS             isolated.NATDNSStatus       `json:"dns"`
	Drift           []string                    `json:"drift"`
	RelayUnaffected bool                        `json:"relay_unaffected"`
}

// RegisterIsolatedNAT registers the NAT tool family. The server entry point can
// call this independently while guest-lifecycle registration is integrated.
func RegisterIsolatedNAT(s *server.MCPServer, deps *isolatedLifecycleDeps) {
	s.AddTool(mcp.NewTool("enable_isolated_vm_nat",
		mcp.WithDescription("Atomically apply and verify unrestricted IPv4 forwarding and masquerade for one exact managed guest."),
		mcp.WithString("isolated_vm_id", mcp.Required()),
		mcp.WithString("operation_id"), mcp.WithBoolean("resume_exact"),
		mcp.WithNumber("expected_generation"),
	), setIsolatedVMNATHandler(deps, isolatedstate.NATDesiredEnabled))
	s.AddTool(mcp.NewTool("disable_isolated_vm_nat",
		mcp.WithDescription("Block new forwarded flows and return draining until exact marked conntrack reaches zero."),
		mcp.WithString("isolated_vm_id", mcp.Required()),
		mcp.WithString("operation_id"), mcp.WithBoolean("resume_exact"),
		mcp.WithNumber("expected_generation"),
	), setIsolatedVMNATHandler(deps, isolatedstate.NATDesiredDisabled))
	s.AddTool(mcp.NewTool("get_isolated_vm_nat",
		mcp.WithDescription("Get cached NAT, copied DNS, pending DNS drift, and optional appliance-live state."),
		mcp.WithString("isolated_vm_id", mcp.Required()),
		mcp.WithBoolean("live"),
	), getIsolatedVMNATHandler(deps))
	s.AddTool(mcp.NewTool("list_isolated_vm_nat",
		mcp.WithDescription("List cached per-VM NAT state with optional exact appliance-live comparison."),
		mcp.WithString("orchestrator_id"), mcp.WithString("network_id"),
		mcp.WithString("state", mcp.Description("enabled, draining, or disabled")),
		mcp.WithBoolean("live"),
	), listIsolatedVMNATHandler(deps))
	s.AddTool(mcp.NewTool("reconcile_isolated_vm_nat",
		mcp.WithDescription("Import exact appliance NAT truth and reapply it without changing relay state or deleting unknown state."),
		mcp.WithString("isolated_vm_id", mcp.Required()),
		mcp.WithString("operation_id"), mcp.WithBoolean("resume_exact"),
		mcp.WithNumber("expected_generation"),
	), reconcileIsolatedVMNATHandler(deps))
}

func natDependencies(deps *isolatedLifecycleDeps) (isolatedNATState, isolatedNATAppliance, error) {
	if deps == nil {
		return nil, nil, errors.New("NAT dependencies are not configured")
	}
	state, ok := deps.state.(isolatedNATState)
	if !ok {
		return nil, nil, errors.New("isolated state does not implement NAT storage")
	}
	client, ok := deps.appliance.(isolatedNATAppliance)
	if !ok {
		return nil, nil, errors.New("isolated appliance client does not implement NAT operations")
	}
	return state, client, nil
}

func natOperationExpectedGeneration(
	ctx context.Context,
	state isolatedState,
	req mcp.CallToolRequest,
	operationID string,
	current isolatedstate.Generation,
) (isolatedstate.Generation, bool, error) {
	operation, err := state.GetOperation(ctx, operationID)
	if errors.Is(err, isolatedstate.ErrOperationNotFound) {
		expected, generationErr := expectedGeneration(req, current)
		return expected, false, generationErr
	}
	if err != nil {
		return 0, false, err
	}
	if !req.GetBool("resume_exact", false) {
		return 0, true, isolatedstate.ErrResumeExactRequired
	}
	var stored struct {
		Inputs struct {
			ExpectedGeneration isolatedstate.Generation `json:"expected_generation"`
		} `json:"inputs"`
	}
	if err := json.Unmarshal([]byte(operation.RequestJSON), &stored); err != nil {
		return 0, true, fmt.Errorf("INVALID_DURABLE_OPERATION: decode canonical inputs: %w", err)
	}
	return stored.Inputs.ExpectedGeneration, true, nil
}

type natRecords struct {
	orchestrator isolatedstate.Orchestrator
	network      isolatedstate.PrivateNetwork
	vm           isolatedstate.IsolatedVM
	local        isolatedstate.NATAllocation
}

func loadNATRecords(
	ctx context.Context,
	deps *isolatedLifecycleDeps,
	state isolatedNATState,
	vmID string,
	requireLocal bool,
) (natRecords, error) {
	vm, err := deps.state.GetVM(ctx, vmID)
	if err != nil {
		return natRecords{}, err
	}
	network, err := deps.state.GetNetwork(ctx, vm.NetworkID)
	if err != nil {
		return natRecords{}, err
	}
	orchestrator, err := deps.state.GetOrchestrator(ctx, vm.OrchestratorID)
	if err != nil {
		return natRecords{}, err
	}
	local, err := state.GetNAT(ctx, vm.ID)
	if err != nil && (requireLocal || !errors.Is(err, isolatedstate.ErrNATNotFound)) {
		return natRecords{}, err
	}
	return natRecords{
		orchestrator: orchestrator, network: network, vm: vm, local: local,
	}, nil
}

func setIsolatedVMNATHandler(
	deps *isolatedLifecycleDeps,
	desired isolatedstate.NATDesiredState,
) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		state, client, err := natDependencies(deps)
		if err != nil {
			return isolatedError(err)
		}
		id, err := isolated.ParseVMID(req.GetString("isolated_vm_id", ""))
		if err != nil {
			return isolatedError(err)
		}
		records, err := loadNATRecords(ctx, deps, state, id.String(), true)
		if err != nil {
			return isolatedError(err)
		}
		operationID, err := isolatedOperationID(req)
		if err != nil {
			return isolatedError(err)
		}
		expected, replay, err := natOperationExpectedGeneration(
			ctx, deps.state, req, operationID, records.local.DesiredGeneration,
		)
		if err != nil {
			return isolatedError(err)
		}
		action := "enable_isolated_vm_nat"
		phaseText := "applying and verifying NAT forwarding"
		if desired == isolatedstate.NATDesiredDisabled {
			action = "disable_isolated_vm_nat"
			phaseText = "blocking new flows and preserving marked conntrack"
		}
		progress, stop := StartMCPProgress(ctx, req, 5*time.Minute, "validate", phaseText)
		defer stop()
		workflow, err := beginIsolatedWorkflow(ctx, deps.state, progress, isolatedstate.BeginOperationRequest{
			ID: operationID, Kind: action, ResourceType: "nat",
			ResourceID: records.vm.ID, HostNode: &records.orchestrator.HostNode,
			OrchestratorID: optionalTrimmed(records.orchestrator.ID),
			NetworkID:      optionalTrimmed(records.network.ID),
			CanonicalInputs: map[string]any{
				"isolated_vm_id":      records.vm.ID,
				"orchestrator_id":     records.orchestrator.ID,
				"network_id":          records.network.ID,
				"desired_state":       desired,
				"expected_generation": expected,
			},
			ResumeExact: req.GetBool("resume_exact", false),
		})
		if err != nil {
			return isolatedError(err)
		}
		lockKey, _ := isolatedstate.NATLockKey(records.vm.ID)
		localLease, err := deps.locks.Acquire(ctx, isolatedstate.LockAcquireRequest{
			Key: lockKey, OperationID: operationID, TTL: isolatedOperationTTL,
		})
		if err != nil {
			return isolatedError(err)
		}
		defer deps.locks.Release(context.Background(), localLease)
		target, err := resolvePlanTarget(records.orchestrator.HostNode, deps.registry)
		if err != nil {
			return isolatedError(err)
		}
		hostKey, _ := hyperv.HostOrchestratorCreateLockKey(records.orchestrator.PhysicalHostID)
		hostLease, err := deps.host.AcquireFence(ctx, target, isolated.HostCreateFenceRequest{
			PhysicalHostID: records.orchestrator.PhysicalHostID,
			HostNode:       records.orchestrator.HostNode, OperationID: operationID,
			LockKey: hostKey,
		})
		if err != nil {
			return isolatedError(err)
		}
		defer deps.host.ReleaseFence(context.Background(), target, hostLease)

		snapshot, err := client.InspectApplianceState(ctx, records.orchestrator.ID)
		if err != nil {
			return isolatedError(err)
		}
		authority := records.orchestrator
		authority.HostFence = hostLease.Fence
		validationMode := isolated.NATValidateMutation
		if replay {
			validationMode = isolated.NATValidateImport
		}
		validated, err := isolated.ValidateNATIdentity(
			authority, records.network, records.vm, &records.local,
			snapshot, validationMode,
		)
		if err != nil {
			return isolatedError(err)
		}
		if replay && validated.Live.DesiredGeneration > uint64(expected+1) {
			return isolatedError(fmt.Errorf(
				"GENERATION_CONFLICT: appliance generation %d exceeds replay target %d",
				validated.Live.DesiredGeneration, expected+1,
			))
		}
		current, err := isolated.MergeApplianceNAT(
			&records.local, records.orchestrator.ID, validated.Live,
		)
		if err != nil {
			return isolatedError(err)
		}
		current.UpdatedAt = isolatedstate.UnixSeconds(time.Now().Unix())
		if natAlreadyAtDesired(current, desired) {
			if err := state.PutNAT(ctx, current); err != nil {
				return isolatedError(err)
			}
			return finishNATWorkflow(ctx, workflow, records, current, nil)
		}

		semantic, err := isolatedstate.SemanticHash(map[string]any{
			"isolated_vm_id":      records.vm.ID,
			"orchestrator_id":     records.orchestrator.ID,
			"network_id":          records.network.ID,
			"guest_ipv4":          records.vm.IPv4,
			"conntrack_mark":      records.local.ConntrackMark,
			"desired_state":       desired,
			"expected_generation": expected,
		})
		if err != nil {
			return isolatedError(err)
		}
		next := expected + 1
		envelope := natEnvelope(
			operationID, records.vm.ID, semantic, expected, next,
			records.orchestrator, validated.Guest.DesiredGeneration,
			hostLease, "nat_apply",
		)
		var mutation isolated.NATMutationResult
		err = workflow.phase(ctx, 0, "apply_verify", phaseText, func() (any, error) {
			mutation, err = client.SetNATState(ctx, records.orchestrator.ID, isolated.NATInput{
				Header: envelope, ReservationID: validated.Reservation.ID,
				NetworkID: records.network.ID, DesiredState: string(desired),
				ConntrackMark: uint32(records.local.ConntrackMark),
			})
			if err != nil {
				return mutation, err
			}
			mutation.NAT, err = waitForNAT(
				ctx, client, records.orchestrator.ID, records.network.ID,
				records.vm.ID, records.local.ConntrackMark, uint64(next), desired,
			)
			return mutation, err
		})
		if err != nil {
			return isolatedError(err)
		}
		if mutation.NAT.VMID == "" {
			if _, err := workflow.loadPhase(ctx, 0, "apply_verify", &mutation); err != nil {
				return isolatedError(err)
			}
		}
		updated, err := isolated.MergeApplianceNAT(
			&records.local, records.orchestrator.ID, mutation.NAT,
		)
		if err != nil {
			return isolatedError(err)
		}
		updated.UpdatedAt = isolatedstate.UnixSeconds(time.Now().Unix())
		if err := state.PutNAT(ctx, updated); err != nil {
			return isolatedError(err)
		}
		return finishNATWorkflow(ctx, workflow, records, updated, mutation.Mutation)
	}
}

func reconcileIsolatedVMNATHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		state, client, err := natDependencies(deps)
		if err != nil {
			return isolatedError(err)
		}
		id, err := isolated.ParseVMID(req.GetString("isolated_vm_id", ""))
		if err != nil {
			return isolatedError(err)
		}
		records, err := loadNATRecords(ctx, deps, state, id.String(), false)
		if err != nil {
			return isolatedError(err)
		}
		operationID, err := isolatedOperationID(req)
		if err != nil {
			return isolatedError(err)
		}
		expected, replay, err := natOperationExpectedGeneration(
			ctx, deps.state, req, operationID, records.local.DesiredGeneration,
		)
		if err != nil {
			return isolatedError(err)
		}
		progress, stop := StartMCPProgress(ctx, req, 5*time.Minute, "import_truth", "importing exact appliance NAT truth")
		defer stop()
		workflow, err := beginIsolatedWorkflow(ctx, deps.state, progress, isolatedstate.BeginOperationRequest{
			ID: operationID, Kind: "reconcile_isolated_vm_nat", ResourceType: "nat",
			ResourceID: records.vm.ID, HostNode: &records.orchestrator.HostNode,
			OrchestratorID: optionalTrimmed(records.orchestrator.ID),
			NetworkID:      optionalTrimmed(records.network.ID),
			CanonicalInputs: map[string]any{
				"isolated_vm_id":      records.vm.ID,
				"orchestrator_id":     records.orchestrator.ID,
				"network_id":          records.network.ID,
				"expected_generation": expected,
			},
			ResumeExact: req.GetBool("resume_exact", false),
		})
		if err != nil {
			return isolatedError(err)
		}
		lockKey, _ := isolatedstate.NATLockKey(records.vm.ID)
		localLease, err := deps.locks.Acquire(ctx, isolatedstate.LockAcquireRequest{
			Key: lockKey, OperationID: operationID, TTL: isolatedOperationTTL,
		})
		if err != nil {
			return isolatedError(err)
		}
		defer deps.locks.Release(context.Background(), localLease)
		target, err := resolvePlanTarget(records.orchestrator.HostNode, deps.registry)
		if err != nil {
			return isolatedError(err)
		}
		hostKey, _ := hyperv.HostOrchestratorCreateLockKey(records.orchestrator.PhysicalHostID)
		hostLease, err := deps.host.AcquireFence(ctx, target, isolated.HostCreateFenceRequest{
			PhysicalHostID: records.orchestrator.PhysicalHostID,
			HostNode:       records.orchestrator.HostNode, OperationID: operationID,
			LockKey: hostKey,
		})
		if err != nil {
			return isolatedError(err)
		}
		defer deps.host.ReleaseFence(context.Background(), target, hostLease)

		snapshot, err := client.InspectApplianceState(ctx, records.orchestrator.ID)
		if err != nil {
			return isolatedError(err)
		}
		authority := records.orchestrator
		authority.HostFence = hostLease.Fence
		var local *isolatedstate.NATAllocation
		if records.local.VMID != "" {
			local = &records.local
		}
		validated, err := isolated.ValidateNATIdentity(
			authority, records.network, records.vm, local,
			snapshot, isolated.NATValidateImport,
		)
		if err != nil {
			return isolatedError(err)
		}
		var imported isolatedstate.NATAllocation
		importSucceeded, err := deps.state.OperationPhaseSucceeded(
			ctx, operationID, 0, "import_truth",
		)
		if err != nil {
			return isolatedError(err)
		}
		if importSucceeded {
			if _, err := workflow.loadPhase(ctx, 0, "import_truth", &imported); err != nil {
				return isolatedError(err)
			}
		} else {
			imported, err = isolated.MergeApplianceNAT(
				local, records.orchestrator.ID, validated.Live,
			)
			if err != nil {
				return isolatedError(err)
			}
			imported.UpdatedAt = isolatedstate.UnixSeconds(time.Now().Unix())
			if err := workflow.phase(ctx, 0, "import_truth", "importing exact appliance NAT generations and state", func() (any, error) {
				return imported, state.PutNAT(ctx, imported)
			}); err != nil {
				return isolatedError(err)
			}
		}
		if replay &&
			validated.Live.DesiredGeneration > uint64(imported.DesiredGeneration+1) {
			return isolatedError(fmt.Errorf(
				"GENERATION_CONFLICT: appliance generation %d exceeds reconcile replay target %d",
				validated.Live.DesiredGeneration, imported.DesiredGeneration+1,
			))
		}
		semantic, err := isolatedstate.SemanticHash(map[string]any{
			"isolated_vm_id":       records.vm.ID,
			"orchestrator_id":      records.orchestrator.ID,
			"network_id":           records.network.ID,
			"conntrack_mark":       imported.ConntrackMark,
			"appliance_generation": imported.DesiredGeneration,
			"semantic_action":      "reconcile_nat",
		})
		if err != nil {
			return isolatedError(err)
		}
		next := imported.DesiredGeneration + 1
		envelope := natEnvelope(
			operationID, records.vm.ID, semantic, imported.DesiredGeneration,
			next, records.orchestrator, validated.Guest.DesiredGeneration,
			hostLease, "nat_reconcile",
		)
		var mutation isolated.NATMutationResult
		err = workflow.phase(ctx, 1, "reapply_verify", "reapplying appliance NAT truth and verifying policy", func() (any, error) {
			mutation, err = client.ReconcileNAT(
				ctx, records.orchestrator.ID, envelope, records.network.ID,
			)
			if err != nil {
				return mutation, err
			}
			mutation.NAT, err = waitForNAT(
				ctx, client, records.orchestrator.ID, records.network.ID,
				records.vm.ID, imported.ConntrackMark, uint64(next),
				imported.DesiredState,
			)
			return mutation, err
		})
		if err != nil {
			return isolatedError(err)
		}
		if mutation.NAT.VMID == "" {
			if _, err := workflow.loadPhase(ctx, 1, "reapply_verify", &mutation); err != nil {
				return isolatedError(err)
			}
		}
		updated, err := isolated.MergeApplianceNAT(
			&imported, records.orchestrator.ID, mutation.NAT,
		)
		if err != nil {
			return isolatedError(err)
		}
		updated.UpdatedAt = isolatedstate.UnixSeconds(time.Now().Unix())
		if err := state.PutNAT(ctx, updated); err != nil {
			return isolatedError(err)
		}
		return finishNATWorkflow(ctx, workflow, records, updated, mutation.Mutation)
	}
}

func getIsolatedVMNATHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		state, client, err := natDependencies(deps)
		if err != nil {
			return isolatedError(err)
		}
		id, err := isolated.ParseVMID(req.GetString("isolated_vm_id", ""))
		if err != nil {
			return isolatedError(err)
		}
		records, err := loadNATRecords(ctx, deps, state, id.String(), true)
		if err != nil {
			return isolatedError(err)
		}
		view, err := buildNATView(ctx, state, records, nil)
		if err != nil {
			return isolatedError(err)
		}
		if req.GetBool("live", false) {
			snapshot, inspectErr := client.InspectApplianceState(ctx, records.orchestrator.ID)
			if inspectErr != nil {
				return isolatedError(inspectErr)
			}
			validated, validateErr := isolated.ValidateNATIdentity(
				records.orchestrator, records.network, records.vm,
				&records.local, snapshot, isolated.NATValidateImport,
			)
			if validateErr != nil {
				return isolatedError(validateErr)
			}
			view.Live = &validated.Live
			view.Drift = natDrift(records.local, validated.Live)
		}
		return isolatedResult(isolatedToolResult{
			Status: "succeeded", Phase: "get", ResourceID: records.vm.ID,
			Generation: int64(records.local.DesiredGeneration),
			Resource:   view, NextAction: nil,
		}), nil
	}
}

func listIsolatedVMNATHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		state, client, err := natDependencies(deps)
		if err != nil {
			return isolatedError(err)
		}
		orchestratorID := strings.TrimSpace(req.GetString("orchestrator_id", ""))
		networkID := strings.TrimSpace(req.GetString("network_id", ""))
		stateFilter := strings.ToLower(strings.TrimSpace(req.GetString("state", "")))
		if orchestratorID != "" {
			if _, err := isolated.ParseOrchestratorID(orchestratorID); err != nil {
				return isolatedError(err)
			}
		}
		if networkID != "" {
			if _, err := isolated.ParseNetworkID(networkID); err != nil {
				return isolatedError(err)
			}
		}
		locals, err := state.ListNAT(ctx, orchestratorID, networkID, stateFilter)
		if err != nil {
			return isolatedError(err)
		}
		liveByVM := map[string]appliance.NATState{}
		var foreign []appliance.NATState
		if req.GetBool("live", false) {
			if orchestratorID == "" {
				return isolatedError(errors.New("orchestrator_id is required when live=true"))
			}
			live, listErr := listAllNAT(ctx, client, orchestratorID, networkID, "", stateFilter)
			if listErr != nil {
				return isolatedError(listErr)
			}
			known := make(map[string]bool, len(locals))
			for _, local := range locals {
				known[local.VMID] = true
			}
			for _, value := range live {
				if known[value.VMID] {
					liveByVM[value.VMID] = value
				} else {
					foreign = append(foreign, value)
				}
			}
		}
		views := make([]isolatedNATView, 0, len(locals))
		for _, local := range locals {
			records, loadErr := loadNATRecords(ctx, deps, state, local.VMID, true)
			if loadErr != nil {
				return isolatedError(loadErr)
			}
			live, hasLive := liveByVM[local.VMID]
			var livePtr *appliance.NATState
			if hasLive {
				livePtr = &live
			}
			view, viewErr := buildNATView(ctx, state, records, livePtr)
			if viewErr != nil {
				return isolatedError(viewErr)
			}
			if req.GetBool("live", false) && !hasLive {
				view.Drift = append(view.Drift, "missing_on_appliance")
			}
			views = append(views, view)
		}
		return isolatedResult(isolatedToolResult{
			Status: "succeeded", Phase: "list", ResourceID: orchestratorID,
			Resource: views, Detail: map[string]any{
				"foreign_appliance_state": foreign,
				"unknown_state_deleted":   false,
			},
			NextAction: nil,
		}), nil
	}
}

func buildNATView(
	ctx context.Context,
	state isolatedNATState,
	records natRecords,
	live *appliance.NATState,
) (isolatedNATView, error) {
	var pending *isolatedstate.GuestPendingUpdate
	value, err := state.GetGuestPendingUpdate(ctx, records.vm.ID, "dns")
	if err == nil {
		pending = &value
	} else if !errors.Is(err, isolatedstate.ErrGuestPendingUpdateNotFound) {
		return isolatedNATView{}, err
	}
	view := isolatedNATView{
		NAT: records.local, Live: live,
		DNS:             isolated.BuildNATDNSStatus(records.network, records.vm, pending),
		RelayUnaffected: true,
	}
	if live != nil {
		view.Drift = natDrift(records.local, *live)
	}
	return view, nil
}

func natEnvelope(
	operationID, vmID, semantic string,
	expected, next isolatedstate.Generation,
	orchestrator isolatedstate.Orchestrator,
	parentGeneration uint64,
	lease isolated.HostFenceLease,
	phase string,
) isolated.MutationEnvelope {
	return isolated.MutationEnvelope{
		Header: appliance.MutationHeader{
			ParentOperationID: operationID,
			MutationID: isolatedstate.StableMutationID(
				operationID, vmID, "set_nat", phase,
			),
			SemanticHash: semantic, ResourceID: vmID, ParentResourceID: vmID,
			ExpectedGeneration: uint64(expected), NewGeneration: uint64(next),
			HostFence:                uint64(lease.Fence),
			ExpectedParentGeneration: parentGeneration,
		},
		PhysicalHostID: orchestrator.PhysicalHostID,
		HostLeaseID:    lease.LeaseID, HostLeaseSecret: mustDecodeHex(lease.LeaseSecret),
	}
}

func waitForNAT(
	ctx context.Context,
	client isolatedNATAppliance,
	orchestratorID, networkID, vmID string,
	conntrackMark int64,
	generation uint64,
	desired isolatedstate.NATDesiredState,
) (appliance.NATState, error) {
	deadline := time.NewTimer(natApplyVerificationTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		values, err := listAllNAT(ctx, client, orchestratorID, networkID, vmID, "")
		if err != nil {
			return appliance.NATState{}, err
		}
		if len(values) != 1 {
			if len(values) > 1 {
				return appliance.NATState{}, errors.New("FOREIGN_APPLIANCE_STATE: duplicate NAT identities")
			}
		} else {
			value := values[0]
			if value.ConntrackMark != conntrackMark {
				return appliance.NATState{}, errors.New("FOREIGN_APPLIANCE_STATE: conntrack mark changed")
			}
			if value.DesiredGeneration > generation {
				return appliance.NATState{}, fmt.Errorf(
					"GENERATION_CONFLICT: appliance advanced to generation %d while verifying %d",
					value.DesiredGeneration, generation,
				)
			}
			if value.DesiredGeneration == generation &&
				value.AppliedGeneration == generation &&
				value.ObservedGeneration == generation &&
				natStateMatchesDesired(value.State, desired) {
				return value, nil
			}
		}
		select {
		case <-ctx.Done():
			return appliance.NATState{}, ctx.Err()
		case <-deadline.C:
			return appliance.NATState{}, fmt.Errorf(
				"VERIFY_FAILED: NAT generation %d did not converge within %s",
				generation, natApplyVerificationTimeout,
			)
		case <-ticker.C:
		}
	}
}

func listAllNAT(
	ctx context.Context,
	client isolatedNATAppliance,
	orchestratorID, networkID, vmID, state string,
) ([]appliance.NATState, error) {
	var values []appliance.NATState
	token := ""
	for {
		page, err := client.ListNATState(
			ctx, orchestratorID, networkID, vmID, state, 500, token,
		)
		if err != nil {
			return nil, err
		}
		values = append(values, page.States...)
		if page.NextPageToken == "" {
			return values, nil
		}
		if page.NextPageToken == token {
			return nil, errors.New("INVALID_APPLIANCE_RESPONSE: NAT page token did not advance")
		}
		token = page.NextPageToken
	}
}

func natAlreadyAtDesired(
	value isolatedstate.NATAllocation,
	desired isolatedstate.NATDesiredState,
) bool {
	if value.DesiredGeneration != value.AppliedGeneration ||
		value.DesiredGeneration != value.ObservedGeneration ||
		value.DesiredState != desired {
		return false
	}
	if desired == isolatedstate.NATDesiredEnabled {
		return value.ObservedState == isolatedstate.NATObservedEnabled
	}
	return value.ObservedState == isolatedstate.NATObservedDraining ||
		value.ObservedState == isolatedstate.NATObservedDisabled
}

func natStateMatchesDesired(state string, desired isolatedstate.NATDesiredState) bool {
	if desired == isolatedstate.NATDesiredEnabled {
		return state == "enabled"
	}
	return state == "draining" || state == "disabled"
}

func natDrift(local isolatedstate.NATAllocation, live appliance.NATState) []string {
	var drift []string
	if local.ConntrackMark != live.ConntrackMark {
		drift = append(drift, "conntrack_mark")
	}
	if uint64(local.DesiredGeneration) != live.DesiredGeneration ||
		uint64(local.AppliedGeneration) != live.AppliedGeneration ||
		uint64(local.ObservedGeneration) != live.ObservedGeneration {
		drift = append(drift, "generation")
	}
	merged, err := isolated.MergeApplianceNAT(&local, local.OrchestratorID, live)
	if err != nil || merged.DesiredState != local.DesiredState ||
		merged.ObservedState != local.ObservedState {
		drift = append(drift, "state")
	}
	return drift
}

func finishNATWorkflow(
	ctx context.Context,
	workflow *durableWorkflow,
	records natRecords,
	value isolatedstate.NATAllocation,
	detail any,
) (*mcp.CallToolResult, error) {
	status := "succeeded"
	phase := "ready"
	operationStatus := isolatedstate.OperationSucceeded
	var next any
	if value.ObservedState == isolatedstate.NATObservedDraining {
		status = "draining"
		phase = "draining"
		operationStatus = isolatedstate.OperationPaused
		next = map[string]any{
			"tool": "reconcile_isolated_vm_nat",
			"arguments": map[string]any{
				"isolated_vm_id":      value.VMID,
				"expected_generation": value.DesiredGeneration,
			},
			"condition": "after exact marked conntrack reaches zero",
		}
	}
	view, err := buildNATView(ctx, workflow.state.(isolatedNATState), natRecords{
		orchestrator: records.orchestrator,
		network:      records.network, vm: records.vm, local: value,
	}, nil)
	if err != nil {
		return isolatedError(err)
	}
	return workflow.finish(ctx, operationStatus, isolatedToolResult{
		Status: status, Phase: phase, ResourceID: value.VMID,
		Generation: int64(value.DesiredGeneration), Resource: view,
		Detail: detail, NextAction: next,
	})
}
