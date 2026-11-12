package mcptools

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/isolated"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
)

func RegisterIsolatedRelayTools(s *server.MCPServer, deps *isolatedLifecycleDeps) {
	s.AddTool(mcp.NewTool("create_isolated_relay",
		mcp.WithDescription("Create a managed relay to exactly one managed guest TCP port 9091."),
		mcp.WithString("orchestrator_id", mcp.Required()),
		mcp.WithString("isolated_vm_id", mcp.Required()),
		mcp.WithNumber("listen_port", mcp.Description("Optional exact recovery port in 20000-39999")),
		mcp.WithString("operation_id"), mcp.WithBoolean("resume_exact"),
		mcp.WithNumber("expected_generation"),
	), createIsolatedRelayHandler(deps, false))
	s.AddTool(mcp.NewTool("remove_isolated_relay",
		mcp.WithDescription("Retire a relay using the accept/dial/drain barrier; the guest may remain live."),
		mcp.WithString("relay_id", mcp.Required()),
		mcp.WithString("operation_id"), mcp.WithBoolean("resume_exact"),
		mcp.WithNumber("expected_generation"),
	), removeIsolatedRelayHandler(deps))
	s.AddTool(mcp.NewTool("list_isolated_relays",
		mcp.WithDescription("List locally known relays and optionally appliance-live mappings."),
		mcp.WithString("orchestrator_id"), mcp.WithString("network_id"),
		mcp.WithBoolean("live"),
	), listIsolatedRelaysHandler(deps))
	s.AddTool(mcp.NewTool("get_isolated_relay_stats",
		mcp.WithDescription("Get exact relay stats or aggregate an orchestrator's relay stats."),
		mcp.WithString("relay_id"), mcp.WithString("orchestrator_id"),
	), getIsolatedRelayStatsHandler(deps))
	s.AddTool(mcp.NewTool("rebind_isolated_relays",
		mcp.WithDescription("Rebind all managed listeners to the orchestrator's current main IPv4 without changing ports."),
		mcp.WithString("orchestrator_id", mcp.Required()),
		mcp.WithString("operation_id"), mcp.WithBoolean("resume_exact"),
		mcp.WithNumber("expected_generation"),
	), rebindIsolatedRelaysHandler(deps))
	s.AddTool(mcp.NewTool("validate_isolated_relay",
		mcp.WithDescription("Validate listener, mapping, generation, and optional TCP reachability to guest:9091."),
		mcp.WithString("relay_id", mcp.Required()),
		mcp.WithBoolean("probe_target"),
	), validateIsolatedRelayHandler(deps))
	s.AddTool(mcp.NewTool("adopt_isolated_relay",
		mcp.WithDescription("Adopt only an exact already-live managed relay mapping."),
		mcp.WithString("orchestrator_id", mcp.Required()),
		mcp.WithString("relay_id", mcp.Required()),
		mcp.WithString("isolated_vm_id", mcp.Required()),
		mcp.WithString("network_id", mcp.Required()),
		mcp.WithNumber("observed_generation", mcp.Required()),
		mcp.WithString("operation_id"), mcp.WithBoolean("resume_exact"),
		mcp.WithNumber("expected_generation"),
	), createIsolatedRelayHandler(deps, true))
}

func relayPort(snapshot appliance.DesiredSnapshot, explicit int) (int, error) {
	used := map[int]bool{}
	for _, reservation := range snapshot.Reservations {
		if reservation.RetiredAtUnix == nil && reservation.ListenPort != nil {
			used[int(*reservation.ListenPort)] = true
		}
	}
	if explicit != 0 {
		if explicit < appliance.RelayPortMin || explicit > appliance.RelayPortMax {
			return 0, fmt.Errorf("listen_port must be between %d and %d", appliance.RelayPortMin, appliance.RelayPortMax)
		}
		if used[explicit] {
			return 0, fmt.Errorf("PORT_IN_USE: listen port %d is already reserved", explicit)
		}
		return explicit, nil
	}
	for port := appliance.RelayPortMin; port <= appliance.RelayPortMax; port++ {
		if !used[port] {
			return port, nil
		}
	}
	return 0, fmt.Errorf("RELAY_CAPACITY_EXHAUSTED: no relay port remains")
}

func relayEnvelope(
	operationID, relayID, parentID, semantic string,
	expected, next isolatedstate.Generation,
	orchestrator isolatedstate.Orchestrator,
	lease isolated.HostFenceLease,
	phase string,
) isolated.MutationEnvelope {
	return isolated.MutationEnvelope{
		Header: appliance.MutationHeader{
			ParentOperationID: operationID,
			MutationID:        isolatedstate.StableMutationID(operationID, relayID, semantic, phase),
			SemanticHash:      semantic, ResourceID: relayID, ParentResourceID: parentID,
			ExpectedGeneration: uint64(expected), NewGeneration: uint64(next),
			HostFence:                uint64(lease.Fence),
			ExpectedParentGeneration: uint64(orchestrator.DesiredGeneration),
		},
		PhysicalHostID: orchestrator.PhysicalHostID,
		HostLeaseID:    lease.LeaseID, HostLeaseSecret: mustDecodeHex(lease.LeaseSecret),
	}
}

func createIsolatedRelayHandler(deps *isolatedLifecycleDeps, adopt bool) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		orchestratorID, err := isolated.ParseOrchestratorID(req.GetString("orchestrator_id", ""))
		if err != nil {
			return isolatedError(err)
		}
		vmID, err := isolated.ParseVMID(req.GetString("isolated_vm_id", ""))
		if err != nil {
			return isolatedError(err)
		}
		orchestrator, err := deps.state.GetOrchestrator(ctx, orchestratorID.String())
		if err != nil {
			return isolatedError(err)
		}
		vm, err := deps.state.GetVM(ctx, vmID.String())
		if err != nil {
			return isolatedError(err)
		}
		if vm.OrchestratorID != orchestrator.ID || vm.LifecycleState == isolatedstate.VMDeleted {
			return isolatedError(fmt.Errorf("RELAY_TARGET_UNMANAGED: VM %s is not a live managed guest of orchestrator %s", vm.ID, orchestrator.ID))
		}
		if adopt {
			networkID, parseErr := isolated.ParseNetworkID(req.GetString("network_id", ""))
			if parseErr != nil {
				return isolatedError(parseErr)
			}
			if vm.NetworkID != networkID.String() {
				return isolatedError(fmt.Errorf("RELAY_NETWORK_MISMATCH: VM belongs to %s", vm.NetworkID))
			}
		}
		operationID, err := isolatedOperationID(req)
		if err != nil {
			return isolatedError(err)
		}
		resumed, err := resumeResourceID(ctx, deps.state, operationID, "relay")
		if err != nil {
			return isolatedError(err)
		}
		var relayID isolated.RelayID
		if raw := strings.TrimSpace(req.GetString("relay_id", "")); raw != "" {
			relayID, err = isolated.ParseRelayID(raw)
		} else if resumed != "" {
			relayID, err = isolated.ParseRelayID(resumed)
		} else {
			relayID, err = isolated.NewRelayID()
		}
		if err != nil {
			return isolatedError(err)
		}
		existing, existingErr := deps.state.GetRelayForVM(ctx, vm.ID)
		if existingErr == nil && existing.ID != relayID.String() {
			return isolatedError(fmt.Errorf("RELAY_ALREADY_EXISTS: VM %s already owns relay %s", vm.ID, existing.ID))
		}
		if existingErr != nil && !errors.Is(existingErr, isolatedstate.ErrRelayNotFound) {
			return isolatedError(existingErr)
		}
		expected := isolatedstate.Generation(0)
		if existingErr == nil {
			expected, err = expectedGeneration(req, existing.DesiredGeneration)
			if err != nil {
				return isolatedError(err)
			}
		}
		target, err := resolvePlanTarget(orchestrator.HostNode, deps.registry)
		if err != nil {
			return isolatedError(err)
		}
		inputs := map[string]any{
			"orchestrator_id": orchestrator.ID, "relay_id": relayID.String(),
			"isolated_vm_id": vm.ID, "network_id": vm.NetworkID,
			"target_ipv4": vm.IPv4, "target_port": appliance.RelayTargetPort,
			"adopt": adopt,
		}
		progress, stop := StartMCPProgress(ctx, req, 5*time.Minute, "reserve", "reserving relay port")
		defer stop()
		kind := "create_isolated_relay"
		if adopt {
			kind = "adopt_isolated_relay"
		}
		workflow, err := beginIsolatedWorkflow(ctx, deps.state, progress, isolatedstate.BeginOperationRequest{
			ID: operationID, Kind: kind, ResourceType: "relay",
			ResourceID: relayID.String(), HostNode: &orchestrator.HostNode,
			OrchestratorID: optionalTrimmed(orchestrator.ID),
			NetworkID:      optionalTrimmed(vm.NetworkID), CanonicalInputs: inputs,
			ResumeExact: req.GetBool("resume_exact", false),
		})
		if err != nil {
			return isolatedError(err)
		}
		childKey, _ := isolatedstate.RelayLockKey(relayID.String())
		localLease, err := deps.locks.Acquire(ctx, isolatedstate.LockAcquireRequest{
			Key: childKey, OperationID: operationID, TTL: isolatedOperationTTL,
		})
		if err != nil {
			return isolatedError(err)
		}
		defer deps.locks.Release(context.Background(), localLease)
		hostKey, _ := hyperv.HostOrchestratorCreateLockKey(orchestrator.PhysicalHostID)
		hostLease, err := deps.host.AcquireFence(ctx, target, isolated.HostCreateFenceRequest{
			PhysicalHostID: orchestrator.PhysicalHostID, HostNode: orchestrator.HostNode,
			OperationID: operationID, LockKey: hostKey,
		})
		if err != nil {
			return isolatedError(err)
		}
		defer deps.host.ReleaseFence(context.Background(), target, hostLease)
		snapshot, err := deps.appliance.GetApplianceState(ctx, orchestrator.ID)
		if err != nil {
			return isolatedError(err)
		}
		explicitPort := 0
		if value, ok := numericArgument(req.GetArguments()["listen_port"]); ok {
			explicitPort = int(value)
		}
		var reservation appliance.Reservation
		var port int
		err = workflow.phase(ctx, 0, "reserve", "reserving exact relay port on appliance", func() (any, error) {
			if adopt {
				for _, value := range snapshot.Reservations {
					if value.RetiredAtUnix == nil && value.ResourceKind == "relay" &&
						value.ResourceID == relayID.String() && value.ListenPort != nil {
						reservation = value
						port = int(*value.ListenPort)
						return reservation, nil
					}
				}
				return nil, fmt.Errorf("ADOPT_RESERVATION_MISSING: exact live relay reservation was not found")
			}
			var chooseErr error
			port, chooseErr = relayPort(snapshot, explicitPort)
			if chooseErr != nil {
				return nil, chooseErr
			}
			port64 := int64(port)
			reservation = appliance.Reservation{
				ID:           isolatedstate.StableMutationID(operationID, relayID.String(), "reserve_relay", "reservation") + "-relay",
				ResourceKind: "relay", ResourceID: relayID.String(),
				NetworkID: vm.NetworkID, ListenPort: &port64,
				CapacityKind: "relay", CapacityUnits: 1,
			}
			semantic, hashErr := isolatedstate.SemanticHash(inputs)
			if hashErr != nil {
				return nil, hashErr
			}
			result, reserveErr := deps.appliance.ReserveResources(ctx, orchestrator.ID, appliance.ReserveRequest{
				Header: appliance.MutationHeader{
					ParentOperationID: operationID,
					MutationID:        isolatedstate.StableMutationID(operationID, relayID.String(), "reserve_relay", "reserve"),
					SemanticHash:      semantic, ResourceID: relayID.String(),
					ParentResourceID: vm.ID, ExpectedGeneration: 0, NewGeneration: 1,
					HostFence:                uint64(hostLease.Fence),
					ExpectedParentGeneration: uint64(orchestrator.DesiredGeneration),
				},
				Reservations: []appliance.Reservation{reservation},
			})
			if reserveErr != nil {
				return nil, reserveErr
			}
			if len(result.Reservations) != 1 {
				return nil, fmt.Errorf("INVALID_APPLIANCE_RESPONSE: relay reservation missing")
			}
			reservation = result.Reservations[0]
			port = int(*reservation.ListenPort)
			return reservation, nil
		})
		if err != nil {
			return isolatedError(err)
		}
		if reservation.ID == "" {
			if _, err := workflow.loadPhase(ctx, 0, "reserve", &reservation); err != nil {
				return isolatedError(err)
			}
			if reservation.ListenPort == nil {
				return isolatedError(fmt.Errorf("INVALID_DURABLE_PHASE: relay reservation has no listen port"))
			}
			port = int(*reservation.ListenPort)
		}
		semantic, _ := isolatedstate.SemanticHash(map[string]any{
			"relay_id": relayID.String(), "vm_id": vm.ID, "network_id": vm.NetworkID,
			"listen_port": port, "target_ipv4": vm.IPv4, "target_port": 9091,
		})
		next := expected + 1
		envelope := relayEnvelope(operationID, relayID.String(), vm.ID, semantic,
			expected, next, orchestrator, hostLease, "relay_apply")
		var mutation isolated.RelayMutationResult
		err = workflow.phase(ctx, 1, "relay_bind", "binding managed listener to guest TCP 9091", func() (any, error) {
			input := isolated.RelayInput{
				Header: envelope, ReservationID: reservation.ID,
				VMID: vm.ID, NetworkID: vm.NetworkID,
				ListenPort: uint32(port), TargetIPv4: vm.IPv4,
			}
			var applyErr error
			if adopt {
				mutation, applyErr = deps.appliance.AdoptRelay(ctx, orchestrator.ID, input)
			} else {
				mutation, applyErr = deps.appliance.ApplyRelay(ctx, orchestrator.ID, input)
			}
			return mutation, applyErr
		})
		if err != nil {
			return isolatedError(err)
		}
		if mutation.Relay.ID == "" {
			if _, err := workflow.loadPhase(ctx, 1, "relay_bind", &mutation); err != nil {
				return isolatedError(err)
			}
		}
		now := isolatedstate.UnixSeconds(time.Now().Unix())
		record := isolatedstate.RelayAllocation{
			ID: relayID.String(), VMID: vm.ID, OrchestratorID: orchestrator.ID,
			ListenPort: port, TargetIPv4: vm.IPv4, TargetPort: 9091,
			DesiredGeneration:  next,
			AppliedGeneration:  isolatedstate.Generation(mutation.Relay.AppliedGeneration),
			ObservedGeneration: isolatedstate.Generation(mutation.Relay.ObservedGeneration),
			LifecycleState:     isolatedstate.RelayReady,
			CreatedAt:          now, UpdatedAt: now,
		}
		if err := deps.state.PutRelay(ctx, record); err != nil {
			return isolatedError(err)
		}
		if err := deps.state.CommitAllocations(ctx, []isolatedstate.ActiveResourceAllocation{{
			Kind: "relay_port", ScopeID: orchestrator.ID, Value: fmt.Sprint(port),
			ResourceID: record.ID, ApplianceReservationID: reservation.ID,
			AllocatedAt: now,
		}}); err != nil {
			return isolatedError(err)
		}
		return workflow.finish(ctx, isolatedstate.OperationSucceeded, isolatedToolResult{
			Status: "succeeded", Phase: "ready", ResourceID: record.ID,
			Generation: int64(record.DesiredGeneration), Resource: record, NextAction: nil,
		})
	}
}

func removeIsolatedRelayHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := isolated.ParseRelayID(req.GetString("relay_id", ""))
		if err != nil {
			return isolatedError(err)
		}
		relay, err := deps.state.GetRelay(ctx, id.String())
		if err != nil {
			return isolatedError(err)
		}
		vm, err := deps.state.GetVM(ctx, relay.VMID)
		if err != nil {
			return isolatedError(err)
		}
		orchestrator, err := deps.state.GetOrchestrator(ctx, relay.OrchestratorID)
		if err != nil {
			return isolatedError(err)
		}
		expected, err := expectedGeneration(req, relay.DesiredGeneration)
		if err != nil {
			return isolatedError(err)
		}
		operationID, err := isolatedOperationID(req)
		if err != nil {
			return isolatedError(err)
		}
		target, err := resolvePlanTarget(orchestrator.HostNode, deps.registry)
		if err != nil {
			return isolatedError(err)
		}
		hostKey, _ := hyperv.HostOrchestratorCreateLockKey(orchestrator.PhysicalHostID)
		hostLease, err := deps.host.AcquireFence(ctx, target, isolated.HostCreateFenceRequest{
			PhysicalHostID: orchestrator.PhysicalHostID, HostNode: orchestrator.HostNode,
			OperationID: operationID, LockKey: hostKey,
		})
		if err != nil {
			return isolatedError(err)
		}
		defer deps.host.ReleaseFence(context.Background(), target, hostLease)
		semantic, _ := isolatedstate.SemanticHash(map[string]any{
			"relay_id": relay.ID, "vm_id": vm.ID, "network_id": vm.NetworkID,
			"listen_port": relay.ListenPort, "semantic_action": "remove_relay",
		})
		progress, stop := StartMCPProgress(ctx, req, 5*time.Minute, "retire", "stopping accepts and draining relay connections")
		defer stop()
		workflow, err := beginIsolatedWorkflow(ctx, deps.state, progress, isolatedstate.BeginOperationRequest{
			ID: operationID, Kind: "remove_isolated_relay", ResourceType: "relay",
			ResourceID: relay.ID, HostNode: &orchestrator.HostNode,
			OrchestratorID:  optionalTrimmed(orchestrator.ID),
			NetworkID:       optionalTrimmed(vm.NetworkID),
			CanonicalInputs: map[string]any{"relay_id": relay.ID, "expected_generation": expected},
			ResumeExact:     req.GetBool("resume_exact", false),
		})
		if err != nil {
			return isolatedError(err)
		}
		envelope := relayEnvelope(operationID, relay.ID, vm.ID, semantic,
			expected, expected+1, orchestrator, hostLease, "relay_remove")
		if err := workflow.phase(ctx, 0, "retirement_barrier", "closing listener, canceling pending dials, and draining live copies", func() (any, error) {
			return deps.appliance.RemoveRelay(ctx, orchestrator.ID, envelope, vm.ID, vm.NetworkID)
		}); err != nil {
			return isolatedError(err)
		}
		snapshot, err := deps.appliance.GetApplianceState(ctx, orchestrator.ID)
		if err != nil {
			return isolatedError(err)
		}
		reservationID := ""
		for _, value := range snapshot.Reservations {
			if value.ResourceKind == "relay" && value.ResourceID == relay.ID {
				reservationID = value.ID
				break
			}
		}
		if reservationID != "" {
			_, err = deps.appliance.ReleaseResources(ctx, orchestrator.ID, appliance.ReleaseRequest{
				Header: appliance.MutationHeader{
					ParentOperationID: operationID,
					MutationID:        isolatedstate.StableMutationID(operationID, relay.ID, "release_relay", "release"),
					SemanticHash:      semantic, ResourceID: relay.ID, ParentResourceID: vm.ID,
					ExpectedGeneration: uint64(expected + 1), NewGeneration: uint64(expected + 1),
					HostFence:                uint64(hostLease.Fence),
					ExpectedParentGeneration: uint64(orchestrator.DesiredGeneration),
				},
				ReservationIDs: []string{reservationID},
			})
			if err != nil {
				return isolatedError(err)
			}
		}
		now := isolatedstate.UnixSeconds(time.Now().Unix())
		relay.DesiredGeneration = expected + 1
		relay.AppliedGeneration = relay.DesiredGeneration
		relay.ObservedGeneration = relay.DesiredGeneration
		relay.LifecycleState = isolatedstate.RelayRemoved
		relay.RetiredAt = &now
		relay.UpdatedAt = now
		if err := deps.state.PutRelay(ctx, relay); err != nil {
			return isolatedError(err)
		}
		_, _ = deps.state.ReleaseAllocation(ctx, isolatedstate.ReleaseAllocationRequest{
			Kind: "relay_port", ScopeID: orchestrator.ID,
			Value: fmt.Sprint(relay.ListenPort), ResourceID: relay.ID,
			ReleaseOperationID: operationID, ReleasedAt: now,
		})
		return workflow.finish(ctx, isolatedstate.OperationSucceeded, isolatedToolResult{
			Status: "succeeded", Phase: "removed", ResourceID: relay.ID,
			Generation: int64(relay.DesiredGeneration), Resource: relay, NextAction: nil,
		})
	}
}

func listIsolatedRelaysHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		orchestratorID := strings.TrimSpace(req.GetString("orchestrator_id", ""))
		networkID := strings.TrimSpace(req.GetString("network_id", ""))
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
		values, err := deps.state.ListRelays(ctx, orchestratorID, networkID)
		if err != nil {
			return isolatedError(err)
		}
		var live any
		if req.GetBool("live", false) {
			if orchestratorID == "" {
				return isolatedError(fmt.Errorf("orchestrator_id is required when live=true"))
			}
			live, err = deps.appliance.ListRelays(ctx, orchestratorID, networkID, "", true, 500, "")
			if err != nil {
				return isolatedError(err)
			}
		}
		return isolatedResult(isolatedToolResult{
			Status: "succeeded", Phase: "list", ResourceID: orchestratorID,
			Resource: values, Detail: live, NextAction: nil,
		}), nil
	}
}

func getIsolatedRelayStatsHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		relayID := strings.TrimSpace(req.GetString("relay_id", ""))
		orchestratorID := strings.TrimSpace(req.GetString("orchestrator_id", ""))
		if (relayID == "") == (orchestratorID == "") {
			return isolatedError(fmt.Errorf("provide exactly one of relay_id or orchestrator_id"))
		}
		if relayID != "" {
			id, err := isolated.ParseRelayID(relayID)
			if err != nil {
				return isolatedError(err)
			}
			relay, err := deps.state.GetRelay(ctx, id.String())
			if err != nil {
				return isolatedError(err)
			}
			stats, err := deps.appliance.GetRelayStats(ctx, relay.OrchestratorID, relay.ID)
			if err != nil {
				return isolatedError(err)
			}
			return isolatedResult(isolatedToolResult{
				Status: "succeeded", Phase: "stats", ResourceID: relay.ID,
				Resource: stats, NextAction: nil,
			}), nil
		}
		if _, err := isolated.ParseOrchestratorID(orchestratorID); err != nil {
			return isolatedError(err)
		}
		relays, err := deps.state.ListRelays(ctx, orchestratorID, "")
		if err != nil {
			return isolatedError(err)
		}
		aggregate := appliance.RelayStats{RelayID: "*", ListenerState: "ready"}
		for _, relay := range relays {
			if relay.RetiredAt != nil {
				continue
			}
			stats, statsErr := deps.appliance.GetRelayStats(ctx, orchestratorID, relay.ID)
			if statsErr != nil {
				aggregate.ListenerState = "degraded"
				aggregate.LastFailure = statsErr.Error()
				continue
			}
			aggregate.ActiveConnections += stats.ActiveConnections
			aggregate.TotalAcceptedConnections += stats.TotalAcceptedConnections
			aggregate.BytesGuestToMain += stats.BytesGuestToMain
			aggregate.BytesMainToGuest += stats.BytesMainToGuest
			aggregate.TargetDialFailureCount += stats.TargetDialFailureCount
			if stats.LastSuccessfulConnectionUnix > aggregate.LastSuccessfulConnectionUnix {
				aggregate.LastSuccessfulConnectionUnix = stats.LastSuccessfulConnectionUnix
			}
			if stats.ApplianceGeneration > aggregate.ApplianceGeneration {
				aggregate.ApplianceGeneration = stats.ApplianceGeneration
			}
		}
		return isolatedResult(isolatedToolResult{
			Status: "succeeded", Phase: "stats", ResourceID: orchestratorID,
			Resource: aggregate, NextAction: nil,
		}), nil
	}
}

func rebindIsolatedRelaysHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := isolated.ParseOrchestratorID(req.GetString("orchestrator_id", ""))
		if err != nil {
			return isolatedError(err)
		}
		orchestrator, err := deps.state.GetOrchestrator(ctx, id.String())
		if err != nil {
			return isolatedError(err)
		}
		expected, err := expectedGeneration(req, orchestrator.DesiredGeneration)
		if err != nil {
			return isolatedError(err)
		}
		operationID, err := isolatedOperationID(req)
		if err != nil {
			return isolatedError(err)
		}
		progress, stop := StartMCPProgress(ctx, req, 5*time.Minute, "rebind", "rebinding relay listeners")
		defer stop()
		workflow, err := beginIsolatedWorkflow(ctx, deps.state, progress, isolatedstate.BeginOperationRequest{
			ID: operationID, Kind: "rebind_isolated_relays",
			ResourceType: "orchestrator", ResourceID: orchestrator.ID,
			HostNode:       &orchestrator.HostNode,
			OrchestratorID: optionalTrimmed(orchestrator.ID),
			CanonicalInputs: map[string]any{
				"orchestrator_id": orchestrator.ID, "expected_generation": expected,
			},
			ResumeExact: req.GetBool("resume_exact", false),
		})
		if err != nil {
			return isolatedError(err)
		}
		target, err := resolvePlanTarget(orchestrator.HostNode, deps.registry)
		if err != nil {
			return isolatedError(err)
		}
		hostKey, _ := hyperv.HostOrchestratorCreateLockKey(orchestrator.PhysicalHostID)
		hostLease, err := deps.host.AcquireFence(ctx, target, isolated.HostCreateFenceRequest{
			PhysicalHostID: orchestrator.PhysicalHostID, HostNode: orchestrator.HostNode,
			OperationID: operationID, LockKey: hostKey,
		})
		if err != nil {
			return isolatedError(err)
		}
		defer deps.host.ReleaseFence(context.Background(), target, hostLease)
		semantic, _ := isolatedstate.SemanticHash(map[string]any{
			"orchestrator_id": orchestrator.ID, "semantic_action": "rebind_relays",
		})
		envelope := relayEnvelope(operationID, orchestrator.ID, orchestrator.ID,
			semantic, expected, expected+1, orchestrator, hostLease, "rebind")
		var relays []appliance.Relay
		var mutation isolated.MutationResult
		err = workflow.phaseAlways(ctx, 0, "rebind", "rebinding all listeners to current main IPv4", func() (any, error) {
			var rebindErr error
			relays, mutation, rebindErr = deps.appliance.RebindRelays(ctx, orchestrator.ID, envelope)
			return map[string]any{"relays": relays, "mutation": mutation}, rebindErr
		})
		if err != nil {
			return isolatedError(err)
		}
		orchestrator.DesiredGeneration = expected + 1
		orchestrator.AppliedGeneration = orchestrator.DesiredGeneration
		orchestrator.ObservedGeneration = orchestrator.DesiredGeneration
		orchestrator.UpdatedAt = isolatedstate.UnixSeconds(time.Now().Unix())
		if err := deps.state.PutOrchestrator(ctx, orchestrator); err != nil {
			return isolatedError(err)
		}
		return workflow.finish(ctx, isolatedstate.OperationSucceeded, isolatedToolResult{
			Status: "succeeded", Phase: "rebound",
			ResourceID: orchestrator.ID, Generation: int64(orchestrator.DesiredGeneration),
			Resource: relays, Detail: mutation, NextAction: nil,
		})
	}
}

func validateIsolatedRelayHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := isolated.ParseRelayID(req.GetString("relay_id", ""))
		if err != nil {
			return isolatedError(err)
		}
		relay, err := deps.state.GetRelay(ctx, id.String())
		if err != nil {
			return isolatedError(err)
		}
		validation, err := deps.appliance.ValidateRelay(ctx, relay.OrchestratorID, relay.ID, req.GetBool("probe_target", false))
		if err != nil {
			return isolatedError(err)
		}
		return isolatedResult(isolatedToolResult{
			Status: "succeeded", Phase: "validated", ResourceID: relay.ID,
			Generation: int64(relay.DesiredGeneration), Resource: validation,
			NextAction: nil,
		}), nil
	}
}

func sortedRelayPorts(values []isolatedstate.RelayAllocation) []int {
	result := make([]int, 0, len(values))
	for _, value := range values {
		result = append(result, value.ListenPort)
	}
	sort.Ints(result)
	return result
}
