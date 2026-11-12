package mcptools

import (
	"context"
	"encoding/hex"
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

type isolatedNetworkStateAdapter struct {
	state isolatedState
}

func (a isolatedNetworkStateAdapter) ListNetworks(ctx context.Context, orchestratorID string) ([]isolatedstate.PrivateNetwork, error) {
	return a.state.ListNetworks(ctx, orchestratorID)
}

func (a isolatedNetworkStateAdapter) CountActiveVMs(ctx context.Context, networkID string) (int, error) {
	return a.state.CountActiveVMs(ctx, networkID)
}

func (a isolatedNetworkStateAdapter) ImportNetworkReservation(
	ctx context.Context,
	value isolated.NetworkReservationImport,
) error {
	now := isolatedstate.UnixSeconds(time.Now().Unix())
	record := isolatedstate.PrivateNetwork{
		ID: value.NetworkID, OrchestratorID: value.OrchestratorID,
		DisplayName: value.NetworkID, SubnetIndex: value.SubnetIndex,
		CIDR: value.CIDR, GatewayIPv4: value.GatewayIPv4,
		OrchestratorMAC: value.OrchestratorMAC, DNSServersJSON: "[]",
		DesiredGeneration:  value.DesiredGeneration,
		AppliedGeneration:  value.AppliedGeneration,
		ObservedGeneration: value.ObservedGeneration,
		LifecycleState:     isolatedstate.NetworkAllocating,
		CreatedAt:          now, UpdatedAt: now,
	}
	names, err := isolated.ParseNetworkID(value.NetworkID)
	if err != nil {
		return err
	}
	physical, err := isolated.NetworkNames(names)
	if err != nil {
		return err
	}
	record.HyperVSwitchName = physical.HyperVSwitchName
	if value.HyperVSwitchGUID != "" {
		record.HyperVSwitchGUID = optionalTrimmed(value.HyperVSwitchGUID)
	}
	if value.OrchestratorAdapterID != "" {
		record.OrchestratorAdapterID = optionalTrimmed(value.OrchestratorAdapterID)
	}
	if err := a.state.PutNetwork(ctx, record); err != nil {
		return err
	}
	return a.state.CommitAllocations(ctx, []isolatedstate.ActiveResourceAllocation{
		{
			Kind: "subnet", ScopeID: value.OrchestratorID,
			Value: fmt.Sprint(value.SubnetIndex), ResourceID: value.NetworkID,
			ApplianceReservationID: value.ReservationID, AllocatedAt: now,
		},
		{
			Kind: "network_mac", ScopeID: value.OrchestratorID,
			Value: value.OrchestratorMAC, ResourceID: value.NetworkID,
			ApplianceReservationID: value.ReservationID, AllocatedAt: now,
		},
	})
}

type isolatedNetworkHostAdapter struct {
	host  isolatedHost
	state isolatedState
	reg   func(string) (Target, error)
}

func (a isolatedNetworkHostAdapter) ObserveNetwork(
	ctx context.Context,
	query isolated.NetworkHostQuery,
) (isolated.NetworkHostObservation, error) {
	orchestrator, err := a.state.GetOrchestrator(ctx, query.OrchestratorID)
	if err != nil {
		return isolated.NetworkHostObservation{}, err
	}
	target, err := a.reg(orchestrator.HostNode)
	if err != nil {
		return isolated.NetworkHostObservation{}, err
	}
	discovery, err := a.host.Discover(ctx, target, query.OrchestratorID, query.OrchestratorVMGUID)
	if err != nil {
		return isolated.NetworkHostObservation{}, err
	}
	var result isolated.NetworkHostObservation
	for _, value := range discovery.Switches {
		if value.Name != query.SwitchName {
			continue
		}
		result.SwitchExists = true
		result.SwitchName = value.Name
		result.SwitchGUID = value.SwitchGUID
		result.SwitchPrivate = value.Type == "Private"
		result.HostNICCount = value.HostNICCount
		result.ConnectedAdapters = value.ConnectedAdapters
		if value.Ownership != nil {
			result.SwitchOwned = true
			result.OwnedOrchestratorID = value.Ownership.OrchestratorID
			result.OwnedNetworkID = value.Ownership.NetworkID
		}
	}
	for _, value := range discovery.Adapters {
		if value.VMGUID != query.OrchestratorVMGUID || value.Name != query.OrchestratorAdapter {
			continue
		}
		result.AdapterExists = true
		result.AdapterName = value.Name
		result.AdapterID = value.AdapterID
		result.AdapterMAC = value.MAC
		result.AdapterSwitchGUID = value.SwitchGUID
		result.AdapterOwned = value.Ownership != nil
	}
	return result, nil
}

func RegisterIsolatedNetworkTools(s *server.MCPServer, deps *isolatedLifecycleDeps) {
	s.AddTool(mcp.NewTool("add_isolated_network",
		mcp.WithDescription("Allocate an appliance-authoritative /26 and create the exact private switch, orchestrator NIC, and gateway."),
		mcp.WithString("target", mcp.Description("Hyper-V target when selecting an orchestrator")),
		mcp.WithString("orchestrator_id", mcp.Description("Optional exact orchestrator UUID")),
		mcp.WithString("display_name", mcp.Description("Mutable display label")),
		mcp.WithBoolean("dry_run", mcp.Description("Resolve selection and plan without mutation")),
		mcp.WithString("operation_id"), mcp.WithBoolean("resume_exact"),
		mcp.WithNumber("expected_generation"),
	), addIsolatedNetworkHandler(deps))
	s.AddTool(mcp.NewTool("remove_isolated_network",
		mcp.WithDescription("Remove an empty managed private network by exact identities; refuses nonempty networks."),
		mcp.WithString("network_id", mcp.Required()),
		mcp.WithString("operation_id"), mcp.WithBoolean("resume_exact"),
		mcp.WithNumber("expected_generation"),
	), removeIsolatedNetworkHandler(deps))
}

func targetForOrchestrator(record isolatedstate.Orchestrator, regTarget func(string) (Target, error)) (Target, error) {
	return regTarget(record.HostNode)
}

func ensureNetworkAdapters(deps *isolatedLifecycleDeps) {
	if deps.networks == nil {
		deps.networks = isolatedNetworkStateAdapter{state: deps.state}
	}
	if deps.networkHost == nil {
		deps.networkHost = isolatedNetworkHostAdapter{
			host: deps.host, state: deps.state,
			reg: func(hostNode string) (Target, error) {
				return resolvePlanTarget(hostNode, deps.registry)
			},
		}
	}
}

func selectNetworkOrchestrator(
	ctx context.Context,
	deps *isolatedLifecycleDeps,
	target Target,
	explicit string,
) (isolatedstate.Orchestrator, error) {
	host, err := deps.host.PhysicalIdentity(ctx, target)
	if err != nil {
		return isolatedstate.Orchestrator{}, err
	}
	domain := isolated.OrchestratorDomain{
		State: deps.orchestrators, Probe: deps.probe, Host: deps.planner,
	}
	result, err := domain.Select(ctx, isolated.SelectionRequest{
		PhysicalHostID: host.PhysicalHostID, ExplicitOrchestrator: explicit,
		Operation: isolated.OperationAddNetwork, ServerVersion: deps.serverVersion,
	})
	if err != nil {
		return isolatedstate.Orchestrator{}, err
	}
	return result.Orchestrator, nil
}

func addIsolatedNetworkHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ensureNetworkAdapters(deps)
		target, err := resolveTarget(req, deps.registry)
		if err != nil {
			return isolatedError(err)
		}
		explicit := strings.TrimSpace(req.GetString("orchestrator_id", ""))
		if explicit != "" {
			if _, err := isolated.ParseOrchestratorID(explicit); err != nil {
				return isolatedError(err)
			}
		}
		orchestrator, err := selectNetworkOrchestrator(ctx, deps, target, explicit)
		if err != nil {
			return isolatedError(err)
		}
		target, err = targetForOrchestrator(orchestrator, func(name string) (Target, error) {
			return resolvePlanTarget(name, deps.registry)
		})
		if err != nil {
			return isolatedError(err)
		}
		operationID, err := isolatedOperationID(req)
		if err != nil {
			return isolatedError(err)
		}
		resumedResource, err := resumeResourceID(ctx, deps.state, operationID, "network")
		if err != nil {
			return isolatedError(err)
		}
		networkID, err := isolated.NewNetworkID()
		if raw := strings.TrimSpace(req.GetString("network_id", "")); raw != "" {
			networkID, err = isolated.ParseNetworkID(raw)
		} else if resumedResource != "" {
			networkID, err = isolated.ParseNetworkID(resumedResource)
		}
		if err != nil {
			return isolatedError(err)
		}
		displayName := strings.TrimSpace(req.GetString("display_name", ""))
		if displayName == "" {
			displayName = "isolated-network-" + networkID.Short()
		}
		expected, err := expectedGeneration(req, orchestrator.DesiredGeneration)
		if err != nil {
			return isolatedError(err)
		}
		discovery, err := deps.host.Discover(ctx, target, orchestrator.ID, valueOrEmpty(orchestrator.HyperVVMID))
		if err != nil {
			return isolatedError(err)
		}
		if req.GetBool("dry_run", false) {
			snapshot, snapErr := deps.appliance.GetApplianceState(ctx, orchestrator.ID)
			if snapErr != nil {
				return isolatedError(snapErr)
			}
			capacity := isolated.ObserveNetworkCapacity(snapshot, discovery.Routes)
			return isolatedResult(isolatedToolResult{
				OperationID: operationID, Status: "planned", Phase: "dry_run",
				ResourceID: networkID.String(), Plan: map[string]any{
					"orchestrator": orchestrator.ID, "display_name": displayName,
					"capacity": capacity, "approval_required": false,
				}, NextAction: nil,
			}), nil
		}
		inputs := map[string]any{
			"target": target.Name, "orchestrator_id": orchestrator.ID,
			"network_id": networkID.String(), "display_name": displayName,
			"expected_generation": expected,
		}
		progress, stop := StartMCPProgress(ctx, req, 15*time.Minute, "allocate", "reserving network resources on the appliance")
		defer stop()
		workflow, err := beginIsolatedWorkflow(ctx, deps.state, progress, isolatedstate.BeginOperationRequest{
			ID: operationID, Kind: "add_isolated_network", ResourceType: "network",
			ResourceID: networkID.String(), HostNode: &orchestrator.HostNode,
			OrchestratorID:  optionalTrimmed(orchestrator.ID),
			CanonicalInputs: inputs, ResumeExact: req.GetBool("resume_exact", false),
		})
		if err != nil {
			return isolatedError(err)
		}
		orchestratorLock, _ := isolatedstate.OrchestratorLockKey(orchestrator.ID)
		lease, err := deps.locks.Acquire(ctx, isolatedstate.LockAcquireRequest{
			Key: orchestratorLock, OperationID: operationID, TTL: isolatedOperationTTL,
		})
		if err != nil {
			return isolatedError(err)
		}
		defer deps.locks.Release(context.Background(), lease)
		networkLock, _ := isolatedstate.NetworkLockKey(networkID.String())
		networkLease, err := deps.locks.Acquire(ctx, isolatedstate.LockAcquireRequest{
			Key: networkLock, OperationID: operationID, TTL: isolatedOperationTTL,
		})
		if err != nil {
			return isolatedError(err)
		}
		defer deps.locks.Release(context.Background(), networkLease)

		lockKey, _ := hyperv.HostOrchestratorCreateLockKey(orchestrator.PhysicalHostID)
		hostLease, err := deps.host.AcquireFence(ctx, target, isolated.HostCreateFenceRequest{
			PhysicalHostID: orchestrator.PhysicalHostID, HostNode: orchestrator.HostNode,
			OperationID: operationID, LockKey: lockKey,
		})
		if err != nil {
			return isolatedError(err)
		}
		defer deps.host.ReleaseFence(context.Background(), target, hostLease)
		orchestrator.HostFence = hostLease.Fence
		if err := deps.state.PutOrchestrator(ctx, orchestrator); err != nil {
			return isolatedError(err)
		}

		domain := isolated.NetworkDomain{
			State: deps.networks, Appliance: deps.appliance, Host: deps.networkHost,
		}
		var plan isolated.AddNetworkPlan
		err = workflow.phase(ctx, 0, "allocate", "appliance-authoritative subnet and MAC reservation", func() (any, error) {
			var planErr error
			plan, planErr = domain.ReserveAndPlan(ctx, isolated.AddNetworkRequest{
				OperationID: operationID, Orchestrator: orchestrator,
				NetworkID: networkID, DisplayName: displayName,
				ExpectedParentGeneration: expected, Routes: discovery.Routes,
				HostFence: hostLease.Fence,
			})
			return plan, planErr
		})
		if err != nil {
			return isolatedError(err)
		}
		if plan.Network.ID == "" {
			if _, err := workflow.loadPhase(ctx, 0, "allocate", &plan); err != nil {
				return isolatedError(err)
			}
		}
		names, _ := isolated.NetworkNames(networkID)
		guard := func(action, phase string) hyperv.IsolatedMutationGuard {
			return hyperv.IsolatedMutationGuard{
				PhysicalHostID: orchestrator.PhysicalHostID,
				LeaseID:        hostLease.LeaseID, LeaseSecret: hostLease.LeaseSecret,
				Fence: hostLease.Fence, OrchestratorID: orchestrator.ID,
				OperationID:  operationID,
				MutationID:   isolatedstate.StableMutationID(operationID, networkID.String(), action, phase),
				ResourceType: "network", ResourceID: networkID.String(), Action: action,
			}
		}
		var switchResult hyperv.IsolatedSwitchMutationResult
		err = workflow.phase(ctx, 1, "create_private_switch", "creating or verifying exact private vSwitch identity", func() (any, error) {
			owner, ownerErr := hyperv.IsolatedOwnerMarker(orchestrator.ID, "network", networkID.String())
			if ownerErr != nil {
				return nil, ownerErr
			}
			var runErr error
			switchResult, runErr = deps.host.CreateSwitch(ctx, target, hyperv.CreateIsolatedPrivateSwitchParams{
				Guard:              guard("create_private_switch", "create_private_switch"),
				OrchestratorVMGUID: valueOrEmpty(orchestrator.HyperVVMID),
				Metadata: hyperv.IsolatedNetworkMetadata{
					SchemaVersion:  hyperv.IsolatedMetadataSchema,
					PhysicalHostID: orchestrator.PhysicalHostID,
					OrchestratorID: orchestrator.ID, NetworkID: networkID.String(),
					OwnerMarker: owner, HostFence: hostLease.Fence,
					MutationID: isolatedstate.StableMutationID(operationID, networkID.String(), "create_private_switch", "create_private_switch"),
					Generation: 1, State: "creating", SwitchName: names.HyperVSwitchName,
					OrchestratorVMGUID:  valueOrEmpty(orchestrator.HyperVVMID),
					OrchestratorAdapter: names.OrchestratorAdapterName,
					OrchestratorMAC:     plan.Network.OrchestratorMAC,
				},
			})
			return switchResult, runErr
		})
		if err != nil {
			return isolatedError(err)
		}
		if switchResult.SwitchGUID == "" {
			if _, err := workflow.loadPhase(ctx, 1, "create_private_switch", &switchResult); err != nil {
				return isolatedError(err)
			}
		}
		var adapterResult hyperv.IsolatedAdapterMutationResult
		err = workflow.phase(ctx, 2, "add_orchestrator_nic", "attaching exact static-MAC orchestrator NIC", func() (any, error) {
			var runErr error
			adapterResult, runErr = deps.host.AttachNIC(ctx, target, hyperv.AttachIsolatedNICParams{
				Guard:     guard("attach_nic", "add_orchestrator_nic"),
				NetworkID: networkID.String(), ResourceType: "network",
				ResourceID:         networkID.String(),
				OrchestratorVMGUID: valueOrEmpty(orchestrator.HyperVVMID),
				VMGUID:             valueOrEmpty(orchestrator.HyperVVMID),
				AdapterName:        names.OrchestratorAdapterName,
				SwitchGUID:         switchResult.SwitchGUID,
				MAC:                plan.Network.OrchestratorMAC, Generation: 1,
			})
			return adapterResult, runErr
		})
		if err != nil {
			return isolatedError(err)
		}
		if adapterResult.AdapterID == "" {
			if _, err := workflow.loadPhase(ctx, 2, "add_orchestrator_nic", &adapterResult); err != nil {
				return isolatedError(err)
			}
		}
		var applied isolated.NetworkMutationResult
		err = workflow.phase(ctx, 3, "appliance_apply_network", "applying gateway configuration on the appliance", func() (any, error) {
			semantic, hashErr := isolatedstate.SemanticHash(plan.Plan.Inputs)
			if hashErr != nil {
				return nil, hashErr
			}
			var runErr error
			applied, runErr = deps.appliance.ApplyPrivateNetwork(ctx, orchestrator.ID, isolated.ApplyPrivateNetworkInput{
				Header: isolated.MutationEnvelope{
					Header: appliance.MutationHeader{
						ParentOperationID: operationID,
						MutationID:        isolatedstate.StableMutationID(operationID, networkID.String(), "apply_network", "appliance_apply_network"),
						SemanticHash:      semantic, ResourceID: networkID.String(),
						ParentResourceID:   orchestrator.ID,
						ExpectedGeneration: 0, NewGeneration: 1,
						HostFence:                uint64(hostLease.Fence),
						ExpectedParentGeneration: uint64(expected),
					},
					PhysicalHostID:  orchestrator.PhysicalHostID,
					HostLeaseID:     hostLease.LeaseID,
					HostLeaseSecret: mustDecodeHex(hostLease.LeaseSecret),
				},
				ReservationID: plan.Reservation.ID, CIDR: plan.Network.CIDR,
				GatewayIPv4: plan.Network.GatewayIPv4,
				NICMAC:      plan.Network.OrchestratorMAC, DNSServers: []string{},
			})
			return applied, runErr
		})
		if err != nil {
			return isolatedError(err)
		}
		plan.Network.HyperVSwitchGUID = optionalTrimmed(switchResult.SwitchGUID)
		plan.Network.OrchestratorAdapterID = optionalTrimmed(adapterResult.AdapterID)
		plan.Network.AppliedGeneration = 1
		plan.Network.ObservedGeneration = 1
		plan.Network.LifecycleState = isolatedstate.NetworkReady
		plan.Network.UpdatedAt = isolatedstate.UnixSeconds(time.Now().Unix())
		if err := deps.state.PutNetwork(ctx, plan.Network); err != nil {
			return isolatedError(err)
		}
		orchestrator.DesiredGeneration = isolatedstate.Generation(plan.ResultingParentGeneration)
		orchestrator.AppliedGeneration = orchestrator.DesiredGeneration
		orchestrator.ObservedGeneration = orchestrator.DesiredGeneration
		orchestrator.UpdatedAt = isolatedstate.UnixSeconds(time.Now().Unix())
		if err := deps.state.PutOrchestrator(ctx, orchestrator); err != nil {
			return isolatedError(err)
		}
		return workflow.finish(ctx, isolatedstate.OperationSucceeded, isolatedToolResult{
			Status: "succeeded", Phase: "ready", ResourceID: plan.Network.ID,
			Generation: int64(plan.Network.DesiredGeneration),
			Resource:   plan.Network, NextAction: nil,
		})
	}
}

func mustDecodeHex(value string) []byte {
	decoded, _ := hexDecodeString(value)
	return decoded
}

var hexDecodeString = func(value string) ([]byte, error) {
	return hex.DecodeString(value)
}

func removeIsolatedNetworkHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ensureNetworkAdapters(deps)
		id, err := isolated.ParseNetworkID(req.GetString("network_id", ""))
		if err != nil {
			return isolatedError(err)
		}
		network, err := deps.state.GetNetwork(ctx, id.String())
		if err != nil {
			return isolatedError(err)
		}
		orchestrator, err := deps.state.GetOrchestrator(ctx, network.OrchestratorID)
		if err != nil {
			return isolatedError(err)
		}
		expected, err := expectedGeneration(req, network.DesiredGeneration)
		if err != nil {
			return isolatedError(err)
		}
		guests, err := deps.state.CountActiveVMs(ctx, network.ID)
		if err != nil {
			return isolatedError(err)
		}
		if guests != 0 {
			return isolatedError(fmt.Errorf("NETWORK_NOT_EMPTY: network %s has %d non-deleted guests", network.ID, guests))
		}
		target, err := resolvePlanTarget(orchestrator.HostNode, deps.registry)
		if err != nil {
			return isolatedError(err)
		}
		discovery, err := deps.host.Discover(ctx, target, orchestrator.ID, valueOrEmpty(orchestrator.HyperVVMID))
		if err != nil {
			return isolatedError(err)
		}
		names, _ := isolated.NetworkNames(id)
		observation, err := deps.networkHost.ObserveNetwork(ctx, isolated.NetworkHostQuery{
			PhysicalHostID: orchestrator.PhysicalHostID, OrchestratorID: orchestrator.ID,
			OrchestratorVMGUID: valueOrEmpty(orchestrator.HyperVVMID),
			NetworkID:          network.ID, SwitchName: names.HyperVSwitchName,
			OrchestratorAdapter: names.OrchestratorAdapterName,
		})
		if err != nil {
			return isolatedError(err)
		}
		operationID, err := isolatedOperationID(req)
		if err != nil {
			return isolatedError(err)
		}
		domain := isolated.NetworkDomain{State: deps.networks, Appliance: deps.appliance, Host: deps.networkHost}
		plan, err := domain.BuildRemovePlan(ctx, isolated.RemoveNetworkRequest{
			OperationID: operationID, Network: network,
			ExpectedGeneration: expected, Host: observation,
		})
		if err != nil {
			return isolatedError(err)
		}
		_ = discovery
		progress, stop := StartMCPProgress(ctx, req, 10*time.Minute, "remove", "retiring appliance network before host removal")
		defer stop()
		workflow, err := beginIsolatedWorkflow(ctx, deps.state, progress, isolatedstate.BeginOperationRequest{
			ID: operationID, Kind: "remove_isolated_network",
			ResourceType: "network", ResourceID: network.ID,
			HostNode: &orchestrator.HostNode, OrchestratorID: optionalTrimmed(orchestrator.ID),
			NetworkID: optionalTrimmed(network.ID), CanonicalInputs: plan.Inputs,
			ResumeExact: req.GetBool("resume_exact", false),
		})
		if err != nil {
			return isolatedError(err)
		}
		lockKey, _ := hyperv.HostOrchestratorCreateLockKey(orchestrator.PhysicalHostID)
		hostLease, err := deps.host.AcquireFence(ctx, target, isolated.HostCreateFenceRequest{
			PhysicalHostID: orchestrator.PhysicalHostID, HostNode: orchestrator.HostNode,
			OperationID: operationID, LockKey: lockKey,
		})
		if err != nil {
			return isolatedError(err)
		}
		defer deps.host.ReleaseFence(context.Background(), target, hostLease)
		header := isolated.MutationEnvelope{
			Header: appliance.MutationHeader{
				ParentOperationID: operationID,
				MutationID:        isolatedstate.StableMutationID(operationID, network.ID, "remove_network", "appliance_remove_network"),
				SemanticHash:      plan.SemanticHash, ResourceID: network.ID,
				ParentResourceID:   orchestrator.ID,
				ExpectedGeneration: uint64(expected), NewGeneration: uint64(expected + 1),
				HostFence:                uint64(hostLease.Fence),
				ExpectedParentGeneration: uint64(orchestrator.DesiredGeneration),
			},
			PhysicalHostID: orchestrator.PhysicalHostID,
			HostLeaseID:    hostLease.LeaseID, HostLeaseSecret: mustDecodeHex(hostLease.LeaseSecret),
		}
		if err := workflow.phase(ctx, 0, "appliance_remove_network", "retiring gateway and network policy", func() (any, error) {
			return deps.appliance.RemovePrivateNetwork(ctx, orchestrator.ID, header)
		}); err != nil {
			return isolatedError(err)
		}
		guard := func(action, phase string) hyperv.IsolatedMutationGuard {
			return hyperv.IsolatedMutationGuard{
				PhysicalHostID: orchestrator.PhysicalHostID,
				LeaseID:        hostLease.LeaseID, LeaseSecret: hostLease.LeaseSecret,
				Fence: hostLease.Fence, OrchestratorID: orchestrator.ID,
				OperationID:  operationID,
				MutationID:   isolatedstate.StableMutationID(operationID, network.ID, action, phase),
				ResourceType: "network", ResourceID: network.ID, Action: action,
			}
		}
		if err := workflow.phase(ctx, 1, "remove_orchestrator_nic", "removing exact orchestrator adapter", func() (any, error) {
			return deps.host.RemoveNIC(ctx, target, hyperv.RemoveIsolatedNICParams{
				Guard:     guard("remove_nic", "remove_orchestrator_nic"),
				NetworkID: network.ID, ResourceType: "network", ResourceID: network.ID,
				OrchestratorVMGUID: valueOrEmpty(orchestrator.HyperVVMID),
				VMGUID:             valueOrEmpty(orchestrator.HyperVVMID),
				AdapterName:        names.OrchestratorAdapterName,
				ExpectedAdapterID:  valueOrEmpty(network.OrchestratorAdapterID),
				ExpectedSwitchGUID: valueOrEmpty(network.HyperVSwitchGUID),
				ExpectedMAC:        network.OrchestratorMAC,
				ExpectedGeneration: int64(expected),
			})
		}); err != nil {
			return isolatedError(err)
		}
		if err := workflow.phase(ctx, 2, "delete_private_switch", "deleting exact empty private switch", func() (any, error) {
			return deps.host.DeleteSwitch(ctx, target, hyperv.DeleteIsolatedPrivateSwitchParams{
				Guard:              guard("delete_private_switch", "delete_private_switch"),
				OrchestratorVMGUID: valueOrEmpty(orchestrator.HyperVVMID),
				NetworkID:          network.ID, SwitchName: network.HyperVSwitchName,
				ExpectedSwitchGUID: valueOrEmpty(network.HyperVSwitchGUID),
				ExpectedGeneration: int64(expected),
			})
		}); err != nil {
			return isolatedError(err)
		}
		now := isolatedstate.UnixSeconds(time.Now().Unix())
		network.DesiredGeneration = expected + 1
		network.AppliedGeneration = network.DesiredGeneration
		network.ObservedGeneration = network.DesiredGeneration
		network.LifecycleState = isolatedstate.NetworkDeleted
		network.RetiredAt = &now
		network.UpdatedAt = now
		if err := deps.state.PutNetwork(ctx, network); err != nil {
			return isolatedError(err)
		}
		for kind, value := range map[string]string{
			"subnet": fmt.Sprint(network.SubnetIndex), "network_mac": network.OrchestratorMAC,
		} {
			_, _ = deps.state.ReleaseAllocation(ctx, isolatedstate.ReleaseAllocationRequest{
				Kind: kind, ScopeID: orchestrator.ID, Value: value,
				ResourceID: network.ID, ReleaseOperationID: operationID, ReleasedAt: now,
			})
		}
		return workflow.finish(ctx, isolatedstate.OperationSucceeded, isolatedToolResult{
			Status: "succeeded", Phase: "deleted", ResourceID: network.ID,
			Generation: int64(network.DesiredGeneration), Resource: network, NextAction: nil,
		})
	}
}
