package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/isolated"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
)

func RegisterIsolatedVMTools(s *server.MCPServer, deps *isolatedLifecycleDeps) {
	s.AddTool(mcp.NewTool("create_isolated_vm",
		mcp.WithDescription("Create and enroll an isolated Windows or Linux guest with appliance-authoritative static networking and relay identity."),
		mcp.WithString("network_id", mcp.Required()),
		mcp.WithString("display_name", mcp.Required()),
		mcp.WithString("guest_os", mcp.Required()),
		mcp.WithString("profile", mcp.Required()),
		mcp.WithBoolean("nat_enabled"),
		mcp.WithString("bootstrap_network_requirement"),
		mcp.WithBoolean("known_network_bootstrap"),
		mcp.WithArray("reachable_services", mcp.Description("Reachable service declarations as {kind,address,port} or kind=address[:port]")),
		windowsDomainJoinSchema("domain_join", "Optional post-relay Windows domain join"),
		mcp.WithString("isolated_vm_id"),
		mcp.WithString("operation_id"),
		mcp.WithBoolean("resume_exact"),
		mcp.WithNumber("expected_generation"),
	), createIsolatedVMHandler(deps))
	s.AddTool(mcp.NewTool("delete_isolated_vm",
		mcp.WithDescription("Delete the exact owned isolated VM, child storage, relay, NAT state, registry entry, and reservations."),
		mcp.WithString("isolated_vm_id", mcp.Required()),
		mcp.WithBoolean("delete_storage", mcp.Description("Delete exact owned child storage (default true)")),
		mcp.WithString("operation_id"), mcp.WithBoolean("resume_exact"),
		mcp.WithNumber("expected_generation"),
	), deleteIsolatedVMHandler(deps))
	s.AddTool(mcp.NewTool("list_isolated_vms",
		mcp.WithDescription("List isolated guests from durable state."),
		mcp.WithString("target"), mcp.WithString("orchestrator_id"),
		mcp.WithString("network_id"), mcp.WithBoolean("include_deleted"), mcp.WithBoolean("live"),
	), listIsolatedVMsHandler(deps))
	s.AddTool(mcp.NewTool("get_isolated_vm",
		mcp.WithDescription("Get one exact isolated guest."),
		mcp.WithString("isolated_vm_id", mcp.Required()), mcp.WithBoolean("live"),
	), getIsolatedVMHandler(deps))
	s.AddTool(mcp.NewTool("repair_isolated_vm",
		mcp.WithDescription("Reconcile an isolated guest non-destructively, then automatically recreate exact owned VM storage if required."),
		mcp.WithString("isolated_vm_id", mcp.Required()),
		mcp.WithString("operation_id"), mcp.WithBoolean("resume_exact"),
		mcp.WithNumber("expected_generation"),
	), repairIsolatedVMHandler(deps))
	s.AddTool(mcp.NewTool("rename_isolated_display_name",
		mcp.WithDescription("Update only the mutable display label; immutable VM, TLS, path, and allocation identities do not change."),
		mcp.WithString("resource_type", mcp.Required()),
		mcp.WithString("resource_id", mcp.Required()),
		mcp.WithString("display_name", mcp.Required()),
	), renameIsolatedDisplayNameHandler(deps))
}

type productionIsolatedGuestRuntime struct {
	deps *isolatedLifecycleDeps
}

func (r productionIsolatedGuestRuntime) Provision(
	ctx context.Context,
	vm isolatedstate.IsolatedVM,
	network isolatedstate.PrivateNetwork,
	orchestrator isolatedstate.Orchestrator,
	target Target,
	hostLease isolated.HostFenceLease,
	operationID string,
	progress *MCPProgressState,
) (isolatedstate.IsolatedVM, hyperv.IsolatedVMMutationResult, error) {
	dns, err := isolated.ParseDNSServers(vm.DNSServersJSON)
	if err != nil {
		return vm, hyperv.IsolatedVMMutationResult{}, err
	}
	switch vm.GuestOS {
	case isolatedstate.GuestWindows:
		profile, profileName, err := r.deps.defaults.ResolveOrdinaryWindowsForTarget(vm.ProfileName, target.Name)
		if err != nil {
			return vm, hyperv.IsolatedVMMutationResult{}, err
		}
		plan := planFromProfile(profile, profileName)
		plan.Target, plan.Name, plan.Hostname = target.Name, vm.HyperVName, vm.NodeName
		plan.VSwitch, plan.LabLinkNodeName, plan.LabLinkRole = network.HyperVSwitchName, vm.NodeName, "isolated-vm"
		plan.RegisterWithLabLink, plan.LabLinkPort = true, appliance.RelayTargetPort
		plan.CleanupOnFailure, plan.DeferBoot, plan.NetworkFirstBoot = false, true, true
		plan.DomainJoin = nil
		plan.FirstBootScript, err = isolated.WindowsStaticNetworkScript(vm.IPv4, vm.PrefixLength, vm.GatewayIPv4, vm.MAC, dns)
		if err != nil {
			return vm, hyperv.IsolatedVMMutationResult{}, err
		}
		derivePlanPaths(&plan)
		if _, err := r.deps.credentials.Get(plan.AdminPasswordCredential); err != nil {
			return vm, hyperv.IsolatedVMMutationResult{}, err
		}
		result, runErr := executeWindowsVMPlan(ctx, plan, r.deps.registry, r.deps.pool,
			r.deps.credentials, r.deps.secrets, r.deps.audit, r.deps.enrollment)
		if runErr != nil || result == nil || result.IsError {
			if runErr != nil {
				return vm, hyperv.IsolatedVMMutationResult{}, runErr
			}
			return vm, hyperv.IsolatedVMMutationResult{}, fmt.Errorf("provision Windows guest: %s", toolResultText(result))
		}
		vm.StorageRoot, vm.VMPath, vm.VHDPath = plan.VMRoot, plan.VMLocation, plan.VHDPath
	case isolatedstate.GuestLinux:
		networkConfig, err := isolated.LinuxStaticNetworkConfig(vm.IPv4, vm.PrefixLength, vm.GatewayIPv4, vm.MAC, dns)
		if err != nil {
			return vm, hyperv.IsolatedVMMutationResult{}, err
		}
		req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{
			"target": target.Name, "profile": vm.ProfileName, "name": vm.HyperVName,
			"hostname": vm.NodeName, "network_config": networkConfig,
			"vswitch": network.HyperVSwitchName, "register_with_lablink": true,
			"lablink_node_name": vm.NodeName, "lablink_role": "isolated-vm",
			"lablink_port": appliance.RelayTargetPort,
		}}}
		plan, resolvedTarget, err := resolveLinuxVMPlan(req, r.deps.registry, r.deps.defaults, r.deps.credentials)
		if err != nil {
			return vm, hyperv.IsolatedVMMutationResult{}, err
		}
		plan.DeferBoot = true
		result, runErr := executeLinuxVMPlan(ctx, req, plan, resolvedTarget, r.deps.registry,
			r.deps.pool, r.deps.defaults, r.deps.credentials, r.deps.audit,
			r.deps.enrollment, r.deps.lease, progress)
		if runErr != nil || result == nil || result.IsError {
			if runErr != nil {
				return vm, hyperv.IsolatedVMMutationResult{}, runErr
			}
			return vm, hyperv.IsolatedVMMutationResult{}, fmt.Errorf("provision Linux guest: %s", toolResultText(result))
		}
		vm.StorageRoot, vm.VMPath, vm.VHDPath = plan.VMRoot, plan.VMLocation, plan.VHDPath
	default:
		return vm, hyperv.IsolatedVMMutationResult{}, fmt.Errorf("unsupported guest OS %q", vm.GuestOS)
	}
	return r.claim(ctx, vm, network, orchestrator, target, hostLease, operationID)
}

func (r productionIsolatedGuestRuntime) claim(
	ctx context.Context,
	vm isolatedstate.IsolatedVM,
	network isolatedstate.PrivateNetwork,
	orchestrator isolatedstate.Orchestrator,
	target Target,
	hostLease isolated.HostFenceLease,
	operationID string,
) (isolatedstate.IsolatedVM, hyperv.IsolatedVMMutationResult, error) {
	owner, err := hyperv.IsolatedOwnerMarker(orchestrator.ID, "vm", vm.ID)
	if err != nil {
		return vm, hyperv.IsolatedVMMutationResult{}, err
	}
	names, _ := isolated.VMNames(isolated.VMID(vm.ID))
	guard := guestHostGuard(orchestrator, hostLease, operationID, vm.ID, "claim_isolated_vm", "host_claim")
	script, err := hyperv.BuildClaimIsolatedVMScript(hyperv.ClaimIsolatedVMParams{
		Guard: guard, OrchestratorVMGUID: valueOrEmpty(orchestrator.HyperVVMID),
		VMName: vm.HyperVName, SwitchGUID: valueOrEmpty(network.HyperVSwitchGUID),
		AdapterName: names.PrivateAdapterName, MAC: vm.MAC,
		Metadata: hyperv.IsolatedVMMetadata{
			SchemaVersion: hyperv.IsolatedMetadataSchema, PhysicalHostID: orchestrator.PhysicalHostID,
			OrchestratorID: orchestrator.ID, NetworkID: network.ID, VMID: vm.ID,
			OwnerMarker: owner, HostFence: hostLease.Fence, LifecycleState: "creating",
			ManagedRoot: vm.StorageRoot, ExpectedVHDPaths: []string{vm.VHDPath},
			NodeName: vm.NodeName, IPv4: vm.IPv4, MAC: vm.MAC,
			Incarnation: int64(vm.Incarnation), Generation: int64(vm.DesiredGeneration),
		},
	})
	if err != nil {
		return vm, hyperv.IsolatedVMMutationResult{}, err
	}
	out, _, err := runPS(ctx, r.deps.registry, r.deps.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return vm, hyperv.IsolatedVMMutationResult{}, err
	}
	mutation, err := hyperv.ParseIsolatedVMMutationResult(jsonExtract(out))
	if err != nil {
		return vm, mutation, err
	}
	vm.HyperVVMID, vm.HyperVAdapterID = optionalTrimmed(mutation.VMGUID), optionalTrimmed(mutation.AdapterID)
	return vm, mutation, nil
}

func (r productionIsolatedGuestRuntime) StartAndEnroll(
	ctx context.Context,
	vm isolatedstate.IsolatedVM,
	relay isolatedstate.RelayAllocation,
	orchestrator isolatedstate.Orchestrator,
	target Target,
	progress *MCPProgressState,
) error {
	progress.Update("guest_start", "starting exact isolated VM after relay and NAT verification")
	script, err := hyperv.BuildStartIsolatedVMScript(hyperv.StartIsolatedVMParams{
		VMName: vm.HyperVName, ExpectedVMID: vm.ID,
		ExpectedGUID: valueOrEmpty(vm.HyperVVMID), ExpectedIPv4: vm.IPv4,
	})
	if err != nil {
		return err
	}
	if _, _, err := runPS(ctx, r.deps.registry, r.deps.pool, target, script, vmDefaultTimeoutSec); err != nil {
		return err
	}
	mainIP := valueOrEmpty(orchestrator.MainIP)
	if mainIP == "" {
		snapshot, snapErr := r.deps.appliance.InspectApplianceState(ctx, orchestrator.ID)
		if snapErr != nil {
			return snapErr
		}
		mainIP = snapshot.MainIPv4
	}
	address := fmt.Sprintf("%s:%d", mainIP, relay.ListenPort)
	identityPlan := windowsVMPlan{
		LabLinkNodeName: vm.NodeName, LabLinkRole: "isolated-vm",
		LabLinkPort: appliance.RelayTargetPort,
	}
	timeout := windowsEnrollmentReadyTimeout
	if vm.GuestOS == isolatedstate.GuestLinux {
		timeout = linuxEnrollmentReadyTimeout
	}
	if err := verifyEnrolledVMWithOptions(ctx, identityPlan, startedVMInfo{IPAddress: vm.IPv4, State: "Running"},
		r.deps.registry, r.deps.pool, true, enrollmentWaitOptions{
			Timeout: timeout, Address: address,
			OnStatus: func(status string) { progress.Update("relay_mtls_verify", status) },
		}); err != nil {
		return err
	}
	if vm.GuestOS == isolatedstate.GuestLinux {
		iso := filepath.Join(vm.VMPath, "cidata.iso")
		cleanup := fmt.Sprintf(`
$vm = Get-VM -Id %s -ErrorAction Stop
$iso = %s
@(Get-VMDvdDrive -VM $vm -ErrorAction SilentlyContinue | Where-Object Path -eq $iso) | Remove-VMDvdDrive -ErrorAction Stop
if (Test-Path -LiteralPath $iso -PathType Leaf) { Remove-Item -LiteralPath $iso -Force -ErrorAction Stop }
`, hyperv.PSLit(valueOrEmpty(vm.HyperVVMID)), hyperv.PSLit(iso))
		if _, _, err := runPS(ctx, r.deps.registry, r.deps.pool, target, cleanup, vmDefaultTimeoutSec); err != nil {
			return fmt.Errorf("guest enrolled but exact CIDATA cleanup failed: %w", err)
		}
	}
	return nil
}

func (r productionIsolatedGuestRuntime) Inspect(ctx context.Context, vm isolatedstate.IsolatedVM, target Target) (hyperv.IsolatedVMMutationResult, error) {
	script, err := hyperv.BuildInspectIsolatedVMScript(hyperv.InspectIsolatedVMParams{
		VMName: vm.HyperVName, ExpectedVMID: vm.ID, ExpectedGUID: valueOrEmpty(vm.HyperVVMID),
	})
	if err != nil {
		return hyperv.IsolatedVMMutationResult{}, err
	}
	out, _, err := runPS(ctx, r.deps.registry, r.deps.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return hyperv.IsolatedVMMutationResult{}, err
	}
	return hyperv.ParseIsolatedVMMutationResult(jsonExtract(out))
}

func (r productionIsolatedGuestRuntime) Reconcile(
	ctx context.Context, vm isolatedstate.IsolatedVM, network isolatedstate.PrivateNetwork,
	orchestrator isolatedstate.Orchestrator, target Target, lease isolated.HostFenceLease,
	operationID string,
) (hyperv.IsolatedVMMutationResult, error) {
	result, err := r.Inspect(ctx, vm, target)
	if err != nil {
		return result, err
	}
	if !strings.EqualFold(result.AdapterID, valueOrEmpty(vm.HyperVAdapterID)) ||
		!strings.EqualFold(result.SwitchGUID, valueOrEmpty(network.HyperVSwitchGUID)) ||
		!strings.EqualFold(strings.ReplaceAll(result.MAC, "-", ""), strings.ReplaceAll(vm.MAC, "-", "")) ||
		!sameWindowsPath(result.VHDPath, vm.VHDPath) {
		return result, fmt.Errorf("VM_IDENTITY_MISMATCH: host VM, NIC, switch, MAC, or child VHD changed")
	}
	if !result.TimeSyncEnabled {
		script := fmt.Sprintf(`
$vm = Get-VM -Id %s -ErrorAction Stop
Enable-VMIntegrationService -VM $vm -Name 'Time Synchronization' -ErrorAction Stop
if (-not [bool](Get-VMIntegrationService -VM $vm -Name 'Time Synchronization').Enabled) { throw 'TIME_SYNC_VERIFY_FAILED' }
`, hyperv.PSLit(valueOrEmpty(vm.HyperVVMID)))
		if _, _, err := runPS(ctx, r.deps.registry, r.deps.pool, target, script, vmDefaultTimeoutSec); err != nil {
			return result, err
		}
		result.TimeSyncEnabled = true
	}
	return result, nil
}

func (r productionIsolatedGuestRuntime) Delete(
	ctx context.Context, vm isolatedstate.IsolatedVM, orchestrator isolatedstate.Orchestrator,
	target Target, lease isolated.HostFenceLease, operationID string, deleteStorage bool,
) (hyperv.IsolatedVMMutationResult, error) {
	script, err := hyperv.BuildDeleteIsolatedVMScript(hyperv.DeleteIsolatedVMParams{
		Guard:              guestHostGuard(orchestrator, lease, operationID, vm.ID, "delete_isolated_vm", "host_delete"),
		OrchestratorVMGUID: valueOrEmpty(orchestrator.HyperVVMID),
		VMName:             vm.HyperVName, ExpectedVMID: vm.ID,
		ExpectedVMGUID: valueOrEmpty(vm.HyperVVMID), ExpectedAdapterID: valueOrEmpty(vm.HyperVAdapterID),
		ExpectedVHDPath: vm.VHDPath, ExpectedVMPath: vm.VMPath, DeleteStorage: deleteStorage,
	})
	if err != nil {
		return hyperv.IsolatedVMMutationResult{}, err
	}
	out, _, err := runPS(ctx, r.deps.registry, r.deps.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return hyperv.IsolatedVMMutationResult{}, err
	}
	return hyperv.ParseIsolatedVMMutationResult(jsonExtract(out))
}

func guestHostGuard(orchestrator isolatedstate.Orchestrator, lease isolated.HostFenceLease, operationID, vmID, action, phase string) hyperv.IsolatedMutationGuard {
	return hyperv.IsolatedMutationGuard{
		PhysicalHostID: orchestrator.PhysicalHostID, LeaseID: lease.LeaseID,
		LeaseSecret: lease.LeaseSecret, Fence: lease.Fence,
		OrchestratorID: orchestrator.ID, OperationID: operationID,
		MutationID:   isolatedstate.StableMutationID(operationID, vmID, action, phase),
		ResourceType: "vm", ResourceID: vmID, Action: action,
	}
}

func parseReachableServices(req mcp.CallToolRequest) ([]isolated.ReachableService, error) {
	raw, ok := req.GetArguments()["reachable_services"].([]any)
	if !ok {
		if values, stringsOK := req.GetArguments()["reachable_services"].([]string); stringsOK {
			raw = make([]any, len(values))
			for i := range values {
				raw[i] = values[i]
			}
		}
	}
	var result []isolated.ReachableService
	for _, item := range raw {
		if object, objectOK := item.(map[string]any); objectOK {
			service := isolated.ReachableService{
				Kind:    strings.TrimSpace(fmt.Sprint(object["kind"])),
				Address: strings.TrimSpace(fmt.Sprint(object["address"])),
			}
			if port, portOK := numericArgument(object["port"]); portOK {
				service.Port = int(port)
			}
			result = append(result, service)
			continue
		}
		value := strings.TrimSpace(fmt.Sprint(item))
		kind, endpoint, ok := strings.Cut(value, "=")
		if !ok {
			return nil, fmt.Errorf("reachable_services entries must use kind=address[:port]")
		}
		service := isolated.ReachableService{Kind: strings.TrimSpace(kind)}
		service.Address = strings.TrimSpace(endpoint)
		if host, port, splitErr := netSplitHostPort(endpoint); splitErr == nil {
			service.Address = host
			fmt.Sscan(port, &service.Port)
		}
		result = append(result, service)
	}
	return result, nil
}

var netSplitHostPort = net.SplitHostPort

func createIsolatedVMHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		networkID, err := isolated.ParseNetworkID(req.GetString("network_id", ""))
		if err != nil {
			return isolatedError(err)
		}
		network, err := deps.state.GetNetwork(ctx, networkID.String())
		if err != nil {
			return isolatedError(err)
		}
		orchestrator, err := deps.state.GetOrchestrator(ctx, network.OrchestratorID)
		if err != nil {
			return isolatedError(err)
		}
		target, err := resolvePlanTarget(orchestrator.HostNode, deps.registry)
		if err != nil {
			return isolatedError(err)
		}
		operationID, err := isolatedOperationID(req)
		if err != nil {
			return isolatedError(err)
		}
		resumed, err := resumeResourceID(ctx, deps.state, operationID, "vm")
		if err != nil {
			return isolatedError(err)
		}
		var vmID isolated.VMID
		if raw := strings.TrimSpace(req.GetString("isolated_vm_id", "")); raw != "" {
			vmID, err = isolated.ParseVMID(raw)
		} else if resumed != "" {
			vmID, err = isolated.ParseVMID(resumed)
		} else {
			vmID, err = isolated.NewVMID()
		}
		if err != nil {
			return isolatedError(err)
		}
		relayID, err := isolated.NewRelayID()
		if err != nil {
			return isolatedError(err)
		}
		guestOS := isolatedstate.GuestOS(strings.ToLower(strings.TrimSpace(req.GetString("guest_os", ""))))
		profile := strings.TrimSpace(req.GetString("profile", ""))
		displayName := strings.TrimSpace(req.GetString("display_name", ""))
		services, err := parseReachableServices(req)
		if err != nil {
			return isolatedError(err)
		}
		domainJoin, err := parseWindowsDomainJoinArgument(req.GetArguments()["domain_join"])
		if err != nil {
			return isolatedError(err)
		}
		if domainJoin != nil && guestOS != isolatedstate.GuestWindows {
			return isolatedError(fmt.Errorf("domain_join is supported only for Windows isolated guests"))
		}
		knownNetworkBootstrap := req.GetBool("known_network_bootstrap", false) ||
			domainJoin != nil || detectsNetworkBootstrap(req.GetArguments())
		expected, err := expectedGeneration(req, orchestrator.DesiredGeneration)
		if err != nil {
			return isolatedError(err)
		}
		inputs := map[string]any{
			"network_id": network.ID, "vm_id": vmID.String(), "display_name": displayName,
			"guest_os": guestOS, "profile": profile, "nat_enabled": req.GetBool("nat_enabled", false),
			"bootstrap_network_requirement": req.GetString("bootstrap_network_requirement", ""),
			"known_network_bootstrap":       knownNetworkBootstrap,
			"reachable_services":            services, "domain_join": domainJoin,
			"expected_generation": expected,
		}
		progress, stop := StartMCPProgress(ctx, req, 35*time.Minute, "allocate_identity", "reserving guest identity and network resources")
		defer stop()
		workflow, err := beginIsolatedWorkflow(ctx, deps.state, progress, isolatedstate.BeginOperationRequest{
			ID: operationID, Kind: "create_isolated_vm", ResourceType: "vm",
			ResourceID: vmID.String(), HostNode: &orchestrator.HostNode,
			OrchestratorID: optionalTrimmed(orchestrator.ID), NetworkID: optionalTrimmed(network.ID),
			CanonicalInputs: inputs, ResumeExact: req.GetBool("resume_exact", false),
		})
		if err != nil {
			return isolatedError(err)
		}
		vmLock, _ := isolatedstate.VMLockKey(vmID.String())
		localLease, err := deps.locks.Acquire(ctx, isolatedstate.LockAcquireRequest{
			Key: vmLock, OperationID: operationID, TTL: isolatedOperationTTL,
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
		var plan isolated.GuestPlan
		err = workflow.phase(ctx, 0, "allocate_identity", "appliance-authoritative IP, MAC, relay port, and conntrack reservation", func() (any, error) {
			var planErr error
			plan, planErr = (isolated.GuestDomain{Appliance: deps.appliance}).ReserveAndPlan(ctx, isolated.CreateGuestRequest{
				OperationID: operationID, VMID: vmID, RelayID: relayID,
				Network: network, Orchestrator: orchestrator, DisplayName: displayName,
				GuestOS: guestOS, ProfileName: profile,
				NATEnabled:                  req.GetBool("nat_enabled", false),
				BootstrapNetworkRequirement: req.GetString("bootstrap_network_requirement", ""),
				KnownNetworkBootstrap:       knownNetworkBootstrap,
				DomainJoin:                  domainJoin != nil, ReachableServices: services,
				ExpectedParentGeneration: expected, HostFence: hostLease.Fence,
			})
			if planErr == nil {
				plan.VM.CreatedAt, plan.VM.UpdatedAt = isolatedNow(), isolatedNow()
				plan.Relay.CreatedAt, plan.Relay.UpdatedAt = isolatedNow(), isolatedNow()
				plan.NAT.UpdatedAt = isolatedNow()
				planErr = errors.Join(deps.state.PutVM(ctx, plan.VM), deps.state.PutRelay(ctx, plan.Relay), deps.state.PutNAT(ctx, plan.NAT))
			}
			return plan, planErr
		})
		if err != nil {
			return isolatedError(err)
		}
		if plan.VM.ID == "" {
			if _, err := workflow.loadPhase(ctx, 0, "allocate_identity", &plan); err != nil {
				return isolatedError(err)
			}
		}
		reservation := func(kind string) appliance.Reservation {
			for _, value := range plan.Reservations {
				if value.ResourceKind == kind {
					return value
				}
			}
			return appliance.Reservation{}
		}
		semantic, _ := isolatedstate.SemanticHash(inputs)
		envelope := func(resourceID, parentID, action, phase string) isolated.MutationEnvelope {
			return isolated.MutationEnvelope{
				Header: appliance.MutationHeader{
					ParentOperationID: operationID,
					MutationID:        isolatedstate.StableMutationID(operationID, resourceID, action, phase),
					SemanticHash:      semantic, ResourceID: resourceID, ParentResourceID: parentID,
					ExpectedGeneration: 0, NewGeneration: 1, HostFence: uint64(hostLease.Fence),
					ExpectedParentGeneration: plan.ResultingParentGeneration,
				},
				PhysicalHostID: orchestrator.PhysicalHostID, HostLeaseID: hostLease.LeaseID,
				HostLeaseSecret: mustDecodeHex(hostLease.LeaseSecret),
			}
		}
		err = workflow.phase(ctx, 1, "appliance_register_guest", "registering exact guest allocation with appliance", func() (any, error) {
			return deps.appliance.RegisterIsolatedGuest(ctx, orchestrator.ID, isolated.RegisterGuestInput{
				Header:        envelope(plan.VM.ID, network.ID, "register_guest", "appliance_register_guest"),
				ReservationID: reservation("guest_ip").ID, NetworkID: network.ID,
				IPv4: plan.VM.IPv4, MAC: plan.VM.MAC,
			})
		})
		if err != nil {
			return isolatedError(err)
		}
		err = workflow.phase(ctx, 2, "relay_bind", "binding relay before guest enrollment or boot", func() (any, error) {
			return deps.appliance.ApplyRelay(ctx, orchestrator.ID, isolated.RelayInput{
				Header:        envelope(plan.Relay.ID, plan.VM.ID, "apply_relay", "relay_bind"),
				ReservationID: reservation("relay").ID, VMID: plan.VM.ID, NetworkID: network.ID,
				ListenPort: uint32(plan.Relay.ListenPort), TargetIPv4: plan.VM.IPv4,
			})
		})
		if err != nil {
			return isolatedError(err)
		}
		err = workflow.phase(ctx, 3, "host_create_vm", "provisioning existing Windows/Linux engine while retaining guest off", func() (any, error) {
			var mutation hyperv.IsolatedVMMutationResult
			var runErr error
			plan.VM.LifecycleState = isolatedstate.VMProvisioning
			plan.VM, mutation, runErr = deps.guests.Provision(ctx, plan.VM, network, orchestrator, target, hostLease, operationID, progress)
			if runErr == nil {
				runErr = deps.state.PutVM(ctx, plan.VM)
			}
			return mutation, runErr
		})
		if err != nil {
			return isolatedError(err)
		}
		err = workflow.phase(ctx, 4, "host_time_sync", "verifying Hyper-V host time synchronization is enabled", func() (any, error) {
			observation, inspectErr := deps.guests.Inspect(ctx, plan.VM, target)
			if inspectErr == nil && !observation.TimeSyncEnabled {
				inspectErr = fmt.Errorf("TIME_SYNC_VERIFY_FAILED: Hyper-V time synchronization is disabled")
			}
			return observation, inspectErr
		})
		if err != nil {
			return isolatedError(err)
		}
		natDesired := string(plan.NAT.DesiredState)
		err = workflow.phase(ctx, 5, "nat_apply_and_verify_preboot", "applying and verifying NAT state before first boot", func() (any, error) {
			result, applyErr := deps.appliance.SetNATState(ctx, orchestrator.ID, isolated.NATInput{
				Header:        envelope(plan.VM.ID, network.ID, "set_nat", "nat_apply_and_verify_preboot"),
				ReservationID: reservation("conntrack_mark").ID, NetworkID: network.ID,
				DesiredState: natDesired, ConntrackMark: uint32(plan.NAT.ConntrackMark),
			})
			if applyErr == nil && result.NAT.State != natDesired {
				applyErr = fmt.Errorf("NAT_VERIFY_FAILED: wanted %s, observed %s", natDesired, result.NAT.State)
			}
			if applyErr == nil {
				plan.NAT.AppliedGeneration = isolatedstate.Generation(result.NAT.AppliedGeneration)
				plan.NAT.ObservedGeneration = isolatedstate.Generation(result.NAT.ObservedGeneration)
				plan.NAT.ObservedState = isolatedstate.NATObservedState(result.NAT.State)
				applyErr = deps.state.PutNAT(ctx, plan.NAT)
			}
			return result, applyErr
		})
		if err != nil {
			return isolatedError(err)
		}
		err = workflow.phase(ctx, 6, "guest_start", "starting guest only after relay and NAT verification", func() (any, error) {
			return nil, deps.guests.StartAndEnroll(ctx, plan.VM, plan.Relay, orchestrator, target, progress)
		})
		if err != nil {
			return isolatedError(err)
		}
		err = workflow.phase(ctx, 7, "registry_commit", "committing relay address with strict immutable guest TLS name", func() (any, error) {
			node, ok := deps.registry.GetNode(plan.VM.NodeName)
			if !ok {
				return nil, fmt.Errorf("REGISTRY_COMMIT_FAILED: enrolled guest node is missing")
			}
			mainIP := valueOrEmpty(orchestrator.MainIP)
			if mainIP == "" {
				snapshot, snapErr := deps.appliance.InspectApplianceState(ctx, orchestrator.ID)
				if snapErr != nil {
					return nil, snapErr
				}
				mainIP = snapshot.MainIPv4
			}
			expectedAddress := fmt.Sprintf("%s:%d", mainIP, plan.Relay.ListenPort)
			if node.Address != expectedAddress || node.TLSServerName != plan.VM.NodeName ||
				!strings.EqualFold(node.TransportMode, "mtls") {
				return nil, fmt.Errorf("REGISTRY_IDENTITY_MISMATCH: expected %s with TLS name %s", expectedAddress, plan.VM.NodeName)
			}
			copy := *node
			copy.Labels = cloneLabels(node.Labels)
			copy.Labels["lablink.kind"] = "isolated-vm"
			copy.Labels["lablink.isolated_vm_id"] = plan.VM.ID
			copy.Labels["lablink.orchestrator_id"] = plan.VM.OrchestratorID
			copy.Labels["lablink.network_id"] = plan.VM.NetworkID
			copy.Labels["lablink.display_name"] = plan.VM.DisplayName
			if setErr := deps.registry.SetNode(&copy); setErr != nil {
				return nil, setErr
			}
			return copy, nil
		})
		if err != nil {
			return isolatedError(err)
		}
		if domainJoin != nil {
			err = workflow.phase(ctx, 8, "optional_domain_join", "joining domain after relay enrollment and network verification", func() (any, error) {
				join := deps.joinDomain
				if join == nil {
					join = executeWindowsDomainJoin
				}
				return join(ctx, plan.VM.NodeName, *domainJoin, 180,
					deps.registry, deps.pool, deps.secrets, deps.audit)
			})
			if err != nil {
				return isolatedError(err)
			}
		}
		now := isolatedNow()
		plan.VM.LifecycleState = isolatedstate.VMReady
		plan.VM.AppliedGeneration, plan.VM.ObservedGeneration = plan.VM.DesiredGeneration, plan.VM.DesiredGeneration
		plan.VM.UpdatedAt = now
		plan.Relay.LifecycleState = isolatedstate.RelayReady
		plan.Relay.AppliedGeneration, plan.Relay.ObservedGeneration = 1, 1
		plan.Relay.UpdatedAt = now
		if err := errors.Join(deps.state.PutVM(ctx, plan.VM), deps.state.PutRelay(ctx, plan.Relay),
			deps.state.CommitAllocations(ctx, guestMirrorAllocations(plan))); err != nil {
			return isolatedError(err)
		}
		return workflow.finish(ctx, isolatedstate.OperationSucceeded, isolatedToolResult{
			Status: "succeeded", Phase: "ready", ResourceID: plan.VM.ID,
			Generation: int64(plan.VM.DesiredGeneration), Resource: plan.VM,
		})
	}
}

func guestMirrorAllocations(plan isolated.GuestPlan) []isolatedstate.ActiveResourceAllocation {
	now := isolatedNow()
	var values []isolatedstate.ActiveResourceAllocation
	for _, reservation := range plan.Reservations {
		kind, value := reservation.ResourceKind, reservation.IPv4
		if reservation.MAC != "" {
			value = reservation.MAC
		}
		if reservation.ListenPort != nil {
			value = fmt.Sprint(*reservation.ListenPort)
		}
		if reservation.ConntrackMark != nil {
			value = fmt.Sprint(*reservation.ConntrackMark)
		}
		values = append(values, isolatedstate.ActiveResourceAllocation{
			Kind: kind, ScopeID: plan.VM.OrchestratorID, Value: value,
			ResourceID: reservation.ResourceID, ApplianceReservationID: reservation.ID,
			AllocatedAt: now,
		})
	}
	return values
}

func isolatedNow() isolatedstate.UnixSeconds {
	return isolatedstate.UnixSeconds(time.Now().Unix())
}

func deleteIsolatedVMHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := isolated.ParseVMID(req.GetString("isolated_vm_id", ""))
		if err != nil {
			return isolatedError(err)
		}
		deleteStorage := true
		if value, ok := req.GetArguments()["delete_storage"].(bool); ok {
			deleteStorage = value
		}
		operationID, err := isolatedOperationID(req)
		if err != nil {
			return isolatedError(err)
		}
		return deleteIsolatedVMCore(ctx, deps, id.String(), operationID, deleteStorage,
			req.GetBool("resume_exact", false), req)
	}
}

func deleteIsolatedVMCore(ctx context.Context, deps *isolatedLifecycleDeps, vmID, operationID string, deleteStorage, resume bool, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	vm, err := deps.state.GetVM(ctx, vmID)
	if err != nil {
		return isolatedError(err)
	}
	orchestrator, err := deps.state.GetOrchestrator(ctx, vm.OrchestratorID)
	if err != nil {
		return isolatedError(err)
	}
	target, err := resolvePlanTarget(orchestrator.HostNode, deps.registry)
	if err != nil {
		return isolatedError(err)
	}
	workflow, err := beginIsolatedWorkflow(ctx, deps.state, nil, isolatedstate.BeginOperationRequest{
		ID: operationID, Kind: "delete_isolated_vm", ResourceType: "vm", ResourceID: vm.ID,
		HostNode: &orchestrator.HostNode, OrchestratorID: optionalTrimmed(orchestrator.ID),
		NetworkID: optionalTrimmed(vm.NetworkID), CanonicalInputs: map[string]any{
			"isolated_vm_id": vm.ID, "delete_storage": deleteStorage,
		}, ResumeExact: resume,
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
	relay, relayErr := deps.state.GetRelayForVM(ctx, vm.ID)
	nat, natErr := deps.state.GetNAT(ctx, vm.ID)
	semantic, _ := isolatedstate.SemanticHash(map[string]any{"vm_id": vm.ID, "delete_storage": deleteStorage})
	envelope := func(resourceID, parentID, action, phase string, generation isolatedstate.Generation) isolated.MutationEnvelope {
		return isolated.MutationEnvelope{
			Header: appliance.MutationHeader{
				ParentOperationID: operationID,
				MutationID:        isolatedstate.StableMutationID(operationID, resourceID, action, phase),
				SemanticHash:      semantic, ResourceID: resourceID, ParentResourceID: parentID,
				ExpectedGeneration: uint64(generation), NewGeneration: uint64(generation + 1),
				HostFence:                uint64(hostLease.Fence),
				ExpectedParentGeneration: uint64(orchestrator.DesiredGeneration),
			},
			PhysicalHostID: orchestrator.PhysicalHostID, HostLeaseID: hostLease.LeaseID,
			HostLeaseSecret: mustDecodeHex(hostLease.LeaseSecret),
		}
	}
	if natErr == nil {
		err = workflow.phase(ctx, 0, "retire_nat", "disabling and retiring conntrack ownership", func() (any, error) {
			result, runErr := deps.appliance.SetNATState(ctx, orchestrator.ID, isolated.NATInput{
				Header:    envelope(vm.ID, vm.NetworkID, "disable_nat", "retire_nat", nat.DesiredGeneration),
				NetworkID: vm.NetworkID, DesiredState: string(isolatedstate.NATDesiredDisabled),
				ConntrackMark: uint32(nat.ConntrackMark),
			})
			if runErr == nil && result.NAT.State == string(isolatedstate.NATObservedDraining) {
				runErr = fmt.Errorf("NAT_DRAINING: conntrack retirement is not complete; resume deletion")
			}
			return result, runErr
		})
		if err != nil {
			return isolatedError(err)
		}
	}
	if relayErr == nil {
		err = workflow.phase(ctx, 1, "retire_relay", "retiring relay through accept/dial/drain barrier", func() (any, error) {
			return deps.appliance.RemoveRelay(ctx, orchestrator.ID,
				envelope(relay.ID, vm.ID, "remove_relay", "retire_relay", relay.DesiredGeneration),
				vm.ID, vm.NetworkID)
		})
		if err != nil {
			return isolatedError(err)
		}
	}
	err = workflow.phase(ctx, 2, "remove_guest", "retiring appliance guest allocation", func() (any, error) {
		return deps.appliance.RemoveIsolatedGuest(ctx, orchestrator.ID,
			envelope(vm.ID, vm.NetworkID, "remove_guest", "remove_guest", vm.DesiredGeneration),
			vm.NetworkID)
	})
	if err != nil {
		return isolatedError(err)
	}
	err = workflow.phase(ctx, 3, "delete_exact_vm", "deleting exact VM GUID, adapter, child VHD, and owned storage", func() (any, error) {
		return deps.guests.Delete(ctx, vm, orchestrator, target, hostLease, operationID, deleteStorage)
	})
	if err != nil {
		return isolatedError(err)
	}
	err = workflow.phase(ctx, 4, "registry_cleanup", "removing relay registry address", func() (any, error) {
		nodeName := caseCorrectRegistryNodeName(deps.registry, vm.NodeName)
		if _, ok := deps.registry.GetNode(nodeName); !ok {
			return map[string]any{"already_absent": true}, nil
		}
		return nil, deps.registry.RemoveNode(nodeName)
	})
	if err != nil {
		return isolatedError(err)
	}
	err = workflow.phase(ctx, 5, "release_allocations", "releasing only exact appliance-owned reservations", func() (any, error) {
		snapshot, snapErr := deps.appliance.GetApplianceState(ctx, orchestrator.ID)
		if snapErr != nil {
			return nil, snapErr
		}
		var ids []string
		for _, value := range snapshot.Reservations {
			if value.RetiredAtUnix == nil && (value.ResourceID == vm.ID || (relayErr == nil && value.ResourceID == relay.ID)) {
				ids = append(ids, value.ID)
			}
		}
		if len(ids) == 0 {
			return map[string]any{"already_released": true}, nil
		}
		released, releaseErr := deps.appliance.ReleaseResources(ctx, orchestrator.ID, appliance.ReleaseRequest{
			Header:         envelope(vm.ID, vm.NetworkID, "release_guest", "release_allocations", vm.DesiredGeneration).Header,
			ReservationIDs: ids,
		})
		if releaseErr != nil {
			return released, releaseErr
		}
		for _, reservation := range snapshot.Reservations {
			if !containsString(ids, reservation.ID) {
				continue
			}
			value := reservation.IPv4
			if reservation.MAC != "" {
				value = reservation.MAC
			}
			if reservation.ListenPort != nil {
				value = fmt.Sprint(*reservation.ListenPort)
			}
			if reservation.ConntrackMark != nil {
				value = fmt.Sprint(*reservation.ConntrackMark)
			}
			_, mirrorErr := deps.state.ReleaseAllocation(ctx, isolatedstate.ReleaseAllocationRequest{
				Kind: reservation.ResourceKind, ScopeID: orchestrator.ID, Value: value,
				ResourceID: reservation.ResourceID, ReleaseOperationID: operationID,
			})
			if mirrorErr != nil && !errors.Is(mirrorErr, isolatedstate.ErrAllocationNotFound) {
				return released, mirrorErr
			}
		}
		return released, nil
	})
	if err != nil {
		return isolatedError(err)
	}
	now := isolatedNow()
	vm.LifecycleState, vm.DesiredGeneration, vm.UpdatedAt, vm.RetiredAt = isolatedstate.VMDeleted, vm.DesiredGeneration+1, now, &now
	if err := deps.state.PutVM(ctx, vm); err != nil {
		return isolatedError(err)
	}
	if relayErr == nil {
		relay.LifecycleState, relay.UpdatedAt, relay.RetiredAt = isolatedstate.RelayRemoved, now, &now
		_ = deps.state.PutRelay(ctx, relay)
	}
	return workflow.finish(ctx, isolatedstate.OperationSucceeded, isolatedToolResult{
		Status: "succeeded", Phase: "deleted", ResourceID: vm.ID,
		Generation: int64(vm.DesiredGeneration), Resource: vm,
	})
}

func listIsolatedVMsHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		values, err := deps.state.ListVMs(ctx, req.GetString("orchestrator_id", ""), req.GetString("network_id", ""))
		if err != nil {
			return isolatedError(err)
		}
		filtered := values[:0]
		for _, value := range values {
			if !req.GetBool("include_deleted", false) && value.LifecycleState == isolatedstate.VMDeleted {
				continue
			}
			if target := strings.TrimSpace(req.GetString("target", "")); target != "" {
				orchestrator, getErr := deps.state.GetOrchestrator(ctx, value.OrchestratorID)
				if getErr != nil || !strings.EqualFold(orchestrator.HostNode, target) {
					continue
				}
			}
			filtered = append(filtered, value)
		}
		data, _ := json.MarshalIndent(filtered, "", "  ")
		return mcp.NewToolResultText("```json\n" + string(data) + "\n```"), nil
	}
}

func getIsolatedVMHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := isolated.ParseVMID(req.GetString("isolated_vm_id", ""))
		if err != nil {
			return isolatedError(err)
		}
		vm, err := deps.state.GetVM(ctx, id.String())
		if err != nil {
			return isolatedError(err)
		}
		result := map[string]any{"vm": vm}
		if nat, natErr := deps.state.GetNAT(ctx, vm.ID); natErr == nil {
			result["nat"] = nat
		}
		if relay, relayErr := deps.state.GetRelayForVM(ctx, vm.ID); relayErr == nil {
			result["relay"] = relay
		}
		if req.GetBool("live", false) {
			orchestrator, _ := deps.state.GetOrchestrator(ctx, vm.OrchestratorID)
			target, targetErr := resolvePlanTarget(orchestrator.HostNode, deps.registry)
			if targetErr == nil {
				if live, liveErr := deps.guests.Inspect(ctx, vm, target); liveErr == nil {
					result["live"] = live
				} else {
					result["live_error"] = liveErr.Error()
				}
			}
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText("```json\n" + string(data) + "\n```"), nil
	}
}

func repairIsolatedVMHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := isolated.ParseVMID(req.GetString("isolated_vm_id", ""))
		if err != nil {
			return isolatedError(err)
		}
		vm, err := deps.state.GetVM(ctx, id.String())
		if err != nil {
			return isolatedError(err)
		}
		network, err := deps.state.GetNetwork(ctx, vm.NetworkID)
		if err != nil {
			return isolatedError(err)
		}
		orchestrator, err := deps.state.GetOrchestrator(ctx, vm.OrchestratorID)
		if err != nil {
			return isolatedError(err)
		}
		target, err := resolvePlanTarget(orchestrator.HostNode, deps.registry)
		if err != nil {
			return isolatedError(err)
		}
		operationID, err := isolatedOperationID(req)
		if err != nil {
			return isolatedError(err)
		}
		workflow, err := beginIsolatedWorkflow(ctx, deps.state, nil, isolatedstate.BeginOperationRequest{
			ID: operationID, Kind: "repair_isolated_vm", ResourceType: "vm", ResourceID: vm.ID,
			HostNode: &orchestrator.HostNode, OrchestratorID: optionalTrimmed(orchestrator.ID),
			NetworkID: optionalTrimmed(network.ID), CanonicalInputs: map[string]any{"isolated_vm_id": vm.ID},
			ResumeExact: req.GetBool("resume_exact", false),
		})
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
		var reconcileErr error
		err = workflow.phaseAlways(ctx, 0, "reconcile", "attempting non-destructive host identity, NIC, time, relay, NAT, and registry repair", func() (any, error) {
			result, runErr := deps.guests.Reconcile(ctx, vm, network, orchestrator, target, hostLease, operationID)
			if runErr == nil {
				relay, relayErr := deps.state.GetRelayForVM(ctx, vm.ID)
				if relayErr == nil {
					validation, validateErr := deps.appliance.ValidateRelay(ctx, orchestrator.ID, relay.ID, true)
					if validateErr != nil || !validation.ListenerValid || !validation.MappingValid || !validation.GenerationValid {
						semantic, _ := isolatedstate.SemanticHash(map[string]any{"vm_id": vm.ID, "relay_id": relay.ID, "repair": true})
						_, _, rebindErr := deps.appliance.RebindRelays(ctx, orchestrator.ID, isolated.MutationEnvelope{
							Header: appliance.MutationHeader{
								ParentOperationID: operationID,
								MutationID:        isolatedstate.StableMutationID(operationID, relay.ID, "repair_relay", "rebind"),
								SemanticHash:      semantic, ResourceID: orchestrator.ID,
								ParentResourceID:         orchestrator.ID,
								ExpectedGeneration:       uint64(orchestrator.DesiredGeneration),
								NewGeneration:            uint64(orchestrator.DesiredGeneration + 1),
								HostFence:                uint64(hostLease.Fence),
								ExpectedParentGeneration: uint64(orchestrator.DesiredGeneration),
							},
							PhysicalHostID:  orchestrator.PhysicalHostID,
							HostLeaseID:     hostLease.LeaseID,
							HostLeaseSecret: mustDecodeHex(hostLease.LeaseSecret),
						})
						if rebindErr != nil {
							runErr = fmt.Errorf("relay validation and rebind failed: %v; %w", validateErr, rebindErr)
						}
					}
				}
			}
			if runErr == nil {
				if nat, natErr := deps.state.GetNAT(ctx, vm.ID); natErr == nil {
					semantic, _ := isolatedstate.SemanticHash(map[string]any{"vm_id": vm.ID, "nat": nat.DesiredState, "repair": true})
					natResult, natRepairErr := deps.appliance.ReconcileNAT(ctx, orchestrator.ID, isolated.MutationEnvelope{
						Header: appliance.MutationHeader{
							ParentOperationID: operationID,
							MutationID:        isolatedstate.StableMutationID(operationID, vm.ID, "repair_nat", "reconcile"),
							SemanticHash:      semantic, ResourceID: vm.ID, ParentResourceID: network.ID,
							ExpectedGeneration:       uint64(nat.DesiredGeneration),
							NewGeneration:            uint64(nat.DesiredGeneration + 1),
							HostFence:                uint64(hostLease.Fence),
							ExpectedParentGeneration: uint64(orchestrator.DesiredGeneration),
						},
						PhysicalHostID: orchestrator.PhysicalHostID, HostLeaseID: hostLease.LeaseID,
						HostLeaseSecret: mustDecodeHex(hostLease.LeaseSecret),
					}, network.ID)
					if natRepairErr != nil || natResult.NAT.State != string(nat.DesiredState) {
						runErr = fmt.Errorf("NAT reconciliation failed: %v", natRepairErr)
					}
				}
			}
			if runErr == nil {
				relay, relayErr := deps.state.GetRelayForVM(ctx, vm.ID)
				if relayErr == nil {
					mainIP := valueOrEmpty(orchestrator.MainIP)
					if mainIP == "" {
						snapshot, snapErr := deps.appliance.InspectApplianceState(ctx, orchestrator.ID)
						if snapErr != nil {
							runErr = snapErr
						} else {
							mainIP = snapshot.MainIPv4
						}
					}
					if runErr == nil {
						node, ok := deps.registry.GetNode(vm.NodeName)
						if !ok {
							runErr = fmt.Errorf("registry node %s is missing", vm.NodeName)
						} else {
							copy := *node
							copy.Address = fmt.Sprintf("%s:%d", mainIP, relay.ListenPort)
							copy.TransportMode, copy.TLSServerName = "mtls", vm.NodeName
							runErr = deps.registry.SetNode(&copy)
						}
					}
				}
			}
			reconcileErr = runErr
			return result, nil
		})
		if err != nil {
			return isolatedError(err)
		}
		decision := isolated.DecideGuestRepair(vm, isolated.GuestRepairObservation{
			HostIdentityValid: reconcileErr == nil, NICValid: reconcileErr == nil,
			TimeSyncEnabled: reconcileErr == nil, RelayValid: reconcileErr == nil,
			GuestReachable: reconcileErr == nil, StaticNetworkValid: reconcileErr == nil,
			NATValid: reconcileErr == nil, RegistryValid: reconcileErr == nil,
		}, reconcileErr)
		if !decision.Recreate {
			vm.LifecycleState, vm.UpdatedAt = isolatedstate.VMReady, isolatedNow()
			_ = deps.state.PutVM(ctx, vm)
			return workflow.finish(ctx, isolatedstate.OperationSucceeded, isolatedToolResult{
				Status: "succeeded", Phase: "ready", ResourceID: vm.ID,
				Generation: int64(vm.DesiredGeneration), Resource: vm, Detail: decision,
			})
		}
		oldVHD := vm.VHDPath
		err = workflow.phase(ctx, 1, "exact_delete_old_vm_and_vhd", "deleting exact old VM GUID and accepted-policy child VHD", func() (any, error) {
			return deps.guests.Delete(ctx, vm, orchestrator, target, hostLease, operationID, true)
		})
		if err != nil {
			return isolatedError(err)
		}
		vm.Incarnation = decision.NextIncarnation
		vm.HyperVVMID, vm.HyperVAdapterID = nil, nil
		vm.LifecycleState, vm.DesiredGeneration = isolatedstate.VMRepairing, vm.DesiredGeneration+1
		err = workflow.phase(ctx, 2, "recreate_with_same_identity", "recreating with immutable guest, IP, MAC, relay, and TLS identity", func() (any, error) {
			var result hyperv.IsolatedVMMutationResult
			var runErr error
			vm, result, runErr = deps.guests.Provision(ctx, vm, network, orchestrator, target, hostLease, operationID, NewMCPProgressState(30*time.Minute, "repair", "recreate"))
			return map[string]any{"result": result, "deleted_old_vhd": oldVHD, "incarnation": vm.Incarnation}, runErr
		})
		if err != nil {
			return isolatedError(err)
		}
		relay, err := deps.state.GetRelayForVM(ctx, vm.ID)
		if err != nil {
			return isolatedError(err)
		}
		err = workflow.phase(ctx, 3, "verify", "starting recreated VM and verifying relay mTLS identity", func() (any, error) {
			return nil, deps.guests.StartAndEnroll(ctx, vm, relay, orchestrator, target, NewMCPProgressState(15*time.Minute, "verify", "repair"))
		})
		if err != nil {
			return isolatedError(err)
		}
		vm.LifecycleState, vm.AppliedGeneration, vm.ObservedGeneration, vm.UpdatedAt =
			isolatedstate.VMReady, vm.DesiredGeneration, vm.DesiredGeneration, isolatedNow()
		if err := deps.state.PutVM(ctx, vm); err != nil {
			return isolatedError(err)
		}
		return workflow.finish(ctx, isolatedstate.OperationSucceeded, isolatedToolResult{
			Status: "succeeded", Phase: "ready", ResourceID: vm.ID,
			Generation: int64(vm.DesiredGeneration), Resource: vm, Detail: decision,
		})
	}
}

func renameIsolatedDisplayNameHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		resourceType := strings.ToLower(strings.TrimSpace(req.GetString("resource_type", "")))
		resourceID := strings.TrimSpace(req.GetString("resource_id", ""))
		displayName := strings.TrimSpace(req.GetString("display_name", ""))
		if displayName == "" {
			return isolatedError(fmt.Errorf("display_name is required"))
		}
		var nodeName string
		var resource any
		switch resourceType {
		case "vm":
			value, err := deps.state.GetVM(ctx, resourceID)
			if err != nil {
				return isolatedError(err)
			}
			value.DisplayName, value.UpdatedAt = displayName, isolatedNow()
			if err := deps.state.PutVM(ctx, value); err != nil {
				return isolatedError(err)
			}
			nodeName, resource = value.NodeName, value
		case "network":
			value, err := deps.state.GetNetwork(ctx, resourceID)
			if err != nil {
				return isolatedError(err)
			}
			value.DisplayName, value.UpdatedAt = displayName, isolatedNow()
			if err := deps.state.PutNetwork(ctx, value); err != nil {
				return isolatedError(err)
			}
			resource = value
		case "orchestrator":
			value, err := deps.state.GetOrchestrator(ctx, resourceID)
			if err != nil {
				return isolatedError(err)
			}
			value.DisplayName, value.UpdatedAt = displayName, isolatedNow()
			if err := deps.state.PutOrchestrator(ctx, value); err != nil {
				return isolatedError(err)
			}
			nodeName, resource = value.NodeName, value
		default:
			return isolatedError(fmt.Errorf("resource_type must be vm, network, or orchestrator"))
		}
		if nodeName != "" {
			if node, ok := deps.registry.GetNode(nodeName); ok {
				copy := *node
				copy.Labels = cloneLabels(node.Labels)
				copy.Labels["lablink.display_name"] = displayName
				if err := deps.registry.SetNode(&copy); err != nil {
					return isolatedError(err)
				}
			}
		}
		return isolatedResult(isolatedToolResult{
			Status: "succeeded", Phase: "renamed", ResourceID: resourceID,
			Resource: resource,
		}), nil
	}
}

func cloneLabels(source map[string]string) map[string]string {
	result := make(map[string]string, len(source)+1)
	for key, value := range source {
		result[key] = value
	}
	return result
}

func detectsNetworkBootstrap(arguments map[string]any) bool {
	var walk func(any) bool
	walk = func(value any) bool {
		switch typed := value.(type) {
		case string:
			lower := strings.ToLower(typed)
			for _, marker := range []string{
				"http://", "https://", "invoke-webrequest", "start-bitstransfer",
				"curl ", "wget ", "apt-get ", "apt ", "winget ", "choco ",
			} {
				if strings.Contains(lower, marker) {
					return true
				}
			}
		case map[string]any:
			for _, child := range typed {
				if walk(child) {
					return true
				}
			}
		case []any:
			for _, child := range typed {
				if walk(child) {
					return true
				}
			}
		}
		return false
	}
	return walk(arguments)
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
