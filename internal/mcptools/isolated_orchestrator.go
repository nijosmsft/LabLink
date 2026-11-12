package mcptools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/isolated"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/vmconfig"
)

type isolatedStateAdapter struct {
	store *isolatedstate.Store
}

func (a isolatedStateAdapter) ListOrchestrators(ctx context.Context, host string) ([]isolatedstate.Orchestrator, error) {
	return a.store.ListOrchestrators(ctx, host)
}

func (a isolatedStateAdapter) GetOrchestrator(ctx context.Context, id string) (isolatedstate.Orchestrator, error) {
	return a.store.GetOrchestrator(ctx, id)
}

func (a isolatedStateAdapter) ImportApplianceCache(context.Context, isolated.ServerCacheImport) error {
	return nil
}

type productionIsolatedHost struct {
	reg      *registry.Registry
	pool     *agentclient.Pool
	defaults *vmconfig.Store
}

func (h productionIsolatedHost) target(name string) (Target, error) {
	return resolvePlanTarget(name, h.reg)
}

func (h productionIsolatedHost) PhysicalIdentity(ctx context.Context, target Target) (hyperv.IsolatedPhysicalHostObservation, error) {
	out, _, err := runPS(ctx, h.reg, h.pool, target, hyperv.BuildPhysicalHostIdentityScript(), vmDefaultTimeoutSec)
	if err != nil {
		return hyperv.IsolatedPhysicalHostObservation{}, err
	}
	return hyperv.ParsePhysicalHostIdentityObservation(jsonExtract(out))
}

func (h productionIsolatedHost) Discover(
	ctx context.Context,
	target Target,
	orchestratorID, orchestratorVMID string,
) (hyperv.IsolatedHostDiscovery, error) {
	script, err := hyperv.BuildDiscoverIsolatedHostScript(hyperv.IsolatedDiscoveryParams{
		OrchestratorID: orchestratorID, OrchestratorVMGUID: orchestratorVMID,
	})
	if err != nil {
		return hyperv.IsolatedHostDiscovery{}, err
	}
	out, _, err := runPS(ctx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return hyperv.IsolatedHostDiscovery{}, err
	}
	return hyperv.ParseIsolatedHostDiscovery(jsonExtract(out))
}

func randomHex(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func (h productionIsolatedHost) AcquireFence(
	ctx context.Context,
	target Target,
	request isolated.HostCreateFenceRequest,
) (isolated.HostFenceLease, error) {
	leaseID, err := isolated.NewOperationID()
	if err != nil {
		return isolated.HostFenceLease{}, err
	}
	secret, err := randomHex(32)
	if err != nil {
		return isolated.HostFenceLease{}, err
	}
	script, err := hyperv.BuildAcquireIsolatedHostLockScript(hyperv.IsolatedHostLeaseParams{
		PhysicalHostID: request.PhysicalHostID, LeaseID: leaseID.String(),
		LeaseSecret: secret, HolderIdentity: "lablink-server",
		OperationID: request.OperationID, DurationSeconds: int(isolatedOperationTTL.Seconds()),
	})
	if err != nil {
		return isolated.HostFenceLease{}, err
	}
	out, _, err := runPS(ctx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return isolated.HostFenceLease{}, err
	}
	result, err := hyperv.ParseIsolatedHostLeaseResult(jsonExtract(out))
	if err != nil {
		return isolated.HostFenceLease{}, err
	}
	if !result.Acquired {
		return isolated.HostFenceLease{}, fmt.Errorf(
			"HOST_LOCK_BUSY: current lease %s fence %d expires %s",
			result.CurrentLeaseID, result.CurrentFence, result.CurrentExpiresUTC)
	}
	return isolated.HostFenceLease{
		LeaseID: leaseID.String(), LeaseSecret: secret, Fence: result.Fence,
		LockKey: request.LockKey,
	}, nil
}

func (h productionIsolatedHost) AcquireOrchestratorCreateFence(
	ctx context.Context,
	request isolated.HostCreateFenceRequest,
) (isolated.HostFenceLease, error) {
	target, err := h.target(request.HostNode)
	if err != nil {
		return isolated.HostFenceLease{}, err
	}
	return h.AcquireFence(ctx, target, request)
}

func (h productionIsolatedHost) ReleaseFence(
	ctx context.Context,
	target Target,
	lease isolated.HostFenceLease,
) {
	physicalID := strings.TrimPrefix(strings.TrimSuffix(lease.LockKey.Key, ":orchestrator-create"), "host:")
	script, err := hyperv.BuildReleaseIsolatedHostLockScript(hyperv.IsolatedHostLeaseParams{
		PhysicalHostID: physicalID, LeaseID: lease.LeaseID,
		LeaseSecret: lease.LeaseSecret, Fence: lease.Fence,
	})
	if err == nil {
		_, _, _ = runPS(ctx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	}
}

func (h productionIsolatedHost) Preflight(
	ctx context.Context,
	target Target,
	input isolated.ResourcePreflightInput,
	profile vmconfig.Profile,
) (isolated.ResourcePreflightResult, error) {
	script, err := hyperv.BuildResourceSafetyScript(hyperv.ResourceSafetyParams{
		MemoryMB: float64(input.ProjectedMemoryMB), StoragePath: profile.VMRoot,
		StorageReserveBytes: input.ProjectedStorageBytes, MinHostReservePct: profile.MinHostReservePct,
	})
	if err != nil {
		return isolated.ResourcePreflightResult{}, err
	}
	out, _, err := runPS(ctx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return isolated.ResourcePreflightResult{Allowed: false, Reason: err.Error()}, nil
	}
	var result struct {
		Safe   bool `json:"safe"`
		Memory struct {
			Available float64 `json:"available_before_gb"`
		} `json:"memory"`
		Storage struct {
			Free float64 `json:"free_before_gb"`
		} `json:"storage"`
	}
	if err := json.Unmarshal([]byte(jsonExtract(out)), &result); err != nil {
		return isolated.ResourcePreflightResult{}, err
	}
	return isolated.ResourcePreflightResult{
		Allowed: result.Safe, AvailableMemoryMB: int(result.Memory.Available * 1024),
		AvailableStorageBytes:         int64(result.Storage.Free * 1024 * 1024 * 1024),
		HostReportedSyntheticAdapters: 16, EffectivePrivateAdapterSlots: 15,
		AvailableSwitchSlots: isolated.MaxNetworksPerOrchestrator,
	}, nil
}

func (h productionIsolatedHost) PreflightOrchestrator(
	ctx context.Context,
	input isolated.ResourcePreflightInput,
) (isolated.ResourcePreflightResult, error) {
	target, err := h.target(input.HostNode)
	if err != nil {
		return isolated.ResourcePreflightResult{}, err
	}
	resolved, _, err := h.defaults.ResolveIsolatedOrchestrator(input.ProfileName)
	if err != nil {
		return isolated.ResourcePreflightResult{}, err
	}
	return h.Preflight(ctx, target, input, resolved.LinuxVM)
}

func (h productionIsolatedHost) ClaimOrchestrator(
	ctx context.Context,
	target Target,
	record isolatedstate.Orchestrator,
	lease isolated.HostFenceLease,
) (hyperv.IsolatedVMObservation, error) {
	owner, err := hyperv.IsolatedOwnerMarker(record.ID, "orchestrator", record.ID)
	if err != nil {
		return hyperv.IsolatedVMObservation{}, err
	}
	script := fmt.Sprintf(`
$vm = @(Get-VM -Name %s -ErrorAction SilentlyContinue)
if ($vm.Count -ne 1) { throw 'ORCHESTRATOR_VM_IDENTITY_MISMATCH: expected exactly one VM by immutable generated name' }
$disks = @(Get-VMHardDiskDrive -VM $vm[0] -ErrorAction Stop)
if ($disks.Count -lt 1) { throw 'ORCHESTRATOR_STORAGE_MISSING: orchestrator has no attached VHD' }
$managedRoot = Split-Path -Parent (Split-Path -Parent ([string]$disks[0].Path))
$metadata = [ordered]@{
 schema_version=%d; physical_host_id=%s; orchestrator_id=%s; owner_marker=%s
 host_fence=[int64]%d; lifecycle_state='customizing'; managed_root=$managedRoot
 expected_vhd_paths=@([string]$disks[0].Path); node_name=%s; vm_guid=[string]$vm[0].Id
 generation=[int64]1; private_adapters=@()
}
$vm[0] | Set-VM -Notes (%s + ($metadata | ConvertTo-Json -Depth 20 -Compress)) -ErrorAction Stop
[pscustomobject]@{
 name=[string]$vm[0].Name; vm_guid=[string]$vm[0].Id; state=[string]$vm[0].State
 metadata_kind='orchestrator'; physical_host_id=%s; orchestrator_id=%s
 resource_id=%s; host_fence=[int64]%d; generation=[int64]1; lifecycle_state='customizing'
 expected_vhd=[string]$disks[0].Path
} | ConvertTo-Json -Compress
`, hyperv.PSLit(record.HyperVName), hyperv.IsolatedMetadataSchema,
		hyperv.PSLit(record.PhysicalHostID), hyperv.PSLit(record.ID), hyperv.PSLit(owner),
		lease.Fence, hyperv.PSLit(record.NodeName),
		hyperv.PSLit(hyperv.IsolatedOrchestratorMetadataPrefix),
		hyperv.PSLit(record.PhysicalHostID), hyperv.PSLit(record.ID),
		hyperv.PSLit(record.ID), lease.Fence)
	out, _, err := runPS(ctx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return hyperv.IsolatedVMObservation{}, err
	}
	var observation hyperv.IsolatedVMObservation
	err = json.Unmarshal([]byte(jsonExtract(out)), &observation)
	return observation, err
}

func (h productionIsolatedHost) CreateSwitch(
	ctx context.Context, target Target, params hyperv.CreateIsolatedPrivateSwitchParams,
) (hyperv.IsolatedSwitchMutationResult, error) {
	script, err := hyperv.BuildCreateIsolatedPrivateSwitchScript(params)
	if err != nil {
		return hyperv.IsolatedSwitchMutationResult{}, err
	}
	out, _, err := runPS(ctx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return hyperv.IsolatedSwitchMutationResult{}, err
	}
	return hyperv.ParseIsolatedSwitchMutationResult(jsonExtract(out))
}

func (h productionIsolatedHost) AttachNIC(
	ctx context.Context, target Target, params hyperv.AttachIsolatedNICParams,
) (hyperv.IsolatedAdapterMutationResult, error) {
	script, err := hyperv.BuildAttachIsolatedNICScript(params)
	if err != nil {
		return hyperv.IsolatedAdapterMutationResult{}, err
	}
	out, _, err := runPS(ctx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return hyperv.IsolatedAdapterMutationResult{}, err
	}
	return hyperv.ParseIsolatedAdapterMutationResult(jsonExtract(out))
}

func (h productionIsolatedHost) RemoveNIC(
	ctx context.Context, target Target, params hyperv.RemoveIsolatedNICParams,
) (hyperv.IsolatedAdapterMutationResult, error) {
	script, err := hyperv.BuildRemoveIsolatedNICScript(params)
	if err != nil {
		return hyperv.IsolatedAdapterMutationResult{}, err
	}
	out, _, err := runPS(ctx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return hyperv.IsolatedAdapterMutationResult{}, err
	}
	return hyperv.ParseIsolatedAdapterMutationResult(jsonExtract(out))
}

func (h productionIsolatedHost) DeleteSwitch(
	ctx context.Context, target Target, params hyperv.DeleteIsolatedPrivateSwitchParams,
) (hyperv.IsolatedSwitchMutationResult, error) {
	script, err := hyperv.BuildDeleteIsolatedPrivateSwitchScript(params)
	if err != nil {
		return hyperv.IsolatedSwitchMutationResult{}, err
	}
	out, _, err := runPS(ctx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return hyperv.IsolatedSwitchMutationResult{}, err
	}
	return hyperv.ParseIsolatedSwitchMutationResult(jsonExtract(out))
}

type productionOrchestratorProbe struct {
	host      productionIsolatedHost
	appliance isolatedAppliance
	registry  *registry.Registry
	version   string
}

func (p productionOrchestratorProbe) ObserveOrchestrator(
	ctx context.Context,
	record isolatedstate.Orchestrator,
) (isolated.OrchestratorObservation, error) {
	target, err := p.host.target(record.HostNode)
	if err != nil {
		return isolated.OrchestratorObservation{}, err
	}
	discovery, err := p.host.Discover(ctx, target, record.ID, valueOrEmpty(record.HyperVVMID))
	if err != nil {
		return isolated.OrchestratorObservation{Record: record}, err
	}
	observation := isolated.OrchestratorObservation{
		Record: record, HostReachable: true, MainNICHealthy: true,
		ImmutableIdentityMatch: true,
		Capacity: isolated.OperationCapacity{
			FreeSubnets: 1, PrivateAdapterSlots: 1, SwitchSlots: 1,
			HostResourcesAvailable: true, FreeGuestIPs: 1, FreeMACs: 1,
			FreeRelayPorts: 1, FreeConntrackMarks: 1, GuestSlots: 1,
			NATSupported: true, ReservedConntrackMark: true,
		},
	}
	for _, vm := range discovery.VMs {
		if vm.OrchestratorID == record.ID && vm.ResourceID == record.ID {
			observation.VMState = vm.State
			if record.HyperVVMID != nil && !strings.EqualFold(vm.VMGUID, *record.HyperVVMID) {
				observation.ImmutableIdentityMatch = false
			}
			break
		}
	}
	readiness, readyErr := p.appliance.CheckReadiness(ctx, record.ID)
	if readyErr == nil {
		observation.AgentAuthenticated = true
		observation.Agent = isolated.AgentCompatibility{
			Node: readiness.Node, AgentVersion: readiness.AgentVersion,
			Capabilities: readiness.Capabilities, ProtocolVersion: readiness.ProtocolVersion,
		}
		observation.ApplianceReady = readiness.Ready
		snapshot, inspectErr := p.appliance.InspectApplianceState(ctx, record.ID)
		if inspectErr == nil {
			observation.AppliancePolicyVerified = snapshot.PolicyVerified
			observation.ApplianceSchema = int(snapshot.SchemaVersion)
		}
	}
	return observation, nil
}

func (p productionOrchestratorProbe) RecoverOrchestrator(
	ctx context.Context,
	record isolatedstate.Orchestrator,
) (isolated.RecoveryResult, error) {
	target, err := p.host.target(record.HostNode)
	if err != nil {
		return isolated.RecoveryResult{}, err
	}
	discovery, err := p.host.Discover(ctx, target, record.ID, valueOrEmpty(record.HyperVVMID))
	if err != nil {
		return isolated.RecoveryResult{}, err
	}
	steps := []isolated.RecoveryStep{}
	for _, vm := range discovery.VMs {
		if vm.OrchestratorID == record.ID && strings.EqualFold(vm.State, "off") {
			script := fmt.Sprintf("Start-VM -Id %s -ErrorAction Stop; [pscustomobject]@{started=$true}|ConvertTo-Json -Compress", hyperv.PSLit(vm.VMGUID))
			if _, _, err := runPS(ctx, p.host.reg, p.host.pool, target, script, 1000); err != nil {
				return isolated.RecoveryResult{}, err
			}
			steps = append(steps, isolated.RecoveryStep{Action: "start_vm", Detail: vm.VMGUID})
			break
		}
	}
	observation, err := p.ObserveOrchestrator(ctx, record)
	return isolated.RecoveryResult{Observation: observation, Steps: steps}, err
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func NewIsolatedLifecycleDependencies(
	s *server.MCPServer,
	store *isolatedstate.Store,
	reg *registry.Registry,
	pool *agentclient.Pool,
	defaults *vmconfig.Store,
	creds *credentials.Store,
	auditLog *audit.Log,
	enrollment VMEnrollmentConfig,
	leaseCfg LeaseGateConfig,
	serverVersion string,
) (*isolatedLifecycleDeps, error) {
	if store == nil {
		return nil, errors.New("isolated lifecycle requires an open isolated state store")
	}
	locks, err := isolatedstate.NewLockManager(store, isolatedstate.LockManagerOptions{})
	if err != nil {
		return nil, err
	}
	host := productionIsolatedHost{reg: reg, pool: pool, defaults: defaults}
	applianceClient := isolated.NewApplianceClient(reg, pool, serverVersion)
	stateAdapter := isolatedStateAdapter{store: store}
	probe := productionOrchestratorProbe{
		host: host, appliance: applianceClient, registry: reg, version: serverVersion,
	}
	deps := &isolatedLifecycleDeps{
		server: s, state: store, locks: locks, host: host, appliance: applianceClient,
		orchestrators: stateAdapter, planner: host, probe: probe,
		registry: reg, pool: pool, defaults: defaults, credentials: creds,
		audit: auditLog, enrollment: enrollment, lease: leaseCfg,
		serverVersion: serverVersion,
	}
	deps.networks = isolatedNetworkStateAdapter{state: deps.state}
	deps.networkHost = isolatedNetworkHostAdapter{
		host: deps.host, state: deps.state,
		reg: func(hostNode string) (Target, error) {
			return resolvePlanTarget(hostNode, deps.registry)
		},
	}
	deps.linux = productionLinuxCreator{deps: deps}
	return deps, nil
}

func RegisterIsolatedLifecycleTools(s *server.MCPServer, deps *isolatedLifecycleDeps) {
	RegisterIsolatedOrchestratorTools(s, deps)
	RegisterIsolatedNetworkTools(s, deps)
	RegisterIsolatedRelayTools(s, deps)
}

func RegisterIsolatedOrchestratorTools(s *server.MCPServer, deps *isolatedLifecycleDeps) {
	s.AddTool(mcp.NewTool("create_isolated_orchestrator",
		mcp.WithDescription("Reuse/recover the oldest compatible isolated orchestrator, or approval-gate creation of an Ubuntu 24.04 appliance."),
		mcp.WithString("target", mcp.Description("localhost or a registered Windows Hyper-V host")),
		mcp.WithString("orchestrator_id", mcp.Description("Optional exact orchestrator UUID")),
		mcp.WithString("display_name", mcp.Description("Mutable display label")),
		mcp.WithString("profile", mcp.Description("Exact isolated orchestrator profile")),
		mcp.WithString("main_vswitch", mcp.Description("Exact existing main vSwitch override")),
		mcp.WithBoolean("dry_run", mcp.Description("Resolve and preflight without mutation or approval")),
		mcp.WithString("approved_plan_revision", mcp.Description("Exact approved creation plan revision")),
		mcp.WithString("operation_id", mcp.Description("Durable operation UUID")),
		mcp.WithBoolean("resume_exact", mcp.Description("Resume only exact canonical arguments")),
		mcp.WithNumber("expected_generation", mcp.Description("Optional generation guard")),
	), createIsolatedOrchestratorHandler(deps))
	s.AddTool(mcp.NewTool("list_isolated_orchestrators",
		mcp.WithDescription("List durable isolated orchestrators; live=true adds read-only host/appliance observations."),
		mcp.WithString("target"), mcp.WithBoolean("include_deleted"), mcp.WithBoolean("live"),
	), listIsolatedOrchestratorsHandler(deps))
	s.AddTool(mcp.NewTool("get_isolated_orchestrator",
		mcp.WithDescription("Get one exact isolated orchestrator."),
		mcp.WithString("orchestrator_id", mcp.Required()), mcp.WithBoolean("live"),
	), getIsolatedOrchestratorHandler(deps))
	s.AddTool(mcp.NewTool("reconcile_isolated_orchestrator",
		mcp.WithDescription("Import appliance-authoritative truth and repair exact registry addressing without deleting unknown resources."),
		mcp.WithString("orchestrator_id", mcp.Required()),
		mcp.WithBoolean("refresh_dns"), mcp.WithBoolean("repair_registry_addresses"),
		mcp.WithString("operation_id"), mcp.WithBoolean("resume_exact"),
		mcp.WithNumber("expected_generation"),
	), reconcileIsolatedOrchestratorHandler(deps))
	s.AddTool(mcp.NewTool("delete_isolated_orchestrator",
		mcp.WithDescription("Approval-gated exact orchestrator deletion. Refuses children unless cascade=true."),
		mcp.WithString("orchestrator_id", mcp.Required()), mcp.WithBoolean("cascade"),
		mcp.WithString("approved_plan_revision"), mcp.WithString("operation_id"),
		mcp.WithBoolean("resume_exact"), mcp.WithNumber("expected_generation"),
	), deleteIsolatedOrchestratorHandler(deps))
}

func resolveOrchestratorProfile(
	req mcp.CallToolRequest,
	defaults *vmconfig.Store,
) (vmconfig.ResolvedIsolatedOrchestratorProfile, string, error) {
	resolved, profileName, err := defaults.ResolveIsolatedOrchestrator(req.GetString("profile", ""))
	if err != nil {
		return resolved, "", err
	}
	if profileName == "" {
		return resolved, "", fmt.Errorf("isolated orchestrator profile is required; configure default_isolated_orchestrator_profile or pass profile")
	}
	mainSwitch := strings.TrimSpace(req.GetString("main_vswitch", ""))
	if mainSwitch != "" {
		resolved.Profile.MainVSwitch = mainSwitch
		resolved.LinuxVM.VSwitch = mainSwitch
	}
	return resolved, profileName, nil
}

func createIsolatedOrchestratorHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		target, err := resolveTarget(req, deps.registry)
		if err != nil {
			return isolatedError(err)
		}
		profile, profileName, err := resolveOrchestratorProfile(req, deps.defaults)
		if err != nil {
			return isolatedError(err)
		}
		host, err := deps.host.PhysicalIdentity(ctx, target)
		if err != nil {
			return isolatedError(err)
		}
		hostID, err := isolated.ParsePhysicalHostID(host.PhysicalHostID)
		if err != nil {
			return isolatedError(err)
		}
		operationID, err := isolatedOperationID(req)
		if err != nil {
			return isolatedError(err)
		}
		resumedResource, err := resumeResourceID(ctx, deps.state, operationID, "orchestrator")
		if err != nil {
			return isolatedError(err)
		}
		var orchestratorID isolated.OrchestratorID
		if raw := strings.TrimSpace(req.GetString("orchestrator_id", "")); raw != "" {
			orchestratorID, err = isolated.ParseOrchestratorID(raw)
		} else if resumedResource != "" {
			orchestratorID, err = isolated.ParseOrchestratorID(resumedResource)
		} else {
			orchestratorID, err = isolated.NewOrchestratorID()
		}
		if err != nil {
			return isolatedError(err)
		}
		names, err := isolated.OrchestratorNames(orchestratorID)
		if err != nil {
			return isolatedError(err)
		}
		displayName := strings.TrimSpace(req.GetString("display_name", ""))
		if displayName == "" {
			displayName = names.HyperVName
		}
		inputs := map[string]any{
			"target": target.Name, "physical_host_id": hostID.String(),
			"orchestrator_id": orchestratorID.String(), "display_name": displayName,
			"profile": profileName, "linux_profile": profile.LinuxProfileName,
			"main_vswitch": profile.Profile.MainVSwitch,
			"cpu_count":    profile.Profile.CPUCount, "memory_mb": profile.Profile.MemoryMB,
		}
		if req.GetBool("dry_run", false) {
			preflight, planErr := deps.host.Preflight(ctx, target, isolated.ResourcePreflightInput{
				PhysicalHostID: hostID.String(), HostNode: target.Name,
				MainVSwitch: profile.Profile.MainVSwitch, ProfileName: profileName,
				ProjectedMemoryMB:           int(profile.Profile.MemoryMB),
				ProjectedStorageBytes:       int64(profile.LinuxVM.DiskSizeGB * 1024 * 1024 * 1024),
				RequiredPrivateAdapterSlots: 1, RequiredSwitchSlots: 1,
				RequiredFreeSubnets: 1,
			}, profile.LinuxVM)
			if planErr != nil {
				return isolatedError(planErr)
			}
			return isolatedResult(isolatedToolResult{
				OperationID: operationID, Status: "planned", Phase: "dry_run",
				ResourceID: orchestratorID.String(), Plan: map[string]any{
					"inputs": inputs, "preflight": preflight,
					"approval_required_if_created": true,
				}, NextAction: nil,
			}), nil
		}

		progress, stop := StartMCPProgress(ctx, req, 30*time.Minute, "resolve", "resolved exact profile and host identity")
		defer stop()
		workflow, err := beginIsolatedWorkflow(ctx, deps.state, progress, isolatedstate.BeginOperationRequest{
			ID: operationID, Kind: "create_isolated_orchestrator",
			ResourceType: "orchestrator", ResourceID: orchestratorID.String(),
			HostNode: &target.Name, OrchestratorID: optionalTrimmed(orchestratorID.String()),
			CanonicalInputs: inputs, ResumeExact: req.GetBool("resume_exact", false),
		})
		if err != nil {
			return isolatedError(err)
		}
		lockKey, _ := isolatedstate.HostLockKey(hostID.String())
		localLease, err := deps.locks.Acquire(ctx, isolatedstate.LockAcquireRequest{
			Key: lockKey, OperationID: operationID, TTL: isolatedOperationTTL,
		})
		if err != nil {
			return isolatedError(err)
		}
		defer deps.locks.Release(context.Background(), localLease)

		var createPlan isolated.OrchestratorCreatePlan
		domain := isolated.OrchestratorDomain{
			State: deps.orchestrators, Probe: deps.probe, Host: deps.planner,
		}
		err = workflow.phaseAlways(ctx, 0, "host_lock", "acquiring remote host fence and rechecking reusable capacity", func() (any, error) {
			var planErr error
			createPlan, planErr = domain.PlanCreateOrReuse(ctx, isolated.OrchestratorCreateRequest{
				OperationID: operationID, PhysicalHostID: hostID.String(), HostNode: target.Name,
				DisplayName: displayName, ProfileName: profileName,
				MainVSwitch: profile.Profile.MainVSwitch, OrchestratorID: orchestratorID,
				ProjectedStorageBytes: int64(profile.LinuxVM.DiskSizeGB * 1024 * 1024 * 1024),
				ServerVersion:         deps.serverVersion,
			})
			return map[string]any{
				"plan": createPlan.Plan, "preflight": createPlan.Preflight,
				"reused": createPlan.Reused, "lease_id": createPlan.Lease.LeaseID,
				"fence": createPlan.Lease.Fence,
			}, planErr
		})
		if err != nil {
			return isolatedError(err)
		}
		if createPlan.Lease.LeaseID != "" {
			defer deps.host.ReleaseFence(context.Background(), target, createPlan.Lease)
		}
		if createPlan.Reused != nil {
			return workflow.finish(ctx, isolatedstate.OperationSucceeded, isolatedToolResult{
				Status: "succeeded", Phase: "reuse_recheck",
				ResourceID: createPlan.Reused.Orchestrator.ID,
				Generation: int64(createPlan.Reused.Orchestrator.DesiredGeneration),
				Resource:   createPlan.Reused, NextAction: nil,
			})
		}
		approved, approvalResult, err := approveRevision(
			ctx, deps.server, deps.state, req, operationID,
			"create_isolated_orchestrator", createPlan.Plan,
			"Create a new Ubuntu isolated-orchestrator VM with this exact plan?", "")
		if err != nil {
			return isolatedError(err)
		}
		if !approved {
			_, _ = deps.state.UpdateOperation(ctx, isolatedstate.OperationUpdate{
				OperationID: operationID, Status: isolatedstate.OperationApprovalRequired,
				CurrentPhase: "approval_required", Result: createPlan.Plan,
			})
			return approvalResult, nil
		}

		now := isolatedstate.UnixSeconds(time.Now().Unix())
		record := isolatedstate.Orchestrator{
			ID: orchestratorID.String(), DisplayName: displayName,
			PhysicalHostID: hostID.String(), HostNode: target.Name,
			HyperVName: names.HyperVName, NodeName: names.NodeName,
			ProfileName: profileName, MainVSwitch: profile.Profile.MainVSwitch,
			AgentPort: 9091, DesiredGeneration: 1, HostFence: createPlan.Lease.Fence,
			LifecycleState: isolatedstate.OrchestratorCreating, HealthState: "creating",
			MaxNetworks: profile.Profile.MaxNetworks, MaxVMs: profile.Profile.MaxVMs,
			CreatedAt: now, UpdatedAt: now,
		}
		if err := deps.state.PutOrchestrator(ctx, record); err != nil {
			return isolatedError(err)
		}
		var linuxPlan linuxVMPlan
		err = workflow.phase(ctx, 1, "create_linux_vm", "creating or exactly resuming the ordinary Ubuntu VM bootstrap", func() (any, error) {
			linuxReq := req
			args := cloneArguments(req.GetArguments())
			args["target"] = target.Name
			args["profile"] = profile.LinuxProfileName
			args["name"] = names.HyperVName
			args["hostname"] = names.NodeName
			args["lablink_node_name"] = names.NodeName
			args["lablink_role"] = "isolated-orchestrator"
			args["lablink_port"] = float64(9091)
			args["vswitch"] = profile.Profile.MainVSwitch
			args["cpu_count"] = profile.Profile.CPUCount
			args["memory_mb"] = profile.Profile.MemoryMB
			args["dynamic_memory"] = false
			args["register_with_lablink"] = true
			linuxReq.Params.Arguments = args
			linuxReq.Params.Name = "create_linux_vm"
			var planErr error
			linuxPlan, _, planErr = resolveLinuxVMPlan(linuxReq, deps.registry, deps.defaults, deps.credentials)
			if planErr != nil {
				return nil, planErr
			}
			seed := profile.SeedConfig(deps.serverVersion, orchestratorID.String())
			linuxPlan.Orchestrator = &seed
			result, createErr := deps.linux.Create(ctx, linuxReq, linuxPlan, target, progress)
			if createErr != nil {
				return nil, createErr
			}
			if result == nil || result.IsError {
				return result, fmt.Errorf("create_linux_vm did not complete successfully: %s", toolResultText(result))
			}
			return map[string]any{"hyperv_name": linuxPlan.Name, "node_name": linuxPlan.LabLinkNodeName}, nil
		})
		if err != nil {
			return isolatedError(err)
		}
		var hostObservation hyperv.IsolatedVMObservation
		err = workflow.phase(ctx, 2, "verify_host_identity", "claiming exact Hyper-V identity under the host fence", func() (any, error) {
			observation, claimErr := deps.host.ClaimOrchestrator(ctx, target, record, createPlan.Lease)
			if claimErr != nil {
				return nil, claimErr
			}
			hostObservation = observation
			record.HyperVVMID = &observation.VMGUID
			record.LifecycleState = isolatedstate.OrchestratorCustomizing
			record.UpdatedAt = isolatedstate.UnixSeconds(time.Now().Unix())
			return observation, deps.state.PutOrchestrator(ctx, record)
		})
		if err != nil {
			return isolatedError(err)
		}
		if record.HyperVVMID == nil {
			if _, err := workflow.loadPhase(ctx, 2, "verify_host_identity", &hostObservation); err != nil {
				return isolatedError(err)
			}
			record.HyperVVMID = optionalTrimmed(hostObservation.VMGUID)
		}
		err = workflow.phase(ctx, 3, "verify_capabilities", "verifying strict mTLS identity and appliance readiness", func() (any, error) {
			node, found := deps.registry.GetNode(record.NodeName)
			if !found {
				return nil, fmt.Errorf("ORCHESTRATOR_NODE_NOT_FOUND: %s", record.NodeName)
			}
			node.Role = "isolated-orchestrator"
			if node.Labels == nil {
				node.Labels = map[string]string{}
			}
			node.Labels["lablink.orchestrator_id"] = record.ID
			node.Labels["lablink.kind"] = "isolated-orchestrator"
			if err := deps.registry.SetNode(node); err != nil {
				return nil, err
			}
			readiness, readyErr := deps.appliance.CheckReadiness(ctx, record.ID)
			if readyErr != nil {
				return readiness, readyErr
			}
			record.MainIP = optionalTrimmed(nodeHost(node.Address))
			record.ApplianceSchema = isolated.MinimumApplianceSchema
			record.AppliedGeneration = 1
			record.ObservedGeneration = 1
			record.LifecycleState = isolatedstate.OrchestratorReady
			record.HealthState = "ready"
			record.UpdatedAt = isolatedstate.UnixSeconds(time.Now().Unix())
			seen := record.UpdatedAt
			record.LastSeenAt = &seen
			return readiness, deps.state.PutOrchestrator(ctx, record)
		})
		if err != nil {
			return isolatedError(err)
		}
		if persisted, getErr := deps.state.GetOrchestrator(ctx, record.ID); getErr == nil {
			record = persisted
		}
		return workflow.finish(ctx, isolatedstate.OperationSucceeded, isolatedToolResult{
			Status: "succeeded", Phase: "ready", ResourceID: record.ID,
			Generation: int64(record.DesiredGeneration), Resource: record, NextAction: nil,
		})
	}
}

func listIsolatedOrchestratorsHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		hostID := ""
		if targetName := strings.TrimSpace(req.GetString("target", "")); targetName != "" {
			target, err := resolveTarget(req, deps.registry)
			if err != nil {
				return isolatedError(err)
			}
			host, err := deps.host.PhysicalIdentity(ctx, target)
			if err != nil {
				return isolatedError(err)
			}
			hostID = host.PhysicalHostID
		}
		values, err := deps.state.ListOrchestrators(ctx, hostID)
		if err != nil {
			return isolatedError(err)
		}
		filtered := values[:0]
		for _, value := range values {
			if !req.GetBool("include_deleted", false) && value.LifecycleState == isolatedstate.OrchestratorDeleted {
				continue
			}
			filtered = append(filtered, value)
		}
		var resource any = filtered
		if req.GetBool("live", false) {
			live := make([]map[string]any, 0, len(filtered))
			for _, value := range filtered {
				item := map[string]any{"record": value}
				observation, observeErr := deps.probe.ObserveOrchestrator(ctx, value)
				if observeErr != nil {
					item["error"] = observeErr.Error()
				} else {
					item["observation"] = observation
				}
				live = append(live, item)
			}
			resource = live
		}
		return isolatedResult(isolatedToolResult{
			Status: "succeeded", Phase: "list", ResourceID: hostID,
			Resource: resource, NextAction: nil,
		}), nil
	}
}

func getIsolatedOrchestratorHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := isolated.ParseOrchestratorID(req.GetString("orchestrator_id", ""))
		if err != nil {
			return isolatedError(err)
		}
		value, err := deps.state.GetOrchestrator(ctx, id.String())
		if err != nil {
			return isolatedError(err)
		}
		var detail any
		if req.GetBool("live", false) {
			detail, err = deps.probe.ObserveOrchestrator(ctx, value)
			if err != nil {
				detail = map[string]any{"error": err.Error()}
			}
		}
		return isolatedResult(isolatedToolResult{
			Status: "succeeded", Phase: "get", ResourceID: value.ID,
			Generation: int64(value.DesiredGeneration), Resource: value,
			Detail: detail, NextAction: nil,
		}), nil
	}
}

func reconcileIsolatedOrchestratorHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := isolated.ParseOrchestratorID(req.GetString("orchestrator_id", ""))
		if err != nil {
			return isolatedError(err)
		}
		record, err := deps.state.GetOrchestrator(ctx, id.String())
		if err != nil {
			return isolatedError(err)
		}
		expected, err := expectedGeneration(req, record.DesiredGeneration)
		if err != nil {
			return isolatedError(err)
		}
		operationID, err := isolatedOperationID(req)
		if err != nil {
			return isolatedError(err)
		}
		inputs := map[string]any{
			"orchestrator_id": id.String(), "refresh_dns": req.GetBool("refresh_dns", false),
			"repair_registry_addresses": req.GetBool("repair_registry_addresses", false),
			"expected_generation":       expected,
		}
		progress, stop := StartMCPProgress(ctx, req, 10*time.Minute, "reconcile", "reading host and appliance truth")
		defer stop()
		workflow, err := beginIsolatedWorkflow(ctx, deps.state, progress, isolatedstate.BeginOperationRequest{
			ID: operationID, Kind: "reconcile_isolated_orchestrator",
			ResourceType: "orchestrator", ResourceID: id.String(),
			HostNode: &record.HostNode, OrchestratorID: optionalTrimmed(id.String()),
			CanonicalInputs: inputs, ResumeExact: req.GetBool("resume_exact", false),
		})
		if err != nil {
			return isolatedError(err)
		}
		var snapshot isolated.ApplianceSnapshot
		err = workflow.phaseAlways(ctx, 0, "import_appliance_truth", "importing known appliance resources without deleting unknown host resources", func() (any, error) {
			var inspectErr error
			snapshot, inspectErr = deps.appliance.InspectApplianceState(ctx, id.String())
			if inspectErr != nil {
				return nil, inspectErr
			}
			for _, network := range snapshot.Desired.Networks {
				if network.RetiredAtUnix != nil {
					continue
				}
				existing, getErr := deps.state.GetNetwork(ctx, network.ID)
				if getErr != nil && !errors.Is(getErr, isolatedstate.ErrNetworkNotFound) {
					return nil, getErr
				}
				if errors.Is(getErr, isolatedstate.ErrNetworkNotFound) {
					existing = isolatedstate.PrivateNetwork{
						ID: network.ID, OrchestratorID: id.String(),
						DisplayName: network.ID, CIDR: network.CIDR,
						GatewayIPv4: network.GatewayIPv4, OrchestratorMAC: network.NICMAC,
						DNSServersJSON: "[]", LifecycleState: isolatedstate.NetworkDegraded,
						CreatedAt: isolatedstate.UnixSeconds(time.Now().Unix()),
					}
				}
				existing.DesiredGeneration = isolatedstate.Generation(network.DesiredGeneration)
				existing.AppliedGeneration = isolatedstate.Generation(network.AppliedGeneration)
				existing.ObservedGeneration = isolatedstate.Generation(network.ObservedGeneration)
				existing.UpdatedAt = isolatedstate.UnixSeconds(time.Now().Unix())
				if putErr := deps.state.PutNetwork(ctx, existing); putErr != nil {
					return nil, putErr
				}
			}
			return map[string]any{
				"inventory_generation":      snapshot.InventoryGeneration,
				"unknown_resources_deleted": false,
			}, nil
		})
		if err != nil {
			return isolatedError(err)
		}
		if req.GetBool("repair_registry_addresses", false) && strings.TrimSpace(snapshot.MainIPv4) != "" {
			node, found := deps.registry.GetNode(record.NodeName)
			if !found {
				return isolatedError(fmt.Errorf("ORCHESTRATOR_NODE_NOT_FOUND: %s", record.NodeName))
			}
			node.Address = fmt.Sprintf("%s:%d", snapshot.MainIPv4, record.AgentPort)
			node.TLSServerName = record.NodeName
			node.TransportMode = "mtls"
			if err := deps.registry.SetNode(node); err != nil {
				return isolatedError(err)
			}
			record.MainIP = optionalTrimmed(snapshot.MainIPv4)
		}
		record.DesiredGeneration++
		record.AppliedGeneration = record.DesiredGeneration
		record.ObservedGeneration = record.DesiredGeneration
		record.ApplianceSchema = int(snapshot.SchemaVersion)
		record.HealthState = "ready"
		record.UpdatedAt = isolatedstate.UnixSeconds(time.Now().Unix())
		if err := deps.state.PutOrchestrator(ctx, record); err != nil {
			return isolatedError(err)
		}
		return workflow.finish(ctx, isolatedstate.OperationSucceeded, isolatedToolResult{
			Status: "succeeded", Phase: "reconciled", ResourceID: record.ID,
			Generation: int64(record.DesiredGeneration), Resource: record,
			Detail: map[string]any{"unknown_resources_deleted": false}, NextAction: nil,
		})
	}
}

func deleteIsolatedOrchestratorHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := isolated.ParseOrchestratorID(req.GetString("orchestrator_id", ""))
		if err != nil {
			return isolatedError(err)
		}
		record, err := deps.state.GetOrchestrator(ctx, id.String())
		if err != nil {
			return isolatedError(err)
		}
		expected, err := expectedGeneration(req, record.DesiredGeneration)
		if err != nil {
			return isolatedError(err)
		}
		networks, err := deps.state.ListNetworks(ctx, id.String())
		if err != nil {
			return isolatedError(err)
		}
		vms, err := deps.state.ListVMs(ctx, id.String(), "")
		if err != nil {
			return isolatedError(err)
		}
		relays, err := deps.state.ListRelays(ctx, id.String(), "")
		if err != nil {
			return isolatedError(err)
		}
		var children []isolated.CascadeChild
		for _, value := range networks {
			if value.LifecycleState != isolatedstate.NetworkDeleted {
				children = append(children, isolated.CascadeChild{
					ResourceType: "network", ResourceID: value.ID, Action: "delete",
					ExpectedHostIdentity: valueOrEmpty(value.HyperVSwitchGUID),
					ExpectedGeneration:   value.DesiredGeneration,
				})
			}
		}
		for _, value := range vms {
			if value.LifecycleState != isolatedstate.VMDeleted {
				children = append(children, isolated.CascadeChild{
					ResourceType: "vm", ResourceID: value.ID, Action: "delete",
					ExpectedHostIdentity: valueOrEmpty(value.HyperVVMID),
					ExpectedGeneration:   value.DesiredGeneration,
				})
			}
		}
		for _, value := range relays {
			if value.LifecycleState != isolatedstate.RelayRemoved {
				children = append(children, isolated.CascadeChild{
					ResourceType: "relay", ResourceID: value.ID, Action: "remove",
					ExpectedApplianceIdentity: fmt.Sprint(value.ListenPort),
					ExpectedGeneration:        value.DesiredGeneration,
				})
			}
		}
		cascade := req.GetBool("cascade", false)
		if len(children) != 0 && !cascade {
			return isolatedError(fmt.Errorf("ORCHESTRATOR_NOT_EMPTY: %d live child resources remain; retry with cascade=true", len(children)))
		}
		operationID, err := isolatedOperationID(req)
		if err != nil {
			return isolatedError(err)
		}
		progress, stop := StartMCPProgress(ctx, req, 20*time.Minute, "plan_delete", "enumerating exact deletion identities")
		defer stop()
		workflow, err := beginIsolatedWorkflow(ctx, deps.state, progress, isolatedstate.BeginOperationRequest{
			ID: operationID, Kind: "delete_isolated_orchestrator",
			ResourceType: "orchestrator", ResourceID: record.ID,
			HostNode: &record.HostNode, OrchestratorID: optionalTrimmed(record.ID),
			CanonicalInputs: map[string]any{
				"orchestrator_id": record.ID, "cascade": cascade,
				"expected_generation": expected,
			},
			ResumeExact: req.GetBool("resume_exact", false),
		})
		if err != nil {
			return isolatedError(err)
		}
		deletePlan, err := isolated.BuildOrchestratorDeletePlan(isolated.DeleteOrchestratorRequest{
			OperationID: operationID, Orchestrator: record, Cascade: cascade,
			Children: children, ExpectedGeneration: expected,
		})
		if err != nil {
			return isolatedError(err)
		}
		extraApproval := ""
		if cascade {
			extraApproval = "acknowledge_cascade"
		}
		approved, approvalResult, err := approveRevision(
			ctx, deps.server, deps.state, req, operationID,
			"delete_isolated_orchestrator", deletePlan.Plan,
			"Delete this exact isolated orchestrator and enumerated children?",
			extraApproval)
		if err != nil {
			return isolatedError(err)
		}
		if !approved {
			_, _ = deps.state.UpdateOperation(ctx, isolatedstate.OperationUpdate{
				OperationID: operationID, Status: isolatedstate.OperationApprovalRequired,
				CurrentPhase: "approval_required", Result: deletePlan.Plan,
			})
			return approvalResult, nil
		}
		if len(vms) != 0 {
			return isolatedError(fmt.Errorf("CASCADE_GUEST_LIFECYCLE_REQUIRED: isolated guest deletion is owned by the guest lifecycle tools; no resources were deleted"))
		}
		if len(networks) != 0 || len(relays) != 0 {
			return isolatedError(fmt.Errorf("CASCADE_CHILDREN_REMAIN: remove relay and network children first; approved plan was preserved"))
		}
		record.LifecycleState = isolatedstate.OrchestratorDeleting
		record.HealthState = "deleting"
		record.UpdatedAt = isolatedstate.UnixSeconds(time.Now().Unix())
		if err := deps.state.PutOrchestrator(ctx, record); err != nil {
			return isolatedError(err)
		}
		if err := workflow.phase(ctx, 0, "delete_linux_vm", "deleting exact managed orchestrator VM and owned storage", func() (any, error) {
			deleteReq := req
			deleteReq.Params.Name = "delete_vm"
			deleteReq.Params.Arguments = map[string]any{
				"target": record.HostNode, "name": record.HyperVName,
				"dry_run": false, "force_stop": true, "delete_storage": true,
				"unregister_node": true, "delete_identity": false,
			}
			result, deleteErr := deleteVMHandler(
				deps.registry, deps.pool, deps.defaults, deps.audit, deps.enrollment,
			)(ctx, deleteReq)
			if deleteErr != nil {
				return nil, deleteErr
			}
			if result == nil || result.IsError {
				return result, fmt.Errorf("delete_vm failed: %s", toolResultText(result))
			}
			return map[string]any{"hyperv_name": record.HyperVName, "storage_deleted": true}, nil
		}); err != nil {
			return isolatedError(err)
		}
		record.DesiredGeneration++
		record.LifecycleState = isolatedstate.OrchestratorDeleted
		record.HealthState = "deleted"
		record.UpdatedAt = isolatedstate.UnixSeconds(time.Now().Unix())
		if err := deps.state.PutOrchestrator(ctx, record); err != nil {
			return isolatedError(err)
		}
		_ = deps.registry.RemoveNode(record.NodeName)
		return workflow.finish(ctx, isolatedstate.OperationSucceeded, isolatedToolResult{
			Status: "succeeded", Phase: "deleted",
			ResourceID: record.ID, Generation: int64(record.DesiredGeneration),
			Resource: record, NextAction: nil,
		})
	}
}
