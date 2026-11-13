package mcptools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/cascadeauth"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/isolated"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/secretstore"
	"github.com/nijosmsft/lablink/internal/vmconfig"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	acquireCtx, cancel := context.WithTimeout(ctx, isolatedHostFenceAcquireTimeout)
	defer cancel()
	out, _, err := runPS(acquireCtx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return isolated.HostFenceLease{}, err
	}
	result, err := hyperv.ParseIsolatedHostLeaseResult(jsonExtract(out))
	if err != nil {
		return isolated.HostFenceLease{}, err
	}
	if !result.Acquired {
		return isolated.HostFenceLease{}, fmt.Errorf(
			"HOST_LOCK_BUSY: operation %s holds lease %s fence %d until %s",
			result.CurrentOperationID, result.CurrentLeaseID,
			result.CurrentFence, result.CurrentExpiresUTC)
	}
	expiresAt, err := time.Parse(time.RFC3339, result.ExpiresUTC)
	if err != nil {
		return isolated.HostFenceLease{}, fmt.Errorf(
			"HOST_FENCE_INVALID: parse host lease expiry %q: %w",
			result.ExpiresUTC, err)
	}
	return isolated.HostFenceLease{
		LeaseID: leaseID.String(), LeaseSecret: secret,
		ExpiresAtUnix: expiresAt.Unix(), Fence: result.Fence,
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

func (h productionIsolatedHost) ReleaseOrchestratorCreateFence(
	ctx context.Context,
	request isolated.HostCreateFenceRequest,
	lease isolated.HostFenceLease,
) error {
	target, err := h.target(request.HostNode)
	if err != nil {
		return err
	}
	return h.ReleaseFenceChecked(ctx, target, lease)
}

func (h productionIsolatedHost) ReconcileStaleOrchestratorMetadata(
	ctx context.Context,
	request isolated.StaleOrchestratorMetadataRequest,
) error {
	target, err := h.target(request.HostNode)
	if err != nil {
		return err
	}
	script, err := hyperv.BuildReconcileStaleIsolatedMetadataScript(
		hyperv.ReconcileStaleIsolatedMetadataParams{
			Guard: hyperv.IsolatedMutationGuard{
				PhysicalHostID: request.PhysicalHostID,
				LeaseID:        request.Lease.LeaseID,
				LeaseSecret:    request.Lease.LeaseSecret,
				Fence:          request.Lease.Fence,
				OrchestratorID: request.OrchestratorID,
				OperationID:    request.OperationID,
				MutationID: isolatedstate.StableMutationID(
					request.OperationID, request.OrchestratorID,
					"reconcile_stale_orchestrator_metadata", "capacity_discovery"),
				ResourceType: "orchestrator",
				ResourceID:   request.OrchestratorID,
				Action:       "reconcile_stale_orchestrator_metadata",
			},
			OrchestratorVMGUID: request.OrchestratorVMID,
			HyperVName:         request.HyperVName,
			LifecycleState:     request.LifecycleState,
		})
	if err != nil {
		return err
	}
	out, _, err := runPS(ctx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return err
	}
	_, err = hyperv.ParseIsolatedMetadataCleanupResult(jsonExtract(out))
	return err
}

func (h productionIsolatedHost) ReleaseFence(
	ctx context.Context,
	target Target,
	lease isolated.HostFenceLease,
) {
	_ = h.ReleaseFenceChecked(ctx, target, lease)
}

func (h productionIsolatedHost) ReleaseFenceChecked(
	ctx context.Context,
	target Target,
	lease isolated.HostFenceLease,
) error {
	physicalID := strings.TrimPrefix(strings.TrimSuffix(lease.LockKey.Key, ":orchestrator-create"), "host:")
	script, err := hyperv.BuildReleaseIsolatedHostLockScript(hyperv.IsolatedHostLeaseParams{
		PhysicalHostID: physicalID, LeaseID: lease.LeaseID,
		LeaseSecret: lease.LeaseSecret, Fence: lease.Fence,
	})
	if err != nil {
		return err
	}
	_, _, err = runPS(ctx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	return err
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
 host_fence=[int64]%d; lifecycle_state=%s; managed_root=$managedRoot
 expected_vhd_paths=@([string]$disks[0].Path); node_name=%s; vm_guid=[string]$vm[0].Id
 generation=[int64]%d; private_adapters=@()
}
$existingNotes = [string]$vm[0].Notes
if ($existingNotes.StartsWith(%s,[StringComparison]::Ordinal)) {
    $existing = $existingNotes.Substring(%s.Length) | ConvertFrom-Json
    if ([string]$existing.physical_host_id -cne [string]$metadata.physical_host_id -or
        [string]$existing.orchestrator_id -cne [string]$metadata.orchestrator_id -or
        [string]$existing.owner_marker -cne [string]$metadata.owner_marker -or
        ([string]$existing.vm_guid -and [string]$existing.vm_guid -cne [string]$metadata.vm_guid)) {
        throw 'ORCHESTRATOR_VM_IDENTITY_MISMATCH: existing parent metadata identity changed'
    }
    $metadata.private_adapters = @($existing.private_adapters)
    if ([int64]$existing.generation -gt [int64]$metadata.generation) {
        throw 'ORCHESTRATOR_GENERATION_MISMATCH: host metadata is newer than the server record'
    }
    if ([string]$existing.lifecycle_state -in @('frozen','deleting','lost','deleted')) {
        $metadata.lifecycle_state = [string]$existing.lifecycle_state
        $metadata.generation = [int64]$existing.generation
    }
}
$vm[0] | Set-VM -Notes (%s + ($metadata | ConvertTo-Json -Depth 20 -Compress)) -ErrorAction Stop
[pscustomobject]@{
 name=[string]$vm[0].Name; vm_guid=[string]$vm[0].Id; state=[string]$vm[0].State
 metadata_kind='orchestrator'; physical_host_id=%s; orchestrator_id=%s
 resource_id=%s; host_fence=[int64]%d; generation=[int64]$metadata.generation
 lifecycle_state=[string]$metadata.lifecycle_state
 expected_vhd=[string]$disks[0].Path
} | ConvertTo-Json -Compress
`, hyperv.PSLit(record.HyperVName), hyperv.IsolatedMetadataSchema,
		hyperv.PSLit(record.PhysicalHostID), hyperv.PSLit(record.ID), hyperv.PSLit(owner),
		lease.Fence, hyperv.PSLit(string(record.LifecycleState)),
		hyperv.PSLit(record.NodeName), record.DesiredGeneration,
		hyperv.PSLit(hyperv.IsolatedOrchestratorMetadataPrefix),
		hyperv.PSLit(hyperv.IsolatedOrchestratorMetadataPrefix),
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

func (h productionIsolatedHost) SetParentLifecycle(
	ctx context.Context,
	target Target,
	record isolatedstate.Orchestrator,
	lease isolated.HostFenceLease,
	authority isolatedstate.CascadeAuthority,
	state string,
) error {
	hostAuthority := cascadeAuthorityForHost(authority)
	script, err := hyperv.BuildSetIsolatedParentLifecycleScript(
		hyperv.SetIsolatedParentLifecycleParams{
			Guard: hyperv.IsolatedMutationGuard{
				PhysicalHostID: record.PhysicalHostID,
				LeaseID:        lease.LeaseID, LeaseSecret: lease.LeaseSecret,
				Fence: lease.Fence, OrchestratorID: record.ID,
				OperationID: authority.OperationID,
				MutationID: isolatedstate.StableMutationID(
					authority.OperationID, record.ID, "set_parent_lifecycle", "freeze_parent"),
				ResourceType: "orchestrator", ResourceID: record.ID,
				Action: "set_parent_lifecycle",
			},
			OrchestratorVMGUID: valueOrEmpty(record.HyperVVMID),
			ExpectedGeneration: int64(authority.FrozenGeneration - 1),
			NewGeneration:      int64(authority.FrozenGeneration),
			NewState:           state, CascadeAuthority: &hostAuthority,
		})
	if err != nil {
		return err
	}
	_, _, err = runPS(ctx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	return err
}

func (h productionIsolatedHost) RebindParentFence(
	ctx context.Context,
	target Target,
	record isolatedstate.Orchestrator,
	lease isolated.HostFenceLease,
	authority isolatedstate.CascadeAuthority,
) error {
	script, err := hyperv.BuildRebindIsolatedParentFenceScript(
		hyperv.RebindIsolatedParentFenceParams{
			Guard: hyperv.IsolatedMutationGuard{
				PhysicalHostID: record.PhysicalHostID,
				LeaseID:        lease.LeaseID, LeaseSecret: lease.LeaseSecret,
				Fence: lease.Fence, OrchestratorID: record.ID,
				OperationID: authority.OperationID,
				MutationID: isolatedstate.StableMutationID(
					authority.OperationID, record.ID, "rebind_parent_fence", "cascade_rebind"),
				ResourceType: "orchestrator", ResourceID: record.ID,
				Action: "rebind_parent_fence",
			},
			OrchestratorVMGUID:    valueOrEmpty(record.HyperVVMID),
			ExpectedPreviousFence: record.HostFence,
			ExpectedGeneration:    int64(authority.FrozenGeneration),
			PlanRevision:          authority.PlanRevision,
			PlanHash:              authority.PlanHash,
		})
	if err != nil {
		return err
	}
	_, _, err = runPS(ctx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return h.SetParentLifecycle(
			ctx, target, record, lease, authority, "frozen")
	}
	return err
}

func cascadeAuthorityForHost(authority isolatedstate.CascadeAuthority) hyperv.CascadeAuthority {
	result := hyperv.CascadeAuthority{
		OrchestratorID:   authority.OrchestratorID,
		FrozenGeneration: int64(authority.FrozenGeneration),
		OperationID:      authority.OperationID, PlanRevision: authority.PlanRevision,
		PlanHash: authority.PlanHash, HostFence: authority.HostFence,
		LeaseID: authority.LeaseID,
	}
	for _, item := range authority.Items {
		action := cascadeauth.Action(item.Action)
		if !cascadeauth.IsHostAction(action) {
			continue
		}
		hostItem := hyperv.CascadeAuthorityItem{
			Action: action, ResourceType: item.ResourceType,
			ResourceID: item.ResourceID, Generation: int64(item.ExpectedGeneration),
		}
		if item.ExpectedHostIdentity != nil {
			switch item.ResourceType {
			case "vm":
				hostItem.VMGUID = *item.ExpectedHostIdentity
			case "network":
				hostItem.SwitchGUID = *item.ExpectedHostIdentity
			}
		}
		result.Items = append(result.Items, hostItem)
	}
	return result
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

func (h productionIsolatedHost) ReconcileNICMetadata(
	ctx context.Context,
	target Target,
	params hyperv.ReconcileIsolatedAdapterMetadataParams,
) (hyperv.IsolatedAdapterMutationResult, error) {
	script, err := hyperv.BuildReconcileIsolatedAdapterMetadataScript(params)
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

func (h productionIsolatedHost) CleanupNetworkMetadata(
	ctx context.Context, target Target, params hyperv.CleanupIsolatedNetworkMetadataParams,
) (hyperv.IsolatedMetadataCleanupResult, error) {
	script, err := hyperv.BuildCleanupIsolatedNetworkMetadataScript(params)
	if err != nil {
		return hyperv.IsolatedMetadataCleanupResult{}, err
	}
	out, _, err := runPS(ctx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return hyperv.IsolatedMetadataCleanupResult{}, err
	}
	return hyperv.ParseIsolatedMetadataCleanupResult(jsonExtract(out))
}

func (h productionIsolatedHost) CleanupOrchestratorMetadata(
	ctx context.Context, target Target, params hyperv.CleanupIsolatedOrchestratorMetadataParams,
) (hyperv.IsolatedMetadataCleanupResult, error) {
	script, err := hyperv.BuildCleanupIsolatedOrchestratorMetadataScript(params)
	if err != nil {
		return hyperv.IsolatedMetadataCleanupResult{}, err
	}
	out, _, err := runPS(ctx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return hyperv.IsolatedMetadataCleanupResult{}, err
	}
	return hyperv.ParseIsolatedMetadataCleanupResult(jsonExtract(out))
}

func (h productionIsolatedHost) DeleteOrchestratorVM(
	ctx context.Context,
	target Target,
	params hyperv.DeleteIsolatedOrchestratorVMParams,
) (map[string]any, error) {
	script, err := hyperv.BuildDeleteIsolatedOrchestratorVMScript(params)
	if err != nil {
		return nil, err
	}
	out, _, err := runPS(ctx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(jsonExtract(out)), &result); err != nil {
		return nil, err
	}
	return result, nil
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
	} else {
		observation.ApplyIntentError = readyErr.Error()
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
	secrets *secretstore.Store,
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
	sweepCtx, cancelSweep := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelSweep()
	if _, err := locks.SweepStale(sweepCtx); err != nil {
		return nil, fmt.Errorf("sweep stale isolated locks: %w", err)
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
		secrets: secrets,
		audit:   auditLog, enrollment: enrollment, lease: leaseCfg,
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
	deps.guests = productionIsolatedGuestRuntime{deps: deps}
	deps.joinDomain = executeWindowsDomainJoin
	return deps, nil
}

func RegisterIsolatedLifecycleTools(s *server.MCPServer, deps *isolatedLifecycleDeps) {
	RegisterIsolatedOrchestratorTools(s, deps)
	RegisterIsolatedNetworkTools(s, deps)
	RegisterIsolatedRelayTools(s, deps)
	RegisterIsolatedVMTools(s, deps)
	RegisterIsolatedNAT(s, deps)
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
		err = workflow.phaseAlways(ctx, 0, "host_lock", "acquiring remote host fence", func() (any, error) {
			planCtx, cancelPlan := context.WithTimeout(ctx, isolatedCreatePlanningTimeout)
			defer cancelPlan()
			var planErr error
			createPlan, planErr = domain.PlanCreateOrReuse(planCtx, isolated.OrchestratorCreateRequest{
				OperationID: operationID, PhysicalHostID: hostID.String(), HostNode: target.Name,
				DisplayName: displayName, ProfileName: profileName,
				MainVSwitch: profile.Profile.MainVSwitch, OrchestratorID: orchestratorID,
				ProjectedStorageBytes: int64(profile.LinuxVM.DiskSizeGB * 1024 * 1024 * 1024),
				ServerVersion:         deps.serverVersion,
				PostFenceTimeout:      isolatedPostFenceCapacityTimeout,
				Progress:              progress.Update,
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
		leaseOwned := createPlan.Lease.LeaseID != ""
		defer func() {
			if leaseOwned {
				deps.host.ReleaseFence(context.Background(), target, createPlan.Lease)
			}
		}()
		releasePlanningLease := func() error {
			if !leaseOwned {
				return nil
			}
			releaseCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			if err := deps.host.ReleaseFenceChecked(releaseCtx, target, createPlan.Lease); err != nil {
				return err
			}
			leaseOwned = false
			return nil
		}
		if createPlan.Reused != nil {
			if err := releasePlanningLease(); err != nil {
				return isolatedError(fmt.Errorf("HOST_FENCE_RELEASE_FAILED: reusable capacity was found but planning lease release failed: %w", err))
			}
			return workflow.finish(ctx, isolatedstate.OperationSucceeded, isolatedToolResult{
				Status: "succeeded", Phase: "reuse_recheck",
				ResourceID: createPlan.Reused.Orchestrator.ID,
				Generation: int64(createPlan.Reused.Orchestrator.DesiredGeneration),
				Resource:   createPlan.Reused, NextAction: nil,
			})
		}
		hasApprovedRevision := strings.TrimSpace(req.GetString("approved_plan_revision", "")) != ""
		if !hasApprovedRevision {
			progress.Update("approval_required", "capacity discovery completed; releasing host fence before returning the exact plan")
			if err := releasePlanningLease(); err != nil {
				return isolatedError(fmt.Errorf("HOST_FENCE_RELEASE_FAILED: create plan is ready but planning lease release failed: %w", err))
			}
		}
		approved, approvalResult, err := approveRevision(
			ctx, nil, deps.state, req, operationID,
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
		err = workflow.phaseAlways(ctx, 1, "create_linux_vm", "creating or exactly resuming the ordinary Ubuntu VM bootstrap", func() (any, error) {
			if node, found := deps.registry.GetNode(names.NodeName); found &&
				strings.EqualFold(strings.TrimSpace(node.TLSServerName), names.NodeName) {
				linuxPlan.Name = names.HyperVName
				linuxPlan.LabLinkNodeName = names.NodeName
				return map[string]any{
					"hyperv_name": names.HyperVName, "node_name": names.NodeName,
					"resumed_registered_guest": true,
				}, nil
			}
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
		err = workflow.phaseAlways(ctx, 2, "verify_host_identity", "claiming exact Hyper-V identity under the host fence", func() (any, error) {
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
			node, readiness, readyErr := waitForOrchestratorReadiness(
				ctx, deps.registry, deps.appliance, record, progress, 15*time.Minute, 5*time.Second)
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

func waitForOrchestratorReadiness(
	ctx context.Context,
	reg *registry.Registry,
	applianceClient isolatedAppliance,
	record isolatedstate.Orchestrator,
	progress *MCPProgressState,
	timeout time.Duration,
	interval time.Duration,
) (*registry.Node, isolated.ApplianceReadiness, error) {
	if timeout <= 0 || interval <= 0 {
		return nil, isolated.ApplianceReadiness{}, errors.New("orchestrator readiness timeout and interval must be positive")
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastErr error
	for {
		node, found := reg.GetNode(record.NodeName)
		if !found {
			lastErr = fmt.Errorf("ORCHESTRATOR_NODE_NOT_FOUND: %s", record.NodeName)
		} else {
			node.Role = "isolated-orchestrator"
			if node.Labels == nil {
				node.Labels = map[string]string{}
			}
			node.Labels["lablink.orchestrator_id"] = record.ID
			node.Labels["lablink.kind"] = "isolated-orchestrator"
			if err := reg.SetNode(node); err != nil {
				return nil, isolated.ApplianceReadiness{}, err
			}
			readiness, err := applianceClient.CheckReadiness(ctx, record.ID)
			if err == nil {
				return node, readiness, nil
			}
			code := isolated.ErrorCode(err)
			if code != "AGENT_CAPABILITY_MISSING" &&
				code != "ORCHESTRATOR_NODE_NOT_FOUND" &&
				code != string(appliance.CodeNotReady) &&
				status.Code(err) != codes.Unavailable {
				return nil, readiness, err
			}
			lastErr = err
		}
		if progress != nil {
			progress.Update("verify_capabilities", "waiting for cloud-init to restart the agent in isolated-appliance mode")
		}
		select {
		case <-ctx.Done():
			return nil, isolated.ApplianceReadiness{}, ctx.Err()
		case <-deadline.C:
			return nil, isolated.ApplianceReadiness{}, fmt.Errorf(
				"ORCHESTRATOR_APPLIANCE_READY_TIMEOUT: %w", lastErr)
		case <-ticker.C:
		}
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
		operationID, err := isolatedOperationID(req)
		if err != nil {
			return isolatedError(err)
		}
		expected, cascade, _, err := deleteOperationInputs(
			ctx, deps.state, req, operationID, record.DesiredGeneration,
		)
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
		natStates, err := deps.state.ListNAT(ctx, id.String(), "", "")
		if err != nil {
			return isolatedError(err)
		}
		children := cascadeChildren(networks, vms, relays, natStates)
		if len(children) != 0 && !cascade {
			return isolatedError(fmt.Errorf("ORCHESTRATOR_NOT_EMPTY: %d live child resources remain; retry with cascade=true", len(children)))
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
		var deletePlan isolated.DeleteOrchestratorPlan
		storedPlan, stored, err := consumedApprovedCascadePlan(
			ctx, deps.state, req, operationID, children,
		)
		if err != nil {
			return isolatedError(err)
		}
		if stored {
			deletePlan, err = isolated.RestoreApprovedOrchestratorDeletePlan(
				storedPlan, record.HostFence,
			)
		} else {
			deletePlan, err = isolated.BuildOrchestratorDeletePlan(isolated.DeleteOrchestratorRequest{
				OperationID: operationID, Orchestrator: record, Cascade: cascade,
				Children: children, ExpectedGeneration: expected,
			})
		}
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
		deleteVMSucceeded, err := deps.state.OperationPhaseSucceeded(
			ctx, operationID, 0, "delete_linux_vm")
		if err != nil {
			return isolatedError(err)
		}
		if !deleteVMSucceeded {
			if err := workflow.phase(ctx, 98, "freeze_parent", "atomically freezing exact approved parent generation", func() (any, error) {
				target, targetErr := resolvePlanTarget(record.HostNode, deps.registry)
				if targetErr != nil {
					return nil, targetErr
				}
				frozen, freezeErr := freezeApprovedParent(
					ctx, deps, target, record, expected, deletePlan,
				)
				if freezeErr == nil {
					record = frozen
				}
				return map[string]any{
					"expected_generation": expected,
					"frozen_generation":   expected + 1,
				}, freezeErr
			}); err != nil {
				return isolatedError(err)
			}
			record, err = deps.state.GetOrchestrator(ctx, id.String())
			if err != nil {
				return isolatedError(err)
			}
			networks, err = deps.state.ListNetworks(ctx, id.String())
			if err != nil {
				return isolatedError(err)
			}
			vms, err = deps.state.ListVMs(ctx, id.String(), "")
			if err != nil {
				return isolatedError(err)
			}
			relays, err = deps.state.ListRelays(ctx, id.String(), "")
			if err != nil {
				return isolatedError(err)
			}
			natStates, err = deps.state.ListNAT(ctx, id.String(), "", "")
			if err != nil {
				return isolatedError(err)
			}
			refreshedChildren := cascadeChildren(networks, vms, relays, natStates)
			if _, err := approvedCascadeResumePlan(
				ctx, deps.state, req, operationID, deletePlan.Plan, refreshedChildren,
			); err != nil {
				return isolatedError(err)
			}
		}
		if cascade {
			// Keep approved-plan enumeration unchanged; only execution copies are
			// sorted so an existing revision remains resumable.
			orderedVMs, orderedNetworks := dependencySafeCascadeOrder(vms, networks)
			for _, child := range orderedVMs {
				if child.LifecycleState == isolatedstate.VMDeleted {
					continue
				}
				if err := validateApprovedCascadeChild(
					ctx, deps.state, deletePlan.Plan, "vm", child.ID,
				); err != nil {
					return isolatedError(err)
				}
				childReq := mcp.CallToolRequest{}
				childReq.Params.Name = "delete_isolated_vm"
				childReq.Params.Arguments = map[string]any{
					"isolated_vm_id": child.ID, "delete_storage": true,
					"operation_id": isolatedstate.StableOperationID(operationID, child.ID, "cascade_delete_vm", "guest"),
					"resume_exact": true,
				}
				childCtx := context.WithValue(ctx, cascadeExecutionKey{}, &cascadeExecution{
					Plan: deletePlan, ResourceType: "vm", ResourceID: child.ID,
					Action: cascadeauth.ActionGuestDeleteExact,
				})
				result, childErr := deleteIsolatedVMHandler(deps)(childCtx, childReq)
				if childErr != nil || result == nil || result.IsError {
					if childErr != nil {
						return isolatedError(childErr)
					}
					return isolatedError(fmt.Errorf("CASCADE_GUEST_DELETE_FAILED: %s", toolResultText(result)))
				}
			}
			for _, child := range orderedNetworks {
				if child.LifecycleState == isolatedstate.NetworkDeleted {
					continue
				}
				if err := validateApprovedCascadeChild(
					ctx, deps.state, deletePlan.Plan, "network", child.ID,
				); err != nil {
					return isolatedError(err)
				}
				childReq := mcp.CallToolRequest{}
				childReq.Params.Name = "remove_isolated_network"
				childReq.Params.Arguments = map[string]any{
					"network_id":   child.ID,
					"operation_id": isolatedstate.StableOperationID(operationID, child.ID, "cascade_delete_network", "network"),
					"resume_exact": true,
				}
				childCtx := context.WithValue(ctx, cascadeExecutionKey{}, &cascadeExecution{
					Plan: deletePlan, ResourceType: "network", ResourceID: child.ID,
					Action: cascadeauth.ActionNetworkRemove,
				})
				result, childErr := removeIsolatedNetworkHandler(deps)(childCtx, childReq)
				if childErr != nil || result == nil || result.IsError {
					if childErr != nil {
						return isolatedError(childErr)
					}
					return isolatedError(fmt.Errorf("CASCADE_NETWORK_DELETE_FAILED: %s", toolResultText(result)))
				}
			}

			networks, err = deps.state.ListNetworks(ctx, id.String())
			if err != nil {
				return isolatedError(err)
			}
			relays, err = deps.state.ListRelays(ctx, id.String(), "")
			if err != nil {
				return isolatedError(err)
			}
		}

		vms, err = deps.state.ListVMs(ctx, id.String(), "")
		if err != nil {
			return isolatedError(err)
		}
		natStates, err = deps.state.ListNAT(ctx, id.String(), "", "")
		if err != nil {
			return isolatedError(err)
		}
		allocations, err := deps.state.ListActiveAllocations(ctx, id.String())
		if err != nil {
			return isolatedError(err)
		}
		for _, child := range networks {
			if child.LifecycleState != isolatedstate.NetworkDeleted {
				return isolatedError(fmt.Errorf("CASCADE_CHILDREN_REMAIN: network %s remains %s", child.ID, child.LifecycleState))
			}
		}
		for _, child := range vms {
			if child.LifecycleState != isolatedstate.VMDeleted {
				return isolatedError(fmt.Errorf("CASCADE_CHILDREN_REMAIN: VM %s remains %s", child.ID, child.LifecycleState))
			}
		}
		for _, child := range relays {
			if child.LifecycleState != isolatedstate.RelayRemoved {
				return isolatedError(fmt.Errorf("CASCADE_CHILDREN_REMAIN: relay %s remains %s", child.ID, child.LifecycleState))
			}
		}
		if len(natStates) != 0 || len(allocations) != 0 {
			return isolatedError(fmt.Errorf(
				"CASCADE_CHILDREN_REMAIN: %d NAT states and %d active reservations remain",
				len(natStates), len(allocations)))
		}
		record, err = deps.state.GetOrchestrator(ctx, id.String())
		if err != nil {
			return isolatedError(err)
		}
		target, err := resolvePlanTarget(record.HostNode, deps.registry)
		if err != nil {
			return isolatedError(err)
		}
		var hostLease isolated.HostFenceLease
		if deleteVMSucceeded {
			lockKey, _ := hyperv.HostOrchestratorCreateLockKey(record.PhysicalHostID)
			hostLease, err = deps.host.AcquireFence(ctx, target, isolated.HostCreateFenceRequest{
				PhysicalHostID: record.PhysicalHostID, HostNode: record.HostNode,
				OperationID: operationID, LockKey: lockKey,
			})
		} else {
			hostLease, err = acquireCompatibleOrchestratorFence(
				ctx, deps, target, record, operationID)
		}
		if err != nil {
			return isolatedError(err)
		}
		hostLeaseReleased := false
		defer func() {
			if !hostLeaseReleased {
				deps.host.ReleaseFence(context.Background(), target, hostLease)
			}
		}()
		if !deleteVMSucceeded {
			hostLifecycle, ok := deps.host.(isolatedParentLifecycleHost)
			if !ok {
				return isolatedError(errors.New(
					"PARENT_FREEZE_UNAVAILABLE: host lifecycle authority is not configured"))
			}
			authority := deletePlan.Authority
			authority.HostFence = hostLease.Fence
			authority.LeaseID = hostLease.LeaseID
			if record.HostFence != hostLease.Fence {
				if err := hostLifecycle.RebindParentFence(
					ctx, target, record, hostLease, authority,
				); err != nil {
					return isolatedError(err)
				}
			}
			record.HostFence = hostLease.Fence
			record.UpdatedAt = isolatedNow()
			if err := deps.state.PutOrchestrator(ctx, record); err != nil {
				return isolatedError(err)
			}
			if err := deps.state.InstallCascadeAuthority(ctx, authority); err != nil {
				return isolatedError(err)
			}
			applianceLifecycle, ok := deps.appliance.(isolatedParentLifecycleAppliance)
			if !ok {
				return isolatedError(errors.New(
					"PARENT_FREEZE_UNAVAILABLE: appliance lifecycle authority is not configured"))
			}
			if err := applianceLifecycle.SetParentLifecycle(
				ctx, record.ID, isolated.MutationEnvelope{
					Header: appliance.MutationHeader{
						ParentOperationID: operationID,
						MutationID: isolatedstate.StableMutationID(
							operationID, record.ID, "rebind_parent_fence", "final_rebind"),
						SemanticHash: deletePlan.Plan.SemanticHash,
						ResourceID:   record.ID, ParentResourceID: record.ID,
						HostFence:                uint64(hostLease.Fence),
						ExpectedParentGeneration: uint64(expected),
					},
					PhysicalHostID:       record.PhysicalHostID,
					HostLeaseID:          hostLease.LeaseID,
					HostLeaseSecret:      mustDecodeHex(hostLease.LeaseSecret),
					HostLeaseExpiresUnix: hostLease.ExpiresAtUnix,
					CascadeOperationID:   operationID,
					CascadePlanRevision:  deletePlan.Plan.Revision,
					CascadePlanHash:      deletePlan.Plan.PlanHash,
					CascadeItems: cascadeAuthorityItemsForAppliance(
						deletePlan.Authority),
				}, "frozen", uint64(expected+1),
			); err != nil {
				return isolatedError(err)
			}
			if err := workflow.phase(ctx, 99, "verify_final_inventory", "verifying frozen child inventory under the final host fence", func() (any, error) {
				return verifyFinalCascadeInventory(ctx, deps, record)
			}); err != nil {
				return isolatedError(err)
			}
		}
		record.LifecycleState = isolatedstate.OrchestratorDeleting
		record.HealthState = "deleting"
		record.UpdatedAt = isolatedstate.UnixSeconds(time.Now().Unix())
		if err := deps.state.PutOrchestrator(ctx, record); err != nil {
			return isolatedError(err)
		}
		if err := workflow.phase(ctx, 0, "delete_linux_vm", "deleting exact managed orchestrator VM and owned storage", func() (any, error) {
			if deps.deleteOrchestratorVM != nil {
				return deps.deleteOrchestratorVM(ctx, record)
			}
			if record.HyperVVMID == nil || strings.TrimSpace(*record.HyperVVMID) == "" {
				return nil, errors.New(
					"ORCHESTRATOR_VM_IDENTITY_REQUIRED: persisted Hyper-V VM GUID is missing")
			}
			resolved, _, resolveErr := deps.defaults.ResolveIsolatedOrchestrator(
				record.ProfileName)
			if resolveErr != nil {
				return nil, resolveErr
			}
			authority := deletePlan.Authority
			authority.HostFence = hostLease.Fence
			authority.LeaseID = hostLease.LeaseID
			return deps.host.DeleteOrchestratorVM(
				ctx, target, hyperv.DeleteIsolatedOrchestratorVMParams{
					Guard: hyperv.IsolatedMutationGuard{
						PhysicalHostID: record.PhysicalHostID,
						LeaseID:        hostLease.LeaseID,
						LeaseSecret:    hostLease.LeaseSecret,
						Fence:          hostLease.Fence,
						OrchestratorID: record.ID,
						OperationID:    operationID,
						MutationID: isolatedstate.StableMutationID(
							operationID, record.ID,
							string(cascadeauth.ActionOrchestratorVMDelete),
							"delete_orchestrator_vm"),
						ResourceType: "orchestrator",
						ResourceID:   record.ID,
						Action: string(
							cascadeauth.ActionOrchestratorVMDelete),
						CascadeAuthority: func() *hyperv.CascadeAuthority {
							value := cascadeAuthorityForHost(authority)
							return &value
						}(),
					},
					OrchestratorVMGUID: *record.HyperVVMID,
					HyperVName:         record.HyperVName,
					ExpectedGeneration: int64(record.DesiredGeneration),
					ManagedRoot:        resolved.LinuxVM.VMRoot,
					ExpectedParentVHDX: resolved.LinuxVM.BaseVHD,
					ForceStop:          true,
					DeleteStorage:      true,
				})
		}); err != nil {
			return isolatedError(err)
		}
		if err := workflow.phase(ctx, 1, "cleanup_host_metadata", "removing exact empty orchestrator metadata root", func() (any, error) {
			return deps.host.CleanupOrchestratorMetadata(
				ctx, target, hyperv.CleanupIsolatedOrchestratorMetadataParams{
					Guard: hyperv.IsolatedMutationGuard{
						PhysicalHostID: record.PhysicalHostID,
						LeaseID:        hostLease.LeaseID,
						LeaseSecret:    hostLease.LeaseSecret,
						Fence:          hostLease.Fence,
						OrchestratorID: record.ID,
						OperationID:    operationID,
						MutationID: isolatedstate.StableMutationID(
							operationID, record.ID,
							"cleanup_orchestrator_metadata", "cleanup_host_metadata"),
						ResourceType: "orchestrator",
						ResourceID:   record.ID,
						Action:       "cleanup_orchestrator_metadata",
						CascadeAuthority: func() *hyperv.CascadeAuthority {
							authority := deletePlan.Authority
							authority.HostFence = hostLease.Fence
							authority.LeaseID = hostLease.LeaseID
							value := cascadeAuthorityForHost(authority)
							return &value
						}(),
					},
					OrchestratorVMGUID: valueOrEmpty(record.HyperVVMID),
					HyperVName:         record.HyperVName,
				})
		}); err != nil {
			return isolatedError(err)
		}
		releaseCtx, cancelRelease := context.WithTimeout(context.Background(), 45*time.Second)
		releaseErr := deps.host.ReleaseFenceChecked(releaseCtx, target, hostLease)
		cancelRelease()
		if releaseErr != nil {
			return isolatedError(fmt.Errorf(
				"HOST_FENCE_RELEASE_FAILED: orchestrator VM was deleted but physical host lease release failed: %w",
				releaseErr))
		}
		hostLeaseReleased = true
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

func approvedCascadeResumePlan(
	ctx context.Context,
	state isolatedState,
	req mcp.CallToolRequest,
	operationID string,
	current isolated.RevisionedPlan,
	currentChildren []isolated.CascadeChild,
) (isolated.RevisionedPlan, error) {
	stored, ok, err := consumedApprovedCascadePlan(
		ctx, state, req, operationID, currentChildren,
	)
	if err != nil {
		return isolated.RevisionedPlan{}, err
	}
	if ok {
		return stored, nil
	}
	return current, nil
}

func deleteOperationInputs(
	ctx context.Context,
	state isolatedState,
	req mcp.CallToolRequest,
	operationID string,
	current isolatedstate.Generation,
) (isolatedstate.Generation, bool, bool, error) {
	operation, err := state.GetOperation(ctx, operationID)
	if errors.Is(err, isolatedstate.ErrOperationNotFound) {
		expected, generationErr := expectedGeneration(req, current)
		return expected, req.GetBool("cascade", false), false, generationErr
	}
	if err != nil {
		return 0, false, false, err
	}
	if !req.GetBool("resume_exact", false) {
		return 0, false, true, isolatedstate.ErrResumeExactRequired
	}
	var stored struct {
		Inputs struct {
			Cascade            bool                     `json:"cascade"`
			ExpectedGeneration isolatedstate.Generation `json:"expected_generation"`
		} `json:"inputs"`
	}
	if err := json.Unmarshal([]byte(operation.RequestJSON), &stored); err != nil {
		return 0, false, true, fmt.Errorf(
			"INVALID_DURABLE_OPERATION: decode delete inputs: %w", err)
	}
	return stored.Inputs.ExpectedGeneration, stored.Inputs.Cascade, true, nil
}

func consumedApprovedCascadePlan(
	ctx context.Context,
	state isolatedState,
	req mcp.CallToolRequest,
	operationID string,
	currentChildren []isolated.CascadeChild,
) (isolated.RevisionedPlan, bool, error) {
	revision := strings.TrimSpace(req.GetString("approved_plan_revision", ""))
	if revision == "" || !req.GetBool("resume_exact", false) {
		return isolated.RevisionedPlan{}, false, nil
	}
	approval, err := state.GetApprovalPlan(ctx, revision)
	if err != nil {
		return isolated.RevisionedPlan{}, false, err
	}
	if approval.State != isolatedstate.ApprovalConsumed {
		return isolated.RevisionedPlan{}, false, nil
	}
	if approval.OperationID != operationID ||
		approval.Action != "delete_isolated_orchestrator" {
		return isolated.RevisionedPlan{}, false, errors.New(
			"APPROVAL_IDENTITY_MISMATCH: stored approval does not authorize this exact cascade")
	}
	var stored isolated.RevisionedPlan
	if err := json.Unmarshal([]byte(approval.PlanJSON), &stored); err != nil {
		return isolated.RevisionedPlan{}, false, fmt.Errorf("decode approved cascade plan: %w", err)
	}
	if stored.Revision != revision || stored.PlanHash != approval.PlanHash ||
		stored.OperationID != operationID {
		return isolated.RevisionedPlan{}, false, errors.New(
			"APPROVAL_IDENTITY_MISMATCH: stored cascade plan identity changed")
	}
	approvedChildren := make(map[string]map[string]any)
	rawChildren, _ := stored.Inputs["children"].([]any)
	for _, raw := range rawChildren {
		child, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		key := fmt.Sprint(child["resource_type"]) + "\x00" + fmt.Sprint(child["resource_id"])
		approvedChildren[key] = child
	}
	for _, child := range currentChildren {
		key := child.ResourceType + "\x00" + child.ResourceID
		approved, ok := approvedChildren[key]
		if !ok {
			return isolated.RevisionedPlan{}, false, fmt.Errorf(
				"CASCADE_INVENTORY_CHANGED: unapproved child %s %s remains",
				child.ResourceType, child.ResourceID)
		}
		generation, generationOK := numericArgument(approved["generation"])
		incarnation, incarnationOK := numericArgument(approved["incarnation"])
		if !generationOK ||
			fmt.Sprint(approved["action"]) != string(child.Action) ||
			fmt.Sprint(approved["host_identity"]) != child.ExpectedHostIdentity ||
			fmt.Sprint(approved["appliance_identity"]) != child.ExpectedApplianceIdentity ||
			isolatedstate.Generation(generation) != child.ExpectedGeneration ||
			(incarnationOK && isolatedstate.Incarnation(incarnation) != child.ExpectedIncarnation) ||
			fmt.Sprint(approved["immutable_identity"]) != child.ExpectedImmutableIdentity {
			return isolated.RevisionedPlan{}, false, fmt.Errorf(
				"CASCADE_INVENTORY_CHANGED: approved identity or generation changed for %s %s",
				child.ResourceType, child.ResourceID)
		}
	}
	return stored, true, nil
}

func cascadeChildren(
	networks []isolatedstate.PrivateNetwork,
	vms []isolatedstate.IsolatedVM,
	relays []isolatedstate.RelayAllocation,
	natStates []isolatedstate.NATAllocation,
) []isolated.CascadeChild {
	var children []isolated.CascadeChild
	for _, value := range networks {
		if value.LifecycleState != isolatedstate.NetworkDeleted {
			children = append(children, isolated.CascadeChild{
				ResourceType:              "network",
				ResourceID:                value.ID,
				Action:                    cascadeauth.ActionNetworkRemove,
				ExpectedHostIdentity:      valueOrEmpty(value.HyperVSwitchGUID),
				ExpectedGeneration:        value.DesiredGeneration,
				ExpectedImmutableIdentity: cascadeNetworkIdentity(value),
			})
		}
	}
	for _, value := range vms {
		if value.LifecycleState != isolatedstate.VMDeleted {
			children = append(children, isolated.CascadeChild{
				ResourceType:              "vm",
				ResourceID:                value.ID,
				Action:                    cascadeauth.ActionGuestDeleteExact,
				ExpectedHostIdentity:      valueOrEmpty(value.HyperVVMID),
				ExpectedGeneration:        value.DesiredGeneration,
				ExpectedIncarnation:       value.Incarnation,
				ExpectedImmutableIdentity: cascadeVMIdentity(value),
			})
		}
	}
	for _, value := range relays {
		if value.LifecycleState != isolatedstate.RelayRemoved {
			children = append(children, isolated.CascadeChild{
				ResourceType:              "relay",
				ResourceID:                value.ID,
				Action:                    cascadeauth.ActionRelayRemove,
				ExpectedApplianceIdentity: fmt.Sprint(value.ListenPort),
				ExpectedGeneration:        value.DesiredGeneration,
				ExpectedImmutableIdentity: cascadeRelayIdentity(value),
			})
		}
	}
	for _, value := range natStates {
		children = append(children, isolated.CascadeChild{
			ResourceType:              "nat",
			ResourceID:                value.VMID,
			Action:                    cascadeauth.ActionNATDisable,
			ExpectedApplianceIdentity: fmt.Sprint(value.ConntrackMark),
			ExpectedGeneration:        value.DesiredGeneration,
			ExpectedImmutableIdentity: cascadeNATIdentity(value),
		})
	}
	return children
}

func cascadeNetworkIdentity(value isolatedstate.PrivateNetwork) string {
	hash, _ := isolatedstate.SemanticHash(map[string]any{
		"id": value.ID, "orchestrator_id": value.OrchestratorID,
		"switch_name":  value.HyperVSwitchName,
		"switch_guid":  valueOrEmpty(value.HyperVSwitchGUID),
		"adapter_id":   valueOrEmpty(value.OrchestratorAdapterID),
		"subnet_index": value.SubnetIndex, "cidr": value.CIDR,
		"gateway_ipv4": value.GatewayIPv4, "mac": value.OrchestratorMAC,
	})
	return hash
}

func cascadeVMIdentity(value isolatedstate.IsolatedVM) string {
	hash, _ := isolatedstate.SemanticHash(map[string]any{
		"id": value.ID, "orchestrator_id": value.OrchestratorID,
		"network_id": value.NetworkID, "hyperv_name": value.HyperVName,
		"hyperv_vm_id":      valueOrEmpty(value.HyperVVMID),
		"hyperv_adapter_id": valueOrEmpty(value.HyperVAdapterID),
		"node_name":         value.NodeName, "guest_os": value.GuestOS,
		"ipv4": value.IPv4, "mac": value.MAC, "prefix_length": value.PrefixLength,
		"gateway_ipv4": value.GatewayIPv4, "storage_root": value.StorageRoot,
		"vm_path": value.VMPath, "vhd_path": value.VHDPath,
	})
	return hash
}

func cascadeRelayIdentity(value isolatedstate.RelayAllocation) string {
	hash, _ := isolatedstate.SemanticHash(map[string]any{
		"id": value.ID, "vm_id": value.VMID,
		"orchestrator_id": value.OrchestratorID,
		"listen_port":     value.ListenPort, "target_ipv4": value.TargetIPv4,
		"target_port": value.TargetPort,
	})
	return hash
}

func cascadeNATIdentity(value isolatedstate.NATAllocation) string {
	hash, _ := isolatedstate.SemanticHash(map[string]any{
		"vm_id": value.VMID, "orchestrator_id": value.OrchestratorID,
		"conntrack_mark": value.ConntrackMark,
	})
	return hash
}

func validateApprovedCascadeChild(
	ctx context.Context,
	state isolatedState,
	plan isolated.RevisionedPlan,
	resourceType, resourceID string,
) error {
	var inputs struct {
		Children []struct {
			ResourceType              string                    `json:"resource_type"`
			ResourceID                string                    `json:"resource_id"`
			Action                    string                    `json:"action"`
			ExpectedHostIdentity      string                    `json:"host_identity"`
			ExpectedApplianceIdentity string                    `json:"appliance_identity"`
			ExpectedGeneration        isolatedstate.Generation  `json:"generation"`
			ExpectedIncarnation       isolatedstate.Incarnation `json:"incarnation"`
			ExpectedImmutableIdentity string                    `json:"immutable_identity"`
		} `json:"children"`
	}
	raw, err := json.Marshal(plan.Inputs)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &inputs); err != nil {
		return fmt.Errorf("decode approved cascade children: %w", err)
	}
	for _, approved := range inputs.Children {
		if approved.ResourceType != resourceType || approved.ResourceID != resourceID {
			continue
		}
		switch resourceType {
		case "vm":
			current, err := state.GetVM(ctx, resourceID)
			if err != nil {
				return err
			}
			if current.DesiredGeneration != approved.ExpectedGeneration ||
				current.Incarnation != approved.ExpectedIncarnation ||
				valueOrEmpty(current.HyperVVMID) != approved.ExpectedHostIdentity ||
				cascadeVMIdentity(current) != approved.ExpectedImmutableIdentity {
				return fmt.Errorf(
					"CASCADE_INVENTORY_CHANGED: approved VM %s generation, incarnation, or immutable identity changed",
					resourceID)
			}
		case "network":
			current, err := state.GetNetwork(ctx, resourceID)
			if err != nil {
				return err
			}
			if current.DesiredGeneration != approved.ExpectedGeneration ||
				valueOrEmpty(current.HyperVSwitchGUID) != approved.ExpectedHostIdentity ||
				cascadeNetworkIdentity(current) != approved.ExpectedImmutableIdentity {
				return fmt.Errorf(
					"CASCADE_INVENTORY_CHANGED: approved network %s generation or immutable identity changed",
					resourceID)
			}
		case "relay":
			current, err := state.GetRelay(ctx, resourceID)
			if err != nil {
				return err
			}
			if current.DesiredGeneration != approved.ExpectedGeneration ||
				fmt.Sprint(current.ListenPort) != approved.ExpectedApplianceIdentity ||
				cascadeRelayIdentity(current) != approved.ExpectedImmutableIdentity {
				return fmt.Errorf(
					"CASCADE_INVENTORY_CHANGED: approved relay %s generation or immutable identity changed",
					resourceID)
			}
		default:
			return fmt.Errorf("CASCADE_INVENTORY_CHANGED: unsupported approved child type %s", resourceType)
		}
		return nil
	}
	return fmt.Errorf(
		"CASCADE_INVENTORY_CHANGED: child %s %s is not in the approved plan",
		resourceType, resourceID)
}

func verifyFinalCascadeInventory(
	ctx context.Context,
	deps *isolatedLifecycleDeps,
	orchestrator isolatedstate.Orchestrator,
) (any, error) {
	networks, err := deps.state.ListNetworks(ctx, orchestrator.ID)
	if err != nil {
		return nil, err
	}
	vms, err := deps.state.ListVMs(ctx, orchestrator.ID, "")
	if err != nil {
		return nil, err
	}
	relays, err := deps.state.ListRelays(ctx, orchestrator.ID, "")
	if err != nil {
		return nil, err
	}
	natStates, err := deps.state.ListNAT(ctx, orchestrator.ID, "", "")
	if err != nil {
		return nil, err
	}
	allocations, err := deps.state.ListActiveAllocations(ctx, orchestrator.ID)
	if err != nil {
		return nil, err
	}
	if children := cascadeChildren(networks, vms, relays, natStates); len(children) != 0 ||
		len(allocations) != 0 {
		return nil, fmt.Errorf(
			"CASCADE_INVENTORY_CHANGED: final local inventory has %d live children, %d NAT states, and %d active reservations",
			len(children), len(natStates), len(allocations))
	}
	snapshot, err := deps.appliance.InspectApplianceState(ctx, orchestrator.ID)
	if err != nil {
		return nil, err
	}
	var liveNetworks, liveGuests, liveRelays, liveNAT, liveReservations int
	for _, value := range snapshot.Desired.Networks {
		if value.RetiredAtUnix == nil {
			liveNetworks++
		}
	}
	for _, value := range snapshot.Desired.Guests {
		if value.RetiredAtUnix == nil {
			liveGuests++
		}
	}
	for _, value := range snapshot.Desired.Relays {
		if value.RetiredAtUnix == nil {
			liveRelays++
		}
	}
	for _, value := range snapshot.Desired.NAT {
		if value.State != "disabled" {
			liveNAT++
		}
	}
	for _, value := range snapshot.Desired.Reservations {
		if value.RetiredAtUnix == nil {
			liveReservations++
		}
	}
	if liveNetworks+liveGuests+liveRelays+liveNAT+liveReservations != 0 {
		return nil, fmt.Errorf(
			"CASCADE_INVENTORY_CHANGED: final appliance inventory has networks=%d guests=%d relays=%d NAT=%d reservations=%d",
			liveNetworks, liveGuests, liveRelays, liveNAT, liveReservations)
	}
	return map[string]any{
		"networks": 0, "vms": 0, "relays": 0, "nat": 0, "reservations": 0,
	}, nil
}

func dependencySafeCascadeOrder(
	vms []isolatedstate.IsolatedVM,
	networks []isolatedstate.PrivateNetwork,
) ([]isolatedstate.IsolatedVM, []isolatedstate.PrivateNetwork) {
	orderedVMs := append([]isolatedstate.IsolatedVM(nil), vms...)
	orderedNetworks := append([]isolatedstate.PrivateNetwork(nil), networks...)
	sort.SliceStable(orderedVMs, func(i, j int) bool {
		return orderedVMs[i].ID < orderedVMs[j].ID
	})
	sort.SliceStable(orderedNetworks, func(i, j int) bool {
		return orderedNetworks[i].ID < orderedNetworks[j].ID
	})
	return orderedVMs, orderedNetworks
}
