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
	"github.com/nijosmsft/lablink/internal/cascadeauth"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/isolated"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/secretstore"
	"github.com/nijosmsft/lablink/internal/vmconfig"
)

const isolatedOperationTTL = 2 * time.Minute

var isolatedRelayRetirementTimeout = 30 * time.Second
var isolatedHostFenceAcquireTimeout = 75 * time.Second
var isolatedPostFenceCapacityTimeout = 60 * time.Second
var isolatedCreatePlanningTimeout = 2 * time.Minute

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
	GetApprovalPlan(context.Context, string) (isolatedstate.ApprovalPlan, error)
	ApprovePlan(context.Context, string, string, string) error
	ConsumePlan(context.Context, string, string, string) error
	InstallCascadeAuthority(context.Context, isolatedstate.CascadeAuthority) error
	CompleteCascadeItem(context.Context, string, string, isolatedstate.UnixSeconds) error
	PutOrchestrator(context.Context, isolatedstate.Orchestrator) error
	FreezeOrchestrator(context.Context, string, isolatedstate.Generation, isolatedstate.UnixSeconds) (isolatedstate.Orchestrator, error)
	GetOrchestrator(context.Context, string) (isolatedstate.Orchestrator, error)
	ListOrchestrators(context.Context, string) ([]isolatedstate.Orchestrator, error)
	PutNetwork(context.Context, isolatedstate.PrivateNetwork) error
	GetNetwork(context.Context, string) (isolatedstate.PrivateNetwork, error)
	ListNetworks(context.Context, string) ([]isolatedstate.PrivateNetwork, error)
	CountActiveVMs(context.Context, string) (int, error)
	GetVM(context.Context, string) (isolatedstate.IsolatedVM, error)
	ListVMs(context.Context, string, string) ([]isolatedstate.IsolatedVM, error)
	PutVM(context.Context, isolatedstate.IsolatedVM) error
	PutNAT(context.Context, isolatedstate.NATAllocation) error
	GetNAT(context.Context, string) (isolatedstate.NATAllocation, error)
	ListNAT(context.Context, string, string, string) ([]isolatedstate.NATAllocation, error)
	PutRelay(context.Context, isolatedstate.RelayAllocation) error
	GetRelay(context.Context, string) (isolatedstate.RelayAllocation, error)
	GetRelayForVM(context.Context, string) (isolatedstate.RelayAllocation, error)
	ListRelays(context.Context, string, string) ([]isolatedstate.RelayAllocation, error)
	CommitAllocations(context.Context, []isolatedstate.ActiveResourceAllocation) error
	ListActiveAllocations(context.Context, string) ([]isolatedstate.ActiveResourceAllocation, error)
	ReleaseAllocation(context.Context, isolatedstate.ReleaseAllocationRequest) (isolatedstate.ResourceAllocationHistory, error)
}

type cascadeExecutionKey struct{}

type cascadeExecution struct {
	Plan         isolated.DeleteOrchestratorPlan
	ResourceType string
	ResourceID   string
	Action       cascadeauth.Action
}

func cascadeExecutionFromContext(ctx context.Context) (cascadeExecution, bool) {
	value, ok := ctx.Value(cascadeExecutionKey{}).(*cascadeExecution)
	if !ok || value == nil {
		return cascadeExecution{}, false
	}
	return *value, true
}

func cascadeExecutionPointerFromContext(ctx context.Context) (*cascadeExecution, bool) {
	value, ok := ctx.Value(cascadeExecutionKey{}).(*cascadeExecution)
	return value, ok && value != nil
}

func cascadeAuthorityFromContext(ctx context.Context) *hyperv.CascadeAuthority {
	execution, ok := cascadeExecutionFromContext(ctx)
	if !ok {
		return nil
	}
	authority := cascadeAuthorityForHost(execution.Plan.Authority)
	return &authority
}

func cascadeAuthorityItemsForAppliance(
	authority isolatedstate.CascadeAuthority,
) []appliance.CascadeAuthorityItem {
	items := make([]appliance.CascadeAuthorityItem, 0, len(authority.Items))
	for _, item := range authority.Items {
		items = append(items, appliance.CascadeAuthorityItem{
			ItemID: item.MutationID, ResourceKind: item.ResourceType,
			ResourceID: item.ResourceID, Action: item.Action,
			ExpectedGeneration: uint64(item.ExpectedGeneration),
		})
	}
	return items
}

func applyCascadeEnvelope(
	ctx context.Context,
	envelope *isolated.MutationEnvelope,
	action cascadeauth.Action,
) {
	execution, ok := cascadeExecutionFromContext(ctx)
	if !ok || envelope == nil {
		return
	}
	resourceType := cascadeActionResourceType(action)
	if resourceType == "" {
		return
	}
	envelope.CascadeOperationID = execution.Plan.Authority.OperationID
	envelope.CascadePlanRevision = execution.Plan.Authority.PlanRevision
	envelope.CascadePlanHash = execution.Plan.Authority.PlanHash
	envelope.CascadeResourceKind = resourceType
	envelope.CascadeAction = string(action)
	envelope.Header.CascadeOperationID = envelope.CascadeOperationID
	envelope.Header.CascadePlanRevision = envelope.CascadePlanRevision
	envelope.Header.CascadePlanHash = envelope.CascadePlanHash
	envelope.Header.CascadeResourceKind = envelope.CascadeResourceKind
	envelope.Header.CascadeAction = envelope.CascadeAction
	for _, item := range execution.Plan.Authority.Items {
		if item.ResourceID == envelope.Header.ResourceID &&
			item.ResourceType == resourceType &&
			item.Action == string(action) {
			envelope.CascadeItemID = item.MutationID
			envelope.Header.CascadeItemID = item.MutationID
			return
		}
	}
}

func cascadeActionResourceType(action cascadeauth.Action) string {
	for _, resourceType := range []string{"relay", "nat", "vm", "network", "orchestrator"} {
		if cascadeauth.ValidateScope(resourceType, action) == nil {
			return resourceType
		}
	}
	return ""
}

type isolatedAppliance interface {
	CheckReadiness(context.Context, string) (isolated.ApplianceReadiness, error)
	InspectApplianceState(context.Context, string) (isolated.ApplianceSnapshot, error)
	GetApplianceState(context.Context, string) (appliance.DesiredSnapshot, error)
	ReserveResources(context.Context, string, appliance.ReserveRequest) (appliance.ReserveResult, error)
	ReleaseResources(context.Context, string, appliance.ReleaseRequest) (appliance.ReleaseResult, error)
	ReleaseAuthority(context.Context, string, isolated.MutationEnvelope) error
	ApplyPrivateNetwork(context.Context, string, isolated.ApplyPrivateNetworkInput) (isolated.NetworkMutationResult, error)
	RemovePrivateNetwork(context.Context, string, isolated.MutationEnvelope) (isolated.NetworkMutationResult, error)
	RegisterIsolatedGuest(context.Context, string, isolated.RegisterGuestInput) (isolated.GuestMutationResult, error)
	RemoveIsolatedGuest(context.Context, string, isolated.MutationEnvelope, string) (isolated.GuestMutationResult, error)
	ApplyRelay(context.Context, string, isolated.RelayInput) (isolated.RelayMutationResult, error)
	AdoptRelay(context.Context, string, isolated.RelayInput) (isolated.RelayMutationResult, error)
	RemoveRelay(context.Context, string, isolated.MutationEnvelope, string, string) (isolated.RelayMutationResult, error)
	ListRelays(context.Context, string, string, string, bool, uint32, string) (isolated.RelayList, error)
	GetRelayStats(context.Context, string, string) (appliance.RelayStats, error)
	RebindRelays(context.Context, string, isolated.MutationEnvelope) ([]appliance.Relay, isolated.MutationResult, error)
	ValidateRelay(context.Context, string, string, bool) (isolated.RelayValidation, error)
	SetNATState(context.Context, string, isolated.NATInput) (isolated.NATMutationResult, error)
	ListNATState(context.Context, string, string, string, string, uint32, string) (isolated.NATList, error)
	ReconcileNAT(context.Context, string, isolated.MutationEnvelope, string) (isolated.NATMutationResult, error)
}

type isolatedHost interface {
	PhysicalIdentity(context.Context, Target) (hyperv.IsolatedPhysicalHostObservation, error)
	Discover(context.Context, Target, string, string) (hyperv.IsolatedHostDiscovery, error)
	AcquireFence(context.Context, Target, isolated.HostCreateFenceRequest) (isolated.HostFenceLease, error)
	ReleaseFence(context.Context, Target, isolated.HostFenceLease)
	ReleaseFenceChecked(context.Context, Target, isolated.HostFenceLease) error
	Preflight(context.Context, Target, isolated.ResourcePreflightInput, vmconfig.Profile) (isolated.ResourcePreflightResult, error)
	ClaimOrchestrator(context.Context, Target, isolatedstate.Orchestrator, isolated.HostFenceLease) (hyperv.IsolatedVMObservation, error)
	CreateSwitch(context.Context, Target, hyperv.CreateIsolatedPrivateSwitchParams) (hyperv.IsolatedSwitchMutationResult, error)
	AttachNIC(context.Context, Target, hyperv.AttachIsolatedNICParams) (hyperv.IsolatedAdapterMutationResult, error)
	ReconcileNICMetadata(context.Context, Target, hyperv.ReconcileIsolatedAdapterMetadataParams) (hyperv.IsolatedAdapterMutationResult, error)
	RemoveNIC(context.Context, Target, hyperv.RemoveIsolatedNICParams) (hyperv.IsolatedAdapterMutationResult, error)
	DeleteSwitch(context.Context, Target, hyperv.DeleteIsolatedPrivateSwitchParams) (hyperv.IsolatedSwitchMutationResult, error)
	CleanupNetworkMetadata(context.Context, Target, hyperv.CleanupIsolatedNetworkMetadataParams) (hyperv.IsolatedMetadataCleanupResult, error)
	CleanupOrchestratorMetadata(context.Context, Target, hyperv.CleanupIsolatedOrchestratorMetadataParams) (hyperv.IsolatedMetadataCleanupResult, error)
	DeleteOrchestratorVM(context.Context, Target, hyperv.DeleteIsolatedOrchestratorVMParams) (map[string]any, error)
}

type isolatedParentLifecycleHost interface {
	SetParentLifecycle(
		context.Context,
		Target,
		isolatedstate.Orchestrator,
		isolated.HostFenceLease,
		isolatedstate.CascadeAuthority,
		string,
	) error
	RebindParentFence(
		context.Context,
		Target,
		isolatedstate.Orchestrator,
		isolated.HostFenceLease,
		isolatedstate.CascadeAuthority,
	) error
}

type isolatedParentLifecycleAppliance interface {
	SetParentLifecycle(
		context.Context,
		string,
		isolated.MutationEnvelope,
		string,
		uint64,
	) error
}

type isolatedLinuxCreator interface {
	Create(context.Context, mcp.CallToolRequest, linuxVMPlan, Target, *MCPProgressState) (*mcp.CallToolResult, error)
}

type isolatedGuestRuntime interface {
	Provision(context.Context, isolatedstate.IsolatedVM, isolatedstate.PrivateNetwork, isolatedstate.Orchestrator, Target, isolated.HostFenceLease, string, *MCPProgressState) (isolatedstate.IsolatedVM, hyperv.IsolatedVMMutationResult, error)
	StartAndEnroll(context.Context, isolatedstate.IsolatedVM, isolatedstate.RelayAllocation, isolatedstate.Orchestrator, Target, *MCPProgressState) error
	Inspect(context.Context, isolatedstate.IsolatedVM, Target) (hyperv.IsolatedVMMutationResult, error)
	Reconcile(context.Context, isolatedstate.IsolatedVM, isolatedstate.PrivateNetwork, isolatedstate.Orchestrator, Target, isolated.HostFenceLease, string) (hyperv.IsolatedVMMutationResult, error)
	Delete(context.Context, isolatedstate.IsolatedVM, isolatedstate.Orchestrator, Target, isolated.HostFenceLease, string, bool) (hyperv.IsolatedVMMutationResult, error)
}

type isolatedLifecycleDeps struct {
	server               *server.MCPServer
	state                isolatedState
	locks                *isolatedstate.LockManager
	host                 isolatedHost
	orchestrators        isolated.OrchestratorStateClient
	planner              isolated.HostPlanningClient
	probe                isolated.OrchestratorProbeClient
	networks             isolated.NetworkStateClient
	networkHost          isolated.HostNetworkClient
	appliance            isolatedAppliance
	linux                isolatedLinuxCreator
	registry             *registry.Registry
	pool                 *agentclient.Pool
	defaults             *vmconfig.Store
	credentials          *credentials.Store
	secrets              *secretstore.Store
	audit                *audit.Log
	enrollment           VMEnrollmentConfig
	lease                LeaseGateConfig
	serverVersion        string
	guests               isolatedGuestRuntime
	deleteOrchestratorVM func(context.Context, isolatedstate.Orchestrator) (any, error)
	joinDomain           func(context.Context, string, vmconfig.WindowsDomainJoin, int, *registry.Registry, *agentclient.Pool, *secretstore.Store, *audit.Log) (windowsDomainJoinResult, error)
}

func claimAndPersistOrchestratorFence(
	ctx context.Context,
	deps *isolatedLifecycleDeps,
	target Target,
	orchestrator isolatedstate.Orchestrator,
	lease isolated.HostFenceLease,
) (isolatedstate.Orchestrator, error) {
	orchestrator.HostFence = lease.Fence
	observation, err := deps.host.ClaimOrchestrator(ctx, target, orchestrator, lease)
	if err != nil {
		return orchestrator, err
	}
	orchestrator.HyperVVMID = optionalTrimmed(observation.VMGUID)
	orchestrator.UpdatedAt = isolatedNow()
	if err := deps.state.PutOrchestrator(ctx, orchestrator); err != nil {
		return orchestrator, err
	}
	return orchestrator, nil
}

func freezeApprovedParent(
	ctx context.Context,
	deps *isolatedLifecycleDeps,
	target Target,
	record isolatedstate.Orchestrator,
	expected isolatedstate.Generation,
	plan isolated.DeleteOrchestratorPlan,
) (result isolatedstate.Orchestrator, resultErr error) {
	hostLifecycle, ok := deps.host.(isolatedParentLifecycleHost)
	if !ok {
		return record, errors.New("PARENT_FREEZE_UNAVAILABLE: host lifecycle authority is not configured")
	}
	applianceLifecycle, ok := deps.appliance.(isolatedParentLifecycleAppliance)
	if !ok {
		return record, errors.New("PARENT_FREEZE_UNAVAILABLE: appliance lifecycle authority is not configured")
	}
	hostLease, err := acquireCompatibleOrchestratorFence(
		ctx, deps, target, record, plan.Plan.OperationID)
	if err != nil {
		return record, err
	}
	releaseRecord := record
	defer func() {
		if err := releaseOrchestratorFence(deps, target, releaseRecord, hostLease); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	current, err := deps.state.GetOrchestrator(ctx, record.ID)
	if err != nil {
		return record, err
	}
	authority := plan.Authority
	authority.HostFence = hostLease.Fence
	authority.LeaseID = hostLease.LeaseID
	switch {
	case current.DesiredGeneration == expected &&
		!orchestratorBlocksChildMutation(current.LifecycleState):
		current, err = claimAndPersistOrchestratorFence(
			ctx, deps, target, current, hostLease)
		if err != nil {
			return record, err
		}
		current, err = deps.state.FreezeOrchestrator(
			ctx, current.ID, expected, isolatedNow())
		if err != nil {
			return record, err
		}
		if err := hostLifecycle.SetParentLifecycle(
			ctx, target, current, hostLease, authority, "frozen",
		); err != nil {
			return record, err
		}
	case current.DesiredGeneration == expected+1 &&
		(current.LifecycleState == isolatedstate.OrchestratorFrozen ||
			current.LifecycleState == isolatedstate.OrchestratorDeleting):
		if current.HostFence != hostLease.Fence {
			if err := hostLifecycle.RebindParentFence(
				ctx, target, current, hostLease, authority,
			); err != nil {
				return record, err
			}
		}
		current.HostFence = hostLease.Fence
		current.UpdatedAt = isolatedNow()
		if err := deps.state.PutOrchestrator(ctx, current); err != nil {
			return record, err
		}
	default:
		return record, fmt.Errorf(
			"PARENT_FROZEN: expected pre-freeze generation %d, current generation/state is %d/%s",
			expected, current.DesiredGeneration, current.LifecycleState)
	}
	authority.HostFence = hostLease.Fence
	authority.LeaseID = hostLease.LeaseID
	envelope := isolated.MutationEnvelope{
		Header: appliance.MutationHeader{
			ParentOperationID: plan.Plan.OperationID,
			MutationID: isolatedstate.StableMutationID(
				plan.Plan.OperationID, current.ID, "freeze_parent", "freeze_parent"),
			SemanticHash: plan.Plan.SemanticHash, ResourceID: current.ID,
			ParentResourceID: current.ID, HostFence: uint64(hostLease.Fence),
			ExpectedParentGeneration: uint64(expected),
		},
		PhysicalHostID: current.PhysicalHostID, HostLeaseID: hostLease.LeaseID,
		HostLeaseSecret:      mustDecodeHex(hostLease.LeaseSecret),
		HostLeaseExpiresUnix: hostLease.ExpiresAtUnix,
		CascadeOperationID:   plan.Plan.OperationID,
		CascadePlanRevision:  plan.Plan.Revision,
		CascadePlanHash:      plan.Plan.PlanHash,
		CascadeItems:         cascadeAuthorityItemsForAppliance(authority),
	}
	if err := applianceLifecycle.SetParentLifecycle(
		ctx, current.ID, envelope, "frozen", uint64(expected+1),
	); err != nil {
		return record, err
	}
	if err := deps.state.InstallCascadeAuthority(ctx, authority); err != nil {
		return record, err
	}
	releaseRecord = current
	return current, nil
}

func orchestratorBlocksChildMutation(state isolatedstate.OrchestratorLifecycleState) bool {
	switch state {
	case isolatedstate.OrchestratorFrozen, isolatedstate.OrchestratorDeleting,
		isolatedstate.OrchestratorLost, isolatedstate.OrchestratorDeleted:
		return true
	default:
		return false
	}
}

func admitChildMutationAfterFence(
	ctx context.Context,
	deps *isolatedLifecycleDeps,
	target Target,
	stale isolatedstate.Orchestrator,
	hostLease isolated.HostFenceLease,
	resourceType, resourceID, action string,
) (result isolatedstate.Orchestrator, resultErr error) {
	admitted := false
	defer func() {
		if !admitted {
			releaseCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := deps.host.ReleaseFenceChecked(releaseCtx, target, hostLease); err != nil {
				resultErr = errors.Join(resultErr,
					fmt.Errorf("HOST_FENCE_RELEASE_FAILED: %w", err))
			}
		}
	}()
	current, err := deps.state.GetOrchestrator(ctx, stale.ID)
	if err != nil {
		return stale, err
	}
	if !orchestratorBlocksChildMutation(current.LifecycleState) {
		current, err = claimAndPersistOrchestratorFence(
			ctx, deps, target, current, hostLease)
		if err == nil {
			admitted = true
		}
		return current, err
	}
	execution, ok := cascadeExecutionFromContext(ctx)
	if !ok || execution.ResourceType != resourceType ||
		execution.ResourceID != resourceID || string(execution.Action) != action ||
		execution.Plan.Authority.OrchestratorID != current.ID ||
		execution.Plan.Authority.FrozenGeneration != current.DesiredGeneration {
		return current, fmt.Errorf(
			"PARENT_FROZEN: orchestrator %s is %s at generation %d",
			current.ID, current.LifecycleState, current.DesiredGeneration)
	}
	if err := validateApprovedCascadeChild(
		ctx, deps.state, execution.Plan.Plan, resourceType, resourceID,
	); err != nil {
		return current, err
	}
	hostLifecycle, ok := deps.host.(isolatedParentLifecycleHost)
	if !ok {
		return current, errors.New("PARENT_FREEZE_UNAVAILABLE: host lifecycle authority is not configured")
	}
	applianceLifecycle, ok := deps.appliance.(isolatedParentLifecycleAppliance)
	if !ok {
		return current, errors.New("PARENT_FREEZE_UNAVAILABLE: appliance lifecycle authority is not configured")
	}
	authority := execution.Plan.Authority
	authority.HostFence = hostLease.Fence
	authority.LeaseID = hostLease.LeaseID
	if current.HostFence != hostLease.Fence {
		if err := hostLifecycle.RebindParentFence(
			ctx, target, current, hostLease, authority,
		); err != nil {
			return current, err
		}
	}
	current.HostFence = hostLease.Fence
	current.UpdatedAt = isolatedNow()
	if err := deps.state.PutOrchestrator(ctx, current); err != nil {
		return current, err
	}
	envelope := isolated.MutationEnvelope{
		Header: appliance.MutationHeader{
			ParentOperationID: authority.OperationID,
			MutationID: isolatedstate.StableMutationID(
				authority.OperationID, current.ID, "rebind_parent_fence", "cascade_rebind"),
			SemanticHash: authority.PlanHash, ResourceID: current.ID,
			ParentResourceID: current.ID, HostFence: uint64(hostLease.Fence),
			ExpectedParentGeneration: uint64(authority.FrozenGeneration - 1),
		},
		PhysicalHostID: current.PhysicalHostID, HostLeaseID: hostLease.LeaseID,
		HostLeaseSecret:      mustDecodeHex(hostLease.LeaseSecret),
		HostLeaseExpiresUnix: hostLease.ExpiresAtUnix,
		CascadeOperationID:   authority.OperationID,
		CascadePlanRevision:  authority.PlanRevision,
		CascadePlanHash:      authority.PlanHash,
		CascadeItems:         cascadeAuthorityItemsForAppliance(authority),
	}
	if err := applianceLifecycle.SetParentLifecycle(
		ctx, current.ID, envelope, "frozen", uint64(authority.FrozenGeneration),
	); err != nil {
		return current, err
	}
	if err := deps.state.InstallCascadeAuthority(ctx, authority); err != nil {
		return current, err
	}
	if executionPointer, ok := cascadeExecutionPointerFromContext(ctx); ok {
		executionPointer.Plan.Authority = authority
	}
	admitted = true
	return current, nil
}

func acquireCompatibleOrchestratorFence(
	ctx context.Context,
	deps *isolatedLifecycleDeps,
	target Target,
	orchestrator isolatedstate.Orchestrator,
	operationID string,
) (isolated.HostFenceLease, error) {
	if _, err := deps.appliance.CheckReadiness(ctx, orchestrator.ID); err != nil {
		var compatibilityErr *isolated.CompatibilityError
		if errors.As(err, &compatibilityErr) &&
			compatibilityErr.Code == "AGENT_UPGRADE_REQUIRED" {
			return isolated.HostFenceLease{}, fmt.Errorf(
				"APPLIANCE_UPGRADE_REQUIRED_BEFORE_HOST_FENCE: %w", err)
		}
		return isolated.HostFenceLease{}, err
	}
	lockKey, _ := hyperv.HostOrchestratorCreateLockKey(orchestrator.PhysicalHostID)
	return deps.host.AcquireFence(ctx, target, isolated.HostCreateFenceRequest{
		PhysicalHostID: orchestrator.PhysicalHostID,
		HostNode:       orchestrator.HostNode,
		OperationID:    operationID,
		LockKey:        lockKey,
	})
}

func releaseOrchestratorFence(
	deps *isolatedLifecycleDeps,
	target Target,
	orchestrator isolatedstate.Orchestrator,
	lease isolated.HostFenceLease,
) error {
	applianceCtx, cancelAppliance := context.WithTimeout(context.Background(), 15*time.Second)
	applianceErr := deps.appliance.ReleaseAuthority(applianceCtx, orchestrator.ID, isolated.MutationEnvelope{
		Header: appliance.MutationHeader{
			HostFence:                uint64(lease.Fence),
			ParentResourceID:         orchestrator.ID,
			ExpectedParentGeneration: uint64(orchestrator.DesiredGeneration),
		},
		PhysicalHostID:       orchestrator.PhysicalHostID,
		HostLeaseID:          lease.LeaseID,
		HostLeaseSecret:      mustDecodeHex(lease.LeaseSecret),
		HostLeaseExpiresUnix: lease.ExpiresAtUnix,
	})
	cancelAppliance()
	hostCtx, cancelHost := context.WithTimeout(context.Background(), 45*time.Second)
	hostErr := deps.host.ReleaseFenceChecked(hostCtx, target, lease)
	cancelHost()
	var result error
	if applianceErr != nil {
		result = errors.Join(result, fmt.Errorf(
			"APPLIANCE_AUTHORITY_RELEASE_FAILED: physical host fence was still released: %w",
			applianceErr))
	}
	if hostErr != nil {
		result = errors.Join(result, fmt.Errorf("HOST_FENCE_RELEASE_FAILED: %w", hostErr))
	}
	return result
}

func deferOrchestratorFenceRelease(
	deps *isolatedLifecycleDeps,
	target Target,
	orchestrator isolatedstate.Orchestrator,
	lease isolated.HostFenceLease,
	result **mcp.CallToolResult,
	callErr *error,
) {
	releaseErr := releaseOrchestratorFence(deps, target, orchestrator, lease)
	if releaseErr == nil {
		return
	}
	if *callErr != nil {
		*callErr = errors.Join(*callErr, releaseErr)
		return
	}
	*result = mcp.NewToolResultError(releaseErr.Error())
}

func boundedRelayRetirement(
	ctx context.Context,
	run func(context.Context) (isolated.RelayMutationResult, error),
) (isolated.RelayMutationResult, error) {
	retireCtx, cancel := context.WithTimeout(ctx, isolatedRelayRetirementTimeout)
	defer cancel()
	return run(retireCtx)
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
		existing, err := state.GetApprovalPlan(ctx, plan.Revision)
		if err != nil {
			return false, nil, err
		}
		if existing.OperationID != operationID || existing.PlanHash != plan.PlanHash ||
			existing.Action != action {
			return false, nil, errors.New("APPROVAL_IDENTITY_MISMATCH: stored approval does not authorize this exact operation")
		}
		if existing.State == isolatedstate.ApprovalConsumed {
			if !req.GetBool("resume_exact", false) {
				return false, nil, errors.New("CONSUMED_APPROVAL_REQUIRES_EXACT_RESUME")
			}
			return true, nil, nil
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
