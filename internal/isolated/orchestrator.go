package isolated

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/cascadeauth"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
)

const (
	MaxNetworksPerOrchestrator = 16
	MaxVMsPerOrchestrator      = 100
	MinimumApplianceSchema     = appliance.CurrentSchemaVersion
	MaximumApplianceSchema     = appliance.CurrentSchemaVersion
)

type DomainError struct {
	Code    string
	Message string
}

func (e *DomainError) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

func ErrorCode(err error) string {
	var domainErr *DomainError
	if errors.As(err, &domainErr) {
		return domainErr.Code
	}
	if code := appliance.ErrorCodeOf(err); code != "" {
		return string(code)
	}
	var compatibilityErr *CompatibilityError
	if errors.As(err, &compatibilityErr) {
		return compatibilityErr.Code
	}
	return ""
}

type OrchestratorOperation string

const (
	OperationAddNetwork OrchestratorOperation = "add_network"
	OperationAddGuest   OrchestratorOperation = "add_guest"
	OperationEnableNAT  OrchestratorOperation = "enable_nat"
	OperationReconcile  OrchestratorOperation = "reconcile"
)

type OperationCapacity struct {
	FreeSubnets               int
	PrivateAdapterSlots       int
	SwitchSlots               int
	HostResourcesAvailable    bool
	FreeGuestIPs              int
	FreeMACs                  int
	FreeRelayPorts            int
	FreeConntrackMarks        int
	GuestSlots                int
	NATSupported              bool
	ReservedConntrackMark     bool
	ExistingOrchestratorCount int
}

func (c OperationCapacity) Supports(operation OrchestratorOperation) error {
	switch operation {
	case OperationAddNetwork:
		if c.FreeSubnets <= 0 {
			return capacityError(operation, "no unreserved /26 subnet remains")
		}
		if c.PrivateAdapterSlots <= 0 {
			return capacityError(operation, "no effective synthetic adapter slot remains")
		}
		if c.SwitchSlots <= 0 {
			return capacityError(operation, "no private switch slot remains")
		}
		if !c.HostResourcesAvailable {
			return capacityError(operation, "host memory or storage preflight failed")
		}
	case OperationAddGuest:
		if c.GuestSlots <= 0 {
			return capacityError(operation, "the 100 guest product limit is reached")
		}
		if c.FreeGuestIPs <= 0 || c.FreeMACs <= 0 || c.FreeRelayPorts <= 0 ||
			c.FreeConntrackMarks <= 0 {
			return capacityError(operation, "guest IP, MAC, relay port, or conntrack capacity is exhausted")
		}
	case OperationEnableNAT:
		if !c.NATSupported {
			return capacityError(operation, "required kernel NAT facilities are unavailable")
		}
		if !c.ReservedConntrackMark {
			return capacityError(operation, "the VM has no persisted conntrack mark")
		}
	case OperationReconcile:
		return nil
	default:
		return &DomainError{Code: "INVALID_OPERATION", Message: fmt.Sprintf("unsupported operation %q", operation)}
	}
	return nil
}

func capacityError(operation OrchestratorOperation, message string) error {
	return &DomainError{
		Code:    "ORCHESTRATOR_CAPACITY_EXHAUSTED",
		Message: fmt.Sprintf("%s: %s", operation, message),
	}
}

type OrchestratorObservation struct {
	Record                  isolatedstate.Orchestrator
	HostReachable           bool
	VMState                 string
	MainNICHealthy          bool
	AgentAuthenticated      bool
	Agent                   AgentCompatibility
	ApplianceReady          bool
	AppliancePolicyVerified bool
	ApplianceSchema         int
	ApplyIntentError        string
	RouteConflict           bool
	ImmutableIdentityMatch  bool
	Capacity                OperationCapacity
}

func (o OrchestratorObservation) offline() bool {
	return !o.HostReachable || !o.AgentAuthenticated ||
		strings.EqualFold(strings.TrimSpace(o.VMState), "off")
}

type RecoveryStep struct {
	Action string
	Detail string
}

type RecoveryResult struct {
	Observation OrchestratorObservation
	Steps       []RecoveryStep
}

type OrchestratorStateClient interface {
	ListOrchestrators(context.Context, string) ([]isolatedstate.Orchestrator, error)
	GetOrchestrator(context.Context, string) (isolatedstate.Orchestrator, error)
	ImportApplianceCache(context.Context, ServerCacheImport) error
}

type OrchestratorProbeClient interface {
	ObserveOrchestrator(context.Context, isolatedstate.Orchestrator) (OrchestratorObservation, error)
	RecoverOrchestrator(context.Context, isolatedstate.Orchestrator) (RecoveryResult, error)
}

type HostPlanningClient interface {
	AcquireOrchestratorCreateFence(context.Context, HostCreateFenceRequest) (HostFenceLease, error)
	ReleaseOrchestratorCreateFence(context.Context, HostCreateFenceRequest, HostFenceLease) error
	ReconcileStaleOrchestratorMetadata(context.Context, StaleOrchestratorMetadataRequest) error
	PreflightOrchestrator(context.Context, ResourcePreflightInput) (ResourcePreflightResult, error)
}

type ApplianceClient interface {
	GetApplianceState(context.Context, string) (appliance.DesiredSnapshot, error)
	ReserveResources(context.Context, string, appliance.ReserveRequest) (appliance.ReserveResult, error)
}

type ReservationRequestBuilder func(
	appliance.DesiredSnapshot,
	int,
) (appliance.ReserveRequest, error)

type AuthoritativeReservationRequest struct {
	OrchestratorID string
	Explicit       bool
	MaxAttempts    int
	Build          ReservationRequestBuilder
}

type AuthoritativeReservationResult struct {
	Result   appliance.ReserveResult
	Attempts int
}

// ReserveAuthoritativeResources implements the appliance-authoritative half
// of the allocation handshake. The caller imports only the returned accepted
// values into its server cache.
func ReserveAuthoritativeResources(
	ctx context.Context,
	client ApplianceClient,
	request AuthoritativeReservationRequest,
) (AuthoritativeReservationResult, error) {
	if client == nil || request.Build == nil || strings.TrimSpace(request.OrchestratorID) == "" {
		return AuthoritativeReservationResult{}, errors.New("isolated: incomplete authoritative reservation request")
	}
	if request.MaxAttempts <= 0 {
		request.MaxAttempts = MaxVMsPerOrchestrator
	}
	for attempt := 1; attempt <= request.MaxAttempts; attempt++ {
		snapshot, err := client.GetApplianceState(ctx, request.OrchestratorID)
		if err != nil {
			return AuthoritativeReservationResult{}, err
		}
		reserveRequest, err := request.Build(snapshot, attempt)
		if err != nil {
			return AuthoritativeReservationResult{}, err
		}
		result, err := client.ReserveResources(ctx, request.OrchestratorID, reserveRequest)
		if err == nil {
			return AuthoritativeReservationResult{Result: result, Attempts: attempt}, nil
		}
		var collision *appliance.CollisionError
		if request.Explicit || !errors.As(err, &collision) {
			return AuthoritativeReservationResult{}, err
		}
		if attempt == request.MaxAttempts {
			return AuthoritativeReservationResult{}, &DomainError{
				Code: "ALLOCATION_RETRY_EXHAUSTED",
				Message: fmt.Sprintf(
					"appliance rejected %d automatic proposals; last collision was %s",
					attempt, collision.Code,
				),
			}
		}
	}
	return AuthoritativeReservationResult{}, &DomainError{
		Code:    "ALLOCATION_RETRY_EXHAUSTED",
		Message: "automatic reservation attempts were exhausted",
	}
}

type HostCreateFenceRequest struct {
	PhysicalHostID string
	HostNode       string
	OperationID    string
	LockKey        hyperv.IsolatedResourceLockKey
}

type StaleOrchestratorMetadataRequest struct {
	PhysicalHostID   string
	HostNode         string
	OperationID      string
	OrchestratorID   string
	HyperVName       string
	OrchestratorVMID string
	LifecycleState   string
	Lease            HostFenceLease
}

type HostFenceLease struct {
	LeaseID       string
	LeaseSecret   string
	ExpiresAtUnix int64
	Fence         int64
	LockKey       hyperv.IsolatedResourceLockKey
}

func (l HostFenceLease) Validate(expectedLock hyperv.IsolatedResourceLockKey) error {
	if _, err := parseImmutableID("lease", l.LeaseID); err != nil {
		return &DomainError{Code: "HOST_FENCE_INVALID", Message: err.Error()}
	}
	secret, err := hex.DecodeString(strings.TrimSpace(l.LeaseSecret))
	if err != nil || len(secret) != 32 || l.Fence <= 0 || l.ExpiresAtUnix <= time.Now().Unix() {
		return &DomainError{Code: "HOST_FENCE_INVALID", Message: "host returned an incomplete creation lease"}
	}
	if l.LockKey != expectedLock {
		return &DomainError{
			Code:    "HOST_FENCE_INVALID",
			Message: fmt.Sprintf("host returned lock %q, expected %q", l.LockKey.Key, expectedLock.Key),
		}
	}
	return nil
}

type ResourcePreflightInput struct {
	PhysicalHostID              string
	HostNode                    string
	MainVSwitch                 string
	ProfileName                 string
	ProjectedMemoryMB           int
	ProjectedStorageBytes       int64
	ExistingOrchestratorCount   int
	AggregateReservedMemoryMB   int
	RequiredPrivateAdapterSlots int
	RequiredSwitchSlots         int
	RequiredFreeSubnets         int
	RequiredRelayPorts          int
	RequiredGuestSlots          int
}

type ResourcePreflightResult struct {
	Allowed                       bool
	Reason                        string
	AvailableMemoryMB             int
	AvailableStorageBytes         int64
	HostReportedSyntheticAdapters int
	EffectivePrivateAdapterSlots  int
	AvailableSwitchSlots          int
}

type SelectionRequest struct {
	PhysicalHostID       string
	ExplicitOrchestrator string
	Operation            OrchestratorOperation
	ServerVersion        string
}

type SelectionSkip struct {
	OrchestratorID string
	Code           string
	Reason         string
	Recovery       []RecoveryStep
}

type SelectionResult struct {
	Orchestrator isolatedstate.Orchestrator
	Observation  OrchestratorObservation
	Recovery     []RecoveryStep
	Skipped      []SelectionSkip
}

type OrchestratorDomain struct {
	State     OrchestratorStateClient
	Probe     OrchestratorProbeClient
	Host      HostPlanningClient
	Appliance ApplianceClient
}

func (d OrchestratorDomain) Select(ctx context.Context, request SelectionRequest) (SelectionResult, error) {
	if d.State == nil || d.Probe == nil {
		return SelectionResult{}, errors.New("isolated: orchestrator state and probe clients are required")
	}
	if strings.TrimSpace(request.PhysicalHostID) == "" {
		return SelectionResult{}, &DomainError{Code: "INVALID_TARGET", Message: "physical host ID is required"}
	}
	if request.Operation == "" {
		return SelectionResult{}, &DomainError{Code: "INVALID_OPERATION", Message: "requested operation is required"}
	}

	if strings.TrimSpace(request.ExplicitOrchestrator) != "" {
		record, err := d.State.GetOrchestrator(ctx, request.ExplicitOrchestrator)
		if err != nil {
			return SelectionResult{}, err
		}
		if record.PhysicalHostID != request.PhysicalHostID {
			return SelectionResult{}, &DomainError{
				Code: "ORCHESTRATOR_HOST_MISMATCH",
				Message: fmt.Sprintf(
					"orchestrator %s belongs to host %s, not %s",
					record.ID, record.PhysicalHostID, request.PhysicalHostID,
				),
			}
		}
		observation, recovery, err := d.observeRecoverFirst(ctx, record)
		if err != nil {
			return SelectionResult{}, err
		}
		if err := validateOrchestratorObservation(observation, request.Operation, request.ServerVersion); err != nil {
			return SelectionResult{}, err
		}
		return SelectionResult{Orchestrator: record, Observation: observation, Recovery: recovery}, nil
	}

	records, err := d.State.ListOrchestrators(ctx, request.PhysicalHostID)
	if err != nil {
		return SelectionResult{}, err
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].CreatedAt == records[j].CreatedAt {
			return records[i].ID < records[j].ID
		}
		return records[i].CreatedAt < records[j].CreatedAt
	})
	result := SelectionResult{}
	for _, record := range records {
		if record.PhysicalHostID != request.PhysicalHostID {
			continue
		}
		if record.LifecycleState == isolatedstate.OrchestratorDeleted ||
			record.LifecycleState == isolatedstate.OrchestratorLost {
			result.Skipped = append(result.Skipped, SelectionSkip{
				OrchestratorID: record.ID,
				Code:           "ORCHESTRATOR_LOST",
				Reason:         "orchestrator is deleted or lost",
			})
			continue
		}
		observation, recovery, observeErr := d.observeRecoverFirst(ctx, record)
		if observeErr == nil {
			observeErr = validateOrchestratorObservation(observation, request.Operation, request.ServerVersion)
		}
		if observeErr == nil {
			result.Orchestrator = record
			result.Observation = observation
			result.Recovery = recovery
			return result, nil
		}
		result.Skipped = append(result.Skipped, SelectionSkip{
			OrchestratorID: record.ID,
			Code:           ErrorCode(observeErr),
			Reason:         observeErr.Error(),
			Recovery:       recovery,
		})
	}
	return result, &DomainError{
		Code:    "NO_USABLE_ORCHESTRATOR",
		Message: "no healthy compatible orchestrator has capacity for " + string(request.Operation),
	}
}

func (d OrchestratorDomain) observeRecoverFirst(
	ctx context.Context,
	record isolatedstate.Orchestrator,
) (OrchestratorObservation, []RecoveryStep, error) {
	observation, err := d.Probe.ObserveOrchestrator(ctx, record)
	if err == nil && !observation.offline() {
		if observation.Record.ID == "" {
			observation.Record = record
		}
		return observation, nil, nil
	}
	recovery, recoverErr := d.Probe.RecoverOrchestrator(ctx, record)
	if recoverErr != nil {
		if err != nil {
			return observation, nil, &DomainError{
				Code:    "ORCHESTRATOR_OFFLINE",
				Message: fmt.Sprintf("observe failed: %v; recovery failed: %v", err, recoverErr),
			}
		}
		return observation, recovery.Steps, &DomainError{
			Code:    "ORCHESTRATOR_OFFLINE",
			Message: "required recovery failed: " + recoverErr.Error(),
		}
	}
	if recovery.Observation.Record.ID == "" {
		recovery.Observation.Record = record
	}
	return recovery.Observation, recovery.Steps, nil
}

func validateOrchestratorObservation(
	observation OrchestratorObservation,
	operation OrchestratorOperation,
	serverVersion string,
) error {
	record := observation.Record
	switch record.LifecycleState {
	case isolatedstate.OrchestratorFrozen, isolatedstate.OrchestratorDeleting:
		return &DomainError{Code: "PARENT_FROZEN", Message: "orchestrator is frozen or deleting"}
	case isolatedstate.OrchestratorLost, isolatedstate.OrchestratorDeleted:
		return &DomainError{Code: "ORCHESTRATOR_LOST", Message: "orchestrator is lost or deleted"}
	}
	if !observation.HostReachable || !observation.AgentAuthenticated {
		return &DomainError{Code: "ORCHESTRATOR_OFFLINE", Message: "host or orchestrator agent is unreachable"}
	}
	if !strings.EqualFold(strings.TrimSpace(observation.VMState), "running") ||
		!observation.MainNICHealthy {
		return &DomainError{Code: "ORCHESTRATOR_UNHEALTHY", Message: "VM or main NIC is not healthy"}
	}
	if !observation.ImmutableIdentityMatch {
		return &DomainError{Code: "ORCHESTRATOR_IDENTITY_MISMATCH", Message: "Hyper-V or appliance immutable identity changed"}
	}
	if err := CheckOrchestratorCompatibility(observation.Agent, serverVersion); err != nil {
		return err
	}
	if observation.ApplianceSchema < MinimumApplianceSchema ||
		observation.ApplianceSchema > MaximumApplianceSchema {
		return &DomainError{
			Code: "APPLIANCE_SCHEMA_UNSUPPORTED",
			Message: fmt.Sprintf(
				"node %s reports appliance schema %d, supported range is %d-%d; run update_agent(node=%s)",
				observation.Agent.Node, observation.ApplianceSchema,
				MinimumApplianceSchema, MaximumApplianceSchema, observation.Agent.Node,
			),
		}
	}
	if !observation.ApplianceReady || !observation.AppliancePolicyVerified {
		detail := "appliance_ready=false or policy is unverified"
		if observation.ApplyIntentError != "" {
			detail += ": " + observation.ApplyIntentError
		}
		return &DomainError{Code: "APPLIANCE_NOT_READY", Message: detail}
	}
	if observation.RouteConflict {
		return &DomainError{Code: "ROUTE_CONFLICT", Message: "a live management route overlaps the private address pool"}
	}
	return observation.Capacity.Supports(operation)
}

type PlanAction struct {
	Phase              string `json:"phase"`
	Action             string `json:"action"`
	ResourceType       string `json:"resource_type"`
	ResourceID         string `json:"resource_id"`
	ExpectedIdentity   string `json:"expected_identity,omitempty"`
	ExpectedGeneration int64  `json:"expected_generation"`
	NewGeneration      int64  `json:"new_generation"`
}

type RevisionedPlan struct {
	Kind         string         `json:"kind"`
	OperationID  string         `json:"operation_id"`
	ResourceID   string         `json:"resource_id"`
	SemanticHash string         `json:"semantic_hash"`
	PlanHash     string         `json:"plan_hash"`
	Revision     string         `json:"revision"`
	Actions      []PlanAction   `json:"actions"`
	Inputs       map[string]any `json:"inputs"`
}

func newRevisionedPlan(
	kind, operationID, resourceID string,
	inputs map[string]any,
	actions []PlanAction,
) (RevisionedPlan, error) {
	normalizedOperation, err := ParseOperationID(operationID)
	if err != nil {
		return RevisionedPlan{}, err
	}
	normalizedResource, err := parseImmutableID("resource", resourceID)
	if err != nil {
		return RevisionedPlan{}, err
	}
	semanticHash, err := isolatedstate.SemanticHash(inputs)
	if err != nil {
		return RevisionedPlan{}, err
	}
	planHash, err := isolatedstate.SemanticHash(map[string]any{
		"kind":          kind,
		"operation_id":  normalizedOperation.String(),
		"resource_id":   normalizedResource,
		"semantic_hash": semanticHash,
		"actions":       actions,
	})
	if err != nil {
		return RevisionedPlan{}, err
	}
	return RevisionedPlan{
		Kind:         kind,
		OperationID:  normalizedOperation.String(),
		ResourceID:   normalizedResource,
		SemanticHash: semanticHash,
		PlanHash:     planHash,
		Revision:     "r1-" + planHash[:16],
		Actions:      append([]PlanAction(nil), actions...),
		Inputs:       cloneInputs(inputs),
	}, nil
}

func cloneInputs(inputs map[string]any) map[string]any {
	result := make(map[string]any, len(inputs))
	for key, value := range inputs {
		result[key] = value
	}
	return result
}

func ValidateResumeExact(stored RevisionedPlan, operationID string, resumeExact bool, inputs map[string]any) error {
	if stored.OperationID != strings.ToLower(strings.TrimSpace(operationID)) {
		return &DomainError{Code: "OPERATION_ID_MISMATCH", Message: "the stored plan belongs to another operation"}
	}
	if !resumeExact {
		return &DomainError{Code: "RESUME_EXACT_REQUIRED", Message: "resume_exact=true is required"}
	}
	hash, err := isolatedstate.SemanticHash(inputs)
	if err != nil {
		return err
	}
	if hash != stored.SemanticHash {
		return &DomainError{
			Code:    "RESUME_ARGUMENT_MISMATCH",
			Message: fmt.Sprintf("stored semantic hash %s, request hash %s", stored.SemanticHash, hash),
		}
	}
	return nil
}

func ValidateApprovedRevision(plan RevisionedPlan, revision string) error {
	if strings.TrimSpace(revision) != plan.Revision {
		return &DomainError{
			Code:    "PLAN_REVISION_MISMATCH",
			Message: fmt.Sprintf("approved revision %q does not match current revision %q", revision, plan.Revision),
		}
	}
	return nil
}

type OrchestratorCreateRequest struct {
	OperationID              string
	PhysicalHostID           string
	HostNode                 string
	DisplayName              string
	ProfileName              string
	MainVSwitch              string
	OrchestratorID           OrchestratorID
	ProjectedStorageBytes    int64
	ExistingReservedMemoryMB int
	ServerVersion            string
	PostFenceTimeout         time.Duration
	Progress                 func(string, string)
}

type OrchestratorCreatePlan struct {
	Plan      RevisionedPlan
	Names     OrchestratorPhysicalNames
	Lease     HostFenceLease
	Preflight ResourcePreflightResult
	Reused    *SelectionResult
}

func (d OrchestratorDomain) PlanCreateOrReuse(
	ctx context.Context,
	request OrchestratorCreateRequest,
) (OrchestratorCreatePlan, error) {
	if d.State == nil || d.Probe == nil || d.Host == nil {
		return OrchestratorCreatePlan{}, errors.New("isolated: state, probe, and host planning clients are required")
	}
	if _, err := ParseOperationID(request.OperationID); err != nil {
		return OrchestratorCreatePlan{}, err
	}
	if err := request.OrchestratorID.Validate(); err != nil {
		return OrchestratorCreatePlan{}, err
	}
	lockKey, err := hyperv.HostOrchestratorCreateLockKey(request.PhysicalHostID)
	if err != nil {
		return OrchestratorCreatePlan{}, err
	}
	fenceRequest := HostCreateFenceRequest{
		PhysicalHostID: request.PhysicalHostID,
		HostNode:       request.HostNode,
		OperationID:    request.OperationID,
		LockKey:        lockKey,
	}
	lease, err := d.Host.AcquireOrchestratorCreateFence(ctx, fenceRequest)
	if err != nil {
		return OrchestratorCreatePlan{}, err
	}
	leaseTransferred := false
	defer func() {
		if !leaseTransferred {
			releaseCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			_ = d.Host.ReleaseOrchestratorCreateFence(releaseCtx, fenceRequest, lease)
		}
	}()
	if err := lease.Validate(lockKey); err != nil {
		return OrchestratorCreatePlan{}, err
	}

	postFenceTimeout := request.PostFenceTimeout
	if postFenceTimeout <= 0 {
		postFenceTimeout = 60 * time.Second
	}
	postFenceCtx, cancelPostFence := context.WithTimeout(ctx, postFenceTimeout)
	defer cancelPostFence()
	report := func(phase, detail string) {
		if request.Progress != nil {
			request.Progress(phase, detail)
		}
	}
	timeoutError := func(stage string, err error) error {
		if errors.Is(postFenceCtx.Err(), context.DeadlineExceeded) &&
			!errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return &DomainError{
				Code: "POST_FENCE_CAPACITY_TIMEOUT",
				Message: fmt.Sprintf(
					"post-fence %s exceeded %s for operation %s at fence %d",
					stage, postFenceTimeout, request.OperationID, lease.Fence,
				),
			}
		}
		return err
	}

	report("host_fence_acquired", fmt.Sprintf(
		"remote host fence %d acquired; reconciling deleted metadata", lease.Fence))
	existingAfterFence, err := d.State.ListOrchestrators(postFenceCtx, request.PhysicalHostID)
	if err != nil {
		return OrchestratorCreatePlan{}, timeoutError("durable inventory read", err)
	}
	for _, record := range existingAfterFence {
		if record.PhysicalHostID != request.PhysicalHostID ||
			(record.LifecycleState != isolatedstate.OrchestratorDeleted &&
				record.LifecycleState != isolatedstate.OrchestratorLost) ||
			record.HyperVVMID == nil {
			continue
		}
		report("stale_metadata_reconcile", "checking exact deleted orchestrator metadata "+record.ID)
		if err := d.Host.ReconcileStaleOrchestratorMetadata(
			postFenceCtx,
			StaleOrchestratorMetadataRequest{
				PhysicalHostID: request.PhysicalHostID, HostNode: request.HostNode,
				OperationID: request.OperationID, OrchestratorID: record.ID,
				HyperVName: record.HyperVName, OrchestratorVMID: *record.HyperVVMID,
				LifecycleState: string(record.LifecycleState), Lease: lease,
			},
		); err != nil {
			return OrchestratorCreatePlan{}, timeoutError("stale metadata reconciliation", err)
		}
	}

	report("capacity_discovery", "host fence acquired; checking reusable orchestrator capacity")
	selection, selectErr := d.Select(postFenceCtx, SelectionRequest{
		PhysicalHostID: request.PhysicalHostID,
		Operation:      OperationAddNetwork,
		ServerVersion:  request.ServerVersion,
	})
	if selectErr == nil {
		leaseTransferred = true
		return OrchestratorCreatePlan{Lease: lease, Reused: &selection}, nil
	}
	if ErrorCode(selectErr) != "NO_USABLE_ORCHESTRATOR" {
		return OrchestratorCreatePlan{}, timeoutError("reusable orchestrator discovery", selectErr)
	}
	activeExisting := 0
	for _, record := range existingAfterFence {
		if record.LifecycleState != isolatedstate.OrchestratorDeleted &&
			record.LifecycleState != isolatedstate.OrchestratorLost {
			activeExisting++
		}
	}
	preflightInput := ResourcePreflightInput{
		PhysicalHostID:              request.PhysicalHostID,
		HostNode:                    request.HostNode,
		MainVSwitch:                 request.MainVSwitch,
		ProfileName:                 request.ProfileName,
		ProjectedMemoryMB:           8192,
		ProjectedStorageBytes:       request.ProjectedStorageBytes,
		ExistingOrchestratorCount:   activeExisting,
		AggregateReservedMemoryMB:   request.ExistingReservedMemoryMB,
		RequiredPrivateAdapterSlots: 1,
		RequiredSwitchSlots:         1,
		RequiredFreeSubnets:         1,
		RequiredRelayPorts:          0,
		RequiredGuestSlots:          0,
	}
	report("capacity_preflight", "no reusable orchestrator found; checking bounded host capacity")
	preflight, err := d.Host.PreflightOrchestrator(postFenceCtx, preflightInput)
	if err != nil {
		return OrchestratorCreatePlan{}, timeoutError("resource preflight", err)
	}
	if !preflight.Allowed {
		return OrchestratorCreatePlan{}, &DomainError{
			Code:    "RESOURCE_PREFLIGHT_FAILED",
			Message: preflight.Reason,
		}
	}
	names, err := OrchestratorNames(request.OrchestratorID)
	if err != nil {
		return OrchestratorCreatePlan{}, err
	}
	inputs := map[string]any{
		"physical_host_id":          request.PhysicalHostID,
		"host_node":                 request.HostNode,
		"orchestrator_id":           request.OrchestratorID.String(),
		"display_name":              request.DisplayName,
		"hyperv_name":               names.HyperVName,
		"node_name":                 names.NodeName,
		"profile_name":              request.ProfileName,
		"main_vswitch":              request.MainVSwitch,
		"vcpu":                      4,
		"memory_mb":                 8192,
		"projected_storage_bytes":   request.ProjectedStorageBytes,
		"required_appliance_schema": MinimumApplianceSchema,
	}
	actions := []PlanAction{
		{Phase: "create_linux_vm", Action: "create", ResourceType: "orchestrator", ResourceID: request.OrchestratorID.String(), ExpectedGeneration: 0, NewGeneration: 1},
		{Phase: "verify_host_identity", Action: "verify", ResourceType: "orchestrator", ResourceID: request.OrchestratorID.String(), ExpectedGeneration: 1, NewGeneration: 1},
		{Phase: "verify_mtls", Action: "verify", ResourceType: "orchestrator", ResourceID: request.OrchestratorID.String(), ExpectedGeneration: 1, NewGeneration: 1},
		{Phase: "verify_capabilities", Action: "verify", ResourceType: "orchestrator", ResourceID: request.OrchestratorID.String(), ExpectedGeneration: 1, NewGeneration: 1},
		{Phase: "configure_appliance", Action: "configure", ResourceType: "orchestrator", ResourceID: request.OrchestratorID.String(), ExpectedGeneration: 0, NewGeneration: 1},
	}
	plan, err := newRevisionedPlan(
		"create_isolated_orchestrator", request.OperationID,
		request.OrchestratorID.String(), inputs, actions,
	)
	if err != nil {
		return OrchestratorCreatePlan{}, err
	}
	leaseTransferred = true
	return OrchestratorCreatePlan{
		Plan: plan, Names: names, Lease: lease, Preflight: preflight,
	}, nil
}

type ReconcileOrchestratorRequest struct {
	OperationID        string
	Orchestrator       isolatedstate.Orchestrator
	RefreshDNS         bool
	RepairRegistry     bool
	ExpectedGeneration isolatedstate.Generation
}

func BuildOrchestratorReconcilePlan(request ReconcileOrchestratorRequest) (RevisionedPlan, error) {
	if request.Orchestrator.DesiredGeneration != request.ExpectedGeneration {
		return RevisionedPlan{}, staleGenerationError(
			int64(request.ExpectedGeneration), int64(request.Orchestrator.DesiredGeneration),
		)
	}
	newGeneration := request.ExpectedGeneration + 1
	inputs := map[string]any{
		"orchestrator_id":  request.Orchestrator.ID,
		"physical_host_id": request.Orchestrator.PhysicalHostID,
		"hyperv_vm_id":     nullableString(request.Orchestrator.HyperVVMID),
		"refresh_dns":      request.RefreshDNS,
		"repair_registry":  request.RepairRegistry,
		"semantic_action":  "reconcile",
	}
	actions := []PlanAction{{
		Phase: "reconcile", Action: "reconcile", ResourceType: "orchestrator",
		ResourceID:         request.Orchestrator.ID,
		ExpectedIdentity:   nullableString(request.Orchestrator.HyperVVMID),
		ExpectedGeneration: int64(request.ExpectedGeneration),
		NewGeneration:      int64(newGeneration),
	}}
	return newRevisionedPlan(
		"reconcile_isolated_orchestrator", request.OperationID,
		request.Orchestrator.ID, inputs, actions,
	)
}

type CascadeChild struct {
	ResourceType              string
	ResourceID                string
	Action                    cascadeauth.Action
	ExpectedHostIdentity      string
	ExpectedApplianceIdentity string
	ExpectedGeneration        isolatedstate.Generation
	ExpectedIncarnation       isolatedstate.Incarnation
	ExpectedImmutableIdentity string
}

type DeleteOrchestratorRequest struct {
	OperationID        string
	Orchestrator       isolatedstate.Orchestrator
	Cascade            bool
	Children           []CascadeChild
	ExpectedGeneration isolatedstate.Generation
}

type DeleteOrchestratorPlan struct {
	Plan      RevisionedPlan
	Authority isolatedstate.CascadeAuthority
}

func BuildOrchestratorDeletePlan(request DeleteOrchestratorRequest) (DeleteOrchestratorPlan, error) {
	if request.Orchestrator.DesiredGeneration != request.ExpectedGeneration {
		return DeleteOrchestratorPlan{}, staleGenerationError(
			int64(request.ExpectedGeneration), int64(request.Orchestrator.DesiredGeneration),
		)
	}
	if len(request.Children) > 0 && !request.Cascade {
		return DeleteOrchestratorPlan{}, &DomainError{
			Code:    "ORCHESTRATOR_NOT_EMPTY",
			Message: "cascade=false while non-deleted child resources remain",
		}
	}
	children := append([]CascadeChild(nil), request.Children...)
	sort.Slice(children, func(i, j int) bool {
		if children[i].ResourceType == children[j].ResourceType {
			return children[i].ResourceID < children[j].ResourceID
		}
		return children[i].ResourceType < children[j].ResourceType
	})
	inputChildren := make([]map[string]any, 0, len(children))
	actions := make([]PlanAction, 0, len(children)+2)
	authorityItems := make([]isolatedstate.CascadeAuthorityItem, 0, len(children))
	frozenGeneration := request.ExpectedGeneration + 1
	actions = append(actions, PlanAction{
		Phase: "freeze", Action: "freeze", ResourceType: "orchestrator",
		ResourceID:         request.Orchestrator.ID,
		ExpectedIdentity:   nullableString(request.Orchestrator.HyperVVMID),
		ExpectedGeneration: int64(request.ExpectedGeneration),
		NewGeneration:      int64(frozenGeneration),
	})
	for index, child := range children {
		if err := cascadeauth.ValidateScope(child.ResourceType, child.Action); err != nil {
			return DeleteOrchestratorPlan{}, err
		}
		phase := fmt.Sprintf("cascade_%03d_%s", index, child.Action)
		mutationID := isolatedstate.StableMutationID(
			request.OperationID, child.ResourceID, string(child.Action), phase,
		)
		inputChildren = append(inputChildren, map[string]any{
			"resource_type":      child.ResourceType,
			"resource_id":        child.ResourceID,
			"action":             child.Action,
			"host_identity":      child.ExpectedHostIdentity,
			"appliance_identity": child.ExpectedApplianceIdentity,
			"generation":         child.ExpectedGeneration,
			"incarnation":        child.ExpectedIncarnation,
			"immutable_identity": child.ExpectedImmutableIdentity,
		})
		actions = append(actions, PlanAction{
			Phase: phase, Action: string(child.Action), ResourceType: child.ResourceType,
			ResourceID: child.ResourceID, ExpectedIdentity: child.ExpectedHostIdentity,
			ExpectedGeneration: int64(child.ExpectedGeneration),
			NewGeneration:      int64(child.ExpectedGeneration + 1),
		})
		hostIdentity := optionalString(child.ExpectedHostIdentity)
		applianceIdentity := optionalString(child.ExpectedApplianceIdentity)
		operations, err := cascadeauth.OperationsForResource(child.ResourceType)
		if err != nil {
			return DeleteOrchestratorPlan{}, err
		}
		for _, operation := range operations {
			action := operation.Action
			itemMutationID := mutationID
			if action != child.Action {
				itemMutationID = isolatedstate.StableMutationID(
					request.OperationID, child.ResourceID, string(action), phase+"_"+string(action))
			}
			authorityItems = append(authorityItems, isolatedstate.CascadeAuthorityItem{
				MutationID: itemMutationID, Action: string(action),
				ResourceType: operation.ResourceType, ResourceID: child.ResourceID,
				ExpectedHostIdentity:      hostIdentity,
				ExpectedApplianceIdentity: applianceIdentity,
				ExpectedGeneration: cascadeAuthorityExpectedGeneration(
					child.ExpectedGeneration, action),
			})
		}
	}

	for _, operation := range cascadeauth.OrchestratorOperations() {
		authorityItems = append(authorityItems, isolatedstate.CascadeAuthorityItem{
			MutationID: isolatedstate.StableMutationID(
				request.OperationID, request.Orchestrator.ID,
				string(operation.Action), "cascade_"+string(operation.Action)),
			Action: string(operation.Action), ResourceType: operation.ResourceType,
			ResourceID: request.Orchestrator.ID, ExpectedGeneration: frozenGeneration,
		})
	}
	actions = append(actions, PlanAction{
		Phase: "delete_orchestrator", Action: string(cascadeauth.ActionOrchestratorVMDelete), ResourceType: "orchestrator",
		ResourceID:         request.Orchestrator.ID,
		ExpectedIdentity:   nullableString(request.Orchestrator.HyperVVMID),
		ExpectedGeneration: int64(frozenGeneration),
		NewGeneration:      int64(frozenGeneration + 1),
	})
	inputs := map[string]any{
		"orchestrator_id":  request.Orchestrator.ID,
		"physical_host_id": request.Orchestrator.PhysicalHostID,
		"hyperv_vm_id":     nullableString(request.Orchestrator.HyperVVMID),
		"cascade":          request.Cascade,
		"children":         inputChildren,
	}
	plan, err := newRevisionedPlan(
		"delete_isolated_orchestrator", request.OperationID,
		request.Orchestrator.ID, inputs, actions,
	)
	if err != nil {
		return DeleteOrchestratorPlan{}, err
	}
	return DeleteOrchestratorPlan{
		Plan: plan,
		Authority: isolatedstate.CascadeAuthority{
			OrchestratorID:   request.Orchestrator.ID,
			FrozenGeneration: frozenGeneration,
			OperationID:      request.OperationID,
			PlanRevision:     plan.Revision,
			PlanHash:         plan.PlanHash,
			HostFence:        request.Orchestrator.HostFence,
			Items:            authorityItems,
		},
	}, nil
}

// RestoreApprovedOrchestratorDeletePlan reconstructs the immutable cascade
// authority from the stored approved plan without replanning against the
// post-freeze parent generation.
func RestoreApprovedOrchestratorDeletePlan(
	plan RevisionedPlan,
	hostFence int64,
) (DeleteOrchestratorPlan, error) {
	if plan.Kind != "delete_isolated_orchestrator" {
		return DeleteOrchestratorPlan{}, errors.New("approved plan is not an orchestrator deletion")
	}
	var inputs struct {
		OrchestratorID string `json:"orchestrator_id"`
		Children       []struct {
			ResourceType              string                    `json:"resource_type"`
			ResourceID                string                    `json:"resource_id"`
			Action                    cascadeauth.Action        `json:"action"`
			ExpectedHostIdentity      string                    `json:"host_identity"`
			ExpectedApplianceIdentity string                    `json:"appliance_identity"`
			ExpectedGeneration        isolatedstate.Generation  `json:"generation"`
			ExpectedIncarnation       isolatedstate.Incarnation `json:"incarnation"`
			ExpectedImmutableIdentity string                    `json:"immutable_identity"`
		} `json:"children"`
	}
	raw, err := json.Marshal(plan.Inputs)
	if err != nil {
		return DeleteOrchestratorPlan{}, err
	}
	if err := json.Unmarshal(raw, &inputs); err != nil {
		return DeleteOrchestratorPlan{}, err
	}
	if inputs.OrchestratorID == "" || plan.OperationID == "" ||
		plan.Revision == "" || plan.PlanHash == "" {
		return DeleteOrchestratorPlan{}, errors.New("approved deletion plan identity is incomplete")
	}
	var frozenGeneration isolatedstate.Generation
	for _, action := range plan.Actions {
		if action.Phase == "freeze" && action.ResourceType == "orchestrator" &&
			action.ResourceID == inputs.OrchestratorID {
			frozenGeneration = isolatedstate.Generation(action.NewGeneration)
			break
		}
	}
	if frozenGeneration <= 0 {
		return DeleteOrchestratorPlan{}, errors.New("approved deletion plan has no valid freeze action")
	}
	items := make([]isolatedstate.CascadeAuthorityItem, 0, len(inputs.Children))
	for index, child := range inputs.Children {
		if err := cascadeauth.ValidateScope(child.ResourceType, child.Action); err != nil {
			return DeleteOrchestratorPlan{}, err
		}
		phase := fmt.Sprintf("cascade_%03d_%s", index, child.Action)
		operations, err := cascadeauth.OperationsForResource(child.ResourceType)
		if err != nil {
			return DeleteOrchestratorPlan{}, err
		}
		for _, operation := range operations {
			action := operation.Action
			itemMutationID := isolatedstate.StableMutationID(
				plan.OperationID, child.ResourceID, string(child.Action), phase)
			if action != child.Action {
				itemMutationID = isolatedstate.StableMutationID(
					plan.OperationID, child.ResourceID, string(action), phase+"_"+string(action))
			}
			items = append(items, isolatedstate.CascadeAuthorityItem{
				MutationID: itemMutationID, Action: string(action),
				ResourceType: operation.ResourceType, ResourceID: child.ResourceID,
				ExpectedHostIdentity:      optionalString(child.ExpectedHostIdentity),
				ExpectedApplianceIdentity: optionalString(child.ExpectedApplianceIdentity),
				ExpectedGeneration: cascadeAuthorityExpectedGeneration(
					child.ExpectedGeneration, action),
			})
		}
	}
	for _, operation := range cascadeauth.OrchestratorOperations() {
		items = append(items, isolatedstate.CascadeAuthorityItem{
			MutationID: isolatedstate.StableMutationID(
				plan.OperationID, inputs.OrchestratorID,
				string(operation.Action), "cascade_"+string(operation.Action)),
			Action: string(operation.Action), ResourceType: operation.ResourceType,
			ResourceID: inputs.OrchestratorID, ExpectedGeneration: frozenGeneration,
		})
	}
	return DeleteOrchestratorPlan{
		Plan: plan,
		Authority: isolatedstate.CascadeAuthority{
			OrchestratorID: inputs.OrchestratorID, FrozenGeneration: frozenGeneration,
			OperationID: plan.OperationID, PlanRevision: plan.Revision,
			PlanHash: plan.PlanHash, HostFence: hostFence, Items: items,
		},
	}, nil
}

func cascadeAuthorityExpectedGeneration(
	generation isolatedstate.Generation,
	action cascadeauth.Action,
) isolatedstate.Generation {
	if action == cascadeauth.ActionGuestReleaseResources {
		return 0
	}
	return generation
}

func ValidateCascadeResume(
	stored DeleteOrchestratorPlan,
	operationID, revision string,
	currentChildren []CascadeChild,
) error {
	if stored.Plan.OperationID != strings.ToLower(strings.TrimSpace(operationID)) {
		return &DomainError{Code: "CASCADE_OPERATION_MISMATCH", Message: "operation ID changed"}
	}
	if revision != stored.Plan.Revision {
		return &DomainError{Code: "CASCADE_REVISION_MISMATCH", Message: "approved cascade revision changed"}
	}
	replanned, err := BuildOrchestratorDeletePlan(DeleteOrchestratorRequest{
		OperationID: operationID,
		Orchestrator: isolatedstate.Orchestrator{
			ID:                stored.Authority.OrchestratorID,
			PhysicalHostID:    stringInput(stored.Plan.Inputs, "physical_host_id"),
			HyperVVMID:        optionalString(stringInput(stored.Plan.Inputs, "hyperv_vm_id")),
			DesiredGeneration: stored.Authority.FrozenGeneration - 1,
			HostFence:         stored.Authority.HostFence,
		},
		Cascade:            true,
		Children:           currentChildren,
		ExpectedGeneration: stored.Authority.FrozenGeneration - 1,
	})
	if err != nil {
		return err
	}
	if replanned.Plan.PlanHash != stored.Plan.PlanHash {
		return &DomainError{
			Code:    "CASCADE_INVENTORY_CHANGED",
			Message: "child enumeration, identity, action, or generation changed; create a new revision",
		}
	}
	return nil
}

type ServerCacheImport struct {
	OrchestratorID      string
	ApplianceSchema     int
	InventoryGeneration uint64
	ParentGeneration    uint64
	Networks            []appliance.Network
	Guests              []appliance.Guest
	Relays              []appliance.Relay
	NAT                 []appliance.NATState
	Reservations        []appliance.Reservation
}

func (d OrchestratorDomain) ImportServerCache(ctx context.Context, orchestratorID string) (ServerCacheImport, error) {
	if d.State == nil || d.Appliance == nil {
		return ServerCacheImport{}, errors.New("isolated: state and appliance clients are required")
	}
	snapshot, err := d.Appliance.GetApplianceState(ctx, orchestratorID)
	if err != nil {
		return ServerCacheImport{}, err
	}
	result := ServerCacheImport{
		OrchestratorID:      orchestratorID,
		ApplianceSchema:     MinimumApplianceSchema,
		InventoryGeneration: snapshot.Status.InventoryGeneration,
		ParentGeneration:    snapshot.Authority.ParentGeneration,
		Networks:            append([]appliance.Network(nil), snapshot.Networks...),
		Guests:              append([]appliance.Guest(nil), snapshot.Guests...),
		Relays:              append([]appliance.Relay(nil), snapshot.Relays...),
		NAT:                 append([]appliance.NATState(nil), snapshot.NAT...),
		Reservations:        append([]appliance.Reservation(nil), snapshot.Reservations...),
	}
	if err := d.State.ImportApplianceCache(ctx, result); err != nil {
		return ServerCacheImport{}, err
	}
	return result, nil
}

func staleGenerationError(expected, current int64) error {
	return &DomainError{
		Code:    "GENERATION_CONFLICT",
		Message: fmt.Sprintf("expected generation %d, current desired generation is %d", expected, current),
	}
}

func nullableString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func optionalString(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

func stringInput(inputs map[string]any, key string) string {
	value, _ := inputs[key].(string)
	return value
}
