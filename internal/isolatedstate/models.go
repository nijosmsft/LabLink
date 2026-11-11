// Package isolatedstate owns the durable server-side state for isolated VM
// orchestration. Display names are mutable labels; IDs and infrastructure
// identity fields are the durable identities used for reconciliation.
package isolatedstate

type Generation int64
type Incarnation int64
type UnixSeconds int64

type OrchestratorLifecycleState string
type NetworkLifecycleState string
type VMLifecycleState string
type RelayLifecycleState string
type NATDesiredState string
type NATObservedState string
type OperationStatus string
type OperationPhaseStatus string
type ApprovalPlanState string
type GuestOS string

const (
	OrchestratorPlanned     OrchestratorLifecycleState = "planned"
	OrchestratorCreating    OrchestratorLifecycleState = "creating"
	OrchestratorCustomizing OrchestratorLifecycleState = "customizing"
	OrchestratorReady       OrchestratorLifecycleState = "ready"
	OrchestratorRecovering  OrchestratorLifecycleState = "recovering"
	OrchestratorDegraded    OrchestratorLifecycleState = "degraded"
	OrchestratorFrozen      OrchestratorLifecycleState = "frozen"
	OrchestratorDeleting    OrchestratorLifecycleState = "deleting"
	OrchestratorLost        OrchestratorLifecycleState = "lost"
	OrchestratorDeleted     OrchestratorLifecycleState = "deleted"
)

const (
	NetworkAllocating NetworkLifecycleState = "allocating"
	NetworkCreating   NetworkLifecycleState = "creating"
	NetworkReady      NetworkLifecycleState = "ready"
	NetworkDegraded   NetworkLifecycleState = "degraded"
	NetworkDeleting   NetworkLifecycleState = "deleting"
	NetworkDeleted    NetworkLifecycleState = "deleted"
)

const (
	VMAllocating   VMLifecycleState = "allocating"
	VMCreating     VMLifecycleState = "creating"
	VMProvisioning VMLifecycleState = "provisioning"
	VMReady        VMLifecycleState = "ready"
	VMRepairing    VMLifecycleState = "repairing"
	VMDegraded     VMLifecycleState = "degraded"
	VMDeleting     VMLifecycleState = "deleting"
	VMDeleted      VMLifecycleState = "deleted"
)

const (
	RelayAllocated RelayLifecycleState = "allocated"
	RelayBinding   RelayLifecycleState = "binding"
	RelayReady     RelayLifecycleState = "ready"
	RelayDegraded  RelayLifecycleState = "degraded"
	RelayRetiring  RelayLifecycleState = "retiring"
	RelayRemoving  RelayLifecycleState = "removing"
	RelayRemoved   RelayLifecycleState = "removed"
)

const (
	NATDesiredEnabled  NATDesiredState = "enabled"
	NATDesiredDisabled NATDesiredState = "disabled"

	NATObservedEnabled  NATObservedState = "enabled"
	NATObservedDraining NATObservedState = "draining"
	NATObservedDisabled NATObservedState = "disabled"
)

const (
	OperationPlanned          OperationStatus = "planned"
	OperationApprovalRequired OperationStatus = "approval_required"
	OperationRunning          OperationStatus = "running"
	OperationPaused           OperationStatus = "paused"
	OperationSucceeded        OperationStatus = "succeeded"
	OperationFailed           OperationStatus = "failed"
	OperationCancelled        OperationStatus = "cancelled"
)

const (
	PhasePending   OperationPhaseStatus = "pending"
	PhaseRunning   OperationPhaseStatus = "running"
	PhaseSucceeded OperationPhaseStatus = "succeeded"
	PhaseFailed    OperationPhaseStatus = "failed"
	PhaseSkipped   OperationPhaseStatus = "skipped"
)

const (
	ApprovalPending    ApprovalPlanState = "pending"
	ApprovalApproved   ApprovalPlanState = "approved"
	ApprovalConsumed   ApprovalPlanState = "consumed"
	ApprovalSuperseded ApprovalPlanState = "superseded"
)

const (
	GuestWindows GuestOS = "windows"
	GuestLinux   GuestOS = "linux"
)

type SchemaMeta struct {
	Key   string
	Value string
}

type Orchestrator struct {
	ID                 string
	DisplayName        string
	PhysicalHostID     string
	HostNode           string
	HyperVName         string
	HyperVVMID         *string
	NodeName           string
	ProfileName        string
	MainVSwitch        string
	MainMAC            *string
	MainIP             *string
	AgentPort          int
	ApplianceSchema    int
	DesiredGeneration  Generation
	AppliedGeneration  Generation
	ObservedGeneration Generation
	HostFence          int64
	LifecycleState     OrchestratorLifecycleState
	HealthState        string
	MaxNetworks        int
	MaxVMs             int
	CreatedAt          UnixSeconds
	UpdatedAt          UnixSeconds
	LastSeenAt         *UnixSeconds
}

type PrivateNetwork struct {
	ID                    string
	OrchestratorID        string
	DisplayName           string
	HyperVSwitchName      string
	HyperVSwitchGUID      *string
	OrchestratorAdapterID *string
	SubnetIndex           int
	CIDR                  string
	GatewayIPv4           string
	OrchestratorMAC       string
	DNSServersJSON        string
	DesiredGeneration     Generation
	AppliedGeneration     Generation
	ObservedGeneration    Generation
	LifecycleState        NetworkLifecycleState
	CreatedAt             UnixSeconds
	UpdatedAt             UnixSeconds
	RetiredAt             *UnixSeconds
}

type IsolatedVM struct {
	ID                 string
	OrchestratorID     string
	NetworkID          string
	DisplayName        string
	HyperVName         string
	HyperVVMID         *string
	HyperVAdapterID    *string
	Incarnation        Incarnation
	NodeName           string
	GuestOS            GuestOS
	ProfileName        string
	IPv4               string
	MAC                string
	PrefixLength       int
	GatewayIPv4        string
	DNSServersJSON     string
	StorageRoot        string
	VMPath             string
	VHDPath            string
	DesiredGeneration  Generation
	AppliedGeneration  Generation
	ObservedGeneration Generation
	LifecycleState     VMLifecycleState
	CreatedAt          UnixSeconds
	UpdatedAt          UnixSeconds
	RetiredAt          *UnixSeconds
}

type RelayAllocation struct {
	ID                 string
	VMID               string
	OrchestratorID     string
	ListenPort         int
	TargetIPv4         string
	TargetPort         int
	DesiredGeneration  Generation
	AppliedGeneration  Generation
	ObservedGeneration Generation
	LifecycleState     RelayLifecycleState
	CreatedAt          UnixSeconds
	UpdatedAt          UnixSeconds
	RetiredAt          *UnixSeconds
}

type NATAllocation struct {
	VMID               string
	OrchestratorID     string
	DesiredState       NATDesiredState
	ObservedState      NATObservedState
	ConntrackMark      int64
	DesiredGeneration  Generation
	AppliedGeneration  Generation
	ObservedGeneration Generation
	DrainStartedAt     *UnixSeconds
	UpdatedAt          UnixSeconds
}

type ActiveResourceAllocation struct {
	Kind                   string
	ScopeID                string
	Value                  string
	ResourceID             string
	ApplianceReservationID string
	AllocatedAt            UnixSeconds
}

type ResourceAllocationHistory struct {
	Sequence               int64
	Kind                   string
	ScopeID                string
	Value                  string
	ResourceID             string
	ApplianceReservationID string
	AllocatedAt            UnixSeconds
	ReleasedAt             UnixSeconds
	ReleaseOperationID     string
}

type GuestPendingUpdate struct {
	VMID              string
	UpdateKind        string
	DesiredGeneration Generation
	PayloadJSON       string
	CreatedAt         UnixSeconds
	LastAttemptAt     *UnixSeconds
	LastError         *string
}

type Operation struct {
	ID             string
	Kind           string
	ResourceType   string
	ResourceID     string
	HostNode       *string
	OrchestratorID *string
	NetworkID      *string
	ArgumentHash   string
	RequestJSON    string
	PlanRevision   *string
	Status         OperationStatus
	CurrentPhase   string
	ResultJSON     *string
	ErrorCode      *string
	ErrorText      *string
	CreatedAt      UnixSeconds
	UpdatedAt      UnixSeconds
	FinishedAt     *UnixSeconds
}

type OperationPhase struct {
	OperationID string
	PhaseIndex  int
	PhaseName   string
	Generation  *Generation
	Status      OperationPhaseStatus
	Attempt     int
	StartedAt   *UnixSeconds
	FinishedAt  *UnixSeconds
	DetailJSON  *string
	ErrorText   *string
}

type OperationEvent struct {
	Sequence    int64
	OperationID string
	At          UnixSeconds
	PhaseName   *string
	Level       string
	Message     string
	DetailJSON  *string
}

type ApprovalPlan struct {
	Revision    string
	OperationID string
	Action      string
	PlanJSON    string
	PlanHash    string
	State       ApprovalPlanState
	ApprovedAt  *UnixSeconds
	ConsumedAt  *UnixSeconds
}

type Lock struct {
	LockKey            string
	HolderCookie       string
	HolderHostname     string
	HolderPID          int
	HolderProcessStart UnixSeconds
	OperationID        string
	Fence              int64
	AcquiredAt         UnixSeconds
	HeartbeatAt        UnixSeconds
	ExpiresAt          UnixSeconds
}

// ApplianceImportMetadata is the local projection used while importing the
// appliance-authoritative generation into an orchestrator row.
type ApplianceImportMetadata struct {
	OrchestratorID     string
	ApplianceSchema    int
	AppliedGeneration  Generation
	ObservedGeneration Generation
	LastConfirmedAt    *UnixSeconds
}
