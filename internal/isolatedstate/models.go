package isolatedstate

type UnixSeconds int64

type OrchestratorLifecycleState string
type NetworkLifecycleState string
type VMLifecycleState string
type RelayLifecycleState string
type NATState string
type GuestOS string

const (
	OrchestratorCreating OrchestratorLifecycleState = "creating"
	OrchestratorReady    OrchestratorLifecycleState = "ready"
	OrchestratorDegraded OrchestratorLifecycleState = "degraded"
	OrchestratorDeleting OrchestratorLifecycleState = "deleting"
	OrchestratorDeleted  OrchestratorLifecycleState = "deleted"
)

const (
	NetworkCreating NetworkLifecycleState = "creating"
	NetworkReady    NetworkLifecycleState = "ready"
	NetworkDegraded NetworkLifecycleState = "degraded"
	NetworkDeleting NetworkLifecycleState = "deleting"
	NetworkDeleted  NetworkLifecycleState = "deleted"
)

const (
	VMCreating     VMLifecycleState = "creating"
	VMProvisioning VMLifecycleState = "provisioning"
	VMReady        VMLifecycleState = "ready"
	VMDegraded     VMLifecycleState = "degraded"
	VMDeleting     VMLifecycleState = "deleting"
	VMDeleted      VMLifecycleState = "deleted"
)

const (
	RelayReady    RelayLifecycleState = "ready"
	RelayDegraded RelayLifecycleState = "degraded"
	RelayRemoving RelayLifecycleState = "removing"
	RelayRemoved  RelayLifecycleState = "removed"
)

const (
	NATEnabled  NATState = "enabled"
	NATDisabled NATState = "disabled"
)

const (
	GuestWindows GuestOS = "windows"
	GuestLinux   GuestOS = "linux"
)

type Orchestrator struct {
	ID              string
	DisplayName     string
	PhysicalHostID  string
	HostNode        string
	HyperVName      string
	HyperVVMID      *string
	NodeName        string
	ProfileName     string
	MainVSwitch     string
	MainMAC         *string
	MainIP          *string
	AgentPort       int
	ApplianceSchema int
	LifecycleState  OrchestratorLifecycleState
	HealthState     string
	MaxNetworks     int
	MaxVMs          int
	CreatedAt       UnixSeconds
	UpdatedAt       UnixSeconds
	LastSeenAt      *UnixSeconds
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
	LifecycleState        NetworkLifecycleState
	CreatedAt             UnixSeconds
	UpdatedAt             UnixSeconds
	RetiredAt             *UnixSeconds
}

type IsolatedVM struct {
	ID              string
	OrchestratorID  string
	NetworkID       string
	DisplayName     string
	HyperVName      string
	HyperVVMID      *string
	HyperVAdapterID *string
	NodeName        string
	GuestOS         GuestOS
	ProfileName     string
	IPv4            string
	MAC             string
	PrefixLength    int
	GatewayIPv4     string
	DNSServersJSON  string
	StorageRoot     string
	VMPath          string
	VHDPath         string
	LifecycleState  VMLifecycleState
	CreatedAt       UnixSeconds
	UpdatedAt       UnixSeconds
	RetiredAt       *UnixSeconds
}

type RelayAllocation struct {
	ID             string
	VMID           string
	OrchestratorID string
	ListenPort     int
	TargetIPv4     string
	TargetPort     int
	LifecycleState RelayLifecycleState
	CreatedAt      UnixSeconds
	UpdatedAt      UnixSeconds
	RetiredAt      *UnixSeconds
}

type NATAllocation struct {
	VMID           string
	OrchestratorID string
	State          NATState
	ConntrackMark  int64
	UpdatedAt      UnixSeconds
}
