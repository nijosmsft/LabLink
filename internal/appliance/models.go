package appliance

import (
	"encoding/json"
	"errors"
	"fmt"
)

const (
	DefaultDBPath        = "/var/lib/lablink-agent/isolated-appliance.db"
	CurrentSchemaVersion = 1
	RelayTargetPort      = 9091
)

type ErrorCode string

const (
	CodeSubnetInUse        ErrorCode = "SUBNET_IN_USE"
	CodeIPInUse            ErrorCode = "IP_IN_USE"
	CodeMACInUse           ErrorCode = "MAC_IN_USE"
	CodePortInUse          ErrorCode = "PORT_IN_USE"
	CodeConntrackMarkInUse ErrorCode = "CONNTRACK_MARK_IN_USE"
	CodeCapacityExhausted  ErrorCode = "CAPACITY_EXHAUSTED"
	CodeResourceInUse      ErrorCode = "RESOURCE_IN_USE"
	CodeGenerationConflict ErrorCode = "GENERATION_CONFLICT"
	CodeParentGeneration   ErrorCode = "PARENT_GENERATION_CONFLICT"
	CodeFenceRejected      ErrorCode = "FENCE_REJECTED"
	CodeParentFrozen       ErrorCode = "PARENT_FROZEN"
	CodeResumeMismatch     ErrorCode = "RESUME_ARGUMENT_MISMATCH"
	CodeIntentPending      ErrorCode = "INTENT_PENDING"
	CodeReservationLost    ErrorCode = "RESERVATION_LOST"
	CodeNotFound           ErrorCode = "NOT_FOUND"
	CodeInvalidArgument    ErrorCode = "INVALID_ARGUMENT"
	CodeUnsupportedSchema  ErrorCode = "UNSUPPORTED_SCHEMA"
)

type StoreError struct {
	Code    ErrorCode
	Message string
}

func (e *StoreError) Error() string {
	if e.Message == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func ErrorCodeOf(err error) ErrorCode {
	var storeErr *StoreError
	if errors.As(err, &storeErr) {
		return storeErr.Code
	}
	var collision *CollisionError
	if errors.As(err, &collision) {
		return collision.Code
	}
	return ""
}

type MutationHeader struct {
	ParentOperationID        string
	MutationID               string
	SemanticHash             string
	ResourceID               string
	ParentResourceID         string
	ExpectedGeneration       uint64
	NewGeneration            uint64
	HostFence                uint64
	ExpectedParentGeneration uint64
}

type Authority struct {
	PhysicalHostID       string
	HostLeaseID          string
	HostLeaseSecretHash  string
	HostLeaseExpiresUnix int64
	Fence                uint64
	ParentGeneration     uint64
	ParentState          string
	HandoffPending       bool
	UpdatedAtUnix        int64
}

type Status struct {
	InventoryGeneration uint64
	Ready               bool
	Error               string
	UpdatedAtUnix       int64
}

type Reservation struct {
	ID               string `json:"id"`
	ResourceKind     string `json:"resource_kind"`
	ResourceID       string `json:"resource_id"`
	NetworkID        string `json:"network_id,omitempty"`
	SubnetIndex      *int64 `json:"subnet_index,omitempty"`
	IPv4             string `json:"ipv4,omitempty"`
	MAC              string `json:"mac,omitempty"`
	ListenPort       *int64 `json:"listen_port,omitempty"`
	ConntrackMark    *int64 `json:"conntrack_mark,omitempty"`
	CapacityKind     string `json:"capacity_kind,omitempty"`
	CapacityUnits    int64  `json:"capacity_units,omitempty"`
	State            string `json:"state"`
	ParentGeneration uint64 `json:"parent_generation"`
	CreatedAtUnix    int64  `json:"created_at_unix"`
	RetiredAtUnix    *int64 `json:"retired_at_unix,omitempty"`
}

type ReserveRequest struct {
	Header       MutationHeader
	Reservations []Reservation
}

type ReserveResult struct {
	Reservations        []Reservation `json:"reservations"`
	ParentGeneration    uint64        `json:"parent_generation"`
	InventoryGeneration uint64        `json:"inventory_generation"`
	Replay              bool          `json:"-"`
}

type ReleaseRequest struct {
	Header         MutationHeader
	ReservationIDs []string
}

type ReleaseResult struct {
	RetiredIDs          []string `json:"retired_ids"`
	ParentGeneration    uint64   `json:"parent_generation"`
	InventoryGeneration uint64   `json:"inventory_generation"`
	Replay              bool     `json:"-"`
}

type Collision struct {
	Code                  ErrorCode `json:"code"`
	Field                 string    `json:"field"`
	ExistingReservationID string    `json:"existing_reservation_id,omitempty"`
	ExistingResourceKind  string    `json:"existing_resource_kind,omitempty"`
	ExistingResourceID    string    `json:"existing_resource_id,omitempty"`
}

type CapacityUsage struct {
	Used  int64 `json:"used"`
	Limit int64 `json:"limit"`
}

type InventorySummary struct {
	LiveReservations int64                    `json:"live_reservations"`
	Subnets          int64                    `json:"subnets"`
	IPs              int64                    `json:"ips"`
	MACs             int64                    `json:"macs"`
	Ports            int64                    `json:"ports"`
	ConntrackMarks   int64                    `json:"conntrack_marks"`
	Capacity         map[string]CapacityUsage `json:"capacity"`
}

type CollisionError struct {
	Code                ErrorCode
	Collisions          []Collision
	InventoryGeneration uint64
	Summary             InventorySummary
}

func (e *CollisionError) Error() string {
	return fmt.Sprintf("%s: %d collision(s), inventory generation %d",
		e.Code, len(e.Collisions), e.InventoryGeneration)
}

type Network struct {
	ID                 string
	CIDR               string
	GatewayIPv4        string
	NICMAC             string
	InterfaceName      string
	DNSServersJSON     string
	DesiredGeneration  uint64
	AppliedGeneration  uint64
	ObservedGeneration uint64
	ParentGeneration   uint64
	Incarnation        uint64
	State              string
	LastError          string
	RetiredAtUnix      *int64
}

type Guest struct {
	ID                 string
	NetworkID          string
	IPv4               string
	MAC                string
	DesiredGeneration  uint64
	AppliedGeneration  uint64
	ObservedGeneration uint64
	ParentGeneration   uint64
	Incarnation        uint64
	State              string
	LastError          string
	RetiredAtUnix      *int64
}

type Relay struct {
	ID                 string
	VMID               string
	ListenPort         int64
	TargetIPv4         string
	TargetPort         int64
	DesiredGeneration  uint64
	AppliedGeneration  uint64
	ObservedGeneration uint64
	ParentGeneration   uint64
	Incarnation        uint64
	State              string
	BoundMainIP        string
	LastBindError      string
	RetiredAtUnix      *int64
}

type NATState struct {
	VMID               string
	State              string
	ConntrackMark      int64
	DesiredGeneration  uint64
	AppliedGeneration  uint64
	ObservedGeneration uint64
	ParentGeneration   uint64
	DrainStartedUnix   *int64
	LastError          string
}

type Intent struct {
	MutationID        string
	ParentOperationID string
	ResourceKind      string
	ResourceID        string
	ParentResourceID  string
	DesiredGeneration uint64
	ParentGeneration  uint64
	Fence             uint64
	SemanticHash      string
	CompiledHash      string
	Phase             string
	Error             string
	CreatedAtUnix     int64
	UpdatedAtUnix     int64
}

type StageResult struct {
	Intent Intent
	Replay bool
	Result json.RawMessage
}

type CommitIntentRequest struct {
	MutationID   string
	SemanticHash string
	CompiledHash string
	HostFence    uint64
	Result       json.RawMessage
}

type AppliedOperation struct {
	MutationID        string
	ParentOperationID string
	RequestHash       string
	Result            json.RawMessage
	AppliedAtUnix     int64
}

type DesiredSnapshot struct {
	Status       Status
	Authority    Authority
	Networks     []Network
	Guests       []Guest
	Relays       []Relay
	NAT          []NATState
	Reservations []Reservation
}
