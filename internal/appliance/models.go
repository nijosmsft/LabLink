package appliance

import (
	"errors"
	"fmt"
)

const (
	DefaultDBPath        = "/var/lib/lablink-agent/isolated-appliance.db"
	CurrentSchemaVersion = 5
	RelayPortMin         = 20000
	RelayPortMax         = 39999
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
	CodeApplyFailed        ErrorCode = "APPLY_FAILED"
	CodeVerifyFailed       ErrorCode = "VERIFY_FAILED"
	CodeNotReady           ErrorCode = "APPLIANCE_NOT_READY"
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
	return ""
}

type Status struct {
	Ready         bool
	Error         string
	UpdatedAtUnix int64
}

type Network struct {
	ID             string
	CIDR           string
	GatewayIPv4    string
	NICMAC         string
	InterfaceName  string
	DNSServersJSON string
	State          string
	LastError      string
}

type Guest struct {
	ID        string
	NetworkID string
	IPv4      string
	MAC       string
	State     string
	LastError string
}

type Relay struct {
	ID            string
	VMID          string
	ListenPort    int64
	TargetIPv4    string
	TargetPort    int64
	State         string
	BoundMainIP   string
	LastBindError string
}

type NATState struct {
	VMID          string
	State         string
	ConntrackMark int64
	LastError     string
}

type StaticSnapshot struct {
	Status   Status
	Networks []Network
	Guests   []Guest
	Relays   []Relay
	NAT      []NATState
}

type RelayStats struct {
	RelayID                      string
	ListenerState                string
	BindAddress                  string
	BindError                    string
	ActiveConnections            uint64
	TotalAcceptedConnections     uint64
	BytesGuestToMain             uint64
	BytesMainToGuest             uint64
	LastSuccessfulConnectionUnix int64
	TargetDialFailureCount       uint64
	LastFailure                  string
}
