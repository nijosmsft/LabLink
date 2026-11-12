package isolated

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
)

type NATValidationMode int

const (
	NATValidateMutation NATValidationMode = iota
	NATValidateImport
)

type ValidatedNAT struct {
	Reservation appliance.Reservation
	Guest       appliance.Guest
	Live        appliance.NATState
}

type NATDNSStatus struct {
	NetworkCopiedJSON string                            `json:"network_copied_json"`
	GuestCopiedJSON   string                            `json:"guest_copied_json"`
	CopyDrift         bool                              `json:"copy_drift"`
	Pending           *isolatedstate.GuestPendingUpdate `json:"pending_update,omitempty"`
}

func ValidateNATIdentity(
	orchestrator isolatedstate.Orchestrator,
	network isolatedstate.PrivateNetwork,
	vm isolatedstate.IsolatedVM,
	local *isolatedstate.NATAllocation,
	snapshot ApplianceSnapshot,
	mode NATValidationMode,
) (ValidatedNAT, error) {
	if vm.OrchestratorID != orchestrator.ID ||
		network.OrchestratorID != orchestrator.ID ||
		vm.NetworkID != network.ID {
		return ValidatedNAT{}, &DomainError{
			Code:    "NAT_IDENTITY_MISMATCH",
			Message: "server guest, network, and orchestrator identities differ",
		}
	}
	if vm.LifecycleState == isolatedstate.VMDeleted ||
		network.LifecycleState == isolatedstate.NetworkDeleted ||
		orchestrator.LifecycleState == isolatedstate.OrchestratorDeleted ||
		orchestrator.LifecycleState == isolatedstate.OrchestratorLost {
		return ValidatedNAT{}, &DomainError{
			Code:    "NAT_TARGET_UNMANAGED",
			Message: "NAT requires a live managed guest, network, and orchestrator",
		}
	}
	if local != nil &&
		(local.VMID != vm.ID || local.OrchestratorID != orchestrator.ID) {
		return ValidatedNAT{}, &DomainError{
			Code:    "NAT_IDENTITY_MISMATCH",
			Message: "server NAT allocation belongs to another guest or orchestrator",
		}
	}
	if physical := strings.TrimSpace(snapshot.Fence.PhysicalHostID); physical != "" &&
		physical != orchestrator.PhysicalHostID {
		return ValidatedNAT{}, &DomainError{
			Code:    "FOREIGN_APPLIANCE_STATE",
			Message: "appliance physical-host identity differs from the server record",
		}
	}
	if snapshot.Fence.HostFence != 0 && orchestrator.HostFence != 0 &&
		snapshot.Fence.HostFence != uint64(orchestrator.HostFence) {
		return ValidatedNAT{}, &DomainError{
			Code: "FENCE_REJECTED",
			Message: fmt.Sprintf(
				"appliance fence %d differs from server fence %d",
				snapshot.Fence.HostFence, orchestrator.HostFence,
			),
		}
	}
	if snapshot.Fence.ParentGeneration != 0 &&
		snapshot.Fence.ParentGeneration != uint64(orchestrator.DesiredGeneration) {
		return ValidatedNAT{}, &DomainError{
			Code: "PARENT_GENERATION_CONFLICT",
			Message: fmt.Sprintf(
				"appliance parent generation %d differs from orchestrator generation %d",
				snapshot.Fence.ParentGeneration, orchestrator.DesiredGeneration,
			),
		}
	}

	var liveGuest appliance.Guest
	guestFound := false
	for _, candidate := range snapshot.Desired.Guests {
		if candidate.ID == vm.ID && candidate.RetiredAtUnix == nil {
			if guestFound {
				return ValidatedNAT{}, &DomainError{
					Code:    "FOREIGN_APPLIANCE_STATE",
					Message: "appliance returned duplicate live guest identities",
				}
			}
			liveGuest = candidate
			guestFound = true
		}
	}
	if !guestFound {
		return ValidatedNAT{}, &DomainError{
			Code:    "APPLIANCE_GUEST_NOT_FOUND",
			Message: "exact managed guest is absent from appliance state",
		}
	}
	if liveGuest.NetworkID != vm.NetworkID || liveGuest.IPv4 != vm.IPv4 ||
		!equalMAC(liveGuest.MAC, vm.MAC) {
		return ValidatedNAT{}, &DomainError{
			Code:    "FOREIGN_APPLIANCE_STATE",
			Message: "appliance guest network, IPv4, or MAC identity differs",
		}
	}
	if liveGuest.DesiredGeneration != uint64(vm.DesiredGeneration) {
		return ValidatedNAT{}, staleGenerationError(
			int64(vm.DesiredGeneration), int64(liveGuest.DesiredGeneration),
		)
	}
	if snapshot.Fence.ParentGeneration != 0 &&
		liveGuest.DesiredGeneration != snapshot.Fence.ParentGeneration {
		return ValidatedNAT{}, &DomainError{
			Code:    "PARENT_GENERATION_CONFLICT",
			Message: "guest and appliance authority generations differ",
		}
	}

	var reservation appliance.Reservation
	reservationFound := false
	for _, candidate := range snapshot.Desired.Reservations {
		if candidate.RetiredAtUnix == nil && candidate.ResourceKind == "guest" &&
			candidate.ResourceID == vm.ID {
			if reservationFound {
				return ValidatedNAT{}, &DomainError{
					Code:    "FOREIGN_APPLIANCE_STATE",
					Message: "appliance returned duplicate guest reservations",
				}
			}
			reservation = candidate
			reservationFound = true
		}
	}
	if !reservationFound || reservation.ConntrackMark == nil ||
		*reservation.ConntrackMark <= 0 {
		return ValidatedNAT{}, &DomainError{
			Code:    "NAT_RESERVATION_MISSING",
			Message: "exact guest conntrack-mark reservation is absent",
		}
	}
	if reservation.NetworkID != "" && reservation.NetworkID != vm.NetworkID {
		return ValidatedNAT{}, &DomainError{
			Code:    "FOREIGN_APPLIANCE_STATE",
			Message: "guest reservation belongs to another private network",
		}
	}
	if local != nil && local.ConntrackMark != *reservation.ConntrackMark {
		return ValidatedNAT{}, &DomainError{
			Code:    "FOREIGN_APPLIANCE_STATE",
			Message: "server and appliance conntrack marks differ",
		}
	}

	var live appliance.NATState
	liveFound := false
	for _, candidate := range snapshot.Desired.NAT {
		if candidate.VMID == vm.ID {
			if liveFound {
				return ValidatedNAT{}, &DomainError{
					Code:    "FOREIGN_APPLIANCE_STATE",
					Message: "appliance returned duplicate NAT identities",
				}
			}
			live = candidate
			liveFound = true
		}
	}
	if !liveFound {
		return ValidatedNAT{}, &DomainError{
			Code:    "APPLIANCE_NAT_NOT_FOUND",
			Message: "exact guest NAT state is absent from appliance state",
		}
	}
	if live.ConntrackMark != *reservation.ConntrackMark {
		return ValidatedNAT{}, &DomainError{
			Code:    "FOREIGN_APPLIANCE_STATE",
			Message: "NAT state does not use the guest's reserved conntrack mark",
		}
	}
	if live.ParentGeneration != liveGuest.DesiredGeneration {
		return ValidatedNAT{}, &DomainError{
			Code:    "PARENT_GENERATION_CONFLICT",
			Message: "NAT state belongs to another guest generation",
		}
	}
	if live.AppliedGeneration > live.DesiredGeneration ||
		live.ObservedGeneration > live.DesiredGeneration {
		return ValidatedNAT{}, &DomainError{
			Code:    "GENERATION_CONFLICT",
			Message: "appliance NAT applied or observed generation exceeds desired",
		}
	}
	if local != nil {
		localGeneration := uint64(local.DesiredGeneration)
		if mode == NATValidateMutation && live.DesiredGeneration != localGeneration {
			return ValidatedNAT{}, staleGenerationError(
				int64(local.DesiredGeneration), int64(live.DesiredGeneration),
			)
		}
		if mode == NATValidateImport && live.DesiredGeneration < localGeneration {
			return ValidatedNAT{}, &DomainError{
				Code: "STALE_APPLIANCE_GENERATION",
				Message: fmt.Sprintf(
					"appliance NAT generation %d is behind server generation %d",
					live.DesiredGeneration, local.DesiredGeneration,
				),
			}
		}
	}
	return ValidatedNAT{
		Reservation: reservation, Guest: liveGuest, Live: live,
	}, nil
}

func MergeApplianceNAT(
	local *isolatedstate.NATAllocation,
	orchestratorID string,
	live appliance.NATState,
) (isolatedstate.NATAllocation, error) {
	if strings.TrimSpace(live.VMID) == "" || live.ConntrackMark <= 0 {
		return isolatedstate.NATAllocation{}, &DomainError{
			Code:    "INVALID_APPLIANCE_RESPONSE",
			Message: "appliance NAT identity or conntrack mark is missing",
		}
	}
	if live.AppliedGeneration > live.DesiredGeneration ||
		live.ObservedGeneration > live.DesiredGeneration {
		return isolatedstate.NATAllocation{}, &DomainError{
			Code:    "GENERATION_CONFLICT",
			Message: "appliance NAT generations are not monotonic",
		}
	}
	result := isolatedstate.NATAllocation{
		VMID:               live.VMID,
		OrchestratorID:     orchestratorID,
		ConntrackMark:      live.ConntrackMark,
		DesiredGeneration:  isolatedstate.Generation(live.DesiredGeneration),
		AppliedGeneration:  isolatedstate.Generation(live.AppliedGeneration),
		ObservedGeneration: isolatedstate.Generation(live.ObservedGeneration),
	}
	if local != nil {
		result.UpdatedAt = local.UpdatedAt
	}
	switch live.State {
	case "enabled":
		result.DesiredState = isolatedstate.NATDesiredEnabled
		result.ObservedState = isolatedstate.NATObservedEnabled
	case "draining":
		result.DesiredState = isolatedstate.NATDesiredDisabled
		result.ObservedState = isolatedstate.NATObservedDraining
		if live.DrainStartedUnix != nil {
			started := isolatedstate.UnixSeconds(*live.DrainStartedUnix)
			result.DrainStartedAt = &started
		}
	case "disabled":
		result.DesiredState = isolatedstate.NATDesiredDisabled
		result.ObservedState = isolatedstate.NATObservedDisabled
	default:
		return isolatedstate.NATAllocation{}, &DomainError{
			Code:    "INVALID_APPLIANCE_RESPONSE",
			Message: fmt.Sprintf("unknown appliance NAT state %q", live.State),
		}
	}
	return result, nil
}

func BuildNATDNSStatus(
	network isolatedstate.PrivateNetwork,
	vm isolatedstate.IsolatedVM,
	pending *isolatedstate.GuestPendingUpdate,
) NATDNSStatus {
	return NATDNSStatus{
		NetworkCopiedJSON: network.DNSServersJSON,
		GuestCopiedJSON:   vm.DNSServersJSON,
		CopyDrift:         !canonicalJSONEqual(network.DNSServersJSON, vm.DNSServersJSON),
		Pending:           pending,
	}
}

func canonicalJSONEqual(left, right string) bool {
	var leftValue, rightValue any
	if json.Unmarshal([]byte(strings.TrimSpace(left)), &leftValue) != nil ||
		json.Unmarshal([]byte(strings.TrimSpace(right)), &rightValue) != nil {
		return strings.TrimSpace(left) == strings.TrimSpace(right)
	}
	return reflect.DeepEqual(leftValue, rightValue)
}

func equalMAC(left, right string) bool {
	normalize := func(value string) string {
		value = strings.ToUpper(strings.TrimSpace(value))
		value = strings.NewReplacer(":", "", "-", "", ".", "").Replace(value)
		return value
	}
	return normalize(left) == normalize(right)
}
