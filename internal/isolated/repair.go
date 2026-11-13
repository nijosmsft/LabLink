package isolated

import "github.com/nijosmsft/lablink/internal/isolatedstate"

type GuestRepairObservation struct {
	HostIdentityValid  bool
	NICValid           bool
	TimeSyncEnabled    bool
	RelayValid         bool
	GuestReachable     bool
	StaticNetworkValid bool
	NATValid           bool
	RegistryValid      bool
}

type GuestRepairDecision struct {
	Recreate        bool                      `json:"recreate"`
	NextIncarnation isolatedstate.Incarnation `json:"next_incarnation"`
	Reason          string                    `json:"reason"`
}

func DecideGuestRepair(vm isolatedstate.IsolatedVM, observation GuestRepairObservation, repairErr error) GuestRepairDecision {
	if repairErr == nil && observation.HostIdentityValid && observation.NICValid &&
		observation.TimeSyncEnabled && observation.RelayValid && observation.GuestReachable &&
		observation.StaticNetworkValid && observation.NATValid && observation.RegistryValid {
		return GuestRepairDecision{NextIncarnation: vm.Incarnation, Reason: "non-destructive reconciliation succeeded"}
	}
	reason := "live identity or configuration could not be reconciled"
	if repairErr != nil {
		reason = repairErr.Error()
	}
	return GuestRepairDecision{
		Recreate: true, NextIncarnation: vm.Incarnation + 1, Reason: reason,
	}
}
