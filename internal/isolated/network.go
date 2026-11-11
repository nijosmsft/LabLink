package isolated

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
)

var privateAddressPool = netip.MustParsePrefix("192.168.240.0/20")

const (
	PrivateNetworkPrefixBits = 26
	PrivateSubnetCount       = 1 << (PrivateNetworkPrefixBits - 20)
	FirstGuestAddressOffset  = 10
	LastGuestAddressOffset   = 62
)

type NetworkStateClient interface {
	ListNetworks(context.Context, string) ([]isolatedstate.PrivateNetwork, error)
	CountActiveVMs(context.Context, string) (int, error)
	ImportNetworkReservation(context.Context, NetworkReservationImport) error
}

type HostNetworkClient interface {
	ObserveNetwork(context.Context, NetworkHostQuery) (NetworkHostObservation, error)
}

type NetworkHostQuery struct {
	PhysicalHostID      string
	OrchestratorID      string
	OrchestratorVMGUID  string
	NetworkID           string
	SwitchName          string
	OrchestratorAdapter string
}

type NetworkHostObservation struct {
	SwitchExists        bool
	SwitchName          string
	SwitchGUID          string
	SwitchPrivate       bool
	HostNICCount        int
	ConnectedAdapters   int
	SwitchOwned         bool
	OwnedOrchestratorID string
	OwnedNetworkID      string
	AdapterExists       bool
	AdapterName         string
	AdapterID           string
	AdapterMAC          string
	AdapterSwitchGUID   string
	AdapterOwned        bool
}

type NetworkReservationImport struct {
	NetworkID             string
	OrchestratorID        string
	ReservationID         string
	SubnetIndex           int
	CIDR                  string
	GatewayIPv4           string
	OrchestratorMAC       string
	DesiredGeneration     isolatedstate.Generation
	AppliedGeneration     isolatedstate.Generation
	ObservedGeneration    isolatedstate.Generation
	HyperVSwitchGUID      string
	OrchestratorAdapterID string
}

type RouteConflictObservation struct {
	Candidate netip.Prefix
	Route     hyperv.IsolatedRouteObservation
}

type NetworkCapacityObservation struct {
	Limit                  int
	Used                   int
	AvailableNetworkSlots  int
	AvailableSubnetIndexes []int
	RouteConflicts         []RouteConflictObservation
}

func ObserveNetworkCapacity(
	snapshot appliance.DesiredSnapshot,
	routes []hyperv.IsolatedRouteObservation,
) NetworkCapacityObservation {
	used := make(map[int]struct{})
	for _, reservation := range snapshot.Reservations {
		if reservation.RetiredAtUnix == nil && reservation.SubnetIndex != nil {
			used[int(*reservation.SubnetIndex)] = struct{}{}
		}
	}
	observation := NetworkCapacityObservation{
		Limit: MaxNetworksPerOrchestrator,
		Used:  len(used),
	}
	for index := 0; index < PrivateSubnetCount; index++ {
		if _, exists := used[index]; exists {
			continue
		}
		candidate, _ := PrivateSubnet(index)
		conflicts := FindPrivateRouteConflicts(candidate, routes)
		if len(conflicts) != 0 {
			observation.RouteConflicts = append(observation.RouteConflicts, conflicts...)
			continue
		}
		observation.AvailableSubnetIndexes = append(observation.AvailableSubnetIndexes, index)
	}
	observation.AvailableNetworkSlots = min(
		max(0, MaxNetworksPerOrchestrator-observation.Used),
		len(observation.AvailableSubnetIndexes),
	)
	return observation
}

func FindPrivateRouteConflicts(
	candidate netip.Prefix,
	routes []hyperv.IsolatedRouteObservation,
) []RouteConflictObservation {
	if !candidate.IsValid() {
		return []RouteConflictObservation{{Candidate: candidate}}
	}
	var conflicts []RouteConflictObservation
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(route.DestinationPrefix))
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 {
			continue
		}
		if candidate.Overlaps(prefix.Masked()) {
			conflicts = append(conflicts, RouteConflictObservation{
				Candidate: candidate,
				Route:     route,
			})
		}
	}
	return conflicts
}

func PrivateSubnet(index int) (netip.Prefix, error) {
	if index < 0 || index >= PrivateSubnetCount {
		return netip.Prefix{}, &DomainError{
			Code:    "NETWORK_CAPACITY_EXHAUSTED",
			Message: fmt.Sprintf("subnet index %d is outside the /20 range 0-%d", index, PrivateSubnetCount-1),
		}
	}
	base := privateAddressPool.Masked().Addr().As4()
	offset := index * (1 << (32 - PrivateNetworkPrefixBits))
	value := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	value += uint32(offset)
	address := netip.AddrFrom4([4]byte{
		byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value),
	})
	return netip.PrefixFrom(address, PrivateNetworkPrefixBits), nil
}

func PrivateGateway(prefix netip.Prefix) netip.Addr {
	return prefix.Masked().Addr().Next()
}

func GuestAddress(prefix netip.Prefix, offset int) (netip.Addr, error) {
	if !prefix.IsValid() || prefix.Bits() != PrivateNetworkPrefixBits ||
		!privateAddressPool.Contains(prefix.Addr()) {
		return netip.Addr{}, &DomainError{Code: "INVALID_PRIVATE_SUBNET", Message: prefix.String()}
	}
	if offset < FirstGuestAddressOffset || offset > LastGuestAddressOffset {
		return netip.Addr{}, &DomainError{
			Code:    "INVALID_GUEST_ADDRESS",
			Message: fmt.Sprintf("guest offset must be between %d and %d", FirstGuestAddressOffset, LastGuestAddressOffset),
		}
	}
	address := prefix.Masked().Addr()
	for i := 0; i < offset; i++ {
		address = address.Next()
	}
	return address, nil
}

type AddNetworkRequest struct {
	OperationID              string
	Orchestrator             isolatedstate.Orchestrator
	NetworkID                NetworkID
	DisplayName              string
	ExpectedParentGeneration isolatedstate.Generation
	ExplicitSubnetIndex      *int
	Routes                   []hyperv.IsolatedRouteObservation
	HostFence                int64
}

type AddNetworkPlan struct {
	Plan                      RevisionedPlan
	Network                   isolatedstate.PrivateNetwork
	Reservation               appliance.Reservation
	InventoryGeneration       uint64
	ResultingParentGeneration uint64
	Host                      NetworkHostObservation
	Imported                  bool
	CollisionRetries          int
}

type NetworkDomain struct {
	State     NetworkStateClient
	Appliance ApplianceClient
	Host      HostNetworkClient
}

func (d NetworkDomain) ReserveAndPlan(
	ctx context.Context,
	request AddNetworkRequest,
) (AddNetworkPlan, error) {
	if d.State == nil || d.Appliance == nil || d.Host == nil {
		return AddNetworkPlan{}, errors.New("isolated: network state, appliance, and host clients are required")
	}
	if err := request.NetworkID.Validate(); err != nil {
		return AddNetworkPlan{}, err
	}
	if request.Orchestrator.DesiredGeneration != request.ExpectedParentGeneration {
		return AddNetworkPlan{}, staleGenerationError(
			int64(request.ExpectedParentGeneration),
			int64(request.Orchestrator.DesiredGeneration),
		)
	}
	switch request.Orchestrator.LifecycleState {
	case isolatedstate.OrchestratorFrozen, isolatedstate.OrchestratorDeleting,
		isolatedstate.OrchestratorLost, isolatedstate.OrchestratorDeleted:
		return AddNetworkPlan{}, &DomainError{Code: "PARENT_FROZEN", Message: "orchestrator does not admit child creation"}
	}
	networks, err := d.State.ListNetworks(ctx, request.Orchestrator.ID)
	if err != nil {
		return AddNetworkPlan{}, err
	}
	activeNetworks := 0
	for _, network := range networks {
		if network.LifecycleState != isolatedstate.NetworkDeleted {
			activeNetworks++
		}
	}
	if activeNetworks >= MaxNetworksPerOrchestrator {
		return AddNetworkPlan{}, &DomainError{
			Code:    "NETWORK_CAPACITY_EXHAUSTED",
			Message: fmt.Sprintf("orchestrator already has %d active networks", activeNetworks),
		}
	}

	names, err := NetworkNames(request.NetworkID)
	if err != nil {
		return AddNetworkPlan{}, err
	}
	hostObservation, err := d.Host.ObserveNetwork(ctx, NetworkHostQuery{
		PhysicalHostID:      request.Orchestrator.PhysicalHostID,
		OrchestratorID:      request.Orchestrator.ID,
		OrchestratorVMGUID:  nullableString(request.Orchestrator.HyperVVMID),
		NetworkID:           request.NetworkID.String(),
		SwitchName:          names.HyperVSwitchName,
		OrchestratorAdapter: names.OrchestratorAdapterName,
	})
	if err != nil {
		return AddNetworkPlan{}, err
	}
	importedHost, err := validateNetworkHostCollision(request, names, hostObservation)
	if err != nil {
		return AddNetworkPlan{}, err
	}

	snapshot, err := d.Appliance.GetApplianceState(ctx, request.Orchestrator.ID)
	if err != nil {
		return AddNetworkPlan{}, err
	}
	if existing, ok := reservationForResource(snapshot.Reservations, "network", request.NetworkID.String()); ok {
		return d.planAcceptedNetwork(ctx, request, names, hostObservation, existing,
			snapshot.Status.InventoryGeneration, existing.ParentGeneration, true, 0)
	}

	automatic := request.ExplicitSubnetIndex == nil
	retries := 0
	for {
		index, prefix, err := chooseSubnet(snapshot, request.ExplicitSubnetIndex, request.Routes)
		if err != nil {
			return AddNetworkPlan{}, err
		}
		mac, err := hyperv.DeterministicIsolatedMAC(request.NetworkID.String())
		if err != nil {
			return AddNetworkPlan{}, err
		}
		semanticInputs := networkSemanticInputs(request, names, index, prefix, mac)
		semanticHash, err := isolatedstate.SemanticHash(semanticInputs)
		if err != nil {
			return AddNetworkPlan{}, err
		}
		mutationID := isolatedstate.StableMutationID(
			request.OperationID, request.NetworkID.String(),
			"reserve_network", "allocate",
		)
		subnetIndex := int64(index)
		reservation := appliance.Reservation{
			ID:            mutationID + "-network",
			ResourceKind:  "network",
			ResourceID:    request.NetworkID.String(),
			NetworkID:     request.NetworkID.String(),
			SubnetIndex:   &subnetIndex,
			MAC:           mac,
			CapacityKind:  "network",
			CapacityUnits: 1,
		}
		result, reserveErr := d.Appliance.ReserveResources(ctx, request.Orchestrator.ID, appliance.ReserveRequest{
			Header: appliance.MutationHeader{
				ParentOperationID:        request.OperationID,
				MutationID:               mutationID,
				SemanticHash:             semanticHash,
				ResourceID:               request.NetworkID.String(),
				ParentResourceID:         request.Orchestrator.ID,
				ExpectedGeneration:       0,
				NewGeneration:            1,
				HostFence:                uint64(request.HostFence),
				ExpectedParentGeneration: uint64(request.ExpectedParentGeneration),
			},
			Reservations: []appliance.Reservation{reservation},
		})
		if reserveErr == nil {
			if len(result.Reservations) != 1 {
				return AddNetworkPlan{}, &DomainError{
					Code:    "INVALID_APPLIANCE_RESPONSE",
					Message: "network reservation did not return exactly one accepted reservation",
				}
			}
			return d.planAcceptedNetwork(ctx, request, names, hostObservation,
				result.Reservations[0], result.InventoryGeneration,
				result.ParentGeneration, importedHost || result.Replay, retries)
		}
		var collision *appliance.CollisionError
		if !automatic || !errors.As(reserveErr, &collision) ||
			(collision.Code != appliance.CodeSubnetInUse &&
				collision.Code != appliance.CodeMACInUse &&
				collision.Code != appliance.CodeCapacityExhausted) {
			return AddNetworkPlan{}, reserveErr
		}
		retries++
		if retries >= PrivateSubnetCount {
			return AddNetworkPlan{}, &DomainError{
				Code:    "NETWORK_CAPACITY_EXHAUSTED",
				Message: "all automatic subnet candidates collided",
			}
		}
		snapshot, err = d.Appliance.GetApplianceState(ctx, request.Orchestrator.ID)
		if err != nil {
			return AddNetworkPlan{}, err
		}
	}
}

func validateNetworkHostCollision(
	request AddNetworkRequest,
	names NetworkPhysicalNames,
	observation NetworkHostObservation,
) (bool, error) {
	if observation.SwitchExists {
		if observation.SwitchName != names.HyperVSwitchName ||
			!observation.SwitchPrivate || observation.HostNICCount != 0 {
			return false, &DomainError{
				Code:    "SWITCH_IDENTITY_MISMATCH",
				Message: "same-name switch is not the expected private switch without a host vNIC",
			}
		}
		if !observation.SwitchOwned ||
			observation.OwnedOrchestratorID != request.Orchestrator.ID ||
			observation.OwnedNetworkID != request.NetworkID.String() {
			return false, &DomainError{
				Code:    "SWITCH_OWNERSHIP_MISMATCH",
				Message: "same-name switch is not owned by the exact orchestrator/network IDs",
			}
		}
	}
	if observation.AdapterExists {
		if !observation.AdapterOwned ||
			observation.AdapterName != names.OrchestratorAdapterName ||
			observation.AdapterSwitchGUID != observation.SwitchGUID {
			return false, &DomainError{
				Code:    "ADAPTER_IDENTITY_MISMATCH",
				Message: "same-name orchestrator adapter is not the exact owned adapter",
			}
		}
	}
	return observation.SwitchExists || observation.AdapterExists, nil
}

func (d NetworkDomain) planAcceptedNetwork(
	ctx context.Context,
	request AddNetworkRequest,
	names NetworkPhysicalNames,
	host NetworkHostObservation,
	accepted appliance.Reservation,
	inventoryGeneration, parentGeneration uint64,
	imported bool,
	retries int,
) (AddNetworkPlan, error) {
	if accepted.SubnetIndex == nil {
		return AddNetworkPlan{}, &DomainError{
			Code:    "INVALID_APPLIANCE_RESPONSE",
			Message: "accepted network reservation has no subnet index",
		}
	}
	index := int(*accepted.SubnetIndex)
	prefix, err := PrivateSubnet(index)
	if err != nil {
		return AddNetworkPlan{}, err
	}
	if len(FindPrivateRouteConflicts(prefix, request.Routes)) != 0 {
		return AddNetworkPlan{}, &DomainError{
			Code:    "ROUTE_CONFLICT",
			Message: "appliance-authoritative subnet now overlaps a management route",
		}
	}
	mac := strings.ToUpper(strings.TrimSpace(accepted.MAC))
	if mac == "" {
		return AddNetworkPlan{}, &DomainError{
			Code:    "INVALID_APPLIANCE_RESPONSE",
			Message: "accepted network reservation has no private NIC MAC",
		}
	}
	network := isolatedstate.PrivateNetwork{
		ID:                request.NetworkID.String(),
		OrchestratorID:    request.Orchestrator.ID,
		DisplayName:       request.DisplayName,
		HyperVSwitchName:  names.HyperVSwitchName,
		SubnetIndex:       index,
		CIDR:              prefix.String(),
		GatewayIPv4:       PrivateGateway(prefix).String(),
		OrchestratorMAC:   mac,
		DesiredGeneration: 1,
		LifecycleState:    isolatedstate.NetworkAllocating,
	}
	if host.SwitchGUID != "" {
		network.HyperVSwitchGUID = optionalString(host.SwitchGUID)
	}
	if host.AdapterID != "" {
		network.OrchestratorAdapterID = optionalString(host.AdapterID)
	}
	cacheImport := NetworkReservationImport{
		NetworkID:             network.ID,
		OrchestratorID:        network.OrchestratorID,
		ReservationID:         accepted.ID,
		SubnetIndex:           index,
		CIDR:                  network.CIDR,
		GatewayIPv4:           network.GatewayIPv4,
		OrchestratorMAC:       mac,
		DesiredGeneration:     1,
		HyperVSwitchGUID:      host.SwitchGUID,
		OrchestratorAdapterID: host.AdapterID,
	}
	if err := d.State.ImportNetworkReservation(ctx, cacheImport); err != nil {
		return AddNetworkPlan{}, err
	}

	switchAction := "create"
	adapterAction := "attach"
	if host.SwitchExists {
		switchAction = "verify"
	}
	if host.AdapterExists {
		adapterAction = "verify"
	}
	actions := []PlanAction{
		{
			Phase: "create_private_switch", Action: switchAction,
			ResourceType: "network", ResourceID: network.ID,
			ExpectedIdentity:   host.SwitchGUID,
			ExpectedGeneration: 0, NewGeneration: 1,
		},
		{
			Phase: "add_orchestrator_nic", Action: adapterAction,
			ResourceType: "network", ResourceID: network.ID,
			ExpectedIdentity:   host.AdapterID,
			ExpectedGeneration: 0, NewGeneration: 1,
		},
		{
			Phase: "appliance_apply_network", Action: "apply",
			ResourceType: "network", ResourceID: network.ID,
			ExpectedGeneration: 0, NewGeneration: 1,
		},
		{
			Phase: "verify_gateway", Action: "verify",
			ResourceType: "network", ResourceID: network.ID,
			ExpectedGeneration: 1, NewGeneration: 1,
		},
	}
	inputs := networkSemanticInputs(request, names, index, prefix, mac)
	inputs["reservation_id"] = accepted.ID
	inputs["accepted_parent_generation"] = parentGeneration
	plan, err := newRevisionedPlan(
		"add_isolated_network", request.OperationID, network.ID, inputs, actions,
	)
	if err != nil {
		return AddNetworkPlan{}, err
	}
	return AddNetworkPlan{
		Plan:                      plan,
		Network:                   network,
		Reservation:               accepted,
		InventoryGeneration:       inventoryGeneration,
		ResultingParentGeneration: parentGeneration,
		Host:                      host,
		Imported:                  imported,
		CollisionRetries:          retries,
	}, nil
}

func networkSemanticInputs(
	request AddNetworkRequest,
	names NetworkPhysicalNames,
	index int,
	prefix netip.Prefix,
	mac string,
) map[string]any {
	return map[string]any{
		"physical_host_id":   request.Orchestrator.PhysicalHostID,
		"orchestrator_id":    request.Orchestrator.ID,
		"orchestrator_vm_id": nullableString(request.Orchestrator.HyperVVMID),
		"network_id":         request.NetworkID.String(),
		"display_name":       request.DisplayName,
		"switch_name":        names.HyperVSwitchName,
		"adapter_name":       names.OrchestratorAdapterName,
		"subnet_index":       index,
		"cidr":               prefix.String(),
		"gateway_ipv4":       PrivateGateway(prefix).String(),
		"orchestrator_mac":   mac,
		"semantic_action":    "create_network",
	}
}

func chooseSubnet(
	snapshot appliance.DesiredSnapshot,
	explicit *int,
	routes []hyperv.IsolatedRouteObservation,
) (int, netip.Prefix, error) {
	used := make(map[int]struct{})
	for _, reservation := range snapshot.Reservations {
		if reservation.RetiredAtUnix == nil && reservation.SubnetIndex != nil {
			used[int(*reservation.SubnetIndex)] = struct{}{}
		}
	}
	for _, network := range snapshot.Networks {
		if network.RetiredAtUnix != nil {
			continue
		}
		if prefix, err := netip.ParsePrefix(network.CIDR); err == nil {
			for index := 0; index < PrivateSubnetCount; index++ {
				candidate, _ := PrivateSubnet(index)
				if candidate == prefix.Masked() {
					used[index] = struct{}{}
				}
			}
		}
	}
	if explicit != nil {
		prefix, err := PrivateSubnet(*explicit)
		if err != nil {
			return 0, netip.Prefix{}, err
		}
		if _, exists := used[*explicit]; exists {
			return 0, netip.Prefix{}, &DomainError{
				Code:    "SUBNET_IN_USE",
				Message: fmt.Sprintf("explicit subnet index %d is already reserved", *explicit),
			}
		}
		if conflicts := FindPrivateRouteConflicts(prefix, routes); len(conflicts) != 0 {
			return 0, netip.Prefix{}, routeConflictError(conflicts)
		}
		return *explicit, prefix, nil
	}
	routeConflictCount := 0
	for index := 0; index < PrivateSubnetCount; index++ {
		if _, exists := used[index]; exists {
			continue
		}
		prefix, _ := PrivateSubnet(index)
		if conflicts := FindPrivateRouteConflicts(prefix, routes); len(conflicts) != 0 {
			routeConflictCount++
			continue
		}
		return index, prefix, nil
	}
	if routeConflictCount > 0 {
		return 0, netip.Prefix{}, &DomainError{
			Code:    "ROUTE_CONFLICT",
			Message: fmt.Sprintf("%d otherwise-free /26 candidates overlap management routes", routeConflictCount),
		}
	}
	return 0, netip.Prefix{}, &DomainError{
		Code:    "NETWORK_CAPACITY_EXHAUSTED",
		Message: "all 64 /26 subnet candidates are reserved",
	}
}

func routeConflictError(conflicts []RouteConflictObservation) error {
	conflict := conflicts[0]
	return &DomainError{
		Code: "ROUTE_CONFLICT",
		Message: fmt.Sprintf(
			"candidate %s overlaps route %s on interface %s",
			conflict.Candidate, conflict.Route.DestinationPrefix,
			conflict.Route.InterfaceAlias,
		),
	}
}

func reservationForResource(
	reservations []appliance.Reservation,
	kind, resourceID string,
) (appliance.Reservation, bool) {
	for _, reservation := range reservations {
		if reservation.RetiredAtUnix == nil &&
			reservation.ResourceKind == kind &&
			reservation.ResourceID == resourceID {
			return reservation, true
		}
	}
	return appliance.Reservation{}, false
}

type RemoveNetworkRequest struct {
	OperationID        string
	Network            isolatedstate.PrivateNetwork
	ExpectedGeneration isolatedstate.Generation
	Host               NetworkHostObservation
}

type ReconcileNetworkRequest struct {
	OperationID        string
	Network            isolatedstate.PrivateNetwork
	RefreshDNS         bool
	ExpectedGeneration isolatedstate.Generation
	Host               NetworkHostObservation
}

func BuildNetworkReconcilePlan(request ReconcileNetworkRequest) (RevisionedPlan, error) {
	if request.Network.DesiredGeneration != request.ExpectedGeneration {
		return RevisionedPlan{}, staleGenerationError(
			int64(request.ExpectedGeneration),
			int64(request.Network.DesiredGeneration),
		)
	}
	if request.Network.HyperVSwitchGUID == nil ||
		request.Network.OrchestratorAdapterID == nil {
		return RevisionedPlan{}, &DomainError{
			Code:    "NETWORK_IDENTITY_INCOMPLETE",
			Message: "exact switch GUID and orchestrator adapter ID are required for reconciliation",
		}
	}
	if request.Host.SwitchGUID != *request.Network.HyperVSwitchGUID ||
		request.Host.AdapterID != *request.Network.OrchestratorAdapterID {
		return RevisionedPlan{}, &DomainError{
			Code:    "NETWORK_IDENTITY_MISMATCH",
			Message: "observed switch or adapter identity changed",
		}
	}
	newGeneration := request.ExpectedGeneration + 1
	inputs := map[string]any{
		"network_id":       request.Network.ID,
		"orchestrator_id":  request.Network.OrchestratorID,
		"switch_name":      request.Network.HyperVSwitchName,
		"switch_guid":      *request.Network.HyperVSwitchGUID,
		"adapter_id":       *request.Network.OrchestratorAdapterID,
		"cidr":             request.Network.CIDR,
		"gateway_ipv4":     request.Network.GatewayIPv4,
		"orchestrator_mac": request.Network.OrchestratorMAC,
		"refresh_dns":      request.RefreshDNS,
		"semantic_action":  "reconcile_network",
	}
	actions := []PlanAction{
		{
			Phase: "verify_private_switch", Action: "verify",
			ResourceType: "network", ResourceID: request.Network.ID,
			ExpectedIdentity:   *request.Network.HyperVSwitchGUID,
			ExpectedGeneration: int64(request.ExpectedGeneration),
			NewGeneration:      int64(newGeneration),
		},
		{
			Phase: "verify_orchestrator_nic", Action: "verify",
			ResourceType: "network", ResourceID: request.Network.ID,
			ExpectedIdentity:   *request.Network.OrchestratorAdapterID,
			ExpectedGeneration: int64(request.ExpectedGeneration),
			NewGeneration:      int64(newGeneration),
		},
		{
			Phase: "appliance_reconcile_network", Action: "reconcile",
			ResourceType: "network", ResourceID: request.Network.ID,
			ExpectedGeneration: int64(request.ExpectedGeneration),
			NewGeneration:      int64(newGeneration),
		},
	}
	return newRevisionedPlan(
		"reconcile_isolated_network", request.OperationID,
		request.Network.ID, inputs, actions,
	)
}

func (d NetworkDomain) BuildRemovePlan(
	ctx context.Context,
	request RemoveNetworkRequest,
) (RevisionedPlan, error) {
	if d.State == nil {
		return RevisionedPlan{}, errors.New("isolated: network state client is required")
	}
	if request.Network.DesiredGeneration != request.ExpectedGeneration {
		return RevisionedPlan{}, staleGenerationError(
			int64(request.ExpectedGeneration),
			int64(request.Network.DesiredGeneration),
		)
	}
	guests, err := d.State.CountActiveVMs(ctx, request.Network.ID)
	if err != nil {
		return RevisionedPlan{}, err
	}
	if guests != 0 {
		return RevisionedPlan{}, &DomainError{
			Code:    "NETWORK_NOT_EMPTY",
			Message: fmt.Sprintf("network %s still has %d non-deleted guests", request.Network.ID, guests),
		}
	}
	if request.Network.HyperVSwitchGUID == nil ||
		request.Network.OrchestratorAdapterID == nil {
		return RevisionedPlan{}, &DomainError{
			Code:    "NETWORK_IDENTITY_INCOMPLETE",
			Message: "exact switch GUID and orchestrator adapter ID are required for removal",
		}
	}
	if request.Host.SwitchGUID != *request.Network.HyperVSwitchGUID ||
		request.Host.AdapterID != *request.Network.OrchestratorAdapterID {
		return RevisionedPlan{}, &DomainError{
			Code:    "NETWORK_IDENTITY_MISMATCH",
			Message: "observed switch or adapter identity changed",
		}
	}
	newGeneration := request.ExpectedGeneration + 1
	inputs := map[string]any{
		"network_id":       request.Network.ID,
		"orchestrator_id":  request.Network.OrchestratorID,
		"switch_name":      request.Network.HyperVSwitchName,
		"switch_guid":      *request.Network.HyperVSwitchGUID,
		"adapter_id":       *request.Network.OrchestratorAdapterID,
		"cidr":             request.Network.CIDR,
		"orchestrator_mac": request.Network.OrchestratorMAC,
		"semantic_action":  "remove_network",
	}
	actions := []PlanAction{
		{
			Phase: "appliance_remove_network", Action: "remove",
			ResourceType: "network", ResourceID: request.Network.ID,
			ExpectedGeneration: int64(request.ExpectedGeneration),
			NewGeneration:      int64(newGeneration),
		},
		{
			Phase: "remove_orchestrator_nic", Action: "remove",
			ResourceType: "network", ResourceID: request.Network.ID,
			ExpectedIdentity:   *request.Network.OrchestratorAdapterID,
			ExpectedGeneration: int64(request.ExpectedGeneration),
			NewGeneration:      int64(newGeneration),
		},
		{
			Phase: "remove_private_switch", Action: "remove",
			ResourceType: "network", ResourceID: request.Network.ID,
			ExpectedIdentity:   *request.Network.HyperVSwitchGUID,
			ExpectedGeneration: int64(request.ExpectedGeneration),
			NewGeneration:      int64(newGeneration),
		},
		{
			Phase: "release_subnet", Action: "release",
			ResourceType: "network", ResourceID: request.Network.ID,
			ExpectedGeneration: int64(request.ExpectedGeneration),
			NewGeneration:      int64(newGeneration),
		},
	}
	return newRevisionedPlan(
		"remove_isolated_network", request.OperationID,
		request.Network.ID, inputs, actions,
	)
}

type LostNetworkCleanupRequest struct {
	OperationID string
	Network     isolatedstate.PrivateNetwork
	Authority   isolatedstate.CascadeAuthority
}

func BuildLostNetworkCleanupPlan(request LostNetworkCleanupRequest) (RevisionedPlan, error) {
	if request.Authority.OrchestratorID != request.Network.OrchestratorID {
		return RevisionedPlan{}, &DomainError{
			Code:    "CASCADE_AUTHORITY_MISMATCH",
			Message: "cascade authority belongs to another orchestrator",
		}
	}
	if request.Network.HyperVSwitchGUID == nil ||
		request.Network.OrchestratorAdapterID == nil {
		return RevisionedPlan{}, &DomainError{
			Code:    "NETWORK_IDENTITY_INCOMPLETE",
			Message: "lost cleanup requires exact host switch and adapter identities",
		}
	}
	allowed := make(map[string]isolatedstate.CascadeAuthorityItem)
	for _, item := range request.Authority.Items {
		if item.ResourceType == "network" && item.ResourceID == request.Network.ID &&
			item.CompletedAt == nil {
			allowed[item.Action] = item
		}
	}
	for _, action := range []string{"remove_orchestrator_nic", "remove_private_switch", "release_subnet"} {
		if _, ok := allowed[action]; !ok {
			return RevisionedPlan{}, &DomainError{
				Code:    "CASCADE_ITEM_NOT_AUTHORIZED",
				Message: "lost cleanup is not authorized for " + action,
			}
		}
	}
	inputs := map[string]any{
		"network_id":      request.Network.ID,
		"orchestrator_id": request.Network.OrchestratorID,
		"switch_guid":     *request.Network.HyperVSwitchGUID,
		"adapter_id":      *request.Network.OrchestratorAdapterID,
		"plan_revision":   request.Authority.PlanRevision,
		"plan_hash":       request.Authority.PlanHash,
		"semantic_action": "lost_network_cleanup",
	}
	actions := []PlanAction{
		{
			Phase: "remove_orchestrator_nic", Action: "remove_orchestrator_nic",
			ResourceType: "network", ResourceID: request.Network.ID,
			ExpectedIdentity:   *request.Network.OrchestratorAdapterID,
			ExpectedGeneration: int64(request.Network.DesiredGeneration),
			NewGeneration:      int64(request.Network.DesiredGeneration + 1),
		},
		{
			Phase: "remove_private_switch", Action: "remove_private_switch",
			ResourceType: "network", ResourceID: request.Network.ID,
			ExpectedIdentity:   *request.Network.HyperVSwitchGUID,
			ExpectedGeneration: int64(request.Network.DesiredGeneration),
			NewGeneration:      int64(request.Network.DesiredGeneration + 1),
		},
		{
			Phase: "release_subnet", Action: "release_subnet",
			ResourceType: "network", ResourceID: request.Network.ID,
			ExpectedGeneration: int64(request.Network.DesiredGeneration),
			NewGeneration:      int64(request.Network.DesiredGeneration + 1),
		},
	}
	return newRevisionedPlan(
		"lost_isolated_network_cleanup", request.OperationID,
		request.Network.ID, inputs, actions,
	)
}

func ValidateGenerationConvergence(
	desired, applied, observed isolatedstate.Generation,
) error {
	if applied > desired || observed > desired {
		return &DomainError{
			Code: "GENERATION_CONFLICT",
			Message: fmt.Sprintf(
				"applied/observed generations %d/%d exceed desired generation %d",
				applied, observed, desired,
			),
		}
	}
	if desired != applied || desired != observed {
		return &DomainError{
			Code: "STALE_GENERATION",
			Message: fmt.Sprintf(
				"desired/applied/observed generations are %d/%d/%d",
				desired, applied, observed,
			),
		}
	}
	return nil
}

// MergeApplianceNetworkCache keeps Hyper-V identity from the host/server
// record while taking live addressing and generations from the appliance.
func MergeApplianceNetworkCache(
	local isolatedstate.PrivateNetwork,
	live appliance.Network,
	reservation appliance.Reservation,
) (isolatedstate.PrivateNetwork, error) {
	if local.ID != live.ID || local.ID != reservation.ResourceID {
		return isolatedstate.PrivateNetwork{}, &DomainError{
			Code:    "NETWORK_IDENTITY_MISMATCH",
			Message: "server, appliance network, and reservation IDs differ",
		}
	}
	if reservation.SubnetIndex == nil {
		return isolatedstate.PrivateNetwork{}, &DomainError{
			Code:    "INVALID_APPLIANCE_RESPONSE",
			Message: "network reservation has no subnet index",
		}
	}
	prefix, err := PrivateSubnet(int(*reservation.SubnetIndex))
	if err != nil {
		return isolatedstate.PrivateNetwork{}, err
	}
	local.SubnetIndex = int(*reservation.SubnetIndex)
	local.CIDR = prefix.String()
	if strings.TrimSpace(live.CIDR) != "" {
		local.CIDR = live.CIDR
	}
	local.GatewayIPv4 = live.GatewayIPv4
	if local.GatewayIPv4 == "" {
		local.GatewayIPv4 = PrivateGateway(prefix).String()
	}
	local.OrchestratorMAC = live.NICMAC
	if local.OrchestratorMAC == "" {
		local.OrchestratorMAC = reservation.MAC
	}
	local.DesiredGeneration = isolatedstate.Generation(live.DesiredGeneration)
	local.AppliedGeneration = isolatedstate.Generation(live.AppliedGeneration)
	local.ObservedGeneration = isolatedstate.Generation(live.ObservedGeneration)
	local.LifecycleState = isolatedstate.NetworkLifecycleState(live.State)
	return local, nil
}

func SortedAvailableSubnets(
	snapshot appliance.DesiredSnapshot,
	routes []hyperv.IsolatedRouteObservation,
) []int {
	var available []int
	for index := 0; index < PrivateSubnetCount; index++ {
		candidate := index
		chosen, _, err := chooseSubnet(snapshot, &candidate, routes)
		if err == nil {
			available = append(available, chosen)
		}
	}
	sort.Ints(available)
	return available
}

func SubnetIndexFromCIDR(cidr string) (int, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || prefix.Bits() != PrivateNetworkPrefixBits {
		return 0, &DomainError{Code: "INVALID_PRIVATE_SUBNET", Message: cidr}
	}
	for index := 0; index < PrivateSubnetCount; index++ {
		candidate, _ := PrivateSubnet(index)
		if candidate == prefix.Masked() {
			return index, nil
		}
	}
	return 0, &DomainError{Code: "INVALID_PRIVATE_SUBNET", Message: cidr}
}
