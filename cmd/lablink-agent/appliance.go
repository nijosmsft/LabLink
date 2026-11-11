package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/isolated"
	pb "github.com/nijosmsft/lablink/proto/agent"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	applianceModeEnv = "LABLINK_APPLIANCE_MODE"
	applianceDBEnv   = "LABLINK_APPLIANCE_DB"

	externalApplyPending = "appliance external apply engine is not linked; desired mutations remain pending"
)

type applianceConfig struct {
	Enabled bool
	DBPath  string
}

type applianceRPC struct {
	enabled    bool
	store      *appliance.Store
	startupErr error
}

func resolveApplianceConfig(
	flagEnabled bool,
	flagPath string,
	getenv func(string) string,
) (applianceConfig, error) {
	enabled := flagEnabled
	if !enabled {
		raw := strings.TrimSpace(getenv(applianceModeEnv))
		if raw != "" {
			parsed, err := strconv.ParseBool(raw)
			if err != nil {
				return applianceConfig{Enabled: true}, fmt.Errorf(
					"%s must be a boolean: %w", applianceModeEnv, err)
			}
			enabled = parsed
		}
	}
	if !enabled {
		return applianceConfig{}, nil
	}
	path := strings.TrimSpace(flagPath)
	if path == "" {
		path = strings.TrimSpace(getenv(applianceDBEnv))
	}
	if path == "" {
		path = appliance.DefaultDBPath
	}
	return applianceConfig{Enabled: true, DBPath: path}, nil
}

func loadApplianceRPC(flagEnabled bool, flagPath string) *applianceRPC {
	cfg, err := resolveApplianceConfig(flagEnabled, flagPath, os.Getenv)
	if err != nil {
		return &applianceRPC{enabled: true, startupErr: err}
	}
	if !cfg.Enabled {
		return nil
	}
	return openApplianceRPC(cfg, runtime.GOOS)
}

func openApplianceRPC(cfg applianceConfig, goos string) *applianceRPC {
	service := &applianceRPC{enabled: cfg.Enabled}
	if !cfg.Enabled {
		return service
	}
	if goos != "linux" {
		service.startupErr = fmt.Errorf("appliance mode requires linux, running on %s", goos)
		return service
	}
	store, err := appliance.Open(cfg.DBPath)
	if err != nil {
		service.startupErr = fmt.Errorf("open appliance state: %w", err)
		return service
	}
	service.store = store
	if err := store.SetReadiness(context.Background(), false, externalApplyPending); err != nil {
		_ = store.Close()
		service.store = nil
		service.startupErr = fmt.Errorf("mark appliance not ready: %w", err)
	}
	return service
}

func (a *applianceRPC) Close() error {
	if a == nil || a.store == nil {
		return nil
	}
	return a.store.Close()
}

func (a *applianceRPC) populateInfo(ctx context.Context, response *pb.GetInfoResponse) {
	if a == nil || !a.enabled {
		return
	}
	for _, capability := range isolated.RequiredOrchestratorCapabilities() {
		response.Capabilities = append(response.Capabilities, string(capability))
	}
	response.ProtocolVersion = isolated.MaximumProtocolVersion
	if a.startupErr != nil {
		response.ApplianceError = a.startupErr.Error()
		return
	}
	if a.store == nil {
		response.ApplianceError = "appliance state store is unavailable"
		return
	}
	applianceStatus, err := a.store.Status(ctx)
	if err != nil {
		response.ApplianceError = fmt.Sprintf("read appliance readiness: %v", err)
		return
	}
	response.ApplianceReady = applianceStatus.Ready
	response.ApplianceGeneration = applianceStatus.InventoryGeneration
	response.ApplianceError = applianceStatus.Error
	if !response.ApplianceReady && strings.TrimSpace(response.ApplianceError) == "" {
		response.ApplianceError = "appliance state is not ready"
	}
}

func (s *agentServer) applianceStore() (*appliance.Store, error) {
	if s.appliance == nil || !s.appliance.enabled {
		return nil, status.Error(codes.FailedPrecondition, "appliance mode is not enabled")
	}
	if s.appliance.startupErr != nil {
		return nil, status.Errorf(codes.Unavailable, "appliance is not ready: %v", s.appliance.startupErr)
	}
	if s.appliance.store == nil {
		return nil, status.Error(codes.Unavailable, "appliance state store is unavailable")
	}
	return s.appliance.store, nil
}

func (s *agentServer) GetApplianceState(
	ctx context.Context,
	req *pb.GetApplianceStateRequest,
) (*pb.GetApplianceStateResponse, error) {
	store, err := s.applianceStore()
	if err != nil {
		return nil, err
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return nil, applianceError(err)
	}
	schemaVersion, err := store.SchemaVersion(ctx)
	if err != nil {
		return nil, applianceError(err)
	}
	reservations, err := store.ListReservations(ctx, req.GetIncludeTombstones())
	if err != nil {
		return nil, applianceError(err)
	}
	intents, err := store.RecoveryIntents(ctx)
	if err != nil {
		return nil, applianceError(err)
	}

	response := &pb.GetApplianceStateResponse{
		Appliance: applianceStateProto(schemaVersion, snapshot),
	}
	type appendEntry func()
	entries := make([]appendEntry, 0,
		len(reservations)+len(snapshot.Networks)+len(snapshot.Guests)+
			len(snapshot.Relays)+len(snapshot.NAT)+len(intents))
	guestNetworks := guestNetworkMap(snapshot.Guests)
	for _, value := range reservations {
		value := value
		entries = append(entries, func() {
			response.Reservations = append(response.Reservations, reservationProto(value))
		})
	}
	for _, value := range snapshot.Networks {
		if !req.GetIncludeTombstones() && value.RetiredAtUnix != nil {
			continue
		}
		value := value
		entries = append(entries, func() {
			response.Networks = append(response.Networks, networkProto(value))
		})
	}
	for _, value := range snapshot.Guests {
		if !req.GetIncludeTombstones() && value.RetiredAtUnix != nil {
			continue
		}
		value := value
		entries = append(entries, func() {
			response.Guests = append(response.Guests, guestProto(value))
		})
	}
	for _, value := range snapshot.Relays {
		if !req.GetIncludeTombstones() && value.RetiredAtUnix != nil {
			continue
		}
		value := value
		entries = append(entries, func() {
			response.Relays = append(response.Relays, relayProto(value, guestNetworks[value.VMID]))
		})
	}
	for _, value := range snapshot.NAT {
		value := value
		entries = append(entries, func() {
			response.NatStates = append(response.NatStates, natProto(value, guestNetworks[value.VMID]))
		})
	}
	for _, value := range intents {
		value := value
		entries = append(entries, func() {
			response.ApplyIntents = append(response.ApplyIntents, intentProto(value))
		})
	}

	start, limit, err := pageBounds(req.GetPageToken(), req.GetPageSize(), len(entries))
	if err != nil {
		return nil, err
	}
	end := start + limit
	if end > len(entries) {
		end = len(entries)
	}
	for _, appendValue := range entries[start:end] {
		appendValue()
	}
	if end < len(entries) {
		response.NextPageToken = strconv.Itoa(end)
	}
	return response, nil
}

func (s *agentServer) ReserveResources(
	ctx context.Context,
	req *pb.ReserveResourcesRequest,
) (*pb.ReserveResourcesResponse, error) {
	store, err := s.applianceStore()
	if err != nil {
		return nil, err
	}
	header, err := mutationHeader(req.GetHeader())
	if err != nil {
		return nil, err
	}
	reservations := make([]appliance.Reservation, 0, len(req.GetCandidates()))
	for i, candidate := range req.GetCandidates() {
		if candidate == nil {
			return nil, status.Error(codes.InvalidArgument, "reservation candidate must not be nil")
		}
		reservations = append(reservations, reservationCandidate(header, candidate, i))
	}
	result, err := store.ReserveResources(ctx, appliance.ReserveRequest{
		Header:       header,
		Reservations: reservations,
	})
	if err != nil {
		return nil, applianceError(err)
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return nil, applianceError(err)
	}
	response := &pb.ReserveResourcesResponse{
		ResultingParentGeneration: result.ParentGeneration,
		InventoryGeneration:       result.InventoryGeneration,
		Inventory:                 inventoryProto(snapshot),
		Mutation: mutationResult(
			header,
			&pb.GenerationState{ParentGeneration: result.ParentGeneration},
			result.Replay,
			result.InventoryGeneration,
		),
	}
	for _, reservation := range result.Reservations {
		response.Reservations = append(response.Reservations, reservationProto(reservation))
	}
	if len(response.Reservations) != 0 {
		response.ReservationId = response.Reservations[0].Id
	}
	return response, nil
}

func (s *agentServer) ReleaseResources(
	ctx context.Context,
	req *pb.ReleaseResourcesRequest,
) (*pb.ReleaseResourcesResponse, error) {
	store, err := s.applianceStore()
	if err != nil {
		return nil, err
	}
	header, err := mutationHeader(req.GetHeader())
	if err != nil {
		return nil, err
	}
	result, err := store.ReleaseResources(ctx, appliance.ReleaseRequest{
		Header:         header,
		ReservationIDs: req.GetReservationIds(),
	})
	if err != nil {
		return nil, applianceError(err)
	}
	allReservations, err := store.ListReservations(ctx, true)
	if err != nil {
		return nil, applianceError(err)
	}
	retired := make(map[string]struct{}, len(result.RetiredIDs))
	for _, id := range result.RetiredIDs {
		retired[id] = struct{}{}
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return nil, applianceError(err)
	}
	response := &pb.ReleaseResourcesResponse{
		ResultingParentGeneration: result.ParentGeneration,
		InventoryGeneration:       result.InventoryGeneration,
		Inventory:                 inventoryProto(snapshot),
		Mutation: mutationResult(
			header,
			&pb.GenerationState{ParentGeneration: result.ParentGeneration},
			result.Replay,
			result.InventoryGeneration,
		),
	}
	for _, reservation := range allReservations {
		if _, ok := retired[reservation.ID]; ok {
			response.Reservations = append(response.Reservations, reservationProto(reservation))
		}
	}
	return response, nil
}

func (s *agentServer) ApplyPrivateNetwork(
	ctx context.Context,
	req *pb.ApplyPrivateNetworkRequest,
) (*pb.ApplyPrivateNetworkResponse, error) {
	store, err := s.applianceStore()
	if err != nil {
		return nil, err
	}
	header, err := mutationHeader(req.GetHeader())
	if err != nil {
		return nil, err
	}
	if err := requireReservationForMutation(
		ctx, store, header, req.GetReservationId(), "network", header.ResourceID,
	); err != nil {
		return nil, err
	}
	dns, err := json.Marshal(req.GetDnsServers())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "encode DNS servers: %v", err)
	}
	stage, err := store.StageNetwork(ctx, header, appliance.Network{
		ID:             header.ResourceID,
		CIDR:           req.GetCidr(),
		GatewayIPv4:    req.GetGatewayIpv4(),
		NICMAC:         req.GetNicMac(),
		InterfaceName:  req.GetInterfaceName(),
		DNSServersJSON: string(dns),
		State:          "pending",
		LastError:      externalApplyPending,
	})
	if err != nil {
		return nil, applianceError(err)
	}
	if err := markExternalApplyPending(ctx, store); err != nil {
		return nil, err
	}
	network, found, err := store.Network(ctx, header.ResourceID)
	if err != nil {
		return nil, applianceError(err)
	}
	if !found {
		return nil, status.Error(codes.Internal, "staged network was not found")
	}
	generation, err := applianceGeneration(ctx, store)
	if err != nil {
		return nil, applianceError(err)
	}
	return &pb.ApplyPrivateNetworkResponse{
		Network:  networkProto(network),
		Mutation: mutationResult(header, generationProto(network), stage.Replay, generation),
	}, nil
}

func (s *agentServer) RemovePrivateNetwork(
	ctx context.Context,
	req *pb.RemovePrivateNetworkRequest,
) (*pb.RemovePrivateNetworkResponse, error) {
	store, err := s.applianceStore()
	if err != nil {
		return nil, err
	}
	header, err := mutationHeader(req.GetHeader())
	if err != nil {
		return nil, err
	}
	current, found, err := store.Network(ctx, header.ResourceID)
	if err != nil {
		return nil, applianceError(err)
	}
	if !found {
		return nil, status.Error(codes.NotFound, "network not found")
	}
	now := time.Now().Unix()
	current.State = "retiring"
	current.LastError = externalApplyPending
	current.RetiredAtUnix = &now
	stage, err := store.StageNetwork(ctx, header, current)
	if err != nil {
		return nil, applianceError(err)
	}
	if err := markExternalApplyPending(ctx, store); err != nil {
		return nil, err
	}
	current, _, err = store.Network(ctx, header.ResourceID)
	if err != nil {
		return nil, applianceError(err)
	}
	generation, err := applianceGeneration(ctx, store)
	if err != nil {
		return nil, applianceError(err)
	}
	return &pb.RemovePrivateNetworkResponse{
		Network:  networkProto(current),
		Mutation: mutationResult(header, generationProto(current), stage.Replay, generation),
	}, nil
}

func (s *agentServer) RegisterIsolatedGuest(
	ctx context.Context,
	req *pb.RegisterIsolatedGuestRequest,
) (*pb.RegisterIsolatedGuestResponse, error) {
	store, err := s.applianceStore()
	if err != nil {
		return nil, err
	}
	header, err := mutationHeader(req.GetHeader())
	if err != nil {
		return nil, err
	}
	if header.ParentResourceID == "" {
		header.ParentResourceID = req.GetNetworkId()
	}
	if err := requireReservationForMutation(
		ctx, store, header, req.GetReservationId(), "guest", header.ResourceID,
	); err != nil {
		return nil, err
	}
	stage, err := store.StageGuest(ctx, header, appliance.Guest{
		ID:        header.ResourceID,
		NetworkID: req.GetNetworkId(),
		IPv4:      req.GetIpv4(),
		MAC:       req.GetMac(),
		State:     "pending",
		LastError: externalApplyPending,
	})
	if err != nil {
		return nil, applianceError(err)
	}
	if err := markExternalApplyPending(ctx, store); err != nil {
		return nil, err
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return nil, applianceError(err)
	}
	guest, found := findGuest(snapshot, header.ResourceID)
	if !found {
		return nil, status.Error(codes.Internal, "staged guest was not found")
	}
	return &pb.RegisterIsolatedGuestResponse{
		Guest: guestProto(guest),
		Mutation: mutationResult(
			header, generationProto(guest), stage.Replay, snapshot.Status.InventoryGeneration),
	}, nil
}

func (s *agentServer) RemoveIsolatedGuest(
	ctx context.Context,
	req *pb.RemoveIsolatedGuestRequest,
) (*pb.RemoveIsolatedGuestResponse, error) {
	store, err := s.applianceStore()
	if err != nil {
		return nil, err
	}
	header, err := mutationHeader(req.GetHeader())
	if err != nil {
		return nil, err
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return nil, applianceError(err)
	}
	guest, found := findGuest(snapshot, header.ResourceID)
	if !found {
		return nil, status.Error(codes.NotFound, "guest not found")
	}
	if header.ParentResourceID == "" {
		header.ParentResourceID = firstNonEmpty(req.GetNetworkId(), guest.NetworkID)
	}
	now := time.Now().Unix()
	guest.State = "retiring"
	guest.LastError = externalApplyPending
	guest.RetiredAtUnix = &now
	stage, err := store.StageGuest(ctx, header, guest)
	if err != nil {
		return nil, applianceError(err)
	}
	if err := markExternalApplyPending(ctx, store); err != nil {
		return nil, err
	}
	snapshot, err = store.Snapshot(ctx)
	if err != nil {
		return nil, applianceError(err)
	}
	guest, _ = findGuest(snapshot, header.ResourceID)
	return &pb.RemoveIsolatedGuestResponse{
		Guest: guestProto(guest),
		Mutation: mutationResult(
			header, generationProto(guest), stage.Replay, snapshot.Status.InventoryGeneration),
	}, nil
}

func (s *agentServer) ApplyRelay(
	ctx context.Context,
	req *pb.ApplyRelayRequest,
) (*pb.Relay, error) {
	return s.stageRelay(ctx, req.GetHeader(), req.GetReservationId(), req.GetVmId(),
		req.GetNetworkId(), req.GetListenPort(), req.GetTargetIpv4(), "pending")
}

func (s *agentServer) AdoptRelay(
	ctx context.Context,
	req *pb.AdoptRelayRequest,
) (*pb.Relay, error) {
	return s.stageRelay(ctx, req.GetHeader(), req.GetReservationId(), req.GetVmId(),
		req.GetNetworkId(), req.GetListenPort(), req.GetTargetIpv4(), "pending")
}

func (s *agentServer) stageRelay(
	ctx context.Context,
	pbHeader *pb.MutationHeader,
	reservationID, vmID, networkID string,
	listenPort uint32,
	targetIPv4, desiredState string,
) (*pb.Relay, error) {
	store, err := s.applianceStore()
	if err != nil {
		return nil, err
	}
	header, err := mutationHeader(pbHeader)
	if err != nil {
		return nil, err
	}
	if header.ParentResourceID == "" {
		header.ParentResourceID = vmID
	}
	if err := requireReservationForMutation(
		ctx, store, header, reservationID, "relay", header.ResourceID,
	); err != nil {
		return nil, err
	}
	_, err = store.StageRelay(ctx, header, appliance.Relay{
		ID:            header.ResourceID,
		VMID:          vmID,
		ListenPort:    int64(listenPort),
		TargetIPv4:    targetIPv4,
		TargetPort:    appliance.RelayTargetPort,
		State:         desiredState,
		LastBindError: externalApplyPending,
	})
	if err != nil {
		return nil, applianceError(err)
	}
	if err := markExternalApplyPending(ctx, store); err != nil {
		return nil, err
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return nil, applianceError(err)
	}
	relay, found := findRelay(snapshot, header.ResourceID)
	if !found {
		return nil, status.Error(codes.Internal, "staged relay was not found")
	}
	if networkID == "" {
		networkID = guestNetworkMap(snapshot.Guests)[relay.VMID]
	}
	return relayProto(relay, networkID), nil
}

func (s *agentServer) RemoveRelay(
	ctx context.Context,
	req *pb.RemoveRelayRequest,
) (*pb.Relay, error) {
	store, err := s.applianceStore()
	if err != nil {
		return nil, err
	}
	header, err := mutationHeader(req.GetHeader())
	if err != nil {
		return nil, err
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return nil, applianceError(err)
	}
	relay, found := findRelay(snapshot, header.ResourceID)
	if !found {
		return nil, status.Error(codes.NotFound, "relay not found")
	}
	if header.ParentResourceID == "" {
		header.ParentResourceID = firstNonEmpty(req.GetVmId(), relay.VMID)
	}
	now := time.Now().Unix()
	relay.State = "retiring"
	relay.LastBindError = externalApplyPending
	relay.RetiredAtUnix = &now
	_, err = store.StageRelay(ctx, header, relay)
	if err != nil {
		return nil, applianceError(err)
	}
	if err := markExternalApplyPending(ctx, store); err != nil {
		return nil, err
	}
	snapshot, err = store.Snapshot(ctx)
	if err != nil {
		return nil, applianceError(err)
	}
	relay, _ = findRelay(snapshot, header.ResourceID)
	networkID := firstNonEmpty(req.GetNetworkId(), guestNetworkMap(snapshot.Guests)[relay.VMID])
	return relayProto(relay, networkID), nil
}

func (s *agentServer) ListRelays(
	ctx context.Context,
	req *pb.ListRelaysRequest,
) (*pb.ListRelaysResponse, error) {
	store, err := s.applianceStore()
	if err != nil {
		return nil, err
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return nil, applianceError(err)
	}
	guestNetworks := guestNetworkMap(snapshot.Guests)
	relays := make([]*pb.Relay, 0, len(snapshot.Relays))
	for _, relay := range snapshot.Relays {
		networkID := guestNetworks[relay.VMID]
		if !req.GetIncludeRetired() && relay.RetiredAtUnix != nil {
			continue
		}
		if req.GetVmId() != "" && relay.VMID != req.GetVmId() {
			continue
		}
		if req.GetNetworkId() != "" && networkID != req.GetNetworkId() {
			continue
		}
		relays = append(relays, relayProto(relay, networkID))
	}
	start, limit, err := pageBounds(req.GetPageToken(), req.GetPageSize(), len(relays))
	if err != nil {
		return nil, err
	}
	end := min(start+limit, len(relays))
	response := &pb.ListRelaysResponse{
		Relays:              relays[start:end],
		ApplianceGeneration: snapshot.Status.InventoryGeneration,
	}
	if end < len(relays) {
		response.NextPageToken = strconv.Itoa(end)
	}
	return response, nil
}

func (s *agentServer) GetRelayStats(
	ctx context.Context,
	req *pb.GetRelayStatsRequest,
) (*pb.GetRelayStatsResponse, error) {
	store, err := s.applianceStore()
	if err != nil {
		return nil, err
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return nil, applianceError(err)
	}
	relay, found := findRelay(snapshot, req.GetRelayId())
	if !found {
		return nil, status.Error(codes.NotFound, "relay not found")
	}
	return &pb.GetRelayStatsResponse{
		RelayId:             relay.ID,
		ListenerState:       "pending",
		BindAddress:         relay.BoundMainIP,
		LastFailure:         externalApplyPending,
		RelayGeneration:     relay.DesiredGeneration,
		ApplianceGeneration: snapshot.Status.InventoryGeneration,
	}, nil
}

func (s *agentServer) RebindRelays(
	ctx context.Context,
	req *pb.RebindRelaysRequest,
) (*pb.RebindRelaysResponse, error) {
	store, err := s.applianceStore()
	if err != nil {
		return nil, err
	}
	header, err := mutationHeader(req.GetHeader())
	if err != nil {
		return nil, err
	}
	if err := validateMutationEnvelopeReadOnly(ctx, store, header); err != nil {
		return nil, err
	}
	return nil, status.Error(codes.Unavailable, externalApplyPending)
}

func (s *agentServer) ValidateRelay(
	ctx context.Context,
	req *pb.ValidateRelayRequest,
) (*pb.ValidateRelayResponse, error) {
	store, err := s.applianceStore()
	if err != nil {
		return nil, err
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return nil, applianceError(err)
	}
	relay, found := findRelay(snapshot, req.GetRelayId())
	if !found {
		return nil, status.Error(codes.NotFound, "relay not found")
	}
	return &pb.ValidateRelayResponse{
		Relay:               relayProto(relay, guestNetworkMap(snapshot.Guests)[relay.VMID]),
		Message:             externalApplyPending,
		ApplianceGeneration: snapshot.Status.InventoryGeneration,
	}, nil
}

func (s *agentServer) SetNatState(
	ctx context.Context,
	req *pb.SetNatStateRequest,
) (*pb.NatState, error) {
	store, err := s.applianceStore()
	if err != nil {
		return nil, err
	}
	header, err := mutationHeader(req.GetHeader())
	if err != nil {
		return nil, err
	}
	if header.ParentResourceID == "" {
		header.ParentResourceID = header.ResourceID
	}
	if err := requireReservationForMutation(
		ctx, store, header, req.GetReservationId(), "guest", header.ResourceID,
	); err != nil {
		return nil, err
	}
	var drainStarted *int64
	if req.GetDesiredState() == "draining" {
		now := time.Now().Unix()
		drainStarted = &now
	}
	_, err = store.StageNAT(ctx, header, appliance.NATState{
		VMID:             header.ResourceID,
		State:            req.GetDesiredState(),
		ConntrackMark:    int64(req.GetConntrackMark()),
		DrainStartedUnix: drainStarted,
		LastError:        externalApplyPending,
	})
	if err != nil {
		return nil, applianceError(err)
	}
	if err := markExternalApplyPending(ctx, store); err != nil {
		return nil, err
	}
	nat, found, err := store.NAT(ctx, header.ResourceID)
	if err != nil {
		return nil, applianceError(err)
	}
	if !found {
		return nil, status.Error(codes.Internal, "staged NAT state was not found")
	}
	return natProto(nat, req.GetNetworkId()), nil
}

func (s *agentServer) ListNatState(
	ctx context.Context,
	req *pb.ListNatStateRequest,
) (*pb.ListNatStateResponse, error) {
	store, err := s.applianceStore()
	if err != nil {
		return nil, err
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return nil, applianceError(err)
	}
	guestNetworks := guestNetworkMap(snapshot.Guests)
	states := make([]*pb.NatState, 0, len(snapshot.NAT))
	for _, nat := range snapshot.NAT {
		networkID := guestNetworks[nat.VMID]
		if req.GetVmId() != "" && nat.VMID != req.GetVmId() {
			continue
		}
		if req.GetNetworkId() != "" && networkID != req.GetNetworkId() {
			continue
		}
		if req.GetState() != "" && nat.State != req.GetState() {
			continue
		}
		states = append(states, natProto(nat, networkID))
	}
	start, limit, err := pageBounds(req.GetPageToken(), req.GetPageSize(), len(states))
	if err != nil {
		return nil, err
	}
	end := min(start+limit, len(states))
	response := &pb.ListNatStateResponse{
		NatStates:           states[start:end],
		ApplianceGeneration: snapshot.Status.InventoryGeneration,
	}
	if end < len(states) {
		response.NextPageToken = strconv.Itoa(end)
	}
	return response, nil
}

func (s *agentServer) ReconcileNat(
	ctx context.Context,
	req *pb.ReconcileNatRequest,
) (*pb.ReconcileNatResponse, error) {
	store, err := s.applianceStore()
	if err != nil {
		return nil, err
	}
	header, err := mutationHeader(req.GetHeader())
	if err != nil {
		return nil, err
	}
	current, found, err := store.NAT(ctx, header.ResourceID)
	if err != nil {
		return nil, applianceError(err)
	}
	if !found {
		return nil, status.Error(codes.NotFound, "NAT state not found")
	}
	if header.ParentResourceID == "" {
		header.ParentResourceID = header.ResourceID
	}
	current.LastError = externalApplyPending
	stage, err := store.StageNAT(ctx, header, current)
	if err != nil {
		return nil, applianceError(err)
	}
	if err := markExternalApplyPending(ctx, store); err != nil {
		return nil, err
	}
	current, _, err = store.NAT(ctx, header.ResourceID)
	if err != nil {
		return nil, applianceError(err)
	}
	generation, err := applianceGeneration(ctx, store)
	if err != nil {
		return nil, applianceError(err)
	}
	return &pb.ReconcileNatResponse{
		NatState: natProto(current, req.GetNetworkId()),
		Mutation: mutationResult(
			header, generationProto(current), stage.Replay, generation),
	}, nil
}

func mutationHeader(header *pb.MutationHeader) (appliance.MutationHeader, error) {
	if header == nil {
		return appliance.MutationHeader{}, status.Error(codes.InvalidArgument, "mutation header is required")
	}
	return appliance.MutationHeader{
		ParentOperationID:        header.GetParentOperationId(),
		MutationID:               header.GetMutationId(),
		SemanticHash:             header.GetSemanticHash(),
		ResourceID:               header.GetResourceId(),
		ParentResourceID:         header.GetParentResourceId(),
		ExpectedGeneration:       header.GetExpectedGeneration(),
		NewGeneration:            header.GetNewGeneration(),
		HostFence:                header.GetHostFence(),
		ExpectedParentGeneration: header.GetExpectedParentGeneration(),
	}, nil
}

func reservationCandidate(
	header appliance.MutationHeader,
	candidate *pb.ReservationCandidate,
	index int,
) appliance.Reservation {
	id := header.MutationID
	if index != 0 {
		id += "-" + strconv.Itoa(index+1)
	}
	reservation := appliance.Reservation{
		ID:           id,
		ResourceKind: candidate.GetResourceKind(),
		ResourceID:   candidate.GetResourceId(),
		NetworkID:    candidate.GetNetworkId(),
		IPv4:         candidate.GetIpv4(),
		MAC:          candidate.GetMac(),
	}
	if candidate.SubnetIndex != nil {
		value := int64(candidate.GetSubnetIndex())
		reservation.SubnetIndex = &value
	}
	if candidate.ListenPort != nil {
		value := int64(candidate.GetListenPort())
		reservation.ListenPort = &value
	}
	if candidate.ConntrackMark != nil {
		value := int64(candidate.GetConntrackMark())
		reservation.ConntrackMark = &value
	}
	switch reservation.ResourceKind {
	case "network", "guest", "relay":
		reservation.CapacityKind = reservation.ResourceKind
		reservation.CapacityUnits = 1
	}
	return reservation
}

func requireReservation(
	ctx context.Context,
	store *appliance.Store,
	reservationID, resourceKind, resourceID string,
) error {
	if strings.TrimSpace(reservationID) == "" {
		return status.Error(codes.InvalidArgument, "reservation ID is required")
	}
	reservations, err := store.ListReservations(ctx, false)
	if err != nil {
		return applianceError(err)
	}
	for _, reservation := range reservations {
		if reservation.ID != reservationID {
			continue
		}
		if reservation.ResourceKind != resourceKind ||
			reservation.ResourceID != resourceID {
			break
		}
		return nil
	}
	return applianceError(&appliance.StoreError{
		Code: appliance.CodeReservationLost,
		Message: fmt.Sprintf(
			"reservation %q does not own %s %q",
			reservationID, resourceKind, resourceID,
		),
	})
}

func requireReservationForMutation(
	ctx context.Context,
	store *appliance.Store,
	header appliance.MutationHeader,
	reservationID, resourceKind, resourceID string,
) error {
	_, found, err := store.Intent(ctx, header.MutationID)
	if err != nil {
		return applianceError(err)
	}
	if found {
		return nil
	}
	return requireReservation(ctx, store, reservationID, resourceKind, resourceID)
}

func validateMutationEnvelopeReadOnly(
	ctx context.Context,
	store *appliance.Store,
	header appliance.MutationHeader,
) error {
	if strings.TrimSpace(header.ParentOperationID) == "" ||
		strings.TrimSpace(header.MutationID) == "" ||
		strings.TrimSpace(header.SemanticHash) == "" {
		return status.Error(
			codes.InvalidArgument,
			"parent operation ID, mutation ID, and semantic hash are required",
		)
	}
	authority, err := store.Authority(ctx)
	if err != nil {
		return applianceError(err)
	}
	if authority.HandoffPending || authority.Fence != header.HostFence {
		return status.Errorf(
			codes.Aborted,
			"%s: host fence is %d; request supplied %d",
			appliance.CodeFenceRejected,
			authority.Fence,
			header.HostFence,
		)
	}
	if authority.HostLeaseExpiresUnix > 0 &&
		time.Now().Unix() >= authority.HostLeaseExpiresUnix {
		return status.Errorf(
			codes.Aborted,
			"%s: host lease expired",
			appliance.CodeFenceRejected,
		)
	}
	if authority.ParentGeneration != header.ExpectedParentGeneration {
		return status.Errorf(
			codes.Aborted,
			"%s: parent generation is %d; request expected %d",
			appliance.CodeParentGeneration,
			authority.ParentGeneration,
			header.ExpectedParentGeneration,
		)
	}
	if authority.ParentState != "active" {
		return status.Errorf(
			codes.FailedPrecondition,
			"%s: parent state is %s",
			appliance.CodeParentFrozen,
			authority.ParentState,
		)
	}
	return nil
}

func markExternalApplyPending(ctx context.Context, store *appliance.Store) error {
	if err := store.SetReadiness(ctx, false, externalApplyPending); err != nil {
		return applianceError(err)
	}
	return nil
}

func applianceStateProto(schemaVersion int, snapshot appliance.DesiredSnapshot) *pb.ApplianceState {
	errorText := snapshot.Status.Error
	if strings.TrimSpace(errorText) == "" && !snapshot.Status.Ready {
		errorText = externalApplyPending
	}
	return &pb.ApplianceState{
		SchemaVersion:       uint32(schemaVersion),
		ProtocolVersion:     isolated.MaximumProtocolVersion,
		Ready:               snapshot.Status.Ready,
		ApplianceGeneration: snapshot.Status.InventoryGeneration,
		InventoryGeneration: snapshot.Status.InventoryGeneration,
		Fence: &pb.FenceState{
			PhysicalHostId:   snapshot.Authority.PhysicalHostID,
			HostFence:        snapshot.Authority.Fence,
			HostLeaseId:      snapshot.Authority.HostLeaseID,
			ParentGeneration: snapshot.Authority.ParentGeneration,
			Frozen:           snapshot.Authority.ParentState == "frozen",
			Deleting:         snapshot.Authority.ParentState == "deleting",
			Lost:             snapshot.Authority.ParentState == "lost",
		},
		Error:     errorText,
		Inventory: inventoryProto(snapshot),
	}
}

func inventoryProto(snapshot appliance.DesiredSnapshot) *pb.InventorySummary {
	var liveNetworks, liveGuests uint32
	for _, network := range snapshot.Networks {
		if network.RetiredAtUnix == nil {
			liveNetworks++
		}
	}
	for _, guest := range snapshot.Guests {
		if guest.RetiredAtUnix == nil {
			liveGuests++
		}
	}
	return &pb.InventorySummary{
		MaxNetworks:  16,
		LiveNetworks: liveNetworks,
		MaxGuests:    100,
		LiveGuests:   liveGuests,
	}
}

func reservationProto(value appliance.Reservation) *pb.Reservation {
	result := &pb.Reservation{
		Id:               value.ID,
		ResourceKind:     value.ResourceKind,
		ResourceId:       value.ResourceID,
		NetworkId:        value.NetworkID,
		Ipv4:             value.IPv4,
		Mac:              value.MAC,
		State:            value.State,
		ParentGeneration: value.ParentGeneration,
		CreatedAtUnix:    value.CreatedAtUnix,
	}
	if value.SubnetIndex != nil {
		v := uint32(*value.SubnetIndex)
		result.SubnetIndex = &v
	}
	if value.ListenPort != nil {
		v := uint32(*value.ListenPort)
		result.ListenPort = &v
	}
	if value.ConntrackMark != nil {
		v := uint32(*value.ConntrackMark)
		result.ConntrackMark = &v
	}
	if value.RetiredAtUnix != nil {
		result.RetiredAtUnix = *value.RetiredAtUnix
	}
	return result
}

func networkProto(value appliance.Network) *pb.PrivateNetwork {
	var dns []string
	_ = json.Unmarshal([]byte(value.DNSServersJSON), &dns)
	result := &pb.PrivateNetwork{
		Id:            value.ID,
		Cidr:          value.CIDR,
		GatewayIpv4:   value.GatewayIPv4,
		NicMac:        value.NICMAC,
		InterfaceName: value.InterfaceName,
		DnsServers:    dns,
		Generation:    generationProto(value),
		State:         value.State,
	}
	if value.RetiredAtUnix != nil {
		result.RetiredAtUnix = *value.RetiredAtUnix
	}
	return result
}

func guestProto(value appliance.Guest) *pb.IsolatedGuest {
	result := &pb.IsolatedGuest{
		Id:         value.ID,
		NetworkId:  value.NetworkID,
		Ipv4:       value.IPv4,
		Mac:        value.MAC,
		Generation: generationProto(value),
	}
	if value.RetiredAtUnix != nil {
		result.RetiredAtUnix = *value.RetiredAtUnix
	}
	return result
}

func relayProto(value appliance.Relay, networkID string) *pb.Relay {
	result := &pb.Relay{
		Id:            value.ID,
		VmId:          value.VMID,
		NetworkId:     networkID,
		ListenPort:    uint32(value.ListenPort),
		TargetIpv4:    value.TargetIPv4,
		TargetPort:    uint32(value.TargetPort),
		Generation:    generationProto(value),
		State:         value.State,
		BoundMainIp:   value.BoundMainIP,
		LastBindError: value.LastBindError,
	}
	if value.RetiredAtUnix != nil {
		result.RetiredAtUnix = *value.RetiredAtUnix
	}
	return result
}

func natProto(value appliance.NATState, networkID string) *pb.NatState {
	result := &pb.NatState{
		VmId:          value.VMID,
		NetworkId:     networkID,
		State:         value.State,
		ConntrackMark: uint32(value.ConntrackMark),
		Generation:    generationProto(value),
	}
	if value.DrainStartedUnix != nil {
		result.DrainStartedUnix = *value.DrainStartedUnix
	}
	return result
}

func intentProto(value appliance.Intent) *pb.ApplyIntent {
	return &pb.ApplyIntent{
		MutationId:        value.MutationID,
		ResourceKind:      value.ResourceKind,
		ResourceId:        value.ResourceID,
		DesiredGeneration: value.DesiredGeneration,
		ParentGeneration:  value.ParentGeneration,
		Fence:             value.Fence,
		SemanticHash:      value.SemanticHash,
		CompiledHash:      value.CompiledHash,
		Phase:             value.Phase,
		ErrorText:         value.Error,
		CreatedAtUnix:     value.CreatedAtUnix,
		UpdatedAtUnix:     value.UpdatedAtUnix,
	}
}

type generationValues interface {
	appliance.Network | appliance.Guest | appliance.Relay | appliance.NATState
}

func generationProto[T generationValues](value T) *pb.GenerationState {
	switch typed := any(value).(type) {
	case appliance.Network:
		return &pb.GenerationState{
			DesiredGeneration:  typed.DesiredGeneration,
			AppliedGeneration:  typed.AppliedGeneration,
			ObservedGeneration: typed.ObservedGeneration,
			ParentGeneration:   typed.ParentGeneration,
		}
	case appliance.Guest:
		return &pb.GenerationState{
			DesiredGeneration:  typed.DesiredGeneration,
			AppliedGeneration:  typed.AppliedGeneration,
			ObservedGeneration: typed.ObservedGeneration,
			ParentGeneration:   typed.ParentGeneration,
		}
	case appliance.Relay:
		return &pb.GenerationState{
			DesiredGeneration:  typed.DesiredGeneration,
			AppliedGeneration:  typed.AppliedGeneration,
			ObservedGeneration: typed.ObservedGeneration,
			ParentGeneration:   typed.ParentGeneration,
		}
	case appliance.NATState:
		return &pb.GenerationState{
			DesiredGeneration:  typed.DesiredGeneration,
			AppliedGeneration:  typed.AppliedGeneration,
			ObservedGeneration: typed.ObservedGeneration,
			ParentGeneration:   typed.ParentGeneration,
		}
	default:
		return &pb.GenerationState{}
	}
}

func mutationResult(
	header appliance.MutationHeader,
	generation *pb.GenerationState,
	replayed bool,
	applianceGeneration uint64,
) *pb.MutationResult {
	return &pb.MutationResult{
		MutationId:          header.MutationID,
		SemanticHash:        header.SemanticHash,
		Generation:          generation,
		Replayed:            replayed,
		ApplianceGeneration: applianceGeneration,
	}
}

func guestNetworkMap(guests []appliance.Guest) map[string]string {
	result := make(map[string]string, len(guests))
	for _, guest := range guests {
		result[guest.ID] = guest.NetworkID
	}
	return result
}

func findGuest(snapshot appliance.DesiredSnapshot, id string) (appliance.Guest, bool) {
	for _, guest := range snapshot.Guests {
		if guest.ID == id {
			return guest, true
		}
	}
	return appliance.Guest{}, false
}

func findRelay(snapshot appliance.DesiredSnapshot, id string) (appliance.Relay, bool) {
	for _, relay := range snapshot.Relays {
		if relay.ID == id {
			return relay, true
		}
	}
	return appliance.Relay{}, false
}

func applianceGeneration(ctx context.Context, store *appliance.Store) (uint64, error) {
	value, err := store.Status(ctx)
	return value.InventoryGeneration, err
}

func pageBounds(token string, requested uint32, length int) (int, int, error) {
	start := 0
	if token != "" {
		parsed, err := strconv.Atoi(token)
		if err != nil || parsed < 0 || parsed > length {
			return 0, 0, status.Error(codes.InvalidArgument, "invalid page token")
		}
		start = parsed
	}
	limit := int(requested)
	if limit == 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	return start, limit, nil
}

func applianceError(err error) error {
	if err == nil {
		return nil
	}
	var collision *appliance.CollisionError
	if errors.As(err, &collision) {
		code := codes.AlreadyExists
		if collision.Code == appliance.CodeCapacityExhausted {
			code = codes.ResourceExhausted
		}
		base := status.New(code, err.Error())
		detail := &pb.ApplianceConflict{
			Code:                applianceErrorCode(collision.Code),
			Message:             err.Error(),
			InventoryGeneration: collision.InventoryGeneration,
			Inventory:           collisionInventoryProto(collision.Summary),
		}
		withDetails, detailErr := base.WithDetails(detail)
		if detailErr == nil {
			return withDetails.Err()
		}
		return base.Err()
	}
	switch appliance.ErrorCodeOf(err) {
	case appliance.CodeInvalidArgument:
		return status.Error(codes.InvalidArgument, err.Error())
	case appliance.CodeNotFound:
		return status.Error(codes.NotFound, err.Error())
	case appliance.CodeCapacityExhausted:
		return status.Error(codes.ResourceExhausted, err.Error())
	case appliance.CodeSubnetInUse,
		appliance.CodeIPInUse,
		appliance.CodeMACInUse,
		appliance.CodePortInUse,
		appliance.CodeConntrackMarkInUse,
		appliance.CodeResourceInUse:
		return status.Error(codes.AlreadyExists, err.Error())
	case appliance.CodeParentFrozen, appliance.CodeUnsupportedSchema:
		return status.Error(codes.FailedPrecondition, err.Error())
	case appliance.CodeGenerationConflict,
		appliance.CodeParentGeneration,
		appliance.CodeFenceRejected,
		appliance.CodeResumeMismatch,
		appliance.CodeIntentPending,
		appliance.CodeReservationLost:
		return status.Error(codes.Aborted, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

func applianceErrorCode(code appliance.ErrorCode) pb.ApplianceErrorCode {
	switch code {
	case appliance.CodeSubnetInUse:
		return pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_SUBNET_IN_USE
	case appliance.CodeIPInUse:
		return pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_IP_IN_USE
	case appliance.CodeMACInUse:
		return pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_MAC_IN_USE
	case appliance.CodePortInUse:
		return pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_PORT_IN_USE
	case appliance.CodeConntrackMarkInUse:
		return pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_CONNTRACK_MARK_IN_USE
	case appliance.CodeCapacityExhausted:
		return pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_CAPACITY_EXHAUSTED
	case appliance.CodeGenerationConflict:
		return pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_GENERATION_CONFLICT
	case appliance.CodeParentGeneration:
		return pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_PARENT_GENERATION_CONFLICT
	case appliance.CodeFenceRejected:
		return pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_FENCE_REJECTED
	case appliance.CodeParentFrozen:
		return pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_PARENT_FROZEN
	case appliance.CodeReservationLost:
		return pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_RESERVATION_LOST
	default:
		return pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_UNSPECIFIED
	}
}

func collisionInventoryProto(summary appliance.InventorySummary) *pb.InventorySummary {
	network := summary.Capacity["network"]
	guest := summary.Capacity["guest"]
	return &pb.InventorySummary{
		MaxNetworks:  uint32(network.Limit),
		LiveNetworks: uint32(network.Used),
		MaxGuests:    uint32(guest.Limit),
		LiveGuests:   uint32(guest.Used),
	}
}
