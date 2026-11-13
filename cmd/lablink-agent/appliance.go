package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	applianceModeEnv               = "LABLINK_APPLIANCE_MODE"
	applianceDBEnv                 = "LABLINK_APPLIANCE_DB"
	staticConfigRelayShutdownGrace = 2 * time.Second
)

type applianceConfig struct {
	Enabled bool
	DBPath  string
}

type applianceRPC struct {
	enabled       bool
	store         *appliance.Store
	apply         *appliance.ApplyManager
	relay         *appliance.RelayManager
	mainInterface string
	startupErr    error
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
		service.startupErr = fmt.Errorf(
			"appliance mode requires linux, running on %s", goos)
		return service
	}
	store, err := appliance.Open(cfg.DBPath)
	if err != nil {
		service.startupErr = fmt.Errorf("open appliance state: %w", err)
		return service
	}
	service.store = store
	mainInterface, err := discoverMainInterface(context.Background())
	if err != nil {
		service.failStartup(err)
		return service
	}
	service.mainInterface = mainInterface
	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		service.failStartup(err)
		return service
	}
	for _, network := range snapshot.Networks {
		if strings.TrimSpace(network.InterfaceName) == "" {
			interfaceName, resolveErr := interfaceNameForMAC(network.NICMAC)
			if resolveErr != nil {
				service.failStartup(resolveErr)
				return service
			}
			if err := store.BindNetworkInterface(
				context.Background(), network.ID, interfaceName,
			); err != nil {
				service.failStartup(err)
				return service
			}
			network.InterfaceName = interfaceName
		}
		if err := applyPrivateNetworkd(
			context.Background(), network,
		); err != nil {
			service.failStartup(err)
			return service
		}
	}
	compiler, err := appliance.NewLinuxCompiler(
		appliance.LinuxCompilerConfig{MainInterface: mainInterface})
	if err != nil {
		service.failStartup(err)
		return service
	}
	target, err := appliance.NewLinuxApplyTarget(
		appliance.LinuxTargetConfig{
			EmergencyPath: "/opt/lablink/orchestrator/emergency.nft",
		})
	if err != nil {
		service.failStartup(err)
		return service
	}
	conflicts, err := appliance.NewConflictScanner(
		appliance.ConflictScannerConfig{})
	if err != nil {
		service.failStartup(err)
		return service
	}
	manager, err := appliance.NewApplyManager(appliance.ApplyManagerOptions{
		Store: store, Compiler: compiler, Target: target, Conflicts: conflicts,
	})
	if err != nil {
		service.failStartup(err)
		return service
	}
	if _, err := manager.Start(context.Background()); err != nil {
		service.failStartup(err)
		return service
	}
	relay, err := newApplianceRelayManager(store, mainInterface)
	if err != nil {
		service.failStartup(err)
		return service
	}
	if err := relay.Start(context.Background()); err != nil {
		_ = relay.Shutdown(context.Background())
		service.failStartup(err)
		return service
	}
	if err := manager.ApplyStaticConfig(context.Background()); err != nil {
		_ = relay.Shutdown(context.Background())
		service.failStartup(err)
		return service
	}
	service.apply = manager
	service.relay = relay
	return service
}

func (a *applianceRPC) failStartup(err error) {
	if a.store != nil {
		_ = a.store.Close()
		a.store = nil
	}
	a.startupErr = err
}

func newApplianceRelayManager(
	store *appliance.Store,
	mainInterface string,
) (*appliance.RelayManager, error) {
	return appliance.NewRelayManager(store, appliance.RelayManagerOptions{
		CurrentMainIPv4: func(ctx context.Context) (string, error) {
			return waitForMainIPv4(ctx, mainInterface, 30*time.Second)
		},
	})
}

func discoverMainInterface(ctx context.Context) (string, error) {
	result, err := (appliance.OSCommandExecutor{}).Run(
		ctx, "ip", "-4", "route", "show", "default")
	if err != nil {
		return "", fmt.Errorf("discover appliance main interface: %w", err)
	}
	if result.ExitCode != 0 {
		return "", fmt.Errorf(
			"discover appliance main interface: ip exited %d: %s",
			result.ExitCode, strings.TrimSpace(result.Stderr))
	}
	fields := strings.Fields(result.Stdout)
	for index, field := range fields {
		if field == "dev" && index+1 < len(fields) {
			return fields[index+1], nil
		}
	}
	return "", errors.New(
		"discover appliance main interface: default route has no dev")
}

func discoverMainIPv4(
	ctx context.Context,
	mainInterface string,
) (string, error) {
	result, err := (appliance.OSCommandExecutor{}).Run(
		ctx, "ip", "-4", "-o", "address", "show",
		"dev", mainInterface, "scope", "global")
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		return "", fmt.Errorf(
			"ip address exited %d: %s",
			result.ExitCode, strings.TrimSpace(result.Stderr))
	}
	fields := strings.Fields(result.Stdout)
	for index, field := range fields {
		if field == "inet" && index+1 < len(fields) {
			return strings.SplitN(fields[index+1], "/", 2)[0], nil
		}
	}
	return "", errors.New("main interface has no global IPv4 address")
}

func waitForMainIPv4(
	ctx context.Context,
	mainInterface string,
	timeout time.Duration,
) (string, error) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for {
		address, err := discoverMainIPv4(ctx, mainInterface)
		if err == nil {
			return address, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-deadline.C:
			return "", fmt.Errorf(
				"wait for main IPv4 on %s: %w",
				mainInterface, lastErr)
		case <-ticker.C:
		}
	}
}

func (a *applianceRPC) Close() error {
	if a == nil {
		return nil
	}
	if a.relay != nil {
		_ = a.relay.Shutdown(context.Background())
	}
	if a.store != nil {
		return a.store.Close()
	}
	return nil
}

func (a *applianceRPC) populateInfo(
	ctx context.Context,
	response *pb.GetInfoResponse,
) {
	if a == nil || !a.enabled {
		return
	}
	for _, capability := range isolated.RequiredOrchestratorCapabilities() {
		response.Capabilities = append(
			response.Capabilities, string(capability))
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
	state, err := a.store.Status(ctx)
	if err != nil {
		response.ApplianceError =
			fmt.Sprintf("read appliance readiness: %v", err)
		return
	}
	response.ApplianceReady = state.Ready
	response.ApplianceError = state.Error
	if !state.Ready && strings.TrimSpace(state.Error) == "" {
		response.ApplianceError = "appliance state is not ready"
	}
}

func (s *agentServer) applianceStore() (*appliance.Store, error) {
	if s.appliance == nil || !s.appliance.enabled {
		return nil, status.Error(
			codes.FailedPrecondition, "appliance mode is not enabled")
	}
	if s.appliance.startupErr != nil {
		return nil, status.Errorf(
			codes.Unavailable,
			"appliance is not ready: %v", s.appliance.startupErr)
	}
	if s.appliance.store == nil {
		return nil, status.Error(
			codes.Unavailable, "appliance state store is unavailable")
	}
	return s.appliance.store, nil
}

func (s *agentServer) GetApplianceState(
	ctx context.Context,
	_ *pb.GetApplianceStateRequest,
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
	state := &pb.ApplianceState{
		SchemaVersion:   uint32(schemaVersion),
		ProtocolVersion: isolated.MaximumProtocolVersion,
		Ready:           snapshot.Status.Ready, Error: snapshot.Status.Error,
	}
	if s.appliance.apply != nil {
		verification, compiled, verifyErr :=
			s.appliance.apply.VerifyCurrent(ctx)
		state.PolicyVerified =
			verifyErr == nil && verification.Matched
		state.Ipv4ForwardingEnabled = compiled.EnableForwarding
		if verifyErr != nil && state.Error == "" {
			state.Error = verifyErr.Error()
		} else if !verification.Matched && state.Error == "" {
			state.Error = verification.Detail
		}
	}
	if mainIPv4, mainErr := discoverMainIPv4(
		ctx, s.appliance.mainInterface,
	); mainErr == nil {
		state.MainIpv4 = mainIPv4
	} else if state.Error == "" {
		state.Error = mainErr.Error()
	}
	response := &pb.GetApplianceStateResponse{Appliance: state}
	guestNetworks := map[string]string{}
	for _, value := range snapshot.Guests {
		guestNetworks[value.ID] = value.NetworkID
		response.Guests = append(
			response.Guests, &pb.IsolatedGuest{
				Id: value.ID, NetworkId: value.NetworkID,
				Ipv4: value.IPv4, Mac: value.MAC,
			})
	}
	for _, value := range snapshot.Networks {
		var dns []string
		_ = json.Unmarshal([]byte(value.DNSServersJSON), &dns)
		response.Networks = append(
			response.Networks, &pb.PrivateNetwork{
				Id: value.ID, Cidr: value.CIDR,
				GatewayIpv4:   value.GatewayIPv4,
				NicMac:        value.NICMAC,
				InterfaceName: value.InterfaceName,
				DnsServers:    dns, State: value.State,
			})
	}
	for _, value := range snapshot.Relays {
		response.Relays = append(
			response.Relays, relayProto(
				value, guestNetworks[value.VMID]))
	}
	for _, value := range snapshot.NAT {
		response.NatStates = append(
			response.NatStates, &pb.NatState{
				VmId:          value.VMID,
				NetworkId:     guestNetworks[value.VMID],
				State:         value.State,
				ConntrackMark: uint32(value.ConntrackMark),
			})
	}
	return response, nil
}

func (s *agentServer) ConfigureIsolatedAppliance(
	ctx context.Context,
	req *pb.ConfigureIsolatedApplianceRequest,
) (*pb.ConfigureIsolatedApplianceResponse, error) {
	store, err := s.applianceStore()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(
			codes.InvalidArgument, "configuration is required")
	}
	config := appliance.StaticConfig{}
	for _, value := range req.GetNetworks() {
		if value == nil {
			return nil, status.Error(
				codes.InvalidArgument, "network must not be nil")
		}
		dns, _ := json.Marshal(value.GetDnsServers())
		interfaceName := strings.TrimSpace(value.GetInterfaceName())
		if interfaceName == "" {
			interfaceName, err = interfaceNameForMAC(value.GetNicMac())
			if err != nil {
				return nil, status.Errorf(
					codes.FailedPrecondition,
					"resolve private interface for MAC %s: %v",
					value.GetNicMac(), err)
			}
		}
		config.Networks = append(
			config.Networks, appliance.StaticNetwork{
				ID: value.GetId(), CIDR: value.GetCidr(),
				GatewayIPv4:    value.GetGatewayIpv4(),
				NICMAC:         value.GetNicMac(),
				InterfaceName:  interfaceName,
				DNSServersJSON: string(dns),
			})
	}
	for _, value := range req.GetGuests() {
		if value == nil {
			return nil, status.Error(
				codes.InvalidArgument, "guest must not be nil")
		}
		config.Guests = append(
			config.Guests, appliance.StaticGuest{
				ID: value.GetId(), NetworkID: value.GetNetworkId(),
				IPv4: value.GetIpv4(), MAC: value.GetMac(),
			})
	}
	for _, value := range req.GetRelays() {
		if value == nil {
			return nil, status.Error(
				codes.InvalidArgument, "relay must not be nil")
		}
		config.Relays = append(
			config.Relays, appliance.StaticRelay{
				ID: value.GetId(), VMID: value.GetVmId(),
				ListenPort: int64(value.GetListenPort()),
				TargetIPv4: value.GetTargetIpv4(),
				TargetPort: appliance.RelayTargetPort,
			})
	}
	for _, value := range req.GetNat() {
		if value == nil {
			return nil, status.Error(
				codes.InvalidArgument, "NAT must not be nil")
		}
		config.NAT = append(config.NAT, appliance.StaticNAT{
			VMID:          value.GetVmId(),
			ConntrackMark: int64(value.GetConntrackMark()),
			Enabled:       value.GetEnabled(),
		})
	}
	if err := appliance.ValidateStaticConfig(config); err != nil {
		return nil, applianceError(err)
	}
	old, err := store.Snapshot(ctx)
	if err != nil {
		return nil, applianceError(err)
	}
	if err := retireConfiguredNAT(
		ctx, old, s.appliance.mainInterface, req.GetRetireNat(),
	); err != nil {
		return nil, err
	}
	if s.appliance.relay != nil {
		if err := shutdownRelayForStaticReplace(
			ctx, staticConfigRelayShutdownGrace,
			s.appliance.relay.Shutdown,
		); err != nil {
			return nil, applianceError(err)
		}
		s.appliance.relay = nil
	}
	newNetworks := make(map[string]struct{}, len(config.Networks))
	for _, network := range config.Networks {
		newNetworks[network.ID] = struct{}{}
	}
	for _, network := range old.Networks {
		if _, keep := newNetworks[network.ID]; !keep {
			if err := removePrivateNetworkd(ctx, network); err != nil {
				return nil, status.Errorf(
					codes.Internal, "remove private network %s: %v",
					network.ID, err)
			}
		}
	}
	for _, network := range config.Networks {
		if err := applyPrivateNetworkd(ctx, appliance.Network{
			ID: network.ID, CIDR: network.CIDR,
			GatewayIPv4:   network.GatewayIPv4,
			NICMAC:        network.NICMAC,
			InterfaceName: network.InterfaceName,
		}); err != nil {
			return nil, status.Errorf(
				codes.Internal, "apply private network %s: %v",
				network.ID, err)
		}
	}
	if err := store.ReplaceStaticConfig(ctx, config); err != nil {
		return nil, applianceError(err)
	}
	if err := s.appliance.apply.ApplyStaticConfig(ctx); err != nil {
		return nil, applianceError(err)
	}
	relay, err := newApplianceRelayManager(
		store, s.appliance.mainInterface)
	if err != nil {
		return nil, applianceError(err)
	}
	if err := relay.Start(ctx); err != nil {
		_ = relay.Shutdown(context.Background())
		return nil, applianceError(err)
	}
	s.appliance.relay = relay
	if err := s.appliance.apply.ApplyStaticConfig(ctx); err != nil {
		return nil, applianceError(err)
	}
	state, err := s.GetApplianceState(
		ctx, &pb.GetApplianceStateRequest{})
	if err != nil {
		return nil, err
	}
	return &pb.ConfigureIsolatedApplianceResponse{State: state}, nil
}

func shutdownRelayForStaticReplace(
	ctx context.Context,
	grace time.Duration,
	shutdown func(context.Context) error,
) error {
	shutdownCtx, cancel := context.WithTimeout(ctx, grace)
	err := shutdown(shutdownCtx)
	timedOut := errors.Is(shutdownCtx.Err(), context.DeadlineExceeded) &&
		ctx.Err() == nil
	cancel()
	if timedOut && errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

func retireConfiguredNAT(
	ctx context.Context,
	snapshot appliance.StaticSnapshot,
	mainInterface string,
	requests []*pb.RetiredNatFlow,
) error {
	if len(requests) == 0 {
		return nil
	}
	guests := make(map[string]appliance.Guest, len(snapshot.Guests))
	networks := make(map[string]appliance.Network, len(snapshot.Networks))
	nat := make(map[string]appliance.NATState, len(snapshot.NAT))
	for _, value := range snapshot.Guests {
		guests[value.ID] = value
	}
	for _, value := range snapshot.Networks {
		networks[value.ID] = value
	}
	for _, value := range snapshot.NAT {
		nat[value.VMID] = value
	}
	conntrack, err := appliance.NewLinuxConntrack(
		appliance.LinuxConntrackConfig{})
	if err != nil {
		return applianceError(err)
	}
	for _, request := range requests {
		if request == nil {
			return status.Error(
				codes.InvalidArgument,
				"retired NAT entry must not be nil")
		}
		current, found := nat[request.GetVmId()]
		if !found {
			continue
		}
		guest, found := guests[request.GetVmId()]
		if !found || guest.IPv4 != request.GetGuestIpv4() ||
			current.ConntrackMark != int64(request.GetConntrackMark()) {
			return status.Errorf(
				codes.FailedPrecondition,
				"exact NAT identity for VM %s changed",
				request.GetVmId())
		}
		network, found := networks[guest.NetworkID]
		if !found || strings.TrimSpace(network.InterfaceName) == "" {
			return status.Errorf(
				codes.FailedPrecondition,
				"private interface for VM %s is unavailable",
				request.GetVmId())
		}
		address, err := netip.ParseAddr(guest.IPv4)
		if err != nil {
			return status.Errorf(
				codes.FailedPrecondition,
				"invalid guest address for VM %s",
				request.GetVmId())
		}
		if err := conntrack.RetireExact(
			ctx, appliance.ConntrackFilter{
				GuestIPv4:        address,
				PrivateInterface: network.InterfaceName,
				MainInterface:    mainInterface,
				ConntrackMark:    request.GetConntrackMark(),
			}); err != nil {
			return applianceError(err)
		}
	}
	return nil
}

func (s *agentServer) GetRelayStats(
	ctx context.Context,
	req *pb.GetRelayStatsRequest,
) (*pb.GetRelayStatsResponse, error) {
	if s.appliance == nil || s.appliance.relay == nil {
		return nil, status.Error(
			codes.Unavailable, "relay manager is not available")
	}
	stats, err := s.appliance.relay.Stats(ctx, req.GetRelayId())
	if err != nil {
		return nil, applianceError(err)
	}
	return &pb.GetRelayStatsResponse{
		RelayId:                      stats.RelayID,
		ListenerState:                stats.ListenerState,
		BindAddress:                  stats.BindAddress,
		ActiveConnections:            stats.ActiveConnections,
		TotalAcceptedConnections:     stats.TotalAcceptedConnections,
		BytesGuestToMain:             stats.BytesGuestToMain,
		BytesMainToGuest:             stats.BytesMainToGuest,
		LastSuccessfulConnectionUnix: stats.LastSuccessfulConnectionUnix,
		TargetDialFailureCount:       stats.TargetDialFailureCount,
		LastFailure: firstNonEmpty(
			stats.LastFailure, stats.BindError),
	}, nil
}

func (s *agentServer) ValidateRelay(
	ctx context.Context,
	req *pb.ValidateRelayRequest,
) (*pb.ValidateRelayResponse, error) {
	store, err := s.applianceStore()
	if err != nil {
		return nil, err
	}
	relay, found, err := store.Relay(ctx, req.GetRelayId())
	if err != nil {
		return nil, applianceError(err)
	}
	if !found {
		return nil, status.Error(codes.NotFound, "relay not found")
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return nil, applianceError(err)
	}
	guests := map[string]appliance.Guest{}
	for _, value := range snapshot.Guests {
		guests[value.ID] = value
	}
	guest, guestFound := guests[relay.VMID]
	stats, statsErr := s.appliance.relay.Stats(ctx, relay.ID)
	mappingValid := guestFound &&
		relay.TargetIPv4 == guest.IPv4 &&
		relay.TargetPort == appliance.RelayTargetPort
	message := ""
	if statsErr != nil {
		message = statsErr.Error()
	}
	targetReachable := false
	if req.GetProbeTarget() {
		connection, dialErr := net.DialTimeout(
			"tcp4",
			net.JoinHostPort(
				relay.TargetIPv4,
				strconv.Itoa(appliance.RelayTargetPort)),
			3*time.Second)
		if dialErr == nil {
			targetReachable = true
			_ = connection.Close()
		} else if message == "" {
			message = dialErr.Error()
		}
	}
	return &pb.ValidateRelayResponse{
		Relay: relayProto(relay, guest.NetworkID),
		ListenerValid: statsErr == nil &&
			stats.ListenerState == "ready" &&
			stats.BindAddress != "",
		MappingValid:    mappingValid,
		TargetReachable: targetReachable,
		Message:         message,
	}, nil
}

func applyPrivateNetworkd(
	ctx context.Context,
	network appliance.Network,
) error {
	subnet, err := netip.ParsePrefix(strings.TrimSpace(network.CIDR))
	if err != nil {
		return err
	}
	mac := strings.ToUpper(
		strings.NewReplacer(":", "", "-", "").Replace(network.NICMAC))
	if len(mac) != 12 {
		return fmt.Errorf("invalid private NIC MAC %q", network.NICMAC)
	}
	formattedMAC := strings.Join([]string{
		mac[0:2], mac[2:4], mac[4:6],
		mac[6:8], mac[8:10], mac[10:12],
	}, ":")
	unit, err := appliance.RenderPrivateNetworkdUnit(
		appliance.PrivateNICSpec{
			NetworkID: network.ID, MAC: formattedMAC,
			InterfaceName: network.InterfaceName, Subnet: subnet,
		})
	if err != nil {
		return err
	}
	files := appliance.OSFileSystem{}
	if err := files.WriteFileAtomic(
		unit.Path, []byte(unit.Content), 0o644,
	); err != nil {
		return err
	}
	executor := appliance.OSCommandExecutor{}
	for _, command := range [][]string{
		{"networkctl", "reload"},
		{"networkctl", "reconfigure", network.InterfaceName},
	} {
		result, runErr := executor.Run(
			ctx, command[0], command[1:]...)
		if runErr != nil {
			return runErr
		}
		if result.ExitCode != 0 {
			return fmt.Errorf(
				"%s failed: %s",
				strings.Join(command, " "),
				strings.TrimSpace(result.Stderr))
		}
	}
	gateway, err := appliance.PrivateGateway(subnet)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		result, runErr := executor.Run(
			ctx, "ip", "-4", "-o", "address",
			"show", "dev", network.InterfaceName)
		if runErr != nil {
			return runErr
		}
		if result.ExitCode == 0 &&
			strings.Contains(
				result.Stdout, gateway.String()+"/26") {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf(
				"interface %s did not acquire %s/26: %s",
				network.InterfaceName, gateway,
				strings.TrimSpace(
					result.Stdout+" "+result.Stderr))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func removePrivateNetworkd(
	ctx context.Context,
	network appliance.Network,
) error {
	subnet, err := netip.ParsePrefix(strings.TrimSpace(network.CIDR))
	if err != nil {
		return err
	}
	mac := strings.ToUpper(
		strings.NewReplacer(":", "", "-", "").Replace(network.NICMAC))
	if len(mac) != 12 {
		return fmt.Errorf("invalid private NIC MAC %q", network.NICMAC)
	}
	formattedMAC := strings.Join([]string{
		mac[0:2], mac[2:4], mac[4:6],
		mac[6:8], mac[8:10], mac[10:12],
	}, ":")
	unit, err := appliance.RenderPrivateNetworkdUnit(
		appliance.PrivateNICSpec{
			NetworkID: network.ID, MAC: formattedMAC,
			InterfaceName: network.InterfaceName, Subnet: subnet,
		})
	if err != nil {
		return err
	}
	if err := os.Remove(unit.Path); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return err
	}
	result, runErr := (appliance.OSCommandExecutor{}).Run(
		ctx, "networkctl", "reload")
	if runErr != nil {
		return runErr
	}
	if result.ExitCode != 0 {
		return fmt.Errorf(
			"networkctl reload failed: %s",
			strings.TrimSpace(result.Stderr))
	}
	return nil
}

func interfaceNameForMAC(mac string) (string, error) {
	expected := compactMAC(mac)
	if len(expected) != 12 {
		return "", fmt.Errorf("invalid interface MAC %q", mac)
	}
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		data, err := os.ReadFile(
			"/sys/class/net/" + entry.Name() + "/address")
		if err != nil {
			continue
		}
		if compactMAC(string(data)) == expected {
			return entry.Name(), nil
		}
	}
	return "", fmt.Errorf("no interface has MAC %s", expected)
}

func compactMAC(value string) string {
	return strings.ToLower(strings.NewReplacer(
		":", "", "-", "", " ", "",
	).Replace(strings.TrimSpace(value)))
}

func relayProto(
	value appliance.Relay,
	networkID string,
) *pb.Relay {
	return &pb.Relay{
		Id: value.ID, VmId: value.VMID,
		NetworkId:  networkID,
		ListenPort: uint32(value.ListenPort),
		TargetIpv4: value.TargetIPv4,
		TargetPort: uint32(value.TargetPort),
		State:      value.State, BoundMainIp: value.BoundMainIP,
		LastBindError: value.LastBindError,
	}
}

func applianceError(err error) error {
	if err == nil {
		return nil
	}
	code := codes.Internal
	switch appliance.ErrorCodeOf(err) {
	case appliance.CodeInvalidArgument:
		code = codes.InvalidArgument
	case appliance.CodeNotFound:
		code = codes.NotFound
	case appliance.CodeNotReady, appliance.CodeResourceInUse:
		code = codes.FailedPrecondition
	case appliance.CodeSubnetInUse, appliance.CodeIPInUse,
		appliance.CodeMACInUse, appliance.CodePortInUse,
		appliance.CodeConntrackMarkInUse:
		code = codes.AlreadyExists
	case appliance.CodeCapacityExhausted:
		code = codes.ResourceExhausted
	}
	return status.Error(code, err.Error())
}
