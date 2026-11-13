package isolated

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/registry"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

const (
	isolatedOrchestratorRole = "isolated-orchestrator"
	orchestratorIDLabel      = "lablink.orchestrator_id"
	isolatedKindLabel        = "lablink.kind"
)

type applianceNodeRegistry interface {
	GetNode(string) (*registry.Node, bool)
	NodesByRole(string) []*registry.Node
}

type applianceClientPool interface {
	GetEndpointClient(agentclient.Endpoint) (pb.NodeAgentClient, error)
	ResetEndpoint(agentclient.Endpoint)
}

type ApplianceRPCClient struct {
	registry      applianceNodeRegistry
	pool          applianceClientPool
	serverVersion string

	mu        sync.Mutex
	endpoints map[string]agentclient.Endpoint
}

var _ ApplianceClient = (*ApplianceRPCClient)(nil)

func NewApplianceRPCClient(
	reg applianceNodeRegistry,
	pool applianceClientPool,
	serverVersion string,
) *ApplianceRPCClient {
	return &ApplianceRPCClient{
		registry: reg, pool: pool, serverVersion: serverVersion,
		endpoints: make(map[string]agentclient.Endpoint),
	}
}

func NewApplianceClient(
	reg *registry.Registry,
	pool *agentclient.Pool,
	serverVersion string,
) *ApplianceRPCClient {
	return NewApplianceRPCClient(reg, pool, serverVersion)
}

type ApplianceReadiness struct {
	Node            string
	AgentVersion    string
	Capabilities    []string
	ProtocolVersion uint32
	Ready           bool
	Error           string
}

type ApplianceSnapshot struct {
	SchemaVersion   uint32
	ProtocolVersion uint32
	Ready           bool
	MainIPv4        string
	PolicyVerified  bool
	IPv4Forwarding  bool
	Error           string
	Config          appliance.StaticSnapshot
}

type RelayValidation struct {
	Relay           appliance.Relay
	ListenerValid   bool
	MappingValid    bool
	TargetReachable bool
	Message         string
}

func (c *ApplianceRPCClient) resolveNode(
	orchestratorID string,
) (*registry.Node, error) {
	if c == nil || c.registry == nil || c.pool == nil {
		return nil, errors.New(
			"isolated: appliance registry and client pool are required")
	}
	orchestratorID = strings.TrimSpace(orchestratorID)
	if orchestratorID == "" {
		return nil, &DomainError{
			Code:    "ORCHESTRATOR_NODE_NOT_FOUND",
			Message: "orchestrator ID is required",
		}
	}
	if node, ok := c.registry.GetNode(orchestratorID); ok &&
		isOrchestratorNode(node, orchestratorID) {
		copy := *node
		return &copy, nil
	}
	var matches []*registry.Node
	var unlabeled []*registry.Node
	for _, node := range c.registry.NodesByRole(isolatedOrchestratorRole) {
		if node == nil {
			continue
		}
		label := strings.TrimSpace(node.Labels[orchestratorIDLabel])
		switch {
		case strings.EqualFold(label, orchestratorID):
			copy := *node
			matches = append(matches, &copy)
		case label == "":
			copy := *node
			unlabeled = append(unlabeled, &copy)
		}
	}
	if len(matches) == 0 && len(unlabeled) == 1 {
		return unlabeled[0], nil
	}
	if len(matches) != 1 {
		message := fmt.Sprintf(
			"no registered isolated orchestrator has ID %q", orchestratorID)
		if len(matches) > 1 {
			message = fmt.Sprintf(
				"multiple registered isolated orchestrators have ID %q",
				orchestratorID)
		}
		return nil, &DomainError{
			Code: "ORCHESTRATOR_NODE_NOT_FOUND", Message: message,
		}
	}
	return matches[0], nil
}

func isOrchestratorNode(node *registry.Node, orchestratorID string) bool {
	if node == nil {
		return false
	}
	if strings.EqualFold(
		strings.TrimSpace(node.Role), isolatedOrchestratorRole,
	) {
		label := strings.TrimSpace(node.Labels[orchestratorIDLabel])
		return label == "" || strings.EqualFold(label, orchestratorID)
	}
	return strings.EqualFold(
		strings.TrimSpace(node.Labels[isolatedKindLabel]),
		isolatedOrchestratorRole,
	) && strings.EqualFold(
		strings.TrimSpace(node.Labels[orchestratorIDLabel]),
		orchestratorID,
	)
}

func (c *ApplianceRPCClient) clientFor(
	ctx context.Context,
	orchestratorID string,
	requireReady bool,
) (pb.NodeAgentClient, *registry.Node, ApplianceReadiness, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, ApplianceReadiness{}, err
	}
	node, err := c.resolveNode(orchestratorID)
	if err != nil {
		return nil, nil, ApplianceReadiness{}, err
	}
	endpoint := agentclient.Endpoint{
		Address:       strings.TrimSpace(node.Address),
		TLSServerName: strings.TrimSpace(node.TLSServerName),
	}
	if err := endpoint.ValidateStrict(); err != nil {
		return nil, nil, ApplianceReadiness{}, &DomainError{
			Code: "ORCHESTRATOR_TLS_IDENTITY_REQUIRED",
			Message: fmt.Sprintf(
				"node %q requires an explicit TLS server name: %v",
				node.Name, err),
		}
	}
	if endpoint.TLSServerName != strings.TrimSpace(node.Name) {
		return nil, nil, ApplianceReadiness{}, &DomainError{
			Code: "ORCHESTRATOR_TLS_IDENTITY_MISMATCH",
			Message: fmt.Sprintf(
				"node %q TLS server name %q does not match its node identity",
				node.Name, endpoint.TLSServerName),
		}
	}
	if !strings.EqualFold(strings.TrimSpace(node.TransportMode), "mtls") {
		return nil, nil, ApplianceReadiness{}, &DomainError{
			Code: "ORCHESTRATOR_TRANSPORT_INSECURE",
			Message: fmt.Sprintf(
				"node %q must use mTLS", node.Name),
		}
	}

	c.mu.Lock()
	previous, known := c.endpoints[orchestratorID]
	if known && previous != endpoint {
		c.pool.ResetEndpoint(previous)
	}
	c.endpoints[orchestratorID] = endpoint
	c.mu.Unlock()

	client, err := c.pool.GetEndpointClient(endpoint)
	if err != nil {
		return nil, nil, ApplianceReadiness{}, err
	}
	info, err := client.GetInfo(ctx, &pb.GetInfoRequest{})
	if err != nil {
		return nil, nil, ApplianceReadiness{}, translateApplianceError(ctx, err)
	}
	readiness := ApplianceReadiness{
		Node: node.Name, AgentVersion: info.GetAgentVersion(),
		Capabilities:    append([]string(nil), info.GetCapabilities()...),
		ProtocolVersion: info.GetProtocolVersion(),
		Ready:           info.GetApplianceReady(), Error: info.GetApplianceError(),
	}
	if err := CheckOrchestratorCompatibility(AgentCompatibility{
		Node: node.Name, AgentVersion: info.GetAgentVersion(),
		Capabilities:    info.GetCapabilities(),
		ProtocolVersion: info.GetProtocolVersion(),
	}, c.serverVersion); err != nil {
		return nil, nil, readiness, err
	}
	if requireReady && !readiness.Ready {
		return nil, nil, readiness, &appliance.StoreError{
			Code: appliance.CodeNotReady,
			Message: fallbackValue(
				readiness.Error, "appliance is not ready"),
		}
	}
	return client, node, readiness, nil
}

func (c *ApplianceRPCClient) CheckReadiness(
	ctx context.Context,
	orchestratorID string,
) (ApplianceReadiness, error) {
	_, _, readiness, err := c.clientFor(ctx, orchestratorID, false)
	if err != nil {
		return readiness, err
	}
	if !readiness.Ready {
		return readiness, &appliance.StoreError{
			Code: appliance.CodeNotReady,
			Message: fallbackValue(
				readiness.Error, "appliance is not ready"),
		}
	}
	return readiness, nil
}

func (c *ApplianceRPCClient) InspectApplianceState(
	ctx context.Context,
	orchestratorID string,
) (ApplianceSnapshot, error) {
	client, node, _, err := c.clientFor(ctx, orchestratorID, true)
	if err != nil {
		return ApplianceSnapshot{}, err
	}
	response, callErr := client.GetApplianceState(
		ctx, &pb.GetApplianceStateRequest{})
	if callErr != nil {
		return ApplianceSnapshot{},
			translateApplianceError(ctx, callErr)
	}
	if response.GetAppliance() == nil {
		return ApplianceSnapshot{}, &DomainError{
			Code:    "INVALID_APPLIANCE_RESPONSE",
			Message: "appliance state is missing",
		}
	}
	result := simpleApplianceSnapshot(response.GetAppliance())
	if result.SchemaVersion < MinimumApplianceSchema ||
		result.SchemaVersion > MaximumApplianceSchema {
		return ApplianceSnapshot{}, &appliance.StoreError{
			Code: appliance.CodeUnsupportedSchema,
			Message: fmt.Sprintf(
				"node reports appliance schema %d, supported range is %d-%d; run update_agent(node=%s)",
				result.SchemaVersion, MinimumApplianceSchema,
				MaximumApplianceSchema, node.Name),
		}
	}
	appendSimpleAppliancePage(&result, response)
	return result, nil
}

func (c *ApplianceRPCClient) ConfigureStatic(
	ctx context.Context,
	orchestratorID string,
	config appliance.StaticConfig,
	retire []appliance.RetiredNAT,
) (ApplianceSnapshot, error) {
	client, _, _, err := c.clientFor(ctx, orchestratorID, true)
	if err != nil {
		return ApplianceSnapshot{}, err
	}
	request := &pb.ConfigureIsolatedApplianceRequest{}
	for _, value := range config.Networks {
		var dns []string
		if strings.TrimSpace(value.DNSServersJSON) != "" {
			if err := json.Unmarshal(
				[]byte(value.DNSServersJSON), &dns,
			); err != nil {
				return ApplianceSnapshot{}, fmt.Errorf(
					"decode network %s DNS servers: %w", value.ID, err)
			}
		}
		request.Networks = append(
			request.Networks, &pb.ConfiguredPrivateNetwork{
				Id: value.ID, Cidr: value.CIDR,
				GatewayIpv4: value.GatewayIPv4, NicMac: value.NICMAC,
				InterfaceName: value.InterfaceName, DnsServers: dns,
			})
	}
	for _, value := range config.Guests {
		request.Guests = append(
			request.Guests, &pb.ConfiguredIsolatedGuest{
				Id: value.ID, NetworkId: value.NetworkID,
				Ipv4: value.IPv4, Mac: value.MAC,
			})
	}
	for _, value := range config.Relays {
		request.Relays = append(
			request.Relays, &pb.ConfiguredRelay{
				Id: value.ID, VmId: value.VMID,
				ListenPort: uint32(value.ListenPort),
				TargetIpv4: value.TargetIPv4,
			})
	}
	for _, value := range config.NAT {
		request.Nat = append(request.Nat, &pb.ConfiguredNat{
			VmId:          value.VMID,
			ConntrackMark: uint32(value.ConntrackMark),
			Enabled:       value.Enabled,
		})
	}
	for _, value := range retire {
		request.RetireNat = append(
			request.RetireNat, &pb.RetiredNatFlow{
				VmId: value.VMID, GuestIpv4: value.GuestIPv4,
				ConntrackMark: uint32(value.ConntrackMark),
			})
	}
	response, err := client.ConfigureIsolatedAppliance(ctx, request)
	if err != nil {
		return ApplianceSnapshot{}, translateApplianceError(ctx, err)
	}
	if response.GetState() == nil ||
		response.GetState().GetAppliance() == nil {
		return ApplianceSnapshot{}, &DomainError{
			Code:    "INVALID_APPLIANCE_RESPONSE",
			Message: "configured appliance state is missing",
		}
	}
	result := simpleApplianceSnapshot(response.GetState().GetAppliance())
	appendSimpleAppliancePage(&result, response.GetState())
	return result, nil
}

func (c *ApplianceRPCClient) GetRelayStats(
	ctx context.Context,
	orchestratorID, relayID string,
) (appliance.RelayStats, error) {
	client, _, _, err := c.clientFor(ctx, orchestratorID, true)
	if err != nil {
		return appliance.RelayStats{}, err
	}
	response, err := client.GetRelayStats(
		ctx, &pb.GetRelayStatsRequest{RelayId: relayID})
	if err != nil {
		return appliance.RelayStats{}, translateApplianceError(ctx, err)
	}
	return appliance.RelayStats{
		RelayID:                      response.GetRelayId(),
		ListenerState:                response.GetListenerState(),
		BindAddress:                  response.GetBindAddress(),
		ActiveConnections:            response.GetActiveConnections(),
		TotalAcceptedConnections:     response.GetTotalAcceptedConnections(),
		BytesGuestToMain:             response.GetBytesGuestToMain(),
		BytesMainToGuest:             response.GetBytesMainToGuest(),
		LastSuccessfulConnectionUnix: response.GetLastSuccessfulConnectionUnix(),
		TargetDialFailureCount:       response.GetTargetDialFailureCount(),
		LastFailure:                  response.GetLastFailure(),
	}, nil
}

func (c *ApplianceRPCClient) ValidateRelay(
	ctx context.Context,
	orchestratorID, relayID string,
	probeTarget bool,
) (RelayValidation, error) {
	client, _, _, err := c.clientFor(ctx, orchestratorID, true)
	if err != nil {
		return RelayValidation{}, err
	}
	response, err := client.ValidateRelay(
		ctx, &pb.ValidateRelayRequest{
			RelayId: relayID, ProbeTarget: probeTarget,
		})
	if err != nil {
		return RelayValidation{}, translateApplianceError(ctx, err)
	}
	relay := response.GetRelay()
	return RelayValidation{
		Relay: appliance.Relay{
			ID: relay.GetId(), VMID: relay.GetVmId(),
			ListenPort: int64(relay.GetListenPort()),
			TargetIPv4: relay.GetTargetIpv4(),
			TargetPort: int64(relay.GetTargetPort()),
			State:      relay.GetState(), BoundMainIP: relay.GetBoundMainIp(),
			LastBindError: relay.GetLastBindError(),
		},
		ListenerValid:   response.GetListenerValid(),
		MappingValid:    response.GetMappingValid(),
		TargetReachable: response.GetTargetReachable(),
		Message:         response.GetMessage(),
	}, nil
}

func simpleApplianceSnapshot(value *pb.ApplianceState) ApplianceSnapshot {
	if value == nil {
		return ApplianceSnapshot{}
	}
	return ApplianceSnapshot{
		SchemaVersion:   value.GetSchemaVersion(),
		ProtocolVersion: value.GetProtocolVersion(),
		Ready:           value.GetReady(), MainIPv4: value.GetMainIpv4(),
		PolicyVerified: value.GetPolicyVerified(),
		IPv4Forwarding: value.GetIpv4ForwardingEnabled(),
		Error:          value.GetError(),
	}
}

func appendSimpleAppliancePage(
	result *ApplianceSnapshot,
	response *pb.GetApplianceStateResponse,
) {
	for _, value := range response.GetNetworks() {
		if value == nil {
			continue
		}
		dns, _ := json.Marshal(value.GetDnsServers())
		result.Config.Networks = append(
			result.Config.Networks, appliance.Network{
				ID: value.GetId(), CIDR: value.GetCidr(),
				GatewayIPv4:    value.GetGatewayIpv4(),
				NICMAC:         value.GetNicMac(),
				InterfaceName:  value.GetInterfaceName(),
				DNSServersJSON: string(dns), State: value.GetState(),
			})
	}
	for _, value := range response.GetGuests() {
		if value == nil {
			continue
		}
		result.Config.Guests = append(
			result.Config.Guests, appliance.Guest{
				ID: value.GetId(), NetworkID: value.GetNetworkId(),
				IPv4: value.GetIpv4(), MAC: value.GetMac(),
				State: "active",
			})
	}
	for _, value := range response.GetRelays() {
		if value == nil {
			continue
		}
		result.Config.Relays = append(
			result.Config.Relays, appliance.Relay{
				ID: value.GetId(), VMID: value.GetVmId(),
				ListenPort: int64(value.GetListenPort()),
				TargetIPv4: value.GetTargetIpv4(),
				TargetPort: int64(value.GetTargetPort()),
				State:      value.GetState(), BoundMainIP: value.GetBoundMainIp(),
				LastBindError: value.GetLastBindError(),
			})
	}
	for _, value := range response.GetNatStates() {
		if value == nil {
			continue
		}
		result.Config.NAT = append(
			result.Config.NAT, appliance.NATState{
				VMID: value.GetVmId(), State: value.GetState(),
				ConntrackMark: int64(value.GetConntrackMark()),
			})
	}
}

func translateApplianceError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}
