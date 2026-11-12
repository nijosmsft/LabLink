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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

// ApplianceRPCClient adapts registered isolated-orchestrator nodes to the
// appliance domain interfaces.
type ApplianceRPCClient struct {
	registry      applianceNodeRegistry
	pool          applianceClientPool
	serverVersion string

	mu        sync.Mutex
	endpoints map[string]agentclient.Endpoint
}

var _ ApplianceClient = (*ApplianceRPCClient)(nil)

// NewApplianceRPCClient creates a fail-closed appliance API adapter.
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

// NewApplianceClient creates the production appliance adapter.
func NewApplianceClient(
	reg *registry.Registry,
	pool *agentclient.Pool,
	serverVersion string,
) *ApplianceRPCClient {
	return NewApplianceRPCClient(reg, pool, serverVersion)
}

// ApplianceReadiness is the capability and readiness result reported by an
// orchestrator agent.
type ApplianceReadiness struct {
	Node                string
	AgentVersion        string
	Capabilities        []string
	ProtocolVersion     uint32
	Ready               bool
	ApplianceGeneration uint64
	Error               string
}

// GenerationState is the version tuple returned for a durable mutation.
type GenerationState struct {
	Desired  uint64
	Applied  uint64
	Observed uint64
	Parent   uint64
}

// FenceState describes the accepted physical-host authority without exposing
// its lease secret.
type FenceState struct {
	PhysicalHostID   string
	HostFence        uint64
	HostLeaseID      string
	ParentResourceID string
	ParentGeneration uint64
	Frozen           bool
	Deleting         bool
	Lost             bool
}

// MutationEnvelope contains the complete mutation authority sent on the wire.
type MutationEnvelope struct {
	Header              appliance.MutationHeader
	PhysicalHostID      string
	HostLeaseID         string
	HostLeaseSecret     []byte
	CascadeOperationID  string
	CascadePlanRevision string
	CascadePlanHash     string
	CascadeItemID       string
}

// MutationResult is the typed durable result of an appliance mutation.
type MutationResult struct {
	MutationID          string
	SemanticHash        string
	CompiledHash        string
	Generation          GenerationState
	Replayed            bool
	ApplianceGeneration uint64
	Pending             bool
}

// ApplyIntent is an incomplete or recoverable appliance mutation.
type ApplyIntent struct {
	MutationID        string
	ResourceKind      string
	ResourceID        string
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

// ApplianceSnapshot contains the complete paged appliance inventory.
type ApplianceSnapshot struct {
	SchemaVersion       uint32
	ProtocolVersion     uint32
	Ready               bool
	ApplianceGeneration uint64
	InventoryGeneration uint64
	Fence               FenceState
	MainIPv4            string
	PolicyVerified      bool
	IPv4Forwarding      bool
	Error               string
	Desired             appliance.DesiredSnapshot
	ApplyIntents        []ApplyIntent
}

type NetworkMutationResult struct {
	Network  appliance.Network
	Mutation MutationResult
	Pending  bool
}

type GuestMutationResult struct {
	Guest    appliance.Guest
	Mutation MutationResult
	Pending  bool
}

type RelayMutationResult struct {
	Relay    appliance.Relay
	Mutation MutationResult
	Pending  bool
}

type NATMutationResult struct {
	NAT      appliance.NATState
	Mutation MutationResult
	Pending  bool
}

type ApplyPrivateNetworkInput struct {
	Header        MutationEnvelope
	ReservationID string
	CIDR          string
	GatewayIPv4   string
	NICMAC        string
	InterfaceName string
	DNSServers    []string
}

type RegisterGuestInput struct {
	Header        MutationEnvelope
	ReservationID string
	NetworkID     string
	IPv4          string
	MAC           string
}

type RelayInput struct {
	Header        MutationEnvelope
	ReservationID string
	VMID          string
	NetworkID     string
	ListenPort    uint32
	TargetIPv4    string
}

type NATInput struct {
	Header        MutationEnvelope
	ReservationID string
	NetworkID     string
	DesiredState  string
	ConntrackMark uint32
}

type RelayList struct {
	Relays              []appliance.Relay
	NextPageToken       string
	ApplianceGeneration uint64
}

type NATList struct {
	States              []appliance.NATState
	NextPageToken       string
	ApplianceGeneration uint64
}

type RelayValidation struct {
	Relay               appliance.Relay
	ListenerValid       bool
	MappingValid        bool
	GenerationValid     bool
	TargetReachable     bool
	Message             string
	ApplianceGeneration uint64
}

// ApplianceStatusError preserves the original gRPC status and details while
// exposing the appliance domain code through errors.As and ErrorCodeOf.
type ApplianceStatusError struct {
	Status              *status.Status
	Code                appliance.ErrorCode
	ResourceID          string
	InventoryGeneration uint64
	Generation          GenerationState
	Fence               FenceState
	Collision           *appliance.CollisionError
	contextErr          error
}

func (e *ApplianceStatusError) Error() string {
	if e == nil || e.Status == nil {
		return ""
	}
	return e.Status.Err().Error()
}

func (e *ApplianceStatusError) GRPCStatus() *status.Status {
	if e == nil {
		return nil
	}
	return e.Status
}

func (e *ApplianceStatusError) Unwrap() error {
	if e == nil {
		return nil
	}
	if e.contextErr != nil {
		return e.contextErr
	}
	if e.Collision != nil {
		return e.Collision
	}
	if e.Code != "" {
		return &appliance.StoreError{Code: e.Code, Message: e.Status.Message()}
	}
	return e.Status.Err()
}

func (c *ApplianceRPCClient) resolveNode(orchestratorID string) (*registry.Node, error) {
	if c == nil || c.registry == nil || c.pool == nil {
		return nil, errors.New("isolated: appliance registry and client pool are required")
	}
	orchestratorID = strings.TrimSpace(orchestratorID)
	if orchestratorID == "" {
		return nil, &DomainError{Code: "ORCHESTRATOR_NODE_NOT_FOUND", Message: "orchestrator ID is required"}
	}
	if node, ok := c.registry.GetNode(orchestratorID); ok && isOrchestratorNode(node, orchestratorID) {
		copy := *node
		return &copy, nil
	}
	var matches []*registry.Node
	for _, node := range c.registry.NodesByRole(isolatedOrchestratorRole) {
		if node != nil && strings.EqualFold(strings.TrimSpace(node.Labels[orchestratorIDLabel]), orchestratorID) {
			copy := *node
			matches = append(matches, &copy)
		}
	}
	if len(matches) != 1 {
		message := fmt.Sprintf("no registered isolated orchestrator has ID %q", orchestratorID)
		if len(matches) > 1 {
			message = fmt.Sprintf("multiple registered isolated orchestrators have ID %q", orchestratorID)
		}
		return nil, &DomainError{Code: "ORCHESTRATOR_NODE_NOT_FOUND", Message: message}
	}
	return matches[0], nil
}

func isOrchestratorNode(node *registry.Node, orchestratorID string) bool {
	if node == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(node.Role), isolatedOrchestratorRole) {
		label := strings.TrimSpace(node.Labels[orchestratorIDLabel])
		return label == "" || strings.EqualFold(label, orchestratorID)
	}
	return strings.EqualFold(strings.TrimSpace(node.Labels[isolatedKindLabel]), isolatedOrchestratorRole) &&
		strings.EqualFold(strings.TrimSpace(node.Labels[orchestratorIDLabel]), orchestratorID)
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
		Address: strings.TrimSpace(node.Address), TLSServerName: strings.TrimSpace(node.TLSServerName),
	}
	if err := endpoint.ValidateStrict(); err != nil {
		return nil, nil, ApplianceReadiness{}, &DomainError{
			Code:    "ORCHESTRATOR_TLS_IDENTITY_REQUIRED",
			Message: fmt.Sprintf("node %q requires an explicit TLS server name: %v", node.Name, err),
		}
	}
	if endpoint.TLSServerName != strings.TrimSpace(node.Name) {
		return nil, nil, ApplianceReadiness{}, &DomainError{
			Code: "ORCHESTRATOR_TLS_IDENTITY_MISMATCH",
			Message: fmt.Sprintf("node %q TLS server name %q does not match its immutable node identity",
				node.Name, endpoint.TLSServerName),
		}
	}
	if !strings.EqualFold(strings.TrimSpace(node.TransportMode), "mtls") {
		return nil, nil, ApplianceReadiness{}, &DomainError{
			Code:    "ORCHESTRATOR_TRANSPORT_INSECURE",
			Message: fmt.Sprintf("node %q must use mTLS; no TLS fallback is allowed", node.Name),
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
		ProtocolVersion: info.GetProtocolVersion(), Ready: info.GetApplianceReady(),
		ApplianceGeneration: info.GetApplianceGeneration(), Error: info.GetApplianceError(),
	}
	if err := CheckOrchestratorCompatibility(AgentCompatibility{
		Node: node.Name, AgentVersion: info.GetAgentVersion(),
		Capabilities: info.GetCapabilities(), ProtocolVersion: info.GetProtocolVersion(),
	}, c.serverVersion); err != nil {
		return nil, nil, readiness, err
	}
	if requireReady && !readiness.Ready {
		message := strings.TrimSpace(readiness.Error)
		if message == "" {
			message = "appliance is not ready"
		}
		return nil, nil, readiness, &appliance.StoreError{
			Code: appliance.CodeNotReady,
			Message: fmt.Sprintf("%s on node %q; run update_agent(node=%s) if the agent is outdated",
				message, node.Name, node.Name),
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
			Code:    appliance.CodeNotReady,
			Message: fallbackValue(readiness.Error, "appliance is not ready"),
		}
	}
	return readiness, nil
}

// GetApplianceState implements ApplianceClient.
func (c *ApplianceRPCClient) GetApplianceState(
	ctx context.Context,
	orchestratorID string,
) (appliance.DesiredSnapshot, error) {
	snapshot, err := c.InspectApplianceState(ctx, orchestratorID)
	return snapshot.Desired, err
}

func (c *ApplianceRPCClient) InspectApplianceState(
	ctx context.Context,
	orchestratorID string,
) (ApplianceSnapshot, error) {
	client, node, _, err := c.clientFor(ctx, orchestratorID, true)
	if err != nil {
		return ApplianceSnapshot{}, err
	}
	var result ApplianceSnapshot
	token := ""
	for {
		response, callErr := client.GetApplianceState(ctx, &pb.GetApplianceStateRequest{
			PageSize: 500, PageToken: token, IncludeTombstones: true,
		})
		if callErr != nil {
			return ApplianceSnapshot{}, translateApplianceError(ctx, callErr)
		}
		if response.GetAppliance() == nil {
			return ApplianceSnapshot{}, &DomainError{
				Code: "INVALID_APPLIANCE_RESPONSE", Message: "appliance state is missing",
			}
		}
		if token == "" {
			result = applianceSnapshot(response.GetAppliance())
			if result.SchemaVersion < MinimumApplianceSchema ||
				result.SchemaVersion > MaximumApplianceSchema {
				return ApplianceSnapshot{}, &appliance.StoreError{
					Code: appliance.CodeUnsupportedSchema,
					Message: fmt.Sprintf("node reports appliance schema %d, supported range is %d-%d; run update_agent(node=%s)",
						result.SchemaVersion, MinimumApplianceSchema, MaximumApplianceSchema, node.Name),
				}
			}
			if result.ProtocolVersion < MinimumProtocolVersion ||
				result.ProtocolVersion > MaximumProtocolVersion {
				return ApplianceSnapshot{}, &CompatibilityError{
					Code: "AGENT_PROTOCOL_UNSUPPORTED", Node: node.Name,
					ServerVersion: c.serverVersion, ProtocolVersion: result.ProtocolVersion,
					SupportedProtocol: ProtocolRange{
						Minimum: MinimumProtocolVersion, Maximum: MaximumProtocolVersion,
					},
				}
			}
			if !result.Ready {
				return ApplianceSnapshot{}, &appliance.StoreError{
					Code:    appliance.CodeNotReady,
					Message: fallbackValue(result.Error, "appliance state is not ready"),
				}
			}
		}
		appendAppliancePage(&result, response)
		token = response.GetNextPageToken()
		if token == "" {
			break
		}
	}
	return result, nil
}

// ReserveResources implements ApplianceClient.
func (c *ApplianceRPCClient) ReserveResources(
	ctx context.Context,
	orchestratorID string,
	request appliance.ReserveRequest,
) (appliance.ReserveResult, error) {
	client, _, _, err := c.clientFor(ctx, orchestratorID, true)
	if err != nil {
		return appliance.ReserveResult{}, err
	}
	wire := &pb.ReserveResourcesRequest{
		Header: mutationHeaderProto(MutationEnvelope{Header: request.Header}),
	}
	for _, value := range request.Reservations {
		wire.Candidates = append(wire.Candidates, reservationCandidateProto(value))
	}
	response, err := client.ReserveResources(ctx, wire)
	if err != nil {
		return appliance.ReserveResult{}, translateApplianceError(ctx, err)
	}
	result := appliance.ReserveResult{
		ParentGeneration:    response.GetResultingParentGeneration(),
		InventoryGeneration: response.GetInventoryGeneration(),
		Replay:              response.GetMutation().GetReplayed(),
	}
	for _, value := range response.GetReservations() {
		result.Reservations = append(result.Reservations, reservationFromProto(value))
	}
	return result, nil
}

func (c *ApplianceRPCClient) ReleaseResources(
	ctx context.Context,
	orchestratorID string,
	request appliance.ReleaseRequest,
) (appliance.ReleaseResult, error) {
	client, _, _, err := c.clientFor(ctx, orchestratorID, true)
	if err != nil {
		return appliance.ReleaseResult{}, err
	}
	response, err := client.ReleaseResources(ctx, &pb.ReleaseResourcesRequest{
		Header:         mutationHeaderProto(MutationEnvelope{Header: request.Header}),
		ReservationIds: append([]string(nil), request.ReservationIDs...),
	})
	if err != nil {
		return appliance.ReleaseResult{}, translateApplianceError(ctx, err)
	}
	result := appliance.ReleaseResult{
		ParentGeneration:    response.GetResultingParentGeneration(),
		InventoryGeneration: response.GetInventoryGeneration(),
		Replay:              response.GetMutation().GetReplayed(),
	}
	for _, value := range response.GetReservations() {
		if value != nil {
			result.RetiredIDs = append(result.RetiredIDs, value.GetId())
		}
	}
	return result, nil
}

func (c *ApplianceRPCClient) ApplyPrivateNetwork(
	ctx context.Context,
	orchestratorID string,
	input ApplyPrivateNetworkInput,
) (NetworkMutationResult, error) {
	client, _, _, err := c.clientFor(ctx, orchestratorID, true)
	if err != nil {
		return NetworkMutationResult{}, err
	}
	response, err := client.ApplyPrivateNetwork(ctx, &pb.ApplyPrivateNetworkRequest{
		Header: mutationHeaderProto(input.Header), ReservationId: input.ReservationID,
		Cidr: input.CIDR, GatewayIpv4: input.GatewayIPv4, NicMac: input.NICMAC,
		InterfaceName: input.InterfaceName, DnsServers: append([]string(nil), input.DNSServers...),
	})
	if err != nil {
		return NetworkMutationResult{}, translateApplianceError(ctx, err)
	}
	network := networkFromProto(response.GetNetwork())
	mutation := mutationFromProto(response.GetMutation())
	pending := resourcePending(network.State, mutation.Generation)
	mutation.Pending = pending
	return NetworkMutationResult{Network: network, Mutation: mutation, Pending: pending}, nil
}

func (c *ApplianceRPCClient) RemovePrivateNetwork(
	ctx context.Context,
	orchestratorID string,
	header MutationEnvelope,
) (NetworkMutationResult, error) {
	client, _, _, err := c.clientFor(ctx, orchestratorID, true)
	if err != nil {
		return NetworkMutationResult{}, err
	}
	response, err := client.RemovePrivateNetwork(ctx, &pb.RemovePrivateNetworkRequest{
		Header: mutationHeaderProto(header),
	})
	if err != nil {
		return NetworkMutationResult{}, translateApplianceError(ctx, err)
	}
	network := networkFromProto(response.GetNetwork())
	mutation := mutationFromProto(response.GetMutation())
	pending := resourcePending(network.State, mutation.Generation)
	mutation.Pending = pending
	return NetworkMutationResult{Network: network, Mutation: mutation, Pending: pending}, nil
}

func (c *ApplianceRPCClient) RegisterIsolatedGuest(
	ctx context.Context,
	orchestratorID string,
	input RegisterGuestInput,
) (GuestMutationResult, error) {
	client, _, _, err := c.clientFor(ctx, orchestratorID, true)
	if err != nil {
		return GuestMutationResult{}, err
	}
	response, err := client.RegisterIsolatedGuest(ctx, &pb.RegisterIsolatedGuestRequest{
		Header: mutationHeaderProto(input.Header), ReservationId: input.ReservationID,
		NetworkId: input.NetworkID, Ipv4: input.IPv4, Mac: input.MAC,
	})
	if err != nil {
		return GuestMutationResult{}, translateApplianceError(ctx, err)
	}
	guest := guestFromProto(response.GetGuest())
	mutation := mutationFromProto(response.GetMutation())
	pending := resourcePending(guest.State, mutation.Generation)
	mutation.Pending = pending
	return GuestMutationResult{Guest: guest, Mutation: mutation, Pending: pending}, nil
}

func (c *ApplianceRPCClient) RemoveIsolatedGuest(
	ctx context.Context,
	orchestratorID string,
	header MutationEnvelope,
	networkID string,
) (GuestMutationResult, error) {
	client, _, _, err := c.clientFor(ctx, orchestratorID, true)
	if err != nil {
		return GuestMutationResult{}, err
	}
	response, err := client.RemoveIsolatedGuest(ctx, &pb.RemoveIsolatedGuestRequest{
		Header: mutationHeaderProto(header), NetworkId: networkID,
	})
	if err != nil {
		return GuestMutationResult{}, translateApplianceError(ctx, err)
	}
	guest := guestFromProto(response.GetGuest())
	mutation := mutationFromProto(response.GetMutation())
	pending := resourcePending(guest.State, mutation.Generation)
	mutation.Pending = pending
	return GuestMutationResult{Guest: guest, Mutation: mutation, Pending: pending}, nil
}

func (c *ApplianceRPCClient) ApplyRelay(
	ctx context.Context,
	orchestratorID string,
	input RelayInput,
) (RelayMutationResult, error) {
	return c.relayMutation(ctx, orchestratorID, input, false)
}

func (c *ApplianceRPCClient) AdoptRelay(
	ctx context.Context,
	orchestratorID string,
	input RelayInput,
) (RelayMutationResult, error) {
	return c.relayMutation(ctx, orchestratorID, input, true)
}

func (c *ApplianceRPCClient) relayMutation(
	ctx context.Context,
	orchestratorID string,
	input RelayInput,
	adopt bool,
) (RelayMutationResult, error) {
	client, _, _, err := c.clientFor(ctx, orchestratorID, true)
	if err != nil {
		return RelayMutationResult{}, err
	}
	var value *pb.Relay
	if adopt {
		value, err = client.AdoptRelay(ctx, &pb.AdoptRelayRequest{
			Header: mutationHeaderProto(input.Header), ReservationId: input.ReservationID,
			VmId: input.VMID, NetworkId: input.NetworkID,
			ListenPort: input.ListenPort, TargetIpv4: input.TargetIPv4,
		})
	} else {
		value, err = client.ApplyRelay(ctx, &pb.ApplyRelayRequest{
			Header: mutationHeaderProto(input.Header), ReservationId: input.ReservationID,
			VmId: input.VMID, NetworkId: input.NetworkID,
			ListenPort: input.ListenPort, TargetIpv4: input.TargetIPv4,
		})
	}
	if err != nil {
		return RelayMutationResult{}, translateApplianceError(ctx, err)
	}
	relay := relayFromProto(value)
	mutation := mutationFromHeader(input.Header, generationFromProto(value.GetGeneration()))
	pending := resourcePending(relay.State, mutation.Generation)
	mutation.Pending = pending
	return RelayMutationResult{Relay: relay, Mutation: mutation, Pending: pending}, nil
}

func (c *ApplianceRPCClient) RemoveRelay(
	ctx context.Context,
	orchestratorID string,
	header MutationEnvelope,
	vmID, networkID string,
) (RelayMutationResult, error) {
	client, _, _, err := c.clientFor(ctx, orchestratorID, true)
	if err != nil {
		return RelayMutationResult{}, err
	}
	value, err := client.RemoveRelay(ctx, &pb.RemoveRelayRequest{
		Header: mutationHeaderProto(header), VmId: vmID, NetworkId: networkID,
	})
	if err != nil {
		return RelayMutationResult{}, translateApplianceError(ctx, err)
	}
	relay := relayFromProto(value)
	mutation := mutationFromHeader(header, generationFromProto(value.GetGeneration()))
	pending := resourcePending(relay.State, mutation.Generation)
	mutation.Pending = pending
	return RelayMutationResult{Relay: relay, Mutation: mutation, Pending: pending}, nil
}

func (c *ApplianceRPCClient) ListRelays(
	ctx context.Context,
	orchestratorID, networkID, vmID string,
	includeRetired bool,
	pageSize uint32,
	pageToken string,
) (RelayList, error) {
	client, _, _, err := c.clientFor(ctx, orchestratorID, true)
	if err != nil {
		return RelayList{}, err
	}
	response, err := client.ListRelays(ctx, &pb.ListRelaysRequest{
		NetworkId: networkID, VmId: vmID, IncludeRetired: includeRetired,
		PageSize: pageSize, PageToken: pageToken,
	})
	if err != nil {
		return RelayList{}, translateApplianceError(ctx, err)
	}
	result := RelayList{
		NextPageToken:       response.GetNextPageToken(),
		ApplianceGeneration: response.GetApplianceGeneration(),
	}
	for _, value := range response.GetRelays() {
		result.Relays = append(result.Relays, relayFromProto(value))
	}
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
	value, err := client.GetRelayStats(ctx, &pb.GetRelayStatsRequest{RelayId: relayID})
	if err != nil {
		return appliance.RelayStats{}, translateApplianceError(ctx, err)
	}
	return appliance.RelayStats{
		RelayID: value.GetRelayId(), ListenerState: value.GetListenerState(),
		BindAddress: value.GetBindAddress(), ActiveConnections: value.GetActiveConnections(),
		TotalAcceptedConnections: value.GetTotalAcceptedConnections(),
		BytesGuestToMain:         value.GetBytesGuestToMain(), BytesMainToGuest: value.GetBytesMainToGuest(),
		LastSuccessfulConnectionUnix: value.GetLastSuccessfulConnectionUnix(),
		TargetDialFailureCount:       value.GetTargetDialFailureCount(), LastFailure: value.GetLastFailure(),
		RelayGeneration: value.GetRelayGeneration(), ApplianceGeneration: value.GetApplianceGeneration(),
	}, nil
}

func (c *ApplianceRPCClient) RebindRelays(
	ctx context.Context,
	orchestratorID string,
	header MutationEnvelope,
) ([]appliance.Relay, MutationResult, error) {
	client, node, _, err := c.clientFor(ctx, orchestratorID, true)
	if err != nil {
		return nil, MutationResult{}, err
	}
	endpoint := agentclient.Endpoint{Address: node.Address, TLSServerName: node.TLSServerName}
	response, callErr := client.RebindRelays(ctx, &pb.RebindRelaysRequest{
		Header: mutationHeaderProto(header),
	})
	c.pool.ResetEndpoint(endpoint)
	if callErr != nil {
		return nil, MutationResult{}, translateApplianceError(ctx, callErr)
	}
	relays := make([]appliance.Relay, 0, len(response.GetRelays()))
	for _, value := range response.GetRelays() {
		relays = append(relays, relayFromProto(value))
	}
	return relays, mutationFromProto(response.GetMutation()), nil
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
	value, err := client.ValidateRelay(ctx, &pb.ValidateRelayRequest{
		RelayId: relayID, ProbeTarget: probeTarget,
	})
	if err != nil {
		return RelayValidation{}, translateApplianceError(ctx, err)
	}
	return RelayValidation{
		Relay: relayFromProto(value.GetRelay()), ListenerValid: value.GetListenerValid(),
		MappingValid: value.GetMappingValid(), GenerationValid: value.GetGenerationValid(),
		TargetReachable: value.GetTargetReachable(), Message: value.GetMessage(),
		ApplianceGeneration: value.GetApplianceGeneration(),
	}, nil
}

func (c *ApplianceRPCClient) SetNATState(
	ctx context.Context,
	orchestratorID string,
	input NATInput,
) (NATMutationResult, error) {
	client, _, _, err := c.clientFor(ctx, orchestratorID, true)
	if err != nil {
		return NATMutationResult{}, err
	}
	value, err := client.SetNatState(ctx, &pb.SetNatStateRequest{
		Header: mutationHeaderProto(input.Header), ReservationId: input.ReservationID,
		NetworkId: input.NetworkID, DesiredState: input.DesiredState,
		ConntrackMark: input.ConntrackMark,
	})
	if err != nil {
		return NATMutationResult{}, translateApplianceError(ctx, err)
	}
	nat := natFromProto(value)
	mutation := mutationFromHeader(input.Header, generationFromProto(value.GetGeneration()))
	pending := resourcePending(nat.State, mutation.Generation)
	mutation.Pending = pending
	return NATMutationResult{NAT: nat, Mutation: mutation, Pending: pending}, nil
}

// SetNatState is the generated-RPC-casing alias for SetNATState.
func (c *ApplianceRPCClient) SetNatState(
	ctx context.Context,
	orchestratorID string,
	input NATInput,
) (NATMutationResult, error) {
	return c.SetNATState(ctx, orchestratorID, input)
}

func (c *ApplianceRPCClient) ListNATState(
	ctx context.Context,
	orchestratorID, networkID, vmID, desiredState string,
	pageSize uint32,
	pageToken string,
) (NATList, error) {
	client, _, _, err := c.clientFor(ctx, orchestratorID, true)
	if err != nil {
		return NATList{}, err
	}
	response, err := client.ListNatState(ctx, &pb.ListNatStateRequest{
		NetworkId: networkID, VmId: vmID, State: desiredState,
		PageSize: pageSize, PageToken: pageToken,
	})
	if err != nil {
		return NATList{}, translateApplianceError(ctx, err)
	}
	result := NATList{
		NextPageToken:       response.GetNextPageToken(),
		ApplianceGeneration: response.GetApplianceGeneration(),
	}
	for _, value := range response.GetNatStates() {
		result.States = append(result.States, natFromProto(value))
	}
	return result, nil
}

// ListNatState is the generated-RPC-casing alias for ListNATState.
func (c *ApplianceRPCClient) ListNatState(
	ctx context.Context,
	orchestratorID, networkID, vmID, desiredState string,
	pageSize uint32,
	pageToken string,
) (NATList, error) {
	return c.ListNATState(
		ctx, orchestratorID, networkID, vmID, desiredState, pageSize, pageToken,
	)
}

func (c *ApplianceRPCClient) ReconcileNAT(
	ctx context.Context,
	orchestratorID string,
	header MutationEnvelope,
	networkID string,
) (NATMutationResult, error) {
	client, _, _, err := c.clientFor(ctx, orchestratorID, true)
	if err != nil {
		return NATMutationResult{}, err
	}
	response, err := client.ReconcileNat(ctx, &pb.ReconcileNatRequest{
		Header: mutationHeaderProto(header), NetworkId: networkID,
	})
	if err != nil {
		return NATMutationResult{}, translateApplianceError(ctx, err)
	}
	nat := natFromProto(response.GetNatState())
	mutation := mutationFromProto(response.GetMutation())
	pending := resourcePending(nat.State, mutation.Generation)
	mutation.Pending = pending
	return NATMutationResult{NAT: nat, Mutation: mutation, Pending: pending}, nil
}

// ReconcileNat is the generated-RPC-casing alias for ReconcileNAT.
func (c *ApplianceRPCClient) ReconcileNat(
	ctx context.Context,
	orchestratorID string,
	header MutationEnvelope,
	networkID string,
) (NATMutationResult, error) {
	return c.ReconcileNAT(ctx, orchestratorID, header, networkID)
}

func applianceSnapshot(value *pb.ApplianceState) ApplianceSnapshot {
	result := ApplianceSnapshot{
		SchemaVersion: value.GetSchemaVersion(), ProtocolVersion: value.GetProtocolVersion(),
		Ready: value.GetReady(), ApplianceGeneration: value.GetApplianceGeneration(),
		InventoryGeneration: value.GetInventoryGeneration(), Fence: fenceFromProto(value.GetFence()),
		MainIPv4: value.GetMainIpv4(), PolicyVerified: value.GetPolicyVerified(),
		IPv4Forwarding: value.GetIpv4ForwardingEnabled(), Error: value.GetError(),
	}
	result.Desired.Status = appliance.Status{
		InventoryGeneration: result.InventoryGeneration, Ready: result.Ready, Error: result.Error,
	}
	result.Desired.Authority = appliance.Authority{
		PhysicalHostID: result.Fence.PhysicalHostID, HostLeaseID: result.Fence.HostLeaseID,
		Fence: result.Fence.HostFence, ParentGeneration: result.Fence.ParentGeneration,
		ParentState: fenceParentState(result.Fence),
	}
	return result
}

func appendAppliancePage(result *ApplianceSnapshot, response *pb.GetApplianceStateResponse) {
	for _, value := range response.GetReservations() {
		result.Desired.Reservations = append(result.Desired.Reservations, reservationFromProto(value))
	}
	for _, value := range response.GetNetworks() {
		result.Desired.Networks = append(result.Desired.Networks, networkFromProto(value))
	}
	for _, value := range response.GetGuests() {
		result.Desired.Guests = append(result.Desired.Guests, guestFromProto(value))
	}
	for _, value := range response.GetRelays() {
		result.Desired.Relays = append(result.Desired.Relays, relayFromProto(value))
	}
	for _, value := range response.GetNatStates() {
		result.Desired.NAT = append(result.Desired.NAT, natFromProto(value))
	}
	for _, value := range response.GetApplyIntents() {
		if value == nil {
			continue
		}
		result.ApplyIntents = append(result.ApplyIntents, ApplyIntent{
			MutationID: value.GetMutationId(), ResourceKind: value.GetResourceKind(),
			ResourceID: value.GetResourceId(), DesiredGeneration: value.GetDesiredGeneration(),
			ParentGeneration: value.GetParentGeneration(), Fence: value.GetFence(),
			SemanticHash: value.GetSemanticHash(), CompiledHash: value.GetCompiledHash(),
			Phase: value.GetPhase(), Error: value.GetErrorText(),
			CreatedAtUnix: value.GetCreatedAtUnix(), UpdatedAtUnix: value.GetUpdatedAtUnix(),
		})
	}
}

func mutationHeaderProto(value MutationEnvelope) *pb.MutationHeader {
	header := value.Header
	return &pb.MutationHeader{
		ParentOperationId: header.ParentOperationID, MutationId: header.MutationID,
		SemanticHash: header.SemanticHash, ResourceId: header.ResourceID,
		ExpectedGeneration: header.ExpectedGeneration, NewGeneration: header.NewGeneration,
		PhysicalHostId: value.PhysicalHostID, HostFence: header.HostFence,
		ParentResourceId:         header.ParentResourceID,
		ExpectedParentGeneration: header.ExpectedParentGeneration,
		HostLeaseId:              value.HostLeaseID, HostLeaseSecret: append([]byte(nil), value.HostLeaseSecret...),
		CascadeOperationId: value.CascadeOperationID, CascadePlanRevision: value.CascadePlanRevision,
		CascadePlanHash: value.CascadePlanHash, CascadeItemId: value.CascadeItemID,
	}
}

func reservationCandidateProto(value appliance.Reservation) *pb.ReservationCandidate {
	result := &pb.ReservationCandidate{
		ResourceKind: value.ResourceKind, ResourceId: value.ResourceID,
		NetworkId: value.NetworkID, Ipv4: value.IPv4, Mac: value.MAC,
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
	return result
}

func reservationFromProto(value *pb.Reservation) appliance.Reservation {
	if value == nil {
		return appliance.Reservation{}
	}
	result := appliance.Reservation{
		ID: value.GetId(), ResourceKind: value.GetResourceKind(), ResourceID: value.GetResourceId(),
		NetworkID: value.GetNetworkId(), IPv4: value.GetIpv4(), MAC: value.GetMac(),
		State: value.GetState(), ParentGeneration: value.GetParentGeneration(),
		CreatedAtUnix: value.GetCreatedAtUnix(),
	}
	if value.SubnetIndex != nil {
		v := int64(value.GetSubnetIndex())
		result.SubnetIndex = &v
	}
	if value.ListenPort != nil {
		v := int64(value.GetListenPort())
		result.ListenPort = &v
	}
	if value.ConntrackMark != nil {
		v := int64(value.GetConntrackMark())
		result.ConntrackMark = &v
	}
	if value.GetRetiredAtUnix() != 0 {
		v := value.GetRetiredAtUnix()
		result.RetiredAtUnix = &v
	}
	return result
}

func networkFromProto(value *pb.PrivateNetwork) appliance.Network {
	if value == nil {
		return appliance.Network{}
	}
	dns, _ := json.Marshal(value.GetDnsServers())
	generation := generationFromProto(value.GetGeneration())
	return appliance.Network{
		ID: value.GetId(), CIDR: value.GetCidr(), GatewayIPv4: value.GetGatewayIpv4(),
		NICMAC: value.GetNicMac(), InterfaceName: value.GetInterfaceName(),
		DNSServersJSON: string(dns), DesiredGeneration: generation.Desired,
		AppliedGeneration: generation.Applied, ObservedGeneration: generation.Observed,
		ParentGeneration: generation.Parent, State: value.GetState(),
		RetiredAtUnix: optionalUnix(value.GetRetiredAtUnix()),
	}
}

func guestFromProto(value *pb.IsolatedGuest) appliance.Guest {
	if value == nil {
		return appliance.Guest{}
	}
	generation := generationFromProto(value.GetGeneration())
	return appliance.Guest{
		ID: value.GetId(), NetworkID: value.GetNetworkId(), IPv4: value.GetIpv4(), MAC: value.GetMac(),
		DesiredGeneration: generation.Desired, AppliedGeneration: generation.Applied,
		ObservedGeneration: generation.Observed, ParentGeneration: generation.Parent,
		State: stateForRetirement(value.GetRetiredAtUnix()), RetiredAtUnix: optionalUnix(value.GetRetiredAtUnix()),
	}
}

func relayFromProto(value *pb.Relay) appliance.Relay {
	if value == nil {
		return appliance.Relay{}
	}
	generation := generationFromProto(value.GetGeneration())
	return appliance.Relay{
		ID: value.GetId(), VMID: value.GetVmId(), ListenPort: int64(value.GetListenPort()),
		TargetIPv4: value.GetTargetIpv4(), TargetPort: int64(value.GetTargetPort()),
		DesiredGeneration: generation.Desired, AppliedGeneration: generation.Applied,
		ObservedGeneration: generation.Observed, ParentGeneration: generation.Parent,
		State: value.GetState(), BoundMainIP: value.GetBoundMainIp(),
		LastBindError: value.GetLastBindError(), RetiredAtUnix: optionalUnix(value.GetRetiredAtUnix()),
	}
}

func natFromProto(value *pb.NatState) appliance.NATState {
	if value == nil {
		return appliance.NATState{}
	}
	generation := generationFromProto(value.GetGeneration())
	return appliance.NATState{
		VMID: value.GetVmId(), State: value.GetState(), ConntrackMark: int64(value.GetConntrackMark()),
		DesiredGeneration: generation.Desired, AppliedGeneration: generation.Applied,
		ObservedGeneration: generation.Observed, ParentGeneration: generation.Parent,
		DrainStartedUnix: optionalUnix(value.GetDrainStartedUnix()),
	}
}

func mutationFromProto(value *pb.MutationResult) MutationResult {
	if value == nil {
		return MutationResult{}
	}
	return MutationResult{
		MutationID: value.GetMutationId(), SemanticHash: value.GetSemanticHash(),
		CompiledHash: value.GetCompiledHash(), Generation: generationFromProto(value.GetGeneration()),
		Replayed: value.GetReplayed(), ApplianceGeneration: value.GetApplianceGeneration(),
	}
}

func mutationFromHeader(value MutationEnvelope, generation GenerationState) MutationResult {
	return MutationResult{
		MutationID: value.Header.MutationID, SemanticHash: value.Header.SemanticHash,
		Generation: generation,
	}
}

func generationFromProto(value *pb.GenerationState) GenerationState {
	if value == nil {
		return GenerationState{}
	}
	return GenerationState{
		Desired: value.GetDesiredGeneration(), Applied: value.GetAppliedGeneration(),
		Observed: value.GetObservedGeneration(), Parent: value.GetParentGeneration(),
	}
}

func fenceFromProto(value *pb.FenceState) FenceState {
	if value == nil {
		return FenceState{}
	}
	return FenceState{
		PhysicalHostID: value.GetPhysicalHostId(), HostFence: value.GetHostFence(),
		HostLeaseID: value.GetHostLeaseId(), ParentResourceID: value.GetParentResourceId(),
		ParentGeneration: value.GetParentGeneration(), Frozen: value.GetFrozen(),
		Deleting: value.GetDeleting(), Lost: value.GetLost(),
	}
}

func fenceParentState(value FenceState) string {
	switch {
	case value.Lost:
		return "lost"
	case value.Deleting:
		return "deleting"
	case value.Frozen:
		return "frozen"
	default:
		return "ready"
	}
}

func optionalUnix(value int64) *int64 {
	if value == 0 {
		return nil
	}
	return &value
}

func stateForRetirement(retiredAt int64) string {
	if retiredAt != 0 {
		return "retired"
	}
	return "active"
}

func resourcePending(state string, generation GenerationState) bool {
	return strings.EqualFold(state, "pending") || strings.EqualFold(state, "retiring") ||
		generation.Desired != generation.Applied || generation.Desired != generation.Observed
}

func translateApplianceError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	result := &ApplianceStatusError{Status: st}
	if ctx != nil && ctx.Err() != nil &&
		(st.Code() == codes.Canceled || st.Code() == codes.DeadlineExceeded) {
		result.contextErr = ctx.Err()
	}
	for _, detail := range st.Details() {
		conflict, ok := detail.(*pb.ApplianceConflict)
		if !ok {
			continue
		}
		result.Code = applianceCodeFromProto(conflict.GetCode())
		result.ResourceID = conflict.GetResourceId()
		result.InventoryGeneration = conflict.GetInventoryGeneration()
		result.Generation = generationFromProto(conflict.GetGeneration())
		result.Fence = fenceFromProto(conflict.GetFence())
		if isCollisionCode(result.Code) {
			result.Collision = &appliance.CollisionError{
				Code: result.Code, InventoryGeneration: result.InventoryGeneration,
				Summary: collisionSummaryFromProto(conflict.GetInventory()),
				Collisions: []appliance.Collision{{
					Code: result.Code, ExistingResourceID: result.ResourceID,
				}},
			}
		}
		break
	}
	if result.Code == "" {
		result.Code = applianceCodeFromStatus(st)
	}
	return result
}

func applianceCodeFromStatus(st *status.Status) appliance.ErrorCode {
	message := strings.ToUpper(st.Message())
	for _, code := range []appliance.ErrorCode{
		appliance.CodeGenerationConflict, appliance.CodeParentGeneration,
		appliance.CodeFenceRejected, appliance.CodeParentFrozen,
		appliance.CodeReservationLost, appliance.CodeSubnetInUse,
		appliance.CodeIPInUse, appliance.CodeMACInUse, appliance.CodePortInUse,
		appliance.CodeConntrackMarkInUse, appliance.CodeCapacityExhausted,
		appliance.CodeNotReady, appliance.CodeNotFound, appliance.CodeInvalidArgument,
		appliance.CodeResourceInUse, appliance.CodeResumeMismatch,
		appliance.CodeIntentPending, appliance.CodeUnsupportedSchema,
	} {
		if strings.Contains(message, string(code)) {
			return code
		}
	}
	switch st.Code() {
	case codes.InvalidArgument:
		return appliance.CodeInvalidArgument
	case codes.NotFound:
		return appliance.CodeNotFound
	case codes.ResourceExhausted:
		return appliance.CodeCapacityExhausted
	case codes.FailedPrecondition:
		return appliance.CodeNotReady
	default:
		return ""
	}
}

func applianceCodeFromProto(value pb.ApplianceErrorCode) appliance.ErrorCode {
	switch value {
	case pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_SUBNET_IN_USE:
		return appliance.CodeSubnetInUse
	case pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_IP_IN_USE:
		return appliance.CodeIPInUse
	case pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_MAC_IN_USE:
		return appliance.CodeMACInUse
	case pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_PORT_IN_USE:
		return appliance.CodePortInUse
	case pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_CONNTRACK_MARK_IN_USE:
		return appliance.CodeConntrackMarkInUse
	case pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_CAPACITY_EXHAUSTED:
		return appliance.CodeCapacityExhausted
	case pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_GENERATION_CONFLICT:
		return appliance.CodeGenerationConflict
	case pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_PARENT_GENERATION_CONFLICT:
		return appliance.CodeParentGeneration
	case pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_FENCE_REJECTED:
		return appliance.CodeFenceRejected
	case pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_PARENT_FROZEN:
		return appliance.CodeParentFrozen
	case pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_RESERVATION_LOST:
		return appliance.CodeReservationLost
	default:
		return ""
	}
}

func isCollisionCode(code appliance.ErrorCode) bool {
	switch code {
	case appliance.CodeSubnetInUse, appliance.CodeIPInUse, appliance.CodeMACInUse,
		appliance.CodePortInUse, appliance.CodeConntrackMarkInUse,
		appliance.CodeCapacityExhausted:
		return true
	default:
		return false
	}
}

func collisionSummaryFromProto(value *pb.InventorySummary) appliance.InventorySummary {
	if value == nil {
		return appliance.InventorySummary{}
	}
	maxGuests := int64(value.GetMaxGuests())
	freeIPs := int64(value.GetFreeIpv4Count())
	freeMACs := int64(value.GetFreeMacCount())
	freePorts := int64(value.GetFreeRelayPortCount())
	freeMarks := int64(value.GetFreeConntrackMarkCount())
	return appliance.InventorySummary{
		Subnets: int64(value.GetLiveNetworks()),
		IPs:     max(0, maxGuests-freeIPs), MACs: max(0, maxGuests-freeMACs),
		Ports: max(0, maxGuests-freePorts), ConntrackMarks: max(0, maxGuests-freeMarks),
		Capacity: map[string]appliance.CapacityUsage{
			"network": {Used: int64(value.GetLiveNetworks()), Limit: int64(value.GetMaxNetworks())},
			"guest":   {Used: int64(value.GetLiveGuests()), Limit: maxGuests},
		},
	}
}
