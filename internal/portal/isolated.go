package portal

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/isolated"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
	"github.com/nijosmsft/lablink/internal/registry"
)

const (
	defaultIsolatedLimit = 50
	maxIsolatedLimit     = 200
)

type isolatedStateReader interface {
	ListOrchestrators(context.Context, string) ([]isolatedstate.Orchestrator, error)
	ListNetworks(context.Context, string) ([]isolatedstate.PrivateNetwork, error)
	ListVMs(context.Context, string, string) ([]isolatedstate.IsolatedVM, error)
	ListRelays(context.Context, string, string) ([]isolatedstate.RelayAllocation, error)
	ListNAT(context.Context, string, string, string) ([]isolatedstate.NATAllocation, error)
}

type isolatedApplianceReader interface {
	CheckReadiness(context.Context, string) (isolated.ApplianceReadiness, error)
	InspectApplianceState(context.Context, string) (isolated.ApplianceSnapshot, error)
	GetRelayStats(context.Context, string, string) (appliance.RelayStats, error)
}

type isolatedPortal struct {
	reg       *registry.Registry
	statePath string
	appliance isolatedApplianceReader

	mu       sync.Mutex
	openOnce sync.Once
	state    isolatedStateReader
	owned    *isolatedstate.Store
	openErr  error
}

func newIsolatedPortal(reg *registry.Registry, pool *agentclient.Pool) *isolatedPortal {
	view := &isolatedPortal{
		reg:       reg,
		statePath: isolatedPortalDBPath(),
	}
	if reg != nil && pool != nil {
		view.appliance = isolated.NewApplianceClient(reg, pool, "portal")
	}
	return view
}

func isolatedPortalDBPath() string {
	for _, name := range []string{"LABLINK_HOME", "DEVICE_INTERACTION_HOME"} {
		if home := strings.TrimSpace(os.Getenv(name)); home != "" {
			return filepath.Join(home, "isolated.db")
		}
	}
	return isolatedstate.DefaultDBPath()
}

func (p *isolatedPortal) close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.owned == nil {
		return nil
	}
	err := p.owned.Close()
	p.owned = nil
	return err
}

func (p *isolatedPortal) reader() (isolatedStateReader, error) {
	if p == nil {
		return nil, errors.New("isolated portal is not configured")
	}
	p.mu.Lock()
	if p.state != nil {
		state := p.state
		p.mu.Unlock()
		return state, nil
	}
	p.mu.Unlock()

	p.openOnce.Do(func() {
		store, err := isolatedstate.Open(p.statePath)
		p.mu.Lock()
		defer p.mu.Unlock()
		if err != nil {
			p.openErr = err
			return
		}
		p.state = store
		p.owned = store
	})

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != nil {
		return p.state, nil
	}
	if p.openErr != nil {
		return nil, p.openErr
	}
	return nil, errors.New("isolated state is unavailable")
}

type isolatedErrorJSON struct {
	Scope string `json:"scope"`
	Error string `json:"error"`
}

type isolatedEndpointJSON struct {
	MainIP       string `json:"main_ip,omitempty"`
	AgentPort    int    `json:"agent_port"`
	Address      string `json:"address,omitempty"`
	NodeName     string `json:"node_name"`
	TLSName      string `json:"tls_name,omitempty"`
	Transport    string `json:"transport,omitempty"`
	IdentityOK   bool   `json:"identity_ok"`
	RegistrySeen bool   `json:"registry_seen"`
}

type isolatedReadinessJSON struct {
	Available       bool     `json:"available"`
	Ready           bool     `json:"ready"`
	Node            string   `json:"node,omitempty"`
	AgentVersion    string   `json:"agent_version,omitempty"`
	Capabilities    []string `json:"capabilities"`
	ProtocolVersion uint32   `json:"protocol_version,omitempty"`
	ApplianceSchema uint32   `json:"appliance_schema,omitempty"`
	PolicyVerified  bool     `json:"policy_verified"`
	IPv4Forwarding  bool     `json:"ipv4_forwarding"`
	Error           string   `json:"error,omitempty"`
}

type isolatedCapacityJSON struct {
	MaxNetworks        int `json:"max_networks"`
	UsedNetworks       int `json:"used_networks"`
	FreeSubnets        int `json:"free_subnets"`
	MaxVMs             int `json:"max_vms"`
	UsedVMs            int `json:"used_vms"`
	GuestSlots         int `json:"guest_slots"`
	UsedRelayPorts     int `json:"used_relay_ports"`
	FreeRelayPorts     int `json:"free_relay_ports"`
	FreeGuestIPs       int `json:"free_guest_ips"`
	FreeMACs           int `json:"free_macs"`
	FreeConntrackMarks int `json:"free_conntrack_marks"`
}

type isolatedOrchestratorJSON struct {
	ID             string                                   `json:"id"`
	DisplayName    string                                   `json:"display_name"`
	PhysicalHostID string                                   `json:"physical_host_id"`
	HostNode       string                                   `json:"host_node"`
	HyperVName     string                                   `json:"hyperv_name"`
	HyperVVMID     *string                                  `json:"hyperv_vm_id,omitempty"`
	ProfileName    string                                   `json:"profile_name"`
	MainVSwitch    string                                   `json:"main_vswitch"`
	MainMAC        *string                                  `json:"main_mac,omitempty"`
	LifecycleState isolatedstate.OrchestratorLifecycleState `json:"lifecycle_state"`
	HealthState    string                                   `json:"health_state"`
	LastSeenAt     *isolatedstate.UnixSeconds               `json:"last_seen_at_unix,omitempty"`
	Endpoint       isolatedEndpointJSON                     `json:"endpoint"`
	Readiness      isolatedReadinessJSON                    `json:"readiness"`
	Capacity       isolatedCapacityJSON                     `json:"capacity"`
}

type isolatedNetworkJSON struct {
	ID                    string                              `json:"id"`
	OrchestratorID        string                              `json:"orchestrator_id"`
	DisplayName           string                              `json:"display_name"`
	HyperVSwitchName      string                              `json:"hyperv_switch_name"`
	HyperVSwitchGUID      *string                             `json:"hyperv_switch_guid,omitempty"`
	OrchestratorAdapterID *string                             `json:"orchestrator_adapter_id,omitempty"`
	SubnetIndex           int                                 `json:"subnet_index"`
	CIDR                  string                              `json:"cidr"`
	GatewayIPv4           string                              `json:"gateway_ipv4"`
	OrchestratorMAC       string                              `json:"orchestrator_mac"`
	DNSServers            []string                            `json:"dns_servers"`
	ObservedDNSServers    []string                            `json:"observed_dns_servers"`
	DNSDrift              bool                                `json:"dns_drift"`
	LifecycleState        isolatedstate.NetworkLifecycleState `json:"lifecycle_state"`
	LiveState             string                              `json:"live_state,omitempty"`
	LiveError             string                              `json:"live_error,omitempty"`
}

type isolatedTLSIdentityJSON struct {
	NodeName     string `json:"node_name"`
	TLSName      string `json:"tls_name,omitempty"`
	Transport    string `json:"transport,omitempty"`
	Address      string `json:"address,omitempty"`
	IdentityOK   bool   `json:"identity_ok"`
	RegistrySeen bool   `json:"registry_seen"`
}

type isolatedNATJSON struct {
	State         isolatedstate.NATState `json:"state,omitempty"`
	LiveState     string                 `json:"live_state,omitempty"`
	ConntrackMark int64                  `json:"conntrack_mark,omitempty"`
	LiveError     string                 `json:"live_error,omitempty"`
}

type isolatedVMJSON struct {
	ID              string                         `json:"id"`
	OrchestratorID  string                         `json:"orchestrator_id"`
	NetworkID       string                         `json:"network_id"`
	DisplayName     string                         `json:"display_name"`
	HyperVName      string                         `json:"hyperv_name"`
	HyperVVMID      *string                        `json:"hyperv_vm_id,omitempty"`
	HyperVAdapterID *string                        `json:"hyperv_adapter_id,omitempty"`
	NodeName        string                         `json:"node_name"`
	GuestOS         isolatedstate.GuestOS          `json:"guest_os"`
	ProfileName     string                         `json:"profile_name"`
	IPv4            string                         `json:"ipv4"`
	MAC             string                         `json:"mac"`
	PrefixLength    int                            `json:"prefix_length"`
	GatewayIPv4     string                         `json:"gateway_ipv4"`
	DNSServers      []string                       `json:"dns_servers"`
	DNSDrift        bool                           `json:"dns_drift"`
	LifecycleState  isolatedstate.VMLifecycleState `json:"lifecycle_state"`
	LiveState       string                         `json:"live_state,omitempty"`
	LiveError       string                         `json:"live_error,omitempty"`
	TLS             isolatedTLSIdentityJSON        `json:"tls"`
	NAT             *isolatedNATJSON               `json:"nat,omitempty"`
	RelayID         string                         `json:"relay_id,omitempty"`
	RelayListenPort int                            `json:"relay_listen_port,omitempty"`
}

type isolatedRelayStatsJSON struct {
	ListenerState                string `json:"listener_state,omitempty"`
	BindAddress                  string `json:"bind_address,omitempty"`
	BindError                    string `json:"bind_error,omitempty"`
	ActiveConnections            uint64 `json:"active_connections"`
	TotalAcceptedConnections     uint64 `json:"total_accepted_connections"`
	BytesGuestToMain             uint64 `json:"bytes_guest_to_main"`
	BytesMainToGuest             uint64 `json:"bytes_main_to_guest"`
	LastSuccessfulConnectionUnix int64  `json:"last_successful_connection_unix,omitempty"`
	TargetDialFailureCount       uint64 `json:"target_dial_failure_count"`
	LastFailure                  string `json:"last_failure,omitempty"`
	Error                        string `json:"error,omitempty"`
}

type isolatedRelayJSON struct {
	ID             string                            `json:"id"`
	VMID           string                            `json:"vm_id"`
	OrchestratorID string                            `json:"orchestrator_id"`
	ListenPort     int                               `json:"listen_port"`
	TargetIPv4     string                            `json:"target_ipv4"`
	TargetPort     int                               `json:"target_port"`
	LifecycleState isolatedstate.RelayLifecycleState `json:"lifecycle_state"`
	LiveState      string                            `json:"live_state,omitempty"`
	BoundMainIP    string                            `json:"bound_main_ip,omitempty"`
	LiveError      string                            `json:"live_error,omitempty"`
	Stats          *isolatedRelayStatsJSON           `json:"stats,omitempty"`
}

type isolatedPageJSON struct {
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	Total   int  `json:"total"`
	HasMore bool `json:"has_more"`
}

type isolatedSnapshotJSON struct {
	Orchestrators []isolatedOrchestratorJSON `json:"orchestrators"`
	Networks      []isolatedNetworkJSON      `json:"networks"`
	VMs           []isolatedVMJSON           `json:"vms"`
	Relays        []isolatedRelayJSON        `json:"relays"`
	RelayStats    isolatedPageJSON           `json:"relay_stats_page"`
	Errors        []isolatedErrorJSON        `json:"errors"`
}

func (s *Server) registerIsolatedHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/api/isolated", s.handleIsolated)
}

func (s *Server) handleIsolated(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state, err := s.isolated.reader()
	if err != nil {
		writePortalJSON(w, http.StatusServiceUnavailable, map[string]any{
			"orchestrators": []any{}, "networks": []any{}, "vms": []any{},
			"relays": []any{}, "errors": []isolatedErrorJSON{{Scope: "state", Error: err.Error()}},
		})
		return
	}
	statsLimit, statsOffset := isolatedPage(r, "stats_", defaultIsolatedLimit)
	snapshot := s.loadIsolatedSnapshot(r.Context(), state, statsLimit, statsOffset)
	writePortalJSON(w, http.StatusOK, snapshot)
}

func (s *Server) loadIsolatedSnapshot(
	ctx context.Context,
	state isolatedStateReader,
	statsLimit, statsOffset int,
) isolatedSnapshotJSON {
	result := isolatedSnapshotJSON{
		Orchestrators: []isolatedOrchestratorJSON{},
		Networks:      []isolatedNetworkJSON{},
		VMs:           []isolatedVMJSON{},
		Relays:        []isolatedRelayJSON{},
		Errors:        []isolatedErrorJSON{},
	}
	orchestrators, err := state.ListOrchestrators(ctx, "")
	if err != nil {
		result.Errors = append(result.Errors, isolatedErrorJSON{Scope: "orchestrators", Error: err.Error()})
		return result
	}
	networks, err := state.ListNetworks(ctx, "")
	if err != nil {
		result.Errors = append(result.Errors, isolatedErrorJSON{Scope: "networks", Error: err.Error()})
	}
	vms, err := state.ListVMs(ctx, "", "")
	if err != nil {
		result.Errors = append(result.Errors, isolatedErrorJSON{Scope: "vms", Error: err.Error()})
	}
	relays, err := state.ListRelays(ctx, "", "")
	if err != nil {
		result.Errors = append(result.Errors, isolatedErrorJSON{Scope: "relays", Error: err.Error()})
	}
	nats, err := state.ListNAT(ctx, "", "", "")
	if err != nil {
		result.Errors = append(result.Errors, isolatedErrorJSON{Scope: "nat", Error: err.Error()})
	}

	networkByID := make(map[string]isolatedstate.PrivateNetwork, len(networks))
	networkCount := make(map[string]int)
	for _, value := range networks {
		networkByID[value.ID] = value
		if value.RetiredAt == nil && value.LifecycleState != isolatedstate.NetworkDeleted {
			networkCount[value.OrchestratorID]++
		}
	}
	vmCount := make(map[string]int)
	for _, value := range vms {
		if value.RetiredAt == nil && value.LifecycleState != isolatedstate.VMDeleted {
			vmCount[value.OrchestratorID]++
		}
	}
	relayCount := make(map[string]int)
	for _, value := range relays {
		if value.RetiredAt == nil && value.LifecycleState != isolatedstate.RelayRemoved {
			relayCount[value.OrchestratorID]++
		}
	}

	liveNetworks := map[string]appliance.Network{}
	liveGuests := map[string]appliance.Guest{}
	liveRelays := map[string]appliance.Relay{}
	liveNAT := map[string]appliance.NATState{}

	for _, value := range orchestrators {
		ready := isolatedReadinessJSON{Capabilities: []string{}}
		endpoint := s.isolatedEndpoint(value)
		if s.isolated.appliance != nil {
			callCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			report, readyErr := s.isolated.appliance.CheckReadiness(callCtx, value.ID)
			cancel()
			ready = readinessJSON(report, readyErr)
			if readyErr == nil {
				callCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
				live, inspectErr := s.isolated.appliance.InspectApplianceState(callCtx, value.ID)
				cancel()
				if inspectErr != nil {
					ready.Error = inspectErr.Error()
				} else {
					ready.Available = true
					ready.Ready = live.Ready
					ready.ApplianceSchema = live.SchemaVersion
					ready.PolicyVerified = live.PolicyVerified
					ready.IPv4Forwarding = live.IPv4Forwarding
					if strings.TrimSpace(live.MainIPv4) != "" {
						endpoint.MainIP = live.MainIPv4
						endpoint.Address = net.JoinHostPort(
							live.MainIPv4, strconv.Itoa(endpoint.AgentPort),
						)
					}
					for _, item := range live.Config.Networks {
						liveNetworks[item.ID] = item
					}
					for _, item := range live.Config.Guests {
						liveGuests[item.ID] = item
					}
					for _, item := range live.Config.Relays {
						liveRelays[item.ID] = item
					}
					for _, item := range live.Config.NAT {
						liveNAT[item.VMID] = item
					}
				}
			}
		}
		result.Orchestrators = append(result.Orchestrators, isolatedOrchestratorJSON{
			ID: value.ID, DisplayName: value.DisplayName,
			PhysicalHostID: value.PhysicalHostID, HostNode: value.HostNode,
			HyperVName: value.HyperVName, HyperVVMID: value.HyperVVMID,
			ProfileName: value.ProfileName, MainVSwitch: value.MainVSwitch,
			MainMAC: value.MainMAC, LifecycleState: value.LifecycleState,
			HealthState: value.HealthState, LastSeenAt: value.LastSeenAt,
			Endpoint:  endpoint,
			Readiness: ready,
			Capacity:  isolatedCapacity(value, networkCount[value.ID], vmCount[value.ID], relayCount[value.ID]),
		})
	}

	for _, value := range networks {
		desiredDNS := dnsList(value.DNSServersJSON)
		live := liveNetworks[value.ID]
		observedDNS := dnsList(live.DNSServersJSON)
		result.Networks = append(result.Networks, isolatedNetworkJSON{
			ID: value.ID, OrchestratorID: value.OrchestratorID,
			DisplayName: value.DisplayName, HyperVSwitchName: value.HyperVSwitchName,
			HyperVSwitchGUID:      value.HyperVSwitchGUID,
			OrchestratorAdapterID: value.OrchestratorAdapterID,
			SubnetIndex:           value.SubnetIndex, CIDR: value.CIDR,
			GatewayIPv4: value.GatewayIPv4, OrchestratorMAC: value.OrchestratorMAC,
			DNSServers: desiredDNS, ObservedDNSServers: observedDNS,
			DNSDrift:       live.ID != "" && !sameStrings(desiredDNS, observedDNS),
			LifecycleState: value.LifecycleState,
			LiveState:      live.State, LiveError: live.LastError,
		})
	}

	relayByVM := make(map[string]isolatedstate.RelayAllocation, len(relays))
	for _, value := range relays {
		if value.RetiredAt == nil {
			relayByVM[value.VMID] = value
		}
	}
	natByVM := make(map[string]isolatedstate.NATAllocation, len(nats))
	for _, value := range nats {
		natByVM[value.VMID] = value
	}
	for _, value := range vms {
		parent := networkByID[value.NetworkID]
		live := liveGuests[value.ID]
		item := isolatedVMJSON{
			ID: value.ID, OrchestratorID: value.OrchestratorID,
			NetworkID: value.NetworkID, DisplayName: value.DisplayName,
			HyperVName: value.HyperVName, HyperVVMID: value.HyperVVMID,
			HyperVAdapterID: value.HyperVAdapterID,
			NodeName:        value.NodeName, GuestOS: value.GuestOS,
			ProfileName: value.ProfileName, IPv4: value.IPv4, MAC: value.MAC,
			PrefixLength: value.PrefixLength, GatewayIPv4: value.GatewayIPv4,
			DNSServers:     dnsList(value.DNSServersJSON),
			DNSDrift:       !sameStrings(dnsList(value.DNSServersJSON), dnsList(parent.DNSServersJSON)),
			LifecycleState: value.LifecycleState, LiveState: live.State,
			LiveError: live.LastError, TLS: s.isolatedTLS(value.NodeName),
		}
		if relay, ok := relayByVM[value.ID]; ok {
			item.RelayID = relay.ID
			item.RelayListenPort = relay.ListenPort
		}
		if nat, ok := natByVM[value.ID]; ok {
			liveValue := liveNAT[value.ID]
			item.NAT = &isolatedNATJSON{
				State: nat.State, LiveState: liveValue.State,
				ConntrackMark: nat.ConntrackMark,
				LiveError:     liveValue.LastError,
			}
		}
		result.VMs = append(result.VMs, item)
	}

	statsStart := min(statsOffset, len(relays))
	statsEnd := min(statsStart+statsLimit, len(relays))
	result.RelayStats = isolatedPageJSON{
		Limit: statsLimit, Offset: statsOffset, Total: len(relays),
		HasMore: statsEnd < len(relays),
	}
	for index, value := range relays {
		live := liveRelays[value.ID]
		item := isolatedRelayJSON{
			ID: value.ID, VMID: value.VMID, OrchestratorID: value.OrchestratorID,
			ListenPort: value.ListenPort, TargetIPv4: value.TargetIPv4,
			TargetPort:     value.TargetPort,
			LifecycleState: value.LifecycleState, LiveState: live.State,
			BoundMainIP: live.BoundMainIP, LiveError: live.LastBindError,
		}
		if index >= statsStart && index < statsEnd && s.isolated.appliance != nil {
			callCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			stats, statsErr := s.isolated.appliance.GetRelayStats(callCtx, value.OrchestratorID, value.ID)
			cancel()
			item.Stats = relayStatsJSON(stats, statsErr)
		}
		result.Relays = append(result.Relays, item)
	}
	return result
}

func (s *Server) isolatedEndpoint(value isolatedstate.Orchestrator) isolatedEndpointJSON {
	result := isolatedEndpointJSON{
		MainIP: valueOrEmpty(value.MainIP), AgentPort: value.AgentPort,
		NodeName: value.NodeName,
	}
	if result.MainIP != "" && result.AgentPort > 0 {
		result.Address = net.JoinHostPort(result.MainIP, strconv.Itoa(result.AgentPort))
	}
	identity := s.isolatedTLS(value.NodeName)
	result.TLSName = identity.TLSName
	result.Transport = identity.Transport
	result.IdentityOK = identity.IdentityOK
	result.RegistrySeen = identity.RegistrySeen
	return result
}

func (s *Server) isolatedTLS(nodeName string) isolatedTLSIdentityJSON {
	result := isolatedTLSIdentityJSON{NodeName: nodeName}
	if s.isolated == nil || s.isolated.reg == nil {
		return result
	}
	node, ok := s.isolated.reg.GetNode(nodeName)
	if !ok || node == nil {
		return result
	}
	result.RegistrySeen = true
	result.TLSName = node.TLSServerName
	result.Transport = node.TransportMode
	result.Address = node.Address
	result.IdentityOK = strings.EqualFold(strings.TrimSpace(node.TransportMode), "mtls") &&
		strings.TrimSpace(node.TLSServerName) == strings.TrimSpace(nodeName)
	return result
}

func readinessJSON(value isolated.ApplianceReadiness, err error) isolatedReadinessJSON {
	capabilities := append([]string(nil), value.Capabilities...)
	sort.Strings(capabilities)
	result := isolatedReadinessJSON{
		Available: value.Node != "", Ready: value.Ready, Node: value.Node,
		AgentVersion: value.AgentVersion, Capabilities: capabilities,
		ProtocolVersion: value.ProtocolVersion,
		Error:           strings.TrimSpace(value.Error),
	}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func isolatedCapacity(
	value isolatedstate.Orchestrator,
	networkCount, vmCount, relayCount int,
) isolatedCapacityJSON {
	maxNetworks := value.MaxNetworks
	if maxNetworks <= 0 {
		maxNetworks = isolated.MaxNetworksPerOrchestrator
	}
	maxVMs := value.MaxVMs
	if maxVMs <= 0 {
		maxVMs = isolated.MaxVMsPerOrchestrator
	}
	guestSlots := max(0, maxVMs-vmCount)
	return isolatedCapacityJSON{
		MaxNetworks: maxNetworks, UsedNetworks: networkCount,
		FreeSubnets: max(0, min(maxNetworks, 64)-networkCount),
		MaxVMs:      maxVMs, UsedVMs: vmCount, GuestSlots: guestSlots,
		UsedRelayPorts: relayCount,
		FreeRelayPorts: max(0, appliance.RelayPortMax-appliance.RelayPortMin+1-relayCount),
		FreeGuestIPs:   guestSlots, FreeMACs: guestSlots, FreeConntrackMarks: guestSlots,
	}
}

func isolatedPage(r *http.Request, prefix string, fallback int) (int, int) {
	limit := isolatedLimit(r, prefix+"limit", fallback, maxIsolatedLimit)
	offset, _ := strconv.Atoi(r.URL.Query().Get(prefix + "offset"))
	if offset < 0 {
		offset = 0
	}
	if offset > 1_000_000 {
		offset = 1_000_000
	}
	return limit, offset
}

func isolatedLimit(r *http.Request, name string, fallback, maximum int) int {
	value, _ := strconv.Atoi(r.URL.Query().Get(name))
	if value <= 0 {
		value = fallback
	}
	if value > maximum {
		value = maximum
	}
	return value
}

func relayStatsJSON(value appliance.RelayStats, err error) *isolatedRelayStatsJSON {
	result := &isolatedRelayStatsJSON{
		ListenerState: value.ListenerState, BindAddress: value.BindAddress,
		BindError: value.BindError, ActiveConnections: value.ActiveConnections,
		TotalAcceptedConnections:     value.TotalAcceptedConnections,
		BytesGuestToMain:             value.BytesGuestToMain,
		BytesMainToGuest:             value.BytesMainToGuest,
		LastSuccessfulConnectionUnix: value.LastSuccessfulConnectionUnix,
		TargetDialFailureCount:       value.TargetDialFailureCount,
		LastFailure:                  value.LastFailure,
	}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func dnsList(raw string) []string {
	values := []string{}
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return []string{}
	}
	for index := range values {
		values[index] = strings.TrimSpace(values[index])
	}
	return values
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	a := append([]string(nil), left...)
	b := append([]string(nil), right...)
	sort.Strings(a)
	sort.Strings(b)
	for index := range a {
		if !strings.EqualFold(a[index], b[index]) {
			return false
		}
	}
	return true
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func writePortalJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(value)
}
