package portal

import (
	"context"
	"database/sql"
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
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
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
	Available           bool     `json:"available"`
	Ready               bool     `json:"ready"`
	Node                string   `json:"node,omitempty"`
	AgentVersion        string   `json:"agent_version,omitempty"`
	Capabilities        []string `json:"capabilities"`
	ProtocolVersion     uint32   `json:"protocol_version,omitempty"`
	ApplianceSchema     uint32   `json:"appliance_schema,omitempty"`
	ApplianceGeneration uint64   `json:"appliance_generation,omitempty"`
	InventoryGeneration uint64   `json:"inventory_generation,omitempty"`
	PolicyVerified      bool     `json:"policy_verified"`
	IPv4Forwarding      bool     `json:"ipv4_forwarding"`
	Error               string   `json:"error,omitempty"`
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
	ID                 string                                   `json:"id"`
	DisplayName        string                                   `json:"display_name"`
	PhysicalHostID     string                                   `json:"physical_host_id"`
	HostNode           string                                   `json:"host_node"`
	HyperVName         string                                   `json:"hyperv_name"`
	HyperVVMID         *string                                  `json:"hyperv_vm_id,omitempty"`
	ProfileName        string                                   `json:"profile_name"`
	MainVSwitch        string                                   `json:"main_vswitch"`
	MainMAC            *string                                  `json:"main_mac,omitempty"`
	LifecycleState     isolatedstate.OrchestratorLifecycleState `json:"lifecycle_state"`
	HealthState        string                                   `json:"health_state"`
	DesiredGeneration  isolatedstate.Generation                 `json:"desired_generation"`
	AppliedGeneration  isolatedstate.Generation                 `json:"applied_generation"`
	ObservedGeneration isolatedstate.Generation                 `json:"observed_generation"`
	LastSeenAt         *isolatedstate.UnixSeconds               `json:"last_seen_at_unix,omitempty"`
	Endpoint           isolatedEndpointJSON                     `json:"endpoint"`
	Readiness          isolatedReadinessJSON                    `json:"readiness"`
	Capacity           isolatedCapacityJSON                     `json:"capacity"`
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
	DesiredGeneration     isolatedstate.Generation            `json:"desired_generation"`
	AppliedGeneration     isolatedstate.Generation            `json:"applied_generation"`
	ObservedGeneration    isolatedstate.Generation            `json:"observed_generation"`
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
	DesiredState       isolatedstate.NATDesiredState  `json:"desired_state,omitempty"`
	ObservedState      isolatedstate.NATObservedState `json:"observed_state,omitempty"`
	LiveState          string                         `json:"live_state,omitempty"`
	ConntrackMark      int64                          `json:"conntrack_mark,omitempty"`
	DesiredGeneration  isolatedstate.Generation       `json:"desired_generation,omitempty"`
	AppliedGeneration  isolatedstate.Generation       `json:"applied_generation,omitempty"`
	ObservedGeneration isolatedstate.Generation       `json:"observed_generation,omitempty"`
	LiveError          string                         `json:"live_error,omitempty"`
}

type isolatedVMJSON struct {
	ID                 string                         `json:"id"`
	OrchestratorID     string                         `json:"orchestrator_id"`
	NetworkID          string                         `json:"network_id"`
	DisplayName        string                         `json:"display_name"`
	HyperVName         string                         `json:"hyperv_name"`
	HyperVVMID         *string                        `json:"hyperv_vm_id,omitempty"`
	HyperVAdapterID    *string                        `json:"hyperv_adapter_id,omitempty"`
	Incarnation        isolatedstate.Incarnation      `json:"incarnation"`
	NodeName           string                         `json:"node_name"`
	GuestOS            isolatedstate.GuestOS          `json:"guest_os"`
	ProfileName        string                         `json:"profile_name"`
	IPv4               string                         `json:"ipv4"`
	MAC                string                         `json:"mac"`
	PrefixLength       int                            `json:"prefix_length"`
	GatewayIPv4        string                         `json:"gateway_ipv4"`
	DNSServers         []string                       `json:"dns_servers"`
	DNSDrift           bool                           `json:"dns_drift"`
	DNSUpdatePending   bool                           `json:"dns_update_pending"`
	DNSLastError       string                         `json:"dns_last_error,omitempty"`
	DesiredGeneration  isolatedstate.Generation       `json:"desired_generation"`
	AppliedGeneration  isolatedstate.Generation       `json:"applied_generation"`
	ObservedGeneration isolatedstate.Generation       `json:"observed_generation"`
	LifecycleState     isolatedstate.VMLifecycleState `json:"lifecycle_state"`
	LiveState          string                         `json:"live_state,omitempty"`
	LiveError          string                         `json:"live_error,omitempty"`
	TLS                isolatedTLSIdentityJSON        `json:"tls"`
	NAT                *isolatedNATJSON               `json:"nat,omitempty"`
	RelayID            string                         `json:"relay_id,omitempty"`
	RelayListenPort    int                            `json:"relay_listen_port,omitempty"`
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
	RelayGeneration              uint64 `json:"relay_generation"`
	ApplianceGeneration          uint64 `json:"appliance_generation"`
	Error                        string `json:"error,omitempty"`
}

type isolatedRelayJSON struct {
	ID                 string                            `json:"id"`
	VMID               string                            `json:"vm_id"`
	OrchestratorID     string                            `json:"orchestrator_id"`
	ListenPort         int                               `json:"listen_port"`
	TargetIPv4         string                            `json:"target_ipv4"`
	TargetPort         int                               `json:"target_port"`
	DesiredGeneration  isolatedstate.Generation          `json:"desired_generation"`
	AppliedGeneration  isolatedstate.Generation          `json:"applied_generation"`
	ObservedGeneration isolatedstate.Generation          `json:"observed_generation"`
	LifecycleState     isolatedstate.RelayLifecycleState `json:"lifecycle_state"`
	LiveState          string                            `json:"live_state,omitempty"`
	BoundMainIP        string                            `json:"bound_main_ip,omitempty"`
	LiveError          string                            `json:"live_error,omitempty"`
	Stats              *isolatedRelayStatsJSON           `json:"stats,omitempty"`
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

type natRow struct {
	isolatedstate.NATAllocation
}

type pendingDNSRow struct {
	VMID      string
	LastError string
}

func (s *Server) registerIsolatedHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/api/isolated", s.handleIsolated)
	mux.HandleFunc("/api/isolated/operations", s.handleIsolatedOperations)
	mux.HandleFunc("/api/isolated/operation", s.handleIsolatedOperation)
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
	nats, err := loadNATRows(ctx, state)
	if err != nil {
		result.Errors = append(result.Errors, isolatedErrorJSON{Scope: "nat", Error: err.Error()})
	}
	pendingDNS, err := loadPendingDNSRows(ctx, state)
	if err != nil {
		result.Errors = append(result.Errors, isolatedErrorJSON{Scope: "dns_updates", Error: err.Error()})
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
					ready.ApplianceGeneration = live.ApplianceGeneration
					ready.InventoryGeneration = live.InventoryGeneration
					ready.PolicyVerified = live.PolicyVerified
					ready.IPv4Forwarding = live.IPv4Forwarding
					if strings.TrimSpace(live.MainIPv4) != "" {
						endpoint.MainIP = live.MainIPv4
						endpoint.Address = net.JoinHostPort(
							live.MainIPv4, strconv.Itoa(endpoint.AgentPort),
						)
					}
					for _, item := range live.Desired.Networks {
						liveNetworks[item.ID] = item
					}
					for _, item := range live.Desired.Guests {
						liveGuests[item.ID] = item
					}
					for _, item := range live.Desired.Relays {
						liveRelays[item.ID] = item
					}
					for _, item := range live.Desired.NAT {
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
			HealthState: value.HealthState, DesiredGeneration: value.DesiredGeneration,
			AppliedGeneration:  value.AppliedGeneration,
			ObservedGeneration: value.ObservedGeneration, LastSeenAt: value.LastSeenAt,
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
			DNSDrift:           live.ID != "" && !sameStrings(desiredDNS, observedDNS),
			DesiredGeneration:  value.DesiredGeneration,
			AppliedGeneration:  value.AppliedGeneration,
			ObservedGeneration: value.ObservedGeneration,
			LifecycleState:     value.LifecycleState,
			LiveState:          live.State, LiveError: live.LastError,
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
		natByVM[value.VMID] = value.NATAllocation
	}
	pendingByVM := make(map[string]pendingDNSRow, len(pendingDNS))
	for _, value := range pendingDNS {
		pendingByVM[value.VMID] = value
	}
	for _, value := range vms {
		parent := networkByID[value.NetworkID]
		live := liveGuests[value.ID]
		pending := pendingByVM[value.ID]
		item := isolatedVMJSON{
			ID: value.ID, OrchestratorID: value.OrchestratorID,
			NetworkID: value.NetworkID, DisplayName: value.DisplayName,
			HyperVName: value.HyperVName, HyperVVMID: value.HyperVVMID,
			HyperVAdapterID: value.HyperVAdapterID, Incarnation: value.Incarnation,
			NodeName: value.NodeName, GuestOS: value.GuestOS,
			ProfileName: value.ProfileName, IPv4: value.IPv4, MAC: value.MAC,
			PrefixLength: value.PrefixLength, GatewayIPv4: value.GatewayIPv4,
			DNSServers:       dnsList(value.DNSServersJSON),
			DNSDrift:         !sameStrings(dnsList(value.DNSServersJSON), dnsList(parent.DNSServersJSON)),
			DNSUpdatePending: pending.VMID != "", DNSLastError: pending.LastError,
			DesiredGeneration:  value.DesiredGeneration,
			AppliedGeneration:  value.AppliedGeneration,
			ObservedGeneration: value.ObservedGeneration,
			LifecycleState:     value.LifecycleState, LiveState: live.State,
			LiveError: live.LastError, TLS: s.isolatedTLS(value.NodeName),
		}
		if relay, ok := relayByVM[value.ID]; ok {
			item.RelayID = relay.ID
			item.RelayListenPort = relay.ListenPort
		}
		if nat, ok := natByVM[value.ID]; ok {
			liveValue := liveNAT[value.ID]
			item.NAT = &isolatedNATJSON{
				DesiredState: nat.DesiredState, ObservedState: nat.ObservedState,
				LiveState: liveValue.State, ConntrackMark: nat.ConntrackMark,
				DesiredGeneration:  nat.DesiredGeneration,
				AppliedGeneration:  nat.AppliedGeneration,
				ObservedGeneration: nat.ObservedGeneration,
				LiveError:          liveValue.LastError,
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
			TargetPort: value.TargetPort, DesiredGeneration: value.DesiredGeneration,
			AppliedGeneration:  value.AppliedGeneration,
			ObservedGeneration: value.ObservedGeneration,
			LifecycleState:     value.LifecycleState, LiveState: live.State,
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
		ProtocolVersion:     value.ProtocolVersion,
		ApplianceGeneration: value.ApplianceGeneration,
		Error:               strings.TrimSpace(value.Error),
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

func loadNATRows(ctx context.Context, state isolatedStateReader) ([]natRow, error) {
	rows, err := state.QueryContext(ctx, `
		SELECT vm_id, orchestrator_id, desired_state, observed_state,
		       conntrack_mark, desired_generation, applied_generation,
		       observed_generation, drain_started_unix, updated_at_unix
		FROM nat_allocations ORDER BY vm_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []natRow{}
	for rows.Next() {
		var value natRow
		if err := rows.Scan(
			&value.VMID, &value.OrchestratorID, &value.DesiredState,
			&value.ObservedState, &value.ConntrackMark, &value.DesiredGeneration,
			&value.AppliedGeneration, &value.ObservedGeneration,
			&value.DrainStartedAt, &value.UpdatedAt,
		); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func loadPendingDNSRows(ctx context.Context, state isolatedStateReader) ([]pendingDNSRow, error) {
	rows, err := state.QueryContext(ctx, `
		SELECT vm_id, COALESCE(last_error, '')
		FROM guest_pending_updates
		WHERE lower(update_kind) LIKE '%dns%'
		ORDER BY vm_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []pendingDNSRow{}
	for rows.Next() {
		var value pendingDNSRow
		if err := rows.Scan(&value.VMID, &value.LastError); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

type isolatedOperationJSON struct {
	ID             string                        `json:"id"`
	ResumeID       string                        `json:"resume_id"`
	Kind           string                        `json:"kind"`
	ResourceType   string                        `json:"resource_type"`
	ResourceID     string                        `json:"resource_id"`
	HostNode       *string                       `json:"host_node,omitempty"`
	OrchestratorID *string                       `json:"orchestrator_id,omitempty"`
	NetworkID      *string                       `json:"network_id,omitempty"`
	PlanRevision   *string                       `json:"plan_revision,omitempty"`
	Status         isolatedstate.OperationStatus `json:"status"`
	CurrentPhase   string                        `json:"current_phase"`
	ErrorCode      *string                       `json:"error_code,omitempty"`
	ErrorText      *string                       `json:"error_text,omitempty"`
	CreatedAt      isolatedstate.UnixSeconds     `json:"created_at_unix"`
	UpdatedAt      isolatedstate.UnixSeconds     `json:"updated_at_unix"`
	FinishedAt     *isolatedstate.UnixSeconds    `json:"finished_at_unix,omitempty"`
	Phases         []isolatedOperationPhaseJSON  `json:"phases"`
}

type isolatedOperationPhaseJSON struct {
	PhaseIndex int                                `json:"phase_index"`
	PhaseName  string                             `json:"phase_name"`
	Generation *isolatedstate.Generation          `json:"generation,omitempty"`
	Status     isolatedstate.OperationPhaseStatus `json:"status"`
	Attempt    int                                `json:"attempt"`
	StartedAt  *isolatedstate.UnixSeconds         `json:"started_at_unix,omitempty"`
	FinishedAt *isolatedstate.UnixSeconds         `json:"finished_at_unix,omitempty"`
	ErrorText  *string                            `json:"error_text,omitempty"`
}

type isolatedOperationsJSON struct {
	Operations []isolatedOperationJSON `json:"operations"`
	Page       isolatedPageJSON        `json:"page"`
	Errors     []isolatedErrorJSON     `json:"errors"`
}

func (s *Server) handleIsolatedOperations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state, err := s.isolated.reader()
	if err != nil {
		writePortalJSON(w, http.StatusServiceUnavailable, isolatedOperationsJSON{
			Operations: []isolatedOperationJSON{},
			Errors:     []isolatedErrorJSON{{Scope: "state", Error: err.Error()}},
		})
		return
	}
	limit, offset := isolatedPage(r, "", defaultIsolatedLimit)
	phaseLimit := isolatedLimit(r, "phase_limit", 100, 500)
	operations, total, hasMore, err := loadOperations(r.Context(), state, limit, offset)
	result := isolatedOperationsJSON{
		Operations: operations,
		Page: isolatedPageJSON{
			Limit: limit, Offset: offset, Total: total, HasMore: hasMore,
		},
		Errors: []isolatedErrorJSON{},
	}
	if err != nil {
		result.Operations = []isolatedOperationJSON{}
		result.Errors = append(result.Errors, isolatedErrorJSON{Scope: "operations", Error: err.Error()})
		writePortalJSON(w, http.StatusOK, result)
		return
	}
	for index := range result.Operations {
		phases, phaseErr := loadOperationPhases(
			r.Context(), state, result.Operations[index].ID, phaseLimit, 0,
		)
		if phaseErr != nil {
			result.Errors = append(result.Errors, isolatedErrorJSON{
				Scope: "operation:" + result.Operations[index].ID, Error: phaseErr.Error(),
			})
			continue
		}
		result.Operations[index].Phases = phases
	}
	writePortalJSON(w, http.StatusOK, result)
}

func (s *Server) handleIsolatedOperation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	state, err := s.isolated.reader()
	if err != nil {
		writePortalJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	operation, err := loadOperation(r.Context(), state, id)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "operation not found", http.StatusNotFound)
		return
	}
	if err != nil {
		writePortalJSON(w, http.StatusOK, map[string]any{"error": err.Error()})
		return
	}
	limit, offset := isolatedPage(r, "phase_", 100)
	phases, phaseErr := loadOperationPhases(r.Context(), state, id, limit+1, offset)
	hasMore := len(phases) > limit
	if hasMore {
		phases = phases[:limit]
	}
	phaseTotal, countErr := countOperationPhases(r.Context(), state, id)
	if phaseErr == nil {
		phaseErr = countErr
	}
	operation.Phases = phases
	writePortalJSON(w, http.StatusOK, map[string]any{
		"operation": operation,
		"phases_page": isolatedPageJSON{
			Limit: limit, Offset: offset, Total: phaseTotal, HasMore: hasMore,
		},
		"error": errorText(phaseErr),
	})
}

func loadOperations(
	ctx context.Context,
	state isolatedStateReader,
	limit, offset int,
) ([]isolatedOperationJSON, int, bool, error) {
	total, err := countOperations(ctx, state)
	if err != nil {
		return nil, 0, false, err
	}
	rows, err := state.QueryContext(ctx, `
		SELECT id, kind, resource_type, resource_id, host_node, orchestrator_id,
		       network_id, plan_revision, status, current_phase, error_code,
		       error_text, created_at_unix, updated_at_unix, finished_at_unix
		FROM operations
		ORDER BY created_at_unix DESC, id DESC
		LIMIT ? OFFSET ?`, limit+1, offset)
	if err != nil {
		return nil, 0, false, err
	}
	defer rows.Close()
	values := []isolatedOperationJSON{}
	for rows.Next() {
		value, err := scanOperation(rows)
		if err != nil {
			return nil, 0, false, err
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, false, err
	}
	hasMore := len(values) > limit
	if hasMore {
		values = values[:limit]
	}
	return values, total, hasMore, nil
}

func countOperations(ctx context.Context, state isolatedStateReader) (int, error) {
	rows, err := state.QueryContext(ctx, `SELECT COUNT(*) FROM operations`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return 0, err
		}
		return 0, sql.ErrNoRows
	}
	var total int
	if err := rows.Scan(&total); err != nil {
		return 0, err
	}
	return total, rows.Err()
}

func loadOperation(
	ctx context.Context,
	state isolatedStateReader,
	id string,
) (isolatedOperationJSON, error) {
	rows, err := state.QueryContext(ctx, `
		SELECT id, kind, resource_type, resource_id, host_node, orchestrator_id,
		       network_id, plan_revision, status, current_phase, error_code,
		       error_text, created_at_unix, updated_at_unix, finished_at_unix
		FROM operations WHERE id=?`, strings.ToLower(id))
	if err != nil {
		return isolatedOperationJSON{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return isolatedOperationJSON{}, err
		}
		return isolatedOperationJSON{}, sql.ErrNoRows
	}
	return scanOperation(rows)
}

type rowScanner interface {
	Scan(...any) error
}

func scanOperation(row rowScanner) (isolatedOperationJSON, error) {
	var value isolatedOperationJSON
	err := row.Scan(
		&value.ID, &value.Kind, &value.ResourceType, &value.ResourceID,
		&value.HostNode, &value.OrchestratorID, &value.NetworkID,
		&value.PlanRevision, &value.Status, &value.CurrentPhase,
		&value.ErrorCode, &value.ErrorText, &value.CreatedAt,
		&value.UpdatedAt, &value.FinishedAt,
	)
	value.ResumeID = value.ID
	value.Phases = []isolatedOperationPhaseJSON{}
	return value, err
}

func loadOperationPhases(
	ctx context.Context,
	state isolatedStateReader,
	operationID string,
	limit, offset int,
) ([]isolatedOperationPhaseJSON, error) {
	rows, err := state.QueryContext(ctx, `
		SELECT phase_index, phase_name, generation, status, attempt,
		       started_at_unix, finished_at_unix, error_text
		FROM operation_phases
		WHERE operation_id=?
		ORDER BY phase_index, attempt
		LIMIT ? OFFSET ?`, strings.ToLower(operationID), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []isolatedOperationPhaseJSON{}
	for rows.Next() {
		var value isolatedOperationPhaseJSON
		if err := rows.Scan(
			&value.PhaseIndex, &value.PhaseName, &value.Generation,
			&value.Status, &value.Attempt, &value.StartedAt,
			&value.FinishedAt, &value.ErrorText,
		); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func countOperationPhases(
	ctx context.Context,
	state isolatedStateReader,
	operationID string,
) (int, error) {
	rows, err := state.QueryContext(ctx, `
		SELECT COUNT(*) FROM operation_phases WHERE operation_id=?`,
		strings.ToLower(operationID),
	)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return 0, err
		}
		return 0, sql.ErrNoRows
	}
	var total int
	if err := rows.Scan(&total); err != nil {
		return 0, err
	}
	return total, rows.Err()
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
		LastFailure:                  value.LastFailure, RelayGeneration: value.RelayGeneration,
		ApplianceGeneration: value.ApplianceGeneration,
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

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func writePortalJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(value)
}
