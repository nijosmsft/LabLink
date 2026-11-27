package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
	"github.com/nijosmsft/lablink/internal/registry"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

const (
	vmHostLabel = "lablink.vm_host"
	vmIDLabel   = "lablink.vm_id"
	vmMACLabel  = "lablink.vm_mac"
)

type vmEndpointBinding struct {
	Node         *registry.Node              `json:"-"`
	VMID         string                      `json:"vm_id"`
	MAC          string                      `json:"mac"`
	VSwitch      string                      `json:"vswitch"`
	NodeName     string                      `json:"node_name"`
	Orchestrator *isolatedstate.Orchestrator `json:"-"`
}

type vmEndpointObservation struct {
	NodeName  string   `json:"node_name"`
	VMID      string   `json:"vm_id"`
	MAC       string   `json:"mac"`
	State     string   `json:"state"`
	Addresses []string `json:"addresses"`
	Error     string   `json:"error"`
}

// VMEndpointReconciler resolves managed endpoints through the owning Hyper-V
// host, never through an unauthenticated subnet scan or an IP-derived identity.
type VMEndpointReconciler struct {
	gate     chan struct{}
	reg      *registry.Registry
	pool     *agentclient.Pool
	state    *isolatedstate.Store
	discover func(context.Context, string, []vmEndpointBinding) ([]vmEndpointObservation, error)
	probe    func(context.Context, *registry.Node, string) error
}

func NewVMEndpointReconciler(reg *registry.Registry, pool *agentclient.Pool, state *isolatedstate.Store) *VMEndpointReconciler {
	r := &VMEndpointReconciler{reg: reg, pool: pool, state: state, gate: make(chan struct{}, 1)}
	r.discover = r.discoverOnHost
	r.probe = r.probeEndpoint
	return r
}

func normalizeVMMAC(value string) string {
	return strings.ToUpper(strings.NewReplacer(":", "", "-", "").Replace(strings.TrimSpace(value)))
}

func (r *VMEndpointReconciler) Reconcile(ctx context.Context) error {
	select {
	case r.gate <- struct{}{}:
		defer func() { <-r.gate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	nodes := r.reg.AllNodes()
	byName := make(map[string]*registry.Node, len(nodes))
	bindings := make(map[string]map[string]vmEndpointBinding)
	restricted := make(map[string]bool)
	for _, node := range nodes {
		byName[node.Name] = node
		if source := node.Labels[localVMSourceLabel]; source != "" {
			restricted[source] = true
			continue
		}
		if node.Labels["lablink.local_hyperv"] == "true" {
			restricted[node.Name] = true
		}
		host, vmID, mac := node.Labels[vmHostLabel], node.Labels[vmIDLabel], node.Labels[vmMACLabel]
		if host != "" && vmID != "" && mac != "" && node.Labels["lablink.kind"] != "isolated-vm" {
			if bindings[host] == nil {
				bindings[host] = make(map[string]vmEndpointBinding)
			}
			bindings[host][node.Name] = vmEndpointBinding{
				Node: node, NodeName: node.Name, VMID: vmID, MAC: normalizeVMMAC(mac),
			}
		}
	}
	orchestrators, err := r.state.ListOrchestrators(ctx, "")
	if err != nil {
		return err
	}
	for _, orchestrator := range orchestrators {
		node := byName[orchestrator.NodeName]
		if !simpleActiveOrchestrator(orchestrator) || node == nil || node.Labels[localVMSourceLabel] != "" {
			continue
		}
		if valueOrEmpty(orchestrator.HyperVVMID) == "" {
			continue
		}
		host := orchestrator.HostNode
		if bindings[host] == nil {
			bindings[host] = make(map[string]vmEndpointBinding)
		}
		bindings[host][node.Name] = vmEndpointBinding{
			Node: node, NodeName: node.Name, VMID: valueOrEmpty(orchestrator.HyperVVMID),
			MAC:     normalizeVMMAC(valueOrEmpty(orchestrator.MainMAC)),
			VSwitch: orchestrator.MainVSwitch, Orchestrator: &orchestrator,
		}
	}
	var failures []error
	var failureMu sync.Mutex
	var hosts sync.WaitGroup
	hostSlots := make(chan struct{}, 4)
	run := func(label string, action func(context.Context) error) {
		hosts.Add(1)
		go func() {
			defer hosts.Done()
			select {
			case hostSlots <- struct{}{}:
				defer func() { <-hostSlots }()
			case <-ctx.Done():
				failureMu.Lock()
				failures = append(failures, fmt.Errorf("%s: %w", label, ctx.Err()))
				failureMu.Unlock()
				return
			}
			hostCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
			defer cancel()
			if err := action(hostCtx); err != nil {
				failureMu.Lock()
				failures = append(failures, fmt.Errorf("%s: %w", label, err))
				failureMu.Unlock()
			}
		}()
	}
	for source := range restricted {
		run("refresh Hyper-V host "+source, func(ctx context.Context) error { return r.syncRestrictedHost(ctx, source) })
	}
	for host, group := range bindings {
		run("refresh VMs on "+host, func(ctx context.Context) error { return r.reconcileHost(ctx, host, group, byName) })
	}
	hosts.Wait()
	return errors.Join(failures...)
}

func (r *VMEndpointReconciler) reconcileHost(ctx context.Context, host string, group map[string]vmEndpointBinding, byName map[string]*registry.Node) error {
	list := make([]vmEndpointBinding, 0, len(group))
	for _, binding := range group {
		list = append(list, binding)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].NodeName < list[j].NodeName })
	observations, err := r.discover(ctx, host, list)
	if err != nil {
		return err
	}
	var workers sync.WaitGroup
	slots := make(chan struct{}, 10)
	var failureMu sync.Mutex
	var failures []error
	seen := make(map[string]bool, len(observations))
	for _, observation := range observations {
		binding, found := group[observation.NodeName]
		if !found || seen[observation.NodeName] {
			failureMu.Lock()
			failures = append(failures, fmt.Errorf("host returned an unexpected or duplicate VM %q", observation.NodeName))
			failureMu.Unlock()
			continue
		}
		seen[observation.NodeName] = true
		workers.Add(1)
		go func() {
			defer workers.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				return
			}
			if err := r.reconcileBinding(ctx, binding, observation, byName); err != nil {
				failureMu.Lock()
				failures = append(failures, fmt.Errorf("%s: %w", binding.NodeName, err))
				failureMu.Unlock()
			}
		}()
	}
	workers.Wait()
	for name := range group {
		if !seen[name] {
			failures = append(failures, fmt.Errorf("host omitted VM %q", name))
		}
	}
	if ctx.Err() != nil {
		failures = append(failures, ctx.Err())
	}
	return errors.Join(failures...)
}

func (r *VMEndpointReconciler) discoverOnHost(ctx context.Context, host string, bindings []vmEndpointBinding) ([]vmEndpointObservation, error) {
	target, err := resolvePlanTarget(host, r.reg)
	if err != nil {
		return nil, err
	}
	script, err := buildVMEndpointDiscoveryScript(bindings)
	if err != nil {
		return nil, err
	}
	out, _, err := runPS(ctx, r.reg, r.pool, target, script, 20)
	if err != nil {
		return nil, err
	}
	var rows []vmEndpointObservation
	if err := json.Unmarshal([]byte(jsonExtract(out)), &rows); err != nil {
		return nil, fmt.Errorf("decode VM endpoint discovery: %w", err)
	}
	return rows, nil
}

func buildVMEndpointDiscoveryScript(bindings []vmEndpointBinding) (string, error) {
	data, err := json.Marshal(bindings)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`
$bindings = ConvertFrom-Json %s
$rows = foreach ($binding in $bindings) {
    try {
        $vm = Get-VM -Id ([guid]$binding.vm_id) -ErrorAction Stop
        $adapters = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop | Where-Object {
            if ($binding.mac) { $_.MacAddress.Replace(':','').Replace('-','') -ieq $binding.mac }
            else { $_.SwitchName -ceq $binding.vswitch }
        })
        if ($adapters.Count -ne 1) { throw 'management NIC binding is missing or ambiguous' }
        [pscustomobject]@{
            node_name=[string]$binding.node_name; vm_id=[string]$vm.Id
            mac=[string]$adapters[0].MacAddress; state=[string]$vm.State
            addresses=@($adapters[0].IPAddresses); error=''
        }
    } catch {
        [pscustomobject]@{ node_name=[string]$binding.node_name; error=$_.Exception.Message }
    }
}
ConvertTo-Json -InputObject @($rows) -Depth 4 -Compress
`, hyperv.PSLit(string(data))), nil
}

func (r *VMEndpointReconciler) probeEndpoint(ctx context.Context, node *registry.Node, address string) error {
	if node.TransportMode != "mtls" {
		return fmt.Errorf("endpoint refresh requires mTLS for node %q", node.Name)
	}
	endpoint := agentclient.Endpoint{Address: address, TLSServerName: node.TLSServerName}
	client, err := r.pool.GetMTLSEndpointClient(endpoint)
	if err != nil {
		return err
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = client.GetInfo(probeCtx, &pb.GetInfoRequest{})
	if err != nil && address != node.Address {
		r.pool.ResetEndpoint(endpoint)
	}
	return err
}

func (r *VMEndpointReconciler) reconcileBinding(ctx context.Context, binding vmEndpointBinding, observed vmEndpointObservation, byName map[string]*registry.Node) error {
	if observed.Error != "" {
		return errors.New(observed.Error)
	}
	if !strings.EqualFold(binding.VMID, observed.VMID) ||
		binding.MAC != "" && binding.MAC != normalizeVMMAC(observed.MAC) {
		return fmt.Errorf("host returned a different VM or management NIC identity")
	}
	if observed.State != "Running" {
		return nil
	}
	_, port, err := net.SplitHostPort(binding.Node.Address)
	if err != nil {
		return fmt.Errorf("invalid registered endpoint: %w", err)
	}
	// Try the current address first so additional addresses do not cause churn.
	currentIP := nodeHost(binding.Node.Address)
	sort.SliceStable(observed.Addresses, func(i, j int) bool {
		return observed.Addresses[i] == currentIP && observed.Addresses[j] != currentIP
	})
	var failures []error
	for _, candidate := range observed.Addresses {
		ip, err := netip.ParseAddr(candidate)
		if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() {
			continue
		}
		address := net.JoinHostPort(ip.String(), port)
		if err := r.probe(ctx, binding.Node, address); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", address, err))
			continue
		}
		changed := []*registry.Node{binding.Node}
		addresses := map[string]string{binding.Node.Name: address}
		if parent := binding.Orchestrator; parent != nil {
			vms, err := r.state.ListVMs(ctx, parent.ID, "")
			if err != nil {
				return err
			}
			relays, err := r.state.ListRelays(ctx, parent.ID, "")
			if err != nil {
				return err
			}
			byVM := make(map[string]isolatedstate.RelayAllocation, len(relays))
			for _, relay := range relays {
				if simpleActiveRelay(relay) {
					byVM[relay.VMID] = relay
				}
			}
			for _, vm := range vms {
				child := byName[vm.NodeName]
				if !simpleActiveVM(vm) || child == nil {
					continue
				}
				relay, found := byVM[vm.ID]
				if !found || child.Labels["lablink.orchestrator_id"] != parent.ID {
					return fmt.Errorf("VM %q has no matching registered relay binding", vm.ID)
				}
				changed = append(changed, child)
				addresses[child.Name] = net.JoinHostPort(ip.String(), strconv.Itoa(relay.ListenPort))
			}
			if valueOrEmpty(parent.MainIP) != ip.String() {
				if err := r.state.UpdateOrchestratorMainIP(ctx, parent.ID, binding.VMID, ip.String(), time.Now().Unix()); err != nil {
					return err
				}
			}
		}
		var updates []*registry.Node
		for _, node := range changed {
			if node.Address != addresses[node.Name] {
				updates = append(updates, node)
			}
		}
		if len(updates) == 0 {
			return nil
		}
		if err := r.reg.UpdateAddresses(changed, addresses); err != nil {
			return err
		}
		for _, node := range updates {
			r.pool.ResetEndpoint(agentclient.Endpoint{Address: node.Address, TLSServerName: node.TLSServerName})
		}
		return nil
	}
	if len(failures) == 0 {
		return fmt.Errorf("running VM has no usable management IPv4 from Hyper-V")
	}
	return fmt.Errorf("no discovered endpoint authenticated: %w", errors.Join(failures...))
}

func (r *VMEndpointReconciler) syncRestrictedHost(ctx context.Context, source string) error {
	host, found := r.reg.GetNode(source)
	if !found {
		return fmt.Errorf("owning host is not registered")
	}
	client, err := r.pool.GetMTLSEndpointClient(agentclient.Endpoint{Address: host.Address, TLSServerName: host.TLSServerName})
	if err != nil {
		return err
	}
	stream, err := client.ManageVM(ctx, &pb.ManageVMRequest{
		ToolName: "list_isolated_orchestrators", ArgumentsJson: []byte(`{"target":"localhost"}`), ProfilesJson: []byte(`{}`),
	})
	if err != nil {
		return err
	}
	var nodes []*registry.Node
	received := false
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if len(response.ResultJson) == 0 {
			continue
		}
		var result mcp.CallToolResult
		if err := json.Unmarshal(response.ResultJson, &result); err != nil {
			return err
		}
		if result.IsError {
			return fmt.Errorf("restricted endpoint refresh: %s", toolResultText(&result))
		}
		if err := json.Unmarshal(response.NodesJson, &nodes); err != nil {
			return fmt.Errorf("decode refreshed VM nodes: %w", err)
		}
		received = true
	}
	if !received {
		return fmt.Errorf("restricted endpoint refresh returned no node snapshot")
	}
	old := r.reg.AllNodes()
	if err := updateLocalVMNodes(r.reg, source, nodes); err != nil {
		return err
	}
	for _, node := range old {
		current, found := r.reg.GetNode(node.Name)
		if found && current.Address != node.Address {
			r.pool.ResetEndpoint(agentclient.Endpoint{Address: node.Address, TLSServerName: node.TLSServerName})
		}
	}
	return nil
}
