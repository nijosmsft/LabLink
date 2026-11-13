package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/isolated"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
)

func RegisterSimpleIsolatedLifecycleTools(s *server.MCPServer, deps *isolatedLifecycleDeps) {
	s.AddTool(mcp.NewTool("create_isolated_orchestrator",
		mcp.WithDescription("Create an isolated orchestrator using the normal Linux VM lifecycle."),
		mcp.WithString("target", mcp.Description("localhost or a registered Windows Hyper-V host")),
		mcp.WithString("orchestrator_id", mcp.Description("Optional exact orchestrator UUID")),
		mcp.WithString("display_name", mcp.Description("Mutable display label")),
		mcp.WithString("profile", mcp.Description("Isolated orchestrator profile")),
		mcp.WithString("main_vswitch", mcp.Description("Existing main vSwitch override")),
		mcp.WithBoolean("dry_run"),
	), createSimpleIsolatedOrchestratorHandler(deps))
	s.AddTool(mcp.NewTool("list_isolated_orchestrators",
		mcp.WithString("target"), mcp.WithBoolean("include_deleted"), mcp.WithBoolean("live"),
	), listSimpleIsolatedOrchestratorsHandler(deps))
	s.AddTool(mcp.NewTool("get_isolated_orchestrator",
		mcp.WithString("orchestrator_id", mcp.Required()), mcp.WithBoolean("live"),
	), getSimpleIsolatedOrchestratorHandler(deps))
	s.AddTool(mcp.NewTool("delete_isolated_orchestrator",
		mcp.WithDescription("Delete the orchestrator using the normal VM deletion flow. cascade=true first removes its isolated guests and networks."),
		mcp.WithString("orchestrator_id", mcp.Required()),
		mcp.WithBoolean("cascade"),
		mcp.WithBoolean("delete_storage", mcp.Description("Delete exact managed VM storage (default true)")),
	), deleteSimpleIsolatedOrchestratorHandler(deps))

	s.AddTool(mcp.NewTool("add_isolated_network",
		mcp.WithDescription("Create a private vSwitch and attach it to the orchestrator."),
		mcp.WithString("target"),
		mcp.WithString("orchestrator_id", mcp.Required()),
		mcp.WithString("display_name"),
		mcp.WithBoolean("dry_run"),
	), addSimpleIsolatedNetworkHandler(deps))
	s.AddTool(mcp.NewTool("remove_isolated_network",
		mcp.WithString("network_id", mcp.Required()),
	), removeSimpleIsolatedNetworkHandler(deps))

	s.AddTool(mcp.NewTool("create_isolated_vm",
		mcp.WithDescription("Create a Windows or Linux VM through the normal VM lifecycle, with private static networking, relay, and optional NAT."),
		mcp.WithString("network_id", mcp.Required()),
		mcp.WithString("name", mcp.Required(), mcp.Description("Hyper-V VM name, matching the normal VM flow")),
		mcp.WithString("display_name"),
		mcp.WithString("guest_os", mcp.Required()),
		mcp.WithString("profile", mcp.Required()),
		mcp.WithBoolean("nat_enabled"),
		mcp.WithString("bootstrap_network_requirement"),
		mcp.WithBoolean("known_network_bootstrap"),
		mcp.WithArray("reachable_services"),
		windowsDomainJoinSchema("domain_join", "Optional post-relay Windows domain join"),
	), createSimpleIsolatedVMHandler(deps))
	s.AddTool(mcp.NewTool("delete_isolated_vm",
		mcp.WithString("isolated_vm_id", mcp.Required()),
		mcp.WithBoolean("delete_storage", mcp.Description("Delete exact managed VM storage (default true)")),
	), deleteSimpleIsolatedVMHandler(deps))
	s.AddTool(mcp.NewTool("list_isolated_vms",
		mcp.WithString("target"), mcp.WithString("orchestrator_id"),
		mcp.WithString("network_id"), mcp.WithBoolean("include_deleted"), mcp.WithBoolean("live"),
	), listSimpleIsolatedVMsHandler(deps))
	s.AddTool(mcp.NewTool("get_isolated_vm",
		mcp.WithString("isolated_vm_id", mcp.Required()), mcp.WithBoolean("live"),
	), getSimpleIsolatedVMHandler(deps))
	s.AddTool(mcp.NewTool("rename_isolated_display_name",
		mcp.WithString("resource_type", mcp.Required()),
		mcp.WithString("resource_id", mcp.Required()),
		mcp.WithString("display_name", mcp.Required()),
	), renameSimpleIsolatedDisplayNameHandler(deps))

	s.AddTool(mcp.NewTool("enable_isolated_vm_nat",
		mcp.WithString("isolated_vm_id", mcp.Required()),
	), setSimpleIsolatedNATHandler(deps, true))
	s.AddTool(mcp.NewTool("disable_isolated_vm_nat",
		mcp.WithString("isolated_vm_id", mcp.Required()),
	), setSimpleIsolatedNATHandler(deps, false))
	s.AddTool(mcp.NewTool("get_isolated_vm_nat",
		mcp.WithString("isolated_vm_id", mcp.Required()), mcp.WithBoolean("live"),
	), getSimpleIsolatedNATHandler(deps))
	s.AddTool(mcp.NewTool("list_isolated_vm_nat",
		mcp.WithString("orchestrator_id"), mcp.WithString("network_id"),
		mcp.WithString("state"), mcp.WithBoolean("live"),
	), listSimpleIsolatedNATHandler(deps))

	s.AddTool(mcp.NewTool("list_isolated_relays",
		mcp.WithString("orchestrator_id"), mcp.WithString("network_id"),
		mcp.WithString("isolated_vm_id"), mcp.WithBoolean("live"),
	), listSimpleIsolatedRelaysHandler(deps))
	s.AddTool(mcp.NewTool("get_isolated_relay_stats",
		mcp.WithString("relay_id"), mcp.WithString("orchestrator_id"),
	), getSimpleIsolatedRelayStatsHandler(deps))
	s.AddTool(mcp.NewTool("validate_isolated_relay",
		mcp.WithString("relay_id", mcp.Required()), mcp.WithBoolean("probe_target"),
	), validateSimpleIsolatedRelayHandler(deps))
	s.AddTool(mcp.NewTool("rebind_isolated_relays",
		mcp.WithString("orchestrator_id", mcp.Required()),
	), rebindSimpleIsolatedRelaysHandler(deps))
}

func simpleIsolatedResult(header string, value any) *mcp.CallToolResult {
	data, _ := json.MarshalIndent(value, "", "  ")
	return vmResult(header, string(data))
}

func simpleActiveOrchestrator(value isolatedstate.Orchestrator) bool {
	return value.LifecycleState != isolatedstate.OrchestratorDeleted
}

func simpleActiveNetwork(value isolatedstate.PrivateNetwork) bool {
	return value.LifecycleState != isolatedstate.NetworkDeleted && value.RetiredAt == nil
}

func simpleActiveVM(value isolatedstate.IsolatedVM) bool {
	return value.LifecycleState != isolatedstate.VMDeleted && value.RetiredAt == nil
}

func buildStaticApplianceConfig(
	ctx context.Context,
	deps *isolatedLifecycleDeps,
	orchestratorID string,
) (appliance.StaticConfig, error) {
	networks, err := deps.state.ListNetworks(ctx, orchestratorID)
	if err != nil {
		return appliance.StaticConfig{}, err
	}
	vms, err := deps.state.ListVMs(ctx, orchestratorID, "")
	if err != nil {
		return appliance.StaticConfig{}, err
	}
	relays, err := deps.state.ListRelays(ctx, orchestratorID, "")
	if err != nil {
		return appliance.StaticConfig{}, err
	}
	nat, err := deps.state.ListNAT(ctx, orchestratorID, "", "")
	if err != nil {
		return appliance.StaticConfig{}, err
	}

	config := appliance.StaticConfig{}
	for _, value := range networks {
		if !simpleActiveNetwork(value) {
			continue
		}
		config.Networks = append(config.Networks, appliance.StaticNetwork{
			ID: value.ID, CIDR: value.CIDR, GatewayIPv4: value.GatewayIPv4,
			NICMAC: value.OrchestratorMAC, DNSServersJSON: value.DNSServersJSON,
		})
	}
	activeVMs := map[string]isolatedstate.IsolatedVM{}
	for _, value := range vms {
		if !simpleActiveVM(value) {
			continue
		}
		activeVMs[value.ID] = value
		config.Guests = append(config.Guests, appliance.StaticGuest{
			ID: value.ID, NetworkID: value.NetworkID,
			IPv4: value.IPv4, MAC: value.MAC,
		})
	}
	for _, value := range relays {
		if value.LifecycleState == isolatedstate.RelayRemoved || value.RetiredAt != nil {
			continue
		}
		if _, exists := activeVMs[value.VMID]; !exists {
			continue
		}
		config.Relays = append(config.Relays, appliance.StaticRelay{
			ID: value.ID, VMID: value.VMID, ListenPort: int64(value.ListenPort),
			TargetIPv4: value.TargetIPv4, TargetPort: int64(value.TargetPort),
		})
	}
	for _, value := range nat {
		if _, exists := activeVMs[value.VMID]; !exists {
			continue
		}
		config.NAT = append(config.NAT, appliance.StaticNAT{
			VMID: value.VMID, ConntrackMark: value.ConntrackMark,
			Enabled: value.State == isolatedstate.NATEnabled,
		})
	}
	return config, nil
}

func configureStaticAppliance(
	ctx context.Context,
	deps *isolatedLifecycleDeps,
	orchestratorID string,
	retire []appliance.RetiredNAT,
) (isolated.ApplianceSnapshot, error) {
	config, err := buildStaticApplianceConfig(ctx, deps, orchestratorID)
	if err != nil {
		return isolated.ApplianceSnapshot{}, err
	}
	return deps.appliance.ConfigureStatic(ctx, orchestratorID, config, retire)
}

func configureStaticAfterPrivateNICReady(
	ctx context.Context,
	timeout time.Duration,
	interval time.Duration,
	configure func() (isolated.ApplianceSnapshot, error),
) (isolated.ApplianceSnapshot, error) {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var lastErr error
	for {
		snapshot, err := configure()
		if err == nil {
			return snapshot, nil
		}
		lastErr = err
		if !strings.Contains(strings.ToLower(err.Error()), "no interface has mac") {
			return isolated.ApplianceSnapshot{}, err
		}
		timer := time.NewTimer(interval)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			return isolated.ApplianceSnapshot{}, fmt.Errorf(
				"wait for private NIC readiness: %w", lastErr)
		case <-timer.C:
		}
	}
}

func listSimpleIsolatedOrchestratorsHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		target := strings.TrimSpace(req.GetString("target", ""))
		values, err := deps.state.ListOrchestrators(ctx, "")
		if err != nil {
			return isolatedError(err)
		}
		includeDeleted := req.GetBool("include_deleted", false)
		result := make([]isolatedstate.Orchestrator, 0, len(values))
		for _, value := range values {
			if target != "" && !strings.EqualFold(value.HostNode, target) {
				continue
			}
			if !includeDeleted && !simpleActiveOrchestrator(value) {
				continue
			}
			result = append(result, value)
		}
		return simpleIsolatedResult("**Isolated orchestrators**", result), nil
	}
}

func getSimpleIsolatedOrchestratorHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		value, err := deps.state.GetOrchestrator(ctx,
			strings.TrimSpace(req.GetString("orchestrator_id", "")))
		if err != nil {
			return isolatedError(err)
		}
		result := map[string]any{"orchestrator": value}
		if req.GetBool("live", false) && simpleActiveOrchestrator(value) {
			if live, liveErr := deps.appliance.InspectApplianceState(ctx, value.ID); liveErr == nil {
				result["live"] = live
			} else {
				result["live_error"] = liveErr.Error()
			}
		}
		return simpleIsolatedResult("**Isolated orchestrator**", result), nil
	}
}

func listSimpleIsolatedVMsHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		orchestratorID := strings.TrimSpace(req.GetString("orchestrator_id", ""))
		networkID := strings.TrimSpace(req.GetString("network_id", ""))
		values, err := deps.state.ListVMs(ctx, orchestratorID, networkID)
		if err != nil {
			return isolatedError(err)
		}
		includeDeleted := req.GetBool("include_deleted", false)
		result := make([]isolatedstate.IsolatedVM, 0, len(values))
		for _, value := range values {
			if !includeDeleted && !simpleActiveVM(value) {
				continue
			}
			result = append(result, value)
		}
		return simpleIsolatedResult("**Isolated VMs**", result), nil
	}
}

func getSimpleIsolatedVMHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		value, err := deps.state.GetVM(ctx,
			strings.TrimSpace(req.GetString("isolated_vm_id", "")))
		if err != nil {
			return isolatedError(err)
		}
		return simpleIsolatedResult("**Isolated VM**", value), nil
	}
}

func renameSimpleIsolatedDisplayNameHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		resourceType := strings.ToLower(strings.TrimSpace(req.GetString("resource_type", "")))
		resourceID := strings.TrimSpace(req.GetString("resource_id", ""))
		displayName := strings.TrimSpace(req.GetString("display_name", ""))
		if displayName == "" {
			return isolatedError(errors.New("display_name is required"))
		}
		var resource any
		switch resourceType {
		case "orchestrator":
			value, err := deps.state.GetOrchestrator(ctx, resourceID)
			if err != nil {
				return isolatedError(err)
			}
			value.DisplayName, value.UpdatedAt = displayName, isolatedNow()
			if err := deps.state.PutOrchestrator(ctx, value); err != nil {
				return isolatedError(err)
			}
			resource = value
		case "network":
			value, err := deps.state.GetNetwork(ctx, resourceID)
			if err != nil {
				return isolatedError(err)
			}
			value.DisplayName, value.UpdatedAt = displayName, isolatedNow()
			if err := deps.state.PutNetwork(ctx, value); err != nil {
				return isolatedError(err)
			}
			resource = value
		case "vm":
			value, err := deps.state.GetVM(ctx, resourceID)
			if err != nil {
				return isolatedError(err)
			}
			value.DisplayName, value.UpdatedAt = displayName, isolatedNow()
			if err := deps.state.PutVM(ctx, value); err != nil {
				return isolatedError(err)
			}
			resource = value
		default:
			return isolatedError(fmt.Errorf("resource_type must be orchestrator, network, or vm"))
		}
		return simpleIsolatedResult("**Display name updated**", resource), nil
	}
}

func setSimpleIsolatedNATHandler(
	deps *isolatedLifecycleDeps,
	enabled bool,
) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		vm, err := deps.state.GetVM(ctx,
			strings.TrimSpace(req.GetString("isolated_vm_id", "")))
		if err != nil {
			return isolatedError(err)
		}
		nat, err := deps.state.GetNAT(ctx, vm.ID)
		if err != nil {
			return isolatedError(err)
		}
		if enabled {
			nat.State = isolatedstate.NATEnabled
		} else {
			nat.State = isolatedstate.NATDisabled
		}
		nat.UpdatedAt = isolatedNow()
		if err := deps.state.PutNAT(ctx, nat); err != nil {
			return isolatedError(err)
		}
		if _, err := configureStaticAppliance(ctx, deps, vm.OrchestratorID, nil); err != nil {
			return isolatedError(err)
		}
		return simpleIsolatedResult("**Isolated VM NAT updated**", nat), nil
	}
}

func getSimpleIsolatedNATHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nat, err := deps.state.GetNAT(ctx,
			strings.TrimSpace(req.GetString("isolated_vm_id", "")))
		if err != nil {
			return isolatedError(err)
		}
		return simpleIsolatedResult("**Isolated VM NAT**", nat), nil
	}
}

func listSimpleIsolatedNATHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		values, err := deps.state.ListNAT(ctx,
			strings.TrimSpace(req.GetString("orchestrator_id", "")),
			strings.TrimSpace(req.GetString("network_id", "")),
			strings.TrimSpace(req.GetString("state", "")))
		if err != nil {
			return isolatedError(err)
		}
		return simpleIsolatedResult("**Isolated VM NAT**", values), nil
	}
}

func listSimpleIsolatedRelaysHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		values, err := deps.state.ListRelays(ctx,
			strings.TrimSpace(req.GetString("orchestrator_id", "")),
			strings.TrimSpace(req.GetString("isolated_vm_id", "")))
		if err != nil {
			return isolatedError(err)
		}
		networkID := strings.TrimSpace(req.GetString("network_id", ""))
		if networkID != "" {
			filtered := values[:0]
			for _, value := range values {
				vm, getErr := deps.state.GetVM(ctx, value.VMID)
				if getErr == nil && vm.NetworkID == networkID {
					filtered = append(filtered, value)
				}
			}
			values = filtered
		}
		return simpleIsolatedResult("**Isolated relays**", values), nil
	}
}

func getSimpleIsolatedRelayStatsHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		relayID := strings.TrimSpace(req.GetString("relay_id", ""))
		orchestratorID := strings.TrimSpace(req.GetString("orchestrator_id", ""))
		if (relayID == "") == (orchestratorID == "") {
			return isolatedError(errors.New("provide exactly one of relay_id or orchestrator_id"))
		}
		if relayID != "" {
			relay, err := deps.state.GetRelay(ctx, relayID)
			if err != nil {
				return isolatedError(err)
			}
			stats, err := deps.appliance.GetRelayStats(ctx, relay.OrchestratorID, relay.ID)
			if err != nil {
				return isolatedError(err)
			}
			return simpleIsolatedResult("**Isolated relay stats**", stats), nil
		}
		relays, err := deps.state.ListRelays(ctx, orchestratorID, "")
		if err != nil {
			return isolatedError(err)
		}
		result := make([]appliance.RelayStats, 0, len(relays))
		for _, relay := range relays {
			if relay.LifecycleState == isolatedstate.RelayRemoved {
				continue
			}
			stats, statsErr := deps.appliance.GetRelayStats(ctx, orchestratorID, relay.ID)
			if statsErr != nil {
				return isolatedError(statsErr)
			}
			result = append(result, stats)
		}
		return simpleIsolatedResult("**Isolated relay stats**", result), nil
	}
}

func validateSimpleIsolatedRelayHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		relay, err := deps.state.GetRelay(ctx,
			strings.TrimSpace(req.GetString("relay_id", "")))
		if err != nil {
			return isolatedError(err)
		}
		value, err := deps.appliance.ValidateRelay(
			ctx, relay.OrchestratorID, relay.ID, req.GetBool("probe_target", false))
		if err != nil {
			return isolatedError(err)
		}
		return simpleIsolatedResult("**Isolated relay validation**", value), nil
	}
}

func rebindSimpleIsolatedRelaysHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		orchestratorID := strings.TrimSpace(req.GetString("orchestrator_id", ""))
		snapshot, err := configureStaticAppliance(ctx, deps, orchestratorID, nil)
		if err != nil {
			return isolatedError(err)
		}
		return simpleIsolatedResult("**Isolated relays rebound**", snapshot.Config.Relays), nil
	}
}

func simpleGuestResources(
	vms []isolatedstate.IsolatedVM,
	relays []isolatedstate.RelayAllocation,
	nat []isolatedstate.NATAllocation,
	network isolatedstate.PrivateNetwork,
) (string, int, int, error) {
	prefix, err := netip.ParsePrefix(network.CIDR)
	if err != nil {
		return "", 0, 0, err
	}
	usedIP := map[string]bool{}
	usedPort := map[int]bool{}
	usedMark := map[int64]bool{}
	for _, value := range vms {
		if simpleActiveVM(value) {
			usedIP[value.IPv4] = true
		}
	}
	for _, value := range relays {
		if value.LifecycleState != isolatedstate.RelayRemoved {
			usedPort[value.ListenPort] = true
		}
	}
	for _, value := range nat {
		usedMark[value.ConntrackMark] = true
	}
	ip := ""
	for offset := isolated.FirstGuestAddressOffset; offset <= isolated.LastGuestAddressOffset; offset++ {
		address, addressErr := isolated.GuestAddress(prefix, offset)
		if addressErr == nil && !usedIP[address.String()] {
			ip = address.String()
			break
		}
	}
	port := 0
	for value := appliance.RelayPortMin; value <= appliance.RelayPortMax; value++ {
		if !usedPort[value] {
			port = value
			break
		}
	}
	mark := int64(0)
	for value := int64(1); value <= int64(^uint32(0)); value++ {
		if !usedMark[value] {
			mark = value
			break
		}
	}
	if ip == "" || port == 0 || mark == 0 {
		return "", 0, 0, errors.New("isolated guest network resources are exhausted")
	}
	return ip, port, int(mark), nil
}

func simpleOrchestratorForVM(
	ctx context.Context,
	deps *isolatedLifecycleDeps,
	vm isolatedstate.IsolatedVM,
) (isolatedstate.Orchestrator, Target, error) {
	orchestrator, err := deps.state.GetOrchestrator(ctx, vm.OrchestratorID)
	if err != nil {
		return isolatedstate.Orchestrator{}, Target{}, err
	}
	target, err := resolvePlanTarget(orchestrator.HostNode, deps.registry)
	return orchestrator, target, err
}

func withSimpleTargetLease(
	ctx context.Context,
	req mcp.CallToolRequest,
	deps *isolatedLifecycleDeps,
	target string,
	run server.ToolHandlerFunc,
) (*mcp.CallToolResult, error) {
	gated := req
	args := cloneArguments(req.GetArguments())
	args["target"] = target
	gated.Params.Arguments = args
	return LeaseGate(deps.lease, extractTarget("target"), run)(ctx, gated)
}

func simpleWaitProgress() *MCPProgressState {
	return NewMCPProgressState(35*time.Minute, "resolve", "configuration validated")
}

func simpleNormalDeleteRequest(
	req mcp.CallToolRequest,
	target, name, managedRoot, nodeName string,
	deleteStorage bool,
) mcp.CallToolRequest {
	value := req
	value.Params.Arguments = map[string]any{
		"target": target, "name": name, "dry_run": false,
		"force_stop": true, "delete_storage": deleteStorage,
		"managed_root": managedRoot, "unregister_node": true,
		"lablink_node_name": nodeName,
	}
	return value
}

func simpleVMHostIdentity(
	ctx context.Context,
	deps *isolatedLifecycleDeps,
	target Target,
	name string,
) (guid string, adapterID string, err error) {
	script := fmt.Sprintf(`
$vm = Get-VM -Name %s -ErrorAction Stop
$adapter = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop | Select-Object -First 1)
[pscustomobject]@{
  vm_guid=[string]$vm.Id
  adapter_id=if($adapter){[string]$adapter.Id}else{''}
} | ConvertTo-Json -Compress
`, hyperv.PSLit(name))
	out, _, err := runPS(ctx, deps.registry, deps.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return "", "", err
	}
	var value struct {
		VMGUID    string `json:"vm_guid"`
		AdapterID string `json:"adapter_id"`
	}
	if err := json.Unmarshal([]byte(jsonExtract(out)), &value); err != nil {
		return "", "", err
	}
	return value.VMGUID, value.AdapterID, nil
}

func createSimpleIsolatedOrchestratorHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		target, err := resolveTarget(req, deps.registry)
		if err != nil {
			return isolatedError(err)
		}
		profile, profileName, err := resolveOrchestratorProfile(req, deps.defaults)
		if err != nil {
			return isolatedError(err)
		}
		var id isolated.OrchestratorID
		if raw := strings.TrimSpace(req.GetString("orchestrator_id", "")); raw != "" {
			id, err = isolated.ParseOrchestratorID(raw)
		} else {
			id, err = isolated.NewOrchestratorID()
		}
		if err != nil {
			return isolatedError(err)
		}
		names, err := isolated.OrchestratorNames(id)
		if err != nil {
			return isolatedError(err)
		}
		displayName := strings.TrimSpace(req.GetString("display_name", ""))
		if displayName == "" {
			displayName = names.HyperVName
		}
		if req.GetBool("dry_run", false) {
			return simpleIsolatedResult("**Resolved isolated orchestrator**", map[string]any{
				"id": id.String(), "target": target.Name, "name": names.HyperVName,
				"node_name": names.NodeName, "profile": profileName,
				"linux_profile": profile.LinuxProfileName,
				"main_vswitch":  profile.Profile.MainVSwitch,
			}), nil
		}
		if existing, getErr := deps.state.GetOrchestrator(ctx, id.String()); getErr == nil &&
			simpleActiveOrchestrator(existing) {
			return simpleIsolatedResult("**Isolated orchestrator already exists**", existing), nil
		}

		run := func(ctx context.Context, gated mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			progress := simpleWaitProgress()
			linuxReq := gated
			args := cloneArguments(gated.GetArguments())
			args["target"] = target.Name
			args["profile"] = profile.LinuxProfileName
			args["name"] = names.HyperVName
			args["hostname"] = names.NodeName
			args["lablink_node_name"] = names.NodeName
			args["lablink_role"] = "isolated-orchestrator"
			args["lablink_port"] = float64(appliance.RelayTargetPort)
			args["vswitch"] = profile.Profile.MainVSwitch
			args["cpu_count"] = profile.Profile.CPUCount
			args["memory_mb"] = profile.Profile.MemoryMB
			args["dynamic_memory"] = false
			args["register_with_lablink"] = true
			linuxReq.Params.Arguments = args
			linuxReq.Params.Name = "create_linux_vm"
			plan, resolvedTarget, err := resolveLinuxVMPlan(
				linuxReq, deps.registry, deps.defaults, deps.credentials)
			if err != nil {
				return isolatedError(err)
			}
			seed := profile.SeedConfig(deps.serverVersion, id.String())
			plan.Orchestrator = &seed
			result, err := deps.linux.Create(ctx, linuxReq, plan, resolvedTarget, progress)
			if err != nil || result == nil || result.IsError {
				if err != nil {
					return isolatedError(err)
				}
				return result, nil
			}
			guid, _, err := simpleVMHostIdentity(ctx, deps, target, names.HyperVName)
			if err != nil {
				return isolatedError(err)
			}
			host, err := deps.host.PhysicalIdentity(ctx, target)
			if err != nil {
				return isolatedError(err)
			}
			now := isolatedNow()
			record := isolatedstate.Orchestrator{
				ID: id.String(), DisplayName: displayName,
				PhysicalHostID: host.PhysicalHostID, HostNode: target.Name,
				HyperVName: names.HyperVName, HyperVVMID: optionalTrimmed(guid),
				NodeName: names.NodeName, ProfileName: profileName,
				MainVSwitch:     profile.Profile.MainVSwitch,
				AgentPort:       appliance.RelayTargetPort,
				ApplianceSchema: int(isolated.MinimumApplianceSchema),
				LifecycleState:  isolatedstate.OrchestratorReady,
				HealthState:     "ready", MaxNetworks: profile.Profile.MaxNetworks,
				MaxVMs: profile.Profile.MaxVMs, CreatedAt: now, UpdatedAt: now,
			}
			node, readiness, err := waitForOrchestratorReadiness(
				ctx, deps.registry, deps.appliance, record, deps.serverVersion,
				progress, 15*time.Minute, 5*time.Second)
			if err != nil {
				return isolatedError(err)
			}
			record.MainIP = optionalTrimmed(nodeHost(node.Address))
			record.ApplianceSchema = int(readiness.ProtocolVersion)
			seen := isolatedNow()
			record.LastSeenAt = &seen
			if err := deps.state.PutOrchestrator(ctx, record); err != nil {
				return isolatedError(err)
			}
			return simpleIsolatedResult("**Isolated orchestrator created**", record), nil
		}
		return withSimpleTargetLease(ctx, req, deps, target.Name, run)
	}
}

func deleteSimpleIsolatedOrchestratorHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		orchestrator, err := deps.state.GetOrchestrator(
			ctx, strings.TrimSpace(req.GetString("orchestrator_id", "")))
		if err != nil {
			return isolatedError(err)
		}
		deleteStorage := true
		if value, ok := req.GetArguments()["delete_storage"].(bool); ok {
			deleteStorage = value
		}
		vms, err := deps.state.ListVMs(ctx, orchestrator.ID, "")
		if err != nil {
			return isolatedError(err)
		}
		networks, err := deps.state.ListNetworks(ctx, orchestrator.ID)
		if err != nil {
			return isolatedError(err)
		}
		hasChildren := false
		for _, vm := range vms {
			hasChildren = hasChildren || simpleActiveVM(vm)
		}
		for _, network := range networks {
			hasChildren = hasChildren || simpleActiveNetwork(network)
		}
		if hasChildren && !req.GetBool("cascade", false) {
			return isolatedError(errors.New(
				"orchestrator contains isolated VMs or networks; pass cascade=true"))
		}
		if req.GetBool("cascade", false) {
			for _, vm := range vms {
				if !simpleActiveVM(vm) {
					continue
				}
				childReq := req
				childReq.Params.Arguments = map[string]any{
					"isolated_vm_id": vm.ID, "delete_storage": deleteStorage,
				}
				result, err := deleteSimpleIsolatedVM(
					ctx, childReq, deps, vm.ID, deleteStorage)
				if err != nil || result == nil || result.IsError {
					return result, err
				}
			}
			for _, network := range networks {
				if !simpleActiveNetwork(network) {
					continue
				}
				childReq := req
				childReq.Params.Arguments = map[string]any{"network_id": network.ID}
				result, err := removeSimpleIsolatedNetworkHandler(deps)(ctx, childReq)
				if err != nil || result == nil || result.IsError {
					return result, err
				}
			}
		}
		if _, err := deps.appliance.ConfigureStatic(
			ctx, orchestrator.ID, appliance.StaticConfig{}, nil,
		); err != nil {
			return isolatedError(err)
		}
		target, err := resolvePlanTarget(orchestrator.HostNode, deps.registry)
		if err != nil {
			return isolatedError(err)
		}
		run := func(ctx context.Context, gated mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			deleteReq := simpleNormalDeleteRequest(
				gated, target.Name, orchestrator.HyperVName, "",
				orchestrator.NodeName, deleteStorage)
			result, err := deleteVMHandler(
				deps.registry, deps.pool, deps.defaults, deps.audit, deps.enrollment,
			)(ctx, deleteReq)
			if err != nil || result == nil || result.IsError {
				return result, err
			}
			now := isolatedNow()
			orchestrator.LifecycleState = isolatedstate.OrchestratorDeleted
			orchestrator.HealthState = "deleted"
			orchestrator.UpdatedAt = now
			if err := deps.state.PutOrchestrator(ctx, orchestrator); err != nil {
				return isolatedError(err)
			}
			return simpleIsolatedResult("**Isolated orchestrator deleted**", orchestrator), nil
		}
		return withSimpleTargetLease(ctx, req, deps, target.Name, run)
	}
}

func addSimpleIsolatedNetworkHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		orchestrator, err := deps.state.GetOrchestrator(
			ctx, strings.TrimSpace(req.GetString("orchestrator_id", "")))
		if err != nil {
			return isolatedError(err)
		}
		target, err := resolvePlanTarget(orchestrator.HostNode, deps.registry)
		if err != nil {
			return isolatedError(err)
		}
		networkID, err := isolated.NewNetworkID()
		if err != nil {
			return isolatedError(err)
		}
		names, err := isolated.NetworkNames(networkID)
		if err != nil {
			return isolatedError(err)
		}
		networks, err := deps.state.ListNetworks(ctx, orchestrator.ID)
		if err != nil {
			return isolatedError(err)
		}
		used := map[int]bool{}
		for _, value := range networks {
			if simpleActiveNetwork(value) {
				used[value.SubnetIndex] = true
			}
		}
		discovery, err := deps.host.Discover(ctx, target)
		if err != nil {
			return isolatedError(err)
		}
		subnetIndex := -1
		var prefix netip.Prefix
		for index := 0; index < isolated.PrivateSubnetCount; index++ {
			if used[index] {
				continue
			}
			candidate, candidateErr := isolated.PrivateSubnet(index)
			if candidateErr == nil &&
				len(isolated.FindPrivateRouteConflicts(candidate, discovery.Routes)) == 0 {
				subnetIndex, prefix = index, candidate
				break
			}
		}
		if subnetIndex < 0 {
			return isolatedError(errors.New("no private /26 subnet remains"))
		}
		mac, err := isolated.DeterministicMAC(networkID.String())
		if err != nil {
			return isolatedError(err)
		}
		displayName := strings.TrimSpace(req.GetString("display_name", ""))
		if displayName == "" {
			displayName = names.HyperVSwitchName
		}
		plan := map[string]any{
			"id": networkID.String(), "switch": names.HyperVSwitchName,
			"adapter": names.OrchestratorAdapterName, "cidr": prefix.String(),
			"gateway": isolated.PrivateGateway(prefix).String(), "mac": mac,
		}
		if req.GetBool("dry_run", false) {
			return simpleIsolatedResult("**Resolved isolated network**", plan), nil
		}
		run := func(ctx context.Context, gated mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			createReq := gated
			createReq.Params.Arguments = map[string]any{
				"target": target.Name, "name": names.HyperVSwitchName,
				"type": "private", "if_exists": "reuse",
			}
			result, err := createVSwitchHandler(deps.registry, deps.pool, deps.audit)(ctx, createReq)
			if err != nil || result == nil || result.IsError {
				return result, err
			}
			script := fmt.Sprintf(`
$vm = Get-VM -Id %s -ErrorAction Stop
$switch = Get-VMSwitch -Name %s -ErrorAction Stop
$adapter = @(Get-VMNetworkAdapter -VM $vm -Name %s -ErrorAction SilentlyContinue)
if ($adapter.Count -eq 0) {
  Add-VMNetworkAdapter -VM $vm -Name %s -SwitchName $switch.Name -StaticMacAddress %s -ErrorAction Stop
  $adapter = @(Get-VMNetworkAdapter -VM $vm -Name %s -ErrorAction Stop)
}
if ($adapter.Count -ne 1) { throw 'isolated network adapter identity is ambiguous' }
if ([string]$adapter[0].SwitchId -cne [string]$switch.Id) {
  Connect-VMNetworkAdapter -VMNetworkAdapter $adapter[0] -SwitchName $switch.Name -ErrorAction Stop
}
Set-VMNetworkAdapter -VMNetworkAdapter $adapter[0] -StaticMacAddress %s -ErrorAction Stop
[pscustomobject]@{ switch_guid=[string]$switch.Id; adapter_id=[string]$adapter[0].Id } | ConvertTo-Json -Compress
`, hyperv.PSLit(valueOrEmpty(orchestrator.HyperVVMID)),
				hyperv.PSLit(names.HyperVSwitchName),
				hyperv.PSLit(names.OrchestratorAdapterName),
				hyperv.PSLit(names.OrchestratorAdapterName), hyperv.PSLit(mac),
				hyperv.PSLit(names.OrchestratorAdapterName), hyperv.PSLit(mac))
			out, _, err := runPS(ctx, deps.registry, deps.pool, target, script, vmDefaultTimeoutSec)
			if err != nil {
				return isolatedError(err)
			}
			var identity struct {
				SwitchGUID string `json:"switch_guid"`
				AdapterID  string `json:"adapter_id"`
			}
			if err := json.Unmarshal([]byte(jsonExtract(out)), &identity); err != nil {
				return isolatedError(err)
			}
			dns, err := discoverOrchestratorDNS(ctx, deps, orchestrator)
			if err != nil {
				return isolatedError(err)
			}
			encodedDNS, err := json.Marshal(dns)
			if err != nil {
				return isolatedError(err)
			}
			now := isolatedNow()
			record := isolatedstate.PrivateNetwork{
				ID: networkID.String(), OrchestratorID: orchestrator.ID,
				DisplayName: displayName, HyperVSwitchName: names.HyperVSwitchName,
				HyperVSwitchGUID:      optionalTrimmed(identity.SwitchGUID),
				OrchestratorAdapterID: optionalTrimmed(identity.AdapterID),
				SubnetIndex:           subnetIndex, CIDR: prefix.String(),
				GatewayIPv4:     isolated.PrivateGateway(prefix).String(),
				OrchestratorMAC: mac, DNSServersJSON: string(encodedDNS),
				LifecycleState: isolatedstate.NetworkReady,
				CreatedAt:      now, UpdatedAt: now,
			}
			if err := deps.state.PutNetwork(ctx, record); err != nil {
				return isolatedError(err)
			}
			if _, err := configureStaticAfterPrivateNICReady(
				ctx, 30*time.Second, 500*time.Millisecond,
				func() (isolated.ApplianceSnapshot, error) {
					return configureStaticAppliance(
						ctx, deps, orchestrator.ID, nil)
				},
			); err != nil {
				return isolatedError(err)
			}
			return simpleIsolatedResult("**Isolated network created**", record), nil
		}
		return withSimpleTargetLease(ctx, req, deps, target.Name, run)
	}
}

func removeSimpleIsolatedNetworkHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		network, err := deps.state.GetNetwork(
			ctx, strings.TrimSpace(req.GetString("network_id", "")))
		if err != nil {
			return isolatedError(err)
		}
		vms, err := deps.state.ListVMs(ctx, "", network.ID)
		if err != nil {
			return isolatedError(err)
		}
		for _, vm := range vms {
			if simpleActiveVM(vm) {
				return isolatedError(fmt.Errorf(
					"network %s still contains VM %s", network.ID, vm.ID))
			}
		}
		orchestrator, err := deps.state.GetOrchestrator(ctx, network.OrchestratorID)
		if err != nil {
			return isolatedError(err)
		}
		target, err := resolvePlanTarget(orchestrator.HostNode, deps.registry)
		if err != nil {
			return isolatedError(err)
		}
		run := func(ctx context.Context, gated mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			now := isolatedNow()
			network.LifecycleState = isolatedstate.NetworkDeleted
			network.RetiredAt, network.UpdatedAt = &now, now
			if err := deps.state.PutNetwork(ctx, network); err != nil {
				return isolatedError(err)
			}
			if _, err := configureStaticAppliance(ctx, deps, orchestrator.ID, nil); err != nil {
				return isolatedError(err)
			}
			script := fmt.Sprintf(`
$vm = Get-VM -Id %s -ErrorAction Stop
$adapter = @(Get-VMNetworkAdapter -VM $vm -ErrorAction SilentlyContinue | Where-Object { [string]$_.Id -eq %s })
if ($adapter.Count -gt 1) { throw 'isolated adapter identity is ambiguous' }
if ($adapter.Count -eq 1) { Remove-VMNetworkAdapter -VMNetworkAdapter $adapter[0] -ErrorAction Stop }
$switch = @(Get-VMSwitch -Name %s -ErrorAction SilentlyContinue)
if ($switch.Count -gt 1) { throw 'isolated switch identity is ambiguous' }
if ($switch.Count -eq 1) {
  if ([string]$switch[0].Id -cne %s) { throw 'isolated switch GUID changed' }
  Remove-VMSwitch -VMSwitch $switch[0] -Force -ErrorAction Stop
}
`, hyperv.PSLit(valueOrEmpty(orchestrator.HyperVVMID)),
				hyperv.PSLit(valueOrEmpty(network.OrchestratorAdapterID)),
				hyperv.PSLit(network.HyperVSwitchName),
				hyperv.PSLit(valueOrEmpty(network.HyperVSwitchGUID)))
			if _, _, err := runPS(ctx, deps.registry, deps.pool, target, script, vmDefaultTimeoutSec); err != nil {
				return isolatedError(err)
			}
			return simpleIsolatedResult("**Isolated network removed**", network), nil
		}
		return withSimpleTargetLease(ctx, req, deps, target.Name, run)
	}
}

func createSimpleIsolatedVMHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		network, err := deps.state.GetNetwork(
			ctx, strings.TrimSpace(req.GetString("network_id", "")))
		if err != nil {
			return isolatedError(err)
		}
		if !simpleActiveNetwork(network) {
			return isolatedError(fmt.Errorf("network %s is not active", network.ID))
		}
		orchestrator, err := deps.state.GetOrchestrator(ctx, network.OrchestratorID)
		if err != nil {
			return isolatedError(err)
		}
		target, err := resolvePlanTarget(orchestrator.HostNode, deps.registry)
		if err != nil {
			return isolatedError(err)
		}
		name := strings.TrimSpace(req.GetString("name", ""))
		if err := validateVMPathName(name); err != nil {
			return isolatedError(err)
		}
		vms, err := deps.state.ListVMs(ctx, orchestrator.ID, network.ID)
		if err != nil {
			return isolatedError(err)
		}
		cleanedPartial := false
		for _, existing := range vms {
			if simpleActiveVM(existing) && strings.EqualFold(existing.HyperVName, name) {
				if existing.LifecycleState == isolatedstate.VMReady {
					return simpleIsolatedResult("**Isolated VM already exists**", existing), nil
				}
				result, deleteErr := deleteSimpleIsolatedVM(
					ctx, req, deps, existing.ID, true)
				if deleteErr != nil || result == nil || result.IsError {
					return result, deleteErr
				}
				cleanedPartial = true
			}
		}
		if cleanedPartial {
			vms, err = deps.state.ListVMs(ctx, orchestrator.ID, network.ID)
			if err != nil {
				return isolatedError(err)
			}
		}
		relays, err := deps.state.ListRelays(ctx, orchestrator.ID, "")
		if err != nil {
			return isolatedError(err)
		}
		natRows, err := deps.state.ListNAT(ctx, orchestrator.ID, "", "")
		if err != nil {
			return isolatedError(err)
		}
		ip, relayPort, mark, err := simpleGuestResources(vms, relays, natRows, network)
		if err != nil {
			return isolatedError(err)
		}
		vmID, err := isolated.NewVMID()
		if err != nil {
			return isolatedError(err)
		}
		relayID, err := isolated.NewRelayID()
		if err != nil {
			return isolatedError(err)
		}
		mac, err := isolated.DeterministicMAC(vmID.String())
		if err != nil {
			return isolatedError(err)
		}
		guestOS := isolatedstate.GuestOS(
			strings.ToLower(strings.TrimSpace(req.GetString("guest_os", ""))))
		if guestOS != isolatedstate.GuestWindows && guestOS != isolatedstate.GuestLinux {
			return isolatedError(fmt.Errorf("guest_os must be windows or linux"))
		}
		profile := strings.TrimSpace(req.GetString("profile", ""))
		if profile == "" {
			return isolatedError(errors.New("profile is required"))
		}
		services, err := parseReachableServices(req)
		if err != nil {
			return isolatedError(err)
		}
		domainJoin, err := parseWindowsDomainJoinArgument(req.GetArguments()["domain_join"])
		if err != nil {
			return isolatedError(err)
		}
		if domainJoin != nil && guestOS != isolatedstate.GuestWindows {
			return isolatedError(errors.New("domain_join is supported only for Windows"))
		}
		natEnabled := req.GetBool("nat_enabled", false)
		knownBootstrap := req.GetBool("known_network_bootstrap", false) ||
			domainJoin != nil || detectsNetworkBootstrap(req.GetArguments())
		if err := isolated.ValidateBootstrapPolicy(
			req.GetString("bootstrap_network_requirement", ""),
			natEnabled, knownBootstrap, domainJoin != nil, services,
		); err != nil {
			return isolatedError(err)
		}
		nodeName := windowsHostname(name)
		if guestOS == isolatedstate.GuestLinux {
			nodeName = linuxHostname(name)
		}
		if nodeName == "" {
			return isolatedError(fmt.Errorf("name %q does not produce a valid guest hostname", name))
		}
		displayName := strings.TrimSpace(req.GetString("display_name", ""))
		if displayName == "" {
			displayName = name
		}
		now := isolatedNow()
		vm := isolatedstate.IsolatedVM{
			ID: vmID.String(), OrchestratorID: orchestrator.ID, NetworkID: network.ID,
			DisplayName: displayName, HyperVName: name, NodeName: nodeName,
			GuestOS: guestOS, ProfileName: profile,
			IPv4: ip, MAC: mac, PrefixLength: isolated.PrivateNetworkPrefixBits,
			GatewayIPv4:    network.GatewayIPv4,
			DNSServersJSON: network.DNSServersJSON,
			LifecycleState: isolatedstate.VMCreating,
			CreatedAt:      now, UpdatedAt: now,
		}
		relay := isolatedstate.RelayAllocation{
			ID: relayID.String(), VMID: vm.ID, OrchestratorID: orchestrator.ID,
			ListenPort: relayPort, TargetIPv4: ip, TargetPort: appliance.RelayTargetPort,
			LifecycleState: isolatedstate.RelayReady,
			CreatedAt:      now, UpdatedAt: now,
		}
		natState := isolatedstate.NATAllocation{
			VMID: vm.ID, OrchestratorID: orchestrator.ID,
			State:         isolatedstate.NATDisabled,
			ConntrackMark: int64(mark), UpdatedAt: now,
		}
		if natEnabled {
			natState.State = isolatedstate.NATEnabled
		}
		run := func(ctx context.Context, gated mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if err := errors.Join(
				deps.state.PutVM(ctx, vm),
				deps.state.PutRelay(ctx, relay),
				deps.state.PutNAT(ctx, natState),
			); err != nil {
				return isolatedError(err)
			}
			if _, err := configureStaticAppliance(ctx, deps, orchestrator.ID, nil); err != nil {
				return isolatedError(err)
			}
			progress := simpleWaitProgress()
			dns, err := isolated.ParseDNSServers(vm.DNSServersJSON)
			if err != nil {
				return isolatedError(err)
			}
			switch vm.GuestOS {
			case isolatedstate.GuestWindows:
				resolved, profileName, err := deps.defaults.ResolveOrdinaryWindowsForTarget(
					vm.ProfileName, target.Name)
				if err != nil {
					return isolatedError(err)
				}
				plan := planFromProfile(resolved, profileName)
				plan.Target, plan.Name, plan.Hostname = target.Name, vm.HyperVName, vm.NodeName
				plan.VSwitch, plan.LabLinkNodeName = network.HyperVSwitchName, vm.NodeName
				plan.LabLinkRole, plan.LabLinkPort = "isolated-vm", appliance.RelayTargetPort
				plan.RegisterWithLabLink, plan.DeferBoot, plan.NetworkFirstBoot = true, true, true
				plan.DomainJoin = nil
				plan.FirstBootScript, err = isolated.WindowsStaticNetworkScript(
					vm.IPv4, vm.PrefixLength, vm.GatewayIPv4, vm.MAC, dns)
				if err != nil {
					return isolatedError(err)
				}
				derivePlanPaths(&plan)
				result, err := executeWindowsVMPlan(
					ctx, plan, deps.registry, deps.pool, deps.credentials,
					deps.secrets, deps.audit, deps.enrollment)
				if err != nil || result == nil || result.IsError {
					if err != nil {
						return isolatedError(err)
					}
					return result, nil
				}
				vm.StorageRoot, vm.VMPath, vm.VHDPath =
					plan.VMRoot, plan.VMLocation, plan.VHDPath
			case isolatedstate.GuestLinux:
				networkConfig, err := isolated.LinuxStaticNetworkConfig(
					vm.IPv4, vm.PrefixLength, vm.GatewayIPv4, vm.MAC, dns)
				if err != nil {
					return isolatedError(err)
				}
				networkBootstrap, err := isolated.LinuxStaticNetworkBootstrapScript(
					vm.IPv4, vm.PrefixLength, vm.GatewayIPv4, vm.MAC, dns)
				if err != nil {
					return isolatedError(err)
				}
				linuxReq := gated
				linuxReq.Params.Arguments = map[string]any{
					"target": target.Name, "profile": vm.ProfileName,
					"name": vm.HyperVName, "hostname": vm.NodeName,
					"network_config":        networkConfig,
					"vswitch":               network.HyperVSwitchName,
					"register_with_lablink": true,
					"lablink_node_name":     vm.NodeName,
					"lablink_role":          "isolated-vm",
					"lablink_port":          float64(appliance.RelayTargetPort),
				}
				plan, resolvedTarget, err := resolveLinuxVMPlan(
					linuxReq, deps.registry, deps.defaults, deps.credentials)
				if err != nil {
					return isolatedError(err)
				}
				plan.DeferBoot = true
				plan.NetworkBootstrapScript = networkBootstrap
				result, err := executeLinuxVMPlan(
					ctx, linuxReq, plan, resolvedTarget, deps.registry, deps.pool,
					deps.defaults, deps.credentials, deps.audit, deps.enrollment,
					deps.lease, progress)
				if err != nil || result == nil || result.IsError {
					if err != nil {
						return isolatedError(err)
					}
					return result, nil
				}
				vm.StorageRoot, vm.VMPath, vm.VHDPath =
					plan.VMRoot, plan.VMLocation, plan.VHDPath
			}
			guid, adapterID, err := simpleVMHostIdentity(
				ctx, deps, target, vm.HyperVName)
			if err != nil {
				return isolatedError(err)
			}
			vm.HyperVVMID, vm.HyperVAdapterID =
				optionalTrimmed(guid), optionalTrimmed(adapterID)
			script := fmt.Sprintf(`
$vm = Get-VM -Id %s -ErrorAction Stop
if ([string]$vm.State -cne 'Off') {
  throw 'isolated guest must remain off until its private MAC is configured'
}
$adapter = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop |
  Where-Object { [string]$_.Id -eq %s })
if ($adapter.Count -ne 1) {
  throw 'isolated guest adapter identity is ambiguous'
}
Set-VMNetworkAdapter -VMNetworkAdapter $adapter[0] -StaticMacAddress %s -ErrorAction Stop
Start-VM -VM $vm -ErrorAction Stop
`, hyperv.PSLit(guid), hyperv.PSLit(adapterID), hyperv.PSLit(vm.MAC))
			if _, _, err := runPS(
				ctx, deps.registry, deps.pool, target, script, vmDefaultTimeoutSec,
			); err != nil {
				return isolatedError(err)
			}
			mainIP := valueOrEmpty(orchestrator.MainIP)
			if mainIP == "" {
				snapshot, snapErr := deps.appliance.InspectApplianceState(ctx, orchestrator.ID)
				if snapErr != nil {
					return isolatedError(snapErr)
				}
				mainIP = snapshot.MainIPv4
			}
			identityPlan := windowsVMPlan{
				LabLinkNodeName: vm.NodeName, LabLinkRole: "isolated-vm",
				LabLinkPort: appliance.RelayTargetPort,
			}
			timeout := windowsEnrollmentReadyTimeout
			if vm.GuestOS == isolatedstate.GuestLinux {
				timeout = linuxEnrollmentReadyTimeout
			}
			if err := verifyEnrolledVMWithOptions(
				ctx, identityPlan, startedVMInfo{IPAddress: vm.IPv4, State: "Running"},
				deps.registry, deps.pool, true, enrollmentWaitOptions{
					Timeout: timeout,
					Address: fmt.Sprintf("%s:%d", mainIP, relay.ListenPort),
				},
			); err != nil {
				return isolatedError(err)
			}
			if vm.GuestOS == isolatedstate.GuestLinux {
				iso := filepath.Join(vm.VMPath, "cidata.iso")
				cleanup := fmt.Sprintf(`
		$vm = Get-VM -Id %s -ErrorAction Stop
		$iso = %s
		@(Get-VMDvdDrive -VM $vm -ErrorAction SilentlyContinue | Where-Object Path -eq $iso) | Remove-VMDvdDrive -ErrorAction Stop
		if (Test-Path -LiteralPath $iso -PathType Leaf) { Remove-Item -LiteralPath $iso -Force -ErrorAction Stop }
		`, hyperv.PSLit(guid), hyperv.PSLit(iso))
				if _, _, err := runPS(
					ctx, deps.registry, deps.pool, target, cleanup, vmDefaultTimeoutSec,
				); err != nil {
					return isolatedError(err)
				}
			}
			node, ok := deps.registry.GetNode(vm.NodeName)
			if !ok {
				return isolatedError(errors.New("enrolled guest node is missing"))
			}
			copy := *node
			copy.Labels = cloneLabels(node.Labels)
			copy.Labels["lablink.kind"] = "isolated-vm"
			copy.Labels["lablink.isolated_vm_id"] = vm.ID
			copy.Labels["lablink.orchestrator_id"] = vm.OrchestratorID
			copy.Labels["lablink.network_id"] = vm.NetworkID
			copy.Labels["lablink.display_name"] = vm.DisplayName
			if err := deps.registry.SetNode(&copy); err != nil {
				return isolatedError(err)
			}
			if domainJoin != nil {
				join := deps.joinDomain
				if join == nil {
					join = executeWindowsDomainJoin
				}
				if _, err := join(
					ctx, vm.NodeName, *domainJoin, 180,
					deps.registry, deps.pool, deps.secrets, deps.audit,
				); err != nil {
					return isolatedError(err)
				}
			}
			vm.LifecycleState, vm.UpdatedAt = isolatedstate.VMReady, isolatedNow()
			if err := deps.state.PutVM(ctx, vm); err != nil {
				return isolatedError(err)
			}
			return simpleIsolatedResult("**Isolated VM created**", map[string]any{
				"vm": vm, "relay": relay, "nat": natState,
			}), nil
		}
		return withSimpleTargetLease(ctx, req, deps, target.Name, run)
	}
}

func deleteSimpleIsolatedVMHandler(deps *isolatedLifecycleDeps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		vmID := strings.TrimSpace(req.GetString("isolated_vm_id", ""))
		deleteStorage := true
		if value, ok := req.GetArguments()["delete_storage"].(bool); ok {
			deleteStorage = value
		}
		return deleteSimpleIsolatedVM(ctx, req, deps, vmID, deleteStorage)
	}
}

func deleteSimpleIsolatedVM(
	ctx context.Context,
	req mcp.CallToolRequest,
	deps *isolatedLifecycleDeps,
	vmID string,
	deleteStorage bool,
) (*mcp.CallToolResult, error) {
	vm, err := deps.state.GetVM(ctx, vmID)
	if err != nil {
		return isolatedError(err)
	}
	orchestrator, target, err := simpleOrchestratorForVM(ctx, deps, vm)
	if err != nil {
		return isolatedError(err)
	}
	run := func(ctx context.Context, gated mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nat, natErr := deps.state.GetNAT(ctx, vm.ID)
		relay, relayErr := deps.state.GetRelayForVM(ctx, vm.ID)
		now := isolatedNow()
		var retire []appliance.RetiredNAT
		if natErr == nil {
			if nat.State == isolatedstate.NATEnabled {
				retire = append(retire, appliance.RetiredNAT{
					VMID: vm.ID, GuestIPv4: vm.IPv4,
					ConntrackMark: nat.ConntrackMark,
				})
			}
			nat.State = isolatedstate.NATDisabled
			nat.UpdatedAt = now
			_ = deps.state.PutNAT(ctx, nat)
		}
		if relayErr == nil {
			relay.LifecycleState, relay.RetiredAt, relay.UpdatedAt =
				isolatedstate.RelayRemoved, &now, now
			_ = deps.state.PutRelay(ctx, relay)
		}
		if _, err := configureStaticAppliance(ctx, deps, orchestrator.ID, retire); err != nil {
			return isolatedError(err)
		}
		deleteReq := simpleNormalDeleteRequest(
			gated, target.Name, vm.HyperVName, vm.StorageRoot,
			vm.NodeName, deleteStorage)
		result, err := deleteVMHandler(
			deps.registry, deps.pool, deps.defaults, deps.audit, deps.enrollment,
		)(ctx, deleteReq)
		if err != nil || result == nil || result.IsError {
			return result, err
		}
		vm.LifecycleState, vm.RetiredAt, vm.UpdatedAt =
			isolatedstate.VMDeleted, &now, now
		if err := deps.state.PutVM(ctx, vm); err != nil {
			return isolatedError(err)
		}
		if _, err := configureStaticAppliance(
			ctx, deps, orchestrator.ID, nil,
		); err != nil {
			return isolatedError(err)
		}
		return simpleIsolatedResult("**Isolated VM deleted**", vm), nil
	}
	return withSimpleTargetLease(ctx, req, deps, target.Name, run)
}
