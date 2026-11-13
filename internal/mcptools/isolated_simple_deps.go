package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/isolated"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/secretstore"
	"github.com/nijosmsft/lablink/internal/vmconfig"
	pb "github.com/nijosmsft/lablink/proto/agent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type simpleIsolatedState interface {
	PutOrchestrator(context.Context, isolatedstate.Orchestrator) error
	GetOrchestrator(context.Context, string) (isolatedstate.Orchestrator, error)
	ListOrchestrators(context.Context, string) ([]isolatedstate.Orchestrator, error)
	PutNetwork(context.Context, isolatedstate.PrivateNetwork) error
	GetNetwork(context.Context, string) (isolatedstate.PrivateNetwork, error)
	ListNetworks(context.Context, string) ([]isolatedstate.PrivateNetwork, error)
	PutVM(context.Context, isolatedstate.IsolatedVM) error
	GetVM(context.Context, string) (isolatedstate.IsolatedVM, error)
	ListVMs(context.Context, string, string) ([]isolatedstate.IsolatedVM, error)
	PutRelay(context.Context, isolatedstate.RelayAllocation) error
	GetRelay(context.Context, string) (isolatedstate.RelayAllocation, error)
	GetRelayForVM(context.Context, string) (isolatedstate.RelayAllocation, error)
	ListRelays(context.Context, string, string) ([]isolatedstate.RelayAllocation, error)
	PutNAT(context.Context, isolatedstate.NATAllocation) error
	GetNAT(context.Context, string) (isolatedstate.NATAllocation, error)
	ListNAT(context.Context, string, string, string) ([]isolatedstate.NATAllocation, error)
}

type simpleIsolatedAppliance interface {
	CheckReadiness(context.Context, string) (isolated.ApplianceReadiness, error)
	InspectApplianceState(context.Context, string) (isolated.ApplianceSnapshot, error)
	ConfigureStatic(
		context.Context,
		string,
		appliance.StaticConfig,
		[]appliance.RetiredNAT,
	) (isolated.ApplianceSnapshot, error)
	GetRelayStats(context.Context, string, string) (appliance.RelayStats, error)
	ValidateRelay(context.Context, string, string, bool) (isolated.RelayValidation, error)
}

type simpleIsolatedHost interface {
	PhysicalIdentity(context.Context, Target) (simplePhysicalIdentity, error)
	Discover(context.Context, Target) (simpleHostDiscovery, error)
}

type simplePhysicalIdentity struct {
	PhysicalHostID string `json:"physical_host_id"`
}

type simpleHostDiscovery struct {
	Routes []isolated.RouteObservation `json:"routes"`
}

type simpleLinuxCreator interface {
	Create(
		context.Context,
		mcp.CallToolRequest,
		linuxVMPlan,
		Target,
		*MCPProgressState,
	) (*mcp.CallToolResult, error)
}

type isolatedLifecycleDeps struct {
	server        *server.MCPServer
	state         simpleIsolatedState
	host          simpleIsolatedHost
	appliance     simpleIsolatedAppliance
	linux         simpleLinuxCreator
	registry      *registry.Registry
	pool          *agentclient.Pool
	defaults      *vmconfig.Store
	credentials   *credentials.Store
	secrets       *secretstore.Store
	audit         *audit.Log
	enrollment    VMEnrollmentConfig
	lease         LeaseGateConfig
	serverVersion string
	joinDomain    func(
		context.Context,
		string,
		vmconfig.WindowsDomainJoin,
		int,
		*registry.Registry,
		*agentclient.Pool,
		*secretstore.Store,
		*audit.Log,
	) (windowsDomainJoinResult, error)
}

type productionSimpleIsolatedHost struct {
	reg  *registry.Registry
	pool *agentclient.Pool
}

func (h productionSimpleIsolatedHost) PhysicalIdentity(
	ctx context.Context,
	target Target,
) (simplePhysicalIdentity, error) {
	script := `
$id = [string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
if ([string]::IsNullOrWhiteSpace($id)) { throw 'physical host identity is unavailable' }
[pscustomobject]@{ physical_host_id=$id } | ConvertTo-Json -Compress
`
	out, _, err := runPS(
		ctx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return simplePhysicalIdentity{}, err
	}
	var value simplePhysicalIdentity
	err = json.Unmarshal([]byte(jsonExtract(out)), &value)
	return value, err
}

func (h productionSimpleIsolatedHost) Discover(
	ctx context.Context,
	target Target,
) (simpleHostDiscovery, error) {
	script := `
[array]$routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object {
  [pscustomobject]@{
    destination_prefix=[string]$_.DestinationPrefix
    next_hop=[string]$_.NextHop
    interface_alias=[string]$_.InterfaceAlias
    route_metric=[int]$_.RouteMetric
  }
})
[pscustomobject]@{ routes=$routes } | ConvertTo-Json -Depth 5 -Compress
`
	out, _, err := runPS(ctx, h.reg, h.pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return simpleHostDiscovery{}, err
	}
	var value simpleHostDiscovery
	err = json.Unmarshal([]byte(jsonExtract(out)), &value)
	return value, err
}

type productionSimpleLinuxCreator struct {
	deps *isolatedLifecycleDeps
}

func (c productionSimpleLinuxCreator) Create(
	ctx context.Context,
	req mcp.CallToolRequest,
	plan linuxVMPlan,
	target Target,
	progress *MCPProgressState,
) (*mcp.CallToolResult, error) {
	d := c.deps
	return executeLinuxVMPlan(
		ctx, req, plan, target, d.registry, d.pool, d.defaults,
		d.credentials, d.audit, d.enrollment, d.lease, progress)
}

func NewIsolatedLifecycleDependencies(
	s *server.MCPServer,
	store *isolatedstate.Store,
	reg *registry.Registry,
	pool *agentclient.Pool,
	defaults *vmconfig.Store,
	creds *credentials.Store,
	secrets *secretstore.Store,
	auditLog *audit.Log,
	enrollment VMEnrollmentConfig,
	leaseCfg LeaseGateConfig,
	serverVersion string,
) (*isolatedLifecycleDeps, error) {
	if store == nil {
		return nil, errors.New("isolated lifecycle requires an open isolated state store")
	}
	deps := &isolatedLifecycleDeps{
		server: s, state: store,
		host:      productionSimpleIsolatedHost{reg: reg, pool: pool},
		appliance: isolated.NewApplianceClient(reg, pool, serverVersion),
		registry:  reg, pool: pool, defaults: defaults, credentials: creds,
		secrets: secrets, audit: auditLog, enrollment: enrollment,
		lease: leaseCfg, serverVersion: serverVersion,
		joinDomain: executeWindowsDomainJoin,
	}
	deps.linux = productionSimpleLinuxCreator{deps: deps}
	return deps, nil
}

func RegisterIsolatedLifecycleTools(s *server.MCPServer, deps *isolatedLifecycleDeps) {
	RegisterSimpleIsolatedLifecycleTools(s, deps)
}

func resolveOrchestratorProfile(
	req mcp.CallToolRequest,
	defaults *vmconfig.Store,
) (vmconfig.ResolvedIsolatedOrchestratorProfile, string, error) {
	resolved, profileName, err := defaults.ResolveIsolatedOrchestrator(
		req.GetString("profile", ""))
	if err != nil {
		return resolved, "", err
	}
	if profileName == "" {
		return resolved, "", errors.New(
			"isolated orchestrator profile is required; configure default_isolated_orchestrator_profile or pass profile")
	}
	mainSwitch := strings.TrimSpace(req.GetString("main_vswitch", ""))
	if mainSwitch != "" {
		resolved.Profile.MainVSwitch = mainSwitch
		resolved.LinuxVM.VSwitch = mainSwitch
	}
	return resolved, profileName, nil
}

func waitForOrchestratorReadiness(
	ctx context.Context,
	reg *registry.Registry,
	applianceClient simpleIsolatedAppliance,
	record isolatedstate.Orchestrator,
	expectedServerVersion string,
	progress *MCPProgressState,
	timeout, interval time.Duration,
) (*registry.Node, isolated.ApplianceReadiness, error) {
	if timeout <= 0 || interval <= 0 {
		return nil, isolated.ApplianceReadiness{},
			errors.New("orchestrator readiness timeout and interval must be positive")
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastErr error
	for {
		node, found := reg.GetNode(record.NodeName)
		if !found {
			lastErr = fmt.Errorf("ORCHESTRATOR_NODE_NOT_FOUND: %s", record.NodeName)
		} else {
			node.Role = "isolated-orchestrator"
			if node.Labels == nil {
				node.Labels = map[string]string{}
			}
			node.Labels["lablink.orchestrator_id"] = record.ID
			node.Labels["lablink.kind"] = "isolated-orchestrator"
			if err := reg.SetNode(node); err != nil {
				return nil, isolated.ApplianceReadiness{}, err
			}
			readiness, err := applianceClient.CheckReadiness(ctx, record.ID)
			if err == nil {
				return node, readiness, nil
			}
			code := isolated.ErrorCode(err)
			transitionalOrdinaryAgent := code == "AGENT_UPGRADE_REQUIRED" &&
				readiness.ProtocolVersion == 0 &&
				readiness.AgentVersion == expectedServerVersion
			if code != "AGENT_CAPABILITY_MISSING" &&
				code != "ORCHESTRATOR_NODE_NOT_FOUND" &&
				code != string(appliance.CodeNotReady) &&
				!transitionalOrdinaryAgent &&
				status.Code(err) != codes.Unavailable {
				return nil, readiness, err
			}
			lastErr = err
		}
		if progress != nil {
			progress.Update(
				"verify_capabilities",
				"waiting for cloud-init to restart the agent in isolated-appliance mode")
		}
		select {
		case <-ctx.Done():
			return nil, isolated.ApplianceReadiness{}, ctx.Err()
		case <-deadline.C:
			return nil, isolated.ApplianceReadiness{}, fmt.Errorf(
				"ORCHESTRATOR_APPLIANCE_READY_TIMEOUT: %w", lastErr)
		case <-ticker.C:
		}
	}
}

func parseReachableServices(
	req mcp.CallToolRequest,
) ([]isolated.ReachableService, error) {
	raw, ok := req.GetArguments()["reachable_services"].([]any)
	if !ok {
		if values, stringsOK := req.GetArguments()["reachable_services"].([]string); stringsOK {
			raw = make([]any, len(values))
			for i := range values {
				raw[i] = values[i]
			}
		}
	}
	var result []isolated.ReachableService
	for _, item := range raw {
		if object, objectOK := item.(map[string]any); objectOK {
			service := isolated.ReachableService{
				Kind:    strings.TrimSpace(fmt.Sprint(object["kind"])),
				Address: strings.TrimSpace(fmt.Sprint(object["address"])),
			}
			if port, portOK := numericArgument(object["port"]); portOK {
				service.Port = int(port)
			}
			result = append(result, service)
			continue
		}
		value := strings.TrimSpace(fmt.Sprint(item))
		kind, endpoint, ok := strings.Cut(value, "=")
		if !ok {
			return nil, errors.New(
				"reachable_services entries must use kind=address[:port]")
		}
		service := isolated.ReachableService{Kind: strings.TrimSpace(kind)}
		service.Address = strings.TrimSpace(endpoint)
		if host, port, splitErr := net.SplitHostPort(endpoint); splitErr == nil {
			service.Address = host
			fmt.Sscan(port, &service.Port)
		}
		result = append(result, service)
	}
	return result, nil
}

func discoverOrchestratorDNS(
	ctx context.Context,
	deps *isolatedLifecycleDeps,
	orchestrator isolatedstate.Orchestrator,
) ([]string, error) {
	node, ok := deps.registry.GetNode(orchestrator.NodeName)
	if !ok {
		return nil, fmt.Errorf(
			"discover orchestrator DNS: node %s is not registered",
			orchestrator.NodeName)
	}
	client, err := deps.pool.GetClient(node.Address, node.TLSServerName)
	if err != nil {
		return nil, fmt.Errorf("discover orchestrator DNS: %w", err)
	}
	stream, err := client.Execute(ctx, &pb.ExecuteRequest{
		Command: `resolvectl dns | awk '{$1=""; sub(/^ /,""); print}' | tr ' ' '\n' | awk 'NF && !seen[$0]++'`,
		Shell:   "bash", TimeoutSeconds: 30,
	})
	if err != nil {
		return nil, fmt.Errorf("discover orchestrator DNS: %w", err)
	}
	stdout, exit, _, _, err := collectStreamOutput(stream)
	if err != nil {
		return nil, fmt.Errorf("discover orchestrator DNS: %w", err)
	}
	if exit != 0 {
		return nil, fmt.Errorf(
			"discover orchestrator DNS exited %d: %s", exit, strings.TrimSpace(stdout))
	}
	var result []string
	seen := map[string]bool{}
	for _, line := range strings.Split(stdout, "\n") {
		address := net.ParseIP(strings.TrimSpace(line))
		if address == nil || address.To4() == nil || seen[address.String()] {
			continue
		}
		seen[address.String()] = true
		result = append(result, address.String())
	}
	if len(result) == 0 {
		return nil, errors.New("discover orchestrator DNS returned no IPv4 servers")
	}
	return result, nil
}

func isolatedNow() isolatedstate.UnixSeconds {
	return isolatedstate.UnixSeconds(time.Now().Unix())
}

func isolatedError(err error) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultError(err.Error()), nil
}

func optionalTrimmed(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func cloneLabels(source map[string]string) map[string]string {
	result := make(map[string]string, len(source)+5)
	for key, value := range source {
		result[key] = value
	}
	return result
}

func detectsNetworkBootstrap(arguments map[string]any) bool {
	for _, key := range []string{
		"first_boot_script", "domain_join", "package", "packages",
		"download", "downloads", "bootstrap", "bootstrap_script",
	} {
		value, ok := arguments[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return true
			}
		case bool:
			if typed {
				return true
			}
		default:
			return true
		}
	}
	return false
}
