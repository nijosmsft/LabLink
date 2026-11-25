package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/vmconfig"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

const localVMSourceLabel = "lablink.hyperv_host"

// RegisterLocalVMProxy leaves the MCP tool catalog intact. Only VM operations
// targeting the restricted host use ManageVM; ordinary remote agents retain
// their existing transport and capabilities.
func RegisterLocalVMProxy(
	s *server.MCPServer, reg *registry.Registry, pool *agentclient.Pool,
	defaults *vmconfig.Store, creds *credentials.Store,
	state *isolatedstate.Store, localNode string,
) {
	for name, registered := range s.ListTools() {
		if !localVMTools[name] {
			continue
		}
		original := registered.Handler
		tool := registered.Tool
		s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			target, err := localVMProxyTarget(ctx, name, req, defaults, state, localNode)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if isLocalAlias(target) {
				if localNode == "" {
					return original(ctx, req)
				}
				target = localNode
			}
			node, found := reg.GetNode(target)
			if !found {
				return mcp.NewToolResultError(fmt.Sprintf("VM target %q is not registered", target)), nil
			}
			client, err := pool.GetClient(node.Address, node.TLSServerName)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			info, err := client.GetInfo(probeCtx, &pb.GetInfoRequest{})
			cancel()
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			restricted := false
			for _, capability := range info.Capabilities {
				restricted = restricted || capability == LocalHyperVCapability
			}
			if !restricted {
				return original(ctx, req)
			}
			_, hasTarget := tool.InputSchema.Properties["target"]
			request, err := prepareLocalVMRequest(name, req, defaults, creds, hasTarget)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			stop := StartMCPHeartbeat(ctx, req, defaultHeartbeatInterval, func() (int64, int64) { return 0, 1 })
			defer stop()
			stream, err := client.ManageVM(ctx, request)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			var result *mcp.CallToolResult
			for {
				response, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					return mcp.NewToolResultError(fmt.Sprintf("restricted Hyper-V host: %v", err)), nil
				}
				if len(response.ResultJson) == 0 {
					continue
				}
				result = &mcp.CallToolResult{}
				if err := json.Unmarshal(response.ResultJson, result); err != nil {
					return nil, fmt.Errorf("decode VM result: %w", err)
				}
				var nodes []*registry.Node
				if err := json.Unmarshal(response.NodesJson, &nodes); err != nil {
					return nil, fmt.Errorf("decode enrolled VM nodes: %w", err)
				}
				if err := syncLocalVMNodes(reg, target, nodes); err != nil {
					return nil, err
				}
			}
			if result == nil {
				return mcp.NewToolResultError("restricted VM operation returned no result"), nil
			}
			if strings.HasPrefix(name, "list_isolated_") && req.GetString("target", "") == "" && !result.IsError {
				remoteResult, err := original(ctx, req)
				if err != nil || remoteResult == nil || remoteResult.IsError {
					return remoteResult, err
				}
				var localValues, remoteValues []json.RawMessage
				if err := json.Unmarshal([]byte(jsonExtract(toolResultText(result))), &localValues); err != nil {
					return nil, err
				}
				if err := json.Unmarshal([]byte(jsonExtract(toolResultText(remoteResult))), &remoteValues); err != nil {
					return nil, err
				}
				return simpleIsolatedResult("**Isolated resources**", append(remoteValues, localValues...)), nil
			}
			return result, nil
		})
	}
}

func prepareLocalVMRequest(name string, req mcp.CallToolRequest, defaults *vmconfig.Store, creds *credentials.Store, hasTarget bool) (*pb.ManageVMRequest, error) {
	config, err := defaults.List()
	if err != nil {
		return nil, err
	}
	args := cloneArguments(req.GetArguments())
	selected, reference := "", ""
	linux := false
	profileName, target := req.GetString("profile", ""), req.GetString("target", "")
	switch name {
	case "create_windows_vm":
		_, selected, err = defaults.ResolveOrdinaryWindowsForTarget(profileName, target)
		reference = selected
	case "create_linux_vm", "prepare_linux_image", "get_linux_image_status":
		_, selected, err = defaults.ResolveLinuxForTarget(profileName, target)
		reference, linux = selected, true
	case "create_isolated_orchestrator":
		var resolved vmconfig.ResolvedIsolatedOrchestratorProfile
		resolved, selected, err = defaults.ResolveIsolatedOrchestratorForTarget(profileName, target)
		reference, linux = resolved.LinuxProfileName, true
	case "create_isolated_vm":
		var profile vmconfig.Profile
		profile, selected, err = defaults.ResolveForTarget(profileName, target)
		reference = selected
		osName := strings.ToLower(strings.TrimSpace(req.GetString("guest_os", "")))
		profileOS, osErr := profile.EffectiveGuestOS()
		if osErr != nil || osName != profileOS {
			return nil, fmt.Errorf("guest_os must agree with the selected VM profile")
		}
		args["guest_os"], linux = osName, osName == "linux"
	}
	if err != nil {
		return nil, err
	}
	if selected != "" {
		args["profile"] = selected
	}
	references := []string{reference}
	if linux {
		builder := req.GetString("image_builder_profile", "")
		if builder == "" {
			builder = config.Profiles[reference].ImageBuilderProfile
		}
		references = append(references, builder)
	}
	names := make(map[string]bool)
	for _, profileName := range references {
		if profileName == "" {
			continue
		}
		profile := config.Profiles[profileName]
		if profile.SSHPublicKeyFile != "" {
			data, err := os.ReadFile(profile.SSHPublicKeyFile)
			if err != nil {
				return nil, fmt.Errorf("read public key as operator: %w", err)
			}
			profile.SSHPublicKey, profile.SSHPublicKeyFile = strings.TrimSpace(string(data)), ""
			config.Profiles[profileName] = profile
		}
		if profile.AdminCredential != "" {
			names[profile.AdminCredential] = true
		}
		if profile.LinuxPasswordCredential != "" {
			names[profile.LinuxPasswordCredential] = true
		}
	}
	for _, field := range []string{"admin_password_credential", "linux_password_credential"} {
		if value := req.GetString(field, ""); value != "" {
			names[value] = true
		}
	}
	if path := req.GetString("ssh_public_key_file", ""); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read public key as operator: %w", err)
		}
		args["ssh_public_key"], args["ssh_public_key_file"] = strings.TrimSpace(string(data)), ""
	}
	if hasTarget {
		args["target"] = "localhost"
	} else {
		delete(args, "target")
	}
	argData, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	profileData, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	request := &pb.ManageVMRequest{ToolName: name, ArgumentsJson: argData, ProfilesJson: profileData}
	for credentialName := range names {
		profile, err := creds.Get(credentialName)
		if err != nil {
			return nil, err
		}
		request.Credentials = append(request.Credentials, &pb.VMCredential{
			Name: profile.Name, Username: profile.Username, Password: profile.Password,
		})
	}
	return request, nil
}

func syncLocalVMNodes(reg *registry.Registry, source string, nodes []*registry.Node) error {
	if err := updateLocalVMNodes(reg, source, nodes); err != nil {
		return err
	}
	present := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		present[node.Name] = true
	}
	for _, node := range reg.AllNodes() {
		if node.Labels[localVMSourceLabel] == source && !present[node.Name] {
			if err := reg.RemoveNode(node.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

func updateLocalVMNodes(reg *registry.Registry, source string, nodes []*registry.Node) error {
	present := make(map[string]bool)
	var existing []*registry.Node
	addresses := make(map[string]string)
	for _, node := range nodes {
		if node == nil || node.Name == source || strings.TrimSpace(node.Name) == "" {
			return fmt.Errorf("restricted host returned an invalid guest node")
		}
		if present[node.Name] {
			return fmt.Errorf("restricted host returned duplicate guest %q", node.Name)
		}
		if old, exists := reg.GetNode(node.Name); exists {
			if old.Labels[localVMSourceLabel] != source || old.TLSServerName != node.TLSServerName {
				return fmt.Errorf("guest name %q conflicts with an existing node identity", node.Name)
			}
			if old.Address != node.Address {
				existing = append(existing, old)
				addresses[node.Name] = node.Address
			}
		}
		present[node.Name] = true
	}
	if len(existing) != 0 {
		if err := reg.UpdateAddresses(existing, addresses); err != nil {
			return err
		}
	}
	for _, node := range nodes {
		if node.Labels == nil {
			node.Labels = make(map[string]string)
		}
		node.Labels[localVMSourceLabel] = source
		if old, found := reg.GetNode(node.Name); found && reflect.DeepEqual(old, node) {
			continue
		}
		if err := reg.SetNode(node); err != nil {
			return err
		}
	}
	return nil
}

func localVMProxyTarget(ctx context.Context, name string, req mcp.CallToolRequest, defaults *vmconfig.Store, state *isolatedstate.Store, localNode string) (string, error) {
	if value := strings.TrimSpace(req.GetString("target", "")); value != "" {
		return value, nil
	}
	switch name {
	case "create_windows_vm":
		profile, _, err := defaults.ResolveWindows(req.GetString("profile", ""))
		return profile.Target, err
	case "create_linux_vm", "prepare_linux_image", "get_linux_image_status":
		profile, _, err := defaults.ResolveLinux(req.GetString("profile", ""))
		return profile.Target, err
	case "create_isolated_orchestrator":
		profile, _, err := defaults.ResolveIsolatedOrchestrator(req.GetString("profile", ""))
		return profile.LinuxVM.Target, err
	}
	if strings.Contains(name, "isolated") {
		orchestrator := req.GetString("orchestrator_id", "")
		vmID, networkID, relayID := req.GetString("isolated_vm_id", ""), req.GetString("network_id", ""), req.GetString("relay_id", "")
		if name == "rename_isolated_display_name" {
			switch req.GetString("resource_type", "") {
			case "orchestrator":
				orchestrator = req.GetString("resource_id", "")
			case "network":
				networkID = req.GetString("resource_id", "")
			case "vm":
				vmID = req.GetString("resource_id", "")
			}
		}
		if id := vmID; id != "" {
			if vm, err := state.GetVM(ctx, id); err == nil {
				orchestrator = vm.OrchestratorID
			}
		}
		if id := networkID; id != "" {
			if network, err := state.GetNetwork(ctx, id); err == nil {
				orchestrator = network.OrchestratorID
			}
		}
		if id := relayID; id != "" {
			if relay, err := state.GetRelay(ctx, id); err == nil {
				orchestrator = relay.OrchestratorID
			}
		}
		if orchestrator != "" {
			if value, err := state.GetOrchestrator(ctx, orchestrator); err == nil {
				return value.HostNode, nil
			}
		}
		if localNode != "" {
			return localNode, nil
		}
	}
	return "localhost", nil
}
