package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/security"
	"github.com/nijosmsft/lablink/internal/vmconfig"
	pb "github.com/nijosmsft/lablink/proto/agent"
	"google.golang.org/grpc"
)

type isolatedRoutingAgent struct {
	pb.UnimplementedNodeAgentServer
	mu                sync.Mutex
	network           string
	requests          []string
	withoutCapability bool
}

func (a *isolatedRoutingAgent) GetInfo(context.Context, *pb.GetInfoRequest) (*pb.GetInfoResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.withoutCapability {
		return &pb.GetInfoResponse{}, nil
	}
	return &pb.GetInfoResponse{Capabilities: []string{LocalHyperVCapability}}, nil
}

func (a *isolatedRoutingAgent) ManageVM(req *pb.ManageVMRequest, stream grpc.ServerStreamingServer[pb.ManageVMResponse]) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var args map[string]any
	if err := json.Unmarshal(req.ArgumentsJson, &args); err != nil {
		return err
	}
	a.requests = append(a.requests, req.ToolName)
	var result *mcp.CallToolResult
	switch req.ToolName {
	case "add_isolated_network":
		a.network = "11111111-2222-4333-8444-555555555555"
		result = simpleIsolatedResult("**Isolated network created**", isolatedstate.PrivateNetwork{
			ID: a.network, LifecycleState: isolatedstate.NetworkReady,
		})
	case "create_isolated_vm":
		if args["network_id"] != a.network || a.network == "" {
			return fmt.Errorf("owning host cannot find network %v", args["network_id"])
		}
		result = mcp.NewToolResultText("owning host accepted the existing network")
	default:
		return fmt.Errorf("unexpected VM operation %q", req.ToolName)
	}
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return stream.Send(&pb.ManageVMResponse{ResultJson: data, NodesJson: []byte(`[]`)})
}

func TestRestrictedReadyNetworkRoutesAfterHostRegistered(t *testing.T) {
	for _, test := range []struct {
		name        string
		target      string
		modeMissing bool
	}{
		{"named-profile-target", "local-hyperv", false},
		{"localhost-profile-target", "localhost", false},
		{"wrong-service-mode-does-not-use-operator-database", "localhost", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			state, err := isolatedstate.Open(filepath.Join(dir, "isolated.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			reg := registry.Load(filepath.Join(dir, "nodes.json"))
			defaultsPath := filepath.Join(dir, "vm-defaults.json")
			config := fmt.Sprintf(`{"profiles":{"guest":{"guest_os":"windows","target":%q}}}`, test.target)
			if err := os.WriteFile(defaultsPath, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			pool := agentclient.NewPool("", security.ClientTransportConfig{Mode: security.TransportModeInsecure})
			defer pool.Close()
			s := server.NewMCPServer("routing-test", "test")
			s.AddTool(mcp.NewTool("add_isolated_network", mcp.WithString("target")),
				func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					return mcp.NewToolResultError("network creation reached the operator registry"), nil
				})
			s.AddTool(mcp.NewTool("create_isolated_vm"),
				createSimpleIsolatedVMHandler(&isolatedLifecycleDeps{state: state}))
			RegisterLocalVMProxy(s, reg, pool, vmconfig.Load(defaultsPath), nil, state, "")
			agent := &isolatedRoutingAgent{}
			host := &registry.Node{
				Name: "local-hyperv", Address: startNodeAgent(t, agent),
				TLSServerName: "local-hyperv",
				Labels:        map[string]string{"lablink.local_hyperv": "true"},
			}
			if err := reg.SetNode(host); err != nil {
				t.Fatal(err)
			}
			created, err := s.ListTools()["add_isolated_network"].Handler(context.Background(),
				reqNoMeta("add_isolated_network", map[string]any{"target": host.Name, "orchestrator_id": "test-orchestrator"}))
			if err != nil || created == nil || created.IsError || !strings.Contains(toolResultText(created), "ready") {
				t.Fatalf("network creation failed: %+v %v", created, err)
			}
			agent.mu.Lock()
			networkID := agent.network
			agent.withoutCapability = test.modeMissing
			agent.mu.Unlock()
			if _, err := state.GetNetwork(context.Background(), networkID); err == nil {
				t.Fatal("fixture must keep the network in the owning host's registry, not the operator's")
			}
			result, err := s.ListTools()["create_isolated_vm"].Handler(context.Background(),
				reqNoMeta("create_isolated_vm", map[string]any{
					"network_id": networkID, "name": "guest", "guest_os": "windows", "profile": "guest",
				}))
			if test.modeMissing {
				if err != nil || result == nil || !result.IsError ||
					!strings.Contains(toolResultText(result), "refusing operator-registry fallback") {
					t.Fatalf("wrong service mode fell back to the operator registry: %+v %v", result, err)
				}
				return
			}
			if err != nil || result == nil || result.IsError ||
				!strings.Contains(toolResultText(result), "owning host accepted") {
				t.Fatalf("Ready network was looked up in the wrong registry: %+v %v", result, err)
			}
			agent.mu.Lock()
			defer agent.mu.Unlock()
			if len(agent.requests) != 2 || agent.requests[1] != "create_isolated_vm" {
				t.Fatalf("VM was not routed to the network's host: %v", agent.requests)
			}
		})
	}
}

func TestLocalVMProxyHostResolvesLiveRegistryWithoutGuessing(t *testing.T) {
	reg := registry.Load(filepath.Join(t.TempDir(), "nodes.json"))
	if host, err := resolveLocalVMProxyHost(reg, ""); err != nil || host != "" {
		t.Fatalf("unexpected local host before registration: %q %v", host, err)
	}
	for _, name := range []string{"host-one", "host-two"} {
		if err := reg.SetNode(&registry.Node{
			Name: name, Labels: map[string]string{"lablink.local_hyperv": "true"},
		}); err != nil {
			t.Fatal(err)
		}
		if name == "host-one" {
			if host, err := resolveLocalVMProxyHost(reg, ""); err != nil || host != name {
				t.Fatalf("newly registered host was not discovered: %q %v", host, err)
			}
		}
	}
	if _, err := resolveLocalVMProxyHost(reg, ""); err == nil {
		t.Fatal("ambiguous local-host registration was silently guessed")
	}
	if host, err := resolveLocalVMProxyHost(reg, "host-two"); err != nil || host != "host-two" {
		t.Fatalf("explicit host binding was not honored: %q %v", host, err)
	}
}

func TestRestrictedVMPolicyRejectsHostEscapes(t *testing.T) {
	h := &LocalVMHost{policy: LocalVMPolicy{
		VMRoot: `C:\LabLinkData\VMs`, ImageRoot: `C:\LabLinkData\Images`,
		BaseVHDs: []string{`D:\Approved\base.vhdx`}, VSwitches: []string{"Default Switch"},
	}}
	defaults := vmconfig.Load(filepath.Join(t.TempDir(), "absent.json"))
	for _, test := range []struct {
		name string
		args map[string]any
	}{
		{"disk-outside-root", map[string]any{"vm_location": `C:\Windows`}},
		{"sibling-prefix", map[string]any{"vm_location": `C:\LabLinkData\VMs-escape\vm`}},
		{"traversal", map[string]any{"vhd_path": `C:\LabLinkData\VMs\..\outside.vhdx`}},
		{"physical-disk", map[string]any{"vhd_path": `\\.\PhysicalDrive0`}},
		{"unapproved-base", map[string]any{"base_vhd": `C:\secret.vhdx`}},
		{"secret-file-read", map[string]any{"ssh_public_key_file": `C:\LabLinkData\tls\server.key`}},
		{"external-switch", map[string]any{"name": "LabLink-test", "type": "external"}},
		{"unmanaged-switch", map[string]any{"name": "production", "type": "private"}},
		{"replace-switch", map[string]any{"name": "LabLink-test", "type": "private", "if_exists": "replace"}},
		{"padded-replace-switch", map[string]any{"name": "LabLink-test", "type": "private", "if_exists": " Replace "}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := h.validate(context.Background(), reqNoMeta("create_vswitch", test.args), defaults)
			if err == nil {
				t.Fatal("restricted operation accepted unsafe request")
			}
		})
	}
	if err := h.validate(context.Background(),
		reqNoMeta("create_vswitch", map[string]any{"name": "LabLink-test", "type": "private"}), defaults,
	); err != nil {
		t.Fatalf("valid restricted switch rejected: %v", err)
	}
	_, _, err := h.Call(context.Background(), &pb.ManageVMRequest{ToolName: "execute_script", ArgumentsJson: []byte(`{"script_body":"whoami"}`)})
	if err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("arbitrary script accepted: %v", err)
	}
}

func TestRestrictedVMJSONRejectsUnknownFieldsAndTrailingObjects(t *testing.T) {
	for _, value := range []string{
		`{"tool_name":"create_vm","script_body":"whoami"}`,
		`{} {}`,
	} {
		var policy LocalVMPolicy
		if err := decodeStrictJSON([]byte(value), &policy); err == nil {
			t.Fatalf("unsafe JSON accepted: %s", value)
		}
	}
}

func TestRestrictedGuestSyncPreservesUnrelatedNodes(t *testing.T) {
	reg := newRebootTestRegistry(t, map[string]string{"remote": "10.0.0.1:9091"})
	guest := &registry.Node{Name: "guest", Address: "10.0.0.2:9091"}
	if err := syncLocalVMNodes(reg, "local-hyperv", []*registry.Node{guest}); err != nil {
		t.Fatal(err)
	}
	if err := syncLocalVMNodes(reg, "local-hyperv", nil); err != nil {
		t.Fatal(err)
	}
	if _, found := reg.GetNode("remote"); !found {
		t.Fatal("guest deletion removed an unrelated full node")
	}
	if _, found := reg.GetNode("guest"); found {
		t.Fatal("deleted guest still registered")
	}
	if err := syncLocalVMNodes(reg, "local-hyperv", []*registry.Node{{Name: "remote"}}); err == nil {
		t.Fatal("restricted host replaced an unrelated full node")
	}
}

func TestRestrictedProxyTargetDoesNotRestrictRemoteProfiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "defaults.json")
	if err := os.WriteFile(path, []byte(`{"profiles":{"remote":{"target":"remote","guest_os":"windows"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	target, err := localVMProxyTarget(context.Background(), "create_windows_vm",
		reqNoMeta("create_windows_vm", map[string]any{"profile": "remote"}), vmconfig.Load(path), nil, "local-hyperv")
	if err != nil || target != "remote" {
		t.Fatalf("remote profile incorrectly restricted: %q, %v", target, err)
	}
	result := mcp.NewToolResultText("full remote tools remain available")
	data, _ := json.Marshal(result)
	var decoded mcp.CallToolResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("VM result does not survive transport: %v", err)
	}
}

func TestRestrictedIsolatedOSNormalizationCannotBypassLinuxPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "defaults.json")
	if err := os.WriteFile(path, []byte(`{"profiles":{"ubuntu":{
	  "guest_os":"linux","vm_root":"C:\\Managed\\VMs",
	  "base_vhd":"D:\\Approved\\base.vhdx","image_cache_root":"C:\\HostSecrets"
	}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	h := &LocalVMHost{policy: LocalVMPolicy{
		VMRoot: `C:\Managed\VMs`, ImageRoot: `C:\Managed\Images`,
		BaseVHDs: []string{`D:\Approved\base.vhdx`},
	}}
	for _, value := range []string{"linux", "LINUX", " Linux "} {
		err := h.validate(context.Background(), reqNoMeta("create_isolated_vm",
			map[string]any{"profile": "ubuntu", "guest_os": value}), vmconfig.Load(path))
		if err == nil || !strings.Contains(err.Error(), "image_cache_root") {
			t.Fatalf("OS %q bypassed Linux path policy: %v", value, err)
		}
	}
}

func TestRestrictedProxyForwardsResolvedTargetDefaultAndBuilderCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "defaults.json")
	if err := os.WriteFile(path, []byte(`{
	  "default_profile":"remote",
	  "target_defaults":{"local-hyperv":"windows"},
	  "profiles":{
	    "remote":{"guest_os":"windows","admin_password_credential":"not-forwarded"},
	    "windows":{"guest_os":"windows","admin_password_credential":"local-admin"},
	    "builder-windows":{"guest_os":"windows","admin_password_credential":"builder"},
	    "ubuntu":{"guest_os":"linux","linux_password_credential":"guest","image_builder_profile":"builder-windows"}
	  }
	}`), 0600); err != nil {
		t.Fatal(err)
	}
	creds, err := credentials.NewTransient([]*credentials.Profile{
		{Name: "guest", Password: "guest-test-password"},
		{Name: "builder", Password: "builder-test-password"},
		{Name: "local-admin", Password: "local-test-password"},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := vmconfig.Load(path)
	request, err := prepareLocalVMRequest("create_windows_vm", reqNoMeta("create_windows_vm",
		map[string]any{"target": "local-hyperv"}), store, creds, true)
	if err != nil {
		t.Fatal(err)
	}
	var args map[string]any
	if err := json.Unmarshal(request.ArgumentsJson, &args); err != nil {
		t.Fatal(err)
	}
	if args["profile"] != "windows" || args["target"] != "localhost" ||
		len(request.Credentials) != 1 || request.Credentials[0].Name != "local-admin" {
		t.Fatalf("target default was not pinned before forwarding: %+v", args)
	}
	request, err = prepareLocalVMRequest("create_isolated_vm", reqNoMeta("create_isolated_vm",
		map[string]any{"profile": "ubuntu", "guest_os": " LINUX "}), store, creds, false)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, credential := range request.Credentials {
		found[credential.Name] = true
	}
	if len(found) != 2 || !found["builder"] || !found["guest"] {
		t.Fatal("isolated Linux request omitted the distinct builder credential")
	}
}

func TestRestrictedVMArgumentsRejectWrongTypesBeforeHandlerDefaults(t *testing.T) {
	tool := mcp.NewTool("create_vm",
		mcp.WithString("name", mcp.Required()),
		mcp.WithBoolean("delete_storage"),
		mcp.WithNumber("memory_mb"))
	for _, args := range []map[string]any{
		{"name": "guest", "delete_storage": "false"},
		{"name": nil},
		{"memory_mb": float64(4096)},
		{"name": "guest", "memory_mb": "4096"},
		{"name": "guest", "script_body": "whoami"},
	} {
		if err := validateLocalVMArguments(tool, args); err == nil {
			t.Fatalf("malformed request accepted: %+v", args)
		}
	}
	if err := validateLocalVMArguments(tool,
		map[string]any{"name": "guest", "delete_storage": false, "memory_mb": float64(4096)}); err != nil {
		t.Fatal(err)
	}
}

func TestRestrictedPolicySeparatesImagesFromKeysAndCode(t *testing.T) {
	policy := LocalVMPolicy{
		StateDir: `C:\ProgramData\LabLinkHyperV`, InstallRoot: `C:\Program Files\LabLinkHyperV`,
		PKIDir: `C:\ProgramData\LabLinkHyperV\pki`,
		VMRoot: `C:\ProgramData\LabLinkHyperV\VMs`, ImageRoot: `C:\ProgramData\LabLinkHyperV\Images`,
	}
	data, _ := json.Marshal(policy)
	if _, err := DecodeLocalVMPolicy(data); err != nil {
		t.Fatal(err)
	}
	for _, imageRoot := range []string{policy.StateDir, policy.InstallRoot, policy.PKIDir,
		policy.StateDir + `\tls`, policy.PKIDir + `\images`, policy.StateDir + `\staging`} {
		candidate := policy
		candidate.ImageRoot = imageRoot
		data, _ := json.Marshal(candidate)
		if _, err := DecodeLocalVMPolicy(data); err == nil {
			t.Fatalf("private material exposed as a guest image root: %s", imageRoot)
		}
		candidate = policy
		candidate.VMRoot = imageRoot
		data, _ = json.Marshal(candidate)
		if _, err := DecodeLocalVMPolicy(data); err == nil {
			t.Fatalf("private material exposed as a guest VM root: %s", imageRoot)
		}
	}
}
