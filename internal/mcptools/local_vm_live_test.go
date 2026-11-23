package mcptools

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Run only on an explicitly prepared disposable lab installation. The regular
// suite never installs services or creates VMs.
func TestRestrictedLocalHyperVLive(t *testing.T) {
	if os.Getenv("LABLINK_RESTRICTED_LIVE") != "1" {
		t.Skip("requires an installed restricted host and approved disposable VM storage")
	}
	home, serverPath := os.Getenv("LABLINK_TEST_HOME"), os.Getenv("LABLINK_TEST_SERVER")
	if home == "" || serverPath == "" {
		t.Fatal("LABLINK_TEST_HOME and LABLINK_TEST_SERVER are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	password := make([]byte, 24)
	if _, err := rand.Read(password); err != nil {
		t.Fatal(err)
	}
	creds := credentials.LoadStore(filepath.Join(home, "credentials.json"))
	existingCredential := false
	names, err := creds.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		existingCredential = existingCredential || name == "local-vm-admin"
	}
	if existingCredential {
		if _, err := creds.Get("local-vm-admin"); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := creds.Set(&credentials.Profile{Name: "local-vm-admin", Username: "Administrator",
			Password: "Ll9!" + base64.RawURLEncoding.EncodeToString(password)}); err != nil {
			t.Fatal(err)
		}
	}
	pki := filepath.Join(home, "pki")
	tokenBytes, err := os.ReadFile(filepath.Join(home, "agent.token"))
	if err != nil {
		t.Fatal(err)
	}
	transport, err := security.ResolveClientTransport("mtls", false,
		filepath.Join(pki, "ca-bundle", "ca.crt"),
		filepath.Join(pki, "clients", "default", "client.crt"),
		filepath.Join(pki, "clients", "default", "client.key"), "")
	if err != nil {
		t.Fatal(err)
	}
	pool := agentclient.NewPool(strings.TrimSpace(string(tokenBytes)), transport)
	defer pool.Close()
	reg := registry.Load(filepath.Join(home, "nodes.json"))
	node, found := reg.GetNode("local-hyperv")
	if !found {
		t.Fatal("restricted local endpoint is not registered")
	}
	hostClient, err := pool.GetClient(node.Address, node.TLSServerName)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := hostClient.Execute(ctx, &pb.ExecuteRequest{Command: "whoami", Shell: "powershell"})
	if err == nil {
		_, err = execution.Recv()
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("restricted host Execute was not denied: %v", err)
	}
	if _, err := hostClient.KillProcess(ctx, &pb.KillProcessRequest{Pid: 4}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("restricted host KillProcess was not denied: %v", err)
	}
	invalid, err := hostClient.ManageVM(ctx, &pb.ManageVMRequest{
		ToolName: "execute_script", ArgumentsJson: []byte(`{"script_body":"whoami"}`), ProfilesJson: []byte(`{}`),
	})
	if err == nil {
		_, err = invalid.Recv()
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("structured endpoint did not reject exec: %v", err)
	}
	env := append(os.Environ(),
		"LABLINK_HOME="+home, "LABLINK_PORTAL=disabled", "LABLINK_TRANSPORT=mtls",
		"LABLINK_AGENT_TOKEN_FILE="+filepath.Join(home, "agent.token"),
		"LABLINK_TLS_CA="+transport.CACertPath,
		"LABLINK_TLS_CERT="+transport.CertPath,
		"LABLINK_TLS_KEY="+transport.KeyPath)
	mcpClient, err := client.NewStdioMCPClient(serverPath, env)
	if err != nil {
		t.Fatal(err)
	}
	defer mcpClient.Close()
	initialize := mcp.InitializeRequest{}
	initialize.Params.ProtocolVersion = "2025-06-18"
	initialize.Params.ClientInfo = mcp.Implementation{Name: "restricted-hyperv-live", Version: "1"}
	if _, err := mcpClient.Initialize(ctx, initialize); err != nil {
		t.Fatal(err)
	}
	call := func(name string, args map[string]any, errorExpected bool) string {
		t.Helper()
		t.Logf("MCP %s", name)
		req := reqNoMeta(name, args)
		req.Params.Meta = &mcp.Meta{ProgressToken: name}
		result, err := mcpClient.CallTool(ctx, req)
		if err != nil || result == nil || result.IsError != errorExpected {
			t.Fatalf("%s failed: %+v %v", name, result, err)
		}
		return toolResultText(result)
	}
	executeGuest := func(node string) {
		t.Helper()
		for attempt := 0; attempt < 15; attempt++ {
			result, err := mcpClient.CallTool(ctx, reqNoMeta("execute_command", map[string]any{
				"node": node, "command": "whoami", "timeout": 30,
			}))
			if err == nil && result != nil && !result.IsError {
				return
			}
			if err != nil || result == nil ||
				(!strings.Contains(toolResultText(result), "code = Canceled") && !strings.Contains(toolResultText(result), "code = Unavailable")) {
				t.Fatalf("guest command failed: %+v %v", result, err)
			}
			t.Logf("guest transport settling after first boot: %s", node)
			time.Sleep(2 * time.Second)
		}
		t.Fatalf("guest %s did not become executable", node)
	}
	call("execute_command", map[string]any{
		"node": "local-hyperv", "command": "whoami", "shell": "powershell", "timeout": 30,
	}, true)
	// This is the ordinary full lab agent, not the restricted service.
	full := call("execute_command", map[string]any{
		"node": os.Getenv("LABLINK_TEST_FULL_NODE"), "command": "whoami", "shell": "powershell", "timeout": 30,
	}, false)
	if !strings.Contains(strings.ToLower(full), "system") {
		t.Fatalf("full remote agent did not execute its command: %s", full)
	}
	call("list_vswitches", map[string]any{"target": "localhost"}, false)
	call("create_vm", map[string]any{
		"target": "localhost", "name": "escape", "vm_location": `C:\Windows`,
		"new_vhd_path": `C:\Windows\escape.vhdx`, "new_vhd_size_gb": 1,
	}, true)
	if os.Getenv("LABLINK_TEST_COLD") == "1" {
		ready := false
		for attempt := 0; attempt < 30; attempt++ {
			call("prepare_linux_image", map[string]any{
				"target": "localhost", "profile": "local-ubuntu", "disk_size_gb": 66,
			}, false)
			text := call("get_linux_image_status", map[string]any{
				"target": "localhost", "profile": "local-ubuntu", "disk_size_gb": 66,
			}, false)
			var progress struct {
				Status string `json:"status"`
			}
			if err := json.Unmarshal([]byte(jsonExtract(text)), &progress); err != nil {
				t.Fatal(err)
			}
			t.Logf("cold Linux preparation: %s", progress.Status)
			if progress.Status == "ready" {
				ready = true
				break
			}
			time.Sleep(15 * time.Second)
		}
		if !ready {
			t.Fatal("cold Linux preparation did not reach ready")
		}
		if os.Getenv("LABLINK_TEST_COLD_ONLY") == "1" {
			return
		}
	}
	for _, test := range []struct{ tool, profile, name, node string }{
		{"create_windows_vm", "local-windows", "lhv-beta-win", "LHV-BETA-WIN"},
		{"create_linux_vm", "local-ubuntu", "lhv-beta-linux", "lhv-beta-linux"},
	} {
		if selected := os.Getenv("LABLINK_TEST_GUEST_OS"); selected != "" &&
			((selected == "linux" && test.tool != "create_linux_vm") ||
				(selected == "windows" && test.tool != "create_windows_vm")) {
			continue
		}
		existing := call("execute_command", map[string]any{
			"node": os.Getenv("LABLINK_TEST_FULL_NODE"), "shell": "powershell", "timeout": 30,
			"command": fmt.Sprintf("if(Get-VM -Name '%s' -ErrorAction SilentlyContinue){'exists'}else{'absent'}", test.name),
		}, false)
		if strings.Contains(existing, "\nexists") {
			call("delete_vm", map[string]any{
				"target": "localhost", "name": test.name, "lablink_node_name": test.node,
				"dry_run": false, "force_stop": true, "delete_storage": true,
			}, false)
		}
		call(test.tool, map[string]any{
			"target": "localhost", "profile": test.profile, "name": test.name,
			"register_with_lablink": true,
		}, false)
		executeGuest(test.node)
		if script := os.Getenv("LABLINK_TEST_UPGRADE_SCRIPT"); script != "" && test.tool == "create_windows_vm" {
			output, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive",
				"-ExecutionPolicy", "Bypass", "-File", script).CombinedOutput()
			if err != nil {
				t.Fatalf("upgrade with a running guest failed: %v\n%s", err, output)
			}
			executeGuest(test.node)
		}
		call("delete_vm", map[string]any{
			"target": "localhost", "name": test.name, "lablink_node_name": test.node,
			"dry_run": true, "force_stop": true, "delete_storage": true,
		}, false)
		call("delete_vm", map[string]any{
			"target": "localhost", "name": test.name, "lablink_node_name": test.node,
			"dry_run": false, "force_stop": true, "delete_storage": true,
		}, false)
	}
	if os.Getenv("LABLINK_TEST_EXTENDED") == "1" {
		fullRoot := os.Getenv("LABLINK_TEST_FULL_VM_ROOT")
		if fullRoot == "" {
			t.Fatal("extended regression needs an explicit disposable full-agent VM root")
		}
		call("create_windows_vm", map[string]any{
			"target": os.Getenv("LABLINK_TEST_FULL_NODE"), "profile": "local-windows",
			"name": "lhv-full-win", "vm_root": fullRoot, "register_with_lablink": true,
		}, false)
		executeGuest("LHV-FULL-WIN")
		call("delete_vm", map[string]any{
			"target": os.Getenv("LABLINK_TEST_FULL_NODE"), "name": "lhv-full-win",
			"managed_root": fullRoot, "dry_run": false, "force_stop": true, "delete_storage": true,
		}, false)
		var orchestrator isolatedstate.Orchestrator
		text := call("create_isolated_orchestrator", map[string]any{
			"target": "localhost", "profile": "local-ubuntu", "display_name": "restricted-host-integration",
		}, false)
		if err := json.Unmarshal([]byte(jsonExtract(text)), &orchestrator); err != nil {
			t.Fatal(err)
		}
		var network isolatedstate.PrivateNetwork
		text = call("add_isolated_network", map[string]any{"orchestrator_id": orchestrator.ID}, false)
		if err := json.Unmarshal([]byte(jsonExtract(text)), &network); err != nil {
			t.Fatal(err)
		}
		call("create_isolated_vm", map[string]any{
			"network_id": network.ID, "profile": "local-ubuntu", "guest_os": " LINUX ",
			"name": "lhv-beta-private", "nat_enabled": false, "bootstrap_network_requirement": "pre_staged",
		}, false)
		executeGuest("lhv-beta-private")
		call("delete_isolated_orchestrator", map[string]any{
			"orchestrator_id": orchestrator.ID, "cascade": false,
		}, true)
		call("delete_isolated_orchestrator", map[string]any{
			"orchestrator_id": orchestrator.ID, "cascade": true, "delete_storage": true,
		}, false)
		for _, name := range []string{"list_isolated_vms", "list_isolated_relays", "list_isolated_vm_nat"} {
			var values []json.RawMessage
			text := call(name, map[string]any{"orchestrator_id": orchestrator.ID}, false)
			if err := json.Unmarshal([]byte(jsonExtract(text)), &values); err != nil || len(values) != 0 {
				t.Fatalf("restricted cascade left resources: %s (%v)", text, err)
			}
		}
	}
}
