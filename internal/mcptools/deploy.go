package mcptools

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

func RegisterDeploy(s *server.MCPServer, reg *registry.Registry, pool *agentclient.Pool, creds *credentials.Store, agentToken string) {
	s.AddTool(
		mcp.NewTool("deploy_agent",
			mcp.WithDescription("Deploy the LabLink agent to a remote Windows machine via PS Remoting. Installs as a Windows service, writes token to registry, creates firewall rule, and registers the node."),
			mcp.WithString("machine", mcp.Required(), mcp.Description("IP address or hostname of the target machine")),
			mcp.WithString("name", mcp.Required(), mcp.Description("Friendly node name (e.g., server-25)")),
			mcp.WithString("role", mcp.Description("Node role: server, client, or custom")),
			mcp.WithString("credential", mcp.Required(), mcp.Description("Credential profile name (use save_credential to create one first)")),
			mcp.WithNumber("port", mcp.Description("gRPC listen port (default 9091)")),
			mcp.WithString("transport", mcp.Description("Agent transport mode: mtls (default) or insecure")),
			mcp.WithString("tls_server_name", mcp.Description("Certificate name to verify for this node when using mTLS")),
			mcp.WithString("tls_ca", mcp.Description("Local path to the CA certificate bundle PEM when transport=mtls")),
			mcp.WithString("tls_cert", mcp.Description("Local path to the server certificate chain PEM when transport=mtls")),
			mcp.WithString("tls_key", mcp.Description("Local path to the server private key PEM when transport=mtls")),
			mcp.WithBoolean("allow_insecure", mcp.Description("Explicitly acknowledge use of the insecure fallback transport when transport=insecure")),
			mcp.WithBoolean("no_service", mcp.Description("Skip service install; run as detached process instead")),
		),
		deployAgentHandler(reg, pool, creds, agentToken),
	)

	s.AddTool(
		mcp.NewTool("save_credential",
			mcp.WithDescription("Save a named credential profile for use with deploy_agent. Credentials are stored locally in ~/.lablink/credentials.json."),
			mcp.WithString("name", mcp.Required(), mcp.Description("Profile name (e.g., lab-admin)")),
			mcp.WithString("username", mcp.Required(), mcp.Description("Username (e.g., LocalAdminUser)")),
			mcp.WithString("password", mcp.Required(), mcp.Description("Password")),
		),
		saveCredentialHandler(creds),
	)

	s.AddTool(
		mcp.NewTool("list_credentials",
			mcp.WithDescription("List saved credential profile names (passwords are not shown)."),
		),
		listCredentialsHandler(creds),
	)
}

func deployAgentHandler(reg *registry.Registry, pool *agentclient.Pool, creds *credentials.Store, agentToken string) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		machine := request.GetString("machine", "")
		name := request.GetString("name", "")
		role := request.GetString("role", "")
		credName := request.GetString("credential", "")
		port := request.GetInt("port", 9091)
		transportMode := strings.TrimSpace(request.GetString("transport", string(security.TransportModeMTLS)))
		tlsServerName := strings.TrimSpace(request.GetString("tls_server_name", ""))
		tlsCA := strings.TrimSpace(request.GetString("tls_ca", ""))
		tlsCert := strings.TrimSpace(request.GetString("tls_cert", ""))
		tlsKey := strings.TrimSpace(request.GetString("tls_key", ""))
		allowInsecure := request.GetBool("allow_insecure", false)
		noService := request.GetBool("no_service", false)

		switch transportMode {
		case "", string(security.TransportModeMTLS):
			transportMode = string(security.TransportModeMTLS)
			if tlsCA == "" || tlsCert == "" || tlsKey == "" {
				return mcp.NewToolResultError("deploy_agent requires tls_ca, tls_cert, and tls_key when transport=mtls"), nil
			}
		case string(security.TransportModeInsecure):
			if !allowInsecure {
				return mcp.NewToolResultError("deploy_agent requires allow_insecure=true when transport=insecure"), nil
			}
		default:
			return mcp.NewToolResultError(fmt.Sprintf("invalid transport %q (expected mtls or insecure)", transportMode)), nil
		}

		// Resolve credential.
		cred, err := creds.Get(credName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("credential %q not found — use save_credential first", credName)), nil
		}

		// Find the agent binary relative to the MCP server binary.
		agentBin := findAgentBinary()
		if agentBin == "" {
			return mcp.NewToolResultError("cannot find LabLinkAgent.exe in bin/ directory"), nil
		}

		// Build the deploy script command.
		noSvcFlag := ""
		if noService {
			noSvcFlag = " -NoService"
		}
		transportFlag := fmt.Sprintf(" -Transport '%s'", escapePSString(transportMode))
		transportArgs := ""
		if transportMode == string(security.TransportModeMTLS) {
			transportArgs = fmt.Sprintf(" -TlsCA '%s' -TlsCert '%s' -TlsKey '%s'",
				escapePSString(tlsCA),
				escapePSString(tlsCert),
				escapePSString(tlsKey),
			)
		} else {
			transportArgs = " -AllowInsecure"
		}

		psScript := fmt.Sprintf(`
$cred = New-Object PSCredential('%s', (ConvertTo-SecureString '%s' -AsPlainText -Force))
& '%s' -Machines '%s' -AgentBinary '%s' -Token '%s' -Port %d -Credential $cred%s%s%s
`,
			escapePSString(cred.Username),
			escapePSString(cred.Password),
			findDeployScript(),
			machine,
			agentBin,
			escapePSString(agentToken),
			port,
			transportFlag,
			transportArgs,
			noSvcFlag,
		)

		cmd := exec.CommandContext(ctx, "pwsh", "-NoProfile", "-Command", psScript)
		output, err := cmd.CombinedOutput()
		outputStr := string(output)

		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("deploy failed:\n```\n%s\n```\nerror: %v", outputStr, err)), nil
		}

		// Auto-register the node.
		address := fmt.Sprintf("%s:%d", machine, port)
		regResult := ""
		client, connErr := pool.GetClient(address, tlsServerName)
		if connErr == nil {
			info, probeErr := client.GetInfo(ctx, &pb.GetInfoRequest{})
			if probeErr == nil {
				node := &registry.Node{
					Name:          name,
					Address:       address,
					Role:          role,
					OS:            info.Os,
					Arch:          info.Arch,
					CPUCount:      int(info.CpuCount),
					Memory:        info.MemoryBytes,
					TransportMode: transportMode,
					TLSServerName: tlsServerName,
				}
				reg.SetNode(node)
				regResult = fmt.Sprintf("\nNode **%s** registered (%s/%s, %d CPUs, %s)",
					name, info.Os, info.Arch, info.CpuCount, formatBytes(info.MemoryBytes))
			} else {
				regResult = fmt.Sprintf("\nAgent deployed but probe failed: %v — register manually", probeErr)
			}
		} else {
			regResult = fmt.Sprintf("\nAgent deployed but connect failed: %v — register manually", connErr)
		}

		return mcp.NewToolResultText(fmt.Sprintf("```\n%s```\n%s", outputStr, regResult)), nil
	}
}

func saveCredentialHandler(creds *credentials.Store) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name := request.GetString("name", "")
		username := request.GetString("username", "")
		password := request.GetString("password", "")

		if err := creds.Set(&credentials.Profile{
			Name:     name,
			Username: username,
			Password: password,
		}); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("save failed: %v", err)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("Saved credential profile **%s** (user: %s)", name, username)), nil
	}
}

func listCredentialsHandler(creds *credentials.Store) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		names := creds.List()
		if len(names) == 0 {
			return mcp.NewToolResultText("No credential profiles saved. Use `save_credential` to create one."), nil
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("**Saved credential profiles** (%d)\n\n", len(names)))
		for _, n := range names {
			p, _ := creds.Get(n)
			if p != nil {
				sb.WriteString(fmt.Sprintf("- **%s** (user: %s)\n", n, p.Username))
			}
		}
		return mcp.NewToolResultText(sb.String()), nil
	}
}

func findAgentBinary() string {
	// Look relative to the MCP server binary.
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	binDir := filepath.Dir(exe)
	for _, name := range []string{"LabLinkAgent.exe", "lablink-agent-windows-amd64.exe"} {
		candidate := filepath.Join(binDir, name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

func findDeployScript() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	// bin/ is one level below project root, scripts/ is at the same level.
	projectDir := filepath.Dir(filepath.Dir(exe))
	return filepath.Join(projectDir, "scripts", "deploy-agent.ps1")
}

func escapePSString(s string) string {
	// Escape single quotes for PowerShell single-quoted strings.
	return strings.ReplaceAll(s, "'", "''")
}
