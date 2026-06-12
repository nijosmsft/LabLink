package mcptools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

func RegisterInventory(s *server.MCPServer, reg *registry.Registry, pool *agentclient.Pool) {
	addTool(s, 
		mcp.NewTool("register_node",
			mcp.WithDescription("Register a machine in the node inventory by probing its agent."),
			mcp.WithString("name", mcp.Required(), mcp.Description("Friendly node name")),
			mcp.WithString("address", mcp.Required(), mcp.Description("Agent address as host:port")),
			mcp.WithString("role", mcp.Description("Node role: server, client, or custom")),
			mcp.WithString("transport_mode", mcp.Description("Transport mode: mtls or insecure, default mtls")),
			mcp.WithString("tls_server_name", mcp.Description("Certificate name to verify when using mTLS")),
		),
		registerNodeHandler(reg, pool),
	)

	addTool(s, 
		mcp.NewTool("list_nodes",
			mcp.WithDescription("List all registered nodes with status."),
		),
		listNodesHandler(reg, pool),
	)

	addTool(s, 
		mcp.NewTool("remove_node",
			mcp.WithDescription("Remove a node from the registry."),
			mcp.WithString("name", mcp.Required(), mcp.Description("Node name to remove")),
		),
		removeNodeHandler(reg),
	)

	addTool(s, 
		mcp.NewTool("rename_node",
			mcp.WithDescription("Rename a node in the registry."),
			mcp.WithString("old_name", mcp.Required(), mcp.Description("Current node name")),
			mcp.WithString("new_name", mcp.Required(), mcp.Description("New node name")),
		),
		renameNodeHandler(reg),
	)
}

func registerNodeHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name := request.GetString("name", "")
		address := request.GetString("address", "")
		role := request.GetString("role", "")
		transportMode := request.GetString("transport_mode", string(security.TransportModeMTLS))
		tlsServerName := request.GetString("tls_server_name", "")

		client, err := pool.GetClient(address, tlsServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect to %s: %v", address, err)), nil
		}

		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		info, err := client.GetInfo(probeCtx, &pb.GetInfoRequest{})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("probe agent at %s: %v", address, err)), nil
		}

		node := &registry.Node{
			Name:          name,
			Address:       address,
			Role:          role,
			OS:            info.Os,
			Arch:          info.Arch,
			CPUCount:      int(info.CpuCount),
			Memory:        info.MemoryBytes,
			LastSeen:      time.Now(),
			TransportMode: transportMode,
			TLSServerName: tlsServerName,
		}

		if err := reg.SetNode(node); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("save: %v", err)), nil
		}

		result := fmt.Sprintf("Registered **%s** at %s\n- OS: %s/%s\n- CPUs: %d\n- Memory: %s\n- Agent: %s\n- Role: %s\n- Transport: %s",
			name, address, info.Os, info.Arch, info.CpuCount,
			formatBytes(info.MemoryBytes), info.AgentVersion, role, transportMode)
		if tlsServerName != "" {
			result += fmt.Sprintf("\n- TLS name: %s", tlsServerName)
		}
		return mcp.NewToolResultText(result), nil
	}
}

func listNodesHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodes := reg.AllNodes()
		if len(nodes) == 0 {
			return mcp.NewToolResultText("No nodes registered. Use `register_node` to add one."), nil
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("**Registered nodes** (%d)\n\n", len(nodes)))
		sb.WriteString("| Name | Address | Transport | TLS Name | OS | Role | CPUs | Memory | Status |\n")
		sb.WriteString("|------|---------|-----------|----------|----|----- |------|--------|--------|\n")

		for _, n := range nodes {
			status := "offline"
			client, err := pool.GetClient(n.Address, n.TLSServerName)
			if err == nil {
				probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				if _, err := client.GetInfo(probeCtx, &pb.GetInfoRequest{}); err == nil {
					status = "online"
				}
				cancel()
			}

			transportMode := n.TransportMode
			if transportMode == "" {
				transportMode = string(security.TransportModeMTLS)
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s/%s | %s | %d | %s | %s |\n",
				n.Name, n.Address, transportMode, n.TLSServerName, n.OS, n.Arch, n.Role, n.CPUCount, formatBytes(n.Memory), status))
		}
		return mcp.NewToolResultText(sb.String()), nil
	}
}

func renameNodeHandler(reg *registry.Registry) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		oldName := request.GetString("old_name", "")
		newName := request.GetString("new_name", "")

		if _, ok := reg.GetNode(newName); ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q already exists", newName)), nil
		}

		if err := reg.RenameNode(oldName, newName); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("rename: %v", err)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("Renamed **%s** → **%s**", oldName, newName)), nil
	}
}

func removeNodeHandler(reg *registry.Registry) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name := request.GetString("name", "")
		if _, ok := reg.GetNode(name); !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", name)), nil
		}
		if err := reg.RemoveNode(name); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("remove: %v", err)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Removed node **%s**", name)), nil
	}
}
