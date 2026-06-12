package mcptools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/registry"
)

func RegisterTopology(s *server.MCPServer, reg *registry.Registry) {
	addTool(s, 
		mcp.NewTool("register_topology",
			mcp.WithDescription("Define a named group of nodes with role assignments."),
			mcp.WithString("name", mcp.Required(), mcp.Description("Topology name")),
			mcp.WithString("roles", mcp.Required(), mcp.Description("JSON map of role names to node name arrays")),
		),
		registerTopologyHandler(reg),
	)
}

func registerTopologyHandler(reg *registry.Registry) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name := request.GetString("name", "")
		rolesJSON := request.GetString("roles", "")

		var roles map[string][]string
		if err := json.Unmarshal([]byte(rolesJSON), &roles); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid roles JSON: %v", err)), nil
		}

		if err := validateTopologyRoles(reg, roles); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		t := &registry.Topology{
			Name:  name,
			Roles: roles,
		}
		if err := reg.SetTopology(t); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("save: %v", err)), nil
		}

		result := fmt.Sprintf("Registered topology **%s**:\n", name)
		for role, nodes := range roles {
			result += fmt.Sprintf("- **%s**: %v\n", role, nodes)
		}
		return mcp.NewToolResultText(result), nil
	}
}

func validateTopologyRoles(reg *registry.Registry, roles map[string][]string) error {
	for role, nodeNames := range roles {
		for _, nodeName := range nodeNames {
			if _, ok := reg.GetNode(nodeName); !ok {
				return fmt.Errorf("node %q (role %q) not found in registry", nodeName, role)
			}
		}
	}
	return nil
}
