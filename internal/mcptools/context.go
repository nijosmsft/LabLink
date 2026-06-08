package mcptools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/registry"
)

func RegisterContext(s *server.MCPServer, reg *registry.Registry, leaseCfg LeaseGateConfig) {
	addTool(s,
		mcp.NewTool("set_node_context",
			mcp.WithDescription("Set persistent working directory and environment variables for a node. These apply as defaults to all subsequent commands."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("working_dir", mcp.Description("Default working directory")),
			mcp.WithString("env", mcp.Description("JSON object of environment variables (e.g., {\"PATH\": \"/usr/bin\"})")),
		),
		LeaseGate(leaseCfg, extractSingleNode("node"), setNodeContextHandler(reg)),
	)
}

func setNodeContextHandler(reg *registry.Registry) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")

		if _, ok := reg.GetNode(nodeName); !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		workingDir := request.GetString("working_dir", "")
		envJSON := request.GetString("env", "")

		var env map[string]string
		if envJSON != "" {
			if err := json.Unmarshal([]byte(envJSON), &env); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("invalid env JSON: %v", err)), nil
			}
		}

		nctx := &registry.NodeContext{
			WorkingDir: workingDir,
			Env:        env,
		}
		if err := reg.SetNodeContext(nodeName, nctx); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("save: %v", err)), nil
		}

		result := fmt.Sprintf("Set context for **%s**:\n", nodeName)
		if workingDir != "" {
			result += fmt.Sprintf("- Working dir: `%s`\n", workingDir)
		}
		if len(env) > 0 {
			result += fmt.Sprintf("- Env vars: %d keys\n", len(env))
		}
		return mcp.NewToolResultText(result), nil
	}
}
