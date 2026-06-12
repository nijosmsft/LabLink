package mcptools

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/registry"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

func RegisterProcess(s *server.MCPServer, reg *registry.Registry, pool *agentclient.Pool, leaseCfg LeaseGateConfig) {
	addTool(s,
		mcp.NewTool("list_processes",
			mcp.WithDescription("List running processes on a remote node."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("filter", mcp.Description("Process name filter")),
		),
		listProcessesHandler(reg, pool),
	)

	addTool(s,
		mcp.NewTool("kill_process",
			mcp.WithDescription("Kill a process on a remote node."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithNumber("pid", mcp.Required(), mcp.Description("Process ID")),
			mcp.WithBoolean("force", mcp.Description("Force kill (SIGKILL)")),
		),
		LeaseGate(leaseCfg, extractSingleNode("node"), killProcessHandler(reg, pool)),
	)
}

func listProcessesHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		filter := request.GetString("filter", "")

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect to %s: %v", node.Address, err)), nil
		}

		resp, err := client.ListProcesses(ctx, &pb.ListProcessesRequest{NameFilter: filter})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("list_processes: %v", err)), nil
		}

		if len(resp.Processes) == 0 {
			return mcp.NewToolResultText(fmt.Sprintf("No processes found on **%s** matching %q", nodeName, filter)), nil
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("**Processes on %s** (%d results)\n\n", nodeName, len(resp.Processes)))
		sb.WriteString("| PID | Name | Memory | CPU% | Command Line |\n")
		sb.WriteString("|-----|------|--------|------|--------------|\n")
		for _, p := range resp.Processes {
			cmdLine := p.CommandLine
			if len(cmdLine) > 80 {
				cmdLine = cmdLine[:77] + "..."
			}
			sb.WriteString(fmt.Sprintf("| %d | %s | %s | %.1f | %s |\n",
				p.Pid, p.Name, formatBytes(p.MemoryBytes), p.CpuPercent, cmdLine))
		}
		return mcp.NewToolResultText(sb.String()), nil
	}
}

func killProcessHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		pid := request.GetFloat("pid", 0)
		force := request.GetBool("force", false)

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect to %s: %v", node.Address, err)), nil
		}

		resp, err := client.KillProcess(ctx, &pb.KillProcessRequest{
			Pid:   int32(pid),
			Force: force,
		})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("kill_process: %v", err)), nil
		}

		if resp.Success {
			return mcp.NewToolResultText(fmt.Sprintf("Killed process %d on **%s**", int(pid), nodeName)), nil
		}
		return mcp.NewToolResultError(resp.Message), nil
	}
}
