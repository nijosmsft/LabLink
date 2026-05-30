package mcptools

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/registry"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

func RegisterSchedule(s *server.MCPServer, reg *registry.Registry, pool *agentclient.Pool, auditLog *audit.Log) {
	addTool(s, 
		mcp.NewTool("schedule_command",
			mcp.WithDescription("Schedule a command to run after a delay on a remote node. The command runs detached. Useful for synchronized starts across multiple nodes (schedule all to start at the same wall-clock time)."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("command", mcp.Required(), mcp.Description("Command to execute")),
			mcp.WithNumber("delay_seconds", mcp.Required(), mcp.Description("Seconds to wait before executing")),
			mcp.WithString("shell", mcp.Description("Shell: powershell, cmd, bash")),
		),
		scheduleCommandHandler(reg, pool, auditLog),
	)
}

func scheduleCommandHandler(reg *registry.Registry, pool *agentclient.Pool, auditLog *audit.Log) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		command := request.GetString("command", "")
		delaySec := request.GetInt("delay_seconds", 0)
		shell := request.GetString("shell", "")

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect: %v", err)), nil
		}

		if shell == "" {
			shell = defaultScheduleShell(node)
		}

		normalizedShell, wrappedCmd, err := buildScheduledCommand(shell, delaySec, command)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid shell %q: %v", shell, err)), nil
		}

		workingDir := ""
		if nctx, ok := reg.GetNodeContext(nodeName); ok && nctx.WorkingDir != "" {
			workingDir = nctx.WorkingDir
		}

		callCtx, callCancel := nodeCallContext(ctx, nodeName)
		defer callCancel()

		stream, err := client.Execute(callCtx, &pb.ExecuteRequest{
			Command:        wrappedCmd,
			Shell:          normalizedShell,
			WorkingDir:     workingDir,
			Env:            nodeContextEnv(reg, nodeName),
			TimeoutSeconds: 10,
			Detach:         true,
		})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("schedule failed: %v", err)), nil
		}
		output, exitCode, pid, jobID, err := collectStreamOutput(stream)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("schedule stream failed: %v", err)), nil
		}

		auditLog.Append(audit.Entry{
			Timestamp: timeNow(),
			Node:      nodeName,
			Tool:      "schedule_command",
			Command:   fmt.Sprintf("[delay %ds] %s", delaySec, command),
			ExitCode:  exitCode,
		})

		result := fmt.Sprintf("Scheduled on **%s** with **%s** (PID %d): will run in %d seconds\n```\n%s\n```",
			nodeName, normalizedShell, pid, delaySec, command)
		if jobID != "" {
			result += fmt.Sprintf("\n\n**Job ID**: `%s` — use `get_job_status` / `get_job_output` / `cancel_job` to manage.", jobID)
		}
		if strings.TrimSpace(output) != "" {
			result += fmt.Sprintf("\n```\n%s```", strings.TrimSpace(output))
		}
		return mcp.NewToolResultText(result), nil
	}
}

func defaultScheduleShell(node *registry.Node) string {
	if strings.EqualFold(node.OS, "windows") {
		return "powershell"
	}
	return "bash"
}

func buildScheduledCommand(shell string, delaySec int, command string) (string, string, error) {
	switch strings.ToLower(shell) {
	case "powershell", "pwsh":
		return "powershell", fmt.Sprintf("Start-Sleep -Seconds %d; %s", delaySec, command), nil
	case "cmd":
		return "cmd", fmt.Sprintf("timeout /t %d /nobreak >NUL & %s", delaySec, command), nil
	case "bash":
		return "bash", fmt.Sprintf("sleep %d; %s", delaySec, command), nil
	default:
		return "", "", fmt.Errorf("unsupported shell")
	}
}
