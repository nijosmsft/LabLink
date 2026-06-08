package mcptools

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/registry"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

func RegisterMultiNode(s *server.MCPServer, reg *registry.Registry, pool *agentclient.Pool, auditLog *audit.Log, leaseCfg LeaseGateConfig) {
	addTool(s,
		mcp.NewTool("run_script_on_role",
			mcp.WithDescription("Execute the same inline script on all nodes with a given role, in parallel. Optionally scope to a topology."),
			mcp.WithString("role", mcp.Required(), mcp.Description("Node role to target (e.g., client)")),
			mcp.WithString("script_body", mcp.Required(), mcp.Description("Inline script content")),
			mcp.WithString("topology", mcp.Description("Topology name to scope the role to")),
			mcp.WithString("shell", mcp.Description("Shell: powershell, bash")),
			mcp.WithNumber("timeout", mcp.Description("Timeout in seconds per node")),
		),
		LeaseGate(leaseCfg, extractRoleNodes, runScriptOnRoleHandler(reg, pool, auditLog)),
	)

	addTool(s,
		mcp.NewTool("execute_on_role",
			mcp.WithDescription("Execute the same command on all nodes with a given role, in parallel. Optionally scope to a topology."),
			mcp.WithString("role", mcp.Required(), mcp.Description("Node role to target (e.g., client)")),
			mcp.WithString("command", mcp.Required(), mcp.Description("Command to execute")),
			mcp.WithString("topology", mcp.Description("Topology name to scope the role to")),
			mcp.WithString("shell", mcp.Description("Shell: powershell, cmd, bash")),
			mcp.WithNumber("timeout", mcp.Description("Timeout in seconds per node")),
		),
		LeaseGate(leaseCfg, extractRoleNodes, executeOnRoleHandler(reg, pool, auditLog)),
	)
}

type nodeResult struct {
	NodeName string
	Output   string
	ExitCode int
	Pid      int
	Duration time.Duration
	Err      error
}

func executeOnRoleHandler(reg *registry.Registry, pool *agentclient.Pool, auditLog *audit.Log) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		role := request.GetString("role", "")
		command := request.GetString("command", "")
		topology := request.GetString("topology", "")
		shell := request.GetString("shell", "")
		timeout := request.GetFloat("timeout", 0)

		var nodes []*registry.Node
		if topology != "" {
			nodes = reg.NodesForTopologyRole(topology, role)
		} else {
			nodes = reg.NodesByRole(role)
		}

		if len(nodes) == 0 {
			msg := fmt.Sprintf("No nodes found with role %q", role)
			if topology != "" {
				msg += fmt.Sprintf(" in topology %q", topology)
			}
			return mcp.NewToolResultError(msg), nil
		}

		results := make([]nodeResult, len(nodes))
		var wg sync.WaitGroup
		for i, node := range nodes {
			wg.Add(1)
			go func(idx int, n *registry.Node) {
				defer wg.Done()
				results[idx] = executeOnNode(ctx, n, command, shell, timeout, reg, pool)
			}(i, node)
		}
		wg.Wait()

		for _, r := range results {
			auditLog.Append(audit.Entry{
				Timestamp:   time.Now(),
				Node:        r.NodeName,
				Tool:        "execute_on_role",
				Command:     command,
				Shell:       shell,
				ExitCode:    r.ExitCode,
				DurationMs:  r.Duration.Milliseconds(),
				OutputBytes: len(r.Output),
			})
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("**execute_on_role** role=%s, %d nodes\n\n", role, len(nodes)))
		for _, r := range results {
			sb.WriteString(fmt.Sprintf("### %s (exit=%d, %s)\n", r.NodeName, r.ExitCode, r.Duration.Round(time.Millisecond)))
			if r.Err != nil {
				sb.WriteString(fmt.Sprintf("**Error**: %v\n", r.Err))
			} else {
				truncated, output, spillPath := truncateOutput(r.Output)
				if truncated {
					sb.WriteString(fmt.Sprintf("*Output truncated — full at: `%s`*\n", spillPath))
				}
				sb.WriteString("```\n")
				sb.WriteString(strings.TrimRight(output, "\n"))
				sb.WriteString("\n```\n\n")
			}
		}
		return mcp.NewToolResultText(sb.String()), nil
	}
}

func runScriptOnRoleHandler(reg *registry.Registry, pool *agentclient.Pool, auditLog *audit.Log) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		role := request.GetString("role", "")
		scriptBody := request.GetString("script_body", "")
		topology := request.GetString("topology", "")
		shell := request.GetString("shell", "")
		timeout := request.GetFloat("timeout", 0)

		var nodes []*registry.Node
		if topology != "" {
			nodes = reg.NodesForTopologyRole(topology, role)
		} else {
			nodes = reg.NodesByRole(role)
		}

		if len(nodes) == 0 {
			msg := fmt.Sprintf("No nodes found with role %q", role)
			if topology != "" {
				msg += fmt.Sprintf(" in topology %q", topology)
			}
			return mcp.NewToolResultError(msg), nil
		}

		results := make([]nodeResult, len(nodes))
		var wg sync.WaitGroup
		for i, node := range nodes {
			wg.Add(1)
			go func(idx int, n *registry.Node) {
				defer wg.Done()
				results[idx] = executeScriptOnNode(ctx, n, scriptBody, shell, timeout, reg, pool)
			}(i, node)
		}
		wg.Wait()

		for _, r := range results {
			auditLog.Append(audit.Entry{
				Timestamp:   time.Now(),
				Node:        r.NodeName,
				Tool:        "run_script_on_role",
				Command:     "(inline script)",
				Shell:       shell,
				ExitCode:    r.ExitCode,
				DurationMs:  r.Duration.Milliseconds(),
				OutputBytes: len(r.Output),
			})
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("**run_script_on_role** role=%s, %d nodes\n\n", role, len(nodes)))
		for _, r := range results {
			sb.WriteString(fmt.Sprintf("### %s (exit=%d, %s)\n", r.NodeName, r.ExitCode, r.Duration.Round(time.Millisecond)))
			if r.Err != nil {
				sb.WriteString(fmt.Sprintf("**Error**: %v\n", r.Err))
			} else {
				truncated, output, spillPath := truncateOutput(r.Output)
				if truncated {
					sb.WriteString(fmt.Sprintf("*Output truncated — full at: `%s`*\n", spillPath))
				}
				sb.WriteString("```\n")
				sb.WriteString(strings.TrimRight(output, "\n"))
				sb.WriteString("\n```\n\n")
			}
		}
		return mcp.NewToolResultText(sb.String()), nil
	}
}

func executeScriptOnNode(ctx context.Context, node *registry.Node, scriptBody, shell string, timeout float64, reg *registry.Registry, pool *agentclient.Pool) nodeResult {
	result := nodeResult{NodeName: node.Name}

	client, err := pool.GetClient(node.Address, node.TLSServerName)
	if err != nil {
		result.Err = err
		return result
	}

	workingDir := ""
	var env map[string]string
	if nctx, ok := reg.GetNodeContext(node.Name); ok {
		workingDir = nctx.WorkingDir
		env = nctx.Env
	}

	callCtx, callCancel := nodeCallContext(ctx, node.Name)
	defer callCancel()

	start := time.Now()
	stream, err := client.ExecuteScript(callCtx, &pb.ExecuteScriptRequest{
		ScriptBody:     scriptBody,
		Shell:          shell,
		WorkingDir:     workingDir,
		Env:            env,
		TimeoutSeconds: int32(timeout),
	})
	if err != nil {
		result.Err = err
		result.Duration = time.Since(start)
		return result
	}

	output, exitCode, pid, _, err := collectStreamOutput(stream)
	result.Duration = time.Since(start)
	result.Output = output
	result.ExitCode = exitCode
	result.Pid = pid
	result.Err = err
	return result
}

func executeOnNode(ctx context.Context, node *registry.Node, command, shell string, timeout float64, reg *registry.Registry, pool *agentclient.Pool) nodeResult {
	result := nodeResult{NodeName: node.Name}

	client, err := pool.GetClient(node.Address, node.TLSServerName)
	if err != nil {
		result.Err = err
		return result
	}

	workingDir := ""
	var env map[string]string
	if nctx, ok := reg.GetNodeContext(node.Name); ok {
		workingDir = nctx.WorkingDir
		env = nctx.Env
	}

	callCtx, callCancel := nodeCallContext(ctx, node.Name)
	defer callCancel()

	start := time.Now()
	stream, err := client.Execute(callCtx, &pb.ExecuteRequest{
		Command:        command,
		Shell:          shell,
		WorkingDir:     workingDir,
		Env:            env,
		TimeoutSeconds: int32(timeout),
	})
	if err != nil {
		result.Err = err
		result.Duration = time.Since(start)
		return result
	}

	output, exitCode, pid, _, err := collectStreamOutput(stream)
	result.Duration = time.Since(start)
	result.Output = output
	result.ExitCode = exitCode
	result.Pid = pid
	result.Err = err
	return result
}
