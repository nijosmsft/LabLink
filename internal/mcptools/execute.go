package mcptools

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/registry"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

const defaultOutputLimit = 100 * 1024 // 100KB

func outputLimit() int {
	if v := os.Getenv("LABLINK_OUTPUT_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	if v := os.Getenv("DEVICE_INTERACTION_OUTPUT_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultOutputLimit
}

func RegisterExecute(s *server.MCPServer, reg *registry.Registry, pool *agentclient.Pool, auditLog *audit.Log, leaseCfg LeaseGateConfig) {
	s.AddTool(
		mcp.NewTool("execute_command",
			mcp.WithDescription("Execute a shell command on a remote node."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("command", mcp.Required(), mcp.Description("Command to execute")),
			mcp.WithString("shell", mcp.Description("Shell: powershell/cmd/bash; auto-detect")),
			mcp.WithString("working_dir", mcp.Description("Working directory")),
			mcp.WithNumber("timeout", mcp.Description("Timeout seconds; 0 = none")),
			mcp.WithBoolean("detach", mcp.Description("Start detached (survives agent restart)")),
		),
		LeaseGate(leaseCfg, extractSingleNode("node"), executeCommandHandler(reg, pool, auditLog)),
	)

	s.AddTool(
		mcp.NewTool("execute_script",
			mcp.WithDescription("Execute an inline script on a remote node."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("script_body", mcp.Required(), mcp.Description("Inline script content")),
			mcp.WithString("shell", mcp.Description("Shell: powershell/bash; auto-detect")),
			mcp.WithString("working_dir", mcp.Description("Working directory")),
			mcp.WithNumber("timeout", mcp.Description("Timeout seconds; 0 = none")),
		),
		LeaseGate(leaseCfg, extractSingleNode("node"), executeScriptHandler(reg, pool, auditLog)),
	)
}

func executeCommandHandler(reg *registry.Registry, pool *agentclient.Pool, auditLog *audit.Log) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		command := request.GetString("command", "")

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		shell := request.GetString("shell", "")
		workingDir := request.GetString("working_dir", "")
		timeout := request.GetFloat("timeout", 0)
		detach := request.GetBool("detach", false)

		// Apply node context defaults.
		if nctx, ok := reg.GetNodeContext(nodeName); ok {
			if workingDir == "" && nctx.WorkingDir != "" {
				workingDir = nctx.WorkingDir
			}
		}

		ctx, op := beginOp(ctx, "execute_command", nodeName, command, map[string]string{
			"shell":       shell,
			"timeout":     fmt.Sprintf("%g", timeout),
			"detach":      fmt.Sprintf("%t", detach),
			"working_dir": workingDir,
		})
		var opErr error
		defer func() { op.Done(opErr) }()

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("connect to %s: %v", node.Address, err)), nil
		}

		env := nodeContextEnv(reg, nodeName)

		// Use health-aware context: cancelled if node dies.
		callCtx, callCancel := nodeCallContext(ctx, nodeName)
		defer callCancel()

		start := time.Now()
		stopHB := StartMCPHeartbeat(ctx, request, defaultHeartbeatInterval, func() (int64, int64) {
			return int64(time.Since(start).Seconds()), int64(timeout)
		})
		defer stopHB()
		stream, err := client.Execute(callCtx, &pb.ExecuteRequest{
			Command:        command,
			Shell:          shell,
			WorkingDir:     workingDir,
			Env:            env,
			TimeoutSeconds: int32(timeout),
			Detach:         detach,
		})
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("execute: %v", err)), nil
		}

		output, exitCode, pid, jobID, err := collectStreamOutput(stream)
		duration := time.Since(start)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("stream: %v", err)), nil
		}

		outputBytes := len(output)
		truncated, output, spillPath := truncateOutput(output)

		auditLog.Append(audit.Entry{
			Timestamp:   start,
			Node:        nodeName,
			Tool:        "execute_command",
			Command:     command,
			Shell:       shell,
			ExitCode:    exitCode,
			DurationMs:  duration.Milliseconds(),
			OutputBytes: outputBytes,
			Truncated:   truncated,
		})

		result := formatExecResult(nodeName, command, pid, exitCode, jobID, output, truncated, spillPath, duration)
		return mcp.NewToolResultText(result), nil
	}
}

func executeScriptHandler(reg *registry.Registry, pool *agentclient.Pool, auditLog *audit.Log) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		scriptBody := request.GetString("script_body", "")

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		shell := request.GetString("shell", "")
		workingDir := request.GetString("working_dir", "")
		timeout := request.GetFloat("timeout", 0)

		if nctx, ok := reg.GetNodeContext(nodeName); ok {
			if workingDir == "" && nctx.WorkingDir != "" {
				workingDir = nctx.WorkingDir
			}
		}

		ctx, op := beginOp(ctx, "execute_script", nodeName, "(inline script)", map[string]string{
			"shell":       shell,
			"timeout":     fmt.Sprintf("%g", timeout),
			"working_dir": workingDir,
		})
		var opErr error
		defer func() { op.Done(opErr) }()

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("connect to %s: %v", node.Address, err)), nil
		}

		env := nodeContextEnv(reg, nodeName)

		callCtx, callCancel := nodeCallContext(ctx, nodeName)
		defer callCancel()

		start := time.Now()
		stopHB := StartMCPHeartbeat(ctx, request, defaultHeartbeatInterval, func() (int64, int64) {
			return int64(time.Since(start).Seconds()), int64(timeout)
		})
		defer stopHB()
		stream, err := client.ExecuteScript(callCtx, &pb.ExecuteScriptRequest{
			ScriptBody:     scriptBody,
			Shell:          shell,
			WorkingDir:     workingDir,
			Env:            env,
			TimeoutSeconds: int32(timeout),
		})
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("execute_script: %v", err)), nil
		}

		output, exitCode, pid, _, err := collectStreamOutput(stream)
		duration := time.Since(start)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("stream: %v", err)), nil
		}

		outputBytes := len(output)
		truncated, output, spillPath := truncateOutput(output)

		auditLog.Append(audit.Entry{
			Timestamp:   start,
			Node:        nodeName,
			Tool:        "execute_script",
			Command:     "(inline script)",
			Shell:       shell,
			ExitCode:    exitCode,
			DurationMs:  duration.Milliseconds(),
			OutputBytes: outputBytes,
			Truncated:   truncated,
		})

		result := formatExecResult(nodeName, "(inline script)", pid, exitCode, "", output, truncated, spillPath, duration)
		return mcp.NewToolResultText(result), nil
	}
}

func nodeContextEnv(reg *registry.Registry, nodeName string) map[string]string {
	nctx, ok := reg.GetNodeContext(nodeName)
	if !ok || len(nctx.Env) == 0 {
		return nil
	}
	env := make(map[string]string, len(nctx.Env))
	for k, v := range nctx.Env {
		env[k] = v
	}
	return env
}

type executeStream interface {
	Recv() (*pb.ExecuteResponse, error)
}

func collectStreamOutput(stream executeStream) (string, int, int, string, error) {
	var buf strings.Builder
	var exitCode, pid int
	var jobID string

	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return buf.String(), exitCode, pid, jobID, err
		}
		if resp.Pid != 0 && pid == 0 {
			pid = int(resp.Pid)
		}
		if resp.JobId != "" && jobID == "" {
			jobID = resp.JobId
		}
		if len(resp.Data) > 0 {
			buf.Write(resp.Data)
		}
		if resp.Done {
			exitCode = int(resp.ExitCode)
			break
		}
	}
	return buf.String(), exitCode, pid, jobID, nil
}

func truncateOutput(output string) (bool, string, string) {
	limit := outputLimit()
	if len(output) <= limit {
		return false, output, ""
	}

	truncated := output[:limit]
	tmpFile, err := writeTruncatedOutputSpill(output)
	if err != nil {
		truncated += fmt.Sprintf("\n\n... OUTPUT TRUNCATED (total %d bytes). Full output could not be saved: %v", len(output), err)
		return true, truncated, ""
	}
	truncated += fmt.Sprintf("\n\n... OUTPUT TRUNCATED (total %d bytes). Full output saved to: %s", len(output), tmpFile)
	return true, truncated, tmpFile
}

func formatExecResult(node, command string, pid, exitCode int, jobID, output string, truncated bool, spillPath string, duration time.Duration) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("**Node**: %s | **PID**: %d | **Exit**: %d | **Duration**: %s\n", node, pid, exitCode, duration.Round(time.Millisecond)))
	if jobID != "" {
		sb.WriteString(fmt.Sprintf("**Job ID**: `%s` — use `get_job_status` / `get_job_output` / `cancel_job` to manage.\n", jobID))
	}
	if truncated && spillPath != "" {
		sb.WriteString(fmt.Sprintf("**Output truncated** — full output at: `%s`\n", spillPath))
	}
	sb.WriteString("\n```\n")
	sb.WriteString(strings.TrimRight(output, "\n"))
	sb.WriteString("\n```\n")
	return sb.String()
}

func writeTruncatedOutputSpill(output string) (string, error) {
	tmpDir := os.TempDir()
	tmpFile := filepath.Join(tmpDir, fmt.Sprintf("lablink-output-%d.txt", time.Now().UnixNano()))
	if err := os.WriteFile(tmpFile, []byte(output), 0644); err != nil {
		return "", err
	}
	return tmpFile, nil
}
