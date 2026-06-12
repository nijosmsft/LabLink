package mcptools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/registry"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

func RegisterDiagnostics(s *server.MCPServer, reg *registry.Registry, pool *agentclient.Pool, auditLog *audit.Log, leaseCfg LeaseGateConfig) {
	addTool(s,
		mcp.NewTool("collect_etw_trace",
			mcp.WithDescription("Collect an ETW/WPR trace on a remote node. Starts WPR, waits for the specified duration, stops, and pulls the .etl file back to the local machine."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("profile", mcp.Required(), mcp.Description("WPR profile name or path to .wprp file on the node")),
			mcp.WithNumber("duration", mcp.Required(), mcp.Description("Trace duration in seconds")),
			mcp.WithString("local_output", mcp.Required(), mcp.Description("Local path to save the .etl file")),
		),
		LeaseGate(leaseCfg, extractSingleNode("node"), collectEtwTraceHandler(reg, pool, auditLog)),
	)

	addTool(s,
		mcp.NewTool("get_crash_dumps",
			mcp.WithDescription("List and optionally pull crash dumps from a remote node (C:\\Windows\\Minidump and C:\\Windows\\MEMORY.DMP)."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("local_dir", mcp.Description("If specified, pull all dumps to this local directory")),
		),
		LeaseGate(leaseCfg, extractSingleNode("node"), getCrashDumpsHandler(reg, pool)),
	)

	addTool(s,
		mcp.NewTool("sync_time",
			mcp.WithDescription("Synchronize system clocks across all nodes or a specific topology by forcing a time resync (w32tm /resync)."),
			mcp.WithString("topology", mcp.Description("Topology name (if omitted, syncs all nodes)")),
		),
		LeaseGate(leaseCfg, extractSyncTimeNodes, syncTimeHandler(reg, pool)),
	)

	addTool(s,
		mcp.NewTool("enable_kd",
			mcp.WithDescription("Enable kernel debugging on a remote VM. Configures bcdedit for network KD (kdnet). Requires a reboot to take effect."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("host_ip", mcp.Required(), mcp.Description("Debugger host IP (the machine running WinDbg)")),
			mcp.WithNumber("port", mcp.Description("KD network port (default 50000). Each VM needs a unique port.")),
			mcp.WithString("key", mcp.Description("Encryption key (auto-generated if omitted). Format: w.x.y.z")),
			mcp.WithBoolean("reboot", mcp.Description("Reboot after enabling (default false)")),
		),
		LeaseGate(leaseCfg, extractSingleNode("node"), enableKdHandler(reg, pool)),
	)

	addTool(s,
		mcp.NewTool("disable_kd",
			mcp.WithDescription("Disable kernel debugging on a remote VM. Requires a reboot to take effect."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithBoolean("reboot", mcp.Description("Reboot after disabling (default false)")),
		),
		LeaseGate(leaseCfg, extractSingleNode("node"), disableKdHandler(reg, pool)),
	)

	addTool(s,
		mcp.NewTool("get_kd_status",
			mcp.WithDescription("Check kernel debugging status and settings on a remote VM."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
		),
		getKdStatusHandler(reg, pool),
	)
}

func collectEtwTraceHandler(reg *registry.Registry, pool *agentclient.Pool, auditLog *audit.Log) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		profile := request.GetString("profile", "")
		duration := request.GetInt("duration", 10)
		localOutput := request.GetString("local_output", "")

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect: %v", err)), nil
		}

		var sb strings.Builder
		remoteEtl := `C:\LabLink\trace.etl`

		// Start WPR.
		startCmd := fmt.Sprintf(`wpr -start '%s' -filemode`, profile)
		output, exitCode, _, err := executeAndCollect(ctx, client, startCmd, "powershell", "", nil, 30)
		if err != nil || exitCode != 0 {
			return mcp.NewToolResultError(fmt.Sprintf("WPR start failed (exit %d):\n%s\nerr: %v", exitCode, output, err)), nil
		}
		sb.WriteString("WPR started\n")

		// Wait for the specified duration; emit heartbeat during capture.
		captureStart := time.Now()
		stopHB := StartMCPHeartbeat(ctx, request, defaultHeartbeatInterval, func() (int64, int64) {
			return int64(time.Since(captureStart).Seconds()), int64(duration)
		})
		waitCmd := fmt.Sprintf(`Start-Sleep %d; 'Wait done'`, duration)
		output, _, _, _ = executeAndCollect(ctx, client, waitCmd, "powershell", "", nil, int32(duration+30))
		stopHB()
		sb.WriteString(fmt.Sprintf("Traced for %d seconds\n", duration))

		// Stop WPR and save.
		stopCmd := fmt.Sprintf(`wpr -stop '%s' -skipPdbGen`, remoteEtl)
		output, exitCode, _, err = executeAndCollect(ctx, client, stopCmd, "powershell", "", nil, 120)
		if err != nil || exitCode != 0 {
			return mcp.NewToolResultError(fmt.Sprintf("WPR stop failed (exit %d):\n%s\nerr: %v", exitCode, output, err)), nil
		}
		sb.WriteString("WPR stopped\n")

		pullStream, err := client.PullFile(ctx, &pb.PullFileRequest{RemotePath: remoteEtl})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("pull: %v", err)), nil
		}

		// Stage 2: wire a byte-based progress notifier so large ETL pulls emit
		// MCP heartbeats and don't hit the transport idle timeout.
		stage2Token := ProgressTokenFromRequest(request)
		var stage2Notifier progressNotifier
		if stage2Token != nil {
			stage2Notifier = heartbeatNotifierOverride
			if stage2Notifier == nil {
				stage2Notifier = buildMCPNotifier(ctx, stage2Token)
			}
		}

		totalBytes, err := pullRemoteFileToPathWithProgress(ctx, pullStream, localOutput, nopProgressReporter{}, stage2Notifier)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		sb.WriteString(fmt.Sprintf("Pulled %s (%s)\n", localOutput, formatBytes(totalBytes)))

		// Clean up remote trace.
		executeAndCollect(ctx, client, fmt.Sprintf(`Remove-Item '%s' -ErrorAction SilentlyContinue`, remoteEtl), "powershell", "", nil, 10)

		auditLog.Append(audit.Entry{
			Timestamp:   timeNow(),
			Node:        nodeName,
			Tool:        "collect_etw_trace",
			Command:     fmt.Sprintf("profile=%s duration=%ds", profile, duration),
			OutputBytes: int(totalBytes),
		})

		return mcp.NewToolResultText(fmt.Sprintf("**ETW trace collected from %s**\n\n```\n%s```\n\nSaved to: `%s`", nodeName, sb.String(), localOutput)), nil
	}
}

func getCrashDumpsHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		localDir := request.GetString("local_dir", "")

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect: %v", err)), nil
		}

		// List dumps.
		listCmd := `
$dumps = @()
Get-ChildItem 'C:\Windows\Minidump\*.dmp' -ErrorAction SilentlyContinue | ForEach-Object {
    $dumps += [PSCustomObject]@{Path=$_.FullName; Size=$_.Length; Date=$_.LastWriteTime}
}
if (Test-Path 'C:\Windows\MEMORY.DMP') {
    $f = Get-Item 'C:\Windows\MEMORY.DMP'
    $dumps += [PSCustomObject]@{Path=$f.FullName; Size=$f.Length; Date=$f.LastWriteTime}
}
if ($dumps.Count -eq 0) {
    'NO_DUMPS'
} else {
    $dumps | ForEach-Object { "$($_.Path)|$($_.Size)|$($_.Date)" }
}
`
		output, _, _, err := executeAndCollect(ctx, client, listCmd, "powershell", "", nil, 15)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("list failed: %v", err)), nil
		}

		output = strings.TrimSpace(output)
		if output == "NO_DUMPS" {
			return mcp.NewToolResultText(fmt.Sprintf("No crash dumps found on **%s**", nodeName)), nil
		}

		lines := strings.Split(output, "\n")
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("**Crash dumps on %s** (%d found)\n\n", nodeName, len(lines)))
		sb.WriteString("| File | Size | Date |\n")
		sb.WriteString("|------|------|------|\n")

		var dumpPaths []string
		for _, line := range lines {
			parts := strings.SplitN(strings.TrimSpace(line), "|", 3)
			if len(parts) == 3 {
				sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", filepath.Base(parts[0]), parts[1], parts[2]))
				dumpPaths = append(dumpPaths, parts[0])
			}
		}

		// Pull dumps if local_dir specified.
		if localDir != "" && len(dumpPaths) > 0 {
			if err := os.MkdirAll(localDir, 0755); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("mkdir %s: %v", localDir, err)), nil
			}
			sb.WriteString(fmt.Sprintf("\nPulling to `%s`:\n", localDir))
			for _, remotePath := range dumpPaths {
				localPath := filepath.Join(localDir, fmt.Sprintf("%s_%s", nodeName, filepath.Base(remotePath)))
				pullStream, err := client.PullFile(ctx, &pb.PullFileRequest{RemotePath: remotePath})
				if err != nil {
					sb.WriteString(fmt.Sprintf("- %s: pull error: %v\n", filepath.Base(remotePath), err))
					continue
				}

				bytes, err := pullRemoteFileToPath(pullStream, localPath)
				if err != nil {
					sb.WriteString(fmt.Sprintf("- %s: pull error: %v\n", filepath.Base(remotePath), err))
					continue
				}
				sb.WriteString(fmt.Sprintf("- %s → %s (%s)\n", filepath.Base(remotePath), localPath, formatBytes(bytes)))
			}
		}

		return mcp.NewToolResultText(sb.String()), nil
	}
}

func syncTimeHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		topology := request.GetString("topology", "")

		var nodes []*registry.Node
		if topology != "" {
			// Sync all roles in the topology.
			for _, name := range reg.AllTopologyNames() {
				if name == topology {
					if t, ok := reg.GetTopology(name); ok {
						for _, nodeNames := range t.Roles {
							for _, nn := range nodeNames {
								if n, ok := reg.GetNode(nn); ok {
									nodes = append(nodes, n)
								}
							}
						}
					}
				}
			}
		} else {
			nodes = reg.AllNodes()
		}

		if len(nodes) == 0 {
			return mcp.NewToolResultError("no nodes to sync"), nil
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("**Time sync** (%d nodes)\n\n", len(nodes)))

		for _, n := range nodes {
			client, err := pool.GetClient(n.Address, n.TLSServerName)
			if err != nil {
				sb.WriteString(fmt.Sprintf("- **%s**: connect error\n", n.Name))
				continue
			}
			output, _, _, _ := executeAndCollect(ctx, client, `w32tm /resync /force 2>&1; Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'`, "powershell", "", nil, 15)
			lines := strings.Split(strings.TrimSpace(output), "\n")
			lastLine := lines[len(lines)-1]
			sb.WriteString(fmt.Sprintf("- **%s**: %s\n", n.Name, strings.TrimSpace(lastLine)))
		}

		return mcp.NewToolResultText(sb.String()), nil
	}
}

func enableKdHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		hostIP := request.GetString("host_ip", "")
		port := request.GetInt("port", 50000)
		key := request.GetString("key", "")
		reboot := request.GetBool("reboot", false)

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect: %v", err)), nil
		}

		var cmd string
		keyArg := ""
		if key != "" {
			keyArg = fmt.Sprintf(" key:%s", key)
		}
		cmd = fmt.Sprintf(`
bcdedit /debug on
bcdedit /dbgsettings net hostip:%s port:%d%s
bcdedit /set "{dbgsettings}" busparams 0.0.0
bcdedit /set testsigning on
bcdedit /set hypervisorlaunchtype off
bcdedit /set "{default}" device_integrity_state disable 2>$null
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Value 0 -Type DWord -ErrorAction SilentlyContinue
'KD + test signing + device integrity disabled'
bcdedit /dbgsettings
`, hostIP, port, keyArg)

		output, exitCode, _, err := executeAndCollect(ctx, client, cmd, "powershell", "", nil, 15)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("enable KD failed: %v", err)), nil
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("**KD enabled on %s**\n", nodeName))
		sb.WriteString(fmt.Sprintf("- Host: %s\n- Port: %d\n", hostIP, port))
		sb.WriteString(fmt.Sprintf("\n```\n%s```\n", strings.TrimSpace(output)))

		if exitCode != 0 {
			sb.WriteString("\n**Warning**: bcdedit returned non-zero exit code\n")
		}

		sb.WriteString("\nReboot required for KD to take effect.")

		if reboot {
			executeAndCollect(ctx, client, "shutdown /r /t 2 /f", "cmd", "", nil, 5)
			sb.WriteString("\nReboot initiated.")
		}

		// Extract the key from output for the user to copy into WinDbg.
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(strings.ToLower(line), "key") && strings.Contains(line, ".") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					sb.WriteString(fmt.Sprintf("\n**WinDbg connect string**: `net:port=%d,key=%s`", port, strings.TrimSpace(parts[1])))
				}
				break
			}
		}

		return mcp.NewToolResultText(sb.String()), nil
	}
}

func disableKdHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		reboot := request.GetBool("reboot", false)

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect: %v", err)), nil
		}

		output, _, _, err := executeAndCollect(ctx, client, `bcdedit /debug off; 'KD disabled'`, "powershell", "", nil, 15)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("disable KD failed: %v", err)), nil
		}

		result := fmt.Sprintf("**KD disabled on %s**\n```\n%s```\nReboot required.", nodeName, strings.TrimSpace(output))

		if reboot {
			executeAndCollect(ctx, client, "shutdown /r /t 2 /f", "cmd", "", nil, 5)
			result += "\nReboot initiated."
		}

		return mcp.NewToolResultText(result), nil
	}
}

func getKdStatusHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect: %v", err)), nil
		}

		cmd := `
Write-Host "--- Debug State ---"
$debug = bcdedit /enum "{current}" | Select-String "debug\s+"
if ($debug) { $debug.Line.Trim() } else { "debug: not set" }

Write-Host ""
Write-Host "--- Debug Settings ---"
bcdedit /dbgsettings 2>&1

Write-Host ""
Write-Host "--- Boot Config ---"
bcdedit /enum "{current}" | Select-String "debug|testsigning|hypervisor" | ForEach-Object { $_.Line.Trim() }
`
		output, _, _, err := executeAndCollect(ctx, client, cmd, "powershell", "", nil, 15)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("query failed: %v", err)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("**KD status on %s**\n\n```\n%s```", nodeName, strings.TrimSpace(output))), nil
	}
}
