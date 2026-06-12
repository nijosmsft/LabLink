package mcptools

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/registry"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

func RegisterNodeOps(s *server.MCPServer, reg *registry.Registry, pool *agentclient.Pool, leaseCfg LeaseGateConfig) {
	addTool(s,
		mcp.NewTool("wait_for_node",
			mcp.WithDescription("Poll a node's agent until it responds."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithNumber("timeout", mcp.Description("Max seconds to wait, default 120")),
		),
		waitForNodeHandler(reg, pool),
	)

	addTool(s,
		mcp.NewTool("get_node_info",
			mcp.WithDescription("Get OS, driver, NIC, and uptime info from a live node."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
		),
		getNodeInfoHandler(reg, pool),
	)

	addTool(s,
		mcp.NewTool("tail_file",
			mcp.WithDescription("Read the last N lines of a file on a remote node."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("path", mcp.Required(), mcp.Description("File path on the node")),
			mcp.WithNumber("lines", mcp.Description("Lines to read, default 50")),
		),
		tailFileHandler(reg, pool),
	)

	addTool(s,
		mcp.NewTool("ping_nodes",
			mcp.WithDescription("Check online/offline status of all registered nodes."),
		),
		pingNodesHandler(reg, pool),
	)

	addTool(s,
		mcp.NewTool("copy_between_nodes",
			mcp.WithDescription("Copy a file directly between two nodes without local staging."),
			mcp.WithString("source_node", mcp.Required(), mcp.Description("Node to copy from")),
			mcp.WithString("source_path", mcp.Required(), mcp.Description("Source file path")),
			mcp.WithString("dest_node", mcp.Required(), mcp.Description("Node to copy to")),
			mcp.WithString("dest_path", mcp.Required(), mcp.Description("Destination file path")),
		),
		LeaseGate(leaseCfg, extractCopyBetweenNodes, copyBetweenNodesHandler(reg, pool)),
	)
}

func waitForNodeHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		timeout := request.GetInt("timeout", 120)

		if _, ok := reg.GetNode(nodeName); !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		hbStart := time.Now()
		stop := StartMCPHeartbeat(ctx, request, defaultHeartbeatInterval, func() (int64, int64) {
			return int64(time.Since(hbStart).Seconds()), int64(timeout)
		})
		defer stop()

		// If health monitor is active, use it but don't trust stale "online" status.
		// First do a fresh probe to verify current state. If the node is actually down,
		// wait for the monitor to detect it coming back. Require 2 consecutive "online"
		// readings to avoid false positives during early boot.
		if hmon != nil {
			node, _ := reg.GetNode(nodeName)
			start := time.Now()
			deadline := start.Add(time.Duration(timeout) * time.Second)
			polls := 0
			consecutiveOnline := 0
			requiredConsecutive := 2

			// Fresh probe first — don't trust cached status.
			pool.ResetConnection(node.Address)
			client, err := pool.GetClient(node.Address, node.TLSServerName)
			if err == nil {
				probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				_, err = client.GetInfo(probeCtx, &pb.GetInfoRequest{})
				cancel()
			}
			if err != nil {
				// Node is actually down. Wait for recovery.
				consecutiveOnline = 0
			} else {
				consecutiveOnline = 1
			}

			for time.Now().Before(deadline) {
				if consecutiveOnline >= requiredConsecutive {
					elapsed := time.Since(start).Round(time.Second)
					return mcp.NewToolResultText(fmt.Sprintf("**%s** is online (confirmed after %s, %d polls)", nodeName, elapsed, polls)), nil
				}

				polls++
				select {
				case <-ctx.Done():
					return mcp.NewToolResultError(fmt.Sprintf("cancelled waiting for %s", nodeName)), nil
				case <-time.After(3 * time.Second):
				}

				status := hmon.GetStatus(nodeName)
				if status.Status == "online" {
					consecutiveOnline++
				} else {
					consecutiveOnline = 0
				}
			}

			return mcp.NewToolResultError(fmt.Sprintf("**%s** did not come online within %ds", nodeName, timeout)), nil
		}

		// Fallback: probe directly if no health monitor.
		node, _ := reg.GetNode(nodeName)
		start := time.Now()
		deadline := start.Add(time.Duration(timeout) * time.Second)
		attempts := 0

		for time.Now().Before(deadline) {
			attempts++
			pool.ResetConnection(node.Address)
			client, err := pool.GetClient(node.Address, node.TLSServerName)
			if err == nil {
				probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				_, err = client.GetInfo(probeCtx, &pb.GetInfoRequest{})
				cancel()
				if err == nil {
					return mcp.NewToolResultText(fmt.Sprintf("**%s** is online (took %d attempts, %s)",
						nodeName, attempts, time.Since(start).Round(time.Second))), nil
				}
			}

			select {
			case <-ctx.Done():
				return mcp.NewToolResultError(fmt.Sprintf("cancelled waiting for %s", nodeName)), nil
			case <-time.After(5 * time.Second):
			}
		}

		return mcp.NewToolResultError(fmt.Sprintf("**%s** did not come online within %ds (%d attempts)", nodeName, timeout, attempts)), nil
	}
}

func getNodeInfoHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
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
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$uptime = (Get-Date) - $os.LastBootUpTime

Write-Host "Hostname: $($os.CSName)"
Write-Host "OS: $($os.Caption) Build $($os.BuildNumber)"
Write-Host "Version: $($os.Version)"
Write-Host "Uptime: $([int]$uptime.TotalHours)h $($uptime.Minutes)m"
Write-Host "CPUs: $($cs.NumberOfLogicalProcessors) ($($cs.NumberOfProcessors) socket(s))"
Write-Host "Memory: $([math]::Round($cs.TotalPhysicalMemory/1GB, 1)) GB"

Write-Host ""
Write-Host "--- Drivers ---"
@('xdp', 'xdplwf', 'ebpfcore', 'netebpfext') | ForEach-Object {
    $svc = Get-Service $_ -ErrorAction SilentlyContinue
    if ($svc) {
        $drv = Get-CimInstance Win32_SystemDriver -Filter "Name='$_'" -ErrorAction SilentlyContinue
        Write-Host "$($_): $($svc.Status) (path: $($drv.PathName))"
    }
}

Write-Host ""
Write-Host "--- NICs ---"
Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
    $ip = (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress -join ', '
    Write-Host "$($_.Name): $($_.LinkSpeed) driver=$($_.DriverVersion) ip=$ip"
}

Write-Host ""
Write-Host "--- Test Signing ---"
$ts = bcdedit /enum "{current}" 2>$null | Select-String "testsigning\s+Yes"
if ($ts) { Write-Host "Test signing: ON" } else { Write-Host "Test signing: OFF" }
`
		output, _, _, err := executeAndCollect(ctx, client, cmd, "powershell", "", nil, 20)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed: %v", err)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("**%s** system info:\n\n```\n%s```", nodeName, strings.TrimRight(output, "\n\r "))), nil
	}
}

func tailFileHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		path := request.GetString("path", "")
		lines := request.GetInt("lines", 50)

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect: %v", err)), nil
		}

		cmd := fmt.Sprintf(`Get-Content '%s' -Tail %d -ErrorAction Stop`, path, lines)
		output, exitCode, _, err := executeAndCollect(ctx, client, cmd, "powershell", "", nil, 15)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed: %v", err)), nil
		}
		if exitCode != 0 {
			return mcp.NewToolResultError(fmt.Sprintf("exit %d:\n%s", exitCode, output)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("**%s:%s** (last %d lines)\n\n```\n%s```", nodeName, path, lines, strings.TrimRight(output, "\n\r "))), nil
	}
}

func pingNodesHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodes := reg.AllNodes()
		if len(nodes) == 0 {
			return mcp.NewToolResultText("No nodes registered."), nil
		}

		type pingResult struct {
			Name    string
			Status  string
			Latency time.Duration
		}

		results := make([]pingResult, len(nodes))

		// Ping all nodes concurrently.
		var wg sync.WaitGroup
		for i, n := range nodes {
			wg.Add(1)
			go func(idx int, node *registry.Node) {
				defer wg.Done()
				r := pingResult{Name: node.Name, Status: "offline"}
				start := time.Now()
				client, err := pool.GetClient(node.Address, node.TLSServerName)
				if err == nil {
					probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
					_, err = client.GetInfo(probeCtx, &pb.GetInfoRequest{})
					cancel()
					if err == nil {
						r.Status = "online"
						r.Latency = time.Since(start)
					}
				}
				results[idx] = r
			}(i, n)
		}
		wg.Wait()

		online, offline := 0, 0
		var sb strings.Builder
		for _, r := range results {
			icon := "x"
			latency := ""
			if r.Status == "online" {
				icon = "ok"
				latency = fmt.Sprintf(" (%s)", r.Latency.Round(time.Millisecond))
				online++
			} else {
				offline++
			}
			sb.WriteString(fmt.Sprintf("  %s  %s%s\n", icon, r.Name, latency))
		}

		header := fmt.Sprintf("**%d online, %d offline** (of %d)\n\n", online, offline, len(nodes))
		return mcp.NewToolResultText(header + sb.String()), nil
	}
}

func copyBetweenNodesHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		srcNodeName := request.GetString("source_node", "")
		srcPath := request.GetString("source_path", "")
		dstNodeName := request.GetString("dest_node", "")
		dstPath := request.GetString("dest_path", "")

		srcNode, ok := reg.GetNode(srcNodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("source node %q not found", srcNodeName)), nil
		}
		dstNode, ok := reg.GetNode(dstNodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("dest node %q not found", dstNodeName)), nil
		}

		srcClient, err := pool.GetClient(srcNode.Address, srcNode.TLSServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect to source: %v", err)), nil
		}
		dstClient, err := pool.GetClient(dstNode.Address, dstNode.TLSServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect to dest: %v", err)), nil
		}

		// Pull from source.
		pullStream, err := srcClient.PullFile(ctx, &pb.PullFileRequest{RemotePath: srcPath})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("pull from %s: %v", srcNodeName, err)), nil
		}

		// Push to dest — stream chunks directly without writing to local disk.
		pushStream, err := dstClient.PushFile(ctx)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("push to %s: %v", dstNodeName, err)), nil
		}

		var totalBytes int64
		var totalSize int64
		first := true
		for {
			resp, err := pullStream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("pull from %s: %v", srcNodeName, err)), nil
			}

			msg := &pb.PushFileRequest{
				RemotePath: dstPath,
				Chunk:      resp.Chunk,
			}
			if first {
				totalSize = resp.TotalSize
				msg.FileSize = totalSize
				first = false
			}
			totalBytes += int64(len(resp.Chunk))

			if err := pushStream.Send(msg); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("push chunk: %v", err)), nil
			}
		}

		// Explicitly terminate the upload so the destination can detect truncation.
		finalSize := totalSize
		if first {
			finalSize = 0
		}
		if err := pushStream.Send(&pb.PushFileRequest{
			RemotePath: dstPath,
			FileSize:   finalSize,
			IsLast:     true,
		}); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("send final chunk: %v", err)), nil
		}

		pushResp, err := pushStream.CloseAndRecv()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("close push: %v", err)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("Copied **%s:%s** → **%s:%s** (%s)",
			srcNodeName, srcPath, dstNodeName, pushResp.RemotePath, formatBytes(totalBytes))), nil
	}
}
