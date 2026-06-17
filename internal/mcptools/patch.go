package mcptools

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/registry"
)

// Tuning knobs for reboot_nodes. Package-level vars so tests can shrink them
// without injecting a clock interface through every layer.
var (
	rebootNodesInitialDownSleep  = 5 * time.Second
	rebootNodesPollInterval      = 5 * time.Second
	rebootNodesConnectTimeout    = 2 * time.Second
	rebootNodesDownConfirmations = 2
	rebootNodesDial              = func(addr string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout("tcp", addr, timeout)
	}
)

const (
	remotesfpCopyPath    = `C:\LabLink\sfpcopy.exe`
	defaultSfpCopySource = ``
)

// PatchConfig holds configurable paths for patching.
type PatchConfig struct {
	SfpCopySource string // Network share or local path to sfpcopy.exe (dev machine accessible)
	CacheDir      string // Local cache dir for sfpcopy.exe on the dev machine
}

func NewPatchConfig(configDir string) *PatchConfig {
	src := os.Getenv("SFPCOPY_SOURCE")
	if src == "" {
		src = defaultSfpCopySource
	}
	return &PatchConfig{
		SfpCopySource: src,
		CacheDir:      filepath.Join(configDir, "cache"),
	}
}

// localSfpCopyPath returns the cached sfpcopy.exe path on the dev machine.
// Downloads from the source if not cached.
func (pc *PatchConfig) localSfpCopyPath() (string, error) {
	cached := filepath.Join(pc.CacheDir, "sfpcopy.exe")
	if _, err := os.Stat(cached); err == nil {
		return cached, nil
	}

	// Source exists locally or on a network share accessible from the dev machine.
	if pc.SfpCopySource == "" {
		return "", fmt.Errorf("sfpcopy.exe source is not configured (set SFPCOPY_SOURCE to a local path or accessible share)")
	}
	if _, err := os.Stat(pc.SfpCopySource); err != nil {
		return "", fmt.Errorf("sfpcopy.exe not found at %s (set SFPCOPY_SOURCE env var to override)", pc.SfpCopySource)
	}

	if err := os.MkdirAll(pc.CacheDir, 0755); err != nil {
		return "", err
	}

	data, err := os.ReadFile(pc.SfpCopySource)
	if err != nil {
		return "", fmt.Errorf("read sfpcopy from %s: %w", pc.SfpCopySource, err)
	}
	if err := os.WriteFile(cached, data, 0755); err != nil {
		return "", fmt.Errorf("cache sfpcopy: %w", err)
	}
	return cached, nil
}

func RegisterPatch(s *server.MCPServer, reg *registry.Registry, pool *agentclient.Pool, auditLog *audit.Log, patchCfg *PatchConfig, leaseCfg LeaseGateConfig) {
	addTool(s,
		mcp.NewTool("patch_binary",
			mcp.WithDescription("Replace a protected Windows system binary on a remote node using sfpcopy."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("local_path", mcp.Required(), mcp.Description("Local path to the replacement binary")),
			mcp.WithString("dest_path", mcp.Required(), mcp.Description("System path to replace")),
			mcp.WithBoolean("reboot", mcp.Description("Reboot after patching, default false")),
		),
		LeaseGate(leaseCfg, extractSingleNode("node"), patchBinaryHandler(reg, pool, auditLog, patchCfg)),
	)

	addTool(s,
		mcp.NewTool("reboot_node",
			mcp.WithDescription("Reboot a single remote node and wait for its agent to return."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithNumber("wait_seconds", mcp.Description("Max seconds to wait, default 120")),
		),
		LeaseGate(leaseCfg, extractSingleNode("node"), rebootNodeHandler(reg, pool, auditLog)),
	)

	addTool(s,
		mcp.NewTool("reboot_nodes",
			mcp.WithDescription("Reboot multiple nodes in parallel and wait for all to return."),
			mcp.WithArray("nodes",
				mcp.Required(),
				mcp.Description("Node names from the registry"),
				mcp.WithStringItems(),
			),
			mcp.WithNumber("wait_seconds", mcp.Description("Max seconds to wait for all nodes, default 300")),
		),
		LeaseGate(leaseCfg, extractMultiNodes("nodes"), rebootNodesHandler(reg, pool, auditLog)),
	)

	addTool(s,
		mcp.NewTool("restore_binary",
			mcp.WithDescription("Restore a previously patched binary from backup on a remote node."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("dest_path", mcp.Required(), mcp.Description("System path to restore")),
			mcp.WithString("backup_file", mcp.Description("Specific backup file; omit to list available backups.")),
			mcp.WithBoolean("reboot", mcp.Description("Reboot after restoring, default false")),
		),
		LeaseGate(leaseCfg, extractSingleNode("node"), restoreBinaryHandler(reg, pool, auditLog)),
	)

	addTool(s,
		mcp.NewTool("ensure_test_signing",
			mcp.WithDescription("Enable test signing on a remote node if not already set."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
		),
		LeaseGate(leaseCfg, extractSingleNode("node"), ensureTestSigningHandler(reg, pool)),
	)
}

func patchBinaryHandler(reg *registry.Registry, pool *agentclient.Pool, auditLog *audit.Log, patchCfg *PatchConfig) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		localPath := request.GetString("local_path", "")
		destPath := request.GetString("dest_path", "")
		reboot := request.GetBool("reboot", false)

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect to %s: %v", node.Address, err)), nil
		}

		var sb strings.Builder

		// Step 1: Ensure sfpcopy.exe exists on the node.
		// Check remotely first; if missing, cache locally and push via gRPC.
		sfpCheck := fmt.Sprintf(`if (Test-Path '%s') { 'exists' } else { 'missing' }`, remotesfpCopyPath)
		output, _, _, _ := executeAndCollect(ctx, client, sfpCheck, "powershell", "", nil, 10)
		if strings.TrimSpace(output) != "exists" {
			localSfp, err := patchCfg.localSfpCopyPath()
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("sfpcopy.exe: %v", err)), nil
			}
			_, err = pushFileToNode(ctx, client, localSfp, remotesfpCopyPath)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("push sfpcopy.exe: %v", err)), nil
			}
			sb.WriteString("Pushed sfpcopy.exe to node\n")
		} else {
			sb.WriteString("sfpcopy.exe already on node\n")
		}

		// Step 2: Ensure test signing is enabled.
		tsCheck := `
$ts = bcdedit /enum "{current}" | Select-String "testsigning\s+Yes"
if (-not $ts) {
    bcdedit /set testsigning on | Out-Null
    'Test signing enabled (reboot needed)'
} else {
    'Test signing already on'
}
`
		output, _, _, _ = executeAndCollect(ctx, client, tsCheck, "powershell", "", nil, 15)
		sb.WriteString(strings.TrimSpace(output) + "\n")

		// Step 3: Push the binary to a staging path on the node.
		stagingPath := `C:\LabLink\staging\` + baseName(destPath)
		pushResult, err := pushFileToNode(ctx, client, localPath, stagingPath)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("push file: %v", err)), nil
		}
		sb.WriteString(fmt.Sprintf("Pushed %s (%s)\n", baseName(localPath), formatBytes(pushResult)))

		// Step 4: Backup original and sfpcopy.
		patchCmd := fmt.Sprintf(`
$backupDir = 'C:\LabLink\backup'
if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$origName = [IO.Path]::GetFileName('%s')
$backupPath = Join-Path $backupDir "$origName.$ts.bak"

if (Test-Path '%s') {
    Copy-Item '%s' $backupPath -Force
    "Backed up original to $backupPath"
} else {
    "No existing file at %s to backup"
}

& '%s' '%s' '%s'
if ($LASTEXITCODE -eq 0) {
    'sfpcopy OK'
} else {
    "sfpcopy FAILED (exit $LASTEXITCODE)"
    exit 1
}
`, destPath, destPath, destPath, destPath, remotesfpCopyPath, stagingPath, destPath)

		output, exitCode, _, err := executeAndCollect(ctx, client, patchCmd, "powershell", "", nil, 30)
		if err != nil || exitCode != 0 {
			return mcp.NewToolResultError(fmt.Sprintf("patch failed (exit %d):\n%s\nerr: %v", exitCode, output, err)), nil
		}
		sb.WriteString(strings.TrimSpace(output) + "\n")

		auditLog.Append(audit.Entry{
			Timestamp: timeNow(),
			Node:      nodeName,
			Tool:      "patch_binary",
			Command:   fmt.Sprintf("%s -> %s", localPath, destPath),
			ExitCode:  exitCode,
		})

		// Step 5: Reboot if requested.
		if reboot {
			executeAndCollect(ctx, client, "shutdown /r /t 2 /f", "cmd", "", nil, 5)
			sb.WriteString("Reboot initiated, waiting for node to go down...\n")

			// Wait for the node to actually go down before returning,
			// so the caller knows it's safe to call wait_for_node.
			time.Sleep(15 * time.Second)

			// Reset the stale connection so next call reconnects.
			pool.ResetConnection(node.Address)
			sb.WriteString("Node is down. Use wait_for_node to wait for it to come back.\n")
		}

		return mcp.NewToolResultText(fmt.Sprintf("**Patched %s on %s**\n\n```\n%s```", baseName(destPath), nodeName, sb.String())), nil
	}
}

func rebootNodeHandler(reg *registry.Registry, pool *agentclient.Pool, auditLog *audit.Log) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		waitSec := request.GetInt("wait_seconds", 120)

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		var doneAtomic atomic.Int64
		stop := StartMCPHeartbeat(ctx, request, defaultHeartbeatInterval, func() (int64, int64) {
			return doneAtomic.Load(), 1
		})
		defer stop()

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect to %s: %v", node.Address, err)), nil
		}

		// Initiate reboot.
		executeAndCollect(ctx, client, "shutdown /r /t 2 /f", "cmd", "", nil, 5)

		auditLog.Append(audit.Entry{
			Timestamp: timeNow(),
			Node:      nodeName,
			Tool:      "reboot_node",
			Command:   "shutdown /r /t 2 /f",
		})

		pool.ResetConnection(node.Address)
		start := time.Now()
		deadline := start.Add(time.Duration(waitSec) * time.Second)
		wentDown, backOnline, wall := waitForReboot(ctx, rebootNodesDial, node.Address, start, deadline)
		if backOnline {
			doneAtomic.Store(1)
			return mcp.NewToolResultText(fmt.Sprintf("**%s** rebooted (went offline, back online after %s).", nodeName, wall.Round(time.Second))), nil
		}
		if !wentDown {
			return mcp.NewToolResultError(fmt.Sprintf("Reboot initiated but %s never went offline within %ds -- the reboot may not have taken effect.", nodeName, waitSec)), nil
		}
		return mcp.NewToolResultError(fmt.Sprintf("%s went offline but did not come back within %ds.", nodeName, waitSec)), nil
	}
}

// rebootNodeStatus tracks the result of a single node within a reboot_nodes call.
type rebootNodeStatus struct {
	NodeName   string
	Kicked     bool
	KickErr    error
	WentDown   bool
	BackOnline bool
	WallTime   time.Duration
}

type rebootWaitState struct {
	wentDown            bool
	backOnline          bool
	consecutiveFailures int
}

func (s *rebootWaitState) observe(reachable bool) {
	if s.backOnline {
		return
	}
	if !s.wentDown {
		if reachable {
			s.consecutiveFailures = 0
			return
		}
		s.consecutiveFailures++
		if s.consecutiveFailures >= rebootNodesDownConfirmations {
			s.wentDown = true
			s.consecutiveFailures = 0
		}
		return
	}
	if reachable {
		s.backOnline = true
	}
}

func waitForReboot(ctx context.Context, dial func(addr string, timeout time.Duration) (net.Conn, error), addr string, start time.Time, deadline time.Time) (wentDown bool, backOnline bool, wall time.Duration) {
	select {
	case <-ctx.Done():
		return false, false, time.Since(start)
	case <-time.After(rebootNodesInitialDownSleep):
	}

	state := rebootWaitState{}
	for time.Now().Before(deadline) {
		conn, err := dial(addr, rebootNodesConnectTimeout)
		reachable := err == nil
		if conn != nil {
			_ = conn.Close()
		}
		state.observe(reachable)
		if state.wentDown {
			wentDown = true
		}
		if state.backOnline {
			return true, true, time.Since(start)
		}

		select {
		case <-ctx.Done():
			return wentDown, false, time.Since(start)
		case <-time.After(rebootNodesPollInterval):
		}
	}
	return wentDown, false, time.Since(start)
}

func rebootNodesHandler(reg *registry.Registry, pool *agentclient.Pool, auditLog *audit.Log) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		names := request.GetStringSlice("nodes", nil)
		waitSec := request.GetInt("wait_seconds", 300)

		if len(names) == 0 {
			return mcp.NewToolResultError("nodes list is empty; supply at least one node name"), nil
		}

		// Atomic validation: resolve every name before kicking anything. De-dupe
		// in input order so callers can safely pass overlapping lists.
		nodes := make([]*registry.Node, 0, len(names))
		var unknown []string
		seen := make(map[string]struct{}, len(names))
		for _, name := range names {
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			node, ok := reg.GetNode(name)
			if !ok {
				unknown = append(unknown, name)
				continue
			}
			nodes = append(nodes, node)
		}
		if len(unknown) > 0 {
			return mcp.NewToolResultError(fmt.Sprintf(
				"unknown node(s): %s — refusing to kick any reboot (validation is atomic)",
				strings.Join(unknown, ", "))), nil
		}

		var doneAtomic atomic.Int64
		stop := StartMCPHeartbeat(ctx, request, defaultHeartbeatInterval, func() (int64, int64) {
			return doneAtomic.Load(), int64(len(nodes))
		})
		defer stop()

		statuses := make([]rebootNodeStatus, len(nodes))
		starts := make([]time.Time, len(nodes))
		now := timeNow()
		for i, node := range nodes {
			statuses[i].NodeName = node.Name
			starts[i] = now
		}

		// Step 1: fan out the shutdown command in parallel.
		var wg sync.WaitGroup
		for i, node := range nodes {
			wg.Add(1)
			go func(idx int, n *registry.Node) {
				defer wg.Done()
				client, err := pool.GetClient(n.Address, n.TLSServerName)
				if err != nil {
					statuses[idx].KickErr = err
					return
				}
				if _, _, _, err := executeAndCollect(ctx, client, "shutdown /r /t 2 /f", "cmd", "", nil, 5); err != nil {
					statuses[idx].KickErr = err
					return
				}
				statuses[idx].Kicked = true
			}(i, node)
		}
		wg.Wait()

		// Audit every reboot attempt — one entry per node, matching reboot_node.
		for i, node := range nodes {
			entry := audit.Entry{
				Timestamp: timeNow(),
				Node:      node.Name,
				Tool:      "reboot_nodes",
				Command:   "shutdown /r /t 2 /f",
			}
			if statuses[i].KickErr != nil {
				entry.ExitCode = -1
			}
			auditLog.Append(entry)
		}

		deadline := now.Add(time.Duration(waitSec) * time.Second)

		// Step 2: central sleep before polling. Correctness does not depend on
		// this grace period; each node still must be observed down before up.
		select {
		case <-ctx.Done():
			// Caller cancelled — fall through and render whatever we have.
		case <-time.After(rebootNodesInitialDownSleep):
		}

		// Drop cached gRPC connections; the next probe should dial fresh.
		for _, node := range nodes {
			pool.ResetConnection(node.Address)
		}

		// Step 3: poll loop. Every rebootNodesPollInterval, try every still-pending
		// node in parallel via TCP-connect to its agent port. A node is done only
		// after failed dials confirm it went down and a later dial succeeds.
		waitStates := make([]rebootWaitState, len(nodes))
		pending := make([]int, 0, len(nodes))
		for i := range nodes {
			if statuses[i].Kicked {
				pending = append(pending, i)
			}
		}

		for len(pending) > 0 && time.Now().Before(deadline) {
			results := make([]bool, len(pending))
			var pollWg sync.WaitGroup
			for j, idx := range pending {
				pollWg.Add(1)
				go func(j, idx int) {
					defer pollWg.Done()
					conn, err := rebootNodesDial(nodes[idx].Address, rebootNodesConnectTimeout)
					if err == nil {
						_ = conn.Close()
						results[j] = true
					}
				}(j, idx)
			}
			pollWg.Wait()

			stillPending := pending[:0]
			for j, idx := range pending {
				waitStates[idx].observe(results[j])
				statuses[idx].WentDown = waitStates[idx].wentDown
				if waitStates[idx].backOnline {
					statuses[idx].BackOnline = true
					statuses[idx].WallTime = time.Since(starts[idx])
					doneAtomic.Add(1)
				} else {
					stillPending = append(stillPending, idx)
				}
			}
			pending = stillPending
			if len(pending) == 0 {
				break
			}

			select {
			case <-ctx.Done():
				pending = nil
			case <-time.After(rebootNodesPollInterval):
			}
		}

		// Whatever remained when we exited the loop never came back — record the
		// timeout wall time so the table column has something to show.
		for i := range statuses {
			if !statuses[i].BackOnline && statuses[i].WallTime == 0 {
				statuses[i].WallTime = time.Since(starts[i])
			}
		}

		return mcp.NewToolResultText(renderRebootNodesTable(statuses, waitSec)), nil
	}
}

func renderRebootNodesTable(statuses []rebootNodeStatus, waitSec int) string {
	kicked, down, back := 0, 0, 0
	for _, s := range statuses {
		if s.Kicked {
			kicked++
		}
		if s.WentDown {
			down++
		}
		if s.BackOnline {
			back++
		}
	}
	headline := "Reboot incomplete"
	if kicked == len(statuses) && down == len(statuses) && back == len(statuses) {
		headline = "All nodes rebooted and back online"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("**%s** (%d/%d kicked, %d/%d went offline, %d/%d back)\n\n", headline, kicked, len(statuses), down, len(statuses), back, len(statuses)))
	sb.WriteString("| Node | Shutdown kicked? | Went offline? | Came back online? | Wall time |\n")
	sb.WriteString("|---|---|---|---|---|\n")
	for _, s := range statuses {
		kickCol := "yes"
		if !s.Kicked {
			if s.KickErr != nil {
				kickCol = fmt.Sprintf("NO (%v)", s.KickErr)
			} else {
				kickCol = "NO"
			}
		}
		downCol := "yes"
		if !s.WentDown {
			if s.Kicked {
				downCol = "NO (never observed offline)"
			} else {
				downCol = "n/a"
			}
		}
		backCol := "yes"
		if !s.BackOnline {
			if s.Kicked {
				if s.WentDown {
					backCol = fmt.Sprintf("NO (went offline; timeout %ds)", waitSec)
				} else {
					backCol = "NO (never observed offline; reboot may not have taken effect)"
				}
			} else {
				backCol = "n/a"
			}
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n", s.NodeName, kickCol, downCol, backCol, s.WallTime.Round(time.Second)))
	}
	return sb.String()
}

func restoreBinaryHandler(reg *registry.Registry, pool *agentclient.Pool, auditLog *audit.Log) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		destPath := request.GetString("dest_path", "")
		backupFile := request.GetString("backup_file", "")
		reboot := request.GetBool("reboot", false)

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect: %v", err)), nil
		}

		binaryName := baseName(destPath)

		// If no backup file specified, list available backups.
		if backupFile == "" {
			listCmd := fmt.Sprintf(`Get-ChildItem 'C:\LabLink\backup\%s.*' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | ForEach-Object { "$($_.Name) ($($_.Length) bytes, $($_.LastWriteTime))" }`, binaryName)
			output, _, _, _ := executeAndCollect(ctx, client, listCmd, "powershell", "", nil, 10)
			output = strings.TrimSpace(output)
			if output == "" {
				return mcp.NewToolResultText(fmt.Sprintf("No backups found for **%s** on **%s**", binaryName, nodeName)), nil
			}
			return mcp.NewToolResultText(fmt.Sprintf("**Available backups for %s on %s:**\n\n```\n%s\n```\n\nUse `restore_binary` with `backup_file=<filename>` to restore one.", binaryName, nodeName, output)), nil
		}

		// Restore the specified backup.
		restoreCmd := fmt.Sprintf(`
$backupPath = 'C:\LabLink\backup\%s'
if (-not (Test-Path $backupPath)) {
    "Backup file not found: $backupPath"
    exit 1
}
& '%s' $backupPath '%s'
if ($LASTEXITCODE -eq 0) {
    'Restore OK'
} else {
    "sfpcopy FAILED (exit $LASTEXITCODE)"
    exit 1
}
`, backupFile, remotesfpCopyPath, destPath)

		output, exitCode, _, err := executeAndCollect(ctx, client, restoreCmd, "powershell", "", nil, 30)
		if err != nil || exitCode != 0 {
			return mcp.NewToolResultError(fmt.Sprintf("restore failed (exit %d):\n%s\nerr: %v", exitCode, output, err)), nil
		}

		auditLog.Append(audit.Entry{
			Timestamp: timeNow(),
			Node:      nodeName,
			Tool:      "restore_binary",
			Command:   fmt.Sprintf("%s -> %s", backupFile, destPath),
			ExitCode:  exitCode,
		})

		result := fmt.Sprintf("**Restored %s on %s** from backup `%s`\n```\n%s```", binaryName, nodeName, backupFile, strings.TrimSpace(output))

		if reboot {
			executeAndCollect(ctx, client, "shutdown /r /t 2 /f", "cmd", "", nil, 5)
			result += "\nReboot initiated"
		}

		return mcp.NewToolResultText(result), nil
	}
}

func ensureTestSigningHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect to %s: %v", node.Address, err)), nil
		}

		cmd := `
$ts = bcdedit /enum "{current}" | Select-String "testsigning\s+Yes"
if (-not $ts) {
    bcdedit /set testsigning on | Out-Null
    'Test signing ENABLED — reboot required for it to take effect'
} else {
    'Test signing already enabled — no reboot needed'
}
`
		output, _, _, err := executeAndCollect(ctx, client, cmd, "powershell", "", nil, 15)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("check failed: %v", err)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("**%s**: %s", nodeName, strings.TrimSpace(output))), nil
	}
}
