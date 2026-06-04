package mcptools

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	rebootNodesInitialDownSleep = 10 * time.Second
	rebootNodesPollInterval     = 5 * time.Second
	rebootNodesConnectTimeout   = 2 * time.Second
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

func RegisterPatch(s *server.MCPServer, reg *registry.Registry, pool *agentclient.Pool, auditLog *audit.Log, patchCfg *PatchConfig) {
	addTool(s,
		mcp.NewTool("patch_binary",
			mcp.WithDescription("Patch a protected Windows system binary on a remote node. Pushes the local binary, backs up the original, and replaces it via a Windows engineering replace-utility (path supplied by the operator via SFPCOPY_SOURCE). Ensures test signing is enabled. A reboot may be required for kernel binaries."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("local_path", mcp.Required(), mcp.Description("Local path to the replacement binary (e.g., C:\\build\\drivers\\mydriver.sys)")),
			mcp.WithString("dest_path", mcp.Required(), mcp.Description("System path to replace (e.g., C:\\Windows\\System32\\drivers\\mydriver.sys)")),
			mcp.WithBoolean("reboot", mcp.Description("Reboot the machine after patching (default false)")),
		),
		patchBinaryHandler(reg, pool, auditLog, patchCfg),
	)

	addTool(s,
		mcp.NewTool("reboot_node",
			mcp.WithDescription("Reboot a remote node. Waits for the agent to come back online."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithNumber("wait_seconds", mcp.Description("Max seconds to wait for the node to come back (default 120)")),
		),
		rebootNodeHandler(reg, pool, auditLog),
	)

	addTool(s,
		mcp.NewTool("reboot_nodes",
			mcp.WithDescription(`Reboot multiple remote nodes IN PARALLEL and wait for all to come back online.

USE THIS for any multi-node reboot request. Wall-clock time scales with the
slowest single reboot (typically 30-60s), NOT with the number of nodes.

Internal flow:
  1. Kick "shutdown /r /t 2 /f" on every node concurrently via agents
  2. Sleep 10s for the nodes to actually go down
  3. Poll all nodes via parallel TCP-connect every 5s; mark each as done when it
     reconnects; loop until either every node is back OR wait_seconds elapses
  4. Return per-node status table

For a SINGLE node reboot, reboot_node is fine. For ANY multi-node case, prefer
this tool — calling reboot_node in a loop blocks for wait_seconds per node.`),
			mcp.WithArray("nodes",
				mcp.Required(),
				mcp.Description("Node names from the registry"),
				mcp.WithStringItems(),
			),
			mcp.WithNumber("wait_seconds", mcp.Description("Max seconds to wait for ALL nodes to come back (default 300)")),
		),
		rebootNodesHandler(reg, pool, auditLog),
	)

	addTool(s,
		mcp.NewTool("restore_binary",
			mcp.WithDescription("Restore a previously patched binary from the backup directory on a remote node."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("dest_path", mcp.Required(), mcp.Description("System path to restore (e.g., C:\\Windows\\System32\\drivers\\mydriver.sys)")),
			mcp.WithString("backup_file", mcp.Description("Specific backup filename to restore. If omitted, lists available backups.")),
			mcp.WithBoolean("reboot", mcp.Description("Reboot after restoring (default false)")),
		),
		restoreBinaryHandler(reg, pool, auditLog),
	)

	addTool(s,
		mcp.NewTool("ensure_test_signing",
			mcp.WithDescription("Check and enable test signing (bcdedit /set testsigning on) on a remote node. Returns whether a reboot is needed."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
		),
		ensureTestSigningHandler(reg, pool),
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

		// Wait for the node to come back.
		waitCmd := fmt.Sprintf(`
$maxWait = %d
$waited = 0
Start-Sleep 10
while ($waited -lt $maxWait) {
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $c.Connect('%s', %s)
        $c.Close()
        "Node back online after $waited seconds"
        exit 0
    } catch {
        Start-Sleep 5
        $waited += 5
    }
}
"Timeout waiting for node after $maxWait seconds"
exit 1
`, waitSec, nodeHost(node.Address), nodePort(node.Address))

		// Run the wait loop locally via PowerShell.
		output, exitCode, _, _ := executeLocalPowershell(ctx, waitCmd, waitSec+30)

		if exitCode == 0 {
			return mcp.NewToolResultText(fmt.Sprintf("**%s** rebooted and back online.\n```\n%s```", nodeName, strings.TrimSpace(output))), nil
		}
		return mcp.NewToolResultError(fmt.Sprintf("Reboot initiated but node did not come back within %ds:\n%s", waitSec, output)), nil
	}
}

// rebootNodeStatus tracks the result of a single node within a reboot_nodes call.
type rebootNodeStatus struct {
	NodeName   string
	Kicked     bool
	KickErr    error
	BackOnline bool
	WallTime   time.Duration
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

		// Step 2: central sleep so nodes have time to actually go down.
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
		// node in parallel via TCP-connect to its agent port. Mark each as done as
		// soon as the connect succeeds. Loop until all back or wait_seconds elapses.
		deadline := time.Now().Add(time.Duration(waitSec) * time.Second)
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
					conn, err := net.DialTimeout("tcp", nodes[idx].Address, rebootNodesConnectTimeout)
					if err == nil {
						_ = conn.Close()
						results[j] = true
					}
				}(j, idx)
			}
			pollWg.Wait()

			stillPending := pending[:0]
			for j, idx := range pending {
				if results[j] {
					statuses[idx].BackOnline = true
					statuses[idx].WallTime = time.Since(starts[idx])
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
	kicked, back := 0, 0
	for _, s := range statuses {
		if s.Kicked {
			kicked++
		}
		if s.BackOnline {
			back++
		}
	}
	headline := "All nodes rebooted and back online"
	if back != len(statuses) {
		headline = "Some nodes did not return within the wait window"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("**%s** (%d/%d kicked, %d/%d back)\n\n", headline, kicked, len(statuses), back, len(statuses)))
	sb.WriteString("| Node | Shutdown kicked? | Came back online? | Wall time |\n")
	sb.WriteString("|---|---|---|---|\n")
	for _, s := range statuses {
		kickCol := "yes"
		if !s.Kicked {
			if s.KickErr != nil {
				kickCol = fmt.Sprintf("NO (%v)", s.KickErr)
			} else {
				kickCol = "NO"
			}
		}
		backCol := "yes"
		if !s.BackOnline {
			if s.Kicked {
				backCol = fmt.Sprintf("NO (timeout %ds)", waitSec)
			} else {
				backCol = "n/a"
			}
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", s.NodeName, kickCol, backCol, s.WallTime.Round(time.Second)))
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
