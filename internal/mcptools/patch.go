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
	s.AddTool(
		mcp.NewTool("patch_binary",
			mcp.WithDescription("Patch a protected Windows system binary on a remote node. Pushes the local binary, backs up the original, and replaces it via a Windows engineering replace-utility (path supplied by the operator via SFPCOPY_SOURCE). Ensures test signing is enabled. A reboot may be required for kernel binaries."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("local_path", mcp.Required(), mcp.Description("Local path to the replacement binary (e.g., C:\\build\\drivers\\mydriver.sys)")),
			mcp.WithString("dest_path", mcp.Required(), mcp.Description("System path to replace (e.g., C:\\Windows\\System32\\drivers\\mydriver.sys)")),
			mcp.WithBoolean("reboot", mcp.Description("Reboot the machine after patching (default false)")),
		),
		patchBinaryHandler(reg, pool, auditLog, patchCfg),
	)

	s.AddTool(
		mcp.NewTool("reboot_node",
			mcp.WithDescription("Reboot a remote node. Waits for the agent to come back online."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithNumber("wait_seconds", mcp.Description("Max seconds to wait for the node to come back (default 120)")),
		),
		rebootNodeHandler(reg, pool, auditLog),
	)

	s.AddTool(
		mcp.NewTool("restore_binary",
			mcp.WithDescription("Restore a previously patched binary from the backup directory on a remote node."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("dest_path", mcp.Required(), mcp.Description("System path to restore (e.g., C:\\Windows\\System32\\drivers\\mydriver.sys)")),
			mcp.WithString("backup_file", mcp.Description("Specific backup filename to restore. If omitted, lists available backups.")),
			mcp.WithBoolean("reboot", mcp.Description("Reboot after restoring (default false)")),
		),
		restoreBinaryHandler(reg, pool, auditLog),
	)

	s.AddTool(
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
