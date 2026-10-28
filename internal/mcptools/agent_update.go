package mcptools

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/registry"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

const (
	defaultAgentUpdateTimeout = 180
	windowsUpdateBinary       = `C:\LabLink\update\lablink-agent.next.exe`
	windowsUpdateScript       = `C:\LabLink\update\apply-agent-update.ps1`
	linuxUpdateBinary         = `/opt/lablink/update/lablink-agent.next`
	linuxUpdateScript         = `/opt/lablink/update/apply-agent-update.sh`
)

type AgentUpdateConfig struct {
	ServerVersion      string
	WindowsAgentBinary string
	LinuxAgentBinary   string
	PollInterval       time.Duration
}

func RegisterAgentUpdate(
	s *server.MCPServer,
	reg *registry.Registry,
	pool *agentclient.Pool,
	config AgentUpdateConfig,
	leaseCfg LeaseGateConfig,
) {
	addTool(s,
		mcp.NewTool("update_agent",
			mcp.WithDescription("Update one registered Windows or Linux agent to the running LabLink server's bundled version. The server pushes the matching local payload over mTLS, launches an OS-specific detached atomic replacement with rollback, waits for reconnection, and verifies AgentVersion. No client internet access is used."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Registered node name")),
			mcp.WithNumber("timeout_seconds", mcp.Description("Maximum seconds to wait for the detached update and authenticated reconnection (default 180)")),
		),
		LeaseGate(leaseCfg, extractSingleNode("node"), updateAgentHandler(reg, pool, config)),
	)
}

func updateAgentHandler(reg *registry.Registry, pool *agentclient.Pool, config AgentUpdateConfig) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := strings.TrimSpace(request.GetString("node", ""))
		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}
		timeoutSeconds := request.GetInt("timeout_seconds", defaultAgentUpdateTimeout)
		if timeoutSeconds < 30 {
			return mcp.NewToolResultError("timeout_seconds must be at least 30"), nil
		}
		if strings.TrimSpace(config.ServerVersion) == "" {
			return mcp.NewToolResultError("running LabLink server version is unavailable"), nil
		}

		start := time.Now()
		stopHeartbeat := StartMCPHeartbeat(ctx, request, defaultHeartbeatInterval, func() (int64, int64) {
			return int64(time.Since(start).Seconds()), int64(timeoutSeconds)
		})
		defer stopHeartbeat()

		current, err := probeAgentInfo(ctx, node, pool)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("probe %s before update: %v", nodeName, err)), nil
		}
		if current.AgentVersion == config.ServerVersion {
			return mcp.NewToolResultText(fmt.Sprintf(
				"**%s** already runs %s (%s/%s); no update needed.",
				nodeName, config.ServerVersion, current.Os, current.Arch,
			)), nil
		}

		localBinary, remoteBinary, remoteScript, launcher, shell, err := updatePlan(current, config)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("prepare update for %s: %v", nodeName, err)), nil
		}
		hash, size, err := validateBundledAgent(localBinary, config.ServerVersion)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("validate bundled agent: %v", err)), nil
		}

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("connect to %s: %v", nodeName, err)), nil
		}
		if err := prepareAgentUpdateTarget(ctx, node, reg, pool, current.Os); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("prepare update staging on %s: %v", nodeName, err)), nil
		}
		transferCtx, transferCancel := context.WithTimeout(ctx, 2*time.Minute)
		defer transferCancel()
		if _, err := pushFileToNode(transferCtx, client, localBinary, remoteBinary); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("push bundled agent to %s: %v", nodeName, err)), nil
		}
		script := linuxAgentUpdateScript(config.ServerVersion, hash)
		if strings.EqualFold(current.Os, "windows") {
			script = windowsAgentUpdateScript(config.ServerVersion, hash)
		}
		if err := pushBytesToNode(transferCtx, client, []byte(script), remoteScript); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("push detached update script to %s: %v", nodeName, err)), nil
		}

		launch := executeScriptOnNode(ctx, node, launcher, shell, 30, reg, pool)
		if launch.Err != nil || launch.ExitCode != 0 {
			return mcp.NewToolResultError(fmt.Sprintf(
				"launch detached update on %s failed (exit=%d): %v\n%s",
				nodeName, launch.ExitCode, launch.Err, strings.TrimSpace(launch.Output),
			)), nil
		}

		updated, attempts, err := waitForAgentVersion(
			ctx,
			node,
			pool,
			config.ServerVersion,
			time.Duration(timeoutSeconds)*time.Second,
			config.PollInterval,
		)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf(
				"detached update launched on %s but verification failed: %v",
				nodeName, err,
			)), nil
		}
		if hmon != nil {
			hmon.RecordAuthenticatedProbeSuccess(node, updated.AgentVersion)
		}
		return mcp.NewToolResultText(fmt.Sprintf(
			"**%s updated successfully**\n- Previous: %s\n- Current: %s\n- Platform: %s/%s\n- Payload: %s (%d bytes, SHA256 %s)\n- Verification attempts: %d\n- Elapsed: %s",
			nodeName,
			current.AgentVersion,
			updated.AgentVersion,
			updated.Os,
			updated.Arch,
			localBinary,
			size,
			hash,
			attempts,
			time.Since(start).Round(time.Second),
		)), nil
	}
}

func probeAgentInfo(ctx context.Context, node *registry.Node, pool *agentclient.Pool) (*pb.GetInfoResponse, error) {
	pool.ResetConnection(node.Address)
	client, err := pool.GetClient(node.Address, node.TLSServerName)
	if err != nil {
		return nil, err
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return client.GetInfo(probeCtx, &pb.GetInfoRequest{})
}

func updatePlan(info *pb.GetInfoResponse, config AgentUpdateConfig) (localBinary, remoteBinary, remoteScript, launcher, shell string, err error) {
	osName := strings.ToLower(strings.TrimSpace(info.Os))
	arch := strings.ToLower(strings.TrimSpace(info.Arch))
	if arch != "amd64" {
		return "", "", "", "", "", fmt.Errorf("unsupported agent architecture %q; bundled updates currently support amd64", info.Arch)
	}
	switch osName {
	case "windows":
		localBinary = config.WindowsAgentBinary
		remoteBinary = windowsUpdateBinary
		remoteScript = windowsUpdateScript
		launcher = windowsAgentUpdateLauncher()
		shell = "powershell"
	case "linux":
		localBinary = config.LinuxAgentBinary
		remoteBinary = linuxUpdateBinary
		remoteScript = linuxUpdateScript
		launcher = linuxAgentUpdateLauncher()
		shell = "bash"
	default:
		return "", "", "", "", "", fmt.Errorf("unsupported agent OS %q", info.Os)
	}
	if strings.TrimSpace(localBinary) == "" {
		return "", "", "", "", "", fmt.Errorf("server has no bundled %s/%s agent path", osName, arch)
	}
	return localBinary, remoteBinary, remoteScript, launcher, shell, nil
}

func prepareAgentUpdateTarget(
	ctx context.Context,
	node *registry.Node,
	reg *registry.Registry,
	pool *agentclient.Pool,
	osName string,
) error {
	var script, shell string
	if strings.EqualFold(osName, "windows") {
		script = `$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path 'C:\LabLink\update' | Out-Null
if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
    Add-MpPreference -ExclusionPath 'C:\LabLink'
}`
		shell = "powershell"
	} else {
		script = `set -euo pipefail
install -d -o root -g root -m 0700 /opt/lablink/update`
		shell = "bash"
	}
	result := executeScriptOnNode(ctx, node, script, shell, 30, reg, pool)
	if result.Err != nil {
		return result.Err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("exit %d: %s", result.ExitCode, strings.TrimSpace(result.Output))
	}
	return nil
}

func validateBundledAgent(path, expectedVersion string) (string, int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	if !bytes.Contains(data, []byte(expectedVersion)) {
		return "", 0, fmt.Errorf("%s does not contain running server version %s", path, expectedVersion)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:]), int64(len(data)), nil
}

func pushBytesToNode(ctx context.Context, client pb.NodeAgentClient, data []byte, remotePath string) error {
	stream, err := client.PushFile(ctx)
	if err != nil {
		return err
	}
	_, err = sendLocalFile(stream, bytes.NewReader(data), int64(len(data)), remotePath)
	return err
}

func waitForAgentVersion(
	ctx context.Context,
	node *registry.Node,
	pool *agentclient.Pool,
	expected string,
	timeout time.Duration,
	pollInterval time.Duration,
) (*pb.GetInfoResponse, int, error) {
	if pollInterval <= 0 {
		pollInterval = 3 * time.Second
	}
	deadline := time.Now().Add(timeout)
	attempts := 0
	lastVersion := ""
	var lastErr error
	for time.Now().Before(deadline) {
		attempts++
		info, err := probeAgentInfo(ctx, node, pool)
		if err == nil {
			lastVersion = info.AgentVersion
			if info.AgentVersion == expected {
				return info, attempts, nil
			}
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return nil, attempts, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
	if lastVersion != "" {
		return nil, attempts, fmt.Errorf("timed out waiting for version %s; node reports %s", expected, lastVersion)
	}
	return nil, attempts, fmt.Errorf("timed out waiting for version %s; last probe error: %v", expected, lastErr)
}

func windowsAgentUpdateScript(expectedVersion, expectedHash string) string {
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$source = 'C:\LabLink\update\lablink-agent.next.exe'
$destination = 'C:\LabLink\lablink-agent.exe'
$backup = 'C:\LabLink\update\lablink-agent.previous.exe'
$log = 'C:\LabLink\update\update.log'
$expectedVersion = %s
$expectedHash = %s

function Write-UpdateLog([string]$Message) {
    Add-Content -LiteralPath $log -Value ("{0:o} {1}" -f (Get-Date), $Message)
}

try {
    Start-Sleep -Seconds 3
    Write-UpdateLog "starting update to $expectedVersion"
    if (-not (Test-Path -LiteralPath $source)) { throw "staged agent missing: $source" }
    $actualHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) { throw "staged agent SHA256 mismatch: $actualHash" }
    if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
        Add-MpPreference -ExclusionPath $destination
    }
    Stop-Service -Name 'LabLink Agent' -Force -ErrorAction Stop
    (Get-Service -Name 'LabLink Agent').WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $destination) {
        Copy-Item -LiteralPath $destination -Destination $backup -Force
    }
    Remove-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue
    Move-Item -LiteralPath $source -Destination $destination -Force
    $reported = (& $destination --version 2>&1 | Out-String).Trim()
    if ($reported -notmatch [regex]::Escape($expectedVersion)) {
        throw "replacement reports '$reported', expected $expectedVersion"
    }
    Start-Service -Name 'LabLink Agent' -ErrorAction Stop
    (Get-Service -Name 'LabLink Agent').WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    Write-UpdateLog "update completed successfully"
}
catch {
    Write-UpdateLog "update failed: $($_.Exception.Message)"
    if (Test-Path -LiteralPath $backup) {
        Copy-Item -LiteralPath $backup -Destination $destination -Force
    }
    try { Start-Service -Name 'LabLink Agent' -ErrorAction SilentlyContinue } catch {}
    throw
}
`, hyperv.PSLit(expectedVersion), hyperv.PSLit(expectedHash))
}

func windowsAgentUpdateLauncher() string {
	return `$ErrorActionPreference = 'Stop'
$taskName = 'LabLinkAgentUpdate'
$scriptPath = 'C:\LabLink\update\apply-agent-update.ps1'
if (-not (Test-Path -LiteralPath $scriptPath)) { throw "update script missing: $scriptPath" }
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $scriptPath)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Write-Output 'detached Windows agent update scheduled'
`
}

func linuxAgentUpdateScript(expectedVersion, expectedHash string) string {
	return fmt.Sprintf(`#!/bin/bash
set -Eeuo pipefail
source_path=/opt/lablink/update/lablink-agent.next
destination=/opt/lablink/lablink-agent
backup=/opt/lablink/update/lablink-agent.previous
log=/var/log/lablink-agent-update.log
expected_version=%s
expected_hash=%s
exec >>"$log" 2>&1

rollback() {
    rc=$?
    echo "$(date --iso-8601=seconds) update failed with exit $rc"
    if [[ -f "$backup" ]]; then
        cp -f "$backup" "$destination"
        chmod 0755 "$destination"
    fi
    systemctl start lablink-agent.service || true
    exit "$rc"
}
trap rollback ERR

sleep 3
echo "$(date --iso-8601=seconds) starting update to $expected_version"
test -f "$source_path"
actual_hash="$(sha256sum "$source_path" | awk '{print $1}')"
[[ "$actual_hash" == "$expected_hash" ]]
chmod 0755 "$source_path"
systemctl stop lablink-agent.service
rm -f "$backup"
if [[ -f "$destination" ]]; then cp -f "$destination" "$backup"; fi
rm -f "$destination"
mv -f "$source_path" "$destination"
chmod 0755 "$destination"
reported="$("$destination" --version 2>&1)"
grep -F -- "$expected_version" <<<"$reported" >/dev/null
systemctl start lablink-agent.service
systemctl is-active --quiet lablink-agent.service
rm -f "$backup"
trap - ERR
echo "$(date --iso-8601=seconds) update completed successfully"
`, shellQuote(expectedVersion), shellQuote(expectedHash))
}

func linuxAgentUpdateLauncher() string {
	return `set -euo pipefail
command -v systemd-run >/dev/null
test -f /opt/lablink/update/lablink-agent.next
test -f /opt/lablink/update/apply-agent-update.sh
chmod 0755 /opt/lablink/update/lablink-agent.next
chmod 0700 /opt/lablink/update/apply-agent-update.sh
if systemctl is-active --quiet lablink-agent-update.service; then
    echo "another LabLink agent update is already running" >&2
    exit 1
fi
systemctl reset-failed lablink-agent-update.service 2>/dev/null || true
systemd-run --unit=lablink-agent-update --collect --no-block /bin/bash /opt/lablink/update/apply-agent-update.sh
echo "detached Linux agent update scheduled"
`
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
