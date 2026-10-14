package mcptools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/registry"
	pb "github.com/nijosmsft/lablink/proto/agent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
			mcp.WithDescription("Reboot a single Windows or Linux node and verify its authenticated agent returns with a changed boot identity."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithNumber("wait_seconds", mcp.Description("Max seconds to wait, default 120")),
		),
		LeaseGate(leaseCfg, extractSingleNode("node"), rebootNodeHandler(reg, pool, auditLog)),
	)

	addTool(s,
		mcp.NewTool("reboot_nodes",
			mcp.WithDescription("Reboot Windows and Linux nodes in parallel and verify their authenticated agents return with changed boot identities."),
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
		plan, err := newRebootPlan(node)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		var doneAtomic atomic.Int64
		stop := StartMCPHeartbeat(ctx, request, defaultHeartbeatInterval, func() (int64, int64) {
			return doneAtomic.Load(), 1
		})
		defer stop()

		statuses := rebootNodes(ctx, pool, auditLog, "reboot_node", []*rebootPlan{plan}, waitSec, func() {
			doneAtomic.Store(1)
		})
		s := statuses[0]
		if s.KickErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to initiate reboot on %s: %v", nodeName, s.KickErr)), nil
		}
		if s.IdentityChanged {
			offline := "without a sampled offline interval"
			if s.WentDown {
				offline = fmt.Sprintf("after going offline at %s", s.DownAfter.Round(time.Second))
			}
			return mcp.NewToolResultText(fmt.Sprintf(
				"**%s** rebooted; authenticated agent recovered with a changed boot identity after %s (%s).",
				nodeName, s.WallTime.Round(time.Second), offline,
			)), nil
		}
		if s.LastIdentityErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf(
				"%s became reachable after reboot initiation, but its boot identity could not be validated within %ds: %v",
				nodeName, waitSec, s.LastIdentityErr,
			)), nil
		}
		if s.AuthenticatedRecovery {
			return mcp.NewToolResultError(fmt.Sprintf(
				"reboot not observed for %s within %ds: the authenticated agent remained reachable with the same boot identity",
				nodeName, waitSec,
			)), nil
		}
		if s.WentDown {
			return mcp.NewToolResultError(fmt.Sprintf(
				"%s went offline after %s but did not return with an authenticated agent within %ds",
				nodeName, s.DownAfter.Round(time.Second), waitSec,
			)), nil
		}
		return mcp.NewToolResultError(fmt.Sprintf(
			"reboot not observed for %s within %ds: no changed boot identity or authenticated recovery was observed",
			nodeName, waitSec,
		)), nil
	}
}

type rebootPlan struct {
	node            *registry.Node
	command         string
	shell           string
	identityCommand string
	identityShell   string
	initialIdentity string
}

const (
	windowsRebootCommand = "shutdown /r /t 2 /f"
	linuxRebootCommand   = "systemctl reboot"
	windowsBootIDCommand = `$boot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime; if ($null -eq $boot) { exit 2 }; $boot.ToUniversalTime().ToString('o')`
	linuxBootIDCommand   = "cat /proc/sys/kernel/random/boot_id"
)

var linuxBootIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func newRebootPlan(node *registry.Node) (*rebootPlan, error) {
	plan := &rebootPlan{node: node}
	switch strings.ToLower(strings.TrimSpace(node.OS)) {
	case "windows":
		plan.command = windowsRebootCommand
		plan.shell = "cmd"
		plan.identityCommand = windowsBootIDCommand
		plan.identityShell = "powershell"
	case "linux":
		plan.command = linuxRebootCommand
		plan.shell = "bash"
		plan.identityCommand = linuxBootIDCommand
		plan.identityShell = "bash"
	default:
		return nil, fmt.Errorf(
			"unsupported OS %q for node %q (expected windows or linux); refusing to initiate reboot",
			node.OS, node.Name,
		)
	}
	return plan, nil
}

func normalizeBootIdentity(plan *rebootPlan, output string) (string, error) {
	value := strings.TrimSpace(output)
	if value == "" {
		return "", fmt.Errorf("empty boot identity returned by %s", plan.node.Name)
	}
	if len(strings.Fields(value)) != 1 {
		return "", fmt.Errorf("malformed boot identity %q returned by %s", value, plan.node.Name)
	}
	switch plan.identityShell {
	case "powershell":
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return "", fmt.Errorf("malformed Windows last-boot timestamp %q returned by %s: %w", value, plan.node.Name, err)
		}
		return parsed.UTC().Format(time.RFC3339Nano), nil
	case "bash":
		if !linuxBootIDPattern.MatchString(value) {
			return "", fmt.Errorf("malformed Linux boot_id %q returned by %s", value, plan.node.Name)
		}
		return strings.ToLower(value), nil
	default:
		return "", fmt.Errorf("unsupported boot identity shell %q", plan.identityShell)
	}
}

func readBootIdentity(ctx context.Context, pool *agentclient.Pool, plan *rebootPlan, reset bool) (identity string, authenticated bool, err error) {
	if reset {
		pool.ResetConnection(plan.node.Address)
	}
	client, err := pool.GetClient(plan.node.Address, plan.node.TLSServerName)
	if err != nil {
		return "", false, fmt.Errorf("connect: %w", err)
	}

	probeCtx, cancel := context.WithTimeout(ctx, rebootNodesConnectTimeout)
	defer cancel()
	if _, err := client.GetInfo(probeCtx, &pb.GetInfoRequest{}); err != nil {
		return "", false, fmt.Errorf("authenticated probe: %w", err)
	}
	authenticated = true

	identityCtx, identityCancel := context.WithTimeout(ctx, 5*time.Second)
	defer identityCancel()
	output, exitCode, _, err := executeAndCollect(identityCtx, client, plan.identityCommand, plan.identityShell, "", nil, 5)
	if err != nil {
		return "", true, fmt.Errorf("capture boot identity: %w", err)
	}
	if exitCode != 0 {
		return "", true, fmt.Errorf("capture boot identity exited %d: %s", exitCode, strings.TrimSpace(output))
	}
	identity, err = normalizeBootIdentity(plan, output)
	if err != nil {
		return "", true, err
	}
	return identity, true, nil
}

func isExpectedRebootDisconnect(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	return status.Code(err) == codes.Unavailable
}

func initiateReboot(ctx context.Context, client pb.NodeAgentClient, plan *rebootPlan) error {
	stream, err := client.Execute(ctx, &pb.ExecuteRequest{
		Command:        plan.command,
		Shell:          plan.shell,
		TimeoutSeconds: 5,
	})
	if err != nil {
		return fmt.Errorf("launch reboot command: %w", err)
	}

	var output strings.Builder
	pid := 0
	for {
		resp, recvErr := stream.Recv()
		if recvErr != nil {
			if pid > 0 && isExpectedRebootDisconnect(recvErr) && ctx.Err() == nil {
				return nil
			}
			return fmt.Errorf("reboot command stream ended before successful completion (pid=%d): %w", pid, recvErr)
		}
		if resp.Pid != 0 && pid == 0 {
			pid = int(resp.Pid)
		}
		if len(resp.Data) > 0 {
			output.Write(resp.Data)
		}
		if !resp.Done {
			continue
		}
		if resp.ExitCode != 0 {
			return fmt.Errorf("reboot command exited %d: %s", resp.ExitCode, strings.TrimSpace(output.String()))
		}
		if pid == 0 {
			return fmt.Errorf("reboot command reported success without launch evidence")
		}
		return nil
	}
}

// rebootNodeStatus tracks the result of a single node within a reboot_nodes call.
type rebootNodeStatus struct {
	NodeName              string
	Kicked                bool
	KickErr               error
	WentDown              bool
	DownAfter             time.Duration
	AuthenticatedRecovery bool
	IdentityChanged       bool
	LastIdentityErr       error
	WallTime              time.Duration
}

type rebootWaitState struct {
	consecutiveFailures int
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
		plans := make([]*rebootPlan, 0, len(names))
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
			plan, err := newRebootPlan(node)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			plans = append(plans, plan)
		}
		if len(unknown) > 0 {
			return mcp.NewToolResultError(fmt.Sprintf(
				"unknown node(s): %s — refusing to kick any reboot (validation is atomic)",
				strings.Join(unknown, ", "))), nil
		}

		var doneAtomic atomic.Int64
		stop := StartMCPHeartbeat(ctx, request, defaultHeartbeatInterval, func() (int64, int64) {
			return doneAtomic.Load(), int64(len(plans))
		})
		defer stop()

		statuses := rebootNodes(ctx, pool, auditLog, "reboot_nodes", plans, waitSec, func() {
			doneAtomic.Add(1)
		})

		return mcp.NewToolResultText(renderRebootNodesTable(statuses, waitSec)), nil
	}
}

func rebootNodes(ctx context.Context, pool *agentclient.Pool, auditLog *audit.Log, auditTool string, plans []*rebootPlan, waitSec int, nodeDone func()) []rebootNodeStatus {
	statuses := make([]rebootNodeStatus, len(plans))
	starts := make([]time.Time, len(plans))
	for i, plan := range plans {
		statuses[i].NodeName = plan.node.Name
	}

	// Preflight every boot identity before mutating any node.
	var preflightWG sync.WaitGroup
	for i, plan := range plans {
		preflightWG.Add(1)
		go func(idx int, p *rebootPlan) {
			defer preflightWG.Done()
			identity, _, err := readBootIdentity(ctx, pool, p, false)
			if err != nil {
				statuses[idx].KickErr = fmt.Errorf("capture initial boot identity: %w", err)
				return
			}
			p.initialIdentity = identity
		}(i, plan)
	}
	preflightWG.Wait()
	for i := range statuses {
		if statuses[i].KickErr != nil {
			// Preserve atomic fleet behavior: no reboot is initiated if any
			// node cannot complete the read-only preflight.
			for j := range statuses {
				if j != i && statuses[j].KickErr == nil {
					statuses[j].KickErr = fmt.Errorf("reboot not initiated because another node failed preflight")
				}
			}
			return statuses
		}
	}

	var kickWG sync.WaitGroup
	for i, plan := range plans {
		kickWG.Add(1)
		go func(idx int, p *rebootPlan) {
			defer kickWG.Done()
			client, err := pool.GetClient(p.node.Address, p.node.TLSServerName)
			if err != nil {
				statuses[idx].KickErr = fmt.Errorf("connect: %w", err)
				return
			}
			if err := initiateReboot(ctx, client, p); err != nil {
				statuses[idx].KickErr = err
				return
			}
			statuses[idx].Kicked = true
		}(i, plan)
	}
	kickWG.Wait()

	now := timeNow()
	for i := range starts {
		starts[i] = now
	}
	for i, plan := range plans {
		entry := audit.Entry{
			Timestamp: timeNow(),
			Node:      plan.node.Name,
			Tool:      auditTool,
			Command:   plan.command,
		}
		if statuses[i].KickErr != nil {
			entry.ExitCode = -1
		}
		auditLog.Append(entry)
	}

	deadline := now.Add(time.Duration(waitSec) * time.Second)
	waitCtx, cancelWait := context.WithDeadline(ctx, deadline)
	defer cancelWait()
	select {
	case <-waitCtx.Done():
	case <-time.After(rebootNodesInitialDownSleep):
	}

	waitStates := make([]rebootWaitState, len(plans))
	pending := make([]int, 0, len(plans))
	for i := range plans {
		if statuses[i].Kicked {
			pending = append(pending, i)
		}
	}

	for len(pending) > 0 && time.Now().Before(deadline) && waitCtx.Err() == nil {
		type probeResult struct {
			identity      string
			authenticated bool
			err           error
		}
		results := make([]probeResult, len(pending))
		var pollWG sync.WaitGroup
		for j, idx := range pending {
			pollWG.Add(1)
			go func(resultIndex, planIndex int) {
				defer pollWG.Done()
				results[resultIndex].identity, results[resultIndex].authenticated, results[resultIndex].err =
					readBootIdentity(waitCtx, pool, plans[planIndex], true)
			}(j, idx)
		}
		pollWG.Wait()

		stillPending := pending[:0]
		for j, idx := range pending {
			result := results[j]
			if result.authenticated {
				statuses[idx].AuthenticatedRecovery = true
				waitStates[idx].consecutiveFailures = 0
				if result.err != nil {
					statuses[idx].LastIdentityErr = result.err
					stillPending = append(stillPending, idx)
					continue
				}
				statuses[idx].LastIdentityErr = nil
				if result.identity != plans[idx].initialIdentity {
					if hmon != nil {
						hmon.RecordAuthenticatedProbeSuccess(plans[idx].node)
					}
					statuses[idx].IdentityChanged = true
					statuses[idx].WallTime = time.Since(starts[idx])
					nodeDone()
					continue
				}
				stillPending = append(stillPending, idx)
				continue
			}

			waitStates[idx].consecutiveFailures++
			if waitStates[idx].consecutiveFailures >= rebootNodesDownConfirmations && !statuses[idx].WentDown {
				statuses[idx].WentDown = true
				statuses[idx].DownAfter = time.Since(starts[idx])
			}
			stillPending = append(stillPending, idx)
		}
		pending = stillPending
		if len(pending) == 0 {
			break
		}
		select {
		case <-waitCtx.Done():
		case <-time.After(rebootNodesPollInterval):
		}
	}

	for i := range statuses {
		if !statuses[i].IdentityChanged && statuses[i].WallTime == 0 {
			statuses[i].WallTime = time.Since(starts[i])
		}
	}
	return statuses
}

func renderRebootNodesTable(statuses []rebootNodeStatus, waitSec int) string {
	kicked, down, recovered, changed := 0, 0, 0, 0
	for _, s := range statuses {
		if s.Kicked {
			kicked++
		}
		if s.WentDown {
			down++
		}
		if s.AuthenticatedRecovery {
			recovered++
		}
		if s.IdentityChanged {
			changed++
		}
	}
	headline := "Reboot incomplete"
	if kicked == len(statuses) && changed == len(statuses) {
		headline = "All nodes rebooted and authenticated"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(
		"**%s** (%d/%d kicked, %d/%d sampled offline, %d/%d authenticated, %d/%d boot identities changed)\n\n",
		headline, kicked, len(statuses), down, len(statuses), recovered, len(statuses), changed, len(statuses),
	))
	sb.WriteString("| Node | Reboot kicked? | Sampled offline? | Authenticated recovery? | Boot identity changed? | Wall time |\n")
	sb.WriteString("|---|---|---|---|---|---|\n")
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
				downCol = "no (not required)"
			} else {
				downCol = "n/a"
			}
		} else {
			downCol = fmt.Sprintf("yes (after %s)", s.DownAfter.Round(time.Second))
		}
		recoveryCol := "yes"
		if !s.AuthenticatedRecovery {
			if s.Kicked {
				if s.WentDown {
					recoveryCol = fmt.Sprintf("NO (offline; timeout %ds)", waitSec)
				} else {
					recoveryCol = fmt.Sprintf("NO (timeout %ds)", waitSec)
				}
			} else {
				recoveryCol = "n/a"
			}
		}
		identityCol := "yes"
		if !s.IdentityChanged {
			switch {
			case !s.Kicked:
				identityCol = "n/a"
			case s.LastIdentityErr != nil:
				identityCol = fmt.Sprintf("NO (%v)", s.LastIdentityErr)
			case s.AuthenticatedRecovery:
				identityCol = "NO (same identity; reboot not observed)"
			default:
				identityCol = "NO (not available)"
			}
		}
		sb.WriteString(fmt.Sprintf(
			"| %s | %s | %s | %s | %s | %s |\n",
			s.NodeName, kickCol, downCol, recoveryCol, identityCol, s.WallTime.Round(time.Second),
		))
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
