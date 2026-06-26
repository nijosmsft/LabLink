package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/healthmon"
	"github.com/nijosmsft/lablink/internal/leasing"
	"github.com/nijosmsft/lablink/internal/mcptools"
	"github.com/nijosmsft/lablink/internal/ops"
	"github.com/nijosmsft/lablink/internal/portal"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/security"
	"github.com/shirou/gopsutil/v4/process"
)

var serverVersion = "v0.5.1"

func main() {
	// Handle --version before any other startup work so the call is cheap and
	// safe in automated post-install verification.
	if len(os.Args) >= 2 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("lablink-server %s\n", serverVersion)
		return
	}

	// Determine config directory.
	configDir := security.FirstPresentEnv("LABLINK_HOME", "DEVICE_INTERACTION_HOME")
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("cannot determine home dir: %v", err)
		}
		configDir = filepath.Join(home, ".lablink")
	}

	// Node registry.
	nodesFile := security.FirstPresentEnv("LABLINK_NODES", "DEVICE_INTERACTION_NODES")
	if nodesFile == "" {
		nodesFile = filepath.Join(configDir, "nodes.json")
	}
	reg := registry.Load(nodesFile)

	// Auth token.
	token, tokenSource, err := security.ResolveToken(
		"",
		"",
		[]string{"LABLINK_AGENT_TOKEN", "DEVICE_AGENT_TOKEN"},
		[]string{"LABLINK_AGENT_TOKEN_FILE"},
	)
	if err != nil {
		log.Fatalf("invalid auth token configuration: %v", err)
	}
	if token == "" {
		log.Fatalf("missing shared auth token; set LABLINK_AGENT_TOKEN or LABLINK_AGENT_TOKEN_FILE")
	}

	allowInsecure, err := security.AllowInsecure(false)
	if err != nil {
		log.Fatalf("invalid transport configuration: %v", err)
	}

	clientTransport, err := security.ResolveClientTransport(
		security.FirstPresentEnv("LABLINK_TRANSPORT"),
		allowInsecure,
		security.FirstPresentEnv("LABLINK_TLS_CA", "LABLINK_TLS_CA_CERT"),
		security.FirstPresentEnv("LABLINK_TLS_CERT", "LABLINK_TLS_CLIENT_CERT"),
		security.FirstPresentEnv("LABLINK_TLS_KEY", "LABLINK_TLS_CLIENT_KEY"),
		security.FirstPresentEnv("LABLINK_TLS_SERVER_NAME"),
	)
	if err != nil {
		log.Fatalf("invalid transport configuration: %v", err)
	}
	if clientTransport.Mode == security.TransportModeMTLS {
		if _, err := security.NewClientCredentials(clientTransport, ""); err != nil {
			log.Fatalf("invalid mTLS client credentials: %v", err)
		}
	}

	// gRPC connection pool.
	pool := agentclient.NewPool(token, clientTransport)
	defer pool.Close()
	if clientTransport.Mode == security.TransportModeInsecure {
		log.Printf("WARNING: %v", security.InsecureTransportOptInError(false))
	} else {
		log.Printf("LabLink agent transport: %s", clientTransport.Mode)
	}
	log.Printf("LabLink shared auth token: %s", tokenSource)

	// Audit log.
	auditLog := audit.NewLog(configDir)

	// Lease store (v0.4.0 M2). One SQLite file shared across every
	// lablink-server.exe on this dev box. Path honors LABLINK_HOME via
	// configDir resolution above.
	leaseDBPath := filepath.Join(configDir, "leases.db")
	leaseStore, err := leasing.OpenSQLiteStore(leaseDBPath)
	if err != nil {
		log.Fatalf("open lease store at %s: %v", leaseDBPath, err)
	}
	defer leaseStore.Close()
	log.Printf("LabLink lease store: %s", leaseDBPath)

	// Boot-time sweeper (v0.4.0 M4). Runs ONCE before tool registration so
	// the lease table reflects current reality before any agent can call
	// lease(). The breakdown distinguishes "TTL elapsed" (any host) from
	// "owning process is gone" (this host's leases only). Errors are
	// logged but do NOT fail startup — a degraded sweeper is preferable
	// to a server that won't boot.
	sweepHostname, _ := os.Hostname()
	sweepCtx, sweepCancel := context.WithTimeout(context.Background(), 30*time.Second)
	swept, err := leaseStore.Sweep(sweepCtx, sweepHostname, isProcessAlive)
	sweepCancel()
	if err != nil {
		log.Printf("WARNING: lease sweeper failed (continuing): %v", err)
	} else {
		log.Printf("lease sweeper: marked %d leases expired (%d dead-process + %d TTL)",
			swept.Total(), swept.DeadProcess, swept.TTL)
	}

	// Lease enforcement gate. Controls whether the 24 mutating tools enforce
	// lease ownership before dispatching to their handlers. Enforcement is
	// disabled by default; opt in with LABLINK_LEASE_REQUIRED=1 (or
	// true/yes/on/enabled) when one-terminal-at-a-time protection is desired.
	leaseEnabled := leaseEnforcementEnabled(security.FirstPresentEnv("LABLINK_LEASE_REQUIRED"))
	if leaseEnabled {
		log.Printf("LabLink lease enforcement: ENABLED via LABLINK_LEASE_REQUIRED (mutating tools require an active lease)")
	} else {
		log.Printf("LabLink lease enforcement: DISABLED (default; set LABLINK_LEASE_REQUIRED=1 to require leases on mutating tools)")
	}

	// Credential store.
	credsFile := filepath.Join(configDir, "credentials.json")
	creds := credentials.LoadStore(credsFile)

	// Health monitor — background keepalive for all nodes.
	monitor := healthmon.New(reg, pool)
	monitor.Start()
	defer monitor.Stop()
	mcptools.SetHealthMonitor(monitor)

	// Local operations portal (per-process). Disable with LABLINK_PORTAL=disabled.
	if !strings.EqualFold(security.FirstPresentEnv("LABLINK_PORTAL"), "disabled") {
		opsReg := ops.NewRegistry(200)
		mcptools.SetOpsRegistry(opsReg)
		listenAddr := security.FirstPresentEnv("LABLINK_PORTAL_ADDR")
		if listenAddr == "" {
			listenAddr = "127.0.0.1:0"
		}
		p, err := portal.New(opsReg, reg, pool, listenAddr)
		if err != nil {
			log.Printf("LabLink portal disabled: %v", err)
		} else {
			mcptools.SetPortalURL(p.URL())
			log.Printf("LabLink portal: %s", p.URL())
		}
	}

	// MCP server.
	s := server.NewMCPServer(
		"lablink",
		serverVersion,
		server.WithToolCapabilities(true),
		server.WithInstructions(`Remote device management for test automation.

Use save_credential to store WinRM credentials, then deploy_agent to install agents on new machines.
Use register_node to add test machines, then execute_command to run commands on them.
For multi-node operations, use register_topology to define node groups, then execute_on_role.
Use set_node_context to avoid repeating working_dir and env vars on every command.
Use get_history to recall previously executed commands.
Use patch_binary to replace protected Windows system binaries (e.g., a kernel driver) using a replace-utility the operator supplies via SFPCOPY_SOURCE.
Use ensure_test_signing to enable test signing, and reboot_node to reboot machines.
Use export_nodes / import_nodes to save/restore the node registry as YAML.

ANTI-PATTERNS — DO NOT do these things:
- DO NOT call reboot_node in a loop to reboot multiple nodes. Each call
  serially waits the full wait_seconds for one node, so a loop of N nodes
  blocks for N * wait_seconds wall-clock time. Use reboot_nodes(nodes=[...])
  instead — it kicks every node in parallel and waits ONCE for the fleet to
  recover, so total time is bounded by the slowest single reboot.
- DO NOT call execute_command in a loop across many nodes when every node
  runs the same command. Use execute_on_role with a topology so the
  commands fan out in parallel and finish in roughly the time of the
  slowest single node, not N * single-node time.
- DO NOT call ping_nodes inside a loop to check individual nodes — it
  already pings every registered node in parallel in one call.`),
	)

	// Lease-gate config — passed to every Register* that wraps mutating tools.
	leaseCfg := mcptools.LeaseGateConfig{
		Store:    leaseStore,
		Registry: reg,
		Enabled:  leaseEnabled,
	}

	// Register all tools.
	mcptools.RegisterInventory(s, reg, pool)
	mcptools.RegisterExecute(s, reg, pool, auditLog, leaseCfg)
	mcptools.RegisterTransfer(s, reg, pool, leaseCfg)
	mcptools.RegisterProcess(s, reg, pool, leaseCfg)
	mcptools.RegisterTopology(s, reg)
	mcptools.RegisterContext(s, reg, leaseCfg)
	mcptools.RegisterMultiNode(s, reg, pool, auditLog, leaseCfg)
	mcptools.RegisterHistory(s, auditLog)
	mcptools.RegisterDeploy(s, reg, pool, creds, token)
	mcptools.RegisterImportExport(s, reg)
	mcptools.RegisterNodeOps(s, reg, pool, leaseCfg)
	mcptools.RegisterSchedule(s, reg, pool, auditLog, leaseCfg)
	mcptools.RegisterDiagnostics(s, reg, pool, auditLog, leaseCfg)
	mcptools.RegisterPackage(s, reg, pool, leaseCfg)
	patchCfg := mcptools.NewPatchConfig(configDir)
	mcptools.RegisterPatch(s, reg, pool, auditLog, patchCfg, leaseCfg)
	mcptools.RegisterJobs(s, reg, pool, leaseCfg)
	mcptools.RegisterPortal(s)
	mcptools.RegisterForward(s, reg, pool, leaseCfg)
	mcptools.RegisterLeasing(s, reg, leaseStore)
	mcptools.RegisterVM(s, reg, pool, creds, auditLog, leaseCfg)

	// Run with stdio transport.
	if err := server.ServeStdio(s); err != nil && !isExpectedStdioShutdownError(err) {
		log.Fatalf("MCP server failed: %v", err)
	}
}

// leaseEnforcementEnabled reports whether the LABLINK_LEASE_REQUIRED env var
// explicitly opts in to lease enforcement. Any other value, including empty or
// unset, leaves enforcement disabled.
func leaseEnforcementEnabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	}
	return false
}

// isProcessAlive is the live-process probe passed to leaseStore.Sweep. It
// returns true when a process with the given pid exists AND (when the
// stored process_start_unix is non-zero) the live process's create time
// matches within +/- 2 seconds — guards against PID reuse where a brand-
// new process happens to take the recycled pid of a crashed lease owner.
//
// On gopsutil errors (permission denied, etc.) the probe returns true to
// stay conservative: never expire a lease we can't actually confirm dead.
func isProcessAlive(pid int, startUnix int64) bool {
	if pid <= 0 {
		return false
	}
	exists, err := process.PidExists(int32(pid))
	if err != nil {
		return true // unknown -> assume alive
	}
	if !exists {
		return false
	}
	if startUnix == 0 {
		return true
	}
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return true
	}
	createMs, err := p.CreateTime()
	if err != nil {
		return true
	}
	createUnix := createMs / 1000
	delta := createUnix - startUnix
	if delta < 0 {
		delta = -delta
	}
	return delta <= 2
}
