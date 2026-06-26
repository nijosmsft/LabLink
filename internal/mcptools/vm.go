package mcptools

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/hyperv/unattend"
	"github.com/nijosmsft/lablink/internal/registry"
)

// vmDefaultTimeoutSec bounds the Hyper-V PowerShell calls. Discovery is quick;
// mutations (New-VM, differencing-disk + mount injection) can take a while but
// are not the multi-minute clean-install path (deferred). 0 would mean "no
// timeout" on both target paths.
const vmDefaultTimeoutSec = 600

// passwordMask is the redaction placeholder used everywhere a password would
// otherwise appear (ops args, audit, tool results).
const passwordMask = "***"

// RegisterVM wires the Phase-1 Hyper-V VM-management primitives. Discovery
// tools are ungated; mutating tools are lease-gated on the resolved target
// (local target => no lease; remote node => lease required). The orchestrator
// create_windows_vm is deliberately DEFERRED (primitives-first, OQ-5).
func RegisterVM(s *server.MCPServer, reg *registry.Registry, pool *agentclient.Pool, creds *credentials.Store, auditLog *audit.Log, leaseCfg LeaseGateConfig) {
	// list_physical_nics — discovery, read-only, ungated.
	s.AddTool(
		mcp.NewTool("list_physical_nics",
			mcp.WithDescription("List physical NICs on a target (localhost or node), flagging the management NIC that carries LabLink/host connectivity and which NICs are safe for an external vSwitch."),
			mcp.WithString("target", mcp.Description("localhost (default) or a registered node name")),
			mcp.WithBoolean("include_virtual", mcp.Description("Include virtual/vEthernet adapters (default false)")),
		),
		listPhysicalNicsHandler(reg, pool),
	)

	// list_vswitches — discovery, read-only, ungated.
	s.AddTool(
		mcp.NewTool("list_vswitches",
			mcp.WithDescription("List Hyper-V virtual switches on a target (localhost or node)."),
			mcp.WithString("target", mcp.Description("localhost (default) or a registered node name")),
		),
		listVSwitchesHandler(reg, pool),
	)

	// create_vswitch — mutating, lease-gated, management-NIC safeguard.
	s.AddTool(
		mcp.NewTool("create_vswitch",
			mcp.WithDescription("Create (or reuse/replace) a Hyper-V virtual switch. On a remote target, an external switch on the management NIC is BLOCKED unless allow_management_nic_disruption=true (it can sever the agent connection)."),
			mcp.WithString("target", mcp.Description("localhost (default) or a registered node name")),
			mcp.WithString("name", mcp.Required(), mcp.Description("vSwitch name")),
			mcp.WithString("type", mcp.Required(), mcp.Description("external | internal | private")),
			mcp.WithString("net_adapter", mcp.Description("Physical NIC name (required when type=external)")),
			mcp.WithBoolean("allow_management_os", mcp.Description("Keep host connectivity on an external switch (default true)")),
			mcp.WithBoolean("allow_management_nic_disruption", mcp.Description("Override the management-NIC severance safeguard on a remote target (default false)")),
			mcp.WithString("if_exists", mcp.Description("reuse (default) | fail | replace")),
		),
		LeaseGate(leaseCfg, extractTarget("target"), createVSwitchHandler(reg, pool, auditLog)),
	)

	// create_vm — mutating, lease-gated.
	s.AddTool(
		mcp.NewTool("create_vm",
			mcp.WithDescription("Create a Gen2 Hyper-V Windows VM with secure boot, deterministic DVD boot, optional dynamic memory, and path/free-space validation."),
			mcp.WithString("target", mcp.Description("localhost (default) or a registered node name")),
			mcp.WithString("name", mcp.Required(), mcp.Description("VM name")),
			mcp.WithString("vm_location", mcp.Description("Folder for VM config; required unless use_host_defaults=true")),
			mcp.WithBoolean("use_host_defaults", mcp.Description("Permit the Hyper-V host default VM location (default false)")),
			mcp.WithString("vhd_path", mcp.Description("Path to an existing VHDX to attach")),
			mcp.WithString("new_vhd_path", mcp.Description("Path for a new VHDX")),
			mcp.WithNumber("new_vhd_size_gb", mcp.Description("Size of the new VHDX in GB")),
			mcp.WithNumber("memory_mb", mcp.Description("Startup memory MB (default 4096)")),
			mcp.WithBoolean("dynamic_memory", mcp.Description("Enable dynamic memory (default false)")),
			mcp.WithNumber("dynamic_min_mb", mcp.Description("Dynamic memory minimum MB")),
			mcp.WithNumber("dynamic_max_mb", mcp.Description("Dynamic memory maximum MB")),
			mcp.WithNumber("dynamic_buffer_pct", mcp.Description("Dynamic memory buffer percentage")),
			mcp.WithNumber("cpu_count", mcp.Description("vCPU count (default 2)")),
			mcp.WithString("vswitch", mcp.Description("vSwitch to attach the primary NIC to")),
			mcp.WithString("iso_path", mcp.Description("Windows install ISO to attach as DVD and set as first boot device")),
			mcp.WithBoolean("secure_boot", mcp.Description("Gen2 Secure Boot with MicrosoftWindows template (default true)")),
			mcp.WithNumber("required_free_gb", mcp.Description("Extra free-space requirement in GB on the new VHD volume")),
		),
		LeaseGate(leaseCfg, extractTarget("target"), createVMHandler(reg, pool, auditLog)),
	)

	// provision_unattend — mutating, lease-gated.
	s.AddTool(
		mcp.NewTool("provision_unattend",
			mcp.WithDescription("Generate an unattend answer file and inject it into a VM's OS disk (Method A: differencing-disk + mount). Method B clean-install ISO is deferred. Password is redacted in all output; first-boot scrub of Panther/UnattendGC/AutoLogon is baked in."),
			mcp.WithString("target", mcp.Description("localhost (default) or a registered node name")),
			mcp.WithString("vm_name", mcp.Required(), mcp.Description("VM to provision (used as default hostname)")),
			mcp.WithString("hostname", mcp.Description("Guest computer name (default = vm_name)")),
			mcp.WithString("admin_password", mcp.Description("Local Administrator password (prefer admin_password_credential)")),
			mcp.WithString("admin_password_credential", mcp.Description("Name of a saved credential profile to source the admin password from (preferred)")),
			mcp.WithString("locale", mcp.Description("Locale, e.g. en-US (default en-US)")),
			mcp.WithString("timezone", mcp.Description("Time zone, e.g. 'Pacific Standard Time'")),
			mcp.WithString("product_key", mcp.Description("Optional product key")),
			mcp.WithString("first_boot_script", mcp.Description("Inline PowerShell run once at first logon")),
			mcp.WithBoolean("auto_logon", mcp.Description("Enable one-time AutoLogon (AutoLogonCount=1, then scrubbed) (default false)")),
			mcp.WithBoolean("obfuscate_password", mcp.Description("Use Windows answer-file base64 obfuscation (NOT encryption) (default false)")),
			mcp.WithString("injection_method", mcp.Description("mount-vhd (default) | autounattend-iso (deferred)")),
			mcp.WithString("vhd_path", mcp.Required(), mcp.Description("OS disk to inject into (or differencing-child path when base_vhd is set)")),
			mcp.WithString("base_vhd", mcp.Description("Shared sysprepped base VHDX; a differencing child is created at vhd_path and the base is never mutated")),
		),
		LeaseGate(leaseCfg, extractTarget("target"), provisionUnattendHandler(reg, pool, creds, auditLog)),
	)
}

// --- result formatting -----------------------------------------------------

// vmResult renders the agreed chainable-tool convention: a human-readable
// markdown header plus a single fenced ```json block (the parsed/validated
// payload), last in the response, never containing secrets.
func vmResult(header string, jsonBody string) *mcp.CallToolResult {
	var sb strings.Builder
	sb.WriteString(header)
	sb.WriteString("\n\n```json\n")
	sb.WriteString(strings.TrimSpace(jsonBody))
	sb.WriteString("\n```\n")
	return mcp.NewToolResultText(sb.String())
}

// --- handlers --------------------------------------------------------------

func listPhysicalNicsHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t, err := resolveTarget(req, reg)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		includeVirtual := req.GetBool("include_virtual", false)

		ctx, op := beginOp(ctx, "list_physical_nics", t.Name, "discover NICs", map[string]string{
			"target": t.Name, "include_virtual": fmt.Sprintf("%t", includeVirtual),
		})
		var opErr error
		defer func() { op.Done(opErr) }()

		script := hyperv.BuildListNicsScript(includeVirtual, targetMgmtIP(t))
		out, _, err := runPS(ctx, reg, pool, t, script, vmDefaultTimeoutSec)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(err.Error()), nil
		}
		nics, perr := hyperv.ParseNICs(out)
		if perr != nil {
			opErr = perr
			return mcp.NewToolResultError(fmt.Sprintf("parse NICs: %v\nraw:\n%s", perr, out)), nil
		}
		mgmt := ""
		for _, n := range nics {
			if n.IsManagementNIC {
				mgmt = n.Name
				break
			}
		}
		header := fmt.Sprintf("**Physical NICs on `%s`** — %d found", t.Name, len(nics))
		if mgmt != "" {
			header += fmt.Sprintf(" — ⚠️ management NIC: `%s` (avoid binding an external vSwitch to it)", mgmt)
		}
		return vmResult(header, jsonExtract(out)), nil
	}
}

func listVSwitchesHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t, err := resolveTarget(req, reg)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		ctx, op := beginOp(ctx, "list_vswitches", t.Name, "discover vSwitches", map[string]string{"target": t.Name})
		var opErr error
		defer func() { op.Done(opErr) }()

		out, _, err := runPS(ctx, reg, pool, t, hyperv.BuildListVSwitchesScript(), vmDefaultTimeoutSec)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(err.Error()), nil
		}
		sws, perr := hyperv.ParseVSwitches(out)
		if perr != nil {
			opErr = perr
			return mcp.NewToolResultError(fmt.Sprintf("parse vSwitches: %v\nraw:\n%s", perr, out)), nil
		}
		header := fmt.Sprintf("**Hyper-V vSwitches on `%s`** — %d found", t.Name, len(sws))
		return vmResult(header, jsonExtract(out)), nil
	}
}

func createVSwitchHandler(reg *registry.Registry, pool *agentclient.Pool, auditLog *audit.Log) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t, err := resolveTarget(req, reg)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		p := hyperv.CreateVSwitchParams{
			Name:                req.GetString("name", ""),
			Type:                req.GetString("type", ""),
			NetAdapter:          req.GetString("net_adapter", ""),
			AllowManagementOS:   req.GetBool("allow_management_os", true),
			IfExists:            req.GetString("if_exists", "reuse"),
			IsRemote:            !t.IsLocal,
			AllowMgmtDisruption: req.GetBool("allow_management_nic_disruption", false),
			MgmtIP:              targetMgmtIP(t),
		}

		ctx, op := beginOp(ctx, "create_vswitch", t.Name, fmt.Sprintf("create vSwitch %s (%s)", p.Name, p.Type), map[string]string{
			"target": t.Name, "name": p.Name, "type": p.Type, "net_adapter": p.NetAdapter,
			"if_exists": p.IfExists, "allow_management_nic_disruption": fmt.Sprintf("%t", p.AllowMgmtDisruption),
		})
		var opErr error
		defer func() { op.Done(opErr) }()

		script, berr := hyperv.BuildCreateVSwitchScript(p)
		if berr != nil {
			opErr = berr
			return mcp.NewToolResultError(berr.Error()), nil
		}
		start := time.Now()
		out, exit, rerr := runPS(ctx, reg, pool, t, script, vmDefaultTimeoutSec)
		auditLog.Append(audit.Entry{
			Timestamp: start, Node: t.Name, Tool: "create_vswitch",
			Command: fmt.Sprintf("create_vswitch name=%s type=%s net_adapter=%s", p.Name, p.Type, p.NetAdapter),
			Shell:   "powershell", ExitCode: exit, DurationMs: time.Since(start).Milliseconds(),
		})
		if rerr != nil {
			opErr = rerr
			return mcp.NewToolResultError(rerr.Error()), nil
		}
		header := fmt.Sprintf("**vSwitch `%s` ready on `%s`**", p.Name, t.Name)
		return vmResult(header, jsonExtract(out)), nil
	}
}

func createVMHandler(reg *registry.Registry, pool *agentclient.Pool, auditLog *audit.Log) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t, err := resolveTarget(req, reg)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		p := hyperv.CreateVMParams{
			Name:                req.GetString("name", ""),
			VMLocation:          req.GetString("vm_location", ""),
			UseHostDefaults:     req.GetBool("use_host_defaults", false),
			VHDPath:             req.GetString("vhd_path", ""),
			NewVHDPath:          req.GetString("new_vhd_path", ""),
			NewVHDSizeGB:        req.GetFloat("new_vhd_size_gb", 0),
			MemoryMB:            req.GetFloat("memory_mb", 4096),
			DynamicMemory:       req.GetBool("dynamic_memory", false),
			DynamicMinMB:        req.GetFloat("dynamic_min_mb", 0),
			DynamicMaxMB:        req.GetFloat("dynamic_max_mb", 0),
			DynamicBufferPct:    req.GetFloat("dynamic_buffer_pct", 0),
			CPUCount:            req.GetFloat("cpu_count", 2),
			VSwitch:             req.GetString("vswitch", ""),
			ISOPath:             req.GetString("iso_path", ""),
			SecureBoot:          req.GetBool("secure_boot", true),
			RequiredFreeSpaceGB: req.GetFloat("required_free_gb", 0),
		}

		ctx, op := beginOp(ctx, "create_vm", t.Name, fmt.Sprintf("create VM %s", p.Name), map[string]string{
			"target": t.Name, "name": p.Name, "vswitch": p.VSwitch, "iso_path": p.ISOPath,
		})
		var opErr error
		defer func() { op.Done(opErr) }()

		script, berr := hyperv.BuildCreateVMScript(p)
		if berr != nil {
			opErr = berr
			return mcp.NewToolResultError(berr.Error()), nil
		}
		start := time.Now()
		out, exit, rerr := runPS(ctx, reg, pool, t, script, vmDefaultTimeoutSec)
		auditLog.Append(audit.Entry{
			Timestamp: start, Node: t.Name, Tool: "create_vm",
			Command: fmt.Sprintf("create_vm name=%s vswitch=%s", p.Name, p.VSwitch),
			Shell:   "powershell", ExitCode: exit, DurationMs: time.Since(start).Milliseconds(),
		})
		if rerr != nil {
			opErr = rerr
			return mcp.NewToolResultError(rerr.Error()), nil
		}
		header := fmt.Sprintf("**VM `%s` created on `%s`**", p.Name, t.Name)
		return vmResult(header, jsonExtract(out)), nil
	}
}

func provisionUnattendHandler(reg *registry.Registry, pool *agentclient.Pool, creds *credentials.Store, auditLog *audit.Log) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t, err := resolveTarget(req, reg)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		vmName := req.GetString("vm_name", "")
		if strings.TrimSpace(vmName) == "" {
			return mcp.NewToolResultError("vm_name is required"), nil
		}
		hostname := req.GetString("hostname", vmName)
		method := strings.TrimSpace(req.GetString("injection_method", string(unattend.MethodMountVHD)))
		vhdPath := req.GetString("vhd_path", "")
		baseVhd := req.GetString("base_vhd", "")

		// Resolve the admin password: prefer a saved credential profile; never
		// log/return the plaintext.
		password, perr := resolveAdminPassword(req, creds)
		if perr != nil {
			return mcp.NewToolResultError(perr.Error()), nil
		}

		// beginOp/audit MUST never receive the raw password.
		ctx, op := beginOp(ctx, "provision_unattend", t.Name, fmt.Sprintf("provision %s", vmName), map[string]string{
			"target": t.Name, "vm_name": vmName, "hostname": hostname,
			"injection_method": method, "vhd_path": vhdPath, "base_vhd": baseVhd,
			"admin_password": passwordMask,
		})
		var opErr error
		defer func() { op.Done(opErr) }()

		if method == string(unattend.MethodAutoUnattendISO) {
			_, berr := unattend.BuildIsoInjectScript(unattend.MountInjectParams{})
			opErr = berr
			return mcp.NewToolResultError(berr.Error()), nil
		}
		if method != string(unattend.MethodMountVHD) {
			opErr = fmt.Errorf("invalid injection_method %q", method)
			return mcp.NewToolResultError(opErr.Error()), nil
		}
		if strings.TrimSpace(vhdPath) == "" {
			opErr = fmt.Errorf("vhd_path is required for mount-vhd injection")
			return mcp.NewToolResultError(opErr.Error()), nil
		}

		// Render the answer file (password lives only in memory + the staged file).
		xml, rerr := unattend.Render(unattend.Params{
			Hostname:        hostname,
			AdminPassword:   password,
			Locale:          req.GetString("locale", "en-US"),
			TimeZone:        req.GetString("timezone", ""),
			ProductKey:      req.GetString("product_key", ""),
			FirstBootScript: req.GetString("first_boot_script", ""),
			AutoLogon:       req.GetBool("auto_logon", false),
			Obfuscate:       req.GetBool("obfuscate_password", false),
		})
		if rerr != nil {
			opErr = rerr
			return mcp.NewToolResultError(rerr.Error()), nil
		}

		// Stage the answer file (and optional first-boot script) locally, push to
		// the target, then ALWAYS scrub the local staged copies.
		localUnattend, cleanupLocal, serr := stageSecretFile(xml, "lablink-unattend-*.xml")
		if serr != nil {
			opErr = serr
			return mcp.NewToolResultError(serr.Error()), nil
		}
		defer cleanupLocal()

		stamp := time.Now().UnixNano()
		remoteUnattend := fmt.Sprintf(`C:\Windows\Temp\lablink-unattend-%d.xml`, stamp)
		// Register the scrub BEFORE initiating the push, keyed on the known
		// staged path. The lablink agent COMMITS the uploaded bytes to disk
		// (os.Rename to remoteUnattend) BEFORE SendAndClose, so a post-commit
		// push/transport error can return a non-nil error with the cleartext
		// answer file already on the target. Deferring here — rather than after a
		// successful push — guarantees the scrub fires on EVERY outcome (success
		// OR any push/transport error), closing that window. Remove-Item
		// -ErrorAction SilentlyContinue makes the scrub a no-op if the bytes
		// never landed. The injection script's finally also removes it; this
		// Go-side defer additionally covers push/runPS/transport failures and
		// build errors that abort before (or instead of) running that script.
		defer scrubRemoteStaged(reg, pool, t, remoteUnattend)
		if err := pushToTarget(ctx, reg, pool, t, localUnattend, remoteUnattend); err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("stage unattend on target: %v", err)), nil
		}

		remoteFirstBoot := ""
		firstBoot := req.GetString("first_boot_script", "")
		if strings.TrimSpace(firstBoot) != "" {
			localFB, cleanupFB, ferr := stageSecretFile(firstBoot, "lablink-firstboot-*.ps1")
			if ferr != nil {
				opErr = ferr
				return mcp.NewToolResultError(ferr.Error()), nil
			}
			defer cleanupFB()
			remoteFirstBoot = fmt.Sprintf(`C:\Windows\Temp\lablink-firstboot-%d.ps1`, stamp)
			// Same post-commit window as the unattend push above: defer the
			// scrub before the push so a post-commit push/transport error still
			// removes the staged file from the target.
			defer scrubRemoteStaged(reg, pool, t, remoteFirstBoot)
			if err := pushToTarget(ctx, reg, pool, t, localFB, remoteFirstBoot); err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("stage first-boot script on target: %v", err)), nil
			}
		}

		script, berr := unattend.BuildMountInjectScript(unattend.MountInjectParams{
			VHDPath:         vhdPath,
			BaseVHD:         baseVhd,
			UnattendRemote:  remoteUnattend,
			FirstBootRemote: remoteFirstBoot,
		})
		if berr != nil {
			opErr = berr
			return mcp.NewToolResultError(berr.Error()), nil
		}

		start := time.Now()
		out, exit, runErr := runPS(ctx, reg, pool, t, script, vmDefaultTimeoutSec)
		auditLog.Append(audit.Entry{
			Timestamp: start, Node: t.Name, Tool: "provision_unattend",
			Command: fmt.Sprintf("provision_unattend vm_name=%s hostname=%s method=%s admin_password=%s", vmName, hostname, method, passwordMask),
			Shell:   "powershell", ExitCode: exit, DurationMs: time.Since(start).Milliseconds(),
		})
		if runErr != nil {
			opErr = runErr
			return mcp.NewToolResultError(runErr.Error()), nil
		}
		header := fmt.Sprintf("**Provisioned `%s` on `%s`** (method=%s, password redacted; first-boot scrub of Panther/UnattendGC/AutoLogon baked in). Obfuscation is NOT encryption — the answer file contains the password until Windows consumes+scrubs it.", vmName, t.Name, method)
		return vmResult(header, jsonExtract(out)), nil
	}
}

// resolveAdminPassword sources the admin password from a saved credential
// profile (preferred) or an inline arg. Returns an error if neither is set.
func resolveAdminPassword(req mcp.CallToolRequest, creds *credentials.Store) (string, error) {
	credName := strings.TrimSpace(req.GetString("admin_password_credential", ""))
	if credName != "" {
		if creds == nil {
			return "", fmt.Errorf("credential store unavailable")
		}
		p, err := creds.Get(credName)
		if err != nil {
			return "", fmt.Errorf("credential %q not found — use save_credential first", credName)
		}
		return p.Password, nil
	}
	inline := req.GetString("admin_password", "")
	if strings.TrimSpace(inline) == "" {
		return "", fmt.Errorf("provide admin_password_credential (preferred) or admin_password")
	}
	return inline, nil
}

// stageSecretFile writes content to a uniquely-named temp file and returns its
// path plus a cleanup func that removes it. Used for the cleartext-password
// answer file so the local staged copy is always scrubbed via defer.
func stageSecretFile(content, pattern string) (string, func(), error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", func() {}, err
	}
	path := f.Name()
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(path)
		return "", func() {}, err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", func() {}, err
	}
	cleanup := func() { _ = os.Remove(path) }
	return path, cleanup, nil
}

// scrubRemoteStaged removes a staged cleartext file from the TARGET host on ALL
// paths (success or failure), including a post-commit push/transport error where
// the agent already committed (os.Rename) the bytes to disk before SendAndClose
// failed. Callers MUST defer this BEFORE initiating the push so the scrub fires
// regardless of the push outcome. It is idempotent: the injection script's
// finally also removes the file and the path may already be gone, so the
// Remove-Item uses -ErrorAction SilentlyContinue and a no-op is fine. It runs on
// a detached, time-bounded context so the scrub still fires even when the
// operation failed because the parent context was cancelled.
//
// A scrub FAILURE (e.g. the node is unreachable) may mean the cleartext file is
// still on the target, so it is surfaced via a warn log keyed on the path — it
// is NEVER swallowed silently. The password is never part of this script, its
// output, or the logged error.
func scrubRemoteStaged(reg *registry.Registry, pool *agentclient.Pool, t Target, remotePath string) {
	if strings.TrimSpace(remotePath) == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	script := hyperv.WrapTagged(fmt.Sprintf("Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue\n", hyperv.PSLit(remotePath)))
	if _, _, err := runPS(ctx, reg, pool, t, script, 60); err != nil {
		// The staged cleartext file may still be on the target — make the
		// failure visible. The path is safe to log; the password is not part of
		// the scrub script or its error.
		log.Printf("WARN lablink: failed to scrub staged cleartext file %q on %s: %v", remotePath, t.Name, err)
	}
}

// jsonExtract returns the JSON payload from a script's combined output. If no
// JSON object/array is present (e.g. an empty result), it returns "{}".
func jsonExtract(output string) string {
	s := strings.TrimSpace(output)
	start := strings.IndexAny(s, "{[")
	if start == -1 {
		return "{}"
	}
	end := strings.LastIndexAny(s, "}]")
	if end <= start {
		return "{}"
	}
	return s[start : end+1]
}
