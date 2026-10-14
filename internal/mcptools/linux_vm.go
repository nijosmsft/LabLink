package mcptools

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/linuximage"
	"github.com/nijosmsft/lablink/internal/linuxvm"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/vmconfig"
	"github.com/nijosmsft/lablink/internal/winpath"
)

type vmLifecycleLock struct {
	params hyperv.LinuxVMLockParams
}

func acquireVMLifecycleLock(
	ctx context.Context,
	name string,
	target Target,
	reg *registry.Registry,
	pool *agentclient.Pool,
) (vmLifecycleLock, error) {
	lockOwner, err := newRemoteStageID()
	if err != nil {
		return vmLifecycleLock{}, err
	}
	lock := vmLifecycleLock{
		params: hyperv.LinuxVMLockParams{Key: linuxVMLockKey(name), Owner: lockOwner},
	}
	acquireScript, err := hyperv.BuildLinuxVMAcquireLockScript(lock.params)
	if err != nil {
		return vmLifecycleLock{}, err
	}
	lockOut, _, err := runPS(ctx, reg, pool, target, acquireScript, vmDefaultTimeoutSec)
	if err != nil {
		return vmLifecycleLock{}, fmt.Errorf("acquire VM lifecycle lock: %w", err)
	}
	var result struct {
		Acquired bool `json:"acquired"`
	}
	if err := json.Unmarshal([]byte(jsonExtract(lockOut)), &result); err != nil {
		return vmLifecycleLock{}, fmt.Errorf("parse VM lifecycle lock result: %w", err)
	}
	if !result.Acquired {
		return vmLifecycleLock{}, fmt.Errorf("another VM lifecycle operation is active for VM %q on %s", name, target.Name)
	}
	return lock, nil
}

func (l vmLifecycleLock) release(reg *registry.Registry, pool *agentclient.Pool, target Target) {
	releaseScript, err := hyperv.BuildLinuxVMReleaseLockScript(l.params)
	if err != nil {
		return
	}
	_, _, _ = runPS(context.Background(), reg, pool, target, releaseScript, vmDefaultTimeoutSec)
}

type linuxVMPlan struct {
	Profile                   string  `json:"profile,omitempty"`
	Target                    string  `json:"target"`
	Name                      string  `json:"name"`
	Hostname                  string  `json:"hostname"`
	LinuxUsername             string  `json:"linux_username"`
	SSHPublicKey              string  `json:"ssh_public_key"`
	SSHPublicKeyFile          string  `json:"ssh_public_key_file,omitempty"`
	LinuxPasswordCredential   string  `json:"linux_password_credential,omitempty"`
	AllowSSHPasswordAuth      bool    `json:"allow_ssh_password_auth"`
	NetworkConfig             string  `json:"network_config,omitempty"`
	PasswordHash              string  `json:"-"`
	ImageCacheRoot            string  `json:"image_cache_root"`
	VMRoot                    string  `json:"vm_root"`
	VMLocation                string  `json:"vm_location"`
	VHDPath                   string  `json:"vhd_path"`
	CIDATAPath                string  `json:"cidata_path"`
	VSwitch                   string  `json:"vswitch"`
	MemoryMB                  float64 `json:"memory_mb"`
	CPUCount                  float64 `json:"cpu_count"`
	DynamicMemory             bool    `json:"dynamic_memory"`
	DynamicMinMB              float64 `json:"dynamic_min_mb,omitempty"`
	DynamicMaxMB              float64 `json:"dynamic_max_mb,omitempty"`
	DynamicBufferPct          float64 `json:"dynamic_buffer_pct,omitempty"`
	DiskSizeGB                float64 `json:"disk_size_gb"`
	RegisterWithLabLink       bool    `json:"register_with_lablink"`
	LabLinkNodeName           string  `json:"lablink_node_name"`
	LabLinkRole               string  `json:"lablink_role"`
	LabLinkPort               int     `json:"lablink_port"`
	MinHostReservePct         float64 `json:"min_host_reserve_pct"`
	AllowHostResourcePressure bool    `json:"allow_host_resource_pressure"`
	PreparedVHDX              string  `json:"prepared_vhdx,omitempty"`
	LabLinkAddress            string  `json:"lablink_address,omitempty"`
	State                     string  `json:"state,omitempty"`
	Registered                bool    `json:"registered"`
	sshPasswordAuthExplicit   bool
}

func registerCreateLinuxVMTool(
	s *server.MCPServer,
	reg *registry.Registry,
	pool *agentclient.Pool,
	defaults *vmconfig.Store,
	creds *credentials.Store,
	auditLog *audit.Log,
	enrollment VMEnrollmentConfig,
	leaseCfg LeaseGateConfig,
) {
	s.AddTool(
		mcp.NewTool("create_linux_vm",
			mcp.WithDescription("Create an Ubuntu 24.04 amd64 Gen2 Hyper-V VM from the verified Azure-VHD-derived NoCloud cache and provision it with a standard CIDATA ISO. An empty cache starts/resumes preparation through the required nested Windows builder and returns image_preparing without creating a VM."),
			mcp.WithString("target", mcp.Description("localhost or a registered Windows Hyper-V host")),
			mcp.WithString("profile", mcp.Description("Linux VM profile; empty uses linux_target_defaults/default_linux_profile")),
			mcp.WithString("name", mcp.Required(), mcp.Description("VM name")),
			mcp.WithString("hostname", mcp.Description("Lowercase RFC1123 guest hostname; defaults from name")),
			mcp.WithString("linux_username", mcp.Description("Non-root Linux account")),
			mcp.WithString("ssh_public_key", mcp.Description("Inline OpenSSH public key (mutually exclusive with ssh_public_key_file)")),
			mcp.WithString("ssh_public_key_file", mcp.Description("Local server path to an OpenSSH public key")),
			mcp.WithString("linux_password_credential", mcp.Description("Saved credential profile supplying the Linux password; plaintext is never stored in metadata or output")),
			mcp.WithBoolean("allow_ssh_password_auth", mcp.Description("Enable SSH password authentication; defaults true with linux_password_credential and false otherwise")),
			mcp.WithString("network_config", mcp.Description("Optional NoCloud network-config YAML; DHCP from the generic image is used when omitted")),
			mcp.WithString("image_cache_root", mcp.Description("Host root for the verified prepared image cache")),
			mcp.WithString("image_builder_profile", mcp.Description("Required Windows builder profile when image preparation is needed")),
			mcp.WithString("builder_vm_name", mcp.Description("Reusable builder VM name override when image preparation is needed")),
			mcp.WithBoolean("delete_builder_after_prepare", mcp.Description("Delete the owned builder after successful on-demand preparation")),
			mcp.WithString("vm_root", mcp.Description("Managed VM storage root")),
			mcp.WithString("vswitch", mcp.Description("Existing Hyper-V vSwitch")),
			mcp.WithNumber("memory_mb", mcp.Description("Startup memory MB")),
			mcp.WithNumber("cpu_count", mcp.Description("vCPU count")),
			mcp.WithBoolean("dynamic_memory", mcp.Description("Enable Hyper-V dynamic memory")),
			mcp.WithNumber("dynamic_min_mb", mcp.Description("Dynamic memory minimum MB")),
			mcp.WithNumber("dynamic_max_mb", mcp.Description("Dynamic memory maximum MB")),
			mcp.WithNumber("dynamic_buffer_pct", mcp.Description("Dynamic memory buffer percentage")),
			mcp.WithNumber("disk_size_gb", mcp.Description("Requested OS disk virtual size GB")),
			mcp.WithBoolean("register_with_lablink", mcp.Description("Verify mTLS and register the guest (default true)")),
			mcp.WithString("lablink_node_name", mcp.Description("Expected guest mTLS identity and registry name")),
			mcp.WithString("lablink_role", mcp.Description("Registry role (default vm)")),
			mcp.WithNumber("lablink_port", mcp.Description("Guest LabLink agent port (default 9091)")),
			mcp.WithNumber("min_host_reserve_pct", mcp.Description("Minimum projected free RAM/storage percentage (default 10)")),
			mcp.WithBoolean("allow_host_resource_pressure", mcp.Description("Explicitly bypass host reserve failures")),
			mcp.WithBoolean("dry_run", mcp.Description("Resolve and validate configuration without host mutation")),
		),
		createLinuxVMHandler(reg, pool, defaults, creds, auditLog, enrollment, leaseCfg),
	)
}

func createLinuxVMHandler(
	reg *registry.Registry,
	pool *agentclient.Pool,
	defaults *vmconfig.Store,
	creds *credentials.Store,
	auditLog *audit.Log,
	enrollment VMEnrollmentConfig,
	leaseCfg LeaseGateConfig,
) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		plan, target, err := resolveLinuxVMPlanBase(req, reg, defaults)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if req.GetBool("dry_run", false) {
			plan, err = resolveLinuxVMAccess(plan, creds)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if strings.TrimSpace(plan.ImageCacheRoot) == "" {
				return mcp.NewToolResultError("image_cache_root is required for a dry-run or new Linux VM; an existing managed resume uses its persisted parent"), nil
			}
			return vmResult("**Resolved Linux VM configuration** (dry run; no changes made)", marshalPlan(plan)), nil
		}
		progress := NewMCPProgressState(30*time.Minute, "resolve", "configuration validated")
		stopHB := StartMCPProgressHeartbeat(ctx, req, defaultHeartbeatInterval, progress)
		defer stopHB()
		gatedReq := req
		args := cloneArguments(req.GetArguments())
		args["target"] = plan.Target
		gatedReq.Params.Arguments = args
		gatedReq.Params.Name = "create_linux_vm"
		execute := func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return executeLinuxVMPlan(ctx, req, plan, target, reg, pool, defaults, creds, auditLog, enrollment, leaseCfg, progress)
		}
		return LeaseGate(leaseCfg, extractTarget("target"), execute)(ctx, gatedReq)
	}
}

func resolveLinuxVMPlan(req mcp.CallToolRequest, reg *registry.Registry, defaults *vmconfig.Store, creds *credentials.Store) (linuxVMPlan, Target, error) {
	plan, target, err := resolveLinuxVMPlanBase(req, reg, defaults)
	if err != nil {
		return linuxVMPlan{}, Target{}, err
	}
	plan, err = resolveLinuxVMAccess(plan, creds)
	if err != nil {
		return linuxVMPlan{}, Target{}, err
	}
	return plan, target, nil
}

func resolveLinuxVMPlanBase(req mcp.CallToolRequest, reg *registry.Registry, defaults *vmconfig.Store) (linuxVMPlan, Target, error) {
	requestedTarget := strings.TrimSpace(req.GetString("target", ""))
	profile, profileName, err := defaults.ResolveLinuxForTarget(req.GetString("profile", ""), requestedTarget)
	if err != nil {
		return linuxVMPlan{}, Target{}, err
	}
	plan := linuxVMPlan{
		Profile: profileName, Target: profile.Target, LinuxUsername: profile.LinuxUsername,
		SSHPublicKey: profile.SSHPublicKey, SSHPublicKeyFile: profile.SSHPublicKeyFile,
		LinuxPasswordCredential: profile.LinuxPasswordCredential,
		NetworkConfig:           profile.NetworkConfig,
		ImageCacheRoot:          profile.ImageCacheRoot,
		VMRoot:                  profile.VMRoot, VSwitch: profile.VSwitch, MemoryMB: profile.MemoryMB,
		CPUCount: profile.CPUCount, DynamicMemory: profile.DynamicMemory,
		DynamicMinMB: profile.DynamicMinMB, DynamicMaxMB: profile.DynamicMaxMB,
		DynamicBufferPct: profile.DynamicBufferPct, DiskSizeGB: profile.DiskSizeGB,
		RegisterWithLabLink: boolValue(profile.RegisterLabLink, true), LabLinkRole: profile.LabLinkRole,
		LabLinkPort: profile.LabLinkPort, MinHostReservePct: profile.MinHostReservePct,
	}
	allowPasswordSet := false
	if profile.AllowSSHPasswordAuth != nil {
		plan.AllowSSHPasswordAuth = *profile.AllowSSHPasswordAuth
		allowPasswordSet = true
		plan.sshPasswordAuthExplicit = true
	}
	args := req.GetArguments()
	applyStringArg(args, "target", &plan.Target)
	applyStringArg(args, "name", &plan.Name)
	applyStringArg(args, "hostname", &plan.Hostname)
	applyStringArg(args, "linux_username", &plan.LinuxUsername)
	applyStringArg(args, "ssh_public_key", &plan.SSHPublicKey)
	applyStringArg(args, "ssh_public_key_file", &plan.SSHPublicKeyFile)
	applyStringArg(args, "linux_password_credential", &plan.LinuxPasswordCredential)
	applyStringArg(args, "network_config", &plan.NetworkConfig)
	applyStringArg(args, "image_cache_root", &plan.ImageCacheRoot)
	applyStringArg(args, "vm_root", &plan.VMRoot)
	applyStringArg(args, "vswitch", &plan.VSwitch)
	applyStringArg(args, "lablink_node_name", &plan.LabLinkNodeName)
	applyStringArg(args, "lablink_role", &plan.LabLinkRole)
	applyFloatArg(args, "memory_mb", &plan.MemoryMB)
	applyFloatArg(args, "cpu_count", &plan.CPUCount)
	applyFloatArg(args, "dynamic_min_mb", &plan.DynamicMinMB)
	applyFloatArg(args, "dynamic_max_mb", &plan.DynamicMaxMB)
	applyFloatArg(args, "dynamic_buffer_pct", &plan.DynamicBufferPct)
	applyFloatArg(args, "disk_size_gb", &plan.DiskSizeGB)
	applyFloatArg(args, "min_host_reserve_pct", &plan.MinHostReservePct)
	applyBoolArg(args, "dynamic_memory", &plan.DynamicMemory)
	applyBoolArg(args, "register_with_lablink", &plan.RegisterWithLabLink)
	applyBoolArg(args, "allow_host_resource_pressure", &plan.AllowHostResourcePressure)
	if value, ok := args["allow_ssh_password_auth"].(bool); ok {
		plan.AllowSSHPasswordAuth = value
		allowPasswordSet = true
		plan.sshPasswordAuthExplicit = true
	}
	if value, ok := numericArgument(args["lablink_port"]); ok {
		plan.LabLinkPort = int(value)
	}
	if requestedTarget != "" {
		plan.Target = requestedTarget
	}
	if plan.Target == "" {
		plan.Target = "localhost"
	}
	if plan.MemoryMB <= 0 {
		plan.MemoryMB = 4096
	}
	if plan.CPUCount <= 0 {
		plan.CPUCount = 2
	}
	if plan.DiskSizeGB <= 0 {
		plan.DiskSizeGB = 64
	}
	if math.Trunc(plan.DiskSizeGB) != plan.DiskSizeGB {
		return linuxVMPlan{}, Target{}, fmt.Errorf("disk_size_gb must be an integer")
	}
	if err := linuximage.ValidateDiskSizeGB(int(plan.DiskSizeGB)); err != nil {
		return linuxVMPlan{}, Target{}, err
	}
	if plan.MinHostReservePct <= 0 {
		plan.MinHostReservePct = 10
	}
	if plan.LabLinkPort <= 0 {
		plan.LabLinkPort = 9091
	}
	if plan.LabLinkRole == "" {
		plan.LabLinkRole = "vm"
	}
	if plan.Hostname == "" {
		plan.Hostname = linuxHostname(plan.Name)
	}
	if plan.LabLinkNodeName == "" {
		plan.LabLinkNodeName = plan.Hostname
	}
	if err := validateFixedLinuxProfile(profile); err != nil {
		return linuxVMPlan{}, Target{}, err
	}
	if err := validateVMPathName(plan.Name); err != nil {
		return linuxVMPlan{}, Target{}, err
	}
	if err := linuxvm.ValidateHostname(plan.Hostname); err != nil {
		return linuxVMPlan{}, Target{}, err
	}
	if err := linuxvm.ValidateUsername(plan.LinuxUsername); err != nil {
		return linuxVMPlan{}, Target{}, err
	}
	if !allowPasswordSet {
		plan.AllowSSHPasswordAuth = strings.TrimSpace(plan.LinuxPasswordCredential) != ""
	}
	cleanVMRoot, err := winpath.CleanAbsolute(plan.VMRoot)
	if err != nil || cleanVMRoot != plan.VMRoot {
		return linuxVMPlan{}, Target{}, fmt.Errorf("vm_root must be a clean absolute Windows host path")
	}
	if plan.ImageCacheRoot != "" {
		cleanCacheRoot, err := winpath.CleanAbsolute(plan.ImageCacheRoot)
		if err != nil || cleanCacheRoot != plan.ImageCacheRoot {
			return linuxVMPlan{}, Target{}, fmt.Errorf("image_cache_root must be a clean absolute Windows host path")
		}
	}
	if plan.VSwitch == "" {
		return linuxVMPlan{}, Target{}, fmt.Errorf("incomplete Linux VM configuration; missing: vswitch")
	}
	plan.VMLocation, _ = winpath.Join(plan.VMRoot, plan.Name)
	plan.VHDPath, _ = winpath.Join(plan.VMLocation, plan.Name+".vhdx")
	target, err := resolvePlanTarget(plan.Target, reg)
	return plan, target, err
}

func resolveLinuxVMAccess(plan linuxVMPlan, creds *credentials.Store) (linuxVMPlan, error) {
	if strings.TrimSpace(plan.SSHPublicKey) != "" && strings.TrimSpace(plan.SSHPublicKeyFile) != "" {
		return linuxVMPlan{}, fmt.Errorf("ssh_public_key and ssh_public_key_file are mutually exclusive")
	}
	if plan.SSHPublicKeyFile != "" {
		if !filepath.IsAbs(plan.SSHPublicKeyFile) {
			return linuxVMPlan{}, fmt.Errorf("ssh_public_key_file must be an absolute local server path")
		}
		data, err := os.ReadFile(plan.SSHPublicKeyFile)
		if err != nil {
			return linuxVMPlan{}, fmt.Errorf("read ssh_public_key_file: %w", err)
		}
		plan.SSHPublicKey = strings.TrimSpace(string(data))
	}
	if strings.TrimSpace(plan.SSHPublicKey) != "" {
		if err := linuxvm.ValidateSSHPublicKey(plan.SSHPublicKey); err != nil {
			return linuxVMPlan{}, err
		}
	}
	hasPassword := strings.TrimSpace(plan.LinuxPasswordCredential) != ""
	if !plan.sshPasswordAuthExplicit {
		plan.AllowSSHPasswordAuth = hasPassword
	}
	if hasPassword {
		if creds == nil {
			return linuxVMPlan{}, fmt.Errorf("credential store unavailable")
		}
		credential, err := creds.Get(plan.LinuxPasswordCredential)
		if err != nil {
			return linuxVMPlan{}, fmt.Errorf("credential %q not found — use save_credential first", plan.LinuxPasswordCredential)
		}
		plan.PasswordHash, err = linuxvm.HashPasswordSHA512(credential.Password)
		if err != nil {
			return linuxVMPlan{}, err
		}
	}
	if strings.TrimSpace(plan.SSHPublicKey) == "" && !hasPassword {
		return linuxVMPlan{}, fmt.Errorf("provide at least one of ssh_public_key, ssh_public_key_file, or linux_password_credential")
	}
	if plan.AllowSSHPasswordAuth != hasPassword {
		if hasPassword {
			return linuxVMPlan{}, fmt.Errorf("allow_ssh_password_auth must be true when linux_password_credential is configured")
		}
		return linuxVMPlan{}, fmt.Errorf("allow_ssh_password_auth requires linux_password_credential")
	}
	return plan, nil
}

func executeLinuxVMPlan(
	ctx context.Context,
	originalReq mcp.CallToolRequest,
	plan linuxVMPlan,
	target Target,
	reg *registry.Registry,
	pool *agentclient.Pool,
	defaults *vmconfig.Store,
	creds *credentials.Store,
	auditLog *audit.Log,
	enrollment VMEnrollmentConfig,
	leaseCfg LeaseGateConfig,
	progress *MCPProgressState,
) (*mcp.CallToolResult, error) {
	ctx, op := beginOp(ctx, "create_linux_vm", target.Name, fmt.Sprintf("create Linux VM %s", plan.Name), map[string]string{
		"target": target.Name, "name": plan.Name, "register_with_lablink": fmt.Sprintf("%t", plan.RegisterWithLabLink),
	})
	var opErr error
	defer func() { op.Done(opErr) }()
	progress.Update("inspect", "reading persisted managed VM identity before locks or cache preparation")
	initialExisting, err := readManagedLinuxVM(ctx, plan, target, reg, pool)
	if err != nil {
		opErr = err
		return mcp.NewToolResultError(err.Error()), nil
	}
	if initialExisting.Exists {
		if err := validateManagedLinuxVMState(plan, initialExisting); err != nil {
			opErr = err
			return mcp.NewToolResultError(err.Error()), nil
		}
	}
	var preflightReady readyLinuxImage
	if !initialExisting.Exists {
		plan, err = resolveLinuxVMAccess(plan, creds)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(err.Error()), nil
		}
		if plan.ImageCacheRoot != "" {
			progress.Update("image", "non-mutating cache check before VM lifecycle locking")
			preflightReady, err = readReadyLinuxImage(ctx, plan.ImageCacheRoot, int(plan.DiskSizeGB), target, reg, pool)
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(err.Error()), nil
			}
		}
		if preflightReady.PreparedVHDX == "" {
			imagePlan, imageTarget, resolveErr := resolveLinuxImagePlan(originalReq, reg, defaults, creds)
			if resolveErr != nil {
				opErr = resolveErr
				return mcp.NewToolResultError(resolveErr.Error()), nil
			}
			if !strings.EqualFold(imageTarget.Name, target.Name) {
				opErr = fmt.Errorf("Linux image builder target %q does not match VM target %q", imageTarget.Name, target.Name)
				return mcp.NewToolResultError(opErr.Error()), nil
			}
			preflightScript, scriptErr := hyperv.BuildLinuxImageBuilderSourcePreflightScript(
				imagePlan.Builder.BaseVHD, imagePlan.Builder.VMRoot, imagePlan.Builder.VSwitch,
			)
			if scriptErr != nil {
				opErr = scriptErr
				return mcp.NewToolResultError(scriptErr.Error()), nil
			}
			if _, _, runErr := runPS(ctx, reg, pool, target, preflightScript, vmDefaultTimeoutSec); runErr != nil {
				opErr = runErr
				return mcp.NewToolResultError(fmt.Sprintf("Linux image builder source preconditions: %v", runErr)), nil
			}
		}
	}

	progress.Update("lock", "acquiring per-VM lifecycle lock after non-mutating resume/cache preflight")
	lifecycleLock, err := acquireVMLifecycleLock(ctx, plan.Name, target, reg, pool)
	if err != nil {
		opErr = err
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer lifecycleLock.release(reg, pool, target)

	progress.Update("inspect", "revalidating persisted managed VM identity under the lifecycle lock")
	existing, err := readManagedLinuxVM(ctx, plan, target, reg, pool)
	if err != nil {
		opErr = err
		return mcp.NewToolResultError(err.Error()), nil
	}
	if initialExisting.Exists && !existing.Exists {
		opErr = fmt.Errorf("VM_RESUME_RACE: managed VM %q disappeared before lifecycle lock acquisition; retry without mutating artifacts", plan.Name)
		return mcp.NewToolResultError(opErr.Error()), nil
	}
	if existing.Exists {
		if err := validateManagedLinuxVMState(plan, existing); err != nil {
			opErr = err
			return mcp.NewToolResultError(err.Error()), nil
		}
		plan.PreparedVHDX = existing.Metadata.ParentVHDX
		plan.VHDPath = existing.Metadata.ChildVHDX
		plan.VMRoot = existing.Metadata.ManagedRoot
		plan.LabLinkNodeName = existing.Metadata.NodeName
		plan.Registered = existing.Metadata.Registered
		ownership, err := linuxVMOwnership(plan, existing.Metadata.ExpectedCIDATAISO)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		progress.Update("validate", "non-mutating exact child and parent VHD validation before resume mutation, boot, or mTLS")
		storageValidation, err := hyperv.BuildValidateExistingLinuxVMStorageScript(plan.Name, *existing.Metadata)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(err.Error()), nil
		}
		if _, _, err := runPS(ctx, reg, pool, target, storageValidation, vmDefaultTimeoutSec); err != nil {
			opErr = err
			return retainedLinuxVMError(plan, existing.Metadata.ExpectedCIDATAISO,
				fmt.Errorf("validate existing managed Linux VM storage: %w", err)), nil
		}
		progress.Update("reconcile", "reconciling persisted CIDATA ownership for managed VM resume")
		if err := reconcileLinuxVMArtifacts(ctx, plan.Name, ownership, target, reg, pool); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if existing.Metadata.CleanupPhase == hyperv.LinuxVMCleanupAttached {
			progress.Update("configure", "finishing idempotent managed VM configuration before boot")
			configureScript, err := hyperv.BuildConfigureExistingLinuxVMScript(hyperv.ConfigureExistingLinuxVMParams{
				Name: plan.Name, Metadata: *existing.Metadata, Ownership: ownership,
				MemoryMB: plan.MemoryMB, CPUCount: plan.CPUCount, DynamicMemory: plan.DynamicMemory,
				DynamicMinMB: plan.DynamicMinMB, DynamicMaxMB: plan.DynamicMaxMB,
				DynamicBufferPct: plan.DynamicBufferPct,
			})
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(err.Error()), nil
			}
			if _, _, err := runPS(ctx, reg, pool, target, configureScript, vmDefaultTimeoutSec); err != nil {
				opErr = err
				return retainedLinuxVMError(plan, existing.Metadata.ExpectedCIDATAISO,
					fmt.Errorf("finish existing managed Linux VM configuration: %w", err)), nil
			}
		}
		return finishLinuxVM(ctx, plan, existing.Metadata.ExpectedCIDATAISO, target, reg, pool, progress)
	}
	progress.Update("reconcile", "reconciling stale pre-VM CIDATA ownership and exact managed artifacts")
	ownership, err := linuxVMOwnership(plan, "")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if err := reconcileLinuxVMArtifacts(ctx, plan.Name, ownership, target, reg, pool); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	progress.Update("image", "checking the reusable Ubuntu image cache for new VM creation")
	ready := preflightReady
	if ready.PreparedVHDX == "" {
		ready, err = readReadyLinuxImage(ctx, plan.ImageCacheRoot, int(plan.DiskSizeGB), target, reg, pool)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(err.Error()), nil
		}
	}
	if ready.PreparedVHDX == "" {
		prepReq := originalReq
		prepArgs := cloneArguments(originalReq.GetArguments())
		prepArgs["target"] = plan.Target
		prepArgs["image_cache_root"] = plan.ImageCacheRoot
		prepArgs["disk_size_gb"] = plan.DiskSizeGB
		prepReq.Params.Arguments = prepArgs
		prepResult, err := prepareLinuxImageHandler(reg, pool, defaults, creds, auditLog, enrollment, leaseCfg)(ctx, prepReq)
		if err != nil || prepResult == nil || prepResult.IsError {
			return prepResult, err
		}
		ready, err = readReadyLinuxImage(ctx, plan.ImageCacheRoot, int(plan.DiskSizeGB), target, reg, pool)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if ready.PreparedVHDX == "" {
			return vmResult("**Linux image is preparing** — no VM was created. Re-run `create_linux_vm` after BITS/transforms complete.", `{"status":"image_preparing","vm_created":false}`), nil
		}
	}
	plan.PreparedVHDX = ready.PreparedVHDX
	ownership, err = linuxVMOwnership(plan, "")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if err := ensureLinuxVMChildAbsent(ctx, plan.VHDPath, target, reg, pool); err != nil {
		opErr = err
		return mcp.NewToolResultError(err.Error()), nil
	}
	progress.Update("ownership", "persisting atomic per-VM CIDATA ownership before staging secrets")
	persistOwnership, err := hyperv.BuildPersistLinuxVMOwnershipScript(hyperv.LinuxVMOwnershipParams{Ownership: ownership})
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if _, _, err := runPS(ctx, reg, pool, target, persistOwnership, vmDefaultTimeoutSec); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("persist Linux VM CIDATA ownership: %v", err)), nil
	}
	progress.Update("staging", "creating verified restricted staging and transferring enrollment secrets")
	stage, err := prepareLinuxSeedPayload(ctx, plan, ownership, target, reg, pool, enrollment)
	if err != nil {
		if cleanupErr := reconcileLinuxVMArtifacts(context.Background(), plan.Name, ownership, target, reg, pool); cleanupErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("%v; additionally failed to reconcile persisted CIDATA ownership: %v", err, cleanupErr)), nil
		}
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer stage.cleanupLocal()
	preVMCleanup := preVMLinuxSeedCleanup{
		cleanupStage: stage.cleanupRemote,
		reconcile: func(cleanupCtx context.Context) error {
			return reconcileLinuxVMArtifacts(cleanupCtx, plan.Name, ownership, target, reg, pool)
		},
	}
	defer func() { _ = preVMCleanup.cleanupBeforeVM(context.Background()) }()

	progress.Update("iso", "building restricted NoCloud CIDATA ISO after ACL and ownership verification")
	isoScript, err := hyperv.BuildCIDATAISOScript(hyperv.CIDATAISOParams{
		SourceDir: stage.remoteDir, ISOPath: stage.isoPath, OwnershipPath: stage.ownershipPath,
	})
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if _, _, err := runPS(ctx, reg, pool, target, isoScript, vmDefaultTimeoutSec); err != nil {
		opErr = err
		return mcp.NewToolResultError(fmt.Sprintf("build CIDATA ISO: %v", err)), nil
	}
	if err := preVMCleanup.cleanupAfterISO(ctx); err != nil {
		opErr = err
		return mcp.NewToolResultError(err.Error()), nil
	}
	metadata, err := hyperv.MarshalLinuxVMMetadata(hyperv.LinuxVMMetadata{
		GuestOS: "linux", VMName: plan.Name, NodeName: plan.LabLinkNodeName,
		ManagedRoot: plan.VMRoot, ParentVHDX: plan.PreparedVHDX, ChildVHDX: plan.VHDPath,
		ExpectedCIDATAISO: stage.isoPath, CleanupPhase: hyperv.LinuxVMCleanupAttached,
	})
	if err != nil {
		if cleanupErr := preVMCleanup.cleanupBeforeVM(context.Background()); cleanupErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("%v; additionally failed to remove owned CIDATA ISO %s: %v", err, stage.isoPath, cleanupErr)), nil
		}
		return mcp.NewToolResultError(err.Error()), nil
	}
	createScript, err := hyperv.BuildCreateLinuxVMScript(hyperv.CreateLinuxVMParams{
		Name: plan.Name, VMLocation: plan.VMLocation, ParentVHDX: plan.PreparedVHDX,
		ChildVHDX: plan.VHDPath, ISOPath: stage.isoPath, VSwitch: plan.VSwitch,
		MemoryMB: plan.MemoryMB, CPUCount: plan.CPUCount, DynamicMemory: plan.DynamicMemory,
		DynamicMinMB: plan.DynamicMinMB, DynamicMaxMB: plan.DynamicMaxMB,
		DynamicBufferPct: plan.DynamicBufferPct, DiskSizeGB: plan.DiskSizeGB,
		MinHostReservePct:         plan.MinHostReservePct,
		AllowHostResourcePressure: plan.AllowHostResourcePressure,
		ManagedMetadata:           metadata,
	})
	if err != nil {
		if cleanupErr := preVMCleanup.cleanupBeforeVM(context.Background()); cleanupErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("%v; additionally failed to remove owned CIDATA ISO %s: %v", err, stage.isoPath, cleanupErr)), nil
		}
		return mcp.NewToolResultError(err.Error()), nil
	}
	createStart := time.Now()
	createOut, createExit, err := runPS(ctx, reg, pool, target, createScript, vmDefaultTimeoutSec)
	if auditLog != nil {
		auditLog.Append(audit.Entry{
			Timestamp: createStart, Node: target.Name, Tool: "create_linux_vm",
			Command: fmt.Sprintf("create_linux_vm name=%s image=%s", plan.Name, plan.PreparedVHDX),
			Shell:   "powershell", ExitCode: createExit, DurationMs: time.Since(createStart).Milliseconds(),
		})
	}
	_ = createOut
	if err != nil {
		opErr = err
		exists := linuxVMExists(ctx, plan.Name, target, reg, pool)
		preVMCleanup.vmCreated = exists
		if exists {
			return retainedLinuxVMError(plan, stage.isoPath, fmt.Errorf("VM creation script failed after the VM appeared: %w", err)), nil
		}
		if cleanupErr := preVMCleanup.cleanupBeforeVM(context.Background()); cleanupErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("create Linux VM: %v; owned CIDATA/VHD cleanup failed and requires exact-path cleanup (%s, %s): %v", err, stage.isoPath, plan.VHDPath, cleanupErr)), nil
		}
		return mcp.NewToolResultError(fmt.Sprintf("create Linux VM: %v", err)), nil
	}
	preVMCleanup.vmCreated = true
	return finishLinuxVM(ctx, plan, stage.isoPath, target, reg, pool, progress)
}

type preVMLinuxSeedCleanup struct {
	cleanupStage func(context.Context) error
	reconcile    func(context.Context) error
	vmCreated    bool
	done         bool
	retain       bool
}

func (c *preVMLinuxSeedCleanup) cleanupAfterISO(ctx context.Context) error {
	if err := c.cleanupStage(ctx); err != nil {
		c.retain = true
		return fmt.Errorf("CIDATA staging cleanup failed before VM creation; persisted ownership was retained for exact-path resume reconciliation: %w", err)
	}
	return nil
}

func (c *preVMLinuxSeedCleanup) cleanupBeforeVM(ctx context.Context) error {
	if c.vmCreated || c.done || c.retain {
		return nil
	}
	if err := c.cleanupStage(ctx); err != nil {
		return err
	}
	if err := c.reconcile(ctx); err != nil {
		return err
	}
	c.done = true
	return nil
}

func ensureLinuxVMChildAbsent(ctx context.Context, childVHDX string, target Target, reg *registry.Registry, pool *agentclient.Pool) error {
	script := fmt.Sprintf(`
$childVHDX = %s
if (Test-Path -LiteralPath $childVHDX) {
    throw "CHILD_VHDX_EXISTS: refusing to claim or delete a child disk not created by this invocation"
}
[pscustomobject]@{ status='absent'; child_vhdx=$childVHDX } | ConvertTo-Json -Compress
`, hyperv.PSLit(childVHDX))
	if _, _, err := runPS(ctx, reg, pool, target, script, vmDefaultTimeoutSec); err != nil {
		return fmt.Errorf("validate managed child VHDX ownership: %w", err)
	}
	return nil
}

func finishLinuxVM(
	ctx context.Context,
	plan linuxVMPlan,
	isoPath string,
	target Target,
	reg *registry.Registry,
	pool *agentclient.Pool,
	progress *MCPProgressState,
) (*mcp.CallToolResult, error) {
	progress.Update("boot", "starting VM and waiting up to 15 minutes for Hyper-V KVP IPv4")
	startScript, _ := hyperv.BuildLinuxVMStartAndDiscoverScript(plan.Name)
	out, _, err := runPS(ctx, reg, pool, target, startScript, 1000)
	if err != nil {
		return retainedLinuxVMError(plan, isoPath, fmt.Errorf("start/IP discovery failed: %w", err)), nil
	}
	var started startedVMInfo
	if err := json.Unmarshal([]byte(jsonExtract(out)), &started); err != nil {
		return retainedLinuxVMError(plan, isoPath, fmt.Errorf("parse KVP IP result: %w", err)), nil
	}
	identityPlan := windowsVMPlan{
		LabLinkNodeName: plan.LabLinkNodeName, LabLinkRole: plan.LabLinkRole,
		LabLinkPort: plan.LabLinkPort,
	}
	progress.Update("registration", "NoCloud provisioning has the guest address; waiting up to 10 minutes for the mTLS agent")
	if err := verifyEnrolledVMWithOptions(ctx, identityPlan, started, reg, pool, plan.RegisterWithLabLink, enrollmentWaitOptions{
		Timeout: linuxEnrollmentReadyTimeout,
		OnStatus: func(status string) {
			progress.Update("registration", status)
		},
	}); err != nil {
		return retainedLinuxVMError(plan, isoPath, err), nil
	}
	plan.Registered = plan.RegisterWithLabLink
	registrationScript, _ := hyperv.BuildSetLinuxVMRegistrationScript(plan.Name, plan.Registered)
	if _, _, err := runPS(ctx, reg, pool, target, registrationScript, vmDefaultTimeoutSec); err != nil {
		return retainedLinuxVMError(plan, isoPath, fmt.Errorf("guest verification succeeded but managed registration metadata update failed: %w", err)), nil
	}
	progress.Update("cleanup", "registration verified; detaching and deleting the owned CIDATA ISO")
	cleanupISO, _ := hyperv.BuildLinuxVMCIDATACleanupScript(plan.Name, isoPath)
	if _, _, err := runPS(ctx, reg, pool, target, cleanupISO, vmDefaultTimeoutSec); err != nil {
		return retainedLinuxVMError(plan, isoPath, fmt.Errorf("guest verified but CIDATA cleanup failed: %w", err)), nil
	}
	plan.CIDATAPath = ""
	plan.LabLinkAddress = fmt.Sprintf("%s:%d", started.IPAddress, plan.LabLinkPort)
	plan.State = started.State
	return vmResult(fmt.Sprintf("**Linux VM `%s` created and verified on `%s`**", plan.Name, plan.Target), marshalPlan(plan)), nil
}

type managedLinuxVMState struct {
	Exists            bool                    `json:"exists"`
	State             string                  `json:"state"`
	Metadata          *hyperv.LinuxVMMetadata `json:"metadata"`
	AttachedISOs      []string                `json:"attached_isos"`
	ExpectedISOExists bool                    `json:"expected_iso_exists"`
	OwnershipExists   *bool                   `json:"ownership_exists"`
}

func readManagedLinuxVM(ctx context.Context, plan linuxVMPlan, target Target, reg *registry.Registry, pool *agentclient.Pool) (managedLinuxVMState, error) {
	script, err := hyperv.BuildInspectVMManagementScript(plan.Name)
	if err != nil {
		return managedLinuxVMState{}, err
	}
	out, _, err := runPS(ctx, reg, pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return managedLinuxVMState{}, err
	}
	var state managedLinuxVMState
	if err := json.Unmarshal([]byte(jsonExtract(out)), &state); err != nil {
		return managedLinuxVMState{}, fmt.Errorf("parse existing Linux VM state: %w", err)
	}
	return state, nil
}

func validateManagedLinuxVMState(plan linuxVMPlan, state managedLinuxVMState) error {
	if state.Metadata == nil {
		return fmt.Errorf("VM_REUSE_UNSAFE: existing VM %q has no LabLink managed metadata; owned artifacts were retained", plan.Name)
	}
	metadata := state.Metadata
	if metadata.SchemaVersion != hyperv.LinuxVMMetadataSchema || metadata.GuestOS != "linux" ||
		!strings.EqualFold(metadata.VMName, plan.Name) ||
		!strings.EqualFold(metadata.NodeName, plan.LabLinkNodeName) ||
		!sameWindowsPath(metadata.ManagedRoot, plan.VMRoot) ||
		!sameWindowsPath(metadata.ChildVHDX, plan.VHDPath) {
		return fmt.Errorf("VM_REUSE_UNSAFE: existing VM %q managed metadata does not match the requested VM, root, child, or node identity", plan.Name)
	}
	switch metadata.CleanupPhase {
	case hyperv.LinuxVMCleanupAttached:
		if state.OwnershipExists != nil && !*state.OwnershipExists {
			return fmt.Errorf("VM_REUSE_UNSAFE: existing VM %q is missing persisted CIDATA ownership", plan.Name)
		}
		if !state.ExpectedISOExists {
			return fmt.Errorf("VM_RESUME_CIDATA_MISSING: expected managed CIDATA ISO is not present")
		}
		for _, attachedISO := range state.AttachedISOs {
			if !sameWindowsPath(attachedISO, metadata.ExpectedCIDATAISO) {
				return fmt.Errorf("VM_RESUME_CIDATA_MISMATCH: existing VM %q has an unexpected attached ISO", plan.Name)
			}
		}
		if strings.EqualFold(state.State, "Running") && len(state.AttachedISOs) != 1 {
			return fmt.Errorf("VM_RESUME_RUNNING_CIDATA_MISSING: existing running VM %q does not have the persisted CIDATA ISO attached", plan.Name)
		}
		if state.State != "" && !strings.EqualFold(state.State, "Off") && !strings.EqualFold(state.State, "Running") {
			return fmt.Errorf("VM_REUSE_UNSAFE: existing VM %q is in unsupported state %q", plan.Name, state.State)
		}
	case hyperv.LinuxVMCleanupDetached:
		if state.OwnershipExists != nil && !*state.OwnershipExists {
			return fmt.Errorf("VM_REUSE_UNSAFE: existing VM %q is missing persisted CIDATA ownership", plan.Name)
		}
	case hyperv.LinuxVMCleanupComplete:
	default:
		return fmt.Errorf("VM_REUSE_UNSAFE: unknown CIDATA cleanup phase %q", metadata.CleanupPhase)
	}
	return nil
}

type readyLinuxImage struct {
	PreparedVHDX string `json:"prepared_vhdx"`
	MetadataPath string `json:"metadata_path"`
}

func readReadyLinuxImage(ctx context.Context, cacheRoot string, diskSizeGB int, target Target, reg *registry.Registry, pool *agentclient.Pool) (readyLinuxImage, error) {
	script, err := hyperv.BuildLinuxImageStatusScript(cacheRoot, diskSizeGB)
	if err != nil {
		return readyLinuxImage{}, err
	}
	out, _, err := runPS(ctx, reg, pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return readyLinuxImage{}, err
	}
	var status struct {
		Status string `json:"status"`
		State  struct {
			PreparedVHDX string `json:"prepared_vhdx"`
			MetadataPath string `json:"metadata_path"`
		} `json:"state"`
	}
	if err := json.Unmarshal([]byte(jsonExtract(out)), &status); err != nil {
		return readyLinuxImage{}, fmt.Errorf("parse Linux image status: %w", err)
	}
	if status.Status != "ready" {
		return readyLinuxImage{}, nil
	}
	return readyLinuxImage{PreparedVHDX: status.State.PreparedVHDX, MetadataPath: status.State.MetadataPath}, nil
}

type linuxSeedStage struct {
	remoteDir     string
	isoPath       string
	ownershipPath string
	cleanupLocal  func()
	cleanupRemote func(context.Context) error
}

func prepareLinuxSeedPayload(ctx context.Context, plan linuxVMPlan, ownership hyperv.LinuxVMOwnership, target Target, reg *registry.Registry, pool *agentclient.Pool, config VMEnrollmentConfig) (linuxSeedStage, error) {
	if config.AuthToken == "" {
		return linuxSeedStage{}, fmt.Errorf("Linux VM enrollment requires a configured agent auth token")
	}
	if _, err := os.Stat(config.LinuxAgentBinary); err != nil {
		return linuxSeedStage{}, fmt.Errorf("linux-amd64 LabLink agent: %w", err)
	}
	certPEM, keyPEM, err := ensureGuestServerIdentity(config.PKIDir, plan.LabLinkNodeName)
	if err != nil {
		return linuxSeedStage{}, err
	}
	caPEM, err := os.ReadFile(filepath.Join(config.PKIDir, "ca-bundle", "ca.crt"))
	if err != nil {
		return linuxSeedStage{}, err
	}
	stageID, err := newRemoteStageID()
	if err != nil {
		return linuxSeedStage{}, err
	}
	localRoot := filepath.Join(config.ConfigDir, "staging")
	if err := os.MkdirAll(localRoot, 0700); err != nil {
		return linuxSeedStage{}, err
	}
	localDir, err := os.MkdirTemp(localRoot, "linux-vm-"+stageID+"-")
	if err != nil {
		return linuxSeedStage{}, err
	}
	cleanupLocal := func() { _ = os.RemoveAll(localDir) }
	seedFiles, err := linuxvm.Files(linuxvm.SeedConfig{
		Hostname: plan.Hostname, Username: plan.LinuxUsername,
		SSHPublicKey: plan.SSHPublicKey, PasswordHash: plan.PasswordHash,
		AllowSSHPasswordAuth: plan.AllowSSHPasswordAuth,
		NetworkConfig:        plan.NetworkConfig,
		NodeName:             plan.LabLinkNodeName, Port: plan.LabLinkPort,
	})
	if err != nil {
		cleanupLocal()
		return linuxSeedStage{}, err
	}
	agent, err := os.ReadFile(config.LinuxAgentBinary)
	if err != nil {
		cleanupLocal()
		return linuxSeedStage{}, err
	}
	seedFiles["lablink-agent"] = agent
	seedFiles["ca.crt"] = caPEM
	seedFiles["server.crt"] = certPEM
	seedFiles["server.key"] = keyPEM
	seedFiles["agent.token"] = []byte(config.AuthToken)

	prepareStage, err := hyperv.BuildPrepareLinuxVMStageScript(hyperv.LinuxVMOwnershipParams{Ownership: ownership})
	if err != nil {
		cleanupLocal()
		return linuxSeedStage{}, err
	}
	if _, _, err := runPS(ctx, reg, pool, target, prepareStage, vmDefaultTimeoutSec); err != nil {
		cleanupLocal()
		return linuxSeedStage{}, err
	}
	cleanupRemote := func(cleanupCtx context.Context) error {
		script, err := hyperv.BuildCleanupLinuxVMStageScript(hyperv.LinuxVMOwnershipParams{Ownership: ownership})
		if err != nil {
			return err
		}
		if _, _, err := runPS(cleanupCtx, reg, pool, target, script, vmDefaultTimeoutSec); err != nil {
			return fmt.Errorf("remove and verify restricted CIDATA staging directory: %w", err)
		}
		return nil
	}
	for name, data := range seedFiles {
		perm := os.FileMode(0644)
		if name == "server.key" || name == "agent.token" {
			perm = 0600
		}
		localPath := filepath.Join(localDir, name)
		if err := os.WriteFile(localPath, data, perm); err != nil {
			_ = cleanupRemote(context.Background())
			cleanupLocal()
			return linuxSeedStage{}, err
		}
		if err := pushToTarget(ctx, reg, pool, target, localPath, ownership.StageDir+`\`+name); err != nil {
			if cleanupErr := cleanupRemote(context.Background()); cleanupErr != nil {
				err = fmt.Errorf("%w; remote CIDATA stage cleanup failed: %v", err, cleanupErr)
			}
			cleanupLocal()
			return linuxSeedStage{}, err
		}
	}
	ownershipPath, _ := winpath.Join(ownership.VMLocation, hyperv.LinuxVMOwnershipFile)
	return linuxSeedStage{
		remoteDir: ownership.StageDir, isoPath: ownership.ISOPath, ownershipPath: ownershipPath,
		cleanupLocal: cleanupLocal, cleanupRemote: cleanupRemote,
	}, nil
}

func linuxVMOwnership(plan linuxVMPlan, persistedISO string) (hyperv.LinuxVMOwnership, error) {
	vmLocation := plan.VMLocation
	isoPath := persistedISO
	if isoPath == "" {
		var err error
		isoPath, err = winpath.Join(vmLocation, "cidata.iso")
		if err != nil {
			return hyperv.LinuxVMOwnership{}, err
		}
	}
	stageDir, err := winpath.Join(vmLocation, ".lablink-cidata-stage")
	if err != nil {
		return hyperv.LinuxVMOwnership{}, err
	}
	return hyperv.LinuxVMOwnership{
		SchemaVersion: hyperv.LinuxVMOwnershipSchema,
		VMName:        plan.Name, ManagedRoot: plan.VMRoot, VMLocation: vmLocation,
		ChildVHDX: plan.VHDPath, ISOPath: isoPath, StageDir: stageDir,
	}, nil
}

func reconcileLinuxVMArtifacts(ctx context.Context, name string, ownership hyperv.LinuxVMOwnership, target Target, reg *registry.Registry, pool *agentclient.Pool) error {
	script, err := hyperv.BuildReconcileLinuxVMArtifactsScript(hyperv.ReconcileLinuxVMArtifactsParams{
		Name: name, Ownership: ownership,
	})
	if err != nil {
		return err
	}
	if _, _, err := runPS(ctx, reg, pool, target, script, vmDefaultTimeoutSec); err != nil {
		return fmt.Errorf("reconcile managed Linux VM artifacts: %w", err)
	}
	return nil
}

func linuxVMExists(ctx context.Context, name string, target Target, reg *registry.Registry, pool *agentclient.Pool) bool {
	script := fmt.Sprintf(`if (Get-VM -Name %s -ErrorAction SilentlyContinue) { '{"exists":true}' } else { '{"exists":false}' }`, hyperv.PSLit(name))
	out, _, err := runPS(ctx, reg, pool, target, script, vmDefaultTimeoutSec)
	return err == nil && strings.Contains(out, `"exists":true`)
}

func retainedLinuxVMError(plan linuxVMPlan, isoPath string, err error) *mcp.CallToolResult {
	body, _ := json.MarshalIndent(map[string]any{
		"status": "vm_retained_for_diagnosis", "vm_created": true,
		"name": plan.Name, "target": plan.Target, "cidata_iso": isoPath,
		"registered":      plan.Registered,
		"action_required": "Diagnose/resume the managed VM. The persisted cleanup phase identifies whether the expected CIDATA ISO remains attached or detached.",
		"error":           err.Error(),
	}, "", "  ")
	return vmResult("**Linux VM retained for diagnosis** — registration was not completed; the guest was not added to LabLink.", string(body))
}

func linuxVMLockKey(name string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(name))))
	return fmt.Sprintf("%x", sum[:])
}

func sameWindowsPath(left, right string) bool {
	leftClean, leftErr := winpath.CleanAbsolute(left)
	rightClean, rightErr := winpath.CleanAbsolute(right)
	return leftErr == nil && rightErr == nil && strings.EqualFold(leftClean, rightClean)
}

func containsWindowsPath(paths []string, expected string) bool {
	for _, value := range paths {
		if sameWindowsPath(value, expected) {
			return true
		}
	}
	return false
}

func linuxHostname(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
		if b.Len() == 63 {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}
