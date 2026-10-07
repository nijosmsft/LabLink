package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/vmconfig"
)

type windowsVMPlan struct {
	Profile                   string  `json:"profile,omitempty"`
	Target                    string  `json:"target"`
	Name                      string  `json:"name"`
	Hostname                  string  `json:"hostname"`
	BaseVHD                   string  `json:"base_vhd"`
	VMRoot                    string  `json:"vm_root,omitempty"`
	VHDPath                   string  `json:"vhd_path"`
	VMLocation                string  `json:"vm_location"`
	VSwitch                   string  `json:"vswitch"`
	AdminPasswordCredential   string  `json:"admin_password_credential"`
	MemoryMB                  float64 `json:"memory_mb"`
	CPUCount                  float64 `json:"cpu_count"`
	DynamicMemory             bool    `json:"dynamic_memory"`
	DynamicMinMB              float64 `json:"dynamic_min_mb,omitempty"`
	DynamicMaxMB              float64 `json:"dynamic_max_mb,omitempty"`
	DynamicBufferPct          float64 `json:"dynamic_buffer_pct,omitempty"`
	SecureBoot                bool    `json:"secure_boot"`
	Locale                    string  `json:"locale"`
	TimeZone                  string  `json:"timezone,omitempty"`
	FirstBootScript           string  `json:"-"`
	AutoLogon                 bool    `json:"auto_logon"`
	ObfuscatePassword         bool    `json:"obfuscate_password"`
	RegisterWithLabLink       bool    `json:"register_with_lablink"`
	LabLinkNodeName           string  `json:"lablink_node_name,omitempty"`
	LabLinkRole               string  `json:"lablink_role,omitempty"`
	LabLinkPort               int     `json:"lablink_port,omitempty"`
	LabLinkAddress            string  `json:"lablink_address,omitempty"`
	State                     string  `json:"state,omitempty"`
	MinHostReservePct         float64 `json:"min_host_reserve_pct"`
	AllowHostResourcePressure bool    `json:"allow_host_resource_pressure"`
	ResourceSafety            any     `json:"resource_safety,omitempty"`
}

func createWindowsVMHandler(
	s *server.MCPServer,
	reg *registry.Registry,
	pool *agentclient.Pool,
	creds *credentials.Store,
	defaults *vmconfig.Store,
	auditLog *audit.Log,
	enrollment VMEnrollmentConfig,
	leaseCfg LeaseGateConfig,
) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		plan, err := resolveWindowsVMPlan(ctx, s, req, reg, pool, creds, defaults)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		start := time.Now()
		stopHB := StartMCPHeartbeat(ctx, req, defaultHeartbeatInterval, func() (int64, int64) {
			return int64(time.Since(start).Seconds()), 20 * 60
		})
		defer stopHB()
		if req.GetBool("dry_run", false) {
			safety, err := checkWindowsVMResources(ctx, plan, reg, pool)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			plan.ResourceSafety = safety
			return vmResult("**Resolved Windows VM configuration** (dry run; no changes made)", marshalPlan(plan)), nil
		}

		gatedReq := req
		args := cloneArguments(req.GetArguments())
		args["target"] = plan.Target
		gatedReq.Params.Arguments = args
		gatedReq.Params.Name = "create_windows_vm"

		execute := func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return executeWindowsVMPlan(ctx, plan, reg, pool, creds, auditLog, enrollment)
		}
		return LeaseGate(leaseCfg, extractTarget("target"), execute)(ctx, gatedReq)
	}
}

func resolveWindowsVMPlan(
	ctx context.Context,
	s *server.MCPServer,
	req mcp.CallToolRequest,
	reg *registry.Registry,
	pool *agentclient.Pool,
	creds *credentials.Store,
	defaults *vmconfig.Store,
) (windowsVMPlan, error) {
	requestedTarget := req.GetString("target", "")
	profile, profileName, err := defaults.ResolveForTarget(req.GetString("profile", ""), requestedTarget)
	if err != nil {
		return windowsVMPlan{}, err
	}
	plan := planFromProfile(profile, profileName)
	applyPlanArguments(&plan, req)

	firstMissing := missingPlanFields(plan, false)
	if len(firstMissing) > 0 {
		properties := map[string]any{}
		required := make([]string, 0, len(firstMissing))
		for _, field := range firstMissing {
			required = append(required, field)
			switch field {
			case "target":
				values := []string{"localhost"}
				for _, node := range reg.AllNodes() {
					values = append(values, node.Name)
				}
				sort.Strings(values)
				properties[field] = stringField("Target Hyper-V host", values)
			case "name":
				properties[field] = stringField("VM name", nil)
			case "base_vhd":
				properties[field] = stringField("Shared sysprepped Windows base VHDX path", nil)
			case "vm_root":
				properties[field] = stringField("Root folder for VM config and differencing disks", nil)
			case "admin_password_credential":
				properties[field] = stringField("Saved administrator credential profile", creds.List())
			}
		}
		content, err := elicitVMFields(ctx, s, "Provide the missing Windows VM settings. Explicit values will override defaults.", properties, required)
		if err != nil {
			return windowsVMPlan{}, elicitationConfigError(err, defaults, firstMissing)
		}
		applyStringContent(&plan, content)
	}

	derivePlanPaths(&plan)
	if strings.TrimSpace(plan.VSwitch) == "" {
		target, err := resolvePlanTarget(plan.Target, reg)
		if err != nil {
			return windowsVMPlan{}, err
		}
		out, _, err := runPS(ctx, reg, pool, target, hyperv.BuildListVSwitchesScript(), vmDefaultTimeoutSec)
		if err != nil {
			return windowsVMPlan{}, fmt.Errorf("discover vSwitches: %w", err)
		}
		switches, err := hyperv.ParseVSwitches(out)
		if err != nil {
			return windowsVMPlan{}, fmt.Errorf("parse vSwitches: %w", err)
		}
		if len(switches) == 1 {
			plan.VSwitch = switches[0].Name
		} else {
			values := make([]string, 0, len(switches))
			for _, item := range switches {
				values = append(values, item.Name)
			}
			content, err := elicitVMFields(ctx, s, "Select the Hyper-V vSwitch for the new VM.", map[string]any{
				"vswitch": stringField("Hyper-V vSwitch", values),
			}, []string{"vswitch"})
			if err != nil {
				return windowsVMPlan{}, elicitationConfigError(err, defaults, []string{"vswitch"})
			}
			applyStringContent(&plan, content)
		}
	}

	if missing := missingPlanFields(plan, true); len(missing) > 0 {
		return windowsVMPlan{}, fmt.Errorf("incomplete Windows VM configuration; missing: %s", strings.Join(missing, ", "))
	}
	if err := validateVMPathName(plan.Name); err != nil {
		return windowsVMPlan{}, err
	}
	if strings.TrimSpace(plan.Hostname) == "" {
		return windowsVMPlan{}, fmt.Errorf("VM name %q does not produce a valid Windows hostname; provide hostname explicitly", plan.Name)
	}
	if _, err := creds.Get(plan.AdminPasswordCredential); err != nil {
		return windowsVMPlan{}, err
	}
	return plan, nil
}

func planFromProfile(p vmconfig.Profile, name string) windowsVMPlan {
	secureBoot := true
	if p.SecureBoot != nil {
		secureBoot = *p.SecureBoot
	}
	memory := p.MemoryMB
	if memory <= 0 {
		memory = 4096
	}
	cpu := p.CPUCount
	if cpu <= 0 {
		cpu = 2
	}
	locale := p.Locale
	if locale == "" {
		locale = "en-US"
	}
	return windowsVMPlan{
		Profile: name, Target: p.Target, BaseVHD: p.BaseVHD, VSwitch: p.VSwitch,
		AdminPasswordCredential: p.AdminCredential, MemoryMB: memory, CPUCount: cpu,
		DynamicMemory: p.DynamicMemory, DynamicMinMB: p.DynamicMinMB,
		DynamicMaxMB: p.DynamicMaxMB, DynamicBufferPct: p.DynamicBufferPct,
		SecureBoot: secureBoot, Locale: locale, TimeZone: p.TimeZone,
		AutoLogon: p.AutoLogon, ObfuscatePassword: p.ObfuscatePassword,
		RegisterWithLabLink: p.RegisterLabLink, LabLinkRole: p.LabLinkRole,
		LabLinkPort: p.LabLinkPort, VMRoot: p.VMRoot,
		MinHostReservePct: p.MinHostReservePct,
	}
}

func applyPlanArguments(plan *windowsVMPlan, req mcp.CallToolRequest) {
	args := req.GetArguments()
	applyStringArg(args, "target", &plan.Target)
	applyStringArg(args, "name", &plan.Name)
	applyStringArg(args, "hostname", &plan.Hostname)
	applyStringArg(args, "base_vhd", &plan.BaseVHD)
	applyStringArg(args, "vm_root", &plan.VMRoot)
	applyStringArg(args, "vhd_path", &plan.VHDPath)
	applyStringArg(args, "vm_location", &plan.VMLocation)
	applyStringArg(args, "vswitch", &plan.VSwitch)
	applyStringArg(args, "admin_password_credential", &plan.AdminPasswordCredential)
	applyStringArg(args, "locale", &plan.Locale)
	applyStringArg(args, "timezone", &plan.TimeZone)
	applyStringArg(args, "first_boot_script", &plan.FirstBootScript)
	applyStringArg(args, "lablink_node_name", &plan.LabLinkNodeName)
	applyStringArg(args, "lablink_role", &plan.LabLinkRole)
	applyFloatArg(args, "memory_mb", &plan.MemoryMB)
	applyFloatArg(args, "cpu_count", &plan.CPUCount)
	applyFloatArg(args, "dynamic_min_mb", &plan.DynamicMinMB)
	applyFloatArg(args, "dynamic_max_mb", &plan.DynamicMaxMB)
	applyFloatArg(args, "dynamic_buffer_pct", &plan.DynamicBufferPct)
	applyFloatArg(args, "min_host_reserve_pct", &plan.MinHostReservePct)
	applyBoolArg(args, "dynamic_memory", &plan.DynamicMemory)
	applyBoolArg(args, "secure_boot", &plan.SecureBoot)
	applyBoolArg(args, "auto_logon", &plan.AutoLogon)
	applyBoolArg(args, "obfuscate_password", &plan.ObfuscatePassword)
	applyBoolArg(args, "register_with_lablink", &plan.RegisterWithLabLink)
	applyBoolArg(args, "allow_host_resource_pressure", &plan.AllowHostResourcePressure)
	if value, ok := numericArgument(args["lablink_port"]); ok {
		plan.LabLinkPort = int(value)
	}
}

func missingPlanFields(plan windowsVMPlan, final bool) []string {
	var missing []string
	locationRoot := plan.VMRoot
	if locationRoot == "" {
		locationRoot = plan.VMLocation
	}
	for name, value := range map[string]string{
		"target": plan.Target, "name": plan.Name, "base_vhd": plan.BaseVHD,
		"vm_root": locationRoot, "admin_password_credential": plan.AdminPasswordCredential,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if final && strings.TrimSpace(plan.VSwitch) == "" {
		missing = append(missing, "vswitch")
	}
	sort.Strings(missing)
	return missing
}

func derivePlanPaths(plan *windowsVMPlan) {
	if plan.Hostname == "" {
		plan.Hostname = windowsHostname(plan.Name)
	}
	if plan.RegisterWithLabLink {
		if plan.LabLinkNodeName == "" {
			plan.LabLinkNodeName = plan.Hostname
		}
		if plan.MinHostReservePct <= 0 {
			plan.MinHostReservePct = 10
		}
		if plan.LabLinkRole == "" {
			plan.LabLinkRole = "vm"
		}
		if plan.LabLinkPort <= 0 {
			plan.LabLinkPort = 9091
		}
	}
	root := plan.VMRoot
	if root == "" {
		root = plan.VMLocation
	}
	if root == "" || plan.Name == "" {
		return
	}
	if plan.VMLocation == "" {
		plan.VMLocation = filepath.Join(root, plan.Name)
	}
	if plan.VHDPath == "" {
		plan.VHDPath = filepath.Join(plan.VMLocation, plan.Name+".vhdx")
	}
}

func windowsHostname(name string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(name) {
		if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		}
		if b.Len() == 15 {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}

func validateVMPathName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("invalid VM name %q", name)
	}
	if strings.ContainsAny(name, `\/:*?"<>|`) {
		return fmt.Errorf("VM name %q contains a character unsafe for its VM/VHD folder", name)
	}
	return nil
}

func executeWindowsVMPlan(ctx context.Context, plan windowsVMPlan, reg *registry.Registry, pool *agentclient.Pool, creds *credentials.Store, auditLog *audit.Log, enrollment VMEnrollmentConfig) (*mcp.CallToolResult, error) {
	safety, err := checkWindowsVMResources(ctx, plan, reg, pool)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	plan.ResourceSafety = safety
	payload, err := prepareEnrollmentPayload(ctx, plan, enrollment, reg, pool)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if payload.Cleanup != nil {
		defer payload.Cleanup()
	}
	provisionReq := mcp.CallToolRequest{}
	firstBootScript := plan.FirstBootScript
	autoLogon := plan.AutoLogon
	if plan.RegisterWithLabLink {
		firstBootScript = enrollmentFirstBootScript(plan.FirstBootScript)
		autoLogon = true
	}
	provisionReq.Params.Arguments = map[string]any{
		"target": plan.Target, "vm_name": plan.Name, "hostname": plan.Hostname,
		"base_vhd": plan.BaseVHD, "vhd_path": plan.VHDPath,
		"admin_password_credential": plan.AdminPasswordCredential,
		"locale":                    plan.Locale, "timezone": plan.TimeZone,
		"first_boot_script": firstBootScript, "auto_logon": autoLogon,
		"obfuscate_password": plan.ObfuscatePassword, "injection_method": "mount-vhd",
		"payload_remote_dir": payload.RemoteDir,
	}
	provisioned, err := provisionUnattendHandler(reg, pool, creds, auditLog)(ctx, provisionReq)
	if err != nil || provisioned == nil || provisioned.IsError {
		return provisioned, err
	}

	createReq := mcp.CallToolRequest{}
	createReq.Params.Arguments = map[string]any{
		"target": plan.Target, "name": plan.Name, "vm_location": plan.VMLocation,
		"vhd_path": plan.VHDPath, "memory_mb": plan.MemoryMB, "cpu_count": plan.CPUCount,
		"dynamic_memory": plan.DynamicMemory, "dynamic_min_mb": plan.DynamicMinMB,
		"dynamic_max_mb": plan.DynamicMaxMB, "dynamic_buffer_pct": plan.DynamicBufferPct,
		"vswitch": plan.VSwitch, "secure_boot": plan.SecureBoot,
		"min_host_reserve_pct":         plan.MinHostReservePct,
		"allow_host_resource_pressure": plan.AllowHostResourcePressure,
	}
	created, err := createVMHandler(reg, pool, auditLog)(ctx, createReq)
	if err != nil || created == nil || created.IsError {
		cleanupProvisionedVHD(ctx, plan, reg, pool)
		return created, err
	}
	if plan.RegisterWithLabLink {
		started, err := startVMAndDiscoverIP(ctx, plan, reg, pool)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("VM created but guest start/IP discovery failed: %v", err)), nil
		}
		if err := registerEnrolledVM(ctx, plan, started, reg, pool); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("VM created at %s but LabLink registration failed: %v", started.IPAddress, err)), nil
		}
		plan.LabLinkAddress = fmt.Sprintf("%s:%d", started.IPAddress, plan.LabLinkPort)
		plan.State = started.State
	}
	return vmResult(fmt.Sprintf("**Windows VM `%s` created on `%s`**", plan.Name, plan.Target), marshalPlan(plan)), nil
}

func cleanupProvisionedVHD(ctx context.Context, plan windowsVMPlan, reg *registry.Registry, pool *agentclient.Pool) {
	target, err := resolvePlanTarget(plan.Target, reg)
	if err != nil {
		return
	}
	script := fmt.Sprintf(`$p=%s; if (-not (Get-VM | Get-VMHardDiskDrive -ErrorAction SilentlyContinue | Where-Object Path -eq $p)) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }`, hyperv.PSLit(plan.VHDPath))
	_, _, _ = runPS(ctx, reg, pool, target, script, vmDefaultTimeoutSec)
}

func resolvePlanTarget(name string, reg *registry.Registry) (Target, error) {
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"target": name}
	return resolveTarget(req, reg)
}

func elicitVMFields(ctx context.Context, s *server.MCPServer, message string, properties map[string]any, required []string) (map[string]any, error) {
	result, err := s.RequestElicitation(ctx, mcp.ElicitationRequest{Params: mcp.ElicitationParams{
		Message: message,
		RequestedSchema: map[string]any{
			"type": "object", "properties": properties, "required": required,
			"additionalProperties": false,
		},
	}})
	if err != nil {
		return nil, err
	}
	if result.Action != mcp.ElicitationResponseActionAccept {
		return nil, fmt.Errorf("VM configuration prompt was %s", result.Action)
	}
	content, ok := result.Content.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("VM configuration prompt returned invalid content")
	}
	return content, nil
}

func stringField(description string, values []string) map[string]any {
	field := map[string]any{"type": "string", "description": description}
	if len(values) > 0 {
		field["enum"] = values
	}
	return field
}

func elicitationConfigError(err error, defaults *vmconfig.Store, missing []string) error {
	if errors.Is(err, server.ErrElicitationNotSupported) {
		return fmt.Errorf("missing VM settings (%s); client does not support elicitation. Supply arguments or configure %s", strings.Join(missing, ", "), defaults.Path())
	}
	return err
}

func applyStringContent(plan *windowsVMPlan, content map[string]any) {
	if value, ok := content["target"].(string); ok {
		plan.Target = value
	}
	if value, ok := content["name"].(string); ok {
		plan.Name = value
	}
	if value, ok := content["base_vhd"].(string); ok {
		plan.BaseVHD = value
	}
	if value, ok := content["vm_root"].(string); ok {
		plan.VMRoot = value
	}
	if value, ok := content["admin_password_credential"].(string); ok {
		plan.AdminPasswordCredential = value
	}
	if value, ok := content["vswitch"].(string); ok {
		plan.VSwitch = value
	}
}

func applyStringArg(args map[string]any, name string, dst *string) {
	if value, ok := args[name].(string); ok {
		*dst = value
	}
}

func applyFloatArg(args map[string]any, name string, dst *float64) {
	if value, ok := numericArgument(args[name]); ok {
		*dst = value
	}
}

func numericArgument(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	}
	return 0, false
}

func applyBoolArg(args map[string]any, name string, dst *bool) {
	if value, ok := args[name].(bool); ok {
		*dst = value
	}
}

func cloneArguments(args map[string]any) map[string]any {
	out := make(map[string]any, len(args)+1)
	for key, value := range args {
		out[key] = value
	}
	return out
}

func marshalPlan(plan windowsVMPlan) string {
	data, _ := json.MarshalIndent(plan, "", "  ")
	return string(data)
}
