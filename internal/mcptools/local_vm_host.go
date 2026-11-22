package mcptools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/secretstore"
	"github.com/nijosmsft/lablink/internal/security"
	"github.com/nijosmsft/lablink/internal/vmconfig"
	"github.com/nijosmsft/lablink/internal/winpath"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

const LocalHyperVCapability = "hyperv.manage.v1"

var localVMTools = map[string]bool{
	"list_physical_nics": true, "list_vswitches": true, "create_vswitch": true,
	"create_vm": true, "create_windows_vm": true, "create_linux_vm": true,
	"delete_vm": true, "prepare_linux_image": true, "get_linux_image_status": true,
	"create_isolated_orchestrator": true, "list_isolated_orchestrators": true,
	"get_isolated_orchestrator": true, "delete_isolated_orchestrator": true,
	"add_isolated_network": true, "remove_isolated_network": true,
	"create_isolated_vm": true, "delete_isolated_vm": true,
	"list_isolated_vms": true, "get_isolated_vm": true,
	"rename_isolated_display_name": true,
	"enable_isolated_vm_nat":       true, "disable_isolated_vm_nat": true,
	"get_isolated_vm_nat": true, "list_isolated_vm_nat": true,
	"list_isolated_relays": true, "get_isolated_relay_stats": true,
	"validate_isolated_relay": true, "rebind_isolated_relays": true,
}

// LocalVMPolicy is installed by an administrator. Neither the VM root nor
// trusted images/binaries can be changed through the management RPC.
type LocalVMPolicy struct {
	StateDir       string   `json:"state_dir"`
	VMRoot         string   `json:"vm_root"`
	ImageRoot      string   `json:"image_root"`
	BaseVHDs       []string `json:"base_vhds"`
	SourceBaseVHDs []string `json:"source_base_vhds,omitempty"`
	VSwitches      []string `json:"vswitches"`
	InstallRoot    string   `json:"install_root"`
	PKIDir         string   `json:"pki_dir"`
}

func DecodeLocalVMPolicy(data []byte) (LocalVMPolicy, error) {
	var policy LocalVMPolicy
	if err := decodeStrictJSON(data, &policy); err != nil {
		return policy, err
	}
	for _, path := range []string{policy.StateDir, policy.VMRoot, policy.ImageRoot, policy.InstallRoot, policy.PKIDir} {
		if _, err := winpath.CleanAbsolute(path); err != nil {
			return policy, fmt.Errorf("restricted Hyper-V policy: %w", err)
		}
	}
	for _, path := range []string{policy.ImageRoot, policy.InstallRoot, policy.PKIDir} {
		if strings.EqualFold(policy.VMRoot, path) || localVMWithin(policy.VMRoot, path) || localVMWithin(path, policy.VMRoot) {
			return policy, fmt.Errorf("VM root must not overlap images, trusted code, or PKI")
		}
	}
	for _, root := range []string{policy.VMRoot, policy.ImageRoot} {
		for _, path := range []string{policy.StateDir, policy.InstallRoot, policy.PKIDir,
			policy.StateDir + `\tls`, policy.StateDir + `\Temp`, policy.StateDir + `\VMEnrollment`, policy.StateDir + `\staging`} {
			if strings.EqualFold(root, path) || localVMWithin(root, path) || localVMWithin(path, root) && !strings.EqualFold(path, policy.StateDir) {
				return policy, fmt.Errorf("guest storage must not overlap private service state or trusted code")
			}
		}
	}
	if strings.EqualFold(policy.StateDir, policy.InstallRoot) || localVMWithin(policy.StateDir, policy.InstallRoot) {
		return policy, fmt.Errorf("trusted code must not be stored under service-writable state")
	}
	for _, path := range policy.BaseVHDs {
		if _, err := winpath.CleanAbsolute(path); err != nil {
			return policy, err
		}
	}
	return policy, nil
}

func decodeStrictJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("unexpected trailing JSON: %v", err)
	}
	return nil
}

func localVMWithin(root, path string) bool {
	cleanRoot, err := winpath.CleanAbsolute(root)
	if err != nil {
		return false
	}
	cleanPath, err := winpath.CleanAbsolute(path)
	if err != nil {
		return false
	}
	return strings.HasPrefix(strings.ToLower(cleanPath), strings.ToLower(strings.TrimSuffix(cleanRoot, `\`)+`\`))
}

func rejectLocalVMReparse(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("restricted VM paths must not traverse a reparse point: %s", current)
		}
		parent := filepath.Dir(current)
		if parent == current || current == "." {
			break
		}
	}
	return nil
}

func (p LocalVMPolicy) writable(path string) error {
	if !strings.EqualFold(path, p.VMRoot) && !localVMWithin(p.VMRoot, path) {
		return fmt.Errorf("restricted Hyper-V writes must stay under %s", p.VMRoot)
	}
	return rejectLocalVMReparse(path)
}

func (p LocalVMPolicy) image(path string) error {
	allowed := localVMWithin(p.ImageRoot, path)
	for _, base := range p.BaseVHDs {
		allowed = allowed || strings.EqualFold(base, path)
	}
	if !allowed {
		return fmt.Errorf("image %q is not approved by the restricted Hyper-V installation", path)
	}
	return rejectLocalVMReparse(path)
}

// LocalVMHost invokes the same tool handlers used by the normal MCP server,
// with an immutable host policy and request-scoped in-memory credentials.
type LocalVMHost struct {
	policy  LocalVMPolicy
	reg     *registry.Registry
	pool    *agentclient.Pool
	state   *isolatedstate.Store
	token   string
	version string
	mu      sync.Mutex
}

func NewLocalVMHost(policy LocalVMPolicy, token, version string, transport security.ClientTransportConfig) (*LocalVMHost, error) {
	if token == "" {
		return nil, fmt.Errorf("restricted Hyper-V authentication token is required")
	}
	state, err := isolatedstate.Open(filepath.Join(policy.StateDir, "isolated.db"))
	if err != nil {
		return nil, err
	}
	return &LocalVMHost{
		policy: policy, reg: registry.Load(filepath.Join(policy.StateDir, "nodes.json")),
		pool: agentclient.NewPool(token, transport), state: state, token: token, version: version,
	}, nil
}

func (h *LocalVMHost) Close() error {
	h.pool.Close()
	return h.state.Close()
}

func (h *LocalVMHost) Call(ctx context.Context, request *pb.ManageVMRequest) (*mcp.CallToolResult, []*registry.Node, error) {
	if !localVMTools[request.GetToolName()] {
		return nil, nil, fmt.Errorf("operation is unavailable in Hyper-V-only mode")
	}
	if len(request.ArgumentsJson) > 1024*1024 || len(request.ProfilesJson) > 1024*1024 || len(request.Credentials) > 64 {
		return nil, nil, fmt.Errorf("restricted VM request exceeds size limits")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var args map[string]any
	if err := decodeStrictJSON(request.GetArgumentsJson(), &args); err != nil {
		return nil, nil, err
	}
	if args == nil {
		args = make(map[string]any)
	}
	var config vmconfig.Config
	if err := decodeStrictJSON(request.GetProfilesJson(), &config); err != nil {
		return nil, nil, err
	}
	for name, profile := range config.Profiles {
		profile.Target = "localhost"
		config.Profiles[name] = profile
	}
	config.TargetDefaults = nil
	config.LinuxTargetDefaults = nil
	profiles := make([]*credentials.Profile, 0, len(request.Credentials))
	for _, credential := range request.Credentials {
		if credential == nil || len(credential.Password) > 16384 {
			return nil, nil, fmt.Errorf("invalid VM credential")
		}
		profiles = append(profiles, &credentials.Profile{
			Name: credential.Name, Username: credential.Username, Password: credential.Password,
		})
	}
	creds, err := credentials.NewTransient(profiles)
	if err != nil {
		return nil, nil, err
	}
	runtimeDir, err := os.MkdirTemp(h.policy.StateDir, "vm-request-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(runtimeDir)
	data, err := json.Marshal(config)
	if err != nil {
		return nil, nil, err
	}
	defaultsPath := filepath.Join(runtimeDir, "vm-defaults.json")
	if err := os.WriteFile(defaultsPath, data, 0600); err != nil {
		return nil, nil, err
	}
	defaults := vmconfig.Load(defaultsPath)
	enrollment := VMEnrollmentConfig{
		ConfigDir: h.policy.StateDir, PKIDir: h.policy.PKIDir, AuthToken: h.token,
		AgentBinary:      filepath.Join(h.policy.InstallRoot, "bin", "lablink-agent.exe"),
		LinuxAgentBinary: filepath.Join(h.policy.InstallRoot, "bin", "linux-amd64", "lablink-agent"),
	}
	log := audit.NewLog(h.policy.StateDir)
	secrets := secretstore.Open(filepath.Join(runtimeDir, "unused-secrets.json"))
	s := server.NewMCPServer("local-hyperv", h.version)
	RegisterVM(s, h.reg, h.pool, creds, secrets, defaults, log, enrollment, LeaseGateConfig{})
	deps, err := NewIsolatedLifecycleDependencies(s, h.state, h.reg, h.pool, defaults, creds, secrets, log, enrollment, LeaseGateConfig{}, h.version)
	if err != nil {
		return nil, nil, err
	}
	RegisterIsolatedLifecycleTools(s, deps)
	tool := s.ListTools()[request.ToolName]
	if tool == nil {
		return nil, nil, fmt.Errorf("unsupported VM operation")
	}
	if err := validateLocalVMArguments(tool.Tool, args); err != nil {
		return nil, nil, err
	}
	args["target"] = "localhost"
	req := reqNoMeta(request.ToolName, args)
	if err := h.validate(ctx, req, defaults); err != nil {
		return nil, nil, err
	}
	result, err := tool.Handler(ctx, req)
	return result, h.reg.AllNodes(), err
}

func validateLocalVMArguments(tool mcp.Tool, args map[string]any) error {
	data, err := json.Marshal(tool.InputSchema.Properties)
	if err != nil {
		return err
	}
	var properties map[string]struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &properties); err != nil {
		return err
	}
	for _, field := range tool.InputSchema.Required {
		if value, exists := args[field]; !exists || value == nil {
			return fmt.Errorf("missing required VM argument %q", field)
		}
	}
	for key, value := range args {
		property, exists := properties[key]
		if !exists {
			return fmt.Errorf("unknown argument %q for %s", key, tool.Name)
		}
		valid := false
		switch property.Type {
		case "string":
			_, valid = value.(string)
		case "boolean":
			_, valid = value.(bool)
		case "number", "integer":
			_, valid = value.(float64)
		case "array":
			_, valid = value.([]any)
		case "object":
			_, valid = value.(map[string]any)
		}
		if !valid {
			return fmt.Errorf("VM argument %q must have type %s", key, property.Type)
		}
	}
	return nil
}

func reqNoMeta(name string, args map[string]any) mcp.CallToolRequest {
	req := mcp.CallToolRequest{}
	req.Params.Name, req.Params.Arguments = name, args
	return req
}

func (h *LocalVMHost) validate(ctx context.Context, req mcp.CallToolRequest, defaults *vmconfig.Store) error {
	args := req.GetArguments()
	if req.GetString("ssh_public_key_file", "") != "" {
		return fmt.Errorf("provide the public key inline; restricted service-side file reads are not allowed")
	}
	if args["domain_join"] != nil {
		return fmt.Errorf("join the created VM through its full guest agent after provisioning")
	}
	if value := req.GetString("main_vswitch", ""); value != "" {
		if err := h.validateSwitch(ctx, value); err != nil {
			return err
		}
	}
	for _, key := range []string{"vm_location", "vhd_path", "new_vhd_path"} {
		if value, ok := args[key].(string); ok && value != "" {
			if err := h.policy.writable(value); err != nil {
				return err
			}
		}
	}
	for _, key := range []string{"vm_root", "managed_root"} {
		if value, ok := args[key].(string); ok && value != "" && !strings.EqualFold(value, h.policy.VMRoot) {
			return fmt.Errorf("%s must be the installed restricted VM root", key)
		}
	}
	for _, key := range []string{"base_vhd", "iso_path"} {
		if value, ok := args[key].(string); ok && value != "" {
			if err := h.policy.image(value); err != nil {
				return err
			}
		}
	}
	if value, ok := args["image_cache_root"].(string); ok && value != "" && !strings.EqualFold(value, h.policy.ImageRoot) {
		return fmt.Errorf("image_cache_root must match the installed image root")
	}
	switch req.Params.Name {
	case "create_vswitch":
		mode := strings.ToLower(strings.TrimSpace(req.GetString("if_exists", "reuse")))
		if mode != "reuse" && mode != "fail" {
			return fmt.Errorf("restricted switch creation permits only reuse or fail")
		}
		args["if_exists"] = mode
		if !strings.HasPrefix(strings.ToLower(req.GetString("name", "")), "lablink-") ||
			(req.GetString("type", "") != "private" && req.GetString("type", "") != "internal") {
			return fmt.Errorf("restricted switch creation requires a LabLink- name and private/internal type")
		}
	case "create_windows_vm":
		profile, _, err := defaults.ResolveOrdinaryWindowsForTarget(req.GetString("profile", ""), "localhost")
		if err != nil {
			return err
		}
		if err := h.validateEffectiveProfile(ctx, profile, args, false); err != nil {
			return err
		}
		if profile.DomainJoin != nil || args["domain_join"] != nil {
			return fmt.Errorf("join the created VM through its full guest agent after provisioning")
		}
	case "create_linux_vm", "prepare_linux_image", "get_linux_image_status", "create_isolated_orchestrator":
		var profile vmconfig.Profile
		var err error
		if req.Params.Name == "create_isolated_orchestrator" {
			resolved, _, resolveErr := defaults.ResolveIsolatedOrchestratorForTarget(req.GetString("profile", ""), "localhost")
			profile, err = resolved.LinuxVM, resolveErr
			if resolved.Profile.OfflineBundlePath != "" && !localVMWithin(h.policy.ImageRoot, resolved.Profile.OfflineBundlePath) {
				return fmt.Errorf("offline appliance bundle must be under the installed image root")
			}
		} else {
			profile, _, err = defaults.ResolveLinuxForTarget(req.GetString("profile", ""), "localhost")
		}
		if err != nil {
			return err
		}
		if err := h.validateEffectiveProfile(ctx, profile, args, true); err != nil {
			return err
		}
		builderName := req.GetString("image_builder_profile", profile.ImageBuilderProfile)
		if builderName != "" {
			builder, _, err := defaults.ResolveWindows(builderName)
			if err != nil {
				return err
			}
			if err := h.validateProfile(ctx, builder, false); err != nil {
				return err
			}
		}
	case "create_isolated_vm":
		guestOS := strings.ToLower(strings.TrimSpace(req.GetString("guest_os", "")))
		if guestOS != vmconfig.GuestOSLinux && guestOS != vmconfig.GuestOSWindows {
			return fmt.Errorf("guest_os must be windows or linux")
		}
		args["guest_os"] = guestOS
		profile, _, err := defaults.ResolveForTarget(req.GetString("profile", ""), "localhost")
		if err != nil {
			return err
		}
		profileOS, err := profile.EffectiveGuestOS()
		if err != nil || profileOS != guestOS {
			return fmt.Errorf("guest_os must agree with the selected VM profile")
		}
		if err := h.validateProfile(ctx, profile, guestOS == vmconfig.GuestOSLinux); err != nil {
			return err
		}
		if profile.DomainJoin != nil {
			return fmt.Errorf("join the created VM through its full guest agent after provisioning")
		}
		if guestOS == vmconfig.GuestOSLinux && profile.ImageBuilderProfile != "" {
			builder, _, err := defaults.ResolveWindows(profile.ImageBuilderProfile)
			if err != nil {
				return err
			}
			if err := h.validateProfile(ctx, builder, false); err != nil {
				return err
			}
		}
	case "delete_vm":
		name := req.GetString("name", "")
		if err := validateVMPathName(name); err != nil {
			return err
		}
		script := fmt.Sprintf(`$vm=Get-VM -Name %s -ErrorAction SilentlyContinue
if($vm){[pscustomobject]@{path=[string]$vm.Path}|ConvertTo-Json -Compress}else{'{}'}`, hyperv.PSLit(name))
		out, _, err := runPS(ctx, h.reg, h.pool, Target{Name: "localhost", IsLocal: true}, script, 60)
		if err != nil {
			return err
		}
		var existing struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal([]byte(jsonExtract(out)), &existing); err != nil {
			return err
		}
		if existing.Path != "" {
			if err := h.policy.writable(existing.Path); err != nil {
				return fmt.Errorf("VM is not owned by the restricted host: %w", err)
			}
		}
		args["managed_root"] = h.policy.VMRoot
	case "create_vm":
		if req.GetBool("use_host_defaults", false) {
			return fmt.Errorf("host-default VM storage is not allowed in restricted mode")
		}
		if req.GetString("vm_location", "") == "" {
			return fmt.Errorf("vm_location is required under the restricted VM root")
		}
	}
	if value := req.GetString("vswitch", ""); value != "" {
		if err := h.validateSwitch(ctx, value); err != nil {
			return err
		}
	}
	return nil
}

func (h *LocalVMHost) validateEffectiveProfile(ctx context.Context, profile vmconfig.Profile, args map[string]any, linux bool) error {
	applyStringArg(args, "vm_root", &profile.VMRoot)
	applyStringArg(args, "base_vhd", &profile.BaseVHD)
	applyStringArg(args, "vswitch", &profile.VSwitch)
	applyStringArg(args, "image_cache_root", &profile.ImageCacheRoot)
	applyStringArg(args, "ssh_public_key_file", &profile.SSHPublicKeyFile)
	return h.validateProfile(ctx, profile, linux)
}

func (h *LocalVMHost) validateSwitch(ctx context.Context, name string) error {
	for _, allowed := range h.policy.VSwitches {
		if strings.EqualFold(name, allowed) {
			return nil
		}
	}
	if !strings.HasPrefix(strings.ToLower(name), "lablink-") {
		return fmt.Errorf("vSwitch %q is not approved by the restricted host policy", name)
	}
	script := fmt.Sprintf(`$switch=Get-VMSwitch -Name %s -ErrorAction Stop
[string]$switch.SwitchType`, hyperv.PSLit(name))
	out, exit, err := runPS(ctx, h.reg, h.pool, Target{Name: "localhost", IsLocal: true}, script, 60)
	if err != nil {
		return err
	}
	if exit != 0 || (strings.TrimSpace(out) != "Private" && strings.TrimSpace(out) != "Internal") {
		return fmt.Errorf("unapproved LabLink switch must be private or internal")
	}
	return nil
}

func (h *LocalVMHost) validateProfile(ctx context.Context, profile vmconfig.Profile, linux bool) error {
	if profile.SSHPublicKeyFile != "" {
		return fmt.Errorf("profile ssh_public_key_file must be resolved by the unprivileged operator")
	}
	if !strings.EqualFold(profile.VMRoot, h.policy.VMRoot) {
		return fmt.Errorf("profile vm_root must be %s", h.policy.VMRoot)
	}
	if profile.VSwitch != "" {
		if err := h.validateSwitch(ctx, profile.VSwitch); err != nil {
			return err
		}
	}
	if linux {
		if !strings.EqualFold(profile.ImageCacheRoot, h.policy.ImageRoot) {
			return fmt.Errorf("profile image_cache_root must match the installed image root")
		}
	} else if err := h.policy.image(profile.BaseVHD); err != nil {
		return err
	}
	return nil
}
