package mcptools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/vmconfig"
)

func registerVMTemplateTools(s *server.MCPServer, store *vmconfig.Store) {
	s.AddTool(
		mcp.NewTool("save_vm_template",
			mcp.WithDescription("Save or replace a non-secret Windows or Linux VM template and optionally make it the guest-OS-specific default for its target host."),
			mcp.WithString("name", mcp.Required(), mcp.Description("Template name")),
			mcp.WithString("target", mcp.Required(), mcp.Description("Registered Hyper-V host")),
			mcp.WithString("guest_os", mcp.Description("windows (default) or linux")),
			mcp.WithString("base_vhd", mcp.Description("Shared sysprepped Windows base VHDX")),
			mcp.WithString("vm_root", mcp.Description("Root folder for VM config and child VHDs")),
			mcp.WithString("vswitch", mcp.Description("Default Hyper-V vSwitch")),
			mcp.WithString("admin_password_credential", mcp.Description("Saved credential profile name; never the password")),
			mcp.WithNumber("memory_mb", mcp.Description("Startup memory MB")),
			mcp.WithNumber("cpu_count", mcp.Description("vCPU count")),
			mcp.WithBoolean("dynamic_memory", mcp.Description("Enable dynamic memory")),
			mcp.WithNumber("dynamic_min_mb", mcp.Description("Dynamic memory minimum MB")),
			mcp.WithNumber("dynamic_max_mb", mcp.Description("Dynamic memory maximum MB")),
			mcp.WithNumber("dynamic_buffer_pct", mcp.Description("Dynamic memory buffer percentage")),
			mcp.WithBoolean("secure_boot", mcp.Description("Enable MicrosoftWindows secure boot (default true)")),
			mcp.WithString("locale", mcp.Description("Guest locale")),
			mcp.WithString("timezone", mcp.Description("Guest Windows time zone")),
			mcp.WithBoolean("auto_logon", mcp.Description("Enable one-time AutoLogon")),
			mcp.WithBoolean("obfuscate_password", mcp.Description("Use answer-file password obfuscation")),
			mcp.WithBoolean("register_with_lablink", mcp.Description("Enroll created VMs as LabLink nodes")),
			mcp.WithString("lablink_role", mcp.Description("Role assigned to enrolled VM nodes")),
			mcp.WithNumber("lablink_port", mcp.Description("Guest LabLink agent port (default 9091)")),
			mcp.WithNumber("min_host_reserve_pct", mcp.Description("Minimum projected free host RAM and target-volume capacity percentage (default 10)")),
			mcp.WithBoolean("expose_virtualization_extensions", mcp.Description("Expose nested virtualization extensions to the Windows guest before first start")),
			mcp.WithBoolean("virtualization_based_security_opt_out", mcp.Description("Opt the Windows VM out of virtualization-based security before first start")),
			mcp.WithString("distribution", mcp.Description("Linux distribution (MVP: ubuntu)")),
			mcp.WithString("release", mcp.Description("Linux release (MVP: 24.04)")),
			mcp.WithString("architecture", mcp.Description("Linux architecture (MVP: amd64)")),
			mcp.WithString("image_cache_root", mcp.Description("Host root for cached Linux source and prepared images")),
			mcp.WithString("linux_username", mcp.Description("Default Linux username")),
			mcp.WithString("ssh_public_key", mcp.Description("Inline SSH public key")),
			mcp.WithString("ssh_public_key_file", mcp.Description("SSH public key file on the LabLink server")),
			mcp.WithString("linux_password_credential", mcp.Description("Saved Linux password credential profile name; never the password")),
			mcp.WithBoolean("allow_ssh_password_auth", mcp.Description("Enable Linux SSH password authentication")),
			mcp.WithString("network_config", mcp.Description("Optional NoCloud network-config YAML")),
			mcp.WithNumber("disk_size_gb", mcp.Description("Linux VM disk size in GB")),
			mcp.WithString("image_builder_profile", mcp.Description("Required Windows VM profile used to create/reuse the nested image-builder VM")),
			mcp.WithString("builder_vm_name", mcp.Description("Reusable image-builder VM name; defaults per target")),
			mcp.WithBoolean("delete_builder_after_prepare", mcp.Description("Delete the operation-owned builder VM after successful preparation (default false)")),
			mcp.WithBoolean("set_as_target_default", mcp.Description("Use this template by default when target matches (default true)")),
		),
		func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			secureBoot := req.GetBool("secure_boot", true)
			var registerLabLink *bool
			if value, ok := req.GetArguments()["register_with_lablink"].(bool); ok {
				registerLabLink = &value
			}
			var allowSSHPasswordAuth *bool
			if value, ok := req.GetArguments()["allow_ssh_password_auth"].(bool); ok {
				allowSSHPasswordAuth = &value
			}
			var exposeVirtualizationExtensions *bool
			if value, ok := req.GetArguments()["expose_virtualization_extensions"].(bool); ok {
				exposeVirtualizationExtensions = &value
			}
			var virtualizationBasedSecurityOptOut *bool
			if value, ok := req.GetArguments()["virtualization_based_security_opt_out"].(bool); ok {
				virtualizationBasedSecurityOptOut = &value
			}
			var deleteBuilderAfterPrepare *bool
			if value, ok := req.GetArguments()["delete_builder_after_prepare"].(bool); ok {
				deleteBuilderAfterPrepare = &value
			}
			profile := vmconfig.Profile{
				Target: req.GetString("target", ""), BaseVHD: req.GetString("base_vhd", ""),
				GuestOS: req.GetString("guest_os", ""),
				VMRoot:  req.GetString("vm_root", ""), VSwitch: req.GetString("vswitch", ""),
				AdminCredential: req.GetString("admin_password_credential", ""),
				MemoryMB:        req.GetFloat("memory_mb", 0), CPUCount: req.GetFloat("cpu_count", 0),
				DynamicMemory:    req.GetBool("dynamic_memory", false),
				DynamicMinMB:     req.GetFloat("dynamic_min_mb", 0),
				DynamicMaxMB:     req.GetFloat("dynamic_max_mb", 0),
				DynamicBufferPct: req.GetFloat("dynamic_buffer_pct", 0),
				SecureBoot:       &secureBoot, Locale: req.GetString("locale", ""),
				TimeZone: req.GetString("timezone", ""), AutoLogon: req.GetBool("auto_logon", false),
				ObfuscatePassword:                 req.GetBool("obfuscate_password", false),
				RegisterLabLink:                   registerLabLink,
				LabLinkRole:                       req.GetString("lablink_role", ""),
				LabLinkPort:                       int(req.GetFloat("lablink_port", 9091)),
				MinHostReservePct:                 req.GetFloat("min_host_reserve_pct", 10),
				ExposeVirtualizationExtensions:    exposeVirtualizationExtensions,
				VirtualizationBasedSecurityOptOut: virtualizationBasedSecurityOptOut,
				Distribution:                      req.GetString("distribution", ""),
				Release:                           req.GetString("release", ""),
				Architecture:                      req.GetString("architecture", ""),
				ImageCacheRoot:                    req.GetString("image_cache_root", ""),
				LinuxUsername:                     req.GetString("linux_username", ""),
				SSHPublicKey:                      req.GetString("ssh_public_key", ""),
				SSHPublicKeyFile:                  req.GetString("ssh_public_key_file", ""),
				LinuxPasswordCredential:           req.GetString("linux_password_credential", ""),
				AllowSSHPasswordAuth:              allowSSHPasswordAuth,
				NetworkConfig:                     req.GetString("network_config", ""),
				DiskSizeGB:                        req.GetFloat("disk_size_gb", 0),
				ImageBuilderProfile:               req.GetString("image_builder_profile", ""),
				BuilderVMName:                     req.GetString("builder_vm_name", ""),
				DeleteBuilderAfterPrepare:         deleteBuilderAfterPrepare,
			}
			name := req.GetString("name", "")
			if err := store.Set(name, profile, req.GetBool("set_as_target_default", true)); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return mcp.NewToolResultText(fmt.Sprintf("VM template `%s` saved for `%s`.", name, profile.Target)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("list_vm_templates",
			mcp.WithDescription("List saved VM templates and Windows/Linux per-target defaults."),
		),
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			config, err := store.List()
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			data, _ := json.MarshalIndent(config, "", "  ")
			return vmResult(fmt.Sprintf("**VM templates** (%d)", len(config.Profiles)), string(data)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("delete_vm_template",
			mcp.WithDescription("Delete a VM template and any Windows/Linux target-default references to it."),
			mcp.WithString("name", mcp.Required(), mcp.Description("Template name")),
		),
		func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			name := req.GetString("name", "")
			if err := store.Delete(name); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return mcp.NewToolResultText(fmt.Sprintf("VM template `%s` deleted.", name)), nil
		},
	)
}
