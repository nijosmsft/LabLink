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
			mcp.WithDescription("Save or replace a non-secret Windows VM template and optionally make it the default for its target host."),
			mcp.WithString("name", mcp.Required(), mcp.Description("Template name")),
			mcp.WithString("target", mcp.Required(), mcp.Description("Registered Hyper-V host")),
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
			mcp.WithBoolean("set_as_target_default", mcp.Description("Use this template by default when target matches (default true)")),
		),
		func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			secureBoot := req.GetBool("secure_boot", true)
			profile := vmconfig.Profile{
				Target: req.GetString("target", ""), BaseVHD: req.GetString("base_vhd", ""),
				VMRoot: req.GetString("vm_root", ""), VSwitch: req.GetString("vswitch", ""),
				AdminCredential: req.GetString("admin_password_credential", ""),
				MemoryMB:        req.GetFloat("memory_mb", 0), CPUCount: req.GetFloat("cpu_count", 0),
				DynamicMemory:    req.GetBool("dynamic_memory", false),
				DynamicMinMB:     req.GetFloat("dynamic_min_mb", 0),
				DynamicMaxMB:     req.GetFloat("dynamic_max_mb", 0),
				DynamicBufferPct: req.GetFloat("dynamic_buffer_pct", 0),
				SecureBoot:       &secureBoot, Locale: req.GetString("locale", ""),
				TimeZone: req.GetString("timezone", ""), AutoLogon: req.GetBool("auto_logon", false),
				ObfuscatePassword: req.GetBool("obfuscate_password", false),
				RegisterLabLink:   req.GetBool("register_with_lablink", false),
				LabLinkRole:       req.GetString("lablink_role", ""),
				LabLinkPort:       int(req.GetFloat("lablink_port", 9091)),
				MinHostReservePct: req.GetFloat("min_host_reserve_pct", 10),
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
			mcp.WithDescription("List saved Windows VM templates and per-target defaults."),
		),
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			config, err := store.List()
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			data, _ := json.MarshalIndent(config, "", "  ")
			return vmResult(fmt.Sprintf("**Windows VM templates** (%d)", len(config.Profiles)), string(data)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("delete_vm_template",
			mcp.WithDescription("Delete a Windows VM template and any target-default references to it."),
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
