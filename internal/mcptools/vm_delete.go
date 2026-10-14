package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/vmconfig"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

func deleteVMHandler(
	reg *registry.Registry,
	pool *agentclient.Pool,
	defaults *vmconfig.Store,
	auditLog *audit.Log,
	enrollment VMEnrollmentConfig,
) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		target, err := resolveTarget(req, reg)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		name := strings.TrimSpace(req.GetString("name", ""))
		if name == "" {
			return mcp.NewToolResultError("VM name is required"), nil
		}
		dryRun := req.GetBool("dry_run", true)

		ctx, op := beginOp(ctx, "delete_vm", target.Name, fmt.Sprintf("delete VM %s", name), map[string]string{
			"target": target.Name, "name": name, "dry_run": fmt.Sprintf("%t", dryRun),
			"force_stop":     fmt.Sprintf("%t", req.GetBool("force_stop", false)),
			"delete_storage": fmt.Sprintf("%t", req.GetBool("delete_storage", false)),
		})
		var opErr error
		defer func() { op.Done(opErr) }()

		lifecycleLock, err := acquireVMLifecycleLock(ctx, name, target, reg, pool)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(err.Error()), nil
		}
		defer lifecycleLock.release(reg, pool, target)

		metadata, err := inspectVMManagement(ctx, name, target, reg, pool)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(err.Error()), nil
		}
		identity, err := resolveVMDeleteIdentity(req, target, defaults, metadata)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(err.Error()), nil
		}
		params := hyperv.DeleteVMParams{
			Name: name, ManagedRoot: identity.ManagedRoot, DryRun: dryRun,
			ForceStop:          req.GetBool("force_stop", false),
			DeleteStorage:      req.GetBool("delete_storage", false),
			ExpectedParentVHDX: identity.ExpectedParentVHDX,
		}
		script, err := hyperv.BuildDeleteVMScript(params)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(err.Error()), nil
		}
		nodeName := caseCorrectRegistryNodeName(reg, identity.NodeName)

		if !dryRun && identity.GuestOS == vmconfig.GuestOSWindows {
			releaseGuestDHCP(ctx, nodeName, reg, pool)
		}
		start := time.Now()
		out, exit, runErr := runPS(ctx, reg, pool, target, script, vmDefaultTimeoutSec)
		auditLog.Append(audit.Entry{
			Timestamp: start, Node: target.Name, Tool: "delete_vm",
			Command: fmt.Sprintf("delete_vm name=%s dry_run=%t delete_storage=%t", name, dryRun, params.DeleteStorage),
			Shell:   "powershell", ExitCode: exit, DurationMs: time.Since(start).Milliseconds(),
		})
		if runErr != nil {
			opErr = runErr
			return mcp.NewToolResultError(runErr.Error()), nil
		}
		if dryRun {
			return vmResult(fmt.Sprintf("**VM `%s` deletion dry run on `%s`**", name, target.Name), jsonExtract(out)), nil
		}

		if req.GetBool("unregister_node", true) {
			if err := reg.RemoveNode(nodeName); err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("VM deleted but unregister node %q failed: %v", nodeName, err)), nil
			}
		}
		if req.GetBool("delete_identity", false) {
			if err := deleteIssuedIdentity(enrollment.PKIDir, nodeName); err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("VM deleted but identity cleanup failed: %v", err)), nil
			}
		}
		return vmResult(fmt.Sprintf("**VM `%s` deleted from `%s`**", name, target.Name), jsonExtract(out)), nil
	}
}

type vmDeleteIdentity struct {
	GuestOS            string
	NodeName           string
	ManagedRoot        string
	ExpectedParentVHDX string
}

func inspectVMManagement(ctx context.Context, name string, target Target, reg *registry.Registry, pool *agentclient.Pool) (*hyperv.LinuxVMMetadata, error) {
	script, err := hyperv.BuildInspectVMManagementScript(name)
	if err != nil {
		return nil, err
	}
	out, _, err := runPS(ctx, reg, pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return nil, fmt.Errorf("inspect VM management metadata: %w", err)
	}
	var result struct {
		Exists   bool                    `json:"exists"`
		Metadata *hyperv.LinuxVMMetadata `json:"metadata"`
	}
	if err := json.Unmarshal([]byte(jsonExtract(out)), &result); err != nil {
		return nil, fmt.Errorf("parse VM management metadata: %w", err)
	}
	return result.Metadata, nil
}

func resolveVMDeleteIdentity(req mcp.CallToolRequest, target Target, defaults *vmconfig.Store, metadata *hyperv.LinuxVMMetadata) (vmDeleteIdentity, error) {
	explicitRoot := strings.TrimSpace(req.GetString("managed_root", ""))
	explicitNode := strings.TrimSpace(req.GetString("lablink_node_name", ""))
	name := strings.TrimSpace(req.GetString("name", ""))
	if metadata != nil {
		if (metadata.SchemaVersion != 1 && metadata.SchemaVersion != hyperv.LinuxVMMetadataSchema) ||
			metadata.GuestOS != vmconfig.GuestOSLinux ||
			!strings.EqualFold(metadata.VMName, name) {
			return vmDeleteIdentity{}, fmt.Errorf("managed VM metadata is invalid or belongs to a different VM")
		}
		if explicitRoot != "" && !sameWindowsPath(explicitRoot, metadata.ManagedRoot) {
			return vmDeleteIdentity{}, fmt.Errorf("managed_root conflicts with persisted Linux VM metadata")
		}
		if explicitNode != "" && !strings.EqualFold(explicitNode, metadata.NodeName) {
			return vmDeleteIdentity{}, fmt.Errorf("lablink_node_name conflicts with persisted Linux VM metadata")
		}
		return vmDeleteIdentity{
			GuestOS: vmconfig.GuestOSLinux, NodeName: metadata.NodeName,
			ManagedRoot: metadata.ManagedRoot, ExpectedParentVHDX: metadata.ParentVHDX,
		}, nil
	}

	managedRoot := explicitRoot
	if managedRoot == "" {
		profile, _, err := defaults.ResolveWindowsForTarget("", target.Name)
		if err != nil {
			return vmDeleteIdentity{}, err
		}
		managedRoot = profile.VMRoot
	}
	nodeName := explicitNode
	if nodeName == "" {
		nodeName = windowsHostname(name)
	}
	return vmDeleteIdentity{GuestOS: vmconfig.GuestOSWindows, NodeName: nodeName, ManagedRoot: managedRoot}, nil
}

func caseCorrectRegistryNodeName(reg *registry.Registry, requested string) string {
	for _, node := range reg.AllNodes() {
		if strings.EqualFold(node.Name, requested) {
			return node.Name
		}
	}
	return requested
}

// releaseGuestDHCP is intentionally best effort. A successful release usually
// tears down the same connection carrying the response, so transport errors
// are expected and ignored.
func releaseGuestDHCP(ctx context.Context, nodeName string, reg *registry.Registry, pool *agentclient.Pool) {
	node, ok := reg.GetNode(nodeName)
	if !ok {
		return
	}
	client, err := pool.GetClient(node.Address, node.TLSServerName)
	if err != nil {
		return
	}
	releaseCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stream, err := client.Execute(releaseCtx, &pb.ExecuteRequest{
		Command: "ipconfig /release", Shell: "cmd", TimeoutSeconds: 20,
	})
	if err != nil {
		return
	}
	_, _, _, _, _ = collectStreamOutput(stream)
}

func deleteIssuedIdentity(pkiDir, nodeName string) error {
	if err := validateVMPathName(nodeName); err != nil {
		return err
	}
	base := filepath.Clean(filepath.Join(pkiDir, "issued", "servers"))
	target := filepath.Clean(filepath.Join(base, nodeName))
	if !strings.HasPrefix(strings.ToLower(target), strings.ToLower(base)+string(os.PathSeparator)) {
		return fmt.Errorf("identity path escapes issued-server directory")
	}
	if err := os.RemoveAll(target); err != nil {
		return err
	}
	return nil
}
