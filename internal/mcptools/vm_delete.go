package mcptools

import (
	"context"
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
		name := req.GetString("name", "")
		dryRun := req.GetBool("dry_run", true)
		managedRoot := req.GetString("managed_root", "")
		if managedRoot == "" {
			if profile, _, err := defaults.ResolveForTarget("", target.Name); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			} else {
				managedRoot = profile.VMRoot
			}
		}
		params := hyperv.DeleteVMParams{
			Name: name, ManagedRoot: managedRoot, DryRun: dryRun,
			ForceStop:     req.GetBool("force_stop", false),
			DeleteStorage: req.GetBool("delete_storage", false),
		}
		script, err := hyperv.BuildDeleteVMScript(params)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		nodeName := strings.TrimSpace(req.GetString("lablink_node_name", ""))
		if nodeName == "" {
			nodeName = windowsHostname(name)
		}

		ctx, op := beginOp(ctx, "delete_vm", target.Name, fmt.Sprintf("delete VM %s", name), map[string]string{
			"target": target.Name, "name": name, "dry_run": fmt.Sprintf("%t", dryRun),
			"force_stop":     fmt.Sprintf("%t", params.ForceStop),
			"delete_storage": fmt.Sprintf("%t", params.DeleteStorage),
		})
		var opErr error
		defer func() { op.Done(opErr) }()

		if !dryRun {
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
