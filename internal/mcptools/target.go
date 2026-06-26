package mcptools

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/registry"
)

// Target is the execution endpoint for a tool that can run on either the
// lablink-server host (localhost) or a registered node. It is the unifying
// abstraction for the VM-management tools and is intentionally generic so
// future "runs here or on a node" tools can reuse it (Heimdall review §2).
type Target struct {
	Name    string         // "localhost" or a registry node name
	IsLocal bool           // true for the server host
	Node    *registry.Node // resolved node when remote; nil when local
}

// localAliases recognises the values that mean "the server host".
func isLocalAlias(v string) bool {
	v = strings.TrimSpace(v)
	return v == "" || strings.EqualFold(v, "localhost") || strings.EqualFold(v, "local")
}

// resolveTarget reads the "target" arg (default localhost) and resolves a
// remote node against the registry. Centralises the aliases and node
// validation so every VM tool behaves identically.
func resolveTarget(req mcp.CallToolRequest, reg *registry.Registry) (Target, error) {
	v := strings.TrimSpace(req.GetString("target", "localhost"))
	if isLocalAlias(v) {
		return Target{Name: "localhost", IsLocal: true}, nil
	}
	node, ok := reg.GetNode(v)
	if !ok {
		return Target{}, fmt.Errorf("target node %q not found in registry", v)
	}
	return Target{Name: v, IsLocal: false, Node: node}, nil
}

// extractTarget is the lease extractor for the "target" arg: no nodes for a
// local target (you own your own host — no lease), one node for a remote
// target (the caller must hold a lease on it). Lives beside the other lease
// extractors in leasecheck.go by convention.
func extractTarget(arg string) NodeExtractor {
	return func(req mcp.CallToolRequest, _ *registry.Registry) []string {
		v := strings.TrimSpace(req.GetString(arg, "localhost"))
		if isLocalAlias(v) {
			return nil
		}
		return []string{v}
	}
}

// targetMgmtIP returns the target-side IP that the server uses to reach a
// remote node (the host part of node.Address), used to identify the management
// NIC. Returns "" for a local target.
func targetMgmtIP(t Target) string {
	if t.IsLocal || t.Node == nil {
		return ""
	}
	return nodeHost(t.Node.Address)
}

// runPS executes a PowerShell script on the target, local or remote, using
// Windows PowerShell on both paths for Hyper-V parity. It returns the combined
// output and exit code, and a non-nil error when the script could not run OR
// exited nonzero (runPS treats a nonzero exit as a tool failure, per the
// network/Heimdall reviews). The tagged "LABLINK_ERROR:" line emitted by the
// hyperv builders is surfaced in the error.
func runPS(ctx context.Context, reg *registry.Registry, pool *agentclient.Pool, t Target, script string, timeoutSec int) (string, int, error) {
	var output string
	var exitCode int

	if t.IsLocal {
		out, code, _, err := executeLocalPowershell(ctx, script, timeoutSec)
		if err != nil {
			return out, code, fmt.Errorf("local powershell: %w", err)
		}
		output, exitCode = out, code
	} else {
		if t.Node == nil {
			return "", -1, fmt.Errorf("remote target %q has no resolved node", t.Name)
		}
		res := executeScriptOnNode(ctx, t.Node, script, "powershell", float64(timeoutSec), reg, pool)
		if res.Err != nil {
			return res.Output, res.ExitCode, fmt.Errorf("remote powershell on %s: %w", t.Name, res.Err)
		}
		output, exitCode = res.Output, res.ExitCode
	}

	if exitCode != 0 {
		return output, exitCode, fmt.Errorf("powershell exited %d: %s", exitCode, firstTaggedError(output))
	}
	return output, exitCode, nil
}

// firstTaggedError returns the first "LABLINK_ERROR:"/"<TAG>:" style line in
// the output, or a trimmed tail of the output if none is found.
func firstTaggedError(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "LABLINK_ERROR:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "LABLINK_ERROR:"))
		}
	}
	trimmed := strings.TrimSpace(output)
	if len(trimmed) > 400 {
		trimmed = trimmed[len(trimmed)-400:]
	}
	return trimmed
}

// pushToTarget stages a local file onto the target: a local filesystem copy for
// localhost, or pushFileToNode (the push_file machinery) for a remote node.
func pushToTarget(ctx context.Context, reg *registry.Registry, pool *agentclient.Pool, t Target, localPath, remotePath string) error {
	if t.IsLocal {
		return copyLocalFile(localPath, remotePath)
	}
	if t.Node == nil {
		return fmt.Errorf("remote target %q has no resolved node", t.Name)
	}
	client, err := pool.GetClient(t.Node.Address, t.Node.TLSServerName)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", t.Node.Address, err)
	}
	callCtx, cancel := nodeCallContext(ctx, t.Name)
	defer cancel()
	_, err = pushFileToNode(callCtx, client, localPath, remotePath)
	return err
}

func copyLocalFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
