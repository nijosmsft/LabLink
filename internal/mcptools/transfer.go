package mcptools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/registry"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

const (
	transferChunkSize = 1024 * 1024 // 1MB

	// defaultTransferTimeoutSecs matches cmd/lablink-pulltest/main.go:47
	// (10-minute budget); chosen to give multi-GB transfers room while
	// still bounding hung calls. Callers may override per-invocation via
	// the timeout_seconds MCP arg; 0 disables the deadline entirely.
	defaultTransferTimeoutSecs = 600
)

const timeoutArgDescription = "Transfer timeout seconds; 0 = none, default 600."

func RegisterTransfer(s *server.MCPServer, reg *registry.Registry, pool *agentclient.Pool, leaseCfg LeaseGateConfig) {
	s.AddTool(
		mcp.NewTool("push_file",
			mcp.WithDescription("Upload a local file to a remote node."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("local_path", mcp.Required(), mcp.Description("Local file path")),
			mcp.WithString("remote_path", mcp.Required(), mcp.Description("Destination path on the node")),
			mcp.WithNumber("timeout_seconds", mcp.Description(timeoutArgDescription)),
		),
		LeaseGate(leaseCfg, extractSingleNode("node"), pushFileHandler(reg, pool)),
	)

	s.AddTool(
		mcp.NewTool("pull_file",
			mcp.WithDescription("Download a file from a remote node to local disk."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
			mcp.WithString("remote_path", mcp.Required(), mcp.Description("File path on the node")),
			mcp.WithString("local_path", mcp.Required(), mcp.Description("Local destination path")),
			mcp.WithNumber("timeout_seconds", mcp.Description(timeoutArgDescription)),
		),
		LeaseGate(leaseCfg, extractSingleNode("node"), pullFileHandler(reg, pool)),
	)
}

// applyTransferTimeout wraps ctx in a context.WithTimeout when timeoutSec > 0.
// Returns (ctx, cancel) where cancel is always safe to defer (no-op when no
// deadline was applied). timeoutSec == 0 disables the deadline so very large
// transfers can proceed unbounded. Negative values are treated as no-op here;
// the MCP handlers reject them before calling this function.
func applyTransferTimeout(ctx context.Context, timeoutSec int) (context.Context, context.CancelFunc) {
	if timeoutSec <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
}

func pushFileHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		localPath := request.GetString("local_path", "")
		remotePath := request.GetString("remote_path", "")
		timeoutSec := request.GetInt("timeout_seconds", defaultTransferTimeoutSecs)

		if timeoutSec < 0 {
			return mcp.NewToolResultError("timeout_seconds must be >= 0 (0 disables the deadline)"), nil
		}

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		ctx, op := beginOp(ctx, "push_file", nodeName,
			fmt.Sprintf("%s → %s", localPath, remotePath),
			map[string]string{"local_path": localPath, "remote_path": remotePath})
		var opErr error
		defer func() { op.Done(opErr) }()

		ctx, cancelTimeout := applyTransferTimeout(ctx, timeoutSec)
		defer cancelTimeout()

		f, err := os.Open(localPath)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("open %s: %v", localPath, err)), nil
		}
		defer f.Close()

		info, err := f.Stat()
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("stat %s: %v", localPath, err)), nil
		}

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("connect to %s: %v", node.Address, err)), nil
		}

		stream, err := client.PushFile(ctx)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("push_file: %v", err)), nil
		}

		notifier := buildMCPNotifier(ctx, ProgressTokenFromRequest(request))
		resp, err := sendLocalFileWithProgress(ctx, stream, f, info.Size(), remotePath, op, notifier)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("upload: %v", err)), nil
		}

		result := fmt.Sprintf("Pushed **%s** → **%s:%s** (%s)",
			filepath.Base(localPath), nodeName, resp.RemotePath, formatBytes(resp.BytesWritten))
		return mcp.NewToolResultText(result), nil
	}
}

func pullFileHandler(reg *registry.Registry, pool *agentclient.Pool) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodeName := request.GetString("node", "")
		remotePath := request.GetString("remote_path", "")
		localPath := request.GetString("local_path", "")
		timeoutSec := request.GetInt("timeout_seconds", defaultTransferTimeoutSecs)

		if timeoutSec < 0 {
			return mcp.NewToolResultError("timeout_seconds must be >= 0 (0 disables the deadline)"), nil
		}

		node, ok := reg.GetNode(nodeName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("node %q not found", nodeName)), nil
		}

		ctx, op := beginOp(ctx, "pull_file", nodeName,
			fmt.Sprintf("%s → %s", remotePath, localPath),
			map[string]string{"remote_path": remotePath, "local_path": localPath})
		var opErr error
		defer func() { op.Done(opErr) }()

		ctx, cancelTimeout := applyTransferTimeout(ctx, timeoutSec)
		defer cancelTimeout()

		client, err := pool.GetClient(node.Address, node.TLSServerName)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("connect to %s: %v", node.Address, err)), nil
		}

		stream, err := client.PullFile(ctx, &pb.PullFileRequest{RemotePath: remotePath})
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(fmt.Sprintf("pull_file: %v", err)), nil
		}

		notifier := buildMCPNotifier(ctx, ProgressTokenFromRequest(request))
		written, err := pullRemoteFileToPathWithProgress(ctx, stream, localPath, op, notifier)
		if err != nil {
			opErr = err
			return mcp.NewToolResultError(err.Error()), nil
		}

		result := fmt.Sprintf("Pulled **%s:%s** → **%s** (%s)",
			nodeName, remotePath, localPath, formatBytes(written))
		return mcp.NewToolResultText(result), nil
	}
}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

