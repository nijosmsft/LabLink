package mcptools

import (
	"context"
	"errors"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/ops"
)

var globalOpsRegistry *ops.Registry

// SetOpsRegistry registers a process-wide operations registry. Tool handlers
// that opt in via beginOp will record themselves there for the local portal.
// Safe to leave nil; in that case beginOp is a no-op pass-through.
func SetOpsRegistry(r *ops.Registry) { globalOpsRegistry = r }

// beginOp records a new operation when an ops registry is configured. The
// returned ctx is the one the handler must pass to downstream RPCs so portal
// cancellation propagates. Done must be called with the terminal error
// (nil for success).
func beginOp(ctx context.Context, tool, node, summary string, args map[string]string) (context.Context, *ops.Handle) {
	return globalOpsRegistry.Begin(ctx, tool, node, summary, args)
}

// addTool registers a tool whose handler is automatically tracked in the
// operations registry, so every invocation shows up in the local portal even
// if the underlying handler doesn't call beginOp itself. The tool's "node"
// argument (when present) is used as the row's node label.
//
// Handlers that already call beginOp continue to work; they will produce a
// nested entry, which is fine — we keep this opt-in policy simple ("every
// tool is visible") rather than threading flags through every handler.
//
// To bypass the wrapper (e.g. for very chatty tools), call s.AddTool directly.
func addTool(s *server.MCPServer, tool mcp.Tool, handler server.ToolHandlerFunc) {
	s.AddTool(tool, wrapHandlerWithOps(tool.Name, handler))
}

func wrapHandlerWithOps(toolName string, handler server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		node := request.GetString("node", "")
		ctx, h := beginOp(ctx, toolName, node, "", nil)
		result, err := handler(ctx, request)
		var doneErr error
		switch {
		case err != nil:
			doneErr = err
		case result != nil && result.IsError:
			doneErr = errors.New(toolResultText(result))
		}
		h.Done(doneErr)
		return result, err
	}
}

// toolResultText extracts a short textual summary from a tool result for
// reporting via the ops registry. Best effort; returns "" if no text content.
func toolResultText(result *mcp.CallToolResult) string {
	if result == nil {
		return ""
	}
	for _, c := range result.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			return tc.Text
		}
	}
	return ""
}

