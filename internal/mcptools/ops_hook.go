package mcptools

import (
	"context"

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
