package mcptools

import (
	"context"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// defaultHeartbeatInterval is the tick spacing for StartMCPHeartbeat.
// Package-level var so tests can shrink it via t.Cleanup without threading a
// clock interface through every handler.
var defaultHeartbeatInterval = 5 * time.Second

// heartbeatNotifierOverride, when non-nil, is used by StartMCPHeartbeat
// instead of the real MCP notification path.  Set by tests to record calls
// without requiring a live MCP server in context.  The override is consulted
// only after a valid progressToken has been found in the request, so the
// "no token → no notification" invariant is preserved even when the override
// is set.
var heartbeatNotifierOverride progressNotifier

// ProgressTokenFromRequest extracts _meta.progressToken from an inbound
// CallToolRequest.  Returns nil if the client did not supply one.
func ProgressTokenFromRequest(req mcp.CallToolRequest) mcp.ProgressToken {
	if meta := req.Params.Meta; meta != nil {
		return meta.ProgressToken
	}
	return nil
}

// buildMCPNotifier returns a progressNotifier that sends a
// notifications/progress message to the current MCP client on every call.
// Returns nil if token is nil or if there is no MCPServer in ctx (e.g. in
// tests that do not run inside a real server).
func buildMCPNotifier(ctx context.Context, token mcp.ProgressToken) progressNotifier {
	if token == nil {
		return nil
	}
	srv := server.ServerFromContext(ctx)
	if srv == nil {
		return nil
	}
	return func(done, total int64) {
		params := map[string]any{
			"progressToken": token,
			"progress":      float64(done),
			"total":         float64(total),
		}
		_ = srv.SendNotificationToClient(ctx, "notifications/progress", params)
	}
}

// StartMCPHeartbeat starts a background goroutine that sends a
// notifications/progress message to the MCP client every interval.
// progress is called on each tick to retrieve the current (done, total) pair.
// Returns a cancel func that stops the goroutine and waits for it to exit.
// Safe to call when req carries no _meta.progressToken — the goroutine is not
// started and the returned cancel is a no-op.
func StartMCPHeartbeat(
	ctx context.Context,
	req mcp.CallToolRequest,
	interval time.Duration,
	progress func() (done, total int64),
) func() {
	token := ProgressTokenFromRequest(req)
	if token == nil {
		return func() {}
	}

	notifier := heartbeatNotifierOverride
	if notifier == nil {
		notifier = buildMCPNotifier(ctx, token)
	}
	if notifier == nil {
		return func() {}
	}

	hbCtx, cancel := context.WithCancel(ctx)
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-ticker.C:
				d, t := progress()
				notifier(d, t)
			}
		}
	}()
	return func() {
		cancel()
		<-doneCh
	}
}
