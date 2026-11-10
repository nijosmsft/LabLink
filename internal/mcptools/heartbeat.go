package mcptools

import (
	"context"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// defaultHeartbeatInterval is the tick spacing for StartMCPHeartbeat.
// Package-level var so tests can shrink it via t.Cleanup without threading a
// clock interface through every handler.
var defaultHeartbeatInterval = 5 * time.Second

// heartbeatNotifierOverride, when non-nil, replaces the real MCP notification
// path for elapsed-time and byte-progress heartbeats. Tests use it to record
// calls without a live MCP server. The override is consulted only after a valid
// progressToken is found, preserving the no-token/no-notification invariant.
var heartbeatNotifierOverride progressNotifier
var heartbeatDetailNotifierOverride func(done, total int64, message string)

// progressNotifier sends numeric progress to the MCP client. The units are
// selected by the caller (for example elapsed seconds or transferred bytes).
type progressNotifier func(done, total int64)

type MCPProgressState struct {
	mu      sync.RWMutex
	started time.Time
	total   int64
	phase   string
	status  string
}

func NewMCPProgressState(total time.Duration, phase, status string) *MCPProgressState {
	totalSeconds := int64(total.Seconds())
	if totalSeconds < 1 {
		totalSeconds = 1
	}
	return &MCPProgressState{
		started: time.Now(),
		total:   totalSeconds,
		phase:   phase,
		status:  status,
	}
}

func (p *MCPProgressState) Update(phase, status string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.phase = phase
	p.status = status
	p.mu.Unlock()
}

func (p *MCPProgressState) snapshot() (int64, int64, string) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	done := int64(time.Since(p.started).Seconds())
	if done > p.total {
		done = p.total
	}
	return done, p.total, "phase=" + p.phase + "; status=" + p.status
}

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

func progressNotifierForRequest(ctx context.Context, req mcp.CallToolRequest) progressNotifier {
	token := ProgressTokenFromRequest(req)
	if token == nil {
		return nil
	}
	if heartbeatNotifierOverride != nil {
		return heartbeatNotifierOverride
	}
	return buildMCPNotifier(ctx, token)
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
	notifier := progressNotifierForRequest(ctx, req)
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

func StartMCPProgressHeartbeat(
	ctx context.Context,
	req mcp.CallToolRequest,
	interval time.Duration,
	state *MCPProgressState,
) func() {
	token := ProgressTokenFromRequest(req)
	if token == nil || state == nil {
		return func() {}
	}
	notifier := heartbeatDetailNotifierOverride
	if notifier == nil {
		srv := server.ServerFromContext(ctx)
		if srv == nil {
			return func() {}
		}
		notifier = func(done, total int64, message string) {
			_ = srv.SendNotificationToClient(ctx, "notifications/progress", map[string]any{
				"progressToken": token,
				"progress":      float64(done),
				"total":         float64(total),
				"message":       message,
			})
		}
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
				notifier(state.snapshot())
			}
		}
	}()
	return func() {
		cancel()
		<-doneCh
	}
}

// StartMCPProgress creates phase/status state and starts its heartbeat in one
// call. Composite operations should own one state for their entire lifetime
// and update it at phase boundaries rather than starting nested heartbeats.
func StartMCPProgress(
	ctx context.Context,
	req mcp.CallToolRequest,
	total time.Duration,
	phase string,
	status string,
) (*MCPProgressState, func()) {
	state := NewMCPProgressState(total, phase, status)
	stop := StartMCPProgressHeartbeat(ctx, req, defaultHeartbeatInterval, state)
	return state, stop
}
