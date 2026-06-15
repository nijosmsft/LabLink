package mcptools

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/leasing"
	"github.com/nijosmsft/lablink/internal/registry"
)

// leaseWaitPollMax bounds the per-iteration sleep used by the lease and
// wait_for_release retry loops. The actual sleep is min(this, wait/10).
var leaseWaitPollMax = 2 * time.Second

// leaseWaitPollMin is the floor for the retry sleep so we don't busy-spin
// when the caller passes a very small wait_seconds value.
var leaseWaitPollMin = 200 * time.Millisecond

// RegisterLeasing registers the 8 lease tools described in v0.4.0 M2 of
// the leasing design memo. Tools wrap the in-process leasing.Store (M1).
//
// The reg argument is used only by the topology / role convenience tools
// and the optional node-name validation in lease(). Store is owned by the
// caller (cmd/lablink-server/main.go).
func RegisterLeasing(s *server.MCPServer, reg *registry.Registry, store leasing.Store) {
	addTool(s,
		mcp.NewTool("lease",
			mcp.WithDescription("Acquire an exclusive all-or-nothing lease on nodes."),
			mcp.WithArray("nodes", mcp.Required(), mcp.Description("Node names to lease (all-or-nothing)."), mcp.WithStringItems()),
			mcp.WithNumber("duration_minutes", mcp.Description("Lease TTL in minutes, default 60.")),
			mcp.WithNumber("wait_seconds", mcp.Description("Block seconds; 0 = fail fast.")),
			mcp.WithString("reason", mcp.Description("Audit reason.")),
			mcp.WithString("agent_id", mcp.Description("Agent id override; blank = default.")),
		),
		leaseHandler(reg, store),
	)

	addTool(s,
		mcp.NewTool("release",
			mcp.WithDescription("Release a lease; pass lease_id or nodes."),
			mcp.WithString("lease_id", mcp.Description("Lease to release; or use nodes.")),
			mcp.WithArray("nodes", mcp.Description("Release leases on these nodes."), mcp.WithStringItems()),
			mcp.WithString("agent_id", mcp.Description("Agent id override; blank = default.")),
		),
		releaseHandler(store),
	)

	addTool(s,
		mcp.NewTool("extend_lease",
			mcp.WithDescription("Extend the TTL of an active lease this agent owns."),
			mcp.WithString("lease_id", mcp.Required(), mcp.Description("Lease to extend.")),
			mcp.WithNumber("additional_minutes", mcp.Required(), mcp.Description("Minutes to add to current expiry.")),
			mcp.WithString("agent_id", mcp.Description("Agent id override; blank = default.")),
		),
		extendLeaseHandler(store),
	)

	addTool(s,
		mcp.NewTool("list_leases",
			mcp.WithDescription("List held leases, optionally filtered by agent or node."),
			mcp.WithString("agent_id", mcp.Description("Agent id filter.")),
			mcp.WithString("node", mcp.Description("Node name filter.")),
			mcp.WithBoolean("include_expired", mcp.Description("Include expired rows; default false.")),
			mcp.WithNumber("limit", mcp.Description("Max rows, default 50.")),
		),
		listLeasesHandler(store),
	)

	addTool(s,
		mcp.NewTool("force_release",
			mcp.WithDescription("Force-break another agent's lease; reason required."),
			mcp.WithDestructiveHintAnnotation(true),
			mcp.WithString("lease_id", mcp.Description("Lease to force-release; or use nodes.")),
			mcp.WithArray("nodes", mcp.Description("Force-release leases on these nodes."), mcp.WithStringItems()),
			mcp.WithString("reason", mcp.Required(), mcp.Description("Audit reason.")),
		),
		forceReleaseHandler(store),
	)

	addTool(s,
		mcp.NewTool("wait_for_release",
			mcp.WithDescription("Block until all given nodes have no active lease; does not acquire."),
			mcp.WithArray("nodes", mcp.Required(), mcp.Description("Node names to watch."), mcp.WithStringItems()),
			mcp.WithNumber("timeout_seconds", mcp.Description("Max seconds to wait, default 300.")),
		),
		waitForReleaseHandler(store),
	)

	addTool(s,
		mcp.NewTool("lease_topology",
			mcp.WithDescription("Atomically lease every node in a registered topology."),
			mcp.WithString("topology", mcp.Required(), mcp.Description("Topology name from registry.")),
			mcp.WithNumber("duration_minutes", mcp.Description("Lease TTL in minutes, default 60.")),
			mcp.WithNumber("wait_seconds", mcp.Description("Block seconds; 0 = fail fast.")),
			mcp.WithString("reason", mcp.Description("Audit reason.")),
			mcp.WithString("agent_id", mcp.Description("Agent id override; blank = default.")),
		),
		leaseTopologyHandler(reg, store),
	)

	addTool(s,
		mcp.NewTool("lease_role",
			mcp.WithDescription("Atomically lease every node with a given role, optionally scoped to a topology."),
			mcp.WithString("role", mcp.Required(), mcp.Description("Role name.")),
			mcp.WithString("topology", mcp.Description("Topology; blank = all.")),
			mcp.WithNumber("duration_minutes", mcp.Description("Lease TTL in minutes, default 60.")),
			mcp.WithNumber("wait_seconds", mcp.Description("Block seconds; 0 = fail fast.")),
			mcp.WithString("reason", mcp.Description("Audit reason.")),
			mcp.WithString("agent_id", mcp.Description("Agent id override; blank = default.")),
		),
		leaseRoleHandler(reg, store),
	)
}

// -------------------- handlers --------------------

func leaseHandler(reg *registry.Registry, store leasing.Store) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodes := normalizeNodeList(request.GetStringSlice("nodes", nil))
		if len(nodes) == 0 {
			return mcp.NewToolResultError("nodes list is empty — supply at least one node (whole-lab leases are NOT supported in v1)"), nil
		}

		if missing := unknownNodes(reg, nodes); len(missing) > 0 {
			return mcp.NewToolResultError(fmt.Sprintf(
				"unknown node(s) in registry: %s — atomic validation refused before any lease was taken",
				strings.Join(missing, ", "),
			)), nil
		}

		req := buildAcquireRequest(nodes, request)
		return acquireAndRender(ctx, store, req)
	}
}

func releaseHandler(store leasing.Store) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		leaseID := strings.TrimSpace(request.GetString("lease_id", ""))
		nodes := normalizeNodeList(request.GetStringSlice("nodes", nil))
		agentID := strings.TrimSpace(request.GetString("agent_id", ""))
		if agentID == "" {
			agentID = leasing.Default().EffectiveID
		}

		if leaseID == "" && len(nodes) == 0 {
			return mcp.NewToolResultError("release: must specify either lease_id or nodes"), nil
		}
		if leaseID != "" && len(nodes) > 0 {
			return mcp.NewToolResultError("release: lease_id and nodes are mutually exclusive"), nil
		}

		if leaseID != "" {
			if err := store.Release(ctx, leaseID, agentID); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("release %s: %v", leaseID, err)), nil
			}
			return mcp.NewToolResultText(renderReleased([]string{leaseID})), nil
		}

		// nodes path: find this agent's leases that overlap.
		leases, err := store.List(ctx, leasing.ListFilter{AgentID: agentID})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("list leases: %v", err)), nil
		}
		targets := pickLeasesTouchingNodes(leases, nodes)
		if len(targets) == 0 {
			return mcp.NewToolResultError(fmt.Sprintf(
				"no active leases owned by %s cover any of: %s",
				agentID, strings.Join(nodes, ", "),
			)), nil
		}

		released := make([]string, 0, len(targets))
		var firstErr error
		for _, l := range targets {
			if err := store.Release(ctx, l.ID, agentID); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("release %s: %w", l.ID, err)
				}
				continue
			}
			released = append(released, l.ID)
		}
		if firstErr != nil && len(released) == 0 {
			return mcp.NewToolResultError(firstErr.Error()), nil
		}
		body := renderReleased(released)
		if firstErr != nil {
			body += fmt.Sprintf("\n\n_partial failure_: %v", firstErr)
		}
		return mcp.NewToolResultText(body), nil
	}
}

func extendLeaseHandler(store leasing.Store) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		leaseID := strings.TrimSpace(request.GetString("lease_id", ""))
		addMin := request.GetInt("additional_minutes", 0)
		agentID := strings.TrimSpace(request.GetString("agent_id", ""))
		if agentID == "" {
			agentID = leasing.Default().EffectiveID
		}
		if leaseID == "" {
			return mcp.NewToolResultError("extend_lease: lease_id is required"), nil
		}
		if addMin <= 0 {
			return mcp.NewToolResultError("extend_lease: additional_minutes must be > 0"), nil
		}
		add := time.Duration(addMin) * time.Minute
		lease, err := store.Extend(ctx, leaseID, agentID, add)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("extend %s: %v", leaseID, err)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf(
			"## Extended lease `%s`\n\n- agent: `%s`\n- nodes: %s\n- new expires_at: %s (added %d min)\n",
			lease.ID, lease.AgentID, joinNodes(lease.Nodes),
			lease.ExpiresAt.UTC().Format(time.RFC3339), addMin,
		)), nil
	}
}

func listLeasesHandler(store leasing.Store) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		filter := leasing.ListFilter{
			AgentID:        strings.TrimSpace(request.GetString("agent_id", "")),
			IncludeExpired: request.GetBool("include_expired", false),
			Limit:          request.GetInt("limit", 50),
		}
		nodeFilter := strings.TrimSpace(request.GetString("node", ""))
		leases, err := store.List(ctx, filter)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("list leases: %v", err)), nil
		}
		if nodeFilter != "" {
			leases = pickLeasesTouchingNodes(leases, []string{nodeFilter})
		}
		return mcp.NewToolResultText(renderLeaseTable(leases, filter.IncludeExpired)), nil
	}
}

func forceReleaseHandler(store leasing.Store) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		leaseID := strings.TrimSpace(request.GetString("lease_id", ""))
		nodes := normalizeNodeList(request.GetStringSlice("nodes", nil))
		reason := strings.TrimSpace(request.GetString("reason", ""))
		if reason == "" {
			return mcp.NewToolResultError("force_release: reason is required (recorded in audit)"), nil
		}
		if leaseID == "" && len(nodes) == 0 {
			return mcp.NewToolResultError("force_release: must specify either lease_id or nodes"), nil
		}
		if leaseID != "" && len(nodes) > 0 {
			return mcp.NewToolResultError("force_release: lease_id and nodes are mutually exclusive"), nil
		}

		forcedBy := leasing.Default().EffectiveID

		if leaseID != "" {
			if err := store.ForceRelease(ctx, leaseID, forcedBy, reason); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("force_release %s: %v", leaseID, err)), nil
			}
			return mcp.NewToolResultText(renderForceReleased([]string{leaseID}, forcedBy, reason)), nil
		}

		// nodes path: find every active lease touching any node, force-release each.
		leases, err := store.List(ctx, leasing.ListFilter{})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("list leases: %v", err)), nil
		}
		targets := pickLeasesTouchingNodes(leases, nodes)
		if len(targets) == 0 {
			return mcp.NewToolResultError(fmt.Sprintf(
				"no active leases touch any of: %s",
				strings.Join(nodes, ", "),
			)), nil
		}
		released := make([]string, 0, len(targets))
		var firstErr error
		for _, l := range targets {
			if err := store.ForceRelease(ctx, l.ID, forcedBy, reason); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("force_release %s: %w", l.ID, err)
				}
				continue
			}
			released = append(released, l.ID)
		}
		if firstErr != nil && len(released) == 0 {
			return mcp.NewToolResultError(firstErr.Error()), nil
		}
		body := renderForceReleased(released, forcedBy, reason)
		if firstErr != nil {
			body += fmt.Sprintf("\n\n_partial failure_: %v", firstErr)
		}
		return mcp.NewToolResultText(body), nil
	}
}

func waitForReleaseHandler(store leasing.Store) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodes := normalizeNodeList(request.GetStringSlice("nodes", nil))
		if len(nodes) == 0 {
			return mcp.NewToolResultError("wait_for_release: nodes list is empty"), nil
		}
		timeoutSec := request.GetInt("timeout_seconds", 300)
		if timeoutSec <= 0 {
			timeoutSec = 300
		}
		deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
		sleep := pollInterval(time.Duration(timeoutSec) * time.Second)

		var freedAtomic atomic.Int64
		stop := StartMCPHeartbeat(ctx, request, defaultHeartbeatInterval, func() (int64, int64) {
			return freedAtomic.Load(), int64(len(nodes))
		})
		defer stop()

		var lastHolders []*leasing.Lease
		for {
			leases, err := store.List(ctx, leasing.ListFilter{})
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("list leases: %v", err)), nil
			}
			holders := pickLeasesTouchingNodes(leases, nodes)

			// Update freed count for heartbeat.
			held := make(map[string]struct{}, len(holders)*2)
			for _, l := range holders {
				for _, n := range l.Nodes {
					held[n] = struct{}{}
				}
			}
			freed := int64(0)
			for _, n := range nodes {
				if _, isHeld := held[n]; !isHeld {
					freed++
				}
			}
			freedAtomic.Store(freed)

			if len(holders) == 0 {
				return mcp.NewToolResultText(fmt.Sprintf(
					"## Nodes free\n\nAll requested nodes are unleased as of %s.\n\n- nodes: %s\n\nNext step: call `lease(nodes=[%s], duration_minutes=...)` to claim them.\n",
					time.Now().UTC().Format(time.RFC3339), joinNodes(nodes), joinNodesQuoted(nodes),
				)), nil
			}
			lastHolders = holders
			if !time.Now().Before(deadline) {
				return mcp.NewToolResultText(renderWaitTimeout(nodes, lastHolders, timeoutSec)), nil
			}
			select {
			case <-ctx.Done():
				return mcp.NewToolResultError(fmt.Sprintf("wait_for_release: %v", ctx.Err())), nil
			case <-time.After(sleep):
			}
		}
	}
}

func leaseTopologyHandler(reg *registry.Registry, store leasing.Store) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		topName := strings.TrimSpace(request.GetString("topology", ""))
		if topName == "" {
			return mcp.NewToolResultError("lease_topology: topology is required"), nil
		}
		top, ok := reg.GetTopology(topName)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("topology %q not found", topName)), nil
		}
		nodes := flattenTopologyNodes(top)
		if len(nodes) == 0 {
			return mcp.NewToolResultError(fmt.Sprintf("topology %q has no nodes assigned to any role", topName)), nil
		}
		req := buildAcquireRequest(nodes, request)
		return acquireAndRender(ctx, store, req)
	}
}

func leaseRoleHandler(reg *registry.Registry, store leasing.Store) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		role := strings.TrimSpace(request.GetString("role", ""))
		if role == "" {
			return mcp.NewToolResultError("lease_role: role is required"), nil
		}
		topName := strings.TrimSpace(request.GetString("topology", ""))

		var resolved []*registry.Node
		if topName != "" {
			if _, ok := reg.GetTopology(topName); !ok {
				return mcp.NewToolResultError(fmt.Sprintf("topology %q not found", topName)), nil
			}
			resolved = reg.NodesForTopologyRole(topName, role)
		} else {
			resolved = reg.NodesByRole(role)
		}
		if len(resolved) == 0 {
			scope := "registry"
			if topName != "" {
				scope = fmt.Sprintf("topology %q", topName)
			}
			return mcp.NewToolResultError(fmt.Sprintf("no nodes with role %q in %s", role, scope)), nil
		}
		nodes := make([]string, 0, len(resolved))
		for _, n := range resolved {
			nodes = append(nodes, n.Name)
		}
		nodes = normalizeNodeList(nodes)
		req := buildAcquireRequest(nodes, request)
		return acquireAndRender(ctx, store, req)
	}
}

// -------------------- helpers --------------------

func buildAcquireRequest(nodes []string, request mcp.CallToolRequest) leasing.AcquireRequest {
	durMin := request.GetInt("duration_minutes", 0)
	if durMin <= 0 {
		durMin = int(leasing.DefaultDuration / time.Minute)
	}
	waitSec := request.GetInt("wait_seconds", 0)
	reason := strings.TrimSpace(request.GetString("reason", ""))
	agentID := strings.TrimSpace(request.GetString("agent_id", ""))

	return leasing.AcquireRequest{
		Nodes:    nodes,
		Duration: time.Duration(durMin) * time.Minute,
		Wait:     time.Duration(waitSec) * time.Second,
		AgentID:  agentID,
		Reason:   reason,
		Identity: leasing.Default(),
	}
}

// acquireAndRender calls Acquire with a handler-owned retry loop that
// preserves the most recent ConflictError on wait timeout (the store's
// internal wait loop returns ErrWaitTimeout instead, losing the holder
// detail we want to show the user). When req.Wait==0 the store is called
// once with Wait=0 and any conflict is rendered immediately.
func acquireAndRender(ctx context.Context, store leasing.Store, req leasing.AcquireRequest) (*mcp.CallToolResult, error) {
	waitTotal := req.Wait
	req.Wait = 0 // handler owns the wait loop so we can keep the last ConflictError

	if waitTotal <= 0 {
		lease, err := store.Acquire(ctx, req)
		return renderAcquireResult(lease, err, req, 0)
	}

	deadline := time.Now().Add(waitTotal)
	sleep := pollInterval(waitTotal)
	var lastConflict *leasing.ConflictError
	startedAt := time.Now()
	for {
		lease, err := store.Acquire(ctx, req)
		if err == nil {
			return renderAcquireResult(lease, nil, req, time.Since(startedAt))
		}
		var ce *leasing.ConflictError
		if !errors.As(err, &ce) {
			// Non-conflict error: surface immediately.
			return renderAcquireResult(nil, err, req, time.Since(startedAt))
		}
		lastConflict = ce
		if !time.Now().Before(deadline) {
			return renderAcquireResult(nil, lastConflict, req, time.Since(startedAt))
		}
		// Trim sleep to the remaining window so we don't overshoot deadline.
		remaining := time.Until(deadline)
		s := sleep
		if remaining < s {
			s = remaining
		}
		select {
		case <-ctx.Done():
			return mcp.NewToolResultError(fmt.Sprintf("lease: %v", ctx.Err())), nil
		case <-time.After(s):
		}
	}
}

func renderAcquireResult(lease *leasing.Lease, err error, req leasing.AcquireRequest, waited time.Duration) (*mcp.CallToolResult, error) {
	if err == nil && lease != nil {
		var sb strings.Builder
		fmt.Fprintf(&sb, "## Lease acquired `%s`\n\n", lease.ID)
		if waited >= time.Second {
			fmt.Fprintf(&sb, "_waited %s for nodes to free up_\n\n", waited.Round(time.Second))
		}
		fmt.Fprintf(&sb, "- agent: `%s`\n", lease.AgentID)
		fmt.Fprintf(&sb, "- nodes: %s\n", joinNodes(lease.Nodes))
		fmt.Fprintf(&sb, "- acquired_at: %s\n", lease.AcquiredAt.UTC().Format(time.RFC3339))
		fmt.Fprintf(&sb, "- expires_at: %s\n", lease.ExpiresAt.UTC().Format(time.RFC3339))
		if lease.Reason != "" {
			fmt.Fprintf(&sb, "- reason: %q\n", lease.Reason)
		}
		fmt.Fprintf(&sb, "\nNext step: when finished, call `release(lease_id=%q)`. To bump the TTL call `extend_lease(lease_id=%q, additional_minutes=...)`.\n",
			lease.ID, lease.ID)
		return mcp.NewToolResultText(sb.String()), nil
	}

	var ce *leasing.ConflictError
	if errors.As(err, &ce) {
		return mcp.NewToolResultError(renderConflict(req, ce, waited, leasing.Default())), nil
	}
	return mcp.NewToolResultError(fmt.Sprintf("lease failed: %v", err)), nil
}

func renderConflict(req leasing.AcquireRequest, ce *leasing.ConflictError, waited time.Duration, self leasing.Identity) string {
	var sb strings.Builder
	if waited >= time.Second {
		fmt.Fprintf(&sb, "ConflictError after waiting %s — nodes still held:\n\n", waited.Round(time.Second))
	} else {
		sb.WriteString("ConflictError — atomic acquire refused:\n\n")
	}
	now := time.Now().UTC()
	sortedNodes := append([]string(nil), req.Nodes...)
	sort.Strings(sortedNodes)
	for _, n := range sortedNodes {
		h := ce.Holders[n]
		if h == nil {
			fmt.Fprintf(&sb, "- %s: AVAILABLE\n", n)
			continue
		}
		exp := h.ExpiresAt.UTC()
		remaining := exp.Sub(now)
		if remaining < 0 {
			remaining = 0
		}
		desc := leasing.DescribeAgentID(h.AgentID, self)
		fmt.Fprintf(&sb, "- %s: %s until %s (%s remaining)",
			n, describeHolder(desc), exp.Format(time.RFC3339), remaining.Round(time.Second))
		if h.Reason != "" {
			fmt.Fprintf(&sb, " — reason %q", h.Reason)
		}
		sb.WriteString("\n")
		fmt.Fprintf(&sb, "  raw: agent_id=`%s` lease_id=`%s`\n", h.AgentID, h.ID)
	}
	heldNodesQuoted := joinNodesQuoted(req.Nodes)
	sb.WriteString("\nNo lease granted. Options:\n")
	fmt.Fprintf(&sb, "- retry with `lease(nodes=[%s], wait_seconds=1800)` to block\n", heldNodesQuoted)
	fmt.Fprintf(&sb, "- call `wait_for_release(nodes=[%s], timeout_seconds=1800)` to passively watch\n", heldNodesQuoted)
	fmt.Fprintf(&sb, "- call `force_release(nodes=[%s], reason='...')` if you have coordinated with the holder (USER INVOCATION ONLY)\n", heldNodesQuoted)
	return sb.String()
}

// describeHolder returns a human-readable ownership phrase for a lease holder,
// using the decoded AgentDescription to disambiguate multi-terminal scenarios.
// When the agent_id could not be decoded (e.g., a LABLINK_AGENT_ID override),
// the raw id is embedded so callers can still grep for it.
func describeHolder(d leasing.AgentDescription) string {
	if !d.Decoded {
		return "held by agent `" + d.Raw + "`"
	}
	if d.SameUser {
		return fmt.Sprintf("held by you from another terminal (host %s, lablink-server PID %d)", d.Hostname, d.PID)
	}
	if d.SameHost {
		return fmt.Sprintf("held by another user on this host (host %s, PID %d, cookie %s)", d.Hostname, d.PID, d.Cookie)
	}
	return fmt.Sprintf("held by another host (%s, PID %d)", d.Hostname, d.PID)
}

func renderReleased(ids []string) string {
	if len(ids) == 0 {
		return "## Released\n\nNo leases were released.\n"
	}
	var sb strings.Builder
	sb.WriteString("## Released\n\n")
	for _, id := range ids {
		fmt.Fprintf(&sb, "- `%s`\n", id)
	}
	return sb.String()
}

func renderForceReleased(ids []string, forcedBy, reason string) string {
	if len(ids) == 0 {
		return "## Force-released\n\nNo leases were force-released.\n"
	}
	var sb strings.Builder
	sb.WriteString("## Force-released\n\n")
	fmt.Fprintf(&sb, "- forced_by: `%s`\n", forcedBy)
	fmt.Fprintf(&sb, "- reason: %q\n", reason)
	sb.WriteString("- leases:\n")
	for _, id := range ids {
		fmt.Fprintf(&sb, "  - `%s`\n", id)
	}
	return sb.String()
}

func renderWaitTimeout(nodes []string, holders []*leasing.Lease, timeoutSec int) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Wait timed out\n\nNodes still held after %ds:\n\n", timeoutSec)
	fmt.Fprintf(&sb, "- requested: %s\n", joinNodes(nodes))
	if len(holders) == 0 {
		sb.WriteString("- still_held_by: (none observed — race with release; retry)\n")
	} else {
		sb.WriteString("- still_held_by:\n")
		for _, h := range holders {
			fmt.Fprintf(&sb, "  - `%s` agent=`%s` nodes=%s expires=%s\n",
				h.ID, h.AgentID, joinNodes(h.Nodes), h.ExpiresAt.UTC().Format(time.RFC3339))
		}
	}
	sb.WriteString("\n`freed=false`. This is a passive query — not an error.\n")
	return sb.String()
}

func renderLeaseTable(leases []*leasing.Lease, includeExpired bool) string {
	if len(leases) == 0 {
		if includeExpired {
			return "## Leases\n\nNo leases recorded (including expired).\n"
		}
		return "## Leases\n\nNo active leases.\n"
	}
	// Stable sort: active first, then by acquired_at desc.
	sort.SliceStable(leases, func(i, j int) bool {
		ai := leases[i].State == leasing.LeaseAcquired
		aj := leases[j].State == leasing.LeaseAcquired
		if ai != aj {
			return ai
		}
		return leases[i].AcquiredAt.After(leases[j].AcquiredAt)
	})
	var sb strings.Builder
	sb.WriteString("## Leases\n\n")
	sb.WriteString("| lease_id | agent | nodes | state | acquired_at | expires_at | reason |\n")
	sb.WriteString("|----------|-------|-------|-------|-------------|------------|--------|\n")
	for _, l := range leases {
		reason := l.Reason
		if reason == "" {
			reason = "—"
		}
		fmt.Fprintf(&sb, "| `%s` | `%s` | %s | %s | %s | %s | %s |\n",
			l.ID, l.AgentID, joinNodes(l.Nodes), l.State,
			l.AcquiredAt.UTC().Format(time.RFC3339),
			l.ExpiresAt.UTC().Format(time.RFC3339),
			truncate(reason, 60),
		)
	}
	return sb.String()
}

// pickLeasesTouchingNodes returns active leases whose Nodes overlap the
// supplied set. Expired/released/forced leases are skipped.
func pickLeasesTouchingNodes(leases []*leasing.Lease, nodes []string) []*leasing.Lease {
	want := make(map[string]struct{}, len(nodes))
	for _, n := range nodes {
		want[n] = struct{}{}
	}
	out := make([]*leasing.Lease, 0)
	now := time.Now()
	for _, l := range leases {
		if !l.IsActive(now) {
			continue
		}
		for _, n := range l.Nodes {
			if _, ok := want[n]; ok {
				out = append(out, l)
				break
			}
		}
	}
	return out
}

func flattenTopologyNodes(t *registry.Topology) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, names := range t.Roles {
		for _, n := range names {
			nn := strings.TrimSpace(n)
			if nn == "" {
				continue
			}
			if _, ok := seen[nn]; ok {
				continue
			}
			seen[nn] = struct{}{}
			out = append(out, nn)
		}
	}
	sort.Strings(out)
	return out
}

func unknownNodes(reg *registry.Registry, nodes []string) []string {
	if reg == nil {
		return nil
	}
	var missing []string
	for _, n := range nodes {
		if _, ok := reg.GetNode(n); !ok {
			missing = append(missing, n)
		}
	}
	return missing
}

func normalizeNodeList(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		t := strings.TrimSpace(s)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

func joinNodes(nodes []string) string {
	if len(nodes) == 0 {
		return "—"
	}
	parts := make([]string, len(nodes))
	for i, n := range nodes {
		parts[i] = "`" + n + "`"
	}
	return strings.Join(parts, ", ")
}

func joinNodesQuoted(nodes []string) string {
	parts := make([]string, len(nodes))
	for i, n := range nodes {
		parts[i] = "'" + n + "'"
	}
	return strings.Join(parts, ", ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// pollInterval returns the per-iteration sleep used by lease/wait retry
// loops: min(leaseWaitPollMax, waitTotal/10), floored at leaseWaitPollMin.
func pollInterval(waitTotal time.Duration) time.Duration {
	s := waitTotal / 10
	if s > leaseWaitPollMax {
		s = leaseWaitPollMax
	}
	if s < leaseWaitPollMin {
		s = leaseWaitPollMin
	}
	return s
}
