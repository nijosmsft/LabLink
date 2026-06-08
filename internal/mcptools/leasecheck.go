package mcptools

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/leasing"
	"github.com/nijosmsft/lablink/internal/registry"
)

// LeaseGateConfig is the wiring an MCP tool registration uses to enable
// lease checks. One LeaseGateConfig is shared across every tool registration
// in a single lablink-server process.
//
// Enabled gates the whole middleware: when false, LeaseGate degrades to a
// pass-through (no lookup, no heartbeat, no allocation). The server toggles
// this via the LABLINK_LEASE_REQUIRED env var.
type LeaseGateConfig struct {
	Store    leasing.Store
	Registry *registry.Registry
	Enabled  bool
}

// NodeExtractor pulls the tool-touched node names out of an MCP request.
// Tools that act on a single node pass extractSingleNode("node"); tools that
// fan out over a role/topology or a node list pass a custom extractor.
//
// An empty return is allowed and means "this call doesn't touch a node" —
// LeaseGate then passes through without consulting the store.
type NodeExtractor func(mcp.CallToolRequest, *registry.Registry) []string

// LeaseGate wraps an inner tool handler so that, before invoking it, the
// caller's effective identity is verified to hold an active lease covering
// every node the call would touch.
//
// Behavior:
//   - cfg.Enabled == false  → pass-through (no store calls).
//   - extract returns []    → pass-through (no node ownership to check).
//   - All requested nodes are covered by one or more active leases owned by
//     this agent_id → call inner; on return, if inner took > 30s and the
//     covering lease's runway is < 5min, opportunistically Extend by 60s
//     (errors silently ignored, this is best-effort heartbeat).
//   - Otherwise → render a structured markdown error listing the holders of
//     the offending nodes and the recommended recovery commands.
//
// The wrap order is: LeaseGate(...) → addTool(...) so that ops-registry
// tracking sees both successful calls and lease-denied calls. Tools that
// bypass addTool (s.AddTool direct) still call LeaseGate first.
func LeaseGate(cfg LeaseGateConfig, extract NodeExtractor, inner server.ToolHandlerFunc) server.ToolHandlerFunc {
	if !cfg.Enabled || cfg.Store == nil {
		return inner
	}
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nodes := normalizeNodeList(extract(req, cfg.Registry))
		if len(nodes) == 0 {
			return inner(ctx, req)
		}

		identity := leasing.Default()
		agentID := identity.EffectiveID
		now := timeNow()

		// Fast path: list only this agent's leases. If every requested node
		// is covered by one of them, we hold the lock collectively.
		ownLeases, err := cfg.Store.List(ctx, leasing.ListFilter{AgentID: agentID})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("lease store error: %v", err)), nil
		}
		covered, uncovered := coverageBy(ownLeases, nodes, now)
		if len(uncovered) == 0 {
			// Reentrant — caller already owns every touched node.
			start := timeNow()
			result, callErr := inner(ctx, req)
			maybeHeartbeat(ctx, cfg.Store, agentID, covered, timeNow().Sub(start))
			return result, callErr
		}

		// Slow path: look up holders of the uncovered nodes to render a
		// useful "who has it" error.
		holders, err := holderLookup(ctx, cfg.Store, uncovered)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("lease store error: %v", err)), nil
		}
		return mcp.NewToolResultError(renderLeaseGateError(req, nodes, uncovered, holders, agentID)), nil
	}
}

// coverageBy splits requested into (covered-by-own-leases, uncovered) and
// returns the set of own leases that participated in covering. The returned
// lease set drives the implicit heartbeat — we only extend leases we
// actually used.
func coverageBy(ownLeases []*leasing.Lease, requested []string, now time.Time) ([]*leasing.Lease, []string) {
	want := make(map[string]struct{}, len(requested))
	for _, n := range requested {
		want[n] = struct{}{}
	}

	usedSet := make(map[string]*leasing.Lease)
	for _, l := range ownLeases {
		if !l.IsActive(now) {
			continue
		}
		for _, n := range l.Nodes {
			if _, ok := want[n]; ok {
				delete(want, n)
				usedSet[l.ID] = l
			}
		}
	}

	used := make([]*leasing.Lease, 0, len(usedSet))
	for _, l := range usedSet {
		used = append(used, l)
	}
	sort.Slice(used, func(i, j int) bool { return used[i].ID < used[j].ID })

	uncovered := make([]string, 0, len(want))
	for n := range want {
		uncovered = append(uncovered, n)
	}
	sort.Strings(uncovered)
	return used, uncovered
}

// holderLookup returns active leases (any agent) that touch any of the
// supplied nodes. The Store has no by-node index; we list all and filter.
func holderLookup(ctx context.Context, store leasing.Store, nodes []string) (map[string]*leasing.Lease, error) {
	all, err := store.List(ctx, leasing.ListFilter{})
	if err != nil {
		return nil, err
	}
	want := make(map[string]struct{}, len(nodes))
	for _, n := range nodes {
		want[n] = struct{}{}
	}
	out := make(map[string]*leasing.Lease)
	now := timeNow()
	for _, l := range all {
		if !l.IsActive(now) {
			continue
		}
		for _, n := range l.Nodes {
			if _, ok := want[n]; ok {
				if _, dup := out[n]; !dup {
					out[n] = l
				}
			}
		}
	}
	return out, nil
}

// Heartbeat thresholds (mirrored from the task spec).
//
// These are vars (not consts) so tests can shrink the latency window to
// sub-second values without forcing real sleeps. Restore the original
// values via t.Cleanup. Production code never mutates these.
var (
	leaseHeartbeatLatency = 30 * time.Second
	leaseHeartbeatRunway  = 5 * time.Minute
	leaseHeartbeatExtend  = 60 * time.Second
)

// maybeHeartbeat extends each used lease when the inner call took longer
// than leaseHeartbeatLatency AND the lease's remaining runway is below
// leaseHeartbeatRunway. Errors are intentionally ignored: heartbeat is a
// best-effort hint and the caller's request already succeeded.
func maybeHeartbeat(ctx context.Context, store leasing.Store, agentID string, used []*leasing.Lease, innerDur time.Duration) {
	if innerDur < leaseHeartbeatLatency {
		return
	}
	now := timeNow()
	for _, l := range used {
		if l == nil {
			continue
		}
		if l.ExpiresAt.Sub(now) >= leaseHeartbeatRunway {
			continue
		}
		_, _ = store.Extend(ctx, l.ID, agentID, leaseHeartbeatExtend)
	}
}

// renderLeaseGateError builds the structured markdown surface a lease-gated
// tool returns when the caller can't proceed. Matches the M2 error style.
func renderLeaseGateError(req mcp.CallToolRequest, requested, uncovered []string, holders map[string]*leasing.Lease, agentID string) string {
	var sb strings.Builder
	sb.WriteString("**Lease check failed.**\n\n")
	fmt.Fprintf(&sb, "Tool `%s` requires an active lease on %s.\n",
		req.Params.Name, joinNodes(requested))
	fmt.Fprintf(&sb, "Your agent_id `%s` does not hold %s.\n\n",
		agentID, joinNodes(uncovered))

	if len(holders) > 0 {
		sb.WriteString("## Current holders\n\n")
		sb.WriteString("| node | lease_id | agent | expires_at | reason |\n")
		sb.WriteString("|------|----------|-------|------------|--------|\n")
		nodes := make([]string, 0, len(holders))
		for n := range holders {
			nodes = append(nodes, n)
		}
		sort.Strings(nodes)
		for _, n := range nodes {
			h := holders[n]
			reason := h.Reason
			if reason == "" {
				reason = "—"
			}
			fmt.Fprintf(&sb, "| `%s` | `%s` | `%s` | %s | %s |\n",
				n, h.ID, h.AgentID,
				h.ExpiresAt.UTC().Format(time.RFC3339),
				truncate(reason, 60),
			)
		}
		sb.WriteString("\n")
	} else {
		fmt.Fprintf(&sb, "No active holder was found for %s — these nodes appear free.\n"+
			"This usually means the lease store transitioned between the precheck and the lookup.\n"+
			"Retry `lease(nodes=[...])` to claim them.\n\n",
			joinNodes(uncovered))
	}

	sb.WriteString("## Recommended next steps\n\n")
	fmt.Fprintf(&sb, "- Wait passively: `wait_for_release(nodes=[%s])` then retry.\n", joinNodesQuoted(uncovered))
	fmt.Fprintf(&sb, "- Block and acquire: `lease(nodes=[%s], wait_seconds=120, reason='...')`.\n", joinNodesQuoted(uncovered))
	sb.WriteString("- If the holder is stuck and you have authority to break it: " +
		"`force_release(nodes=[...], reason='...')` (use sparingly).\n")
	sb.WriteString("- To bypass lease checks for this server only, set " +
		"`LABLINK_LEASE_REQUIRED=0` and restart lablink-server.\n")
	return sb.String()
}

// -------------------- node extractors --------------------

// extractSingleNode returns the value of one named string argument, e.g.
// extractSingleNode("node") for every tool that takes `node: <name>`.
func extractSingleNode(arg string) NodeExtractor {
	return func(req mcp.CallToolRequest, _ *registry.Registry) []string {
		v := strings.TrimSpace(req.GetString(arg, ""))
		if v == "" {
			return nil
		}
		return []string{v}
	}
}

// extractMultiNodes returns every value of a named string-array argument,
// e.g. extractMultiNodes("nodes") for reboot_nodes.
func extractMultiNodes(arg string) NodeExtractor {
	return func(req mcp.CallToolRequest, _ *registry.Registry) []string {
		return normalizeNodeList(req.GetStringSlice(arg, nil))
	}
}

// extractCopyBetweenNodes is the special-case extractor for copy_between_nodes:
// touches BOTH source_node and dest_node, so the caller must hold leases on
// both.
func extractCopyBetweenNodes(req mcp.CallToolRequest, _ *registry.Registry) []string {
	src := strings.TrimSpace(req.GetString("source_node", ""))
	dst := strings.TrimSpace(req.GetString("dest_node", ""))
	out := make([]string, 0, 2)
	if src != "" {
		out = append(out, src)
	}
	if dst != "" {
		out = append(out, dst)
	}
	return normalizeNodeList(out)
}

// extractRoleNodes is used by execute_on_role / run_script_on_role. It
// resolves `role` (+ optional `topology`) to the registered node names.
// Returns nil when no nodes resolve — the inner handler will surface a
// "no nodes match" error.
func extractRoleNodes(req mcp.CallToolRequest, reg *registry.Registry) []string {
	if reg == nil {
		return nil
	}
	role := strings.TrimSpace(req.GetString("role", ""))
	if role == "" {
		return nil
	}
	topology := strings.TrimSpace(req.GetString("topology", ""))
	var nodes []*registry.Node
	if topology != "" {
		nodes = reg.NodesForTopologyRole(topology, role)
	} else {
		nodes = reg.NodesByRole(role)
	}
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if n != nil && n.Name != "" {
			out = append(out, n.Name)
		}
	}
	return normalizeNodeList(out)
}

// extractSyncTimeNodes is the sync_time extractor: if `topology` is set,
// flatten that topology's roles → nodes; otherwise, return every node in
// the registry.
func extractSyncTimeNodes(req mcp.CallToolRequest, reg *registry.Registry) []string {
	if reg == nil {
		return nil
	}
	topology := strings.TrimSpace(req.GetString("topology", ""))
	if topology == "" {
		nodes := reg.AllNodes()
		out := make([]string, 0, len(nodes))
		for _, n := range nodes {
			if n != nil && n.Name != "" {
				out = append(out, n.Name)
			}
		}
		return normalizeNodeList(out)
	}
	t, ok := reg.GetTopology(topology)
	if !ok {
		return nil
	}
	return normalizeNodeList(flattenTopologyNodes(t))
}

// extractJobNode resolves the node from the `node` arg for job-control
// tools. The job_id itself is opaque; if a future revision wants to look
// up the original job's owning agent, that lives in the job record on the
// node — not the lease store. We gate on `node` only.
func extractJobNode() NodeExtractor {
	return extractSingleNode("node")
}
