package mcptools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nijosmsft/lablink/internal/leasing"
	"github.com/nijosmsft/lablink/internal/registry"
)

// newLeaseTestRegistry seeds a minimal registry with the named nodes. All
// nodes use the insecure transport with a dummy address; lease handlers
// never dial them, they're only validated by GetNode.
func newLeaseTestRegistry(t *testing.T, nodes ...string) *registry.Registry {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nodes.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write nodes.json: %v", err)
	}
	reg := registry.Load(path)
	for _, n := range nodes {
		if err := reg.SetNode(&registry.Node{
			Name:          n,
			Address:       "127.0.0.1:0",
			TransportMode: "insecure",
		}); err != nil {
			t.Fatalf("SetNode %s: %v", n, err)
		}
	}
	return reg
}

func newLeaseTestStore(t *testing.T) leasing.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := leasing.OpenSQLiteStore(filepath.Join(dir, "leases.db"))
	if err != nil {
		t.Fatalf("OpenSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustCall(t *testing.T, h func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error), args map[string]any) *mcp.CallToolResult {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Arguments = args
	res, err := h(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if res == nil {
		t.Fatal("handler returned nil result")
	}
	return res
}

// --- 1. lease() granted -----------------------------------------------------

func TestLeaseHandler_Granted(t *testing.T) {
	reg := newLeaseTestRegistry(t, "server-25")
	store := newLeaseTestStore(t)
	h := leaseHandler(reg, store)

	res := mustCall(t, h, map[string]any{
		"nodes":            []string{"server-25"},
		"duration_minutes": 30,
		"reason":           "udp perf sweep",
	})
	if res.IsError {
		t.Fatalf("want success, got error: %s", toolResultText(res))
	}
	text := toolResultText(res)
	if !strings.Contains(text, "Lease acquired") {
		t.Fatalf("missing 'Lease acquired' header: %s", text)
	}
	if !strings.Contains(text, "server-25") {
		t.Fatalf("missing node name in result: %s", text)
	}
	if !strings.Contains(text, "udp perf sweep") {
		t.Fatalf("missing reason in result: %s", text)
	}
}

// --- 2. lease() conflict (fail-fast) ----------------------------------------

func TestLeaseHandler_Conflict_FailFast(t *testing.T) {
	reg := newLeaseTestRegistry(t, "server-25")
	store := newLeaseTestStore(t)

	// First holder via direct store call.
	_, err := store.Acquire(context.Background(), leasing.AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 30 * time.Minute,
		AgentID:  "alice-existing",
		Reason:   "prior run",
		Identity: leasing.Identity{EffectiveID: "alice-existing", Hostname: "h", PID: 1, Cookie: "c"},
	})
	if err != nil {
		t.Fatalf("seed acquire: %v", err)
	}

	h := leaseHandler(reg, store)
	res := mustCall(t, h, map[string]any{
		"nodes": []string{"server-25"},
	})
	if !res.IsError {
		t.Fatalf("want IsError=true on conflict, got: %s", toolResultText(res))
	}
	text := toolResultText(res)
	if !strings.Contains(text, "ConflictError") {
		t.Fatalf("expected ConflictError marker in body: %s", text)
	}
	if !strings.Contains(text, "alice-existing") {
		t.Fatalf("expected holder agent in body: %s", text)
	}
	if !strings.Contains(text, "wait_for_release") || !strings.Contains(text, "force_release") {
		t.Fatalf("expected option suggestions in body: %s", text)
	}
}

// --- 3. lease() unknown node rejected atomically ----------------------------

func TestLeaseHandler_UnknownNodeRejected(t *testing.T) {
	reg := newLeaseTestRegistry(t, "server-25")
	store := newLeaseTestStore(t)
	h := leaseHandler(reg, store)

	res := mustCall(t, h, map[string]any{
		"nodes": []string{"server-25", "ghost"},
	})
	if !res.IsError {
		t.Fatalf("want IsError=true for unknown node, got: %s", toolResultText(res))
	}
	if !strings.Contains(toolResultText(res), "ghost") {
		t.Fatalf("error must name the missing node: %s", toolResultText(res))
	}

	// Atomic: server-25 must NOT have been leased.
	leases, err := store.List(context.Background(), leasing.ListFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(leases) != 0 {
		t.Fatalf("atomic validation violated: %d leases exist", len(leases))
	}
}

// --- 4. lease() wait_seconds eventually succeeds when nodes free up ---------

func TestLeaseHandler_WaitSucceedsAfterRelease(t *testing.T) {
	// Shrink poll interval so test is fast.
	origMax, origMin := leaseWaitPollMax, leaseWaitPollMin
	leaseWaitPollMax = 50 * time.Millisecond
	leaseWaitPollMin = 10 * time.Millisecond
	t.Cleanup(func() { leaseWaitPollMax = origMax; leaseWaitPollMin = origMin })

	reg := newLeaseTestRegistry(t, "server-25")
	store := newLeaseTestStore(t)

	first, err := store.Acquire(context.Background(), leasing.AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 30 * time.Minute,
		AgentID:  "alice-existing",
		Identity: leasing.Identity{EffectiveID: "alice-existing", Hostname: "h", PID: 1, Cookie: "c"},
	})
	if err != nil {
		t.Fatalf("seed acquire: %v", err)
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = store.Release(context.Background(), first.ID, "alice-existing")
	}()

	h := leaseHandler(reg, store)
	res := mustCall(t, h, map[string]any{
		"nodes":        []string{"server-25"},
		"wait_seconds": 5,
		"agent_id":     "bob-waiting",
	})
	if res.IsError {
		t.Fatalf("want success after wait, got error: %s", toolResultText(res))
	}
	if !strings.Contains(toolResultText(res), "Lease acquired") {
		t.Fatalf("expected acquired result: %s", toolResultText(res))
	}
}

// --- 5. release() by lease_id -----------------------------------------------

func TestReleaseHandler_ByLeaseID(t *testing.T) {
	store := newLeaseTestStore(t)
	lease, err := store.Acquire(context.Background(), leasing.AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 30 * time.Minute,
		AgentID:  "alice-1",
		Identity: leasing.Identity{EffectiveID: "alice-1", Hostname: "h", PID: 1, Cookie: "c"},
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	h := releaseHandler(store)
	res := mustCall(t, h, map[string]any{
		"lease_id": lease.ID,
		"agent_id": "alice-1",
	})
	if res.IsError {
		t.Fatalf("want success, got: %s", toolResultText(res))
	}
	if !strings.Contains(toolResultText(res), lease.ID) {
		t.Fatalf("expected lease id in body: %s", toolResultText(res))
	}

	// Confirm via store: no active leases now.
	leases, _ := store.List(context.Background(), leasing.ListFilter{})
	if len(leases) != 0 {
		t.Fatalf("expected 0 active leases, got %d", len(leases))
	}
}

// --- 6. release() by nodes scoped to caller's agent id ----------------------

func TestReleaseHandler_ByNodes_OnlyOwnLeases(t *testing.T) {
	store := newLeaseTestStore(t)
	ctx := context.Background()
	// Alice leases server-25.
	alice, err := store.Acquire(ctx, leasing.AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 30 * time.Minute,
		AgentID:  "alice-1",
		Identity: leasing.Identity{EffectiveID: "alice-1", Hostname: "h", PID: 1, Cookie: "c"},
	})
	if err != nil {
		t.Fatalf("alice acquire: %v", err)
	}
	// Bob leases client-26.
	bob, err := store.Acquire(ctx, leasing.AcquireRequest{
		Nodes:    []string{"client-26"},
		Duration: 30 * time.Minute,
		AgentID:  "bob-1",
		Identity: leasing.Identity{EffectiveID: "bob-1", Hostname: "h", PID: 2, Cookie: "c"},
	})
	if err != nil {
		t.Fatalf("bob acquire: %v", err)
	}

	// Bob tries release(nodes=[server-25]) — finds no matching own lease.
	h := releaseHandler(store)
	res := mustCall(t, h, map[string]any{
		"nodes":    []string{"server-25"},
		"agent_id": "bob-1",
	})
	if !res.IsError {
		t.Fatalf("expected error (bob doesn't own server-25): %s", toolResultText(res))
	}

	// Alice's lease still active.
	leases, _ := store.List(ctx, leasing.ListFilter{})
	if len(leases) != 2 {
		t.Fatalf("expected 2 active leases, got %d", len(leases))
	}

	// Bob releases his own.
	res = mustCall(t, h, map[string]any{
		"nodes":    []string{"client-26"},
		"agent_id": "bob-1",
	})
	if res.IsError {
		t.Fatalf("bob own release failed: %s", toolResultText(res))
	}

	// Only alice's lease remains.
	leases, _ = store.List(ctx, leasing.ListFilter{})
	if len(leases) != 1 || leases[0].ID != alice.ID {
		t.Fatalf("expected only alice's lease %s remaining, got %+v", alice.ID, leases)
	}
	_ = bob
}

// --- 7. extend_lease() bumps expiry -----------------------------------------

func TestExtendLeaseHandler_Bumps(t *testing.T) {
	store := newLeaseTestStore(t)
	lease, err := store.Acquire(context.Background(), leasing.AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 10 * time.Minute,
		AgentID:  "alice-1",
		Identity: leasing.Identity{EffectiveID: "alice-1", Hostname: "h", PID: 1, Cookie: "c"},
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	origExpiry := lease.ExpiresAt

	h := extendLeaseHandler(store)
	res := mustCall(t, h, map[string]any{
		"lease_id":           lease.ID,
		"additional_minutes": 20,
		"agent_id":           "alice-1",
	})
	if res.IsError {
		t.Fatalf("extend failed: %s", toolResultText(res))
	}

	// Confirm via List. Note: Extend semantics is "push to at least now+add,
	// but never shrink" (max-of-two), so the new expiry is at most add later
	// than original. With duration=10min and add=20min, new ≈ orig+10min.
	leases, _ := store.List(context.Background(), leasing.ListFilter{})
	if len(leases) != 1 {
		t.Fatalf("want 1 lease, got %d", len(leases))
	}
	if !leases[0].ExpiresAt.After(origExpiry) {
		t.Fatalf("expires_at %v not bumped past original %v", leases[0].ExpiresAt, origExpiry)
	}
}

// --- 8. list_leases() filters by node ---------------------------------------

func TestListLeasesHandler_NodeFilter(t *testing.T) {
	store := newLeaseTestStore(t)
	ctx := context.Background()
	_, err := store.Acquire(ctx, leasing.AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 30 * time.Minute,
		AgentID:  "alice-1",
		Identity: leasing.Identity{EffectiveID: "alice-1", Hostname: "h", PID: 1, Cookie: "c"},
	})
	if err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	_, err = store.Acquire(ctx, leasing.AcquireRequest{
		Nodes:    []string{"client-26"},
		Duration: 30 * time.Minute,
		AgentID:  "bob-1",
		Identity: leasing.Identity{EffectiveID: "bob-1", Hostname: "h", PID: 2, Cookie: "c"},
	})
	if err != nil {
		t.Fatalf("seed bob: %v", err)
	}

	h := listLeasesHandler(store)
	// Filter to server-25 only.
	res := mustCall(t, h, map[string]any{"node": "server-25"})
	if res.IsError {
		t.Fatalf("list failed: %s", toolResultText(res))
	}
	text := toolResultText(res)
	if !strings.Contains(text, "server-25") {
		t.Fatalf("missing server-25 row: %s", text)
	}
	if strings.Contains(text, "client-26") {
		t.Fatalf("client-26 leaked into server-25 filter: %s", text)
	}
}

// --- 9. force_release() requires reason -------------------------------------

func TestForceReleaseHandler_RequiresReason(t *testing.T) {
	store := newLeaseTestStore(t)
	h := forceReleaseHandler(store)
	res := mustCall(t, h, map[string]any{
		"lease_id": "lse-1234abcd",
	})
	if !res.IsError {
		t.Fatalf("want IsError=true when reason missing: %s", toolResultText(res))
	}
	if !strings.Contains(toolResultText(res), "reason") {
		t.Fatalf("error must mention reason: %s", toolResultText(res))
	}
}

// --- 10. force_release() by nodes breaks another agent's lease --------------

func TestForceReleaseHandler_ByNodes(t *testing.T) {
	store := newLeaseTestStore(t)
	ctx := context.Background()
	victim, err := store.Acquire(ctx, leasing.AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 30 * time.Minute,
		AgentID:  "alice-stuck",
		Identity: leasing.Identity{EffectiveID: "alice-stuck", Hostname: "h", PID: 1, Cookie: "c"},
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	h := forceReleaseHandler(store)
	res := mustCall(t, h, map[string]any{
		"nodes":  []string{"server-25"},
		"reason": "alice crashed; recovering lab",
	})
	if res.IsError {
		t.Fatalf("force release failed: %s", toolResultText(res))
	}
	body := toolResultText(res)
	if !strings.Contains(body, victim.ID) {
		t.Fatalf("expected victim lease id %s in body: %s", victim.ID, body)
	}
	if !strings.Contains(body, "alice crashed") {
		t.Fatalf("expected reason in body: %s", body)
	}

	// No active leases remain.
	leases, _ := store.List(ctx, leasing.ListFilter{})
	if len(leases) != 0 {
		t.Fatalf("expected 0 active leases after force, got %d", len(leases))
	}
}

// --- 11. wait_for_release() succeeds when nodes free up ---------------------

func TestWaitForReleaseHandler_FreedAfterRelease(t *testing.T) {
	origMax, origMin := leaseWaitPollMax, leaseWaitPollMin
	leaseWaitPollMax = 30 * time.Millisecond
	leaseWaitPollMin = 10 * time.Millisecond
	t.Cleanup(func() { leaseWaitPollMax = origMax; leaseWaitPollMin = origMin })

	store := newLeaseTestStore(t)
	ctx := context.Background()
	lease, err := store.Acquire(ctx, leasing.AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 30 * time.Minute,
		AgentID:  "alice-1",
		Identity: leasing.Identity{EffectiveID: "alice-1", Hostname: "h", PID: 1, Cookie: "c"},
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	go func() {
		time.Sleep(80 * time.Millisecond)
		_ = store.Release(context.Background(), lease.ID, "alice-1")
	}()

	h := waitForReleaseHandler(store)
	res := mustCall(t, h, map[string]any{
		"nodes":           []string{"server-25"},
		"timeout_seconds": 5,
	})
	if res.IsError {
		t.Fatalf("wait failed: %s", toolResultText(res))
	}
	if !strings.Contains(toolResultText(res), "Nodes free") {
		t.Fatalf("expected 'Nodes free' marker: %s", toolResultText(res))
	}
}

// --- 12. lease_topology() flattens roles ------------------------------------

func TestLeaseTopologyHandler_FlattensRoles(t *testing.T) {
	reg := newLeaseTestRegistry(t, "server-25", "client-26", "client-27")
	if err := reg.SetTopology(&registry.Topology{
		Name: "perf-lab",
		Roles: map[string][]string{
			"server": {"server-25"},
			"client": {"client-26", "client-27"},
		},
	}); err != nil {
		t.Fatalf("SetTopology: %v", err)
	}
	store := newLeaseTestStore(t)
	h := leaseTopologyHandler(reg, store)

	res := mustCall(t, h, map[string]any{
		"topology":         "perf-lab",
		"duration_minutes": 30,
		"reason":           "fleet test",
	})
	if res.IsError {
		t.Fatalf("lease_topology failed: %s", toolResultText(res))
	}
	body := toolResultText(res)
	for _, want := range []string{"server-25", "client-26", "client-27"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %s: %s", want, body)
		}
	}
}

// --- 13. lease_role() narrows by role within topology -----------------------

func TestLeaseRoleHandler_WithinTopology(t *testing.T) {
	reg := newLeaseTestRegistry(t, "server-25", "client-26", "client-27")
	if err := reg.SetTopology(&registry.Topology{
		Name: "perf-lab",
		Roles: map[string][]string{
			"server": {"server-25"},
			"client": {"client-26", "client-27"},
		},
	}); err != nil {
		t.Fatalf("SetTopology: %v", err)
	}
	store := newLeaseTestStore(t)
	h := leaseRoleHandler(reg, store)

	res := mustCall(t, h, map[string]any{
		"role":     "client",
		"topology": "perf-lab",
	})
	if res.IsError {
		t.Fatalf("lease_role failed: %s", toolResultText(res))
	}
	body := toolResultText(res)
	if !strings.Contains(body, "client-26") || !strings.Contains(body, "client-27") {
		t.Fatalf("client nodes missing from body: %s", body)
	}
	if strings.Contains(body, "server-25") {
		t.Fatalf("server-25 should not be included for role=client: %s", body)
	}
}

// --- 13. renderConflict friendly phrases -------------------------------------

// makeHolder builds a minimal *leasing.Lease for conflict rendering tests.
func makeHolder(agentID, leaseID, reason string, expires time.Time) *leasing.Lease {
	return &leasing.Lease{
		ID:        leaseID,
		AgentID:   agentID,
		ExpiresAt: expires,
		Reason:    reason,
		State:     leasing.LeaseAcquired,
	}
}

func TestRenderConflict_SameUser_Phrase(t *testing.T) {
	// Holder's agent_id matches the calling process's cookie AND hostname.
	self := leasing.Identity{Cookie: "deadbeef", Hostname: "WORKHOST"}
	exp := time.Now().UTC().Add(40 * time.Minute)
	ce := &leasing.ConflictError{
		Holders: map[string]*leasing.Lease{
			"RR1N4406-16": makeHolder(
				"deadbeef-WORKHOST-47628-4446",
				"lse-aabbccdd",
				"file-mode WPA capture",
				exp,
			),
		},
	}
	req := leasing.AcquireRequest{Nodes: []string{"RR1N4406-16"}}
	text := renderConflict(req, ce, 0, self)

	if !strings.Contains(text, "another terminal") {
		t.Fatalf("want 'another terminal' phrase for same-user holder:\n%s", text)
	}
	// Raw id must still appear on the raw: line.
	if !strings.Contains(text, "deadbeef-WORKHOST-47628-4446") {
		t.Fatalf("raw agent_id must appear on raw: line:\n%s", text)
	}
	if !strings.Contains(text, "lse-aabbccdd") {
		t.Fatalf("raw lease_id must appear on raw: line:\n%s", text)
	}
	if !strings.Contains(text, "ConflictError") {
		t.Fatalf("ConflictError header must be present:\n%s", text)
	}
}

func TestRenderConflict_SameHostDiffCookie_Phrase(t *testing.T) {
	// Holder shares hostname but has a different cookie (different user, same machine).
	self := leasing.Identity{Cookie: "11223344", Hostname: "WORKHOST"}
	exp := time.Now().UTC().Add(20 * time.Minute)
	ce := &leasing.ConflictError{
		Holders: map[string]*leasing.Lease{
			"server-25": makeHolder(
				"deadbeef-WORKHOST-12345-abcd",
				"lse-00112233",
				"soak test",
				exp,
			),
		},
	}
	req := leasing.AcquireRequest{Nodes: []string{"server-25"}}
	text := renderConflict(req, ce, 0, self)

	if !strings.Contains(text, "another user on this host") {
		t.Fatalf("want 'another user on this host' phrase:\n%s", text)
	}
	if !strings.Contains(text, "deadbeef-WORKHOST-12345-abcd") {
		t.Fatalf("raw agent_id must be on raw: line:\n%s", text)
	}
}

func TestRenderConflict_DifferentHost_Phrase(t *testing.T) {
	// Holder is on a completely different machine.
	self := leasing.Identity{Cookie: "deadbeef", Hostname: "MY-LOCAL-BOX"}
	exp := time.Now().UTC().Add(10 * time.Minute)
	ce := &leasing.ConflictError{
		Holders: map[string]*leasing.Lease{
			"server-25": makeHolder(
				"deadbeef-REMOTE-BOX-99999-ef01",
				"lse-cafebabe",
				"remote soak",
				exp,
			),
		},
	}
	req := leasing.AcquireRequest{Nodes: []string{"server-25"}}
	text := renderConflict(req, ce, 0, self)

	if !strings.Contains(text, "another host") {
		t.Fatalf("want 'another host' phrase:\n%s", text)
	}
	if !strings.Contains(text, "deadbeef-REMOTE-BOX-99999-ef01") {
		t.Fatalf("raw agent_id must be on raw: line:\n%s", text)
	}
}

func TestRenderConflict_CustomAgentID_RawFallback(t *testing.T) {
	// Holder has a custom LABLINK_AGENT_ID that doesn't match the standard shape.
	self := leasing.Identity{Cookie: "deadbeef", Hostname: "WORKHOST"}
	exp := time.Now().UTC().Add(30 * time.Minute)
	ce := &leasing.ConflictError{
		Holders: map[string]*leasing.Lease{
			"server-25": makeHolder("custom-agent-id", "lse-12341234", "custom op", exp),
		},
	}
	req := leasing.AcquireRequest{Nodes: []string{"server-25"}}
	text := renderConflict(req, ce, 0, self)

	// Must NOT contain phrasing that implies decoded knowledge.
	if strings.Contains(text, "another terminal") ||
		strings.Contains(text, "another user on this host") ||
		strings.Contains(text, "another host (") {
		t.Fatalf("decoded phrase must not appear for custom agent_id:\n%s", text)
	}
	// Raw id must appear.
	if !strings.Contains(text, "custom-agent-id") {
		t.Fatalf("raw agent_id must appear for custom holder:\n%s", text)
	}
}

// --- 14. renderLeaseGateError friendly phrases --------------------------------

func TestRenderLeaseGateError_SameUser_Phrase(t *testing.T) {
	self := leasing.Identity{Cookie: "aabbccdd", Hostname: "LAB-HOST"}
	holders := map[string]*leasing.Lease{
		"server-25": makeHolder(
			"aabbccdd-LAB-HOST-55555-1234",
			"lse-deadbeef",
			"perf sweep",
			time.Now().UTC().Add(60*time.Minute),
		),
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = "execute_command"
	text := renderLeaseGateError(req, []string{"server-25"}, []string{"server-25"}, holders, "aabbccdd-LAB-HOST-11111-abcd", self)

	if !strings.Contains(text, "another terminal") {
		t.Fatalf("want 'another terminal' phrase in gate error:\n%s", text)
	}
	// Raw agent_id still greppable inside the holder cell.
	if !strings.Contains(text, "aabbccdd-LAB-HOST-55555-1234") {
		t.Fatalf("raw holder agent_id must appear:\n%s", text)
	}
}

func TestRenderLeaseGateError_DifferentHost_Phrase(t *testing.T) {
	self := leasing.Identity{Cookie: "aabbccdd", Hostname: "LOCAL-HOST"}
	holders := map[string]*leasing.Lease{
		"server-25": makeHolder(
			"aabbccdd-REMOTE-HOST-55555-1234",
			"lse-deadbeef",
			"perf sweep",
			time.Now().UTC().Add(60*time.Minute),
		),
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = "execute_command"
	text := renderLeaseGateError(req, []string{"server-25"}, []string{"server-25"}, holders, "aabbccdd-LOCAL-HOST-11111-abcd", self)

	if !strings.Contains(text, "another host") {
		t.Fatalf("want 'another host' phrase in gate error:\n%s", text)
	}
}

func TestRenderLeaseGateError_CustomAgentID_RawFallback(t *testing.T) {
	self := leasing.Identity{Cookie: "aabbccdd", Hostname: "LOCAL-HOST"}
	holders := map[string]*leasing.Lease{
		"server-25": makeHolder(
			"totally-custom-id",
			"lse-deadbeef",
			"custom reason",
			time.Now().UTC().Add(60*time.Minute),
		),
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = "execute_command"
	text := renderLeaseGateError(req, []string{"server-25"}, []string{"server-25"}, holders, "my-caller-id", self)

	if !strings.Contains(text, "totally-custom-id") {
		t.Fatalf("raw custom agent_id must appear in gate error:\n%s", text)
	}
	if strings.Contains(text, "another terminal") || strings.Contains(text, "another host (") {
		t.Fatalf("decoded phrase must not appear for custom agent_id:\n%s", text)
	}
}
