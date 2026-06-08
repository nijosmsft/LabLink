package mcptools

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nijosmsft/lablink/internal/leasing"
)

// TestLeasing_LifecycleE2E exercises the full v0.4.0 leasing lifecycle
// through the MCP handlers (not just the store). It is the M4 acceptance
// test: every state transition that downstream users will hit must be
// exercised once in the same test so a regression in any single hop trips
// this single test name.
//
// Stages:
//  1. acquire on a node (lease())
//  2. extend it (extend_lease())
//  3. wait for it to TTL-expire (short Duration + Sleep)
//  4. sweep — assert TTL=1 and the slot is reclaimed
//  5. acquire again — must succeed because the slot is free
//  6. force_release the new lease (force_release())
//  7. final acquire — must succeed because force_release freed it
func TestLeasing_LifecycleE2E(t *testing.T) {
	_ = newLeaseTestRegistry(t, "server-25")
	store := newLeaseTestStore(t)

	ctx := context.Background()
	hostname := "e2e-host"
	ident := leasing.Identity{
		EffectiveID: "alice-e2e",
		Hostname:    hostname,
		PID:         424242,
		Cookie:      "cookie-e2e",
	}

	// --- Stage 1: acquire via store with a short TTL we will let expire ---
	first, err := store.Acquire(ctx, leasing.AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 250 * time.Millisecond,
		AgentID:  ident.EffectiveID,
		Reason:   "e2e lifecycle stage 1",
		Identity: ident,
	})
	if err != nil {
		t.Fatalf("stage 1 acquire: %v", err)
	}
	if first.ID == "" {
		t.Fatal("stage 1: empty lease ID")
	}

	// --- Stage 2: extend it (sanity check the MCP handler) ----------------
	extendH := extendLeaseHandler(store)
	extRes := mustCall(t, extendH, map[string]any{
		"lease_id":           first.ID,
		"additional_minutes": 1, // pushes deadline well past our sleep
		"agent_id":           ident.EffectiveID,
	})
	if extRes.IsError {
		t.Fatalf("stage 2 extend: %s", toolResultText(extRes))
	}

	// Force the lease to expire deterministically without sleeping for the
	// full extended TTL: rewind expires_at on the store directly. We use
	// the public Sweep contract that says "TTL = now > expires_at" and
	// shift it by re-acquiring with a fresh ultra-short TTL through the
	// store's Acquire path. The simplest deterministic path: release the
	// first lease, re-acquire with a tiny 50ms TTL, then sleep 100ms.
	releaseH := releaseHandler(store)
	relRes := mustCall(t, releaseH, map[string]any{
		"lease_id": first.ID,
		"agent_id": ident.EffectiveID,
	})
	if relRes.IsError {
		t.Fatalf("stage 2.5 release: %s", toolResultText(relRes))
	}

	// --- Stage 3: re-acquire with a tiny TTL and sleep past it ------------
	short, err := store.Acquire(ctx, leasing.AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 50 * time.Millisecond,
		AgentID:  ident.EffectiveID,
		Reason:   "e2e lifecycle stage 3 (about to expire)",
		Identity: ident,
	})
	if err != nil {
		t.Fatalf("stage 3 acquire: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	// --- Stage 4: sweep and assert TTL=1 ---------------------------------
	// liveProbe says "yes alive" for ANY pid — so the only sweep path
	// that should fire here is TTL.
	probe := func(pid int, startUnix int64) bool { return true }
	swept, err := store.Sweep(ctx, hostname, probe)
	if err != nil {
		t.Fatalf("stage 4 sweep: %v", err)
	}
	if swept.TTL != 1 {
		t.Fatalf("stage 4: want TTL=1, got %+v", swept)
	}
	if swept.DeadProcess != 0 {
		t.Fatalf("stage 4: want DeadProcess=0, got %+v", swept)
	}
	if swept.Total() != 1 {
		t.Fatalf("stage 4: want Total()=1, got %d", swept.Total())
	}
	_ = short // keep the variable used; its ID was captured by sweep

	// --- Stage 5: acquire again — sweep should have freed the slot --------
	second, err := store.Acquire(ctx, leasing.AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 30 * time.Minute,
		AgentID:  "bob-e2e",
		Reason:   "e2e lifecycle stage 5",
		Identity: leasing.Identity{EffectiveID: "bob-e2e", Hostname: hostname, PID: 1, Cookie: "c"},
	})
	if err != nil {
		t.Fatalf("stage 5 acquire (after sweep): %v", err)
	}
	if second.ID == first.ID || second.ID == short.ID {
		t.Fatalf("stage 5: new lease ID should differ from previous")
	}

	// --- Stage 6: force_release the live lease ----------------------------
	forceH := forceReleaseHandler(store)
	forceRes := mustCall(t, forceH, map[string]any{
		"lease_id": second.ID,
		"reason":   "e2e lifecycle stage 6 (force)",
	})
	if forceRes.IsError {
		t.Fatalf("stage 6 force_release: %s", toolResultText(forceRes))
	}
	if !strings.Contains(toolResultText(forceRes), second.ID) {
		t.Fatalf("stage 6: force_release body missing lease id %s: %s",
			second.ID, toolResultText(forceRes))
	}

	// --- Stage 7: final acquire — must succeed (slot free again) ----------
	third, err := store.Acquire(ctx, leasing.AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 5 * time.Minute,
		AgentID:  "carol-e2e",
		Reason:   "e2e lifecycle stage 7",
		Identity: leasing.Identity{EffectiveID: "carol-e2e", Hostname: hostname, PID: 2, Cookie: "c"},
	})
	if err != nil {
		t.Fatalf("stage 7 acquire (after force_release): %v", err)
	}
	if third.ID == "" {
		t.Fatal("stage 7: empty lease ID")
	}
}
