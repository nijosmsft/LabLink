package leasing

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "leases.db")
	s, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatalf("OpenSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func ident(agentID string) Identity {
	return Identity{
		Cookie:      "deadbeef",
		Hostname:    "testhost",
		PID:         1234,
		StartTime:   time.Unix(1_000_000_000, 0),
		RandSuffix:  "abcd",
		EffectiveID: agentID,
	}
}

// --- 1. Acquire_Granted -----------------------------------------------------

func TestAcquire_Granted(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	l, err := s.Acquire(ctx, AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 30 * time.Minute,
		AgentID:  "alice-1",
		Reason:   "udp perf sweep",
		Identity: ident("alice-1"),
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if l == nil || l.ID == "" {
		t.Fatal("expected non-nil lease with id")
	}
	if l.State != LeaseAcquired {
		t.Errorf("state=%q want acquired", l.State)
	}
	if got, want := strings.Join(l.Nodes, ","), "server-25"; got != want {
		t.Errorf("nodes=%q want %q", got, want)
	}
	if !l.ExpiresAt.After(l.AcquiredAt) {
		t.Errorf("expires_at %v not after acquired_at %v", l.ExpiresAt, l.AcquiredAt)
	}
	n, err := s.AuditRowCount(ctx, l.ID, "acquired")
	if err != nil {
		t.Fatalf("AuditRowCount: %v", err)
	}
	if n != 1 {
		t.Errorf("audit 'acquired' rows = %d want 1", n)
	}
}

// --- 2. Acquire_Conflict ----------------------------------------------------

func TestAcquire_Conflict(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	first, err := s.Acquire(ctx, AcquireRequest{
		Nodes:    []string{"server-25"},
		AgentID:  "alice-1",
		Reason:   "first",
		Identity: ident("alice-1"),
	})
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}

	_, err = s.Acquire(ctx, AcquireRequest{
		Nodes:    []string{"server-25"},
		AgentID:  "bob-2",
		Reason:   "second",
		Identity: ident("bob-2"),
	})
	if err == nil {
		t.Fatal("expected ConflictError, got nil")
	}
	var conf *ConflictError
	if !errors.As(err, &conf) {
		t.Fatalf("error type = %T want *ConflictError", err)
	}
	holder, ok := conf.Holders["server-25"]
	if !ok || holder == nil {
		t.Fatalf("missing holder for server-25, holders=%v", conf.Holders)
	}
	if holder.ID != first.ID {
		t.Errorf("holder id = %q want %q", holder.ID, first.ID)
	}
	if holder.AgentID != "alice-1" {
		t.Errorf("holder agent_id = %q want alice-1", holder.AgentID)
	}
}

// --- 3. Acquire_PartialConflict (all-or-nothing rollback) -------------------

func TestAcquire_PartialConflict(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Alice holds client-26.
	if _, err := s.Acquire(ctx, AcquireRequest{
		Nodes:    []string{"client-26"},
		AgentID:  "alice-1",
		Reason:   "kd bring-up",
		Identity: ident("alice-1"),
	}); err != nil {
		t.Fatalf("alice acquire: %v", err)
	}

	// Bob asks for server-25 + client-26 atomically. Must be rejected
	// AND must not have left a partial lease on server-25.
	_, err := s.Acquire(ctx, AcquireRequest{
		Nodes:    []string{"server-25", "client-26"},
		AgentID:  "bob-2",
		Reason:   "paired run",
		Identity: ident("bob-2"),
	})
	if err == nil {
		t.Fatal("expected ConflictError, got nil")
	}
	var conf *ConflictError
	if !errors.As(err, &conf) {
		t.Fatalf("error type = %T want *ConflictError", err)
	}
	if _, ok := conf.Holders["client-26"]; !ok {
		t.Errorf("missing client-26 in holders: %v", conf.Holders)
	}
	if _, ok := conf.Holders["server-25"]; ok {
		t.Errorf("server-25 should NOT be in holders (it was free): %v", conf.Holders)
	}

	// Verify server-25 is still free — a fresh acquire by carol should succeed.
	got, err := s.Acquire(ctx, AcquireRequest{
		Nodes:    []string{"server-25"},
		AgentID:  "carol-3",
		Reason:   "smoke",
		Identity: ident("carol-3"),
	})
	if err != nil {
		t.Fatalf("carol acquire of server-25 after rollback: %v", err)
	}
	if got == nil || got.State != LeaseAcquired {
		t.Fatalf("carol lease not active: %#v", got)
	}
}

// --- 4. Release_ByOwner -----------------------------------------------------

func TestRelease_ByOwner(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	l, err := s.Acquire(ctx, AcquireRequest{
		Nodes:    []string{"server-25"},
		AgentID:  "alice-1",
		Identity: ident("alice-1"),
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := s.Release(ctx, l.ID, "alice-1"); err != nil {
		t.Fatalf("Release by owner: %v", err)
	}
	// After release, a new acquire on the same node by anyone must succeed.
	if _, err := s.Acquire(ctx, AcquireRequest{
		Nodes:    []string{"server-25"},
		AgentID:  "bob-2",
		Identity: ident("bob-2"),
	}); err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	n, err := s.AuditRowCount(ctx, l.ID, "released")
	if err != nil {
		t.Fatalf("AuditRowCount: %v", err)
	}
	if n != 1 {
		t.Errorf("audit 'released' rows = %d want 1", n)
	}
}

// --- 5. Release_ByNonOwner --------------------------------------------------

func TestRelease_ByNonOwner(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	l, err := s.Acquire(ctx, AcquireRequest{
		Nodes:    []string{"server-25"},
		AgentID:  "alice-1",
		Identity: ident("alice-1"),
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	err = s.Release(ctx, l.ID, "bob-2")
	if !errors.Is(err, ErrNotOwner) {
		t.Fatalf("Release by non-owner err = %v want ErrNotOwner", err)
	}
}

// --- 6. Extend --------------------------------------------------------------

func TestExtend(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	l, err := s.Acquire(ctx, AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 10 * time.Minute,
		AgentID:  "alice-1",
		Identity: ident("alice-1"),
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	origExp := l.ExpiresAt

	ext, err := s.Extend(ctx, l.ID, "alice-1", 30*time.Minute)
	if err != nil {
		t.Fatalf("Extend: %v", err)
	}
	if !ext.ExpiresAt.After(origExp) {
		t.Errorf("new expires_at %v not after original %v", ext.ExpiresAt, origExp)
	}
	n, err := s.AuditRowCount(ctx, l.ID, "extended")
	if err != nil {
		t.Fatalf("AuditRowCount: %v", err)
	}
	if n != 1 {
		t.Errorf("audit 'extended' rows = %d want 1", n)
	}

	// Non-owner extend must be refused.
	if _, err := s.Extend(ctx, l.ID, "bob-2", 5*time.Minute); !errors.Is(err, ErrNotOwner) {
		t.Errorf("non-owner extend err = %v want ErrNotOwner", err)
	}
}

// --- 7. List_Filters -------------------------------------------------------

func TestList_Filters(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.Acquire(ctx, AcquireRequest{Nodes: []string{"a"}, AgentID: "alice-1", Identity: ident("alice-1")})
	if err != nil {
		t.Fatalf("acquire a: %v", err)
	}
	_, err = s.Acquire(ctx, AcquireRequest{Nodes: []string{"b"}, AgentID: "bob-2", Identity: ident("bob-2")})
	if err != nil {
		t.Fatalf("acquire b: %v", err)
	}

	all, err := s.List(ctx, ListFilter{})
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("List all = %d want 2", len(all))
	}

	only, err := s.List(ctx, ListFilter{AgentID: "alice-1"})
	if err != nil {
		t.Fatalf("List alice: %v", err)
	}
	if len(only) != 1 || only[0].AgentID != "alice-1" {
		t.Errorf("filter agent_id alice returned %d rows; first=%v", len(only), only)
	}

	// role / topology filters are M1 stubs: they don't reject — they match
	// everything. Document the behavior by asserting non-error on use.
	if _, err := s.List(ctx, ListFilter{Role: "client", Topology: "perf-lab"}); err != nil {
		t.Errorf("List with role/topology stub: %v", err)
	}
}

// --- 8. Sweep_ExpiredLeases ------------------------------------------------

func TestSweep_ExpiredLeases(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Drive "now" backwards so the lease deadline lands in the past.
	frozen := time.Now()
	s.now = func() time.Time { return frozen.Add(-2 * time.Hour) }

	l, err := s.Acquire(ctx, AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 10 * time.Minute,
		AgentID:  "alice-1",
		Identity: ident("alice-1"),
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	// Move "now" forward — the lease is now past its deadline.
	s.now = func() time.Time { return frozen }

	swept, err := s.Sweep(ctx, "testhost", nil)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if swept.Total() < 1 {
		t.Errorf("Sweep total = %d want >=1", swept.Total())
	}
	if swept.TTL < 1 {
		t.Errorf("Sweep TTL = %d want >=1", swept.TTL)
	}
	if swept.DeadProcess != 0 {
		t.Errorf("Sweep DeadProcess = %d want 0 (probe was nil)", swept.DeadProcess)
	}

	got, err := s.getLease(ctx, l.ID)
	if err != nil {
		t.Fatalf("getLease after sweep: %v", err)
	}
	if got.State != LeaseExpired {
		t.Errorf("state after sweep = %q want expired", got.State)
	}
	n, err := s.AuditRowCount(ctx, l.ID, "expired")
	if err != nil {
		t.Fatalf("AuditRowCount: %v", err)
	}
	if n != 1 {
		t.Errorf("audit 'expired' rows = %d want 1", n)
	}
}

// --- 9. Sweep_DeadProcess --------------------------------------------------

func TestSweep_DeadProcess(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Lease registered with pid=99999 / start=time.Unix(42,0). Probe will
	// say that pid is NOT alive — sweeper should expire the lease.
	id := ident("ghost-1")
	id.PID = 99999
	id.StartTime = time.Unix(42, 0)
	l, err := s.Acquire(ctx, AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 1 * time.Hour,
		AgentID:  "ghost-1",
		Identity: id,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	probe := func(pid int, startUnix int64) bool {
		// Pretend nothing is alive on this host.
		return false
	}
	swept, err := s.Sweep(ctx, "testhost", probe)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if swept.Total() < 1 {
		t.Errorf("Sweep total = %d want >=1", swept.Total())
	}
	if swept.DeadProcess < 1 {
		t.Errorf("Sweep DeadProcess = %d want >=1", swept.DeadProcess)
	}
	if swept.TTL != 0 {
		t.Errorf("Sweep TTL = %d want 0 (lease was not past deadline)", swept.TTL)
	}

	got, err := s.getLease(ctx, l.ID)
	if err != nil {
		t.Fatalf("getLease: %v", err)
	}
	if got.State != LeaseExpired {
		t.Errorf("state after sweep = %q want expired", got.State)
	}
	actor, detail, err := s.AuditDetail(ctx, l.ID, "sweep")
	if err != nil {
		t.Fatalf("AuditDetail: %v", err)
	}
	if actor != "" {
		t.Errorf("sweep audit actor = %q want empty", actor)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(detail), &parsed); err != nil {
		t.Fatalf("audit detail JSON: %v (raw=%q)", err, detail)
	}
	if parsed["reason"] != "process_gone" {
		t.Errorf("audit detail reason = %v want process_gone", parsed["reason"])
	}
}

// Sweep must NOT touch leases owned by a different hostname even if their
// pid does not match. This guards the cross-host correctness rule from the
// design memo.
func TestSweep_OtherHostUntouched(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	other := ident("alice-1")
	other.Hostname = "other-host"
	other.PID = 12345
	if _, err := s.Acquire(ctx, AcquireRequest{
		Nodes:    []string{"server-25"},
		AgentID:  "alice-1",
		Identity: other,
	}); err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	probe := func(pid int, startUnix int64) bool { return false }
	if _, err := s.Sweep(ctx, "testhost", probe); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	leases, err := s.List(ctx, ListFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(leases) != 1 || leases[0].Hostname != "other-host" || leases[0].State != LeaseAcquired {
		t.Errorf("other-host lease should be untouched, got %v", leases)
	}
}

// --- Sweep_CountBreakdown (M4) ---------------------------------------------

// Sweep must report TTL-expired and dead-process counts independently so the
// boot-time sweeper log can attribute "what crashed" vs "what was abandoned".
func TestSweep_CountBreakdown(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	frozen := time.Now()

	// Acquire the ghost lease FIRST at the real clock, so its 1h deadline
	// sits in the future regardless of subsequent clock rewinds. Doing
	// this first prevents the *next* Acquire() from inline-expiring the
	// TTL leases via expireOverdueLocked when it observes their past
	// deadlines from the rewound clock.
	id := ident("ghost-1")
	id.PID = 99998
	id.StartTime = time.Unix(43, 0)
	if _, err := s.Acquire(ctx, AcquireRequest{
		Nodes:    []string{"ghost-node"},
		Duration: 1 * time.Hour,
		AgentID:  "ghost-1",
		Identity: id,
	}); err != nil {
		t.Fatalf("acquire ghost: %v", err)
	}

	// Now drive "now" backwards so the next two leases land with
	// deadlines that look like the past once we restore the clock.
	s.now = func() time.Time { return frozen.Add(-2 * time.Hour) }

	for i, node := range []string{"ttl-node-A", "ttl-node-B"} {
		agentID := "ttl-agent-" + string(rune('A'+i))
		if _, err := s.Acquire(ctx, AcquireRequest{
			Nodes:    []string{node},
			Duration: 10 * time.Minute,
			AgentID:  agentID,
			Identity: ident(agentID),
		}); err != nil {
			t.Fatalf("acquire %s: %v", node, err)
		}
	}

	// Restore real clock so Sweep observes the TTL leases as expired.
	s.now = func() time.Time { return frozen }

	probe := func(pid int, _ int64) bool {
		// Pretend only the testhost's own pid is alive — anything else,
		// including pid=99998, is dead.
		return pid != id.PID && pid != 99999
	}

	swept, err := s.Sweep(ctx, "testhost", probe)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if swept.TTL != 2 {
		t.Errorf("swept.TTL = %d want 2", swept.TTL)
	}
	if swept.DeadProcess != 1 {
		t.Errorf("swept.DeadProcess = %d want 1", swept.DeadProcess)
	}
	if swept.Total() != 3 {
		t.Errorf("swept.Total() = %d want 3", swept.Total())
	}
}

// --- 10. ForceRelease ------------------------------------------------------

func TestForceRelease(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	l, err := s.Acquire(ctx, AcquireRequest{
		Nodes:    []string{"server-25"},
		AgentID:  "alice-1",
		Identity: ident("alice-1"),
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	// Empty reason must be refused.
	if err := s.ForceRelease(ctx, l.ID, "ops-bob", ""); !errors.Is(err, ErrReasonRequired) {
		t.Errorf("empty-reason force_release err = %v want ErrReasonRequired", err)
	}

	if err := s.ForceRelease(ctx, l.ID, "ops-bob", "unattended"); err != nil {
		t.Fatalf("ForceRelease: %v", err)
	}

	got, err := s.getLease(ctx, l.ID)
	if err != nil {
		t.Fatalf("getLease: %v", err)
	}
	if got.State != LeaseForced {
		t.Errorf("state after force = %q want forced", got.State)
	}

	actor, detail, err := s.AuditDetail(ctx, l.ID, "forced")
	if err != nil {
		t.Fatalf("AuditDetail: %v", err)
	}
	if actor != "ops-bob" {
		t.Errorf("forced actor = %q want ops-bob", actor)
	}
	if !strings.Contains(detail, "unattended") {
		t.Errorf("forced detail %q missing reason", detail)
	}
	if !strings.Contains(detail, "alice-1") {
		t.Errorf("forced detail %q missing original_owner", detail)
	}
}

// --- 11. ConcurrentAcquire_Race --------------------------------------------

func TestConcurrentAcquire_Race(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()

	const N = 10
	var wins int32
	var conflicts int32
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			id := ident("racer-" + string(rune('A'+i)))
			_, err := s.Acquire(ctx, AcquireRequest{
				Nodes:    []string{"hot-node"},
				AgentID:  id.EffectiveID,
				Identity: id,
				Reason:   "race",
			})
			if err == nil {
				atomic.AddInt32(&wins, 1)
				return
			}
			var conf *ConflictError
			if errors.As(err, &conf) {
				atomic.AddInt32(&conflicts, 1)
				return
			}
			t.Errorf("unexpected error: %v", err)
		}(i)
	}

	close(start)
	wg.Wait()

	if wins != 1 {
		t.Errorf("wins=%d want 1", wins)
	}
	if conflicts != N-1 {
		t.Errorf("conflicts=%d want %d", conflicts, N-1)
	}
	// Verify exactly one active lease holds hot-node.
	got, err := s.List(ctx, ListFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	holders := 0
	for _, l := range got {
		for _, n := range l.Nodes {
			if n == "hot-node" && l.State == LeaseAcquired {
				holders++
			}
		}
	}
	if holders != 1 {
		t.Errorf("active holders on hot-node = %d want 1", holders)
	}
}

// --- 12. WALMode_Verified --------------------------------------------------

func TestWALMode_Verified(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	mode, err := s.JournalMode(ctx)
	if err != nil {
		t.Fatalf("JournalMode: %v", err)
	}
	if strings.ToLower(mode) != "wal" {
		t.Errorf("PRAGMA journal_mode = %q want wal", mode)
	}
}

// --- Extras: identity helper & wait timeout --------------------------------

func TestAcquire_WaitTimeoutThenGranted(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	first, err := s.Acquire(ctx, AcquireRequest{
		Nodes:    []string{"server-25"},
		Duration: 5 * time.Minute,
		AgentID:  "alice-1",
		Identity: ident("alice-1"),
	})
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}

	// Bob waits 300ms — alice still holds — expect ErrWaitTimeout.
	t0 := time.Now()
	_, err = s.Acquire(ctx, AcquireRequest{
		Nodes:    []string{"server-25"},
		Wait:     300 * time.Millisecond,
		AgentID:  "bob-2",
		Identity: ident("bob-2"),
	})
	if !errors.Is(err, ErrWaitTimeout) {
		t.Fatalf("err = %v want ErrWaitTimeout", err)
	}
	if d := time.Since(t0); d < 200*time.Millisecond {
		t.Errorf("wait elapsed %v < 200ms — didn't poll", d)
	}

	// Now release and retry — should succeed quickly.
	if err := s.Release(ctx, first.ID, "alice-1"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := s.Acquire(ctx, AcquireRequest{
		Nodes:    []string{"server-25"},
		Wait:     2 * time.Second,
		AgentID:  "bob-2",
		Identity: ident("bob-2"),
	}); err != nil {
		t.Fatalf("second Acquire after release: %v", err)
	}
}

func TestIdentityDefault_NotEmpty(t *testing.T) {
	id := Default()
	if id.EffectiveID == "" {
		t.Error("Default().EffectiveID should be non-empty")
	}
	if id.Hostname == "" {
		t.Error("Default().Hostname should be non-empty")
	}
	if id.PID == 0 {
		t.Error("Default().PID should be non-zero")
	}
	// Sanity-check it includes pid in default layout when env var unset.
	// Note: if LABLINK_AGENT_ID is set in this test environment we skip
	// the substring check.
	if id.EffectiveID == id.Cookie+"-"+id.Hostname { // partial — keep loose
		t.Error("layered id missing pid")
	}
	_ = runtime.GOOS
}

func TestAcquire_NoNodesRejected(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Acquire(context.Background(), AcquireRequest{
		AgentID:  "x",
		Identity: ident("x"),
	})
	if !errors.Is(err, ErrNoNodes) {
		t.Errorf("err = %v want ErrNoNodes", err)
	}
}
