package isolatedstate

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

func TestLockContentionRenewalAndTwoStoreHandles(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "isolated.db")
	firstStore, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer firstStore.Close()
	secondStore, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer secondStore.Close()
	clock := &testClock{now: time.Unix(100, 0)}
	first := newTestLockManager(t, firstStore, clock, ProcessIdentity{
		Hostname: "devbox", PID: 1001, ProcessStart: 10, Cookie: "cookie-a",
	}, nil)
	second := newTestLockManager(t, secondStore, clock, ProcessIdentity{
		Hostname: "devbox", PID: 1002, ProcessStart: 20, Cookie: "cookie-b",
	}, func(context.Context, ProcessIdentity) (bool, bool, error) {
		return true, true, nil
	})
	key, _ := OrchestratorLockKey("ORCH")
	lease, err := first.Acquire(ctx, LockAcquireRequest{
		Key: key, OperationID: "op-a", TTL: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = second.Acquire(ctx, LockAcquireRequest{
		Key: key, OperationID: "op-b", TTL: 30 * time.Second,
	})
	var contention *LockContentionError
	if !errors.As(err, &contention) || contention.Fence != lease.Fence {
		t.Fatalf("error=%v, want contention at fence %d", err, lease.Fence)
	}
	clock.Advance(10 * time.Second)
	renewed, err := first.Renew(ctx, lease, 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.HeartbeatAt != 110 || renewed.ExpiresAt != 170 {
		t.Fatalf("unexpected renewed lease: %+v", renewed)
	}
}

func TestDeadProcessLockReclamationAndFencingMonotonicity(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "isolated.db")
	firstStore, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer firstStore.Close()
	secondStore, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer secondStore.Close()
	clock := &testClock{now: time.Unix(100, 0)}
	first := newTestLockManager(t, firstStore, clock, ProcessIdentity{
		Hostname: "devbox", PID: 2001, ProcessStart: 10, Cookie: "cookie-a",
	}, nil)
	second := newTestLockManager(t, secondStore, clock, ProcessIdentity{
		Hostname: "devbox", PID: 2002, ProcessStart: 20, Cookie: "cookie-b",
	}, func(_ context.Context, identity ProcessIdentity) (bool, bool, error) {
		if identity.PID == 2001 {
			return false, true, nil
		}
		return true, true, nil
	})
	key, _ := NetworkLockKey("network-1")
	oldLease, err := first.Acquire(ctx, LockAcquireRequest{
		Key: key, OperationID: "op-a", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	newLease, err := second.Acquire(ctx, LockAcquireRequest{
		Key: key, OperationID: "op-b", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("reclaim dead process: %v", err)
	}
	if newLease.Fence <= oldLease.Fence {
		t.Fatalf("new fence=%d, old=%d", newLease.Fence, oldLease.Fence)
	}
	if err := first.Release(ctx, oldLease); err == nil {
		t.Fatal("stale holder released reclaimed lock")
	} else {
		var stale *StaleFenceError
		if !errors.As(err, &stale) || stale.CurrentFence != newLease.Fence {
			t.Fatalf("error=%v, want stale fence diagnostic", err)
		}
	}
	if err := second.Release(ctx, newLease); err != nil {
		t.Fatal(err)
	}
	third := newTestLockManager(t, firstStore, clock, ProcessIdentity{
		Hostname: "devbox", PID: 2003, ProcessStart: 30, Cookie: "cookie-c",
	}, nil)
	thirdLease, err := third.Acquire(ctx, LockAcquireRequest{
		Key: key, OperationID: "op-c", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if thirdLease.Fence <= newLease.Fence {
		t.Fatalf("fence after release=%d, want > %d", thirdLease.Fence, newLease.Fence)
	}
}

func TestExpiredLockCanBeReclaimedAcrossHostnames(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "isolated.db")
	firstStore, _ := Open(path)
	defer firstStore.Close()
	secondStore, _ := Open(path)
	defer secondStore.Close()
	clock := &testClock{now: time.Unix(100, 0)}
	first := newTestLockManager(t, firstStore, clock, ProcessIdentity{
		Hostname: "devbox-a", PID: 3001, ProcessStart: 10, Cookie: "cookie-a",
	}, nil)
	second := newTestLockManager(t, secondStore, clock, ProcessIdentity{
		Hostname: "devbox-b", PID: 3002, ProcessStart: 20, Cookie: "cookie-b",
	}, nil)
	key, _ := AllocationLockKey("orch")
	oldLease, err := first.Acquire(ctx, LockAcquireRequest{
		Key: key, OperationID: "op-a", TTL: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(6 * time.Second)
	newLease, err := second.Acquire(ctx, LockAcquireRequest{
		Key: key, OperationID: "op-b", TTL: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if newLease.Fence <= oldLease.Fence {
		t.Fatalf("new fence=%d, old=%d", newLease.Fence, oldLease.Fence)
	}
}

func TestUnprovenLocalProcessDeathKeepsExpiredLock(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "isolated.db")
	firstStore, _ := Open(path)
	defer firstStore.Close()
	secondStore, _ := Open(path)
	defer secondStore.Close()
	clock := &testClock{now: time.Unix(100, 0)}
	first := newTestLockManager(t, firstStore, clock, ProcessIdentity{
		Hostname: "devbox", PID: 3501, ProcessStart: 10, Cookie: "cookie-a",
	}, nil)
	second := newTestLockManager(t, secondStore, clock, ProcessIdentity{
		Hostname: "devbox", PID: 3502, ProcessStart: 20, Cookie: "cookie-b",
	}, func(context.Context, ProcessIdentity) (bool, bool, error) {
		return false, false, errors.New("access denied")
	})
	key, _ := AllocationLockKey("orch")
	if _, err := first.Acquire(ctx, LockAcquireRequest{
		Key: key, OperationID: "op-a", TTL: 5 * time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(6 * time.Second)
	_, err := second.Reclaim(ctx, LockAcquireRequest{
		Key: key, OperationID: "op-b", TTL: 5 * time.Second,
	})
	var contention *LockContentionError
	if !errors.As(err, &contention) {
		t.Fatalf("error=%v, want conservative lock contention", err)
	}
}

func TestStartupSweepReclaimsOnlySafelyStaleLocks(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "isolated.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	clock := &testClock{now: time.Unix(100, 0)}
	dead := newTestLockManager(t, store, clock, ProcessIdentity{
		Hostname: "devbox", PID: 3601, ProcessStart: 10, Cookie: "dead",
	}, nil)
	remoteExpired := newTestLockManager(t, store, clock, ProcessIdentity{
		Hostname: "other-host", PID: 3602, ProcessStart: 20, Cookie: "remote",
	}, nil)
	unproven := newTestLockManager(t, store, clock, ProcessIdentity{
		Hostname: "devbox", PID: 3603, ProcessStart: 30, Cookie: "unproven",
	}, nil)
	live := newTestLockManager(t, store, clock, ProcessIdentity{
		Hostname: "devbox", PID: 3604, ProcessStart: 40, Cookie: "live",
	}, nil)
	deadKey, _ := NetworkLockKey("dead")
	remoteKey, _ := AllocationLockKey("remote")
	unprovenKey, _ := VMLockKey("unproven")
	liveKey, _ := RelayLockKey("live")
	if _, err := dead.Acquire(ctx, LockAcquireRequest{Key: deadKey, OperationID: "op-dead", TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err := remoteExpired.Acquire(ctx, LockAcquireRequest{Key: remoteKey, OperationID: "op-remote", TTL: time.Second}); err != nil {
		t.Fatal(err)
	}
	if _, err := unproven.Acquire(ctx, LockAcquireRequest{Key: unprovenKey, OperationID: "op-unproven", TTL: time.Second}); err != nil {
		t.Fatal(err)
	}
	if _, err := live.Acquire(ctx, LockAcquireRequest{Key: liveKey, OperationID: "op-live", TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Second)
	sweeper := newTestLockManager(t, store, clock, ProcessIdentity{
		Hostname: "devbox", PID: 3699, ProcessStart: 99, Cookie: "sweeper",
	}, func(_ context.Context, identity ProcessIdentity) (bool, bool, error) {
		switch identity.PID {
		case 3601:
			return false, true, nil
		case 3603:
			return false, false, errors.New("access denied")
		default:
			return true, true, nil
		}
	})
	result, err := sweeper.SweepStale(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.DeadProcess != 1 || result.Expired != 1 {
		t.Fatalf("sweep result = %+v", result)
	}
	remoteLease, err := sweeper.Acquire(ctx, LockAcquireRequest{Key: remoteKey, OperationID: "op-new-remote", TTL: time.Minute})
	if err != nil {
		t.Fatalf("expired remote lock remained: %v", err)
	}
	if err := sweeper.Release(ctx, remoteLease); err != nil {
		t.Fatal(err)
	}
	deadLease, err := sweeper.Acquire(ctx, LockAcquireRequest{Key: deadKey, OperationID: "op-new-dead", TTL: time.Minute})
	if err != nil {
		t.Fatalf("dead-process lock remained: %v", err)
	}
	if err := sweeper.Release(ctx, deadLease); err != nil {
		t.Fatal(err)
	}
	if _, err := sweeper.Acquire(ctx, LockAcquireRequest{Key: unprovenKey, OperationID: "op-new-unproven", TTL: time.Minute}); err == nil {
		t.Fatal("unproven local lock was swept")
	}
	if _, err := sweeper.Acquire(ctx, LockAcquireRequest{Key: liveKey, OperationID: "op-new-live", TTL: time.Minute}); err == nil {
		t.Fatal("live local lock was swept")
	}
}

func TestLockOrderViolation(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	clock := &testClock{now: time.Unix(100, 0)}
	manager := newTestLockManager(t, store, clock, ProcessIdentity{
		Hostname: "devbox", PID: 4001, ProcessStart: 10, Cookie: "cookie-a",
	}, nil)
	vmKey, _ := VMLockKey("vm-1")
	if _, err := manager.Acquire(ctx, LockAcquireRequest{
		Key: vmKey, OperationID: "op", TTL: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	networkKey, _ := NetworkLockKey("network-1")
	_, err = manager.Acquire(ctx, LockAcquireRequest{
		Key: networkKey, OperationID: "op", TTL: time.Minute,
	})
	if !errors.Is(err, ErrLockOrderViolation) {
		t.Fatalf("error=%v, want lock order violation", err)
	}
}

func TestProcessIdentityUsesOnePerProcessCookie(t *testing.T) {
	first, err := NewProcessIdentity()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewProcessIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(first.Cookie) != 64 {
		t.Fatalf("process identities differ or cookie is weak: first=%+v second=%+v", first, second)
	}
}

func newTestLockManager(
	t *testing.T,
	store *Store,
	clock *testClock,
	identity ProcessIdentity,
	liveness ProcessLivenessFunc,
) *LockManager {
	t.Helper()
	manager, err := NewLockManager(store, LockManagerOptions{
		Identity: identity, Now: clock.Now, Liveness: liveness,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}
