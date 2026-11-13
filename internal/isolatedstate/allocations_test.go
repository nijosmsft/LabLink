package isolatedstate

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentAllocationRaceAcrossStoreHandles(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "isolated.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	requests := []ActiveResourceAllocation{
		{
			Kind: "relay_port", ScopeID: "ORCH", Value: "20000",
			ResourceID: "relay-a", ApplianceReservationID: "reservation-a",
			AllocatedAt: 10,
		},
		{
			Kind: "relay_port", ScopeID: "orch", Value: "20000",
			ResourceID: "relay-b", ApplianceReservationID: "reservation-b",
			AllocatedAt: 10,
		},
	}
	stores := []*Store{first, second}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for index := range stores {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			errs <- stores[index].CommitAllocations(ctx, []ActiveResourceAllocation{requests[index]})
		}(index)
	}
	close(start)
	wait.Wait()
	close(errs)

	var success, conflicts int
	for err := range errs {
		if err == nil {
			success++
			continue
		}
		var conflict *AllocationConflictError
		if errors.As(err, &conflict) {
			conflicts++
			continue
		}
		t.Fatalf("unexpected allocation result: %v", err)
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("success=%d conflicts=%d, want 1 and 1", success, conflicts)
	}
	var active int
	if err := first.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM active_resource_allocations`,
	).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("active allocations=%d, want 1", active)
	}
}

func TestAllocationReleasePreservesHistoryAndAllowsReuse(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	first := ActiveResourceAllocation{
		Kind: "guest_ip", ScopeID: "network-a", Value: "10.0.0.2",
		ResourceID: "vm-a", ApplianceReservationID: "reservation-a",
		AllocatedAt: 10,
	}
	if err := store.CommitAllocations(ctx, []ActiveResourceAllocation{first}); err != nil {
		t.Fatal(err)
	}
	history, err := store.ReleaseAllocation(ctx, ReleaseAllocationRequest{
		Kind: "guest_ip", ScopeID: "network-a", Value: "10.0.0.2",
		ResourceID: "vm-a", ReleaseOperationID: "delete-a", ReleasedAt: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if history.Sequence == 0 || history.ResourceID != "vm-a" {
		t.Fatalf("unexpected history: %+v", history)
	}
	replayed, err := store.ReleaseAllocation(ctx, ReleaseAllocationRequest{
		Kind: "guest_ip", ScopeID: "network-a", Value: "10.0.0.2",
		ResourceID: "vm-a", ReleaseOperationID: "delete-a", ReleasedAt: 25,
	})
	if err != nil {
		t.Fatalf("release replay: %v", err)
	}
	if replayed.Sequence != history.Sequence || replayed.ReleasedAt != history.ReleasedAt {
		t.Fatalf("release replay changed history: original=%+v replay=%+v", history, replayed)
	}
	second := ActiveResourceAllocation{
		Kind: "guest_ip", ScopeID: "network-a", Value: "10.0.0.2",
		ResourceID: "vm-b", ApplianceReservationID: "reservation-b",
		AllocatedAt: 30,
	}
	if err := store.CommitAllocations(ctx, []ActiveResourceAllocation{second}); err != nil {
		t.Fatalf("reuse after tombstone: %v", err)
	}
	active, err := store.GetActiveAllocation(ctx, "guest_ip", "network-a", "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if active.ResourceID != "vm-b" {
		t.Fatalf("active resource=%q, want vm-b", active.ResourceID)
	}
	var historyCount int
	if err := store.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM resource_allocation_history`,
	).Scan(&historyCount); err != nil {
		t.Fatal(err)
	}
	if historyCount != 1 {
		t.Fatalf("history count=%d, want 1", historyCount)
	}
}

func TestAllocationBatchIsAtomic(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.CommitAllocations(ctx, []ActiveResourceAllocation{{
		Kind: "guest_ip", ScopeID: "network-a", Value: "10.0.0.2",
		ResourceID: "vm-existing", ApplianceReservationID: "reservation-existing",
		AllocatedAt: 1,
	}}); err != nil {
		t.Fatal(err)
	}
	err = store.CommitAllocations(ctx, []ActiveResourceAllocation{
		{
			Kind: "guest_mac", ScopeID: "orch", Value: "00155d000001",
			ResourceID: "vm-new", ApplianceReservationID: "reservation-new",
			AllocatedAt: 2,
		},
		{
			Kind: "guest_ip", ScopeID: "network-a", Value: "10.0.0.2",
			ResourceID: "vm-new", ApplianceReservationID: "reservation-new",
			AllocatedAt: 2,
		},
	})
	var conflict *AllocationConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error=%v, want allocation conflict", err)
	}
	var count int
	if err := store.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM active_resource_allocations
		WHERE resource_id='vm-new'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("partial batch rows=%d, want 0", count)
	}
}
