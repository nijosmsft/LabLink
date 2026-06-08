package leasing

import (
	"context"
	"time"
)

// Store is the abstract lease backend. M1 ships SQLiteStore as the only
// implementation. The interface is shaped to allow a network-backed v2
// (etcd / sql.DB) drop-in.
type Store interface {
	// Acquire grants a lease over the requested node set atomically.
	// On conflict, returns *ConflictError unless req.Wait > 0 in which
	// case the call polls and may eventually return ErrWaitTimeout.
	// Multi-node acquire is all-or-nothing per memo OQ7.
	Acquire(ctx context.Context, req AcquireRequest) (*Lease, error)

	// Release marks the lease state=released, owner-only. Returns
	// ErrNotOwner if agentID does not match, ErrLeaseNotFound if the
	// id does not exist.
	Release(ctx context.Context, leaseID, agentID string) error

	// Extend bumps the TTL on an active lease, owner-only. Returns the
	// updated Lease. Returns ErrLeaseExpired if the lease is no longer
	// active.
	Extend(ctx context.Context, leaseID, agentID string, add time.Duration) (*Lease, error)

	// List returns currently-tracked leases filtered by ListFilter. By
	// default only active leases are returned; set IncludeExpired to
	// surface tombstoned rows too.
	List(ctx context.Context, filter ListFilter) ([]*Lease, error)

	// ForceRelease marks a lease state=forced regardless of ownership.
	// Audit row records forcedBy + reason. Reason MUST be non-empty.
	// M1 does NOT gate this behind an env var (per the manager — that
	// guardrail lives at the MCP tool surface in M4 via destructiveHint).
	ForceRelease(ctx context.Context, leaseID, forcedBy, reason string) error

	// Sweep performs startup crash recovery on leases owned by this host.
	// For every active lease whose (pid, process_start_time) no longer
	// corresponds to a live process per the supplied probe, mark expired
	// with audit reason process_gone. Also lazily expires leases past
	// their TTL deadline. Returns a per-category breakdown of leases
	// transitioned (see SweepResult).
	//
	// liveProcess(pid, startUnix) -> true if a process with that identity
	// is still running on the local host. Pass nil to skip the dead-
	// process check (useful in tests).
	Sweep(ctx context.Context, hostname string, liveProcess func(pid int, startUnix int64) bool) (SweepResult, error)

	// Close releases resources (db handle, etc).
	Close() error
}
