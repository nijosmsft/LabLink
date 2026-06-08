// Package leasing implements a SQLite-backed lease store that coordinates
// access to lab nodes across multiple lablink-server.exe processes running
// on the same dev box.
//
// The design memo is manager-log/lablink-leasing-design.md (frozen). This
// package implements Milestone 1 — the store layer only. MCP tool wiring,
// existing-tool gating, and the server-boot sweeper land in M2/M3/M4.
package leasing

import (
	"fmt"
	"strings"
	"time"
)

// LeaseState is the lifecycle state of a Lease row.
type LeaseState string

const (
	// LeaseAcquired means the lease currently holds its nodes.
	LeaseAcquired LeaseState = "acquired"
	// LeaseReleased means the owning agent voluntarily dropped the lease.
	LeaseReleased LeaseState = "released"
	// LeaseExpired means the TTL deadline passed (or the owning process
	// went away and the sweeper noticed).
	LeaseExpired LeaseState = "expired"
	// LeaseForced means an admin called ForceRelease.
	LeaseForced LeaseState = "forced"
)

// DefaultDuration is the default TTL applied when AcquireRequest.Duration is
// zero. Mirrors design memo OQ2.
const DefaultDuration = 60 * time.Minute

// Lease is one row in the leases table joined with its leased nodes.
type Lease struct {
	ID         string
	AgentID    string
	Cookie     string
	Hostname   string
	PID        int
	StartTime  time.Time
	Nodes      []string
	Reason     string
	AcquiredAt time.Time
	ExpiresAt  time.Time
	ReleasedAt time.Time
	State      LeaseState
}

// IsActive reports whether the lease is currently holding its nodes.
func (l *Lease) IsActive(now time.Time) bool {
	return l != nil && l.State == LeaseAcquired && l.ExpiresAt.After(now)
}

// AcquireRequest is the input to Store.Acquire.
type AcquireRequest struct {
	Nodes    []string
	Duration time.Duration
	Wait     time.Duration
	AgentID  string
	Reason   string
	// Identity carries the layered identity components (cookie, hostname,
	// pid, process start time) for this agent. Set by the server at boot.
	// If empty, Acquire falls back to Default() at call time.
	Identity Identity
}

// ListFilter narrows a Store.List query.
type ListFilter struct {
	AgentID        string
	Role           string
	Topology       string
	IncludeExpired bool
	Limit          int
}

// ConflictError is returned by Store.Acquire when one or more requested
// nodes are held by another active lease. Holders maps node name to the
// active holder lease.
type ConflictError struct {
	Holders map[string]*Lease
}

func (e *ConflictError) Error() string {
	if e == nil || len(e.Holders) == 0 {
		return "lease conflict"
	}
	parts := make([]string, 0, len(e.Holders))
	for node, h := range e.Holders {
		if h == nil {
			parts = append(parts, node)
			continue
		}
		parts = append(parts, fmt.Sprintf("%s held by %s until %s (reason %q)",
			node, h.AgentID, h.ExpiresAt.UTC().Format(time.RFC3339), h.Reason))
	}
	return "lease conflict: " + strings.Join(parts, "; ")
}

// HeldNodes returns the held node names in no particular order.
func (e *ConflictError) HeldNodes() []string {
	if e == nil {
		return nil
	}
	out := make([]string, 0, len(e.Holders))
	for n := range e.Holders {
		out = append(out, n)
	}
	return out
}

// ErrNotOwner is returned by Release/Extend when the caller's agent_id does
// not match the lease's owner.
var ErrNotOwner = &leaseError{code: "NotOwner", msg: "lease is not owned by this agent"}

// ErrLeaseNotFound is returned when the lease_id does not exist.
var ErrLeaseNotFound = &leaseError{code: "LeaseNotFound", msg: "lease not found"}

// ErrLeaseExpired is returned by Extend when the lease is no longer active.
var ErrLeaseExpired = &leaseError{code: "LeaseExpired", msg: "lease has expired"}

// ErrWaitTimeout is returned by Acquire when wait_seconds elapses without
// the contested nodes becoming free.
var ErrWaitTimeout = &leaseError{code: "WaitTimeout", msg: "wait_seconds elapsed before nodes became free"}

// ErrNoNodes is returned when AcquireRequest.Nodes is empty.
var ErrNoNodes = &leaseError{code: "NoNodes", msg: "no nodes specified for lease"}

// ErrReasonRequired is returned when ForceRelease is called with no reason.
var ErrReasonRequired = &leaseError{code: "ReasonRequired", msg: "force_release requires a non-empty reason"}

type leaseError struct {
	code string
	msg  string
}

func (e *leaseError) Error() string { return e.msg }

// Code returns the short error tag for programmatic dispatch.
func (e *leaseError) Code() string { return e.code }
