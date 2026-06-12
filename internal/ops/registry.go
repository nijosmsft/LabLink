// Package ops tracks long-running MCP tool invocations so a local portal can
// list and cancel them. It is intentionally process-local: each LabLinkServer
// process keeps its own registry.
package ops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

// Status of an Operation.
type Status string

const (
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// Operation is a single in-flight or recently-completed tool invocation.
type Operation struct {
	ID         string            `json:"id"`
	Tool       string            `json:"tool"`
	Node       string            `json:"node,omitempty"`
	Summary    string            `json:"summary,omitempty"`
	Args       map[string]string `json:"args,omitempty"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt *time.Time        `json:"finished_at,omitempty"`
	Status     Status            `json:"status"`
	Error      string            `json:"error,omitempty"`

	// Progress is an optional periodic liveness signal published by
	// long-running streaming tools (push_file, pull_file, …). BytesTotal
	// may be 0 when the total is not yet known. ProgressAt is the most
	// recent update time. Updated via Handle.Progress.
	BytesDone  int64      `json:"bytes_done,omitempty"`
	BytesTotal int64      `json:"bytes_total,omitempty"`
	ProgressAt *time.Time `json:"progress_at,omitempty"`

	cancel            context.CancelFunc
	cancelledByPortal bool
}

// Event is a change notification published over the bus.
type Event struct {
	Kind string     `json:"kind"` // "started" | "progress" | "finished"
	Op   *Operation `json:"op"`
}

// Registry tracks operations and fans out change events to subscribers.
type Registry struct {
	mu          sync.Mutex
	ops         map[string]*Operation
	subscribers map[chan Event]struct{}
	maxHistory  int
	finished    []*Operation
	now         func() time.Time
}

// NewRegistry constructs a Registry. maxHistory is the number of completed
// operations retained for display; 0 means unlimited.
func NewRegistry(maxHistory int) *Registry {
	if maxHistory < 0 {
		maxHistory = 0
	}
	return &Registry{
		ops:         make(map[string]*Operation),
		subscribers: make(map[chan Event]struct{}),
		maxHistory:  maxHistory,
		now:         time.Now,
	}
}

// Begin records a new operation and returns a wrapped context whose
// cancellation can be triggered either by the caller or by the portal
// (Cancel by ID). Done must be called on the returned Handle when the work
// completes.
func (r *Registry) Begin(parent context.Context, tool, node, summary string, args map[string]string) (context.Context, *Handle) {
	if r == nil {
		ctx, cancel := context.WithCancel(parent)
		return ctx, &Handle{noop: true, cancel: cancel}
	}
	id, _ := newID()
	ctx, cancel := context.WithCancel(parent)
	op := &Operation{
		ID:        id,
		Tool:      tool,
		Node:      node,
		Summary:   summary,
		Args:      Redact(args),
		StartedAt: r.now(),
		Status:    StatusRunning,
		cancel:    cancel,
	}
	r.mu.Lock()
	r.ops[id] = op
	r.mu.Unlock()
	r.publish(Event{Kind: "started", Op: opSnapshot(op)})
	return ctx, &Handle{reg: r, id: id, cancel: cancel}
}

// Cancel marks the operation as cancelled-by-portal and triggers its context
// cancel. Returns false if the id is unknown or already finished.
func (r *Registry) Cancel(id string) bool {
	r.mu.Lock()
	op, ok := r.ops[id]
	if !ok || op.Status != StatusRunning {
		r.mu.Unlock()
		return false
	}
	op.cancelledByPortal = true
	cancel := op.cancel
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return true
}

// List returns a snapshot of all operations (running first, most-recent
// finished after).
func (r *Registry) List() []*Operation {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Operation, 0, len(r.ops)+len(r.finished))
	for _, op := range r.ops {
		out = append(out, opSnapshot(op))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	for i := len(r.finished) - 1; i >= 0; i-- {
		out = append(out, opSnapshot(r.finished[i]))
	}
	return out
}

// Subscribe returns a channel of events. Caller must call the returned cancel
// when done. Buffered to avoid blocking publishers on slow consumers; events
// are dropped when the buffer is full.
func (r *Registry) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 32)
	r.mu.Lock()
	r.subscribers[ch] = struct{}{}
	r.mu.Unlock()
	cancel := func() {
		r.mu.Lock()
		if _, ok := r.subscribers[ch]; ok {
			delete(r.subscribers, ch)
			close(ch)
		}
		r.mu.Unlock()
	}
	return ch, cancel
}

func (r *Registry) publish(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for ch := range r.subscribers {
		select {
		case ch <- e:
		default:
			// drop
		}
	}
}

func (r *Registry) finish(id string, err error) {
	r.mu.Lock()
	op, ok := r.ops[id]
	if !ok || op.Status != StatusRunning {
		r.mu.Unlock()
		return
	}
	switch {
	case op.cancelledByPortal:
		op.Status = StatusCancelled
		if err != nil {
			op.Error = err.Error()
		}
	case err == nil:
		op.Status = StatusSucceeded
	default:
		op.Status = StatusFailed
		op.Error = err.Error()
	}
	t := r.now()
	op.FinishedAt = &t
	delete(r.ops, id)
	op.cancel = nil
	r.finished = append(r.finished, op)
	if r.maxHistory > 0 && len(r.finished) > r.maxHistory {
		r.finished = r.finished[len(r.finished)-r.maxHistory:]
	}
	snap := opSnapshot(op)
	r.mu.Unlock()
	r.publish(Event{Kind: "finished", Op: snap})
}

// progress records a periodic liveness/progress update for a running op and
// publishes a "progress" event so subscribers (portal SSE) see it. No-op when
// the operation is unknown or already finished.
func (r *Registry) progress(id string, bytesDone, bytesTotal int64) {
	r.mu.Lock()
	op, ok := r.ops[id]
	if !ok || op.Status != StatusRunning {
		r.mu.Unlock()
		return
	}
	op.BytesDone = bytesDone
	if bytesTotal > 0 {
		op.BytesTotal = bytesTotal
	}
	t := r.now()
	op.ProgressAt = &t
	snap := opSnapshot(op)
	r.mu.Unlock()
	r.publish(Event{Kind: "progress", Op: snap})
}

// Handle is returned by Begin and used by the caller to mark completion.
type Handle struct {
	reg    *Registry
	id     string
	cancel context.CancelFunc
	noop   bool
}

// ID returns the operation id.
func (h *Handle) ID() string {
	if h == nil {
		return ""
	}
	return h.id
}

// Done records terminal status. err==nil → succeeded; err set and the op was
// portal-cancelled → cancelled; otherwise → failed. The wrapped context is
// also cancelled to release any descendant work.
func (h *Handle) Done(err error) {
	if h == nil {
		return
	}
	if h.noop {
		if h.cancel != nil {
			h.cancel()
		}
		return
	}
	h.reg.finish(h.id, err)
	if h.cancel != nil {
		h.cancel()
	}
}

// Progress publishes a liveness/progress update for the operation. It is a
// no-op on a nil or noop handle, and on a finished operation. bytesTotal may
// be 0 when the total size is unknown. Intended for long-running streaming
// tools (push_file, pull_file, …) so MCP clients that honor "tool is alive"
// signals don't kill the call mid-transfer.
func (h *Handle) Progress(bytesDone, bytesTotal int64) {
	if h == nil || h.noop || h.reg == nil {
		return
	}
	h.reg.progress(h.id, bytesDone, bytesTotal)
}

func opSnapshot(op *Operation) *Operation {
	cp := *op
	cp.cancel = nil
	cp.cancelledByPortal = false
	if op.Args != nil {
		cp.Args = make(map[string]string, len(op.Args))
		for k, v := range op.Args {
			cp.Args[k] = v
		}
	}
	if op.FinishedAt != nil {
		t := *op.FinishedAt
		cp.FinishedAt = &t
	}
	if op.ProgressAt != nil {
		t := *op.ProgressAt
		cp.ProgressAt = &t
	}
	return &cp
}

func newID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
