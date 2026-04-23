package ops

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBeginAndDoneSucceeded(t *testing.T) {
	r := NewRegistry(10)
	_, h := r.Begin(context.Background(), "execute_command", "node-a", "hostname", map[string]string{"cmd": "hostname"})
	if got := len(r.List()); got != 1 {
		t.Fatalf("expected 1 op, got %d", got)
	}
	h.Done(nil)
	ops := r.List()
	if len(ops) != 1 {
		t.Fatalf("expected 1 op after done, got %d", len(ops))
	}
	if ops[0].Status != StatusSucceeded {
		t.Fatalf("expected succeeded, got %s", ops[0].Status)
	}
	if ops[0].FinishedAt == nil {
		t.Fatalf("expected finished_at set")
	}
}

func TestBeginAndDoneFailed(t *testing.T) {
	r := NewRegistry(10)
	_, h := r.Begin(context.Background(), "push_file", "node-a", "x", nil)
	h.Done(errors.New("disk full"))
	ops := r.List()
	if ops[0].Status != StatusFailed {
		t.Fatalf("expected failed, got %s", ops[0].Status)
	}
	if ops[0].Error != "disk full" {
		t.Fatalf("unexpected error: %s", ops[0].Error)
	}
}

func TestPortalCancelMarksCancelled(t *testing.T) {
	r := NewRegistry(10)
	ctx, h := r.Begin(context.Background(), "execute_command", "n", "sleep", nil)
	if !r.Cancel(h.ID()) {
		t.Fatalf("expected cancel to succeed")
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatalf("ctx was not cancelled")
	}
	// Caller observes ctx.Err() and ends the handle.
	h.Done(ctx.Err())
	ops := r.List()
	if ops[0].Status != StatusCancelled {
		t.Fatalf("expected cancelled, got %s", ops[0].Status)
	}
}

func TestCancelUnknownReturnsFalse(t *testing.T) {
	r := NewRegistry(10)
	if r.Cancel("nope") {
		t.Fatalf("expected false for unknown id")
	}
}

func TestSubscribeReceivesEvents(t *testing.T) {
	r := NewRegistry(10)
	ch, cancel := r.Subscribe()
	defer cancel()

	_, h := r.Begin(context.Background(), "t", "n", "s", nil)
	select {
	case ev := <-ch:
		if ev.Kind != "started" {
			t.Fatalf("expected started, got %s", ev.Kind)
		}
	case <-time.After(time.Second):
		t.Fatalf("no started event")
	}

	h.Done(nil)
	select {
	case ev := <-ch:
		if ev.Kind != "finished" {
			t.Fatalf("expected finished, got %s", ev.Kind)
		}
		if ev.Op.Status != StatusSucceeded {
			t.Fatalf("expected succeeded, got %s", ev.Op.Status)
		}
	case <-time.After(time.Second):
		t.Fatalf("no finished event")
	}
}

func TestRedactSensitive(t *testing.T) {
	out := Redact(map[string]string{"node": "n", "password": "secret", "Token": "abc"})
	if out["node"] != "n" {
		t.Fatalf("unexpected node redaction: %v", out)
	}
	if out["password"] != "***" || out["Token"] != "***" {
		t.Fatalf("expected redaction, got %v", out)
	}
}

func TestHistoryCap(t *testing.T) {
	r := NewRegistry(2)
	for i := 0; i < 5; i++ {
		_, h := r.Begin(context.Background(), "t", "n", "s", nil)
		h.Done(nil)
	}
	ops := r.List()
	if len(ops) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(ops))
	}
}

func TestNilRegistrySafe(t *testing.T) {
	var r *Registry
	ctx, h := r.Begin(context.Background(), "t", "n", "s", nil)
	if ctx == nil {
		t.Fatalf("expected non-nil ctx")
	}
	h.Done(nil) // must not panic
}
