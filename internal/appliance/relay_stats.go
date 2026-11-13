package appliance

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
)

type relayCounters struct {
	active       atomic.Uint64
	accepted     atomic.Uint64
	guestToMain  atomic.Uint64
	mainToGuest  atomic.Uint64
	dialFailures atomic.Uint64
	lastSuccess  atomic.Int64
	mu           sync.RWMutex
	lastFailure  string
}

func (c *relayCounters) setFailure(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.lastFailure = ""
		return
	}
	c.lastFailure = err.Error()
}

func (c *relayCounters) failure() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastFailure
}

func (m *RelayManager) Stats(
	ctx context.Context,
	relayID string,
) (RelayStats, error) {
	m.mu.RLock()
	runtime := m.relays[relayID]
	m.mu.RUnlock()
	if runtime == nil {
		return RelayStats{}, storeError(
			CodeNotFound, "relay %q is not managed", relayID)
	}
	relay, found, err := m.store.Relay(ctx, relayID)
	if err != nil {
		return RelayStats{}, err
	}
	if !found {
		return RelayStats{}, storeError(
			CodeNotFound, "relay %q is not configured", relayID)
	}
	runtime.mu.Lock()
	runtime.relay = relay
	runtime.mu.Unlock()
	return runtime.stats(), nil
}

func (m *RelayManager) AllStats(
	_ context.Context,
) ([]RelayStats, error) {
	m.mu.RLock()
	runtimes := make([]*relayRuntime, 0, len(m.relays))
	for _, runtime := range m.relays {
		runtimes = append(runtimes, runtime)
	}
	m.mu.RUnlock()
	stats := make([]RelayStats, 0, len(runtimes))
	for _, runtime := range runtimes {
		stats = append(stats, runtime.stats())
	}
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].RelayID < stats[j].RelayID
	})
	return stats, nil
}

func (m *RelayManager) AggregateStats(
	ctx context.Context,
) (RelayStats, error) {
	stats, err := m.AllStats(ctx)
	if err != nil {
		return RelayStats{}, err
	}
	aggregate := RelayStats{RelayID: "*", ListenerState: "ready"}
	for _, relay := range stats {
		aggregate.ActiveConnections += relay.ActiveConnections
		aggregate.TotalAcceptedConnections += relay.TotalAcceptedConnections
		aggregate.BytesGuestToMain += relay.BytesGuestToMain
		aggregate.BytesMainToGuest += relay.BytesMainToGuest
		aggregate.TargetDialFailureCount += relay.TargetDialFailureCount
		if relay.LastSuccessfulConnectionUnix >
			aggregate.LastSuccessfulConnectionUnix {
			aggregate.LastSuccessfulConnectionUnix =
				relay.LastSuccessfulConnectionUnix
		}
		if relay.ListenerState != "ready" {
			aggregate.ListenerState = "degraded"
		}
		if relay.LastFailure != "" {
			aggregate.LastFailure = relay.LastFailure
		}
	}
	return aggregate, nil
}

func (r *relayRuntime) stats() RelayStats {
	r.mu.Lock()
	relayID := r.relay.ID
	listenerState := r.listenerState
	bindAddress := r.boundMainIP
	bindError := r.bindError
	r.mu.Unlock()
	return RelayStats{
		RelayID: relayID, ListenerState: listenerState,
		BindAddress: bindAddress, BindError: bindError,
		ActiveConnections:            r.counters.active.Load(),
		TotalAcceptedConnections:     r.counters.accepted.Load(),
		BytesGuestToMain:             r.counters.guestToMain.Load(),
		BytesMainToGuest:             r.counters.mainToGuest.Load(),
		LastSuccessfulConnectionUnix: r.counters.lastSuccess.Load(),
		TargetDialFailureCount:       r.counters.dialFailures.Load(),
		LastFailure:                  r.counters.failure(),
	}
}
