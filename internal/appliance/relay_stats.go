package appliance

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
)

type RelayStats struct {
	RelayID                      string
	ListenerState                string
	BindAddress                  string
	BindError                    string
	ActiveConnections            uint64
	TotalAcceptedConnections     uint64
	BytesGuestToMain             uint64
	BytesMainToGuest             uint64
	LastSuccessfulConnectionUnix int64
	TargetDialFailureCount       uint64
	LastFailure                  string
	RelayGeneration              uint64
	ApplianceGeneration          uint64
}

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

func (m *RelayManager) Stats(ctx context.Context, relayID string) (RelayStats, error) {
	m.mu.RLock()
	runtime := m.relays[relayID]
	if runtime == nil {
		runtime = m.retiring[relayID]
	}
	m.mu.RUnlock()
	if runtime == nil {
		return RelayStats{}, storeError(CodeNotFound, "relay %q is not managed", relayID)
	}
	runtime.mu.Lock()
	relay := runtime.relay
	runtime.mu.Unlock()
	validated, err := m.store.ValidateRelayCurrent(
		ctx, relay.ID, relay.DesiredGeneration)
	if err != nil {
		return RelayStats{}, err
	}
	runtime.mu.Lock()
	runtime.relay = validated
	runtime.mu.Unlock()
	status, err := m.store.Status(ctx)
	if err != nil {
		return RelayStats{}, err
	}
	return runtime.stats(status.InventoryGeneration), nil
}

func (m *RelayManager) AllStats(ctx context.Context) ([]RelayStats, error) {
	status, err := m.store.Status(ctx)
	if err != nil {
		return nil, err
	}
	m.mu.RLock()
	runtimes := make([]*relayRuntime, 0, len(m.relays)+len(m.retiring))
	for _, runtime := range m.relays {
		runtimes = append(runtimes, runtime)
	}
	for _, runtime := range m.retiring {
		runtimes = append(runtimes, runtime)
	}
	m.mu.RUnlock()
	stats := make([]RelayStats, 0, len(runtimes))
	for _, runtime := range runtimes {
		stats = append(stats, runtime.stats(status.InventoryGeneration))
	}
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].RelayID < stats[j].RelayID
	})
	return stats, nil
}

func (m *RelayManager) AggregateStats(ctx context.Context) (RelayStats, error) {
	stats, err := m.AllStats(ctx)
	if err != nil {
		return RelayStats{}, err
	}
	aggregate := RelayStats{
		RelayID:       "*",
		ListenerState: "ready",
	}
	for _, relay := range stats {
		aggregate.ActiveConnections += relay.ActiveConnections
		aggregate.TotalAcceptedConnections += relay.TotalAcceptedConnections
		aggregate.BytesGuestToMain += relay.BytesGuestToMain
		aggregate.BytesMainToGuest += relay.BytesMainToGuest
		aggregate.TargetDialFailureCount += relay.TargetDialFailureCount
		if relay.LastSuccessfulConnectionUnix > aggregate.LastSuccessfulConnectionUnix {
			aggregate.LastSuccessfulConnectionUnix = relay.LastSuccessfulConnectionUnix
		}
		if relay.ApplianceGeneration > aggregate.ApplianceGeneration {
			aggregate.ApplianceGeneration = relay.ApplianceGeneration
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

func (r *relayRuntime) stats(applianceGeneration uint64) RelayStats {
	r.mu.Lock()
	relayID := r.relay.ID
	listenerState := r.listenerState
	bindAddress := r.boundMainIP
	bindError := r.bindError
	generation := r.relay.DesiredGeneration
	r.mu.Unlock()
	return RelayStats{
		RelayID:                      relayID,
		ListenerState:                listenerState,
		BindAddress:                  bindAddress,
		BindError:                    bindError,
		ActiveConnections:            r.counters.active.Load(),
		TotalAcceptedConnections:     r.counters.accepted.Load(),
		BytesGuestToMain:             r.counters.guestToMain.Load(),
		BytesMainToGuest:             r.counters.mainToGuest.Load(),
		LastSuccessfulConnectionUnix: r.counters.lastSuccess.Load(),
		TargetDialFailureCount:       r.counters.dialFailures.Load(),
		LastFailure:                  r.counters.failure(),
		RelayGeneration:              generation,
		ApplianceGeneration:          applianceGeneration,
	}
}
