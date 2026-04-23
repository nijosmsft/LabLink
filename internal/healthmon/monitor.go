package healthmon

import (
	"context"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/registry"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

const (
	defaultInterval      = 5 * time.Second
	defaultProbeTimeout  = 2 * time.Second
	defaultDeadThreshold = 2
	maxConcurrentProbes  = 10
)

// NodeState represents the health status of a node.
type NodeState struct {
	Status           string // "online", "offline", "unknown"
	LastSeen         time.Time
	ConsecutiveFails int
}

// Monitor periodically probes registered nodes and cancels contexts for dead nodes.
type Monitor struct {
	mu      sync.RWMutex
	states  map[string]*NodeState // node name -> state
	ctxs    map[string]context.Context
	cancels map[string]context.CancelFunc

	reg  *registry.Registry
	pool *agentclient.Pool

	interval      time.Duration
	probeTimeout  time.Duration
	deadThreshold int

	stopCh chan struct{}
}

// New creates a new health monitor.
func New(reg *registry.Registry, pool *agentclient.Pool) *Monitor {
	m := &Monitor{
		states:        make(map[string]*NodeState),
		ctxs:          make(map[string]context.Context),
		cancels:       make(map[string]context.CancelFunc),
		reg:           reg,
		pool:          pool,
		interval:      defaultInterval,
		probeTimeout:  defaultProbeTimeout,
		deadThreshold: defaultDeadThreshold,
		stopCh:        make(chan struct{}),
	}

	// Override from env vars.
	if v := os.Getenv("HEALTH_CHECK_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			m.interval = d
		}
	}
	if v := os.Getenv("HEALTH_CHECK_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			m.probeTimeout = d
		}
	}
	if v := os.Getenv("DEAD_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			m.deadThreshold = n
		}
	}

	return m
}

// Start begins the background health check loop.
func (m *Monitor) Start() {
	go m.loop()
}

// Stop terminates the health check loop.
func (m *Monitor) Stop() {
	close(m.stopCh)
}

// NodeContext returns a context that will be cancelled if the node is declared dead.
// Callers should derive their gRPC call contexts from this.
func (m *Monitor) NodeContext(nodeName string) context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx, ok := m.ctxs[nodeName]
	if ok {
		// Return existing context as-is — even if cancelled (node is dead).
		// Only recordSuccess creates fresh contexts when a node recovers.
		// This prevents callers from getting a valid context for a dead node.
		return ctx
	}

	// No context yet — node was just registered or monitor hasn't probed it yet.
	// Check if the node is known to be offline; if so, return a cancelled context.
	if state, ok := m.states[nodeName]; ok && state.Status == "offline" {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		m.ctxs[nodeName] = ctx
		m.cancels[nodeName] = func() {} // already cancelled
		return ctx
	}

	// Create a live context for new/unknown nodes.
	ctx, cancel := context.WithCancel(context.Background())
	m.ctxs[nodeName] = ctx
	m.cancels[nodeName] = cancel
	return ctx
}

// GetStatus returns the current health state of a node.
func (m *Monitor) GetStatus(nodeName string) NodeState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if s, ok := m.states[nodeName]; ok {
		return *s
	}
	return NodeState{Status: "unknown"}
}

// GetAllStatuses returns health state for all monitored nodes.
func (m *Monitor) GetAllStatuses() map[string]NodeState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]NodeState, len(m.states))
	for k, v := range m.states {
		result[k] = *v
	}
	return result
}

func (m *Monitor) loop() {
	// Run an initial probe immediately.
	m.probeAll()

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.probeAll()
		}
	}
}

func (m *Monitor) probeAll() {
	nodes := m.reg.AllNodes()
	if len(nodes) == 0 {
		return
	}

	// Semaphore to limit concurrent probes.
	sem := make(chan struct{}, maxConcurrentProbes)
	var wg sync.WaitGroup

	for _, node := range nodes {
		wg.Add(1)
		sem <- struct{}{}
		go func(n *registry.Node) {
			defer wg.Done()
			defer func() { <-sem }()
			m.probeNode(n)
		}(node)
	}

	wg.Wait()
}

func (m *Monitor) probeNode(node *registry.Node) {
	client, err := m.pool.GetClient(node.Address, node.TLSServerName)
	if err != nil {
		m.recordFailure(node)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.probeTimeout)
	defer cancel()

	_, err = client.GetInfo(ctx, &pb.GetInfoRequest{})
	if err != nil {
		m.recordFailure(node)
		return
	}

	m.recordSuccess(node)
}

func (m *Monitor) recordSuccess(node *registry.Node) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.states[node.Name]
	if !ok {
		state = &NodeState{}
		m.states[node.Name] = state
	}

	wasOffline := state.Status == "offline"
	state.Status = "online"
	state.LastSeen = time.Now()
	state.ConsecutiveFails = 0

	// If the node was offline and is now back, create a fresh context.
	if wasOffline {
		log.Printf("healthmon: %s is back online", node.Name)
		ctx, cancelFn := context.WithCancel(context.Background())
		m.ctxs[node.Name] = ctx
		m.cancels[node.Name] = cancelFn
		m.pool.ResetConnection(node.Address)
	}

	// Ensure a context exists for new nodes.
	if _, ok := m.ctxs[node.Name]; !ok {
		ctx, cancelFn := context.WithCancel(context.Background())
		m.ctxs[node.Name] = ctx
		m.cancels[node.Name] = cancelFn
	}
}

func (m *Monitor) recordFailure(node *registry.Node) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.states[node.Name]
	if !ok {
		state = &NodeState{Status: "unknown"}
		m.states[node.Name] = state
	}

	state.ConsecutiveFails++

	if state.ConsecutiveFails >= m.deadThreshold && state.Status != "offline" {
		log.Printf("healthmon: %s declared dead (%d consecutive failures)", node.Name, state.ConsecutiveFails)
		state.Status = "offline"

		// Cancel the node's context to unblock all waiters.
		if cancelFn, ok := m.cancels[node.Name]; ok {
			cancelFn()
		}

		// Reset the stale connection.
		m.pool.ResetConnection(node.Address)
	}
}
