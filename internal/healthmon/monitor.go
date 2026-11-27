package healthmon

import (
	"context"
	"fmt"
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
	Status             string    `json:"status"` // "online", "offline", "unknown"
	LastSeen           time.Time `json:"last_seen,omitempty"`
	ConsecutiveFails   int       `json:"consecutive_fails"`
	AgentVersion       string    `json:"agent_version,omitempty"`
	UpgradeRecommended bool      `json:"upgrade_recommended"`
	VersionWarning     string    `json:"version_warning,omitempty"`
	applianceReady     bool
	endpoint           agentclient.Endpoint
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
	serverVersion string

	warnedVersionTuples map[string]struct{}

	stopCh         chan struct{}
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	startOnce      sync.Once
	stopOnce       sync.Once
	onConnected    func(context.Context, *registry.Node, *pb.GetInfoResponse)
	beforeProbe    func(context.Context) error
	reconcileError string
}

// SetOnConnected installs an explicit post-probe action. It runs outside monitor
// locks, on the first successful probe, recovery, or appliance readiness.
func (m *Monitor) SetOnConnected(fn func(context.Context, *registry.Node, *pb.GetInfoResponse)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onConnected = fn
}

// SetBeforeProbe installs host-assisted endpoint reconciliation before each
// probe cycle and after failed probes, before failures count toward offline.
func (m *Monitor) SetBeforeProbe(fn func(context.Context) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.beforeProbe = fn
}

// New creates a new health monitor.
func New(reg *registry.Registry, pool *agentclient.Pool, serverVersion ...string) *Monitor {
	version := ""
	if len(serverVersion) > 0 {
		version = serverVersion[0]
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Monitor{
		states:              make(map[string]*NodeState),
		ctxs:                make(map[string]context.Context),
		cancels:             make(map[string]context.CancelFunc),
		reg:                 reg,
		pool:                pool,
		interval:            defaultInterval,
		probeTimeout:        defaultProbeTimeout,
		deadThreshold:       defaultDeadThreshold,
		serverVersion:       version,
		warnedVersionTuples: make(map[string]struct{}),
		stopCh:              make(chan struct{}),
		ctx:                 ctx,
		cancel:              cancel,
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
	m.startOnce.Do(func() {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.loop()
		}()
	})
}

// Stop terminates the health check loop.
func (m *Monitor) Stop() {
	m.stopOnce.Do(func() {
		m.cancel()
		close(m.stopCh)
	})
	m.wg.Wait()
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

// RecordAuthenticatedProbeSuccess marks a node healthy after the caller has
// independently completed an authenticated agent probe for this exact node.
// Reachability-only checks must not use this method.
func (m *Monitor) RecordAuthenticatedProbeSuccess(node *registry.Node, agentVersion ...string) {
	version := ""
	reportVersion := len(agentVersion) > 0
	if reportVersion {
		version = agentVersion[0]
	}
	m.recordSuccess(node, version, reportVersion)
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
	if m.ctx.Err() != nil {
		return
	}
	m.mu.RLock()
	reconcile := m.beforeProbe
	m.mu.RUnlock()
	if reconcile != nil {
		m.reconcileEndpoints(reconcile)
	}
	if m.ctx.Err() != nil {
		return
	}
	nodes := m.reg.AllNodes()
	if len(nodes) == 0 {
		return
	}

	failed := m.probeNodes(nodes, reconcile == nil)
	if reconcile == nil || len(failed) == 0 || m.ctx.Err() != nil {
		return
	}
	// DHCP may have changed after the initial discovery. Do not count failed
	// probes until a fresh host-assisted lookup and authenticated retry finish.
	m.reconcileEndpoints(reconcile)
	if m.ctx.Err() != nil {
		return
	}
	var retry []*registry.Node
	for _, node := range failed {
		if current, found := m.reg.GetNode(node.Name); found {
			retry = append(retry, current)
		}
	}
	m.probeNodes(retry, true)
}

func (m *Monitor) reconcileEndpoints(reconcile func(context.Context) error) {
	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	err := reconcile(ctx)
	cancel()
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	m.mu.Lock()
	changed := detail != m.reconcileError
	m.reconcileError = detail
	m.mu.Unlock()
	if err != nil && changed {
		log.Printf("healthmon: endpoint reconciliation: %v", err)
	}
}

func (m *Monitor) probeNodes(nodes []*registry.Node, countFailures bool) []*registry.Node {
	sem := make(chan struct{}, maxConcurrentProbes)
	var wg sync.WaitGroup
	var failedMu sync.Mutex
	var failed []*registry.Node
	for _, node := range nodes {
		wg.Add(1)
		sem <- struct{}{}
		go func(n *registry.Node) {
			defer wg.Done()
			defer func() { <-sem }()
			if !m.probeNodeAttempt(n, countFailures) {
				failedMu.Lock()
				failed = append(failed, n)
				failedMu.Unlock()
			}
		}(node)
	}

	wg.Wait()
	return failed
}

func (m *Monitor) probeNode(node *registry.Node) {
	m.probeNodeAttempt(node, true)
}

func (m *Monitor) probeNodeAttempt(node *registry.Node, countFailures bool) bool {
	m.refreshEndpoint(node)
	client, err := m.pool.GetClient(node.Address, node.TLSServerName)
	if err != nil {
		if countFailures && m.ctx.Err() == nil {
			m.recordFailure(node)
		}
		return false
	}

	ctx, cancel := context.WithTimeout(m.ctx, m.probeTimeout)
	defer cancel()

	info, err := client.GetInfo(ctx, &pb.GetInfoRequest{})
	if current, found := m.reg.GetNode(node.Name); found &&
		(current.Address != node.Address || current.TLSServerName != node.TLSServerName) {
		return false
	}
	if err != nil {
		if countFailures && m.ctx.Err() == nil {
			m.recordFailure(node)
		}
		return false
	}

	connected := m.recordSuccess(node, info.AgentVersion, true)
	m.mu.Lock()
	state := m.states[node.Name]
	connected = connected || info.GetApplianceReady() && !state.applianceReady
	state.applianceReady = info.GetApplianceReady()
	callback := m.onConnected
	m.mu.Unlock()
	if connected && callback != nil {
		actionCtx, cancel := context.WithTimeout(m.ctx, 45*time.Second)
		defer cancel()
		callback(actionCtx, node, info)
	}
	return true
}

func (m *Monitor) refreshEndpoint(node *registry.Node) {
	endpoint := agentclient.Endpoint{Address: node.Address, TLSServerName: node.TLSServerName}
	m.mu.Lock()
	state := m.states[node.Name]
	if state == nil {
		state = &NodeState{Status: "unknown"}
		m.states[node.Name] = state
	}
	previous := state.endpoint
	changed := previous.Address != "" && previous != endpoint
	if changed {
		if cancel := m.cancels[node.Name]; cancel != nil {
			cancel()
		}
		delete(m.ctxs, node.Name)
		delete(m.cancels, node.Name)
		state.Status = "unknown"
		state.ConsecutiveFails = 0
		state.applianceReady = false
	}
	state.endpoint = endpoint
	m.mu.Unlock()
	if changed {
		m.pool.ResetEndpoint(previous)
	}
}

func (m *Monitor) recordSuccess(node *registry.Node, agentVersion string, reportVersion bool) bool {
	m.refreshEndpoint(node)
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.states[node.Name]
	connected := !ok || state.Status != "online"
	if !ok {
		state = &NodeState{}
		m.states[node.Name] = state
	}

	wasOffline := state.Status == "offline"
	state.Status = "online"
	state.LastSeen = time.Now()
	state.ConsecutiveFails = 0
	if reportVersion {
		m.recordVersionState(node.Name, state, agentVersion)
	}

	// If the node was offline and is now back, create a fresh context.
	if wasOffline {
		log.Printf("healthmon: %s is back online", node.Name)
		ctx, cancelFn := context.WithCancel(context.Background())
		m.ctxs[node.Name] = ctx
		m.cancels[node.Name] = cancelFn
	}

	// Ensure a context exists for new nodes.
	if _, ok := m.ctxs[node.Name]; !ok {
		ctx, cancelFn := context.WithCancel(context.Background())
		m.ctxs[node.Name] = ctx
		m.cancels[node.Name] = cancelFn
	}
	return connected
}

func (m *Monitor) recordVersionState(nodeName string, state *NodeState, agentVersion string) {
	state.AgentVersion = agentVersion
	state.UpgradeRecommended = false
	state.VersionWarning = ""
	if m.serverVersion == "" || agentVersion == "" || m.serverVersion == agentVersion {
		return
	}
	state.UpgradeRecommended = true
	state.VersionWarning = fmt.Sprintf(
		"agent upgrade recommended: server version %s, agent version %s",
		m.serverVersion, agentVersion,
	)
	key := nodeName + "\x00" + m.serverVersion + "\x00" + agentVersion
	if _, warned := m.warnedVersionTuples[key]; warned {
		return
	}
	m.warnedVersionTuples[key] = struct{}{}
	log.Printf(
		"healthmon: agent upgrade recommended: node=%s server_version=%s agent_version=%s",
		nodeName, m.serverVersion, agentVersion,
	)
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
