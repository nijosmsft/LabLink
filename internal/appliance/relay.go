package appliance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	relayBufferSize            = 64 * 1024
	defaultRelayRebindInterval = 2 * time.Second
)

type RelayListenFunc func(context.Context, string, string) (net.Listener, error)
type RelayDialFunc func(context.Context, string, string) (net.Conn, error)
type MainIPv4Func func(context.Context) (string, error)

type RelayManagerOptions struct {
	Listen          RelayListenFunc
	Dial            RelayDialFunc
	Now             func() time.Time
	CurrentMainIPv4 MainIPv4Func
	RebindInterval  time.Duration
}

type RelayManager struct {
	store *Store
	opts  RelayManagerOptions

	mu       sync.RWMutex
	relays   map[string]*relayRuntime
	retiring map[string]*relayRuntime
	mainIPv4 string
	started  bool
	stopped  bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type relayRuntime struct {
	manager *RelayManager

	mu            sync.Mutex
	relay         Relay
	fence         uint64
	listener      *relayListener
	listenerState string
	boundMainIP   string
	bindError     string
	accepting     bool
	retiring      bool
	stopping      bool
	dials         map[uint64]context.CancelFunc
	connections   map[uint64]*relayConnection
	nextID        uint64
	drained       chan struct{}
	drainedClosed bool
	counters      relayCounters
}

type relayListener struct {
	net.Listener
}

type relayConnection struct {
	incoming net.Conn
	target   net.Conn
}

func NewRelayManager(store *Store, options RelayManagerOptions) (*RelayManager, error) {
	if store == nil {
		return nil, storeError(CodeInvalidArgument, "relay manager store is required")
	}
	if options.Listen == nil {
		var listenConfig net.ListenConfig
		options.Listen = listenConfig.Listen
	}
	if options.Dial == nil {
		var dialer net.Dialer
		options.Dial = dialer.DialContext
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.CurrentMainIPv4 != nil && options.RebindInterval == 0 {
		options.RebindInterval = defaultRelayRebindInterval
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &RelayManager{
		store:    store,
		opts:     options,
		relays:   make(map[string]*relayRuntime),
		retiring: make(map[string]*relayRuntime),
		ctx:      ctx,
		cancel:   cancel,
	}, nil
}

func (m *RelayManager) Start(ctx context.Context) error {
	if m.opts.CurrentMainIPv4 == nil {
		return storeError(CodeInvalidArgument, "current main IPv4 provider is required")
	}
	mainIPv4, err := m.opts.CurrentMainIPv4(ctx)
	if err != nil {
		return fmt.Errorf("appliance: resolve main IPv4: %w", err)
	}
	if err := m.Restore(ctx, mainIPv4); err != nil {
		return err
	}
	if m.opts.RebindInterval > 0 {
		m.wg.Add(1)
		go m.watchMainIPv4()
	}
	return nil
}

// Restore binds every live persisted relay before returning. Callers can make
// the appliance ready only after this method succeeds.
func (m *RelayManager) Restore(ctx context.Context, mainIPv4 string) error {
	normalized, err := normalizeMainIPv4(mainIPv4)
	if err != nil {
		return err
	}
	m.mu.RLock()
	started := m.started
	stopped := m.stopped
	m.mu.RUnlock()
	if started {
		return storeError(CodeResourceInUse, "relay manager is already restored")
	}
	if stopped {
		return storeError(CodeResourceInUse, "relay manager is shut down")
	}
	if err := m.store.SetReadiness(ctx, false, "restoring relay listeners"); err != nil {
		return err
	}
	snapshot, err := m.store.Snapshot(ctx)
	if err != nil {
		return err
	}

	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return storeError(CodeResourceInUse, "relay manager is already restored")
	}
	if m.stopped {
		m.mu.Unlock()
		return storeError(CodeResourceInUse, "relay manager is shut down")
	}
	m.started = true
	m.mainIPv4 = normalized
	m.mu.Unlock()

	var restoreErrors []error
	for _, relay := range snapshot.Relays {
		if relay.RetiredAtUnix != nil || relay.State == "retiring" ||
			relay.State == "removing" || relay.State == "removed" {
			continue
		}
		validated, validateErr := m.store.ValidateRelay(
			ctx, relay.ID, relay.DesiredGeneration, snapshot.Authority.Fence)
		if validateErr != nil {
			restoreErrors = append(restoreErrors,
				fmt.Errorf("relay %s: %w", relay.ID, validateErr))
			continue
		}
		runtime := newRelayRuntime(m, validated, snapshot.Authority.Fence)
		m.mu.Lock()
		m.relays[relay.ID] = runtime
		m.mu.Unlock()
		if bindErr := m.bindRuntime(ctx, runtime, normalized); bindErr != nil {
			restoreErrors = append(restoreErrors,
				fmt.Errorf("relay %s: %w", relay.ID, bindErr))
		}
	}
	restoreErr := errors.Join(restoreErrors...)
	if restoreErr != nil {
		_ = m.store.SetReadiness(ctx, false, restoreErr.Error())
		return restoreErr
	}
	return m.store.SetReadiness(ctx, false, "")
}

func (m *RelayManager) Apply(
	ctx context.Context,
	relayID string,
	expectedGeneration, fence uint64,
) error {
	relay, err := m.store.ValidateRelay(ctx, relayID, expectedGeneration, fence)
	if err != nil {
		return err
	}
	m.mu.RLock()
	mainIPv4 := m.mainIPv4
	runtime := m.relays[relayID]
	stopped := m.stopped
	m.mu.RUnlock()
	if stopped {
		return storeError(CodeResourceInUse, "relay manager is shut down")
	}
	if mainIPv4 == "" {
		return storeError(CodeResourceInUse, "relay manager has not been restored")
	}
	if runtime == nil {
		runtime = newRelayRuntime(m, relay, fence)
		m.mu.Lock()
		if existing := m.relays[relayID]; existing != nil {
			runtime = existing
		} else {
			m.relays[relayID] = runtime
		}
		m.mu.Unlock()
	} else {
		runtime.mu.Lock()
		if runtime.retiring || runtime.stopping {
			runtime.mu.Unlock()
			return storeError(CodeResourceInUse, "relay %q is not accepting applies", relayID)
		}
		if runtime.relay.ListenPort != relay.ListenPort ||
			runtime.relay.TargetIPv4 != relay.TargetIPv4 ||
			runtime.relay.TargetPort != relay.TargetPort ||
			runtime.relay.VMID != relay.VMID {
			runtime.mu.Unlock()
			return storeError(CodeInvalidArgument,
				"relay %q cannot be retargeted in place", relayID)
		}
		runtime.relay = relay
		runtime.fence = fence
		alreadyBound := runtime.listener != nil &&
			runtime.boundMainIP == mainIPv4 && runtime.bindError == ""
		runtime.mu.Unlock()
		if alreadyBound {
			return nil
		}
	}
	return m.bindRuntime(ctx, runtime, mainIPv4)
}

func (m *RelayManager) Rebind(ctx context.Context, mainIPv4 string) error {
	normalized, err := normalizeMainIPv4(mainIPv4)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return storeError(CodeResourceInUse, "relay manager is shut down")
	}
	m.mainIPv4 = normalized
	runtimes := make([]*relayRuntime, 0, len(m.relays))
	for _, runtime := range m.relays {
		runtimes = append(runtimes, runtime)
	}
	m.mu.Unlock()

	var bindErrors []error
	for _, runtime := range runtimes {
		runtime.mu.Lock()
		alreadyBound := runtime.listener != nil &&
			runtime.boundMainIP == normalized && runtime.bindError == ""
		relayID := runtime.relay.ID
		runtime.mu.Unlock()
		if alreadyBound {
			continue
		}
		if bindErr := m.bindRuntime(ctx, runtime, normalized); bindErr != nil {
			bindErrors = append(bindErrors,
				fmt.Errorf("relay %s: %w", relayID, bindErr))
		}
	}
	return errors.Join(bindErrors...)
}

func (m *RelayManager) Retire(
	ctx context.Context,
	relayID string,
	expectedGeneration, fence uint64,
) (Relay, error) {
	relay, err := m.store.BeginRelayRetirement(ctx, relayID, expectedGeneration, fence)
	if err != nil {
		return Relay{}, err
	}

	m.mu.Lock()
	runtime := m.relays[relayID]
	delete(m.relays, relayID)
	if runtime == nil {
		runtime = m.retiring[relayID]
	}
	if runtime != nil {
		m.retiring[relayID] = runtime
	}
	m.mu.Unlock()

	if runtime != nil {
		runtime.stopAccepting(true)
		select {
		case <-runtime.drained:
		case <-ctx.Done():
			return relay, ctx.Err()
		}
	}

	retired, err := m.store.FinalizeRelayRetirement(
		ctx, relayID, expectedGeneration, fence)
	if err != nil {
		return Relay{}, err
	}
	m.mu.Lock()
	delete(m.retiring, relayID)
	m.mu.Unlock()
	return retired, nil
}

func (m *RelayManager) RemoveRelay(
	ctx context.Context,
	relayID string,
	expectedGeneration, fence uint64,
) (Relay, error) {
	return m.Retire(ctx, relayID, expectedGeneration, fence)
}

func (m *RelayManager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return nil
	}
	m.stopped = true
	m.cancel()
	runtimes := make([]*relayRuntime, 0, len(m.relays)+len(m.retiring))
	for _, runtime := range m.relays {
		runtimes = append(runtimes, runtime)
	}
	for _, runtime := range m.retiring {
		runtimes = append(runtimes, runtime)
	}
	m.relays = make(map[string]*relayRuntime)
	m.mu.Unlock()

	for _, runtime := range runtimes {
		runtime.stopAccepting(false)
	}
	for _, runtime := range runtimes {
		select {
		case <-runtime.drained:
		case <-ctx.Done():
			for _, force := range runtimes {
				force.closeConnections()
			}
			for _, force := range runtimes {
				<-force.drained
			}
			m.wg.Wait()
			return ctx.Err()
		}
	}
	m.wg.Wait()
	return nil
}

func (m *RelayManager) MainIPv4() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mainIPv4
}

func (m *RelayManager) watchMainIPv4() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.opts.RebindInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			mainIPv4, err := m.opts.CurrentMainIPv4(m.ctx)
			if err != nil {
				continue
			}
			normalized, err := normalizeMainIPv4(mainIPv4)
			if err != nil {
				continue
			}
			m.mu.RLock()
			current := m.mainIPv4
			needsRebind := normalized != current
			if !needsRebind {
				for _, runtime := range m.relays {
					runtime.mu.Lock()
					needsRebind = runtime.listener == nil ||
						runtime.boundMainIP != normalized || runtime.bindError != ""
					runtime.mu.Unlock()
					if needsRebind {
						break
					}
				}
			}
			m.mu.RUnlock()
			if needsRebind {
				_ = m.Rebind(m.ctx, normalized)
			}
		}
	}
}

func newRelayRuntime(manager *RelayManager, relay Relay, fence uint64) *relayRuntime {
	return &relayRuntime{
		manager:       manager,
		relay:         relay,
		fence:         fence,
		listenerState: "binding",
		accepting:     true,
		dials:         make(map[uint64]context.CancelFunc),
		connections:   make(map[uint64]*relayConnection),
		drained:       make(chan struct{}),
	}
}

func (m *RelayManager) bindRuntime(
	ctx context.Context,
	runtime *relayRuntime,
	mainIPv4 string,
) error {
	runtime.mu.Lock()
	if !runtime.accepting || runtime.retiring || runtime.stopping {
		runtime.mu.Unlock()
		return storeError(CodeResourceInUse, "relay %q is not accepting binds", runtime.relay.ID)
	}
	relay := runtime.relay
	fence := runtime.fence
	oldBound := runtime.boundMainIP
	runtime.mu.Unlock()

	address := net.JoinHostPort(mainIPv4, strconv.FormatInt(relay.ListenPort, 10))
	listener, err := m.opts.Listen(ctx, "tcp4", address)
	if err != nil {
		runtime.mu.Lock()
		runtime.listenerState = "degraded"
		runtime.bindError = err.Error()
		runtime.mu.Unlock()
		_ = m.store.SetRelayBindStatus(ctx, relay.ID, relay.DesiredGeneration,
			fence, oldBound, err.Error(), "degraded")
		return fmt.Errorf("bind %s: %w", address, err)
	}
	session := &relayListener{Listener: listener}
	if err := m.store.SetRelayBindStatus(ctx, relay.ID, relay.DesiredGeneration,
		fence, mainIPv4, "", "ready"); err != nil {
		_ = listener.Close()
		return err
	}

	runtime.mu.Lock()
	if !runtime.accepting || runtime.retiring || runtime.stopping {
		runtime.mu.Unlock()
		_ = listener.Close()
		return storeError(CodeResourceInUse, "relay %q stopped while binding", relay.ID)
	}
	old := runtime.listener
	runtime.listener = session
	runtime.listenerState = "ready"
	runtime.boundMainIP = mainIPv4
	runtime.bindError = ""
	runtime.mu.Unlock()

	m.wg.Add(1)
	go runtime.acceptLoop(session)
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (r *relayRuntime) acceptLoop(listener *relayListener) {
	defer r.manager.wg.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			r.mu.Lock()
			current := r.listener == listener
			if current && r.accepting && !r.retiring && !r.stopping {
				r.listener = nil
				r.listenerState = "degraded"
				r.bindError = err.Error()
				relay := r.relay
				fence := r.fence
				r.mu.Unlock()
				_ = r.manager.store.SetRelayBindStatus(
					context.Background(), relay.ID, relay.DesiredGeneration,
					fence, "", err.Error(), "degraded")
			} else {
				r.mu.Unlock()
			}
			return
		}
		r.counters.accepted.Add(1)
		r.manager.wg.Add(1)
		go func() {
			defer r.manager.wg.Done()
			r.handleAccepted(conn)
		}()
	}
}

func (r *relayRuntime) handleAccepted(incoming net.Conn) {
	dialID, dialCtx, cancel, relay, fence, ok := r.beginDial()
	if !ok {
		_ = incoming.Close()
		return
	}
	defer cancel()

	validated, err := r.manager.store.ValidateRelay(
		dialCtx, relay.ID, relay.DesiredGeneration, fence)
	if err != nil {
		r.finishDial(dialID, nil)
		r.counters.setFailure(err)
		_ = incoming.Close()
		return
	}
	targetAddress := net.JoinHostPort(
		validated.TargetIPv4, strconv.Itoa(RelayTargetPort))
	target, err := r.manager.opts.Dial(dialCtx, "tcp4", targetAddress)
	if err != nil {
		r.finishDial(dialID, nil)
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			r.counters.dialFailures.Add(1)
			r.counters.setFailure(err)
		}
		_ = incoming.Close()
		return
	}
	connectionID, ok := r.finishDial(dialID, &relayConnection{
		incoming: incoming,
		target:   target,
	})
	if !ok {
		_ = target.Close()
		_ = incoming.Close()
		return
	}
	r.counters.lastSuccess.Store(r.manager.opts.Now().Unix())
	r.counters.setFailure(nil)
	r.forward(connectionID, incoming, target)
}

func (r *relayRuntime) beginDial() (
	uint64,
	context.Context,
	context.CancelFunc,
	Relay,
	uint64,
	bool,
) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.accepting || r.retiring || r.stopping {
		return 0, nil, nil, Relay{}, 0, false
	}
	r.nextID++
	id := r.nextID
	ctx, cancel := context.WithCancel(r.manager.ctx)
	r.dials[id] = cancel
	return id, ctx, cancel, r.relay, r.fence, true
}

func (r *relayRuntime) finishDial(id uint64, connection *relayConnection) (uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.dials, id)
	if connection == nil || r.retiring || r.stopping {
		r.maybeCloseDrainedLocked()
		return 0, false
	}
	r.connections[id] = connection
	r.counters.active.Add(1)
	return id, true
}

func (r *relayRuntime) forward(id uint64, incoming, target net.Conn) {
	var copies sync.WaitGroup
	copies.Add(2)
	go func() {
		defer copies.Done()
		copyRelayHalf(target, incoming, &r.counters.mainToGuest)
	}()
	go func() {
		defer copies.Done()
		copyRelayHalf(incoming, target, &r.counters.guestToMain)
	}()
	copies.Wait()
	_ = incoming.Close()
	_ = target.Close()

	r.mu.Lock()
	delete(r.connections, id)
	r.counters.active.Add(^uint64(0))
	r.maybeCloseDrainedLocked()
	r.mu.Unlock()
}

func (r *relayRuntime) stopAccepting(retiring bool) {
	r.mu.Lock()
	r.accepting = false
	r.retiring = r.retiring || retiring
	r.stopping = r.stopping || !retiring
	if retiring {
		r.listenerState = "retiring"
	} else {
		r.listenerState = "stopped"
	}
	listener := r.listener
	r.listener = nil
	cancels := make([]context.CancelFunc, 0, len(r.dials))
	for _, cancel := range r.dials {
		cancels = append(cancels, cancel)
	}
	r.maybeCloseDrainedLocked()
	r.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	for _, cancel := range cancels {
		cancel()
	}
}

func (r *relayRuntime) closeConnections() {
	r.mu.Lock()
	connections := make([]*relayConnection, 0, len(r.connections))
	for _, connection := range r.connections {
		connections = append(connections, connection)
	}
	r.mu.Unlock()
	for _, connection := range connections {
		_ = connection.incoming.Close()
		_ = connection.target.Close()
	}
}

func (r *relayRuntime) maybeCloseDrainedLocked() {
	if r.drainedClosed || (!r.retiring && !r.stopping) ||
		len(r.dials) != 0 || len(r.connections) != 0 {
		return
	}
	close(r.drained)
	r.drainedClosed = true
}

func copyRelayHalf(dst, src net.Conn, counter *atomic.Uint64) {
	buffer := make([]byte, relayBufferSize)
	for {
		read, readErr := src.Read(buffer)
		written := 0
		for written < read {
			n, writeErr := dst.Write(buffer[written:read])
			if n > 0 {
				written += n
				counter.Add(uint64(n))
			}
			if writeErr != nil {
				readErr = writeErr
				break
			}
			if n == 0 {
				readErr = io.ErrNoProgress
				break
			}
		}
		if readErr != nil {
			break
		}
	}
	if closeWriter, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = closeWriter.CloseWrite()
	}
}

func normalizeMainIPv4(value string) (string, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.IsUnspecified() ||
		address.IsMulticast() || address.IsLoopback() {
		return "", storeError(CodeInvalidArgument,
			"main address %q is not a unicast IPv4 address", value)
	}
	return address.String(), nil
}
