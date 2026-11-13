package appliance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	testRelayID   = "relay-test"
	testGuestID   = "guest-test"
	testNetworkID = "network-test"
	testFence     = uint64(41)
)

type recordingListeners struct {
	mu        sync.Mutex
	requested []string
	listeners []net.Listener
	fail      error
}

func (r *recordingListeners) listen(
	_ context.Context,
	network, address string,
) (net.Listener, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requested = append(r.requested, network+" "+address)
	if r.fail != nil {
		return nil, r.fail
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	r.listeners = append(r.listeners, listener)
	return listener, nil
}

func (r *recordingListeners) latest(t *testing.T, count int) net.Listener {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		if len(r.listeners) >= count {
			listener := r.listeners[count-1]
			r.mu.Unlock()
			return listener
		}
		r.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("listener count never reached %d", count)
	return nil
}

func (r *recordingListeners) request(index int) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requested[index]
}

func createRelayStore(t *testing.T, path string, port int64) *Store {
	t.Helper()
	store := openTestStore(t, path)
	installTestAuthority(t, store, testFence, 7)
	ctx := context.Background()

	mustReserve(t, store, testFence, 7, Reservation{
		ID:            "network-test-reservation",
		ResourceKind:  "network",
		ResourceID:    testNetworkID,
		MAC:           "02:00:00:00:40:01",
		CapacityKind:  "network",
		CapacityUnits: 1,
	})
	networkHeader := mutation("relay-network", "hash-relay-network", testFence, 7)
	networkHeader.ResourceID = testNetworkID
	networkHeader.NewGeneration = 1
	if _, err := store.StageNetwork(ctx, networkHeader, Network{
		ID:             testNetworkID,
		CIDR:           "10.90.0.0/26",
		GatewayIPv4:    "10.90.0.1",
		NICMAC:         "02:00:00:00:40:01",
		DNSServersJSON: "[]",
	}); err != nil {
		t.Fatalf("StageNetwork: %v", err)
	}
	if _, err := store.CommitIntent(ctx, CommitIntentRequest{
		MutationID: networkHeader.MutationID, SemanticHash: networkHeader.SemanticHash,
		HostFence: testFence,
	}); err != nil {
		t.Fatalf("commit network: %v", err)
	}

	mark := int64(9001)
	mustReserve(t, store, testFence, 7, Reservation{
		ID:            "guest-test-reservation",
		ResourceKind:  "guest",
		ResourceID:    testGuestID,
		NetworkID:     testNetworkID,
		IPv4:          "10.90.0.10",
		MAC:           "02:00:00:00:40:10",
		ConntrackMark: &mark,
		CapacityKind:  "guest",
		CapacityUnits: 1,
	})
	guestHeader := mutation("relay-guest", "hash-relay-guest", testFence, 1)
	guestHeader.ResourceID = testGuestID
	guestHeader.ParentResourceID = testNetworkID
	guestHeader.NewGeneration = 1
	if _, err := store.StageGuest(ctx, guestHeader, Guest{
		ID:        testGuestID,
		NetworkID: testNetworkID,
		IPv4:      "10.90.0.10",
		MAC:       "02:00:00:00:40:10",
		State:     "ready",
	}); err != nil {
		t.Fatalf("StageGuest: %v", err)
	}
	if _, err := store.CommitIntent(ctx, CommitIntentRequest{
		MutationID: guestHeader.MutationID, SemanticHash: guestHeader.SemanticHash,
		HostFence: testFence,
	}); err != nil {
		t.Fatalf("commit guest: %v", err)
	}

	mustReserve(t, store, testFence, 7, Reservation{
		ID:            "relay-test-reservation",
		ResourceKind:  "relay",
		ResourceID:    testRelayID,
		ListenPort:    &port,
		CapacityKind:  "relay",
		CapacityUnits: 1,
	})
	relayHeader := mutation("relay-stage", "hash-relay-stage", testFence, 1)
	relayHeader.ResourceID = testRelayID
	relayHeader.ParentResourceID = testGuestID
	relayHeader.NewGeneration = 1
	if _, err := store.StageRelay(ctx, relayHeader, Relay{
		ID:         testRelayID,
		VMID:       testGuestID,
		ListenPort: port,
		TargetIPv4: "10.90.0.10",
		State:      "pending",
	}); err != nil {
		t.Fatalf("StageRelay: %v", err)
	}
	if _, err := store.CommitIntent(ctx, CommitIntentRequest{
		MutationID: relayHeader.MutationID, SemanticHash: relayHeader.SemanticHash,
		HostFence: testFence,
	}); err != nil {
		t.Fatalf("commit relay: %v", err)
	}
	return store
}

func newTargetDialer(t *testing.T, listener net.Listener) RelayDialFunc {
	t.Helper()
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp4" {
			t.Errorf("dial network = %q, want tcp4", network)
		}
		if address != "10.90.0.10:9091" {
			t.Errorf("dial address = %q, want 10.90.0.10:9091", address)
		}
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp4", listener.Addr().String())
	}
}

func shutdownManager(t *testing.T, manager *RelayManager) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := manager.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func waitForStats(
	t *testing.T,
	manager *RelayManager,
	predicate func(RelayStats) bool,
) RelayStats {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		stats, err := manager.Stats(context.Background(), testRelayID)
		if err == nil && predicate(stats) {
			return stats
		}
		time.Sleep(time.Millisecond)
	}
	stats, err := manager.Stats(context.Background(), testRelayID)
	t.Fatalf("stats condition not met: stats=%+v err=%v", stats, err)
	return RelayStats{}
}

func TestRelayOpaqueBytesHalfCloseAndStats(t *testing.T) {
	store := createRelayStore(t, filepath.Join(t.TempDir(), "relay.db"), 23001)
	targetListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()
	listeners := &recordingListeners{}
	now := time.Unix(1_700_000_123, 0)
	manager, err := NewRelayManager(store, RelayManagerOptions{
		Listen: listeners.listen,
		Dial:   newTargetDialer(t, targetListener),
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer shutdownManager(t, manager)
	if err := manager.Restore(context.Background(), "192.0.2.10"); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got := listeners.request(0); got != "tcp4 192.0.2.10:23001" {
		t.Fatalf("listen request = %q", got)
	}

	request := append([]byte{0x16, 0x03, 0x03, 0x00, 0x17, 0x00, 0xff}, bytes.Repeat([]byte{0xa5}, 8192)...)
	response := append([]byte{0x17, 0x03, 0x03, 0x00, 0x11}, bytes.Repeat([]byte{0x5a}, 4097)...)
	targetReceived := make(chan []byte, 1)
	go func() {
		conn, acceptErr := targetListener.Accept()
		if acceptErr != nil {
			targetReceived <- nil
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		targetReceived <- data
		_, _ = conn.Write(response)
		_ = conn.(*net.TCPConn).CloseWrite()
	}()

	client, err := net.Dial("tcp4", listeners.latest(t, 1).Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	gotResponse, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if got := <-targetReceived; !bytes.Equal(got, request) {
		t.Fatalf("target received altered opaque bytes: got %d want %d", len(got), len(request))
	}
	if !bytes.Equal(gotResponse, response) {
		t.Fatalf("client received altered opaque bytes: got %d want %d", len(gotResponse), len(response))
	}

	stats := waitForStats(t, manager, func(stats RelayStats) bool {
		return stats.ActiveConnections == 0 &&
			stats.BytesMainToGuest == uint64(len(request)) &&
			stats.BytesGuestToMain == uint64(len(response))
	})
	if stats.TotalAcceptedConnections != 1 ||
		stats.LastSuccessfulConnectionUnix != now.Unix() ||
		stats.TargetDialFailureCount != 0 ||
		stats.ListenerState != "ready" ||
		stats.RelayGeneration != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	aggregate, err := manager.AggregateStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if aggregate.TotalAcceptedConnections != stats.TotalAcceptedConnections ||
		aggregate.BytesMainToGuest != stats.BytesMainToGuest ||
		aggregate.BytesGuestToMain != stats.BytesGuestToMain {
		t.Fatalf("aggregate stats = %+v, relay stats = %+v", aggregate, stats)
	}
	if strings.Contains(stats.LastFailure, string(request)) ||
		strings.Contains(stats.BindError, string(request)) {
		t.Fatal("relay stats retained payload bytes")
	}
}

func TestRelayAcceptsConnectionsAfterAuthorityRelease(t *testing.T) {
	store := createRelayStore(t, filepath.Join(t.TempDir(), "relay.db"), 23001)
	targetListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	defer targetListener.Close()
	listeners := &recordingListeners{}
	manager, err := NewRelayManager(store, RelayManagerOptions{
		Listen: listeners.listen,
		Dial:   newTargetDialer(t, targetListener),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer shutdownManager(t, manager)
	if err := manager.Restore(context.Background(), "192.0.2.10"); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReleaseAuthority(context.Background(), snapshot.Authority); err != nil {
		t.Fatalf("ReleaseAuthority: %v", err)
	}
	if _, err := store.db.ExecContext(context.Background(), `
		UPDATE appliance_authority
		SET host_lease_id='', host_lease_secret_hash='',
			host_lease_expires_unix=0, handoff_pending=1
		WHERE singleton=1
	`); err != nil {
		t.Fatal(err)
	}

	targetDone := make(chan error, 1)
	go func() {
		conn, acceptErr := targetListener.Accept()
		if acceptErr != nil {
			targetDone <- acceptErr
			return
		}
		defer conn.Close()
		request := make([]byte, 4)
		if _, readErr := io.ReadFull(conn, request); readErr != nil {
			targetDone <- readErr
			return
		}
		if string(request) != "ping" {
			targetDone <- fmt.Errorf("target received %q", request)
			return
		}
		_, writeErr := conn.Write([]byte("pong"))
		targetDone <- writeErr
	}()

	client, err := net.Dial("tcp4", listeners.latest(t, 1).Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "pong" {
		t.Fatalf("response = %q, want pong", response)
	}
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
}

func TestRelayRuntimeFailsClosedForFrozenOrCorruptAuthority(t *testing.T) {
	t.Run("frozen", func(t *testing.T) {
		store := createRelayStore(t, filepath.Join(t.TempDir(), "relay.db"), 23011)
		snapshot, err := store.Snapshot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.SetParentLifecycle(
			context.Background(), snapshot.Authority, 7, 8, "frozen",
			"11111111-1111-4111-8111-111111111111", "r1-frozen", "hash-frozen",
			testCascadeAuthorityItems(testNetworkID, 1),
		); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ValidateRelayCurrent(
			context.Background(), testRelayID, 1,
		); ErrorCodeOf(err) != CodeParentFrozen {
			t.Fatalf("frozen relay validation error = %v, want %s", err, CodeParentFrozen)
		}
	})

	t.Run("corrupt identity", func(t *testing.T) {
		store := createRelayStore(t, filepath.Join(t.TempDir(), "relay.db"), 23012)
		if _, err := store.db.ExecContext(context.Background(), `
			UPDATE appliance_authority SET physical_host_id = '' WHERE singleton = 1
		`); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ValidateRelayCurrent(
			context.Background(), testRelayID, 1,
		); ErrorCodeOf(err) != CodeFenceRejected {
			t.Fatalf("corrupt relay validation error = %v, want %s", err, CodeFenceRejected)
		}
	})
}

func TestRelaySlowReaderBackpressure(t *testing.T) {
	store := createRelayStore(t, filepath.Join(t.TempDir(), "relay.db"), 23002)
	targetListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()
	listeners := &recordingListeners{}
	manager, err := NewRelayManager(store, RelayManagerOptions{
		Listen: listeners.listen,
		Dial:   newTargetDialer(t, targetListener),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer shutdownManager(t, manager)
	if err := manager.Restore(context.Background(), "192.0.2.11"); err != nil {
		t.Fatal(err)
	}

	const total = 32 * 1024 * 1024
	writeDone := make(chan error, 1)
	go func() {
		conn, acceptErr := targetListener.Accept()
		if acceptErr != nil {
			writeDone <- acceptErr
			return
		}
		defer conn.Close()
		chunk := bytes.Repeat([]byte{0x6d}, 64*1024)
		written := 0
		for written < total {
			n, writeErr := conn.Write(chunk)
			written += n
			if writeErr != nil {
				writeDone <- writeErr
				return
			}
		}
		_ = conn.(*net.TCPConn).CloseWrite()
		writeDone <- nil
	}()

	client, err := net.Dial("tcp4", listeners.latest(t, 1).Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = client.(*net.TCPConn).CloseWrite()
	select {
	case err := <-writeDone:
		t.Fatalf("target write completed before slow reader consumed data: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	n, err := io.Copy(io.Discard, client)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if n != total {
		t.Fatalf("relayed bytes = %d, want %d", n, total)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestRelayTargetFailureAndBindCollision(t *testing.T) {
	t.Run("target failure", func(t *testing.T) {
		store := createRelayStore(t, filepath.Join(t.TempDir(), "relay.db"), 23003)
		listeners := &recordingListeners{}
		manager, err := NewRelayManager(store, RelayManagerOptions{
			Listen: listeners.listen,
			Dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, syscall.ECONNREFUSED
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer shutdownManager(t, manager)
		if err := manager.Restore(context.Background(), "192.0.2.12"); err != nil {
			t.Fatal(err)
		}
		client, err := net.Dial("tcp4", listeners.latest(t, 1).Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = client.Write([]byte("not-retained"))
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = io.ReadAll(client)
		_ = client.Close()
		stats := waitForStats(t, manager, func(stats RelayStats) bool {
			return stats.TargetDialFailureCount == 1
		})
		if !strings.Contains(stats.LastFailure, "refused") ||
			strings.Contains(stats.LastFailure, "not-retained") {
			t.Fatalf("last failure = %q", stats.LastFailure)
		}
	})

	t.Run("bind collision", func(t *testing.T) {
		store := createRelayStore(t, filepath.Join(t.TempDir(), "relay.db"), 23004)
		listeners := &recordingListeners{fail: syscall.EADDRINUSE}
		manager, err := NewRelayManager(store, RelayManagerOptions{Listen: listeners.listen})
		if err != nil {
			t.Fatal(err)
		}
		defer shutdownManager(t, manager)
		err = manager.Restore(context.Background(), "192.0.2.13")
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("Restore error = %v, want address in use", err)
		}
		stats, err := manager.Stats(context.Background(), testRelayID)
		if err != nil {
			t.Fatal(err)
		}
		if stats.ListenerState != "degraded" ||
			!strings.Contains(strings.ToLower(stats.BindError), "address") {
			t.Fatalf("collision stats = %+v", stats)
		}
		relay, found, err := store.Relay(context.Background(), testRelayID)
		if err != nil || !found {
			t.Fatalf("Relay: found=%v err=%v", found, err)
		}
		if relay.State != "degraded" || relay.LastBindError == "" {
			t.Fatalf("stored relay health = %+v", relay)
		}
	})
}

func TestRelayExplicitRebindPreservesConnectionsAndGeneration(t *testing.T) {
	store := createRelayStore(t, filepath.Join(t.TempDir(), "relay.db"), 23005)
	targetListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()
	go func() {
		for {
			conn, acceptErr := targetListener.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()

	listeners := &recordingListeners{}
	manager, err := NewRelayManager(store, RelayManagerOptions{
		Listen: listeners.listen,
		Dial:   newTargetDialer(t, targetListener),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer shutdownManager(t, manager)
	if err := manager.Restore(context.Background(), "192.0.2.20"); err != nil {
		t.Fatal(err)
	}
	first := listeners.latest(t, 1)
	client, err := net.Dial("tcp4", first.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len("before"))
	if _, err := io.ReadFull(client, echo); err != nil || string(echo) != "before" {
		t.Fatalf("first echo = %q err=%v", echo, err)
	}

	if err := manager.Rebind(context.Background(), "192.0.2.21"); err != nil {
		t.Fatal(err)
	}
	second := listeners.latest(t, 2)
	if _, err := client.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	echo = make([]byte, len("after"))
	if _, err := io.ReadFull(client, echo); err != nil || string(echo) != "after" {
		t.Fatalf("existing connection after rebind = %q err=%v", echo, err)
	}
	secondClient, err := net.Dial("tcp4", second.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secondClient.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	echo = make([]byte, len("new"))
	if _, err := io.ReadFull(secondClient, echo); err != nil || string(echo) != "new" {
		t.Fatalf("new connection echo = %q err=%v", echo, err)
	}
	_ = secondClient.Close()

	relay, found, err := store.Relay(context.Background(), testRelayID)
	if err != nil || !found {
		t.Fatalf("Relay: found=%v err=%v", found, err)
	}
	if relay.DesiredGeneration != 1 || relay.BoundMainIP != "192.0.2.21" {
		t.Fatalf("relay after rebind = %+v", relay)
	}
}

func TestRelayRestartRestore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	store := createRelayStore(t, path, 23006)
	firstListeners := &recordingListeners{}
	first, err := NewRelayManager(store, RelayManagerOptions{Listen: firstListeners.listen})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Restore(context.Background(), "192.0.2.30"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReleaseAuthority(context.Background(), snapshot.Authority); err != nil {
		t.Fatalf("ReleaseAuthority: %v", err)
	}
	if _, err := store.db.ExecContext(context.Background(), `
		UPDATE appliance_authority
		SET host_lease_id='', host_lease_secret_hash='',
			host_lease_expires_unix=0, handoff_pending=1
		WHERE singleton=1
	`); err != nil {
		t.Fatal(err)
	}
	if err := store.SetReadiness(context.Background(), true, ""); err != nil {
		t.Fatal(err)
	}
	shutdownManager(t, first)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	targetListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()
	go func() {
		conn, acceptErr := targetListener.Accept()
		if acceptErr == nil {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}()
	secondListeners := &recordingListeners{}
	second, err := NewRelayManager(reopened, RelayManagerOptions{
		Listen: secondListeners.listen,
		Dial:   newTargetDialer(t, targetListener),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer shutdownManager(t, second)
	if err := second.Restore(context.Background(), "192.0.2.31"); err != nil {
		t.Fatal(err)
	}
	status, err := reopened.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Ready {
		t.Fatal("relay restore left appliance ready before startup completion")
	}
	client, err := net.Dial("tcp4", secondListeners.latest(t, 1).Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("restored")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("restored"))
	if _, err := io.ReadFull(client, got); err != nil || string(got) != "restored" {
		t.Fatalf("restored relay echo = %q err=%v", got, err)
	}
	_ = client.Close()
}

func TestRelayRetirementBarrierAndLiveVMPortRelease(t *testing.T) {
	const port = int64(23007)
	store := createRelayStore(t, filepath.Join(t.TempDir(), "relay.db"), port)
	targetListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()
	targetConn := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := targetListener.Accept()
		if acceptErr == nil {
			targetConn <- conn
		}
	}()
	listeners := &recordingListeners{}
	manager, err := NewRelayManager(store, RelayManagerOptions{
		Listen: listeners.listen,
		Dial:   newTargetDialer(t, targetListener),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer shutdownManager(t, manager)
	if err := manager.Restore(context.Background(), "192.0.2.40"); err != nil {
		t.Fatal(err)
	}
	client, err := net.Dial("tcp4", listeners.latest(t, 1).Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	target := <-targetConn
	waitForStats(t, manager, func(stats RelayStats) bool {
		return stats.ActiveConnections == 1
	})

	retireCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	started := time.Now()
	retired, err := manager.Retire(retireCtx, testRelayID, 1, testFence)
	cancel()
	if err != nil {
		t.Fatalf("Retire with forced drain: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("forced retirement took %s", elapsed)
	}
	if retired.State != "removed" || retired.RetiredAtUnix == nil {
		t.Fatalf("retired relay = %+v", retired)
	}
	result, err := store.ReserveResources(context.Background(), ReserveRequest{
		Header: mutation("post-drain-port-reuse", "hash-post-drain-port-reuse", testFence, 7),
		Reservations: []Reservation{{
			ID:            "replacement-relay-reservation",
			ResourceKind:  "relay",
			ResourceID:    "replacement-relay",
			ListenPort:    int64ptr(port),
			CapacityKind:  "relay",
			CapacityUnits: 1,
		}},
	})
	if err != nil {
		t.Fatalf("port was not reusable after drain: %v", err)
	}
	if len(result.Reservations) != 1 {
		t.Fatalf("replacement reservations = %+v", result.Reservations)
	}
	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Guests) != 1 || snapshot.Guests[0].ID != testGuestID ||
		snapshot.Guests[0].RetiredAtUnix != nil {
		t.Fatalf("relay-only retirement changed live VM: %+v", snapshot.Guests)
	}
	_ = client.Close()
	_ = target.Close()
}

func TestRelayRetirementRetryFromPersistedRetiringState(t *testing.T) {
	const port = int64(23008)
	store := createRelayStore(t, filepath.Join(t.TempDir(), "relay.db"), port)
	if _, err := store.BeginRelayRetirement(
		context.Background(), testRelayID, 1, testFence); err != nil {
		t.Fatal(err)
	}
	manager, err := NewRelayManager(store, RelayManagerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer shutdownManager(t, manager)
	retired, err := manager.Retire(
		context.Background(), testRelayID, 1, testFence)
	if err != nil {
		t.Fatalf("resume retirement: %v", err)
	}
	if retired.State != "removed" || retired.RetiredAtUnix == nil {
		t.Fatalf("retired relay = %+v", retired)
	}
	if _, err := store.ReserveResources(context.Background(), ReserveRequest{
		Header: mutation("retry-port-reuse", "hash-retry-port-reuse", testFence, 7),
		Reservations: []Reservation{{
			ID: "retry-replacement", ResourceKind: "relay",
			ResourceID: "retry-replacement", ListenPort: int64ptr(port),
		}},
	}); err != nil {
		t.Fatalf("retired reservation was not released: %v", err)
	}
}

func TestRelayGracefulShutdownWaitsForActiveConnection(t *testing.T) {
	store := createRelayStore(t, filepath.Join(t.TempDir(), "relay.db"), 23009)
	targetListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()
	targetConn := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := targetListener.Accept()
		if acceptErr == nil {
			targetConn <- conn
		}
	}()
	listeners := &recordingListeners{}
	manager, err := NewRelayManager(store, RelayManagerOptions{
		Listen: listeners.listen,
		Dial:   newTargetDialer(t, targetListener),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background(), "192.0.2.41"); err != nil {
		t.Fatal(err)
	}
	client, err := net.Dial("tcp4", listeners.latest(t, 1).Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	target := <-targetConn
	waitForStats(t, manager, func(stats RelayStats) bool {
		return stats.ActiveConnections == 1
	})

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		shutdownDone <- manager.Shutdown(ctx)
	}()
	select {
	case err := <-shutdownDone:
		t.Fatalf("Shutdown returned before active connection drained: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	_ = client.Close()
	_ = target.Close()
	if err := <-shutdownDone; err != nil {
		t.Fatalf("graceful Shutdown: %v", err)
	}
}

func TestRelayRejectsInvalidPortAndStaleFence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	store := openTestStore(t, path)
	installTestAuthority(t, store, testFence, 7)
	port := int64(RelayPortMin - 1)
	_, err := store.ReserveResources(context.Background(), ReserveRequest{
		Header: mutation("bad-relay-port", "hash-bad-relay-port", testFence, 7),
		Reservations: []Reservation{{
			ID:           "bad-relay-port",
			ResourceKind: "relay",
			ResourceID:   "bad-relay",
			ListenPort:   &port,
		}},
	})
	if ErrorCodeOf(err) != CodeInvalidArgument {
		t.Fatalf("invalid port error = %v", err)
	}

	store = createRelayStore(t, filepath.Join(t.TempDir(), "stale.db"), 23008)
	manager, err := NewRelayManager(store, RelayManagerOptions{
		Listen: (&recordingListeners{}).listen,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer shutdownManager(t, manager)
	err = manager.Apply(context.Background(), testRelayID, 1, testFence+1)
	if ErrorCodeOf(err) != CodeFenceRejected {
		t.Fatalf("stale fence apply error = %v", err)
	}
}

func TestRelayListenerUsesPersistentPort(t *testing.T) {
	store := createRelayStore(t, filepath.Join(t.TempDir(), "relay.db"), 23999)
	listeners := &recordingListeners{}
	manager, err := NewRelayManager(store, RelayManagerOptions{Listen: listeners.listen})
	if err != nil {
		t.Fatal(err)
	}
	defer shutdownManager(t, manager)
	if err := manager.Restore(context.Background(), "198.51.100.8"); err != nil {
		t.Fatal(err)
	}
	request := listeners.request(0)
	if !strings.HasSuffix(request, net.JoinHostPort("198.51.100.8", strconv.Itoa(23999))) {
		t.Fatalf("listen request = %q", request)
	}
}
