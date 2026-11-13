package appliance

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type fakeConntrackInspector struct {
	mu      sync.Mutex
	count   int
	err     error
	filters []ConntrackFilter
}

func (f *fakeConntrackInspector) Count(
	_ context.Context,
	filter ConntrackFilter,
) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.filters = append(f.filters, filter)
	return f.count, f.err
}

func (f *fakeConntrackInspector) setCount(count int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.count = count
}

type recoverableNATTarget struct {
	mu          sync.Mutex
	currentHash string
	failApply   bool
	applyCalls  int
}

func (*recoverableNATTarget) ActivateEmergency(context.Context) error { return nil }

func (t *recoverableNATTarget) Apply(_ context.Context, compiled CompiledApply) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.applyCalls++
	if t.failApply {
		return errors.New("forced NAT apply failure")
	}
	t.currentHash = compiled.CompiledHash
	return nil
}

func (t *recoverableNATTarget) Verify(
	_ context.Context,
	compiled CompiledApply,
) (Verification, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Verification{Matched: t.currentHash == compiled.CompiledHash}, nil
}

func setupNATFixture(
	t *testing.T,
	target ApplyTarget,
) (*Store, *ApplyManager, int64) {
	t.Helper()
	store := openTestStore(t, filepath.Join(t.TempDir(), "appliance.db"))
	installTestAuthority(t, store, 12, 4)
	ctx := context.Background()

	mustReserve(t, store, 12, 4, Reservation{
		ID:            "network-nat-reservation",
		ResourceKind:  "network",
		ResourceID:    "network-nat",
		MAC:           "02:00:00:00:31:01",
		CapacityKind:  "network",
		CapacityUnits: 1,
	})
	networkHeader := mutation("network-nat-create", "hash-network-nat-create", 12, 4)
	networkHeader.ResourceID = "network-nat"
	networkHeader.NewGeneration = 1
	if _, err := store.StageNetwork(ctx, networkHeader, Network{
		ID:             "network-nat",
		CIDR:           "10.83.0.0/26",
		GatewayIPv4:    "10.83.0.1",
		NICMAC:         "02:00:00:00:31:01",
		InterfaceName:  "eth1",
		DNSServersJSON: `["10.0.0.2"]`,
	}); err != nil {
		t.Fatalf("StageNetwork: %v", err)
	}
	commitTestIntent(t, store, networkHeader)

	mark := int64(601)
	mustReserve(t, store, 12, 4, Reservation{
		ID:            "guest-nat-reservation",
		ResourceKind:  "guest",
		ResourceID:    "guest-nat",
		NetworkID:     "network-nat",
		IPv4:          "10.83.0.10",
		MAC:           "02:00:00:00:31:10",
		ConntrackMark: &mark,
		CapacityKind:  "guest",
		CapacityUnits: 1,
	})
	guestHeader := mutation("guest-nat-create", "hash-guest-nat-create", 12, 1)
	guestHeader.ResourceID = "guest-nat"
	guestHeader.ParentResourceID = "network-nat"
	guestHeader.NewGeneration = 1
	if _, err := store.StageGuest(ctx, guestHeader, Guest{
		ID:        "guest-nat",
		NetworkID: "network-nat",
		IPv4:      "10.83.0.10",
		MAC:       "02:00:00:00:31:10",
	}); err != nil {
		t.Fatalf("StageGuest: %v", err)
	}
	commitTestIntent(t, store, guestHeader)

	manager := newTestApplyManager(t, store, target, ApplyHooks{})
	return store, manager, mark
}

func commitTestIntent(t *testing.T, store *Store, header MutationHeader) {
	t.Helper()
	if _, err := store.CommitIntent(context.Background(), CommitIntentRequest{
		MutationID:   header.MutationID,
		SemanticHash: header.SemanticHash,
		HostFence:    header.HostFence,
	}); err != nil {
		t.Fatalf("CommitIntent(%s): %v", header.MutationID, err)
	}
}

func natMutation(id string, expected uint64) MutationHeader {
	header := mutation(id, "hash-"+id, 12, 1)
	header.ResourceID = "guest-nat"
	header.ParentResourceID = "guest-nat"
	header.ExpectedGeneration = expected
	header.NewGeneration = expected + 1
	return header
}

func newTestNATEngine(
	t *testing.T,
	store *Store,
	manager *ApplyManager,
	conntrack ConntrackInspector,
) *NATEngine {
	t.Helper()
	engine, err := NewNATEngine(NATEngineOptions{
		Store:         store,
		Applier:       manager,
		Conntrack:     conntrack,
		MainInterface: "eth0",
	})
	if err != nil {
		t.Fatalf("NewNATEngine: %v", err)
	}
	return engine
}

func TestNATEngineEnableAndDisableTransitionsToDraining(t *testing.T) {
	target := &fakeTarget{}
	store, manager, mark := setupNATFixture(t, target)
	conntrack := &fakeConntrackInspector{count: 1}
	engine := newTestNATEngine(t, store, manager, conntrack)

	nat, err := engine.SetEnabled(
		context.Background(), natMutation("nat-enable", 0), mark, true)
	if err != nil {
		t.Fatalf("enable NAT: %v", err)
	}
	if nat.State != "enabled" || nat.DesiredGeneration != 1 ||
		nat.AppliedGeneration != 1 || nat.ObservedGeneration != 1 {
		t.Fatalf("enabled NAT = %+v", nat)
	}
	network, found, err := store.Network(context.Background(), "network-nat")
	if err != nil || !found || network.DNSServersJSON != `["10.0.0.2"]` {
		t.Fatalf("NAT enable did not preserve copied upstream DNS: found=%v network=%+v err=%v",
			found, network, err)
	}

	nat, err = engine.SetEnabled(
		context.Background(), natMutation("nat-disable", 1), mark, false)
	if err != nil {
		t.Fatalf("disable NAT: %v", err)
	}
	if nat.State != "draining" || nat.DrainStartedUnix == nil ||
		nat.DesiredGeneration != 2 || nat.AppliedGeneration != 2 {
		t.Fatalf("disabled NAT did not enter draining: %+v", nat)
	}
}

func TestNATEngineKeepsExistingFlowsUntilConntrackReachesZero(t *testing.T) {
	target := &fakeTarget{}
	store, manager, mark := setupNATFixture(t, target)
	conntrack := &fakeConntrackInspector{count: 1}
	engine := newTestNATEngine(t, store, manager, conntrack)
	ctx := context.Background()

	if _, err := engine.SetEnabled(ctx, natMutation("nat-enable", 0), mark, true); err != nil {
		t.Fatalf("enable NAT: %v", err)
	}

	if _, err := engine.SetEnabled(ctx, natMutation("nat-disable", 1), mark, false); err != nil {
		t.Fatalf("disable NAT: %v", err)
	}
	if err := engine.PollOnce(ctx); err != nil {
		t.Fatalf("PollOnce(active): %v", err)
	}
	nat, _, err := store.NAT(ctx, "guest-nat")
	if err != nil || nat.State != "draining" || nat.DesiredGeneration != 2 {
		t.Fatalf("NAT with active flow = %+v err=%v", nat, err)
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReleaseAuthority(ctx, snapshot.Authority); err != nil {
		t.Fatalf("ReleaseAuthority: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `
		UPDATE appliance_authority
		SET host_lease_id='', host_lease_secret_hash='',
			host_lease_expires_unix=0, handoff_pending=1
		WHERE singleton=1
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.SetEnabled(
		ctx, natMutation("nat-external-after-release", 2), mark, true,
	); ErrorCodeOf(err) != CodeFenceRejected {
		t.Fatalf("external mutation after release error = %v, want %s",
			err, CodeFenceRejected)
	}

	conntrack.setCount(0)
	if err := engine.PollOnce(ctx); err != nil {
		t.Fatalf("PollOnce(zero): %v", err)
	}
	nat, _, err = store.NAT(ctx, "guest-nat")
	if err != nil || nat.State != "disabled" || nat.DrainStartedUnix != nil ||
		nat.DesiredGeneration != 3 || nat.AppliedGeneration != 3 ||
		nat.ObservedGeneration != 3 {
		t.Fatalf("NAT after drain completion = %+v err=%v", nat, err)
	}
}

func TestNATDrainSystemTransitionRecoversAfterRestartWithoutLease(t *testing.T) {
	target := &fakeTarget{}
	store, manager, mark := setupNATFixture(t, target)
	ctx := context.Background()
	if _, err := manager.store.StageNAT(ctx, natMutation("nat-enable-restart", 0), NATState{
		VMID: "guest-nat", State: "enabled", ConntrackMark: mark,
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("frozen parent", func(t *testing.T) {
		target := &fakeTarget{}
		store, manager, mark := setupNATFixture(t, target)
		ctx := context.Background()
		engine := newTestNATEngine(t, store, manager,
			&fakeConntrackInspector{count: 0})
		if _, err := engine.SetEnabled(
			ctx, natMutation("nat-enable-frozen", 0), mark, true,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := engine.SetEnabled(
			ctx, natMutation("nat-disable-frozen", 1), mark, false,
		); err != nil {
			t.Fatal(err)
		}
		authority, err := store.Authority(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.SetParentLifecycle(
			ctx, authority, 4, 5, "frozen",
			"55555555-5555-4555-8555-555555555555",
			"r1-frozen-drain", "frozen-drain-plan",
			testCascadeAuthorityItems("network-nat", 1),
		); err != nil {
			t.Fatal(err)
		}
		if err := engine.PollOnce(ctx); err != nil {
			t.Fatalf("PollOnce frozen: %v", err)
		}
		nat, found, err := store.NAT(ctx, "guest-nat")
		if err != nil || !found || nat.State != "disabled" ||
			nat.DesiredGeneration != 3 || nat.AppliedGeneration != 3 ||
			nat.ObservedGeneration != 3 {
			t.Fatalf("frozen drain completion = %+v found=%v err=%v",
				nat, found, err)
		}
	})
	if _, err := manager.ApplyIntent(ctx, "nat-enable-restart"); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.store.StageNAT(ctx, natMutation("nat-disable-restart", 1), NATState{
		VMID: "guest-nat", State: "disabled", ConntrackMark: mark,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ApplyIntent(ctx, "nat-disable-restart"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReleaseAuthority(ctx, snapshot.Authority); err != nil {
		t.Fatal(err)
	}

	failingManager := newTestApplyManager(t, store, target, ApplyHooks{
		BeforeCommit: func(CompiledApply) error {
			return errors.New("simulated crash before commit")
		},
	})
	engine := newTestNATEngine(t, store, failingManager,
		&fakeConntrackInspector{count: 0})
	if err := engine.PollOnce(ctx); err == nil ||
		!strings.Contains(err.Error(), "simulated crash before commit") {
		t.Fatalf("drain completion error = %v", err)
	}
	pending, found, err := store.NAT(ctx, "guest-nat")
	if err != nil || !found || pending.State != "disabled" ||
		pending.DesiredGeneration != 3 || pending.AppliedGeneration != 2 {
		t.Fatalf("pending system transition = %+v found=%v err=%v",
			pending, found, err)
	}

	restarted := newTestApplyManager(t, store, target, ApplyHooks{})
	recovered, err := restarted.Recover(ctx)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if recovered != 1 {
		t.Fatalf("recovered intents = %d, want 1", recovered)
	}
	nat, found, err := store.NAT(ctx, "guest-nat")
	if err != nil || !found || nat.State != "disabled" ||
		nat.DesiredGeneration != 3 || nat.AppliedGeneration != 3 ||
		nat.ObservedGeneration != 3 {
		t.Fatalf("recovered NAT = %+v found=%v err=%v", nat, found, err)
	}
}

func TestNATEngineRejectsStaleFenceAndGenerationBeforeApply(t *testing.T) {
	target := &fakeTarget{}
	store, manager, mark := setupNATFixture(t, target)
	engine := newTestNATEngine(t, store, manager, &fakeConntrackInspector{})

	staleFence := natMutation("nat-stale-fence", 0)
	staleFence.HostFence = 11
	if _, err := engine.SetEnabled(context.Background(), staleFence, mark, true); ErrorCodeOf(err) != CodeFenceRejected {
		t.Fatalf("stale fence error = %v, want %s", err, CodeFenceRejected)
	}
	_, applies := target.counts()
	if applies != 0 {
		t.Fatalf("stale fence caused %d external applies", applies)
	}

	staleGeneration := natMutation("nat-stale-generation", 1)
	if _, err := engine.SetEnabled(context.Background(), staleGeneration, mark, true); ErrorCodeOf(err) != CodeGenerationConflict {
		t.Fatalf("stale generation error = %v, want %s", err, CodeGenerationConflict)
	}
	_, applies = target.counts()
	if applies != 0 {
		t.Fatalf("stale generation caused %d external applies", applies)
	}
}

func TestNATEngineApplyFailureRecoversIntent(t *testing.T) {
	target := &recoverableNATTarget{failApply: true}
	store, manager, mark := setupNATFixture(t, target)
	engine := newTestNATEngine(t, store, manager, &fakeConntrackInspector{})

	if _, err := engine.SetEnabled(
		context.Background(), natMutation("nat-recover", 0), mark, true); ErrorCodeOf(err) != CodeApplyFailed {
		t.Fatalf("failed enable error = %v, want %s", err, CodeApplyFailed)
	}
	intent, found, err := store.Intent(context.Background(), "nat-recover")
	if err != nil || !found || intent.Phase != "failed" {
		t.Fatalf("failed intent = found:%v intent:%+v err:%v", found, intent, err)
	}

	target.mu.Lock()
	target.failApply = false
	target.mu.Unlock()
	recovered, err := manager.Recover(context.Background())
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if recovered != 1 {
		t.Fatalf("recovered = %d, want 1", recovered)
	}
	nat, found, err := store.NAT(context.Background(), "guest-nat")
	if err != nil || !found || nat.State != "enabled" ||
		nat.AppliedGeneration != 1 || nat.ObservedGeneration != 1 {
		t.Fatalf("recovered NAT = found:%v state:%+v err:%v", found, nat, err)
	}
}
