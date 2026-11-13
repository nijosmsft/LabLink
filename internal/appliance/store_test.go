package appliance

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nijosmsft/lablink/internal/cascadeauth"
)

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func installTestAuthority(t *testing.T, store *Store, fence, generation uint64) {
	t.Helper()
	err := store.InstallAuthority(context.Background(), Authority{
		PhysicalHostID:       "host-1",
		HostLeaseID:          "lease-1",
		HostLeaseSecretHash:  "secret-hash",
		HostLeaseExpiresUnix: time.Now().Add(time.Hour).Unix(),
		Fence:                fence,
		ParentGeneration:     generation,
		ParentState:          "active",
	})
	if err != nil {
		t.Fatalf("InstallAuthority: %v", err)
	}
}

func mutation(id, hash string, fence, parentGeneration uint64) MutationHeader {
	return MutationHeader{
		ParentOperationID:        "operation-" + id,
		MutationID:               id,
		SemanticHash:             hash,
		HostFence:                fence,
		ExpectedParentGeneration: parentGeneration,
	}
}

func testCascadeAuthorityItems(resourceID string, generation uint64) []CascadeAuthorityItem {
	return []CascadeAuthorityItem{{
		ItemID:       "22222222-2222-4222-8222-222222222222",
		ResourceKind: "network", ResourceID: resourceID,
		Action: "delete_private_switch", ExpectedGeneration: generation,
	}}
}

func int64ptr(value int64) *int64 { return &value }

func mustReserve(
	t *testing.T,
	store *Store,
	fence, parentGeneration uint64,
	reservation Reservation,
) {
	t.Helper()
	_, err := store.ReserveResources(context.Background(), ReserveRequest{
		Header: mutation(
			"reserve-"+reservation.ID,
			"hash-reserve-"+reservation.ID,
			fence,
			parentGeneration,
		),
		Reservations: []Reservation{reservation},
	})
	if err != nil {
		t.Fatalf("reserve %s: %v", reservation.ID, err)
	}
}

func TestConcurrentReservationRace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "appliance.db")
	first := openTestStore(t, path)
	second := openTestStore(t, path)
	installTestAuthority(t, first, 9, 3)

	start := make(chan struct{})
	type outcome struct {
		result ReserveResult
		err    error
	}
	outcomes := make(chan outcome, 2)
	var wg sync.WaitGroup
	for i, store := range []*Store{first, second} {
		wg.Add(1)
		go func(i int, store *Store) {
			defer wg.Done()
			<-start
			port := int64(22000)
			result, err := store.ReserveResources(context.Background(), ReserveRequest{
				Header: mutation(
					fmt.Sprintf("race-%d", i),
					fmt.Sprintf("hash-%d", i),
					9,
					3,
				),
				Reservations: []Reservation{{
					ID:            fmt.Sprintf("reservation-%d", i),
					ResourceKind:  "relay",
					ResourceID:    fmt.Sprintf("relay-%d", i),
					ListenPort:    &port,
					CapacityKind:  "relay",
					CapacityUnits: 1,
				}},
			})
			outcomes <- outcome{result: result, err: err}
		}(i, store)
	}
	close(start)
	wg.Wait()
	close(outcomes)

	var successes, collisions int
	for outcome := range outcomes {
		switch {
		case outcome.err == nil:
			successes++
			if outcome.result.InventoryGeneration != 1 {
				t.Errorf("winning inventory generation = %d, want 1",
					outcome.result.InventoryGeneration)
			}
		case ErrorCodeOf(outcome.err) == CodePortInUse:
			collisions++
		default:
			t.Errorf("unexpected race result: %v", outcome.err)
		}
	}
	if successes != 1 || collisions != 1 {
		t.Fatalf("successes=%d collisions=%d, want 1 and 1", successes, collisions)
	}
}

func TestCollisionDiagnostics(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "appliance.db"))
	installTestAuthority(t, store, 2, 7)
	ctx := context.Background()

	subnet := int64(4)
	port := int64(23000)
	mark := int64(1004)
	_, err := store.ReserveResources(ctx, ReserveRequest{
		Header: mutation("first", "hash-first", 2, 7),
		Reservations: []Reservation{{
			ID:            "reservation-first",
			ResourceKind:  "guest",
			ResourceID:    "guest-first",
			NetworkID:     "network-first",
			SubnetIndex:   &subnet,
			IPv4:          "10.80.1.10",
			MAC:           "02:00:00:00:00:04",
			ListenPort:    &port,
			ConntrackMark: &mark,
			CapacityKind:  "guest",
			CapacityUnits: 1,
		}},
	})
	if err != nil {
		t.Fatalf("first reservation: %v", err)
	}

	_, err = store.ReserveResources(ctx, ReserveRequest{
		Header: mutation("second", "hash-second", 2, 7),
		Reservations: []Reservation{{
			ID:           "reservation-second",
			ResourceKind: "network",
			ResourceID:   "network-second",
			SubnetIndex:  &subnet,
			ListenPort:   &port,
		}},
	})
	var collision *CollisionError
	if !errors.As(err, &collision) {
		t.Fatalf("second reservation error = %T %v, want *CollisionError", err, err)
	}
	if collision.Code != CodeSubnetInUse {
		t.Errorf("collision code = %s, want %s", collision.Code, CodeSubnetInUse)
	}
	if collision.InventoryGeneration != 1 {
		t.Errorf("inventory generation = %d, want 1", collision.InventoryGeneration)
	}
	if collision.Summary.LiveReservations != 1 ||
		collision.Summary.Subnets != 1 ||
		collision.Summary.Ports != 1 {
		t.Errorf("unexpected collision summary: %+v", collision.Summary)
	}
	if got := collision.Summary.Capacity["guest"]; got.Used != 1 || got.Limit != 100 {
		t.Errorf("guest capacity = %+v, want used=1 limit=100", got)
	}
	if len(collision.Collisions) != 2 {
		t.Fatalf("collisions = %+v, want subnet and port", collision.Collisions)
	}
	if collision.Collisions[0].ExistingResourceID != "guest-first" {
		t.Errorf("existing resource = %q, want guest-first",
			collision.Collisions[0].ExistingResourceID)
	}

	if err := store.SetCapacityLimit(ctx, "guest", 1); err != nil {
		t.Fatalf("SetCapacityLimit: %v", err)
	}
	_, err = store.ReserveResources(ctx, ReserveRequest{
		Header: mutation("capacity", "hash-capacity", 2, 7),
		Reservations: []Reservation{{
			ID:            "reservation-capacity",
			ResourceKind:  "guest",
			ResourceID:    "guest-capacity",
			CapacityKind:  "guest",
			CapacityUnits: 1,
		}},
	})
	if ErrorCodeOf(err) != CodeCapacityExhausted {
		t.Fatalf("capacity error = %v, want %s", err, CodeCapacityExhausted)
	}
}

func TestReservationTombstoneReuse(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "appliance.db"))
	installTestAuthority(t, store, 5, 2)
	ctx := context.Background()
	port := int64(24000)

	reserve := func(mutationID, reservationID, resourceID string) ReserveResult {
		t.Helper()
		result, err := store.ReserveResources(ctx, ReserveRequest{
			Header: mutation(mutationID, "hash-"+mutationID, 5, 2),
			Reservations: []Reservation{{
				ID:           reservationID,
				ResourceKind: "relay",
				ResourceID:   resourceID,
				ListenPort:   &port,
			}},
		})
		if err != nil {
			t.Fatalf("ReserveResources(%s): %v", mutationID, err)
		}
		return result
	}

	first := reserve("reserve-old", "reservation-old", "relay-old")
	_, err := store.ReleaseResources(ctx, ReleaseRequest{
		Header:         mutation("release-old", "hash-release-old", 5, 2),
		ReservationIDs: []string{first.Reservations[0].ID},
	})
	if err != nil {
		t.Fatalf("ReleaseResources: %v", err)
	}
	reserve("reserve-new", "reservation-new", "relay-new")

	history, err := store.ListReservations(ctx, true)
	if err != nil {
		t.Fatalf("ListReservations: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("history length = %d, want 2", len(history))
	}
	byID := make(map[string]Reservation, len(history))
	for _, reservation := range history {
		byID[reservation.ID] = reservation
	}
	old := byID["reservation-old"]
	if old.RetiredAtUnix == nil || old.State != "retired" {
		t.Errorf("old reservation was not retained as a tombstone: %+v", old)
	}
	fresh := byID["reservation-new"]
	if fresh.RetiredAtUnix != nil || fresh.State != "active" {
		t.Errorf("new reservation is not active: %+v", fresh)
	}
}

func TestMutationHashReplayAndConflict(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "appliance.db"))
	installTestAuthority(t, store, 4, 1)
	ctx := context.Background()
	port := int64(25000)
	req := ReserveRequest{
		Header: mutation("stable-mutation", "stable-hash", 4, 1),
		Reservations: []Reservation{{
			ID:           "reservation-stable",
			ResourceKind: "relay",
			ResourceID:   "relay-stable",
			ListenPort:   &port,
		}},
	}
	first, err := store.ReserveResources(ctx, req)
	if err != nil {
		t.Fatalf("first ReserveResources: %v", err)
	}
	replayed, err := store.ReserveResources(ctx, req)
	if err != nil {
		t.Fatalf("replayed ReserveResources: %v", err)
	}
	if !replayed.Replay {
		t.Fatal("replayed result did not report Replay")
	}
	if replayed.InventoryGeneration != first.InventoryGeneration {
		t.Errorf("replay changed inventory generation: got %d want %d",
			replayed.InventoryGeneration, first.InventoryGeneration)
	}
	req.Header.SemanticHash = "different-hash"
	_, err = store.ReserveResources(ctx, req)
	if ErrorCodeOf(err) != CodeResumeMismatch {
		t.Fatalf("different hash error = %v, want %s", err, CodeResumeMismatch)
	}
	live, err := store.ListReservations(ctx, false)
	if err != nil {
		t.Fatalf("ListReservations: %v", err)
	}
	if len(live) != 1 {
		t.Fatalf("live reservations = %d, want 1", len(live))
	}
}

func TestGenerationFenceAndParentRejection(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "appliance.db"))
	installTestAuthority(t, store, 11, 6)
	ctx := context.Background()
	port := int64(26000)

	_, err := store.ReserveResources(ctx, ReserveRequest{
		Header: mutation("bad-fence", "hash-bad-fence", 10, 6),
		Reservations: []Reservation{{
			ID: "bad-fence-reservation", ResourceKind: "relay",
			ResourceID: "bad-fence-relay", ListenPort: &port,
		}},
	})
	if ErrorCodeOf(err) != CodeFenceRejected {
		t.Fatalf("bad fence error = %v, want %s", err, CodeFenceRejected)
	}

	_, err = store.ReserveResources(ctx, ReserveRequest{
		Header: mutation("bad-parent", "hash-bad-parent", 11, 5),
		Reservations: []Reservation{{
			ID: "bad-parent-reservation", ResourceKind: "relay",
			ResourceID: "bad-parent-relay", ListenPort: &port,
		}},
	})
	if ErrorCodeOf(err) != CodeParentGeneration {
		t.Fatalf("bad parent error = %v, want %s", err, CodeParentGeneration)
	}

	header := mutation("network-create", "hash-network-create", 11, 6)
	header.ResourceID = "network-1"
	header.NewGeneration = 1
	mustReserve(t, store, 11, 6, Reservation{
		ID:           "network-1-reservation",
		ResourceKind: "network",
		ResourceID:   "network-1",
		MAC:          "02:00:00:00:10:01",
	})
	_, err = store.StageNetwork(ctx, header, Network{
		ID:             "network-1",
		CIDR:           "10.80.0.0/26",
		GatewayIPv4:    "10.80.0.1",
		NICMAC:         "02:00:00:00:10:01",
		DNSServersJSON: "[]",
	})
	if err != nil {
		t.Fatalf("StageNetwork create: %v", err)
	}
	stale := mutation("network-stale", "hash-network-stale", 11, 6)
	stale.ResourceID = "network-1"
	stale.NewGeneration = 1
	_, err = store.StageNetwork(ctx, stale, Network{
		ID:             "network-1",
		CIDR:           "10.80.0.0/26",
		GatewayIPv4:    "10.80.0.1",
		NICMAC:         "02:00:00:00:10:01",
		DNSServersJSON: "[]",
	})
	if ErrorCodeOf(err) != CodeGenerationConflict {
		t.Fatalf("stale generation error = %v, want %s", err, CodeGenerationConflict)
	}

	mustReserve(t, store, 11, 6, Reservation{
		ID:           "network-2-reservation",
		ResourceKind: "network",
		ResourceID:   "network-2",
		MAC:          "02:00:00:00:10:02",
	})
	currentAuthority, err := store.Authority(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.InstallAuthority(ctx, Authority{
		PhysicalHostID:       "host-1",
		HostLeaseID:          "lease-1",
		HostLeaseSecretHash:  "secret-hash",
		HostLeaseExpiresUnix: currentAuthority.HostLeaseExpiresUnix,
		Fence:                11,
		ParentGeneration:     6,
		ParentState:          "frozen",
	}); err != nil {
		t.Fatalf("freeze authority: %v", err)
	}
	frozen := mutation("network-frozen", "hash-network-frozen", 11, 6)
	frozen.ResourceID = "network-2"
	frozen.NewGeneration = 1
	_, err = store.StageNetwork(ctx, frozen, Network{
		ID:             "network-2",
		CIDR:           "10.80.0.64/26",
		GatewayIPv4:    "10.80.0.65",
		NICMAC:         "02:00:00:00:10:02",
		DNSServersJSON: "[]",
	})
	if ErrorCodeOf(err) != CodeParentFrozen {
		t.Fatalf("frozen parent error = %v, want %s", err, CodeParentFrozen)
	}
}

func TestExpiredAuthorityRejectsExternalMutation(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "appliance.db"))
	installTestAuthority(t, store, 13, 4)
	if _, err := store.db.ExecContext(context.Background(), `
		UPDATE appliance_authority SET host_lease_expires_unix = ?
		WHERE singleton = 1
	`, time.Now().Add(-time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	header := mutation("expired-authority", "expired-authority-hash", 13, 4)
	header.ResourceID = "network-expired"
	header.NewGeneration = 1
	if _, err := store.StageNetwork(context.Background(), header, Network{
		ID: "network-expired", CIDR: "10.80.0.0/26",
		GatewayIPv4: "10.80.0.1", NICMAC: "02:00:00:00:80:01",
		DNSServersJSON: "[]",
	}); ErrorCodeOf(err) != CodeFenceRejected {
		t.Fatalf("expired mutation error = %v, want %s", err, CodeFenceRejected)
	}
}

func TestIntentRecoveryAndCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "appliance.db")
	store := openTestStore(t, path)
	installTestAuthority(t, store, 8, 2)
	ctx := context.Background()
	header := mutation("network-intent", "hash-network-intent", 8, 2)
	header.ResourceID = "network-intent"
	header.NewGeneration = 1
	mustReserve(t, store, 8, 2, Reservation{
		ID:           "network-intent-reservation",
		ResourceKind: "network",
		ResourceID:   "network-intent",
		MAC:          "02:00:00:00:20:01",
	})

	stage, err := store.StageNetwork(ctx, header, Network{
		ID:             "network-intent",
		CIDR:           "10.81.0.0/26",
		GatewayIPv4:    "10.81.0.1",
		NICMAC:         "02:00:00:00:20:01",
		DNSServersJSON: `["10.0.0.1"]`,
	})
	if err != nil {
		t.Fatalf("StageNetwork: %v", err)
	}

	if stage.Intent.Phase != "pending" {
		t.Fatalf("intent phase = %q, want pending", stage.Intent.Phase)
	}
	if err := store.UpdateIntent(ctx, header.MutationID, header.SemanticHash,
		"compiled", "compiled-hash", ""); err != nil {
		t.Fatalf("UpdateIntent: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	intents, err := reopened.RecoveryIntents(ctx)
	if err != nil {
		t.Fatalf("RecoveryIntents: %v", err)
	}
	if len(intents) != 1 || intents[0].CompiledHash != "compiled-hash" ||
		intents[0].Phase != "compiled" {
		t.Fatalf("recovery intents = %+v", intents)
	}
	_, err = reopened.CommitIntent(ctx, CommitIntentRequest{
		MutationID:   header.MutationID,
		SemanticHash: header.SemanticHash,
		CompiledHash: "compiled-hash",
		HostFence:    8,
		Result:       []byte(`{"ok":true}`),
	})
	if err != nil {
		t.Fatalf("CommitIntent: %v", err)
	}
	network, found, err := reopened.Network(ctx, "network-intent")
	if err != nil || !found {
		t.Fatalf("Network: found=%v err=%v", found, err)
	}
	if network.DesiredGeneration != 1 ||
		network.AppliedGeneration != 1 ||
		network.ObservedGeneration != 1 {
		t.Errorf("network generations = desired:%d applied:%d observed:%d",
			network.DesiredGeneration, network.AppliedGeneration,
			network.ObservedGeneration)
	}
	intents, err = reopened.RecoveryIntents(ctx)
	if err != nil {
		t.Fatalf("RecoveryIntents after commit: %v", err)
	}
	if len(intents) != 0 {
		t.Fatalf("recovery intents after commit = %+v, want none", intents)
	}
}

func TestSetParentLifecycleCannotBeThawedByNewFence(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "appliance.db"))
	installTestAuthority(t, store, 8, 2)
	ctx := context.Background()
	current, err := store.Authority(ctx)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("exact frozen cascade items", func(t *testing.T) {
		store := openTestStore(t, filepath.Join(t.TempDir(), "appliance.db"))
		installTestAuthority(t, store, 14, 2)
		ctx := context.Background()
		mustReserve(t, store, 14, 2, Reservation{
			ID: "network-cascade-reservation", ResourceKind: "network",
			ResourceID: "network-cascade", MAC: "02:00:00:00:90:01",
		})
		create := mutation("network-cascade-create", "hash-network-cascade-create", 14, 2)
		create.ResourceID = "network-cascade"
		create.NewGeneration = 1
		if _, err := store.StageNetwork(ctx, create, Network{
			ID: "network-cascade", CIDR: "10.90.0.0/26",
			GatewayIPv4: "10.90.0.1", NICMAC: "02:00:00:00:90:01",
			DNSServersJSON: "[]",
		}); err != nil {
			t.Fatal(err)
		}
		commitTestIntent(t, store, create)

		authority, err := store.Authority(ctx)
		if err != nil {
			t.Fatal(err)
		}
		const (
			operationID = "11111111-1111-4111-8111-111111111111"
			itemID      = "22222222-2222-4222-8222-222222222222"
		)
		if _, err := store.SetParentLifecycle(
			ctx, authority, 2, 3, "frozen", operationID, "r1-exact",
			"exact-plan-hash", []CascadeAuthorityItem{{
				ItemID: itemID, ResourceKind: "network",
				ResourceID:         "network-cascade",
				Action:             string(cascadeauth.ActionNetworkRemove),
				ExpectedGeneration: 1,
			}},
		); err != nil {
			t.Fatal(err)
		}
		header := mutation("network-cascade-remove", "hash-network-cascade-remove", 14, 3)
		header.ResourceID = "network-cascade"
		header.ExpectedGeneration = 1
		header.NewGeneration = 2
		header.CascadeOperationID = operationID
		header.CascadePlanRevision = "r1-exact"
		header.CascadePlanHash = "exact-plan-hash"
		header.CascadeItemID = itemID
		header.CascadeResourceKind = "network"
		header.CascadeAction = string(cascadeauth.ActionNetworkRemove)

		for name, mutate := range map[string]func(*MutationHeader){
			"resource": func(value *MutationHeader) { value.ResourceID = "other-network" },
			"kind":     func(value *MutationHeader) { value.CascadeResourceKind = "vm" },
			"action": func(value *MutationHeader) {
				value.CascadeAction = string(cascadeauth.ActionPrivateSwitchDelete)
			},
			"generation": func(value *MutationHeader) {
				value.ExpectedGeneration = 2
				value.NewGeneration = 3
			},
		} {
			t.Run(name, func(t *testing.T) {
				reused := header
				reused.MutationID += "-" + name
				reused.SemanticHash += "-" + name
				mutate(&reused)
				if _, err := store.StageNetwork(ctx, reused, Network{
					ID: reused.ResourceID, CIDR: "10.90.0.0/26",
					GatewayIPv4: "10.90.0.1", NICMAC: "02:00:00:00:90:01",
					DNSServersJSON: "[]",
				}); ErrorCodeOf(err) != CodeParentFrozen {
					t.Fatalf("reused item error = %v, want %s", err, CodeParentFrozen)
				}
			})
		}
		if _, err := store.StageNetwork(ctx, header, Network{
			ID: "network-cascade", CIDR: "10.90.0.0/26",
			GatewayIPv4: "10.90.0.1", NICMAC: "02:00:00:00:90:01",
			DNSServersJSON: "[]", State: "removing",
		}); err != nil {
			t.Fatalf("exact approved item rejected: %v", err)
		}
	})
	frozen, err := store.SetParentLifecycle(
		ctx, current, 2, 3, "frozen",
		"11111111-1111-4111-8111-111111111111",
		"r1-plan", strings.Repeat("a", 64),
		testCascadeAuthorityItems("33333333-3333-4333-8333-333333333333", 1),
	)
	if err != nil {
		t.Fatal(err)
	}
	if frozen.ParentState != "frozen" || frozen.ParentGeneration != 3 {
		t.Fatalf("frozen authority = %+v", frozen)
	}
	thaw := frozen
	thaw.Fence = 9
	thaw.HostLeaseID = "lease-2"
	thaw.HostLeaseSecretHash = "secret-hash-2"
	thaw.HostLeaseExpiresUnix = time.Now().Add(time.Hour).Unix()
	thaw.ParentState = "active"
	err = store.InstallAuthority(ctx, thaw)
	if ErrorCodeOf(err) != CodeParentFrozen {
		t.Fatalf("thaw error = %v, want %s", err, CodeParentFrozen)
	}
}

func TestDrainingNATPersistsOnReopenForSystemCompletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "appliance.db")
	store := openTestStore(t, path)
	installTestAuthority(t, store, 12, 4)
	ctx := context.Background()

	networkHeader := mutation("nat-network", "hash-nat-network", 12, 4)
	networkHeader.ResourceID = "network-nat"
	networkHeader.NewGeneration = 1
	mustReserve(t, store, 12, 4, Reservation{
		ID:            "network-nat-reservation",
		ResourceKind:  "network",
		ResourceID:    "network-nat",
		MAC:           "02:00:00:00:30:01",
		CapacityKind:  "network",
		CapacityUnits: 1,
	})
	if _, err := store.StageNetwork(ctx, networkHeader, Network{
		ID:             "network-nat",
		CIDR:           "10.82.0.0/26",
		GatewayIPv4:    "10.82.0.1",
		NICMAC:         "02:00:00:00:30:01",
		DNSServersJSON: "[]",
	}); err != nil {
		t.Fatalf("StageNetwork: %v", err)
	}

	guestHeader := mutation("nat-guest", "hash-nat-guest", 12, 1)
	guestHeader.ResourceID = "guest-nat"
	guestHeader.ParentResourceID = "network-nat"
	guestHeader.NewGeneration = 1
	mark := int64(501)
	mustReserve(t, store, 12, 4, Reservation{
		ID:            "guest-nat-reservation",
		ResourceKind:  "guest",
		ResourceID:    "guest-nat",
		NetworkID:     "network-nat",
		IPv4:          "10.82.0.10",
		MAC:           "02:00:00:00:30:10",
		ConntrackMark: &mark,
		CapacityKind:  "guest",
		CapacityUnits: 1,
	})
	if _, err := store.StageGuest(ctx, guestHeader, Guest{
		ID:        "guest-nat",
		NetworkID: "network-nat",
		IPv4:      "10.82.0.10",
		MAC:       "02:00:00:00:30:10",
	}); err != nil {
		t.Fatalf("StageGuest: %v", err)
	}

	port := int64(27000)
	mustReserve(t, store, 12, 4, Reservation{
		ID:            "relay-nat-reservation",
		ResourceKind:  "relay",
		ResourceID:    "relay-nat",
		ListenPort:    &port,
		CapacityKind:  "relay",
		CapacityUnits: 1,
	})
	relayHeader := mutation("nat-relay", "hash-nat-relay", 12, 1)
	relayHeader.ResourceID = "relay-nat"
	relayHeader.ParentResourceID = "guest-nat"
	relayHeader.NewGeneration = 1
	if _, err := store.StageRelay(ctx, relayHeader, Relay{
		ID:         "relay-nat",
		VMID:       "guest-nat",
		ListenPort: port,
		TargetIPv4: "10.82.0.10",
		State:      "bound",
	}); err != nil {
		t.Fatalf("StageRelay: %v", err)
	}

	drainStarted := int64(12345)
	natHeader := mutation("nat-draining", "hash-nat-draining", 12, 1)
	natHeader.ResourceID = "guest-nat"
	natHeader.ParentResourceID = "guest-nat"
	natHeader.NewGeneration = 1
	if _, err := store.StageNAT(ctx, natHeader, NATState{
		VMID:             "guest-nat",
		State:            "draining",
		ConntrackMark:    mark,
		DrainStartedUnix: &drainStarted,
	}); err != nil {
		t.Fatalf("StageNAT: %v", err)
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snapshot.Networks) != 1 || len(snapshot.Guests) != 1 ||
		len(snapshot.Relays) != 1 || len(snapshot.NAT) != 1 ||
		len(snapshot.Reservations) != 3 {
		t.Fatalf("incomplete desired snapshot: %+v", snapshot)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	nat, found, err := reopened.NAT(ctx, "guest-nat")
	if err != nil || !found {
		t.Fatalf("NAT: found=%v err=%v", found, err)
	}
	if nat.State != "draining" || nat.DrainStartedUnix == nil ||
		*nat.DrainStartedUnix != drainStarted {
		t.Fatalf("reopened NAT = %+v, want preserved draining transition", nat)
	}
}

func TestMigrationReopenAndNewerSchemaRejection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "appliance.db")
	store := openTestStore(t, path)
	ctx := context.Background()
	version, err := store.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if version != CurrentSchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, CurrentSchemaVersion)
	}
	mode, err := store.JournalMode(ctx)
	if err != nil || mode != "wal" {
		t.Fatalf("journal mode = %q err=%v, want wal", mode, err)
	}
	foreignKeys, err := store.ForeignKeysEnabled(ctx)
	if err != nil || !foreignKeys {
		t.Fatalf("foreign keys enabled = %v err=%v, want true", foreignKeys, err)
	}
	busyTimeout, err := store.BusyTimeout(ctx)
	if err != nil || busyTimeout != 5000 {
		t.Fatalf("busy timeout = %d err=%v, want 5000", busyTimeout, err)
	}
	if err := store.SetReadiness(ctx, false, "intent recovery required"); err != nil {
		t.Fatalf("SetReadiness: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	status, err := reopened.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Ready || status.Error != "intent recovery required" {
		t.Fatalf("reopened status = %+v", status)
	}
	if _, err := reopened.db.ExecContext(ctx,
		"UPDATE appliance_meta SET value = '999' WHERE key = 'schema_version'",
	); err != nil {
		t.Fatalf("set newer schema: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("close newer schema: %v", err)
	}
	_, err = Open(path)
	if ErrorCodeOf(err) != CodeUnsupportedSchema {
		t.Fatalf("newer schema error = %v, want %s", err, CodeUnsupportedSchema)
	}
}
