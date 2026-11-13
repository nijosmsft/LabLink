package isolatedstate

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestOpenCreatesInitialSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "isolated.db")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	if store.Path() != path {
		t.Fatalf("Path = %q, want %q", store.Path(), path)
	}
	version, err := store.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if version != CurrentSchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", version, CurrentSchemaVersion)
	}

	for _, table := range []string{
		"orchestrators", "private_networks", "isolated_vms",
		"relay_allocations", "nat_allocations",
		"active_resource_allocations", "resource_allocation_history",
		"operations", "operation_phases", "operation_events",
		"locks", "lock_fences", "cascade_authorities",
		"cascade_authority_items",
	} {
		var count int
		if err := store.QueryRowContext(context.Background(), `
			SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`,
			table,
		).Scan(&count); err != nil {
			t.Fatalf("find table %s: %v", table, err)
		}
		if count != 1 {
			t.Errorf("table %s count = %d, want 1", table, count)
		}
	}
}

func TestUpgradeSeedsDurableLockFences(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "isolated.db")
	v1, err := openWithMigrations(path, schemaMigrations[:1])
	if err != nil {
		t.Fatalf("open v1: %v", err)
	}
	mustExec(t, v1, ctx, `
		INSERT INTO locks (
			lock_key, holder_cookie, holder_hostname, holder_pid,
			holder_process_start_unix, operation_id, fence, acquired_at_unix,
			heartbeat_at_unix, expires_at_unix
		) VALUES ('network:network-1', 'cookie', 'host', 1, 1, 'op', 7, 1, 1, 2)`)
	if err := v1.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer upgraded.Close()
	var fence int64
	if err := upgraded.QueryRowContext(ctx, `
		SELECT last_fence FROM lock_fences WHERE lock_key='network:network-1'`,
	).Scan(&fence); err != nil {
		t.Fatal(err)
	}
	if fence != 7 {
		t.Fatalf("seeded fence=%d, want 7", fence)
	}
}

func TestOpenConfiguresWALAndForeignKeys(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "isolated.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	var journalMode string
	if err := store.QueryRowContext(context.Background(), "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("journal_mode: %v", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		t.Fatalf("journal_mode = %q, want wal", journalMode)
	}

	var foreignKeys int
	if err := store.QueryRowContext(context.Background(), "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatalf("foreign_keys: %v", err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys = %d, want 1", foreignKeys)
	}
}

func TestReopenPreservesSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "isolated.db")
	first, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if _, err := first.ExecContext(context.Background(), `
		INSERT INTO schema_meta(key, value) VALUES ('reopen_marker', 'present')`); err != nil {
		t.Fatalf("insert marker: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	second, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer second.Close()

	var value string
	if err := second.QueryRowContext(context.Background(), `
		SELECT value FROM schema_meta WHERE key='reopen_marker'`).Scan(&value); err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if value != "present" {
		t.Fatalf("marker = %q, want present", value)
	}
}

func TestConcurrentOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "isolated.db")
	const workers = 8
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			store, err := Open(path)
			if err != nil {
				errs <- err
				return
			}
			defer store.Close()
			version, err := store.SchemaVersion(context.Background())
			if err != nil {
				errs <- err
				return
			}
			if version != CurrentSchemaVersion {
				errs <- &unexpectedVersionError{got: version}
			}
		}()
	}

	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent Open: %v", err)
	}
}

type unexpectedVersionError struct {
	got int
}

func (e *unexpectedVersionError) Error() string {
	return "unexpected schema version"
}

func TestMigrationFailureIsAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "isolated.db")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open v1: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close v1: %v", err)
	}

	broken := append([]migration(nil), schemaMigrations...)
	broken = append(broken, migration{
		version: CurrentSchemaVersion + 1,
		sql: `
			CREATE TABLE migration_probe (id INTEGER PRIMARY KEY);
			THIS IS NOT VALID SQL;
		`,
	})
	if failed, err := openWithMigrations(path, broken); err == nil {
		_ = failed.Close()
		t.Fatal("broken migration unexpectedly succeeded")
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen after failed migration: %v", err)
	}
	defer reopened.Close()
	version, err := reopened.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if version != CurrentSchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", version, CurrentSchemaVersion)
	}
	var count int
	if err := reopened.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM sqlite_master
		WHERE type='table' AND name='migration_probe'`).Scan(&count); err != nil {
		t.Fatalf("find migration_probe: %v", err)
	}
	if count != 0 {
		t.Fatalf("migration_probe count = %d, want 0 after rollback", count)
	}
}

func TestLiveUniquenessAllowsTombstoneAndAllocationReuse(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "isolated.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	mustExec(t, store, ctx, `
		INSERT INTO orchestrators (
			id, display_name, physical_host_id, host_node, hyperv_name,
			node_name, profile_name, main_vswitch, lifecycle_state,
			created_at_unix, updated_at_unix
		) VALUES ('orch', 'display', 'host-id', 'host-node', 'orch-hv',
		          'orch-node', 'profile', 'main-switch', 'ready', 1, 1)`)
	insertNetwork(t, store, ctx, "network-1")
	insertVM(t, store, ctx, "vm-1", "network-1")
	insertRelay(t, store, ctx, "relay-1", "vm-1")

	if _, err := store.ExecContext(ctx, networkInsertSQL, "network-conflict"); err == nil {
		t.Fatal("duplicate live network allocation unexpectedly succeeded")
	}

	mustExec(t, store, ctx, `UPDATE relay_allocations SET lifecycle_state='removed', retired_at_unix=2 WHERE id='relay-1'`)
	mustExec(t, store, ctx, `UPDATE isolated_vms SET lifecycle_state='deleted', retired_at_unix=2 WHERE id='vm-1'`)
	mustExec(t, store, ctx, `UPDATE private_networks SET lifecycle_state='deleted', retired_at_unix=2 WHERE id='network-1'`)

	insertNetwork(t, store, ctx, "network-2")
	insertVM(t, store, ctx, "vm-2", "network-2")
	insertRelay(t, store, ctx, "relay-2", "vm-2")

	mustExec(t, store, ctx, `
		INSERT INTO active_resource_allocations (
			kind, scope_id, value, resource_id, appliance_reservation_id, allocated_at_unix
		) VALUES ('relay_port', 'orch', '20000', 'relay-2', 'reservation-1', 3)`)
	tx, err := store.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO resource_allocation_history (
			kind, scope_id, value, resource_id, appliance_reservation_id,
			allocated_at_unix, released_at_unix, release_operation_id
		)
		SELECT kind, scope_id, value, resource_id, appliance_reservation_id,
		       allocated_at_unix, 4, 'release-op'
		FROM active_resource_allocations
		WHERE kind='relay_port' AND scope_id='orch' AND value='20000'`); err != nil {
		_ = tx.Rollback()
		t.Fatalf("insert history: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM active_resource_allocations
		WHERE kind='relay_port' AND scope_id='orch' AND value='20000'`); err != nil {
		_ = tx.Rollback()
		t.Fatalf("delete active allocation: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit release: %v", err)
	}

	mustExec(t, store, ctx, `
		INSERT INTO active_resource_allocations (
			kind, scope_id, value, resource_id, appliance_reservation_id, allocated_at_unix
		) VALUES ('relay_port', 'orch', '20000', 'relay-3', 'reservation-2', 5)`)

	var history, active int
	if err := store.QueryRowContext(ctx, `SELECT COUNT(*) FROM resource_allocation_history`).Scan(&history); err != nil {
		t.Fatalf("count history: %v", err)
	}
	if err := store.QueryRowContext(ctx, `SELECT COUNT(*) FROM active_resource_allocations`).Scan(&active); err != nil {
		t.Fatalf("count active: %v", err)
	}
	if history != 1 || active != 1 {
		t.Fatalf("history=%d active=%d, want 1 and 1", history, active)
	}
}

const networkInsertSQL = `
	INSERT INTO private_networks (
		id, orchestrator_id, display_name, hyperv_switch_name, subnet_index,
		cidr, gateway_ipv4, orchestrator_mac, dns_servers_json,
		desired_generation, lifecycle_state, created_at_unix, updated_at_unix
	) VALUES (?, 'orch', 'network display', 'private-switch', 1,
	          '10.0.0.0/26', '10.0.0.1', '00155D000001', '[]',
	          1, 'ready', 1, 1)`

func insertNetwork(t *testing.T, store *Store, ctx context.Context, id string) {
	t.Helper()
	mustExec(t, store, ctx, networkInsertSQL, id)
}

func insertVM(t *testing.T, store *Store, ctx context.Context, id, networkID string) {
	t.Helper()
	mustExec(t, store, ctx, `
		INSERT INTO isolated_vms (
			id, orchestrator_id, network_id, display_name, hyperv_name,
			node_name, guest_os, profile_name, ipv4, mac, gateway_ipv4,
			dns_servers_json, storage_root, vm_path, vhd_path,
			desired_generation, lifecycle_state, created_at_unix, updated_at_unix
		) VALUES (?, 'orch', ?, 'vm display', 'isolated-vm',
		          'isolated-node', 'linux', 'profile', '10.0.0.2', '00155D000002',
		          '10.0.0.1', '[]', 'C:\VM', 'C:\VM\vm', 'C:\VM\vm\vm.vhdx',
		          1, 'ready', 1, 1)`,
		id, networkID,
	)
}

func insertRelay(t *testing.T, store *Store, ctx context.Context, id, vmID string) {
	t.Helper()
	mustExec(t, store, ctx, `
		INSERT INTO relay_allocations (
			id, vm_id, orchestrator_id, listen_port, target_ipv4,
			desired_generation, lifecycle_state, created_at_unix, updated_at_unix
		) VALUES (?, ?, 'orch', 20000, '10.0.0.2',
		          1, 'ready', 1, 1)`,
		id, vmID,
	)
}

type execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func mustExec(t *testing.T, db execer, ctx context.Context, query string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(ctx, query, args...); err != nil {
		t.Fatalf("ExecContext: %v", err)
	}
}
