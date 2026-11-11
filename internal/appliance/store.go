package appliance

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

type Store struct {
	db   *sql.DB
	path string
	now  func() time.Time
}

func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultDBPath
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("appliance: create database directory: %w", err)
		}
	}

	dsn := fmt.Sprintf(
		"file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)&_txlock=immediate",
		path,
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("appliance: open sqlite: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("appliance: ping sqlite: %w", err)
	}
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("appliance: %s: %w", pragma, err)
		}
	}

	s := &Store{db: db, path: path, now: time.Now}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := s.NormalizeDrainingNAT(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("appliance: normalize draining NAT: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Path() string { return s.path }

func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var value string
	if err := s.db.QueryRowContext(ctx,
		"SELECT value FROM appliance_meta WHERE key = 'schema_version'",
	).Scan(&value); err != nil {
		return 0, err
	}
	version, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("appliance: invalid schema version %q: %w", value, err)
	}
	return version, nil
}

func (s *Store) JournalMode(ctx context.Context) (string, error) {
	var mode string
	err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode)
	return mode, err
}

func (s *Store) ForeignKeysEnabled(ctx context.Context) (bool, error) {
	var enabled int
	err := s.db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&enabled)
	return enabled == 1, err
}

func (s *Store) BusyTimeout(ctx context.Context) (int, error) {
	var milliseconds int
	err := s.db.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&milliseconds)
	return milliseconds, err
}

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("appliance: begin migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS appliance_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`); err != nil {
		return fmt.Errorf("appliance: create migration metadata: %w", err)
	}

	version := 0
	var raw string
	err = tx.QueryRowContext(ctx,
		"SELECT value FROM appliance_meta WHERE key = 'schema_version'",
	).Scan(&raw)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return fmt.Errorf("appliance: read schema version: %w", err)
	default:
		version, err = strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("appliance: invalid schema version %q: %w", raw, err)
		}
	}
	if version > CurrentSchemaVersion {
		return &StoreError{
			Code:    CodeUnsupportedSchema,
			Message: fmt.Sprintf("database schema %d is newer than supported schema %d", version, CurrentSchemaVersion),
		}
	}

	if version < 1 {
		if _, err := tx.ExecContext(ctx, schemaSQL); err != nil {
			return fmt.Errorf("appliance: apply schema migration 1: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO appliance_meta(key, value) VALUES ('schema_version', '1')
			ON CONFLICT(key) DO UPDATE SET value = excluded.value
		`); err != nil {
			return fmt.Errorf("appliance: record schema migration 1: %w", err)
		}
		version = 1
	}
	if version != CurrentSchemaVersion {
		return &StoreError{
			Code:    CodeUnsupportedSchema,
			Message: fmt.Sprintf("no forward migration from schema %d to %d", version, CurrentSchemaVersion),
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("appliance: commit migration: %w", err)
	}
	return nil
}

func (s *Store) Status(ctx context.Context) (Status, error) {
	return readStatus(ctx, s.db)
}

func (s *Store) SetReadiness(ctx context.Context, ready bool, errorText string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `
		UPDATE appliance_status
		SET ready = ?, error_text = ?, updated_at_unix = ?
		WHERE singleton = 1
	`, boolInt(ready), errorText, s.now().Unix())
	if err != nil {
		return fmt.Errorf("appliance: set readiness: %w", err)
	}
	return tx.Commit()
}

func (s *Store) Authority(ctx context.Context) (Authority, error) {
	return readAuthority(ctx, s.db)
}

func (s *Store) InstallAuthority(ctx context.Context, next Authority) error {
	if next.ParentState == "" {
		next.ParentState = "active"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	current, err := readAuthority(ctx, tx)
	if err != nil {
		return err
	}
	if next.Fence < current.Fence {
		return storeError(CodeFenceRejected, "cannot install fence %d below current fence %d", next.Fence, current.Fence)
	}
	if next.ParentGeneration < current.ParentGeneration {
		return storeError(CodeParentGeneration, "cannot reduce parent generation from %d to %d",
			current.ParentGeneration, next.ParentGeneration)
	}
	if next.Fence == current.Fence && current.Fence != 0 {
		if current.PhysicalHostID != "" && next.PhysicalHostID != current.PhysicalHostID {
			return storeError(CodeFenceRejected, "same fence belongs to a different physical host")
		}
		if current.HostLeaseID != "" && next.HostLeaseID != current.HostLeaseID {
			return storeError(CodeFenceRejected, "same fence belongs to a different host lease")
		}
		if current.HostLeaseSecretHash != "" && next.HostLeaseSecretHash != current.HostLeaseSecretHash {
			return storeError(CodeFenceRejected, "same fence has a different lease secret hash")
		}
	}
	if !validParentState(next.ParentState) {
		return storeError(CodeInvalidArgument, "invalid parent state %q", next.ParentState)
	}
	next.UpdatedAtUnix = s.now().Unix()
	_, err = tx.ExecContext(ctx, `
		UPDATE appliance_authority SET
			physical_host_id = ?,
			host_lease_id = ?,
			host_lease_secret_hash = ?,
			host_lease_expires_unix = ?,
			fence = ?,
			parent_generation = ?,
			parent_state = ?,
			handoff_pending = ?,
			updated_at_unix = ?
		WHERE singleton = 1
	`, next.PhysicalHostID, next.HostLeaseID, next.HostLeaseSecretHash,
		next.HostLeaseExpiresUnix, next.Fence, next.ParentGeneration,
		next.ParentState, boolInt(next.HandoffPending), next.UpdatedAtUnix)
	if err != nil {
		return fmt.Errorf("appliance: install authority: %w", err)
	}
	return tx.Commit()
}

func (s *Store) SetCapacityLimit(ctx context.Context, kind string, maxUnits int64) error {
	kind = strings.TrimSpace(kind)
	if kind == "" || maxUnits < 0 {
		return storeError(CodeInvalidArgument, "capacity kind must be non-empty and max units non-negative")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO capacity_limits(kind, max_units) VALUES (?, ?)
		ON CONFLICT(kind) DO UPDATE SET max_units = excluded.max_units
	`, kind, maxUnits)
	if err != nil {
		return fmt.Errorf("appliance: set capacity limit: %w", err)
	}
	if _, err := bumpInventoryGeneration(ctx, tx, s.now().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ReserveResources(ctx context.Context, req ReserveRequest) (ReserveResult, error) {
	if err := validateMutationHeader(req.Header, false); err != nil {
		return ReserveResult{}, err
	}
	if len(req.Reservations) == 0 {
		return ReserveResult{}, storeError(CodeInvalidArgument, "at least one reservation is required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ReserveResult{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if result, found, err := replayReserve(ctx, tx, req.Header); err != nil {
		return ReserveResult{}, err
	} else if found {
		result.Replay = true
		return result, nil
	}
	authority, err := validateAuthority(ctx, tx, req.Header, s.now())
	if err != nil {
		return ReserveResult{}, err
	}

	now := s.now().Unix()
	accepted := make([]Reservation, len(req.Reservations))
	copy(accepted, req.Reservations)
	for i := range accepted {
		if err := normalizeReservation(&accepted[i], req.Header, now); err != nil {
			return ReserveResult{}, err
		}
	}

	collisions, err := findCollisions(ctx, tx, accepted)
	if err != nil {
		return ReserveResult{}, err
	}
	if len(collisions) != 0 {
		status, statusErr := readStatus(ctx, tx)
		if statusErr != nil {
			return ReserveResult{}, statusErr
		}
		summary, summaryErr := inventorySummary(ctx, tx)
		if summaryErr != nil {
			return ReserveResult{}, summaryErr
		}
		return ReserveResult{}, &CollisionError{
			Code:                collisions[0].Code,
			Collisions:          collisions,
			InventoryGeneration: status.InventoryGeneration,
			Summary:             summary,
		}
	}

	for _, reservation := range accepted {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO reservations (
				id, resource_kind, resource_id, network_id, subnet_index,
				ipv4, mac, listen_port, conntrack_mark, capacity_kind,
				capacity_units, state, parent_generation, created_at_unix,
				retired_at_unix
			) VALUES (?, ?, ?, NULLIF(?, ''), ?, NULLIF(?, ''), NULLIF(?, ''),
				?, ?, NULLIF(?, ''), NULLIF(?, 0), 'active', ?, ?, NULL)
		`, reservation.ID, reservation.ResourceKind, reservation.ResourceID,
			reservation.NetworkID, reservation.SubnetIndex, reservation.IPv4,
			reservation.MAC, reservation.ListenPort, reservation.ConntrackMark,
			reservation.CapacityKind, reservation.CapacityUnits,
			reservation.ParentGeneration, reservation.CreatedAtUnix)
		if err != nil {
			return ReserveResult{}, fmt.Errorf("appliance: insert reservation %s: %w", reservation.ID, err)
		}
	}
	inventoryGeneration, err := bumpInventoryGeneration(ctx, tx, now)
	if err != nil {
		return ReserveResult{}, err
	}
	result := ReserveResult{
		Reservations:        accepted,
		ParentGeneration:    authority.ParentGeneration,
		InventoryGeneration: inventoryGeneration,
	}
	if err := recordApplied(ctx, tx, req.Header, result, now); err != nil {
		return ReserveResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return ReserveResult{}, fmt.Errorf("appliance: commit reservation: %w", err)
	}
	return result, nil
}

func (s *Store) ReleaseResources(ctx context.Context, req ReleaseRequest) (ReleaseResult, error) {
	if err := validateMutationHeader(req.Header, false); err != nil {
		return ReleaseResult{}, err
	}
	if len(req.ReservationIDs) == 0 {
		return ReleaseResult{}, storeError(CodeInvalidArgument, "at least one reservation ID is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ReleaseResult{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if result, found, err := replayRelease(ctx, tx, req.Header); err != nil {
		return ReleaseResult{}, err
	} else if found {
		result.Replay = true
		return result, nil
	}
	authority, err := validateAuthority(ctx, tx, req.Header, s.now())
	if err != nil {
		return ReleaseResult{}, err
	}
	now := s.now().Unix()
	retired := make([]string, 0, len(req.ReservationIDs))
	seen := make(map[string]struct{}, len(req.ReservationIDs))
	for _, id := range req.ReservationIDs {
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		result, err := tx.ExecContext(ctx, `
			UPDATE reservations
			SET state = 'retired', retired_at_unix = ?
			WHERE id = ? AND retired_at_unix IS NULL
		`, now, id)
		if err != nil {
			return ReleaseResult{}, fmt.Errorf("appliance: retire reservation %s: %w", id, err)
		}
		n, err := result.RowsAffected()
		if err != nil {
			return ReleaseResult{}, err
		}
		if n != 1 {
			return ReleaseResult{}, storeError(CodeNotFound, "live reservation %q not found", id)
		}
		retired = append(retired, id)
	}
	inventoryGeneration, err := bumpInventoryGeneration(ctx, tx, now)
	if err != nil {
		return ReleaseResult{}, err
	}
	result := ReleaseResult{
		RetiredIDs:          retired,
		ParentGeneration:    authority.ParentGeneration,
		InventoryGeneration: inventoryGeneration,
	}
	if err := recordApplied(ctx, tx, req.Header, result, now); err != nil {
		return ReleaseResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return ReleaseResult{}, fmt.Errorf("appliance: commit reservation release: %w", err)
	}
	return result, nil
}

func (s *Store) ListReservations(ctx context.Context, includeRetired bool) ([]Reservation, error) {
	return listReservations(ctx, s.db, includeRetired)
}

func listReservations(
	ctx context.Context,
	q queryer,
	includeRetired bool,
) ([]Reservation, error) {
	query := `
		SELECT id, resource_kind, resource_id, COALESCE(network_id, ''),
			subnet_index, COALESCE(ipv4, ''), COALESCE(mac, ''), listen_port,
			conntrack_mark, COALESCE(capacity_kind, ''),
			COALESCE(capacity_units, 0), state, parent_generation,
			created_at_unix, retired_at_unix
		FROM reservations`
	if !includeRetired {
		query += " WHERE retired_at_unix IS NULL"
	}
	query += " ORDER BY created_at_unix, id"
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var reservations []Reservation
	for rows.Next() {
		reservation, err := scanReservation(rows)
		if err != nil {
			return nil, err
		}
		reservations = append(reservations, reservation)
	}
	return reservations, rows.Err()
}

func (s *Store) StageNetwork(ctx context.Context, header MutationHeader, network Network) (StageResult, error) {
	if header.ResourceID == "" {
		header.ResourceID = network.ID
	}
	return s.stage(ctx, header, "network", func(ctx context.Context, tx *sql.Tx) error {
		network.ID = header.ResourceID
		if err := requireReservation(ctx, tx, "network", network.ID, `
			AND mac = ?
		`, network.NICMAC); err != nil {
			return err
		}
		network.DesiredGeneration = header.NewGeneration
		network.ParentGeneration = header.ExpectedParentGeneration
		if network.Incarnation == 0 {
			network.Incarnation = 1
		}
		if network.State == "" {
			network.State = "active"
		}
		if network.DNSServersJSON == "" {
			network.DNSServersJSON = "[]"
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO networks (
				id, cidr, gateway_ipv4, nic_mac, interface_name,
				dns_servers_json, desired_generation, applied_generation,
				observed_generation, parent_generation, incarnation, state,
				last_error, retired_at_unix
			) VALUES (?, ?, ?, ?, NULLIF(?, ''), ?, ?, 0, 0, ?, ?, ?,
				NULLIF(?, ''), ?)
			ON CONFLICT(id) DO UPDATE SET
				cidr = excluded.cidr,
				gateway_ipv4 = excluded.gateway_ipv4,
				nic_mac = excluded.nic_mac,
				interface_name = excluded.interface_name,
				dns_servers_json = excluded.dns_servers_json,
				desired_generation = excluded.desired_generation,
				parent_generation = excluded.parent_generation,
				incarnation = excluded.incarnation,
				state = excluded.state,
				last_error = excluded.last_error,
				retired_at_unix = excluded.retired_at_unix
		`, network.ID, network.CIDR, network.GatewayIPv4, network.NICMAC,
			network.InterfaceName, network.DNSServersJSON,
			network.DesiredGeneration, network.ParentGeneration,
			network.Incarnation, network.State, network.LastError,
			network.RetiredAtUnix)
		return err
	})
}

func (s *Store) StageGuest(ctx context.Context, header MutationHeader, guest Guest) (StageResult, error) {
	if header.ResourceID == "" {
		header.ResourceID = guest.ID
	}
	if header.ParentResourceID == "" {
		header.ParentResourceID = guest.NetworkID
	}
	return s.stage(ctx, header, "guest", func(ctx context.Context, tx *sql.Tx) error {
		guest.ID = header.ResourceID
		if err := requireReservation(ctx, tx, "guest", guest.ID, `
			AND network_id = ? AND ipv4 = ? AND mac = ?
		`, guest.NetworkID, guest.IPv4, guest.MAC); err != nil {
			return err
		}
		guest.DesiredGeneration = header.NewGeneration
		guest.ParentGeneration = header.ExpectedParentGeneration
		if guest.Incarnation == 0 {
			guest.Incarnation = 1
		}
		if guest.State == "" {
			guest.State = "active"
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO guests (
				id, network_id, ipv4, mac, desired_generation,
				applied_generation, observed_generation, parent_generation,
				incarnation, state, last_error, retired_at_unix
			) VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?, ?, NULLIF(?, ''), ?)
			ON CONFLICT(id) DO UPDATE SET
				network_id = excluded.network_id,
				ipv4 = excluded.ipv4,
				mac = excluded.mac,
				desired_generation = excluded.desired_generation,
				parent_generation = excluded.parent_generation,
				incarnation = excluded.incarnation,
				state = excluded.state,
				last_error = excluded.last_error,
				retired_at_unix = excluded.retired_at_unix
		`, guest.ID, guest.NetworkID, guest.IPv4, guest.MAC,
			guest.DesiredGeneration, guest.ParentGeneration,
			guest.Incarnation, guest.State, guest.LastError,
			guest.RetiredAtUnix)
		return err
	})
}

func (s *Store) StageRelay(ctx context.Context, header MutationHeader, relay Relay) (StageResult, error) {
	if header.ResourceID == "" {
		header.ResourceID = relay.ID
	}
	if header.ParentResourceID == "" {
		header.ParentResourceID = relay.VMID
	}
	return s.stage(ctx, header, "relay", func(ctx context.Context, tx *sql.Tx) error {
		relay.ID = header.ResourceID
		if err := requireReservation(ctx, tx, "relay", relay.ID, `
			AND listen_port = ?
		`, relay.ListenPort); err != nil {
			return err
		}
		relay.DesiredGeneration = header.NewGeneration
		relay.ParentGeneration = header.ExpectedParentGeneration
		if relay.Incarnation == 0 {
			relay.Incarnation = 1
		}
		if relay.TargetPort == 0 {
			relay.TargetPort = RelayTargetPort
		}
		if relay.TargetPort != RelayTargetPort {
			return storeError(CodeInvalidArgument, "relay target port must be %d", RelayTargetPort)
		}
		if relay.State == "" {
			relay.State = "pending"
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO relays (
				id, vm_id, listen_port, target_ipv4, target_port,
				desired_generation, applied_generation, observed_generation,
				parent_generation, incarnation, state, bound_main_ip,
				last_bind_error, retired_at_unix
			) VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?, NULLIF(?, ''),
				NULLIF(?, ''), ?)
			ON CONFLICT(id) DO UPDATE SET
				vm_id = excluded.vm_id,
				listen_port = excluded.listen_port,
				target_ipv4 = excluded.target_ipv4,
				target_port = excluded.target_port,
				desired_generation = excluded.desired_generation,
				parent_generation = excluded.parent_generation,
				incarnation = excluded.incarnation,
				state = excluded.state,
				bound_main_ip = excluded.bound_main_ip,
				last_bind_error = excluded.last_bind_error,
				retired_at_unix = excluded.retired_at_unix
		`, relay.ID, relay.VMID, relay.ListenPort, relay.TargetIPv4,
			relay.TargetPort, relay.DesiredGeneration,
			relay.ParentGeneration, relay.Incarnation, relay.State,
			relay.BoundMainIP, relay.LastBindError, relay.RetiredAtUnix)
		return err
	})
}

func (s *Store) StageNAT(ctx context.Context, header MutationHeader, nat NATState) (StageResult, error) {
	if header.ResourceID == "" {
		header.ResourceID = nat.VMID
	}
	if header.ParentResourceID == "" {
		header.ParentResourceID = nat.VMID
	}
	return s.stage(ctx, header, "nat", func(ctx context.Context, tx *sql.Tx) error {
		nat.VMID = header.ResourceID
		if err := requireReservation(ctx, tx, "guest", nat.VMID, `
			AND conntrack_mark = ?
		`, nat.ConntrackMark); err != nil {
			return err
		}
		nat.DesiredGeneration = header.NewGeneration
		nat.ParentGeneration = header.ExpectedParentGeneration
		if nat.State != "enabled" && nat.State != "draining" && nat.State != "disabled" {
			return storeError(CodeInvalidArgument, "invalid NAT state %q", nat.State)
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO nat_state (
				vm_id, state, conntrack_mark, desired_generation,
				applied_generation, observed_generation, parent_generation,
				drain_started_unix, last_error
			) VALUES (?, ?, ?, ?, 0, 0, ?, ?, NULLIF(?, ''))
			ON CONFLICT(vm_id) DO UPDATE SET
				state = excluded.state,
				conntrack_mark = excluded.conntrack_mark,
				desired_generation = excluded.desired_generation,
				parent_generation = excluded.parent_generation,
				drain_started_unix = excluded.drain_started_unix,
				last_error = excluded.last_error
		`, nat.VMID, nat.State, nat.ConntrackMark, nat.DesiredGeneration,
			nat.ParentGeneration, nat.DrainStartedUnix, nat.LastError)
		return err
	})
}

func (s *Store) stage(
	ctx context.Context,
	header MutationHeader,
	resourceKind string,
	writeDesired func(context.Context, *sql.Tx) error,
) (StageResult, error) {
	if err := validateMutationHeader(header, true); err != nil {
		return StageResult{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return StageResult{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if operation, found, err := lookupApplied(ctx, tx, header.MutationID); err != nil {
		return StageResult{}, err
	} else if found {
		if operation.RequestHash != header.SemanticHash {
			return StageResult{}, resumeMismatch(header.MutationID)
		}
		return StageResult{Replay: true, Result: operation.Result}, nil
	}
	if intent, found, err := lookupIntent(ctx, tx, header.MutationID); err != nil {
		return StageResult{}, err
	} else if found {
		if intent.SemanticHash != header.SemanticHash {
			return StageResult{}, resumeMismatch(header.MutationID)
		}
		return StageResult{Intent: intent, Replay: true}, nil
	}
	authority, err := validateFence(ctx, tx, header, s.now())
	if err != nil {
		return StageResult{}, err
	}
	if err := validateParentGeneration(ctx, tx, authority, resourceKind, header); err != nil {
		return StageResult{}, err
	}
	currentGeneration, err := resourceGeneration(ctx, tx, resourceKind, header.ResourceID)
	if err != nil {
		return StageResult{}, err
	}
	if currentGeneration != header.ExpectedGeneration ||
		header.NewGeneration != header.ExpectedGeneration+1 {
		return StageResult{}, storeError(CodeGenerationConflict,
			"%s %s generation is %d; expected %d -> %d",
			resourceKind, header.ResourceID, currentGeneration,
			header.ExpectedGeneration, header.NewGeneration)
	}
	if err := writeDesired(ctx, tx); err != nil {
		return StageResult{}, fmt.Errorf("appliance: write desired %s %s: %w",
			resourceKind, header.ResourceID, err)
	}
	now := s.now().Unix()
	intent := Intent{
		MutationID:        header.MutationID,
		ParentOperationID: header.ParentOperationID,
		ResourceKind:      resourceKind,
		ResourceID:        header.ResourceID,
		ParentResourceID:  header.ParentResourceID,
		DesiredGeneration: header.NewGeneration,
		ParentGeneration:  header.ExpectedParentGeneration,
		Fence:             header.HostFence,
		SemanticHash:      header.SemanticHash,
		Phase:             "pending",
		CreatedAtUnix:     now,
		UpdatedAtUnix:     now,
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO apply_intents (
			mutation_id, parent_operation_id, resource_kind, resource_id,
			parent_resource_id, desired_generation, parent_generation, fence,
			semantic_hash, compiled_hash, phase, error_text, created_at_unix,
			updated_at_unix
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 'pending', NULL, ?, ?)
	`, intent.MutationID, intent.ParentOperationID, intent.ResourceKind,
		intent.ResourceID, intent.ParentResourceID, intent.DesiredGeneration,
		intent.ParentGeneration, intent.Fence, intent.SemanticHash, now, now)
	if err != nil {
		return StageResult{}, fmt.Errorf("appliance: insert apply intent: %w", err)
	}
	if _, err := bumpInventoryGeneration(ctx, tx, now); err != nil {
		return StageResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return StageResult{}, fmt.Errorf("appliance: commit desired intent: %w", err)
	}
	return StageResult{Intent: intent}, nil
}

func (s *Store) UpdateIntent(
	ctx context.Context,
	mutationID, semanticHash, phase, compiledHash, errorText string,
) error {
	if !validIntentPhase(phase) || phase == "complete" {
		return storeError(CodeInvalidArgument, "invalid non-terminal intent phase %q", phase)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		UPDATE apply_intents SET
			phase = ?,
			compiled_hash = CASE WHEN ? = '' THEN compiled_hash ELSE ? END,
			error_text = NULLIF(?, ''),
			updated_at_unix = ?
		WHERE mutation_id = ? AND semantic_hash = ? AND phase <> 'complete'
	`, phase, compiledHash, compiledHash, errorText, s.now().Unix(),
		mutationID, semanticHash)
	if err != nil {
		return fmt.Errorf("appliance: update intent: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		intent, found, lookupErr := lookupIntent(ctx, tx, mutationID)
		if lookupErr != nil {
			return lookupErr
		}
		if found && intent.SemanticHash != semanticHash {
			return resumeMismatch(mutationID)
		}
		return storeError(CodeNotFound, "pending intent %q not found", mutationID)
	}
	return tx.Commit()
}

func (s *Store) CommitIntent(ctx context.Context, req CommitIntentRequest) (AppliedOperation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AppliedOperation{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if operation, found, err := lookupApplied(ctx, tx, req.MutationID); err != nil {
		return AppliedOperation{}, err
	} else if found {
		if operation.RequestHash != req.SemanticHash {
			return AppliedOperation{}, resumeMismatch(req.MutationID)
		}
		return operation, nil
	}
	intent, found, err := lookupIntent(ctx, tx, req.MutationID)
	if err != nil {
		return AppliedOperation{}, err
	}
	if !found {
		return AppliedOperation{}, storeError(CodeNotFound, "intent %q not found", req.MutationID)
	}
	if intent.SemanticHash != req.SemanticHash {
		return AppliedOperation{}, resumeMismatch(req.MutationID)
	}
	header := MutationHeader{
		MutationID:               intent.MutationID,
		SemanticHash:             intent.SemanticHash,
		ParentResourceID:         intent.ParentResourceID,
		HostFence:                req.HostFence,
		ExpectedParentGeneration: intent.ParentGeneration,
	}
	authority, err := validateFence(ctx, tx, header, s.now())
	if err != nil {
		return AppliedOperation{}, err
	}
	if err := validateParentGeneration(ctx, tx, authority, intent.ResourceKind, header); err != nil {
		return AppliedOperation{}, err
	}
	currentGeneration, err := resourceGeneration(ctx, tx, intent.ResourceKind, intent.ResourceID)
	if err != nil {
		return AppliedOperation{}, err
	}
	if currentGeneration != intent.DesiredGeneration {
		return AppliedOperation{}, storeError(CodeGenerationConflict,
			"%s %s desired generation advanced from intent %d to %d",
			intent.ResourceKind, intent.ResourceID, intent.DesiredGeneration,
			currentGeneration)
	}
	if err := advanceObserved(ctx, tx, intent); err != nil {
		return AppliedOperation{}, err
	}
	now := s.now().Unix()
	compiledHash := req.CompiledHash
	if compiledHash == "" {
		compiledHash = intent.CompiledHash
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE apply_intents SET
			compiled_hash = NULLIF(?, ''),
			phase = 'complete',
			error_text = NULL,
			updated_at_unix = ?
		WHERE mutation_id = ?
	`, compiledHash, now, intent.MutationID)
	if err != nil {
		return AppliedOperation{}, fmt.Errorf("appliance: complete intent: %w", err)
	}
	result := req.Result
	if len(result) == 0 {
		result = json.RawMessage(`{}`)
	}
	operation := AppliedOperation{
		MutationID:        intent.MutationID,
		ParentOperationID: intent.ParentOperationID,
		RequestHash:       intent.SemanticHash,
		Result:            result,
		AppliedAtUnix:     now,
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO applied_operations (
			mutation_id, parent_operation_id, request_hash, result_json,
			applied_at_unix
		) VALUES (?, ?, ?, ?, ?)
	`, operation.MutationID, operation.ParentOperationID,
		operation.RequestHash, string(operation.Result), operation.AppliedAtUnix)
	if err != nil {
		return AppliedOperation{}, fmt.Errorf("appliance: record applied intent: %w", err)
	}
	if _, err := bumpInventoryGeneration(ctx, tx, now); err != nil {
		return AppliedOperation{}, err
	}
	if err := tx.Commit(); err != nil {
		return AppliedOperation{}, fmt.Errorf("appliance: commit applied intent: %w", err)
	}
	return operation, nil
}

func (s *Store) Intent(ctx context.Context, mutationID string) (Intent, bool, error) {
	return lookupIntent(ctx, s.db, mutationID)
}

func (s *Store) RecoveryIntents(ctx context.Context) ([]Intent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT mutation_id, parent_operation_id, resource_kind, resource_id,
			parent_resource_id, desired_generation, parent_generation, fence, semantic_hash,
			COALESCE(compiled_hash, ''), phase, COALESCE(error_text, ''),
			created_at_unix, updated_at_unix
		FROM apply_intents
		WHERE phase <> 'complete'
		ORDER BY created_at_unix, mutation_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var intents []Intent
	for rows.Next() {
		intent, err := scanIntent(rows)
		if err != nil {
			return nil, err
		}
		intents = append(intents, intent)
	}
	return intents, rows.Err()
}

func (s *Store) NormalizeDrainingNAT(ctx context.Context) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		UPDATE nat_state
		SET state = 'disabled', drain_started_unix = NULL
		WHERE state = 'draining'
	`)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if affected > 0 {
		if _, err := bumpInventoryGeneration(ctx, tx, s.now().Unix()); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return affected, nil
}

func (s *Store) Network(ctx context.Context, id string) (Network, bool, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, cidr, gateway_ipv4, nic_mac, COALESCE(interface_name, ''),
			dns_servers_json, desired_generation, applied_generation,
			observed_generation, parent_generation, incarnation, state,
			COALESCE(last_error, ''), retired_at_unix
		FROM networks WHERE id = ?
	`, id)
	var network Network
	var retired sql.NullInt64
	err := row.Scan(&network.ID, &network.CIDR, &network.GatewayIPv4,
		&network.NICMAC, &network.InterfaceName, &network.DNSServersJSON,
		&network.DesiredGeneration, &network.AppliedGeneration,
		&network.ObservedGeneration, &network.ParentGeneration,
		&network.Incarnation, &network.State, &network.LastError, &retired)
	if errors.Is(err, sql.ErrNoRows) {
		return Network{}, false, nil
	}
	if err != nil {
		return Network{}, false, err
	}
	network.RetiredAtUnix = nullInt64Ptr(retired)
	return network, true, nil
}

func (s *Store) NAT(ctx context.Context, vmID string) (NATState, bool, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT vm_id, state, conntrack_mark, desired_generation,
			applied_generation, observed_generation, parent_generation,
			drain_started_unix, COALESCE(last_error, '')
		FROM nat_state WHERE vm_id = ?
	`, vmID)
	var nat NATState
	var drain sql.NullInt64
	err := row.Scan(&nat.VMID, &nat.State, &nat.ConntrackMark,
		&nat.DesiredGeneration, &nat.AppliedGeneration,
		&nat.ObservedGeneration, &nat.ParentGeneration, &drain,
		&nat.LastError)
	if errors.Is(err, sql.ErrNoRows) {
		return NATState{}, false, nil
	}
	if err != nil {
		return NATState{}, false, err
	}
	nat.DrainStartedUnix = nullInt64Ptr(drain)
	return nat, true, nil
}

func (s *Store) Snapshot(ctx context.Context) (DesiredSnapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return DesiredSnapshot{}, err
	}
	defer func() { _ = tx.Rollback() }()

	snapshot := DesiredSnapshot{}
	snapshot.Status, err = readStatus(ctx, tx)
	if err != nil {
		return DesiredSnapshot{}, err
	}
	snapshot.Authority, err = readAuthority(ctx, tx)
	if err != nil {
		return DesiredSnapshot{}, err
	}
	if snapshot.Networks, err = listNetworks(ctx, tx); err != nil {
		return DesiredSnapshot{}, err
	}
	if snapshot.Guests, err = listGuests(ctx, tx); err != nil {
		return DesiredSnapshot{}, err
	}
	if snapshot.Relays, err = listRelays(ctx, tx); err != nil {
		return DesiredSnapshot{}, err
	}
	if snapshot.NAT, err = listNAT(ctx, tx); err != nil {
		return DesiredSnapshot{}, err
	}
	if snapshot.Reservations, err = listReservations(ctx, tx, false); err != nil {
		return DesiredSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return DesiredSnapshot{}, err
	}
	return snapshot, nil
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type queryer interface {
	queryRower
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func readStatus(ctx context.Context, q queryRower) (Status, error) {
	var status Status
	var ready int
	err := q.QueryRowContext(ctx, `
		SELECT inventory_generation, ready, error_text, updated_at_unix
		FROM appliance_status WHERE singleton = 1
	`).Scan(&status.InventoryGeneration, &ready, &status.Error,
		&status.UpdatedAtUnix)
	status.Ready = ready != 0
	return status, err
}

func readAuthority(ctx context.Context, q queryRower) (Authority, error) {
	var authority Authority
	var handoff int
	err := q.QueryRowContext(ctx, `
		SELECT physical_host_id, host_lease_id, host_lease_secret_hash,
			host_lease_expires_unix, fence, parent_generation, parent_state,
			handoff_pending, updated_at_unix
		FROM appliance_authority WHERE singleton = 1
	`).Scan(&authority.PhysicalHostID, &authority.HostLeaseID,
		&authority.HostLeaseSecretHash, &authority.HostLeaseExpiresUnix,
		&authority.Fence, &authority.ParentGeneration,
		&authority.ParentState, &handoff, &authority.UpdatedAtUnix)
	authority.HandoffPending = handoff != 0
	return authority, err
}

func validateAuthority(
	ctx context.Context,
	tx *sql.Tx,
	header MutationHeader,
	now time.Time,
) (Authority, error) {
	authority, err := validateFence(ctx, tx, header, now)
	if err != nil {
		return Authority{}, err
	}
	if authority.ParentGeneration != header.ExpectedParentGeneration {
		return Authority{}, storeError(CodeParentGeneration,
			"parent generation is %d; request expected %d",
			authority.ParentGeneration, header.ExpectedParentGeneration)
	}
	return authority, nil
}

func validateFence(
	ctx context.Context,
	tx *sql.Tx,
	header MutationHeader,
	now time.Time,
) (Authority, error) {
	authority, err := readAuthority(ctx, tx)
	if err != nil {
		return Authority{}, err
	}
	if authority.HandoffPending {
		return Authority{}, storeError(CodeFenceRejected, "authority handoff is pending")
	}
	if authority.Fence != header.HostFence {
		return Authority{}, storeError(CodeFenceRejected, "host fence is %d; request supplied %d",
			authority.Fence, header.HostFence)
	}
	if authority.HostLeaseExpiresUnix > 0 && now.Unix() >= authority.HostLeaseExpiresUnix {
		return Authority{}, storeError(CodeFenceRejected, "host lease expired")
	}
	if authority.ParentState != "active" {
		return Authority{}, storeError(CodeParentFrozen, "parent state is %s", authority.ParentState)
	}
	return authority, nil
}

func validateParentGeneration(
	ctx context.Context,
	tx *sql.Tx,
	authority Authority,
	resourceKind string,
	header MutationHeader,
) error {
	var current uint64
	switch resourceKind {
	case "network":
		current = authority.ParentGeneration
	case "guest":
		if header.ParentResourceID == "" {
			return storeError(CodeInvalidArgument, "guest parent network ID is required")
		}
		if err := tx.QueryRowContext(ctx,
			"SELECT desired_generation FROM networks WHERE id = ?",
			header.ParentResourceID,
		).Scan(&current); errors.Is(err, sql.ErrNoRows) {
			return storeError(CodeNotFound, "parent network %q not found", header.ParentResourceID)
		} else if err != nil {
			return err
		}
	case "relay", "nat":
		if header.ParentResourceID == "" {
			return storeError(CodeInvalidArgument, "%s parent guest ID is required", resourceKind)
		}
		if err := tx.QueryRowContext(ctx,
			"SELECT desired_generation FROM guests WHERE id = ?",
			header.ParentResourceID,
		).Scan(&current); errors.Is(err, sql.ErrNoRows) {
			return storeError(CodeNotFound, "parent guest %q not found", header.ParentResourceID)
		} else if err != nil {
			return err
		}
	default:
		return storeError(CodeInvalidArgument, "unknown resource kind %q", resourceKind)
	}
	if current != header.ExpectedParentGeneration {
		return storeError(CodeParentGeneration,
			"parent generation is %d; request expected %d",
			current, header.ExpectedParentGeneration)
	}
	return nil
}

func validateMutationHeader(header MutationHeader, requireGeneration bool) error {
	if strings.TrimSpace(header.ParentOperationID) == "" ||
		strings.TrimSpace(header.MutationID) == "" ||
		strings.TrimSpace(header.SemanticHash) == "" {
		return storeError(CodeInvalidArgument,
			"parent operation ID, mutation ID, and semantic hash are required")
	}
	if requireGeneration {
		if strings.TrimSpace(header.ResourceID) == "" {
			return storeError(CodeInvalidArgument, "resource ID is required")
		}
		if header.NewGeneration != header.ExpectedGeneration+1 {
			return storeError(CodeGenerationConflict,
				"new generation %d must follow expected generation %d",
				header.NewGeneration, header.ExpectedGeneration)
		}
	}
	return nil
}

func normalizeReservation(
	reservation *Reservation,
	header MutationHeader,
	now int64,
) error {
	if strings.TrimSpace(reservation.ID) == "" ||
		strings.TrimSpace(reservation.ResourceKind) == "" ||
		strings.TrimSpace(reservation.ResourceID) == "" {
		return storeError(CodeInvalidArgument,
			"reservation ID, resource kind, and resource ID are required")
	}
	if reservation.IPv4 != "" && reservation.NetworkID == "" {
		return storeError(CodeInvalidArgument,
			"reservation %s has an IP without a network ID", reservation.ID)
	}
	if reservation.ListenPort != nil &&
		(*reservation.ListenPort < 1 || *reservation.ListenPort > 65535) {
		return storeError(CodeInvalidArgument,
			"reservation %s has invalid listen port %d",
			reservation.ID, *reservation.ListenPort)
	}
	if reservation.CapacityKind == "" && reservation.CapacityUnits != 0 {
		return storeError(CodeInvalidArgument,
			"reservation %s has capacity units without a capacity kind",
			reservation.ID)
	}
	if reservation.CapacityKind != "" && reservation.CapacityUnits <= 0 {
		return storeError(CodeInvalidArgument,
			"reservation %s capacity units must be positive", reservation.ID)
	}
	reservation.State = "active"
	reservation.ParentGeneration = header.ExpectedParentGeneration
	reservation.CreatedAtUnix = now
	reservation.RetiredAtUnix = nil
	return nil
}

func requireReservation(
	ctx context.Context,
	tx *sql.Tx,
	resourceKind, resourceID, extraPredicate string,
	args ...any,
) error {
	query := `
		SELECT 1 FROM reservations
		WHERE resource_kind = ? AND resource_id = ?
			AND retired_at_unix IS NULL ` + extraPredicate + `
		LIMIT 1`
	queryArgs := make([]any, 0, 2+len(args))
	queryArgs = append(queryArgs, resourceKind, resourceID)
	queryArgs = append(queryArgs, args...)
	var present int
	err := tx.QueryRowContext(ctx, query, queryArgs...).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return storeError(CodeReservationLost,
			"no matching live reservation for %s %q", resourceKind, resourceID)
	}
	if err != nil {
		return err
	}
	return nil
}

func findCollisions(
	ctx context.Context,
	tx *sql.Tx,
	reservations []Reservation,
) ([]Collision, error) {
	var collisions []Collision
	type candidate struct {
		field string
		code  ErrorCode
		key   string
		query string
		args  []any
	}
	var candidates []candidate
	for _, reservation := range reservations {
		if reservation.SubnetIndex != nil {
			candidates = append(candidates, candidate{
				field: "subnet_index", code: CodeSubnetInUse,
				key: strconv.FormatInt(*reservation.SubnetIndex, 10),
				query: `SELECT id, resource_kind, resource_id FROM reservations
					WHERE subnet_index = ? AND retired_at_unix IS NULL`,
				args: []any{*reservation.SubnetIndex},
			})
		}
	}
	for _, reservation := range reservations {
		if reservation.ResourceKind == "network" && reservation.MAC != "" {
			candidates = append(candidates, candidate{
				field: "mac", code: CodeMACInUse, key: reservation.MAC,
				query: `SELECT id, resource_kind, resource_id FROM reservations
					WHERE mac = ? AND retired_at_unix IS NULL`,
				args: []any{reservation.MAC},
			})
		}
	}
	for _, reservation := range reservations {
		if reservation.IPv4 != "" {
			candidates = append(candidates, candidate{
				field: "ipv4", code: CodeIPInUse,
				key: reservation.NetworkID + "\x00" + reservation.IPv4,
				query: `SELECT id, resource_kind, resource_id FROM reservations
					WHERE network_id = ? AND ipv4 = ? AND retired_at_unix IS NULL`,
				args: []any{reservation.NetworkID, reservation.IPv4},
			})
		}
	}
	for _, reservation := range reservations {
		if reservation.ResourceKind != "network" && reservation.MAC != "" {
			candidates = append(candidates, candidate{
				field: "mac", code: CodeMACInUse, key: reservation.MAC,
				query: `SELECT id, resource_kind, resource_id FROM reservations
					WHERE mac = ? AND retired_at_unix IS NULL`,
				args: []any{reservation.MAC},
			})
		}
	}
	for _, reservation := range reservations {
		if reservation.ListenPort != nil {
			candidates = append(candidates, candidate{
				field: "listen_port", code: CodePortInUse,
				key: strconv.FormatInt(*reservation.ListenPort, 10),
				query: `SELECT id, resource_kind, resource_id FROM reservations
					WHERE listen_port = ? AND retired_at_unix IS NULL`,
				args: []any{*reservation.ListenPort},
			})
		}
	}
	for _, reservation := range reservations {
		if reservation.ConntrackMark != nil {
			candidates = append(candidates, candidate{
				field: "conntrack_mark", code: CodeConntrackMarkInUse,
				key: strconv.FormatInt(*reservation.ConntrackMark, 10),
				query: `SELECT id, resource_kind, resource_id FROM reservations
					WHERE conntrack_mark = ? AND retired_at_unix IS NULL`,
				args: []any{*reservation.ConntrackMark},
			})
		}
	}

	seen := make(map[string]map[string]struct{})
	for _, candidate := range candidates {
		fieldSeen := seen[candidate.field]
		if fieldSeen == nil {
			fieldSeen = make(map[string]struct{})
			seen[candidate.field] = fieldSeen
		}
		if _, duplicate := fieldSeen[candidate.key]; duplicate {
			collisions = append(collisions, Collision{
				Code:  candidate.code,
				Field: candidate.field,
			})
			continue
		}
		fieldSeen[candidate.key] = struct{}{}
		var existing Collision
		err := tx.QueryRowContext(ctx, candidate.query, candidate.args...).Scan(
			&existing.ExistingReservationID,
			&existing.ExistingResourceKind,
			&existing.ExistingResourceID,
		)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return nil, err
		default:
			existing.Code = candidate.code
			existing.Field = candidate.field
			collisions = append(collisions, existing)
		}
	}

	requested := make(map[string]int64)
	for _, reservation := range reservations {
		if reservation.CapacityKind != "" {
			requested[reservation.CapacityKind] += reservation.CapacityUnits
		}
	}
	kinds := make([]string, 0, len(requested))
	for kind := range requested {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		units := requested[kind]
		var limit int64
		if err := tx.QueryRowContext(ctx,
			"SELECT max_units FROM capacity_limits WHERE kind = ?", kind,
		).Scan(&limit); errors.Is(err, sql.ErrNoRows) {
			return nil, storeError(CodeInvalidArgument, "unknown capacity kind %q", kind)
		} else if err != nil {
			return nil, err
		}
		var used int64
		if err := tx.QueryRowContext(ctx, `
			SELECT COALESCE(SUM(capacity_units), 0)
			FROM reservations
			WHERE capacity_kind = ? AND retired_at_unix IS NULL
		`, kind).Scan(&used); err != nil {
			return nil, err
		}
		if used+units > limit {
			collisions = append(collisions, Collision{
				Code:  CodeCapacityExhausted,
				Field: "capacity:" + kind,
			})
		}
	}

	seenResources := make(map[string]struct{}, len(reservations))
	for _, reservation := range reservations {
		key := reservation.ResourceKind + "\x00" + reservation.ResourceID
		if _, duplicate := seenResources[key]; duplicate {
			collisions = append(collisions, Collision{
				Code:  CodeResourceInUse,
				Field: "resource",
			})
			continue
		}
		seenResources[key] = struct{}{}
		var existing Collision
		err := tx.QueryRowContext(ctx, `
			SELECT id, resource_kind, resource_id FROM reservations
			WHERE resource_kind = ? AND resource_id = ?
				AND retired_at_unix IS NULL
		`, reservation.ResourceKind, reservation.ResourceID).Scan(
			&existing.ExistingReservationID,
			&existing.ExistingResourceKind,
			&existing.ExistingResourceID,
		)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return nil, err
		default:
			existing.Code = CodeResourceInUse
			existing.Field = "resource"
			collisions = append(collisions, existing)
		}
	}
	return collisions, nil
}

func inventorySummary(ctx context.Context, tx *sql.Tx) (InventorySummary, error) {
	var summary InventorySummary
	err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*),
			COALESCE(SUM(subnet_index IS NOT NULL), 0),
			COALESCE(SUM(ipv4 IS NOT NULL), 0),
			COALESCE(SUM(mac IS NOT NULL), 0),
			COALESCE(SUM(listen_port IS NOT NULL), 0),
			COALESCE(SUM(conntrack_mark IS NOT NULL), 0)
		FROM reservations WHERE retired_at_unix IS NULL
	`).Scan(&summary.LiveReservations, &summary.Subnets, &summary.IPs,
		&summary.MACs, &summary.Ports, &summary.ConntrackMarks)
	if err != nil {
		return InventorySummary{}, err
	}
	summary.Capacity = make(map[string]CapacityUsage)
	rows, err := tx.QueryContext(ctx, `
		SELECT l.kind, l.max_units,
			COALESCE(SUM(r.capacity_units), 0)
		FROM capacity_limits l
		LEFT JOIN reservations r
			ON r.capacity_kind = l.kind AND r.retired_at_unix IS NULL
		GROUP BY l.kind, l.max_units
		ORDER BY l.kind
	`)
	if err != nil {
		return InventorySummary{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var usage CapacityUsage
		if err := rows.Scan(&kind, &usage.Limit, &usage.Used); err != nil {
			return InventorySummary{}, err
		}
		summary.Capacity[kind] = usage
	}
	return summary, rows.Err()
}

func bumpInventoryGeneration(ctx context.Context, tx *sql.Tx, now int64) (uint64, error) {
	_, err := tx.ExecContext(ctx, `
		UPDATE appliance_status
		SET inventory_generation = inventory_generation + 1,
			updated_at_unix = ?
		WHERE singleton = 1
	`, now)
	if err != nil {
		return 0, err
	}
	status, err := readStatus(ctx, tx)
	return status.InventoryGeneration, err
}

func recordApplied(
	ctx context.Context,
	tx *sql.Tx,
	header MutationHeader,
	result any,
	now int64,
) error {
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO applied_operations (
			mutation_id, parent_operation_id, request_hash, result_json,
			applied_at_unix
		) VALUES (?, ?, ?, ?, ?)
	`, header.MutationID, header.ParentOperationID, header.SemanticHash,
		string(encoded), now)
	if err != nil {
		return fmt.Errorf("appliance: record applied operation: %w", err)
	}
	return nil
}

func replayReserve(
	ctx context.Context,
	tx *sql.Tx,
	header MutationHeader,
) (ReserveResult, bool, error) {
	operation, found, err := lookupApplied(ctx, tx, header.MutationID)
	if err != nil || !found {
		return ReserveResult{}, found, err
	}
	if operation.RequestHash != header.SemanticHash {
		return ReserveResult{}, false, resumeMismatch(header.MutationID)
	}
	var result ReserveResult
	if err := json.Unmarshal(operation.Result, &result); err != nil {
		return ReserveResult{}, false, fmt.Errorf("appliance: decode stored reservation result: %w", err)
	}
	return result, true, nil
}

func replayRelease(
	ctx context.Context,
	tx *sql.Tx,
	header MutationHeader,
) (ReleaseResult, bool, error) {
	operation, found, err := lookupApplied(ctx, tx, header.MutationID)
	if err != nil || !found {
		return ReleaseResult{}, found, err
	}
	if operation.RequestHash != header.SemanticHash {
		return ReleaseResult{}, false, resumeMismatch(header.MutationID)
	}
	var result ReleaseResult
	if err := json.Unmarshal(operation.Result, &result); err != nil {
		return ReleaseResult{}, false, fmt.Errorf("appliance: decode stored release result: %w", err)
	}
	return result, true, nil
}

func lookupApplied(
	ctx context.Context,
	q queryRower,
	mutationID string,
) (AppliedOperation, bool, error) {
	var operation AppliedOperation
	var result string
	err := q.QueryRowContext(ctx, `
		SELECT mutation_id, parent_operation_id, request_hash, result_json,
			applied_at_unix
		FROM applied_operations WHERE mutation_id = ?
	`, mutationID).Scan(&operation.MutationID, &operation.ParentOperationID,
		&operation.RequestHash, &result, &operation.AppliedAtUnix)
	if errors.Is(err, sql.ErrNoRows) {
		return AppliedOperation{}, false, nil
	}
	if err != nil {
		return AppliedOperation{}, false, err
	}
	operation.Result = json.RawMessage(result)
	return operation, true, nil
}

func lookupIntent(
	ctx context.Context,
	q queryRower,
	mutationID string,
) (Intent, bool, error) {
	row := q.QueryRowContext(ctx, `
		SELECT mutation_id, parent_operation_id, resource_kind, resource_id,
			parent_resource_id, desired_generation, parent_generation, fence, semantic_hash,
			COALESCE(compiled_hash, ''), phase, COALESCE(error_text, ''),
			created_at_unix, updated_at_unix
		FROM apply_intents WHERE mutation_id = ?
	`, mutationID)
	intent, err := scanIntent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Intent{}, false, nil
	}
	if err != nil {
		return Intent{}, false, err
	}
	return intent, true, nil
}

type scanner interface {
	Scan(...any) error
}

func scanIntent(row scanner) (Intent, error) {
	var intent Intent
	err := row.Scan(&intent.MutationID, &intent.ParentOperationID,
		&intent.ResourceKind, &intent.ResourceID, &intent.ParentResourceID,
		&intent.DesiredGeneration, &intent.ParentGeneration, &intent.Fence, &intent.SemanticHash,
		&intent.CompiledHash, &intent.Phase, &intent.Error,
		&intent.CreatedAtUnix, &intent.UpdatedAtUnix)
	return intent, err
}

func scanReservation(row scanner) (Reservation, error) {
	var reservation Reservation
	var subnet, port, mark, retired sql.NullInt64
	err := row.Scan(&reservation.ID, &reservation.ResourceKind,
		&reservation.ResourceID, &reservation.NetworkID, &subnet,
		&reservation.IPv4, &reservation.MAC, &port, &mark,
		&reservation.CapacityKind, &reservation.CapacityUnits,
		&reservation.State, &reservation.ParentGeneration,
		&reservation.CreatedAtUnix, &retired)
	if err != nil {
		return Reservation{}, err
	}
	reservation.SubnetIndex = nullInt64Ptr(subnet)
	reservation.ListenPort = nullInt64Ptr(port)
	reservation.ConntrackMark = nullInt64Ptr(mark)
	reservation.RetiredAtUnix = nullInt64Ptr(retired)
	return reservation, nil
}

func listNetworks(ctx context.Context, q queryer) ([]Network, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, cidr, gateway_ipv4, nic_mac, COALESCE(interface_name, ''),
			dns_servers_json, desired_generation, applied_generation,
			observed_generation, parent_generation, incarnation, state,
			COALESCE(last_error, ''), retired_at_unix
		FROM networks
		ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var networks []Network
	for rows.Next() {
		var network Network
		var retired sql.NullInt64
		if err := rows.Scan(&network.ID, &network.CIDR,
			&network.GatewayIPv4, &network.NICMAC, &network.InterfaceName,
			&network.DNSServersJSON, &network.DesiredGeneration,
			&network.AppliedGeneration, &network.ObservedGeneration,
			&network.ParentGeneration, &network.Incarnation, &network.State,
			&network.LastError, &retired); err != nil {
			return nil, err
		}
		network.RetiredAtUnix = nullInt64Ptr(retired)
		networks = append(networks, network)
	}
	return networks, rows.Err()
}

func listGuests(ctx context.Context, q queryer) ([]Guest, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, network_id, ipv4, mac, desired_generation,
			applied_generation, observed_generation, parent_generation,
			incarnation, state, COALESCE(last_error, ''), retired_at_unix
		FROM guests
		ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var guests []Guest
	for rows.Next() {
		var guest Guest
		var retired sql.NullInt64
		if err := rows.Scan(&guest.ID, &guest.NetworkID, &guest.IPv4,
			&guest.MAC, &guest.DesiredGeneration, &guest.AppliedGeneration,
			&guest.ObservedGeneration, &guest.ParentGeneration,
			&guest.Incarnation, &guest.State, &guest.LastError,
			&retired); err != nil {
			return nil, err
		}
		guest.RetiredAtUnix = nullInt64Ptr(retired)
		guests = append(guests, guest)
	}
	return guests, rows.Err()
}

func listRelays(ctx context.Context, q queryer) ([]Relay, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, vm_id, listen_port, target_ipv4, target_port,
			desired_generation, applied_generation, observed_generation,
			parent_generation, incarnation, state, COALESCE(bound_main_ip, ''),
			COALESCE(last_bind_error, ''), retired_at_unix
		FROM relays
		ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var relays []Relay
	for rows.Next() {
		var relay Relay
		var retired sql.NullInt64
		if err := rows.Scan(&relay.ID, &relay.VMID, &relay.ListenPort,
			&relay.TargetIPv4, &relay.TargetPort, &relay.DesiredGeneration,
			&relay.AppliedGeneration, &relay.ObservedGeneration,
			&relay.ParentGeneration, &relay.Incarnation, &relay.State,
			&relay.BoundMainIP, &relay.LastBindError, &retired); err != nil {
			return nil, err
		}
		relay.RetiredAtUnix = nullInt64Ptr(retired)
		relays = append(relays, relay)
	}
	return relays, rows.Err()
}

func listNAT(ctx context.Context, q queryer) ([]NATState, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT vm_id, state, conntrack_mark, desired_generation,
			applied_generation, observed_generation, parent_generation,
			drain_started_unix, COALESCE(last_error, '')
		FROM nat_state
		ORDER BY vm_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var states []NATState
	for rows.Next() {
		var state NATState
		var drain sql.NullInt64
		if err := rows.Scan(&state.VMID, &state.State,
			&state.ConntrackMark, &state.DesiredGeneration,
			&state.AppliedGeneration, &state.ObservedGeneration,
			&state.ParentGeneration, &drain, &state.LastError); err != nil {
			return nil, err
		}
		state.DrainStartedUnix = nullInt64Ptr(drain)
		states = append(states, state)
	}
	return states, rows.Err()
}

func resourceGeneration(
	ctx context.Context,
	tx *sql.Tx,
	resourceKind, resourceID string,
) (uint64, error) {
	var query string
	switch resourceKind {
	case "network":
		query = "SELECT desired_generation FROM networks WHERE id = ?"
	case "guest":
		query = "SELECT desired_generation FROM guests WHERE id = ?"
	case "relay":
		query = "SELECT desired_generation FROM relays WHERE id = ?"
	case "nat":
		query = "SELECT desired_generation FROM nat_state WHERE vm_id = ?"
	default:
		return 0, storeError(CodeInvalidArgument, "unknown resource kind %q", resourceKind)
	}
	var generation uint64
	err := tx.QueryRowContext(ctx, query, resourceID).Scan(&generation)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return generation, err
}

func advanceObserved(ctx context.Context, tx *sql.Tx, intent Intent) error {
	var query string
	switch intent.ResourceKind {
	case "network":
		query = `UPDATE networks SET applied_generation = ?,
			observed_generation = ?, last_error = NULL WHERE id = ?`
	case "guest":
		query = `UPDATE guests SET applied_generation = ?,
			observed_generation = ?, last_error = NULL WHERE id = ?`
	case "relay":
		query = `UPDATE relays SET applied_generation = ?,
			observed_generation = ?, last_bind_error = NULL WHERE id = ?`
	case "nat":
		query = `UPDATE nat_state SET applied_generation = ?,
			observed_generation = ?, last_error = NULL WHERE vm_id = ?`
	default:
		return storeError(CodeInvalidArgument, "unknown resource kind %q", intent.ResourceKind)
	}
	result, err := tx.ExecContext(ctx, query, intent.DesiredGeneration,
		intent.DesiredGeneration, intent.ResourceID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return storeError(CodeNotFound, "%s %q not found", intent.ResourceKind, intent.ResourceID)
	}
	return nil
}

func validParentState(state string) bool {
	switch state {
	case "active", "frozen", "deleting", "lost", "deleted":
		return true
	default:
		return false
	}
}

func validIntentPhase(phase string) bool {
	switch phase {
	case "pending", "compiled", "applying", "failed", "complete":
		return true
	default:
		return false
	}
}

func resumeMismatch(mutationID string) error {
	return storeError(CodeResumeMismatch,
		"mutation ID %q was already used with a different semantic hash",
		mutationID)
}

func storeError(code ErrorCode, format string, args ...any) error {
	return &StoreError{Code: code, Message: fmt.Sprintf(format, args...)}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullInt64Ptr(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	v := value.Int64
	return &v
}
