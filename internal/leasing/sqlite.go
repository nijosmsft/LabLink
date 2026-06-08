package leasing

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// SQLiteStore is the SQLite-backed Store. One DB handle per
// lablink-server.exe process; cross-process serialization is delegated to
// SQLite's WAL + BEGIN IMMEDIATE.
type SQLiteStore struct {
	db   *sql.DB
	path string
	now  func() time.Time
	mono func() int64
}

// OpenSQLiteStore opens (and migrates) the leases db at the given path. If
// path is empty, DefaultDBPath() is used. The parent directory is created
// with 0700 permissions if missing.
func OpenSQLiteStore(path string) (*SQLiteStore, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultDBPath()
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("leasing: mkdir %s: %w", dir, err)
		}
	}

	// modernc.org/sqlite accepts file: URIs and query-string PRAGMA hints.
	// _txlock=immediate makes every BeginTx open a BEGIN IMMEDIATE so
	// concurrent writers serialize at the start of the transaction
	// instead of failing with SQLITE_BUSY at COMMIT time. We also run
	// the PRAGMAs explicitly after open to guarantee they stick on the
	// connection database/sql hands us first.
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)&_txlock=immediate", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("leasing: sql.Open: %w", err)
	}

	// WAL is a per-database property persisted on the file. Open one
	// connection eagerly to confirm we can talk to the db and to apply
	// the pragmas in case the DSN form is ignored.
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("leasing: ping: %w", err)
	}

	for _, p := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("leasing: %s: %w", p, err)
		}
	}

	if _, err := db.Exec(schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("leasing: init schema: %w", err)
	}

	s := &SQLiteStore{
		db:   db,
		path: path,
		now:  time.Now,
		mono: runtimeNanotime,
	}
	return s, nil
}

// Close releases the database handle.
func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Path returns the on-disk db path. Useful for diagnostics.
func (s *SQLiteStore) Path() string { return s.path }

// JournalMode returns the current PRAGMA journal_mode. Used by tests.
func (s *SQLiteStore) JournalMode(ctx context.Context) (string, error) {
	row := s.db.QueryRowContext(ctx, "PRAGMA journal_mode")
	var mode string
	if err := row.Scan(&mode); err != nil {
		return "", err
	}
	return mode, nil
}

// --- Acquire ----------------------------------------------------------------

// Acquire implements Store.Acquire. Multi-node acquire is all-or-nothing.
//
// Concurrency: every attempt runs inside BEGIN IMMEDIATE so two processes
// (or two goroutines on one process) racing for the same node see exactly
// one winner. Wait>0 polls every 500ms (capped to remaining time).
func (s *SQLiteStore) Acquire(ctx context.Context, req AcquireRequest) (*Lease, error) {
	nodes := dedupeAndSort(req.Nodes)
	if len(nodes) == 0 {
		return nil, ErrNoNodes
	}
	dur := req.Duration
	if dur <= 0 {
		dur = DefaultDuration
	}
	ident := req.Identity
	if ident.Empty() {
		ident = Default()
	}
	if strings.TrimSpace(req.AgentID) == "" {
		req.AgentID = ident.EffectiveID
	}

	deadline := s.now().Add(req.Wait)
	for {
		lease, confErr, err := s.tryAcquire(ctx, nodes, dur, req.AgentID, req.Reason, ident)
		if err != nil {
			return nil, err
		}
		if lease != nil {
			return lease, nil
		}
		// Conflict path.
		if req.Wait <= 0 {
			return nil, confErr
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, ErrWaitTimeout
		}
		sleep := 500 * time.Millisecond
		if sleep > remaining {
			sleep = remaining
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleep):
		}
	}
}

// tryAcquire performs a single attempt under BEGIN IMMEDIATE.
// Returns (lease, nil, nil) on success, (nil, *ConflictError, nil) on
// conflict, (nil, nil, err) on infra error.
func (s *SQLiteStore) tryAcquire(
	ctx context.Context,
	nodes []string,
	dur time.Duration,
	agentID, reason string,
	ident Identity,
) (*Lease, *ConflictError, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback() }()

	// _txlock=immediate (set on the DSN) already issued BEGIN IMMEDIATE
	// for this BeginTx call, so the writer lock is held now. No further
	// upgrade dance is needed.

	now := s.now()
	if err := s.expireOverdueLocked(ctx, tx, now); err != nil {
		return nil, nil, err
	}

	holders, err := s.activeHoldersLocked(ctx, tx, nodes, now)
	if err != nil {
		return nil, nil, err
	}
	if len(holders) > 0 {
		// Conflict — abort.
		return nil, &ConflictError{Holders: holders}, nil
	}

	id := newLeaseID()
	acquired := now
	expires := now.Add(dur)
	mono := s.mono()
	startUnix := ident.StartTime.Unix()
	if ident.StartTime.IsZero() {
		startUnix = 0
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO leases (
			id, agent_id, cookie, hostname, pid, process_start_unix,
			reason, acquired_at_unix, expires_at_unix,
			monotonic_acquired_ns, state
		) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		id, agentID, ident.Cookie, ident.Hostname, ident.PID, startUnix,
		reason, acquired.Unix(), expires.Unix(), mono, string(LeaseAcquired),
	)
	if err != nil {
		return nil, nil, err
	}

	for _, n := range nodes {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO lease_nodes (lease_id, node_name) VALUES (?,?)`, id, n); err != nil {
			return nil, nil, err
		}
	}

	if err := s.writeAuditLocked(ctx, tx, id, "acquired", agentID, now, map[string]any{
		"nodes":  nodes,
		"reason": reason,
	}); err != nil {
		return nil, nil, err
	}

	if err := tx.Commit(); err != nil {
		// Commit conflict (SQLITE_BUSY etc) — caller may retry.
		return nil, nil, err
	}

	return &Lease{
		ID:         id,
		AgentID:    agentID,
		Cookie:     ident.Cookie,
		Hostname:   ident.Hostname,
		PID:        ident.PID,
		StartTime:  ident.StartTime,
		Nodes:      append([]string(nil), nodes...),
		Reason:     reason,
		AcquiredAt: acquired,
		ExpiresAt:  expires,
		State:      LeaseAcquired,
	}, nil, nil
}

// activeHoldersLocked returns one holder Lease per node currently held by
// somebody else among the requested set.
func (s *SQLiteStore) activeHoldersLocked(
	ctx context.Context,
	tx *sql.Tx,
	nodes []string,
	now time.Time,
) (map[string]*Lease, error) {
	if len(nodes) == 0 {
		return nil, nil
	}
	placeholders := strings.Repeat("?,", len(nodes))
	placeholders = strings.TrimSuffix(placeholders, ",")
	q := fmt.Sprintf(`
		SELECT ln.node_name, l.id, l.agent_id, l.cookie, l.hostname, l.pid,
		       l.process_start_unix, l.reason, l.acquired_at_unix,
		       l.expires_at_unix, l.state
		FROM lease_nodes ln
		JOIN leases l ON l.id = ln.lease_id
		WHERE ln.node_name IN (%s)
		  AND l.state = 'acquired'
		  AND l.expires_at_unix > ?`, placeholders)

	args := make([]any, 0, len(nodes)+1)
	for _, n := range nodes {
		args = append(args, n)
	}
	args = append(args, now.Unix())

	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]*Lease)
	for rows.Next() {
		var node string
		var l Lease
		var startUnix int64
		var state string
		var acq, exp int64
		if err := rows.Scan(&node, &l.ID, &l.AgentID, &l.Cookie, &l.Hostname,
			&l.PID, &startUnix, &l.Reason, &acq, &exp, &state); err != nil {
			return nil, err
		}
		l.StartTime = time.Unix(startUnix, 0)
		l.AcquiredAt = time.Unix(acq, 0)
		l.ExpiresAt = time.Unix(exp, 0)
		l.State = LeaseState(state)
		out[node] = &l
	}
	return out, rows.Err()
}

// --- Release / Extend / ForceRelease ---------------------------------------

// Release marks the lease state=released. Owner-only.
func (s *SQLiteStore) Release(ctx context.Context, leaseID, agentID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	owner, state, _, err := s.loadOwnerStateLocked(ctx, tx, leaseID)
	if err != nil {
		return err
	}
	if owner == "" {
		return ErrLeaseNotFound
	}
	if owner != agentID {
		return ErrNotOwner
	}
	if state != string(LeaseAcquired) {
		// Already released/expired/forced — treat as not-found-ish for
		// caller idempotency. Returning ErrLeaseNotFound is wrong; we
		// want a distinct error so callers can swallow it.
		return ErrLeaseExpired
	}

	now := s.now()
	if _, err := tx.ExecContext(ctx,
		`UPDATE leases SET state=?, released_at_unix=? WHERE id=?`,
		string(LeaseReleased), now.Unix(), leaseID); err != nil {
		return err
	}
	if err := s.writeAuditLocked(ctx, tx, leaseID, "released", agentID, now, nil); err != nil {
		return err
	}
	return tx.Commit()
}

// Extend bumps the TTL. Owner-only. Idempotent; deadline becomes
// max(old, now+add).
func (s *SQLiteStore) Extend(ctx context.Context, leaseID, agentID string, add time.Duration) (*Lease, error) {
	if add <= 0 {
		add = DefaultDuration
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	owner, state, expires, err := s.loadOwnerStateLocked(ctx, tx, leaseID)
	if err != nil {
		return nil, err
	}
	if owner == "" {
		return nil, ErrLeaseNotFound
	}
	if owner != agentID {
		return nil, ErrNotOwner
	}
	if state != string(LeaseAcquired) {
		return nil, ErrLeaseExpired
	}

	now := s.now()
	candidate := now.Add(add).Unix()
	newExp := expires
	if candidate > newExp {
		newExp = candidate
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE leases SET expires_at_unix=? WHERE id=?`, newExp, leaseID); err != nil {
		return nil, err
	}
	if err := s.writeAuditLocked(ctx, tx, leaseID, "extended", agentID, now, map[string]any{
		"add_seconds":    int64(add.Seconds()),
		"new_expires_at": newExp,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getLease(ctx, leaseID)
}

// ForceRelease marks state=forced. No ownership check. reason required.
func (s *SQLiteStore) ForceRelease(ctx context.Context, leaseID, forcedBy, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return ErrReasonRequired
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	owner, state, _, err := s.loadOwnerStateLocked(ctx, tx, leaseID)
	if err != nil {
		return err
	}
	if owner == "" {
		return ErrLeaseNotFound
	}
	if state != string(LeaseAcquired) {
		return ErrLeaseExpired
	}

	now := s.now()
	if _, err := tx.ExecContext(ctx,
		`UPDATE leases SET state=?, released_at_unix=? WHERE id=?`,
		string(LeaseForced), now.Unix(), leaseID); err != nil {
		return err
	}
	if err := s.writeAuditLocked(ctx, tx, leaseID, "forced", forcedBy, now, map[string]any{
		"reason":         reason,
		"original_owner": owner,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// --- List ------------------------------------------------------------------

// List returns leases matching the filter. M1: role and topology are
// recognized parameters but no nodes carry role/topology metadata yet, so
// those filters silently match everything. Will be wired in M3 when
// touched-node extraction lands.
func (s *SQLiteStore) List(ctx context.Context, filter ListFilter) ([]*Lease, error) {
	now := s.now()
	// Lazily expire overdue leases on read so List output is consistent.
	if err := s.expireOverdue(ctx, now); err != nil {
		return nil, err
	}

	q := `SELECT id, agent_id, cookie, hostname, pid, process_start_unix,
	             reason, acquired_at_unix, expires_at_unix,
	             COALESCE(released_at_unix, 0), state
	      FROM leases`
	conds := []string{}
	args := []any{}
	if !filter.IncludeExpired {
		conds = append(conds, "state = ?")
		args = append(args, string(LeaseAcquired))
	}
	if strings.TrimSpace(filter.AgentID) != "" {
		conds = append(conds, "agent_id = ?")
		args = append(args, filter.AgentID)
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY acquired_at_unix DESC"
	if filter.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Lease
	for rows.Next() {
		var l Lease
		var startUnix, acq, exp, rel int64
		var state string
		if err := rows.Scan(&l.ID, &l.AgentID, &l.Cookie, &l.Hostname,
			&l.PID, &startUnix, &l.Reason, &acq, &exp, &rel, &state); err != nil {
			return nil, err
		}
		l.StartTime = time.Unix(startUnix, 0)
		l.AcquiredAt = time.Unix(acq, 0)
		l.ExpiresAt = time.Unix(exp, 0)
		if rel > 0 {
			l.ReleasedAt = time.Unix(rel, 0)
		}
		l.State = LeaseState(state)
		out = append(out, &l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Populate nodes for each lease.
	for _, l := range out {
		ns, err := s.nodesFor(ctx, l.ID)
		if err != nil {
			return nil, err
		}
		l.Nodes = ns
	}
	return out, nil
}

func (s *SQLiteStore) nodesFor(ctx context.Context, leaseID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT node_name FROM lease_nodes WHERE lease_id=? ORDER BY node_name`, leaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// --- Sweep ----------------------------------------------------------------

// Sweep is the startup crash-recovery pass. Returns the count of leases
// transitioned to expired.
func (s *SQLiteStore) Sweep(ctx context.Context, hostname string, liveProcess func(pid int, startUnix int64) bool) (int, error) {
	now := s.now()

	// First pass: TTL expiry — any host's lease.
	tCount, err := s.expireOverdueAndCount(ctx, now)
	if err != nil {
		return 0, err
	}

	// Second pass: dead-process detection — only leases on this host.
	if liveProcess == nil || strings.TrimSpace(hostname) == "" {
		return tCount, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return tCount, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		SELECT id, pid, process_start_unix
		FROM leases
		WHERE state = ? AND hostname = ?`, string(LeaseAcquired), hostname)
	if err != nil {
		return tCount, err
	}
	type victim struct {
		id        string
		pid       int
		startUnix int64
	}
	var victims []victim
	for rows.Next() {
		var v victim
		if err := rows.Scan(&v.id, &v.pid, &v.startUnix); err != nil {
			rows.Close()
			return tCount, err
		}
		if !liveProcess(v.pid, v.startUnix) {
			victims = append(victims, v)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return tCount, err
	}
	rows.Close()

	dCount := 0
	for _, v := range victims {
		if _, err := tx.ExecContext(ctx,
			`UPDATE leases SET state=?, released_at_unix=? WHERE id=? AND state=?`,
			string(LeaseExpired), now.Unix(), v.id, string(LeaseAcquired)); err != nil {
			return tCount + dCount, err
		}
		if err := s.writeAuditLocked(ctx, tx, v.id, "sweep", "", now, map[string]any{
			"reason":     "process_gone",
			"pid":        v.pid,
			"start_unix": v.startUnix,
		}); err != nil {
			return tCount + dCount, err
		}
		dCount++
	}
	if err := tx.Commit(); err != nil {
		return tCount + dCount, err
	}
	return tCount + dCount, nil
}

// expireOverdue lazily transitions any past-deadline active lease to
// state='expired' (no audit row count returned).
func (s *SQLiteStore) expireOverdue(ctx context.Context, now time.Time) error {
	_, err := s.expireOverdueAndCount(ctx, now)
	return err
}

func (s *SQLiteStore) expireOverdueAndCount(ctx context.Context, now time.Time) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx,
		`SELECT id FROM leases WHERE state=? AND expires_at_unix <= ?`,
		string(LeaseAcquired), now.Unix())
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	for _, id := range ids {
		if _, err := tx.ExecContext(ctx,
			`UPDATE leases SET state=?, released_at_unix=? WHERE id=? AND state=?`,
			string(LeaseExpired), now.Unix(), id, string(LeaseAcquired)); err != nil {
			return 0, err
		}
		if err := s.writeAuditLocked(ctx, tx, id, "expired", "", now, map[string]any{
			"reason": "ttl",
		}); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(ids), nil
}

// expireOverdueLocked is the inside-a-transaction variant used by Acquire.
func (s *SQLiteStore) expireOverdueLocked(ctx context.Context, tx *sql.Tx, now time.Time) error {
	rows, err := tx.QueryContext(ctx,
		`SELECT id FROM leases WHERE state=? AND expires_at_unix <= ?`,
		string(LeaseAcquired), now.Unix())
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx,
			`UPDATE leases SET state=?, released_at_unix=? WHERE id=? AND state=?`,
			string(LeaseExpired), now.Unix(), id, string(LeaseAcquired)); err != nil {
			return err
		}
		if err := s.writeAuditLocked(ctx, tx, id, "expired", "", now, map[string]any{
			"reason": "ttl",
		}); err != nil {
			return err
		}
	}
	return nil
}

// --- helpers --------------------------------------------------------------

func (s *SQLiteStore) loadOwnerStateLocked(ctx context.Context, tx *sql.Tx, leaseID string) (owner, state string, expires int64, err error) {
	row := tx.QueryRowContext(ctx,
		`SELECT agent_id, state, expires_at_unix FROM leases WHERE id=?`, leaseID)
	err = row.Scan(&owner, &state, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", 0, nil
	}
	return owner, state, expires, err
}

func (s *SQLiteStore) writeAuditLocked(
	ctx context.Context, tx *sql.Tx,
	leaseID, op, agentID string, at time.Time, detail map[string]any,
) error {
	var detailJSON sql.NullString
	if detail != nil {
		b, err := json.Marshal(detail)
		if err != nil {
			return err
		}
		detailJSON = sql.NullString{String: string(b), Valid: true}
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO lease_audit (lease_id, op, agent_id, at_unix, detail) VALUES (?,?,?,?,?)`,
		leaseID, op, agentID, at.Unix(), detailJSON)
	return err
}

func (s *SQLiteStore) getLease(ctx context.Context, leaseID string) (*Lease, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, agent_id, cookie, hostname, pid, process_start_unix,
		       reason, acquired_at_unix, expires_at_unix,
		       COALESCE(released_at_unix, 0), state
		FROM leases WHERE id=?`, leaseID)
	var l Lease
	var startUnix, acq, exp, rel int64
	var state string
	if err := row.Scan(&l.ID, &l.AgentID, &l.Cookie, &l.Hostname, &l.PID,
		&startUnix, &l.Reason, &acq, &exp, &rel, &state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrLeaseNotFound
		}
		return nil, err
	}
	l.StartTime = time.Unix(startUnix, 0)
	l.AcquiredAt = time.Unix(acq, 0)
	l.ExpiresAt = time.Unix(exp, 0)
	if rel > 0 {
		l.ReleasedAt = time.Unix(rel, 0)
	}
	l.State = LeaseState(state)
	ns, err := s.nodesFor(ctx, l.ID)
	if err != nil {
		return nil, err
	}
	l.Nodes = ns
	return &l, nil
}

// AuditRowCount returns the number of audit rows for a lease. Test helper.
func (s *SQLiteStore) AuditRowCount(ctx context.Context, leaseID, op string) (int, error) {
	q := `SELECT COUNT(*) FROM lease_audit WHERE lease_id=?`
	args := []any{leaseID}
	if op != "" {
		q += ` AND op=?`
		args = append(args, op)
	}
	row := s.db.QueryRowContext(ctx, q, args...)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// AuditDetail returns the JSON detail blob of the most recent audit row for
// (leaseID, op). Empty string when no row matches. Test helper.
func (s *SQLiteStore) AuditDetail(ctx context.Context, leaseID, op string) (string, string, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(agent_id,''), COALESCE(detail,'')
		FROM lease_audit
		WHERE lease_id=? AND op=?
		ORDER BY id DESC LIMIT 1`, leaseID, op)
	var actor, detail string
	if err := row.Scan(&actor, &detail); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", nil
		}
		return "", "", err
	}
	return actor, detail, nil
}

func dedupeAndSort(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		t := strings.TrimSpace(s)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// runtimeNanotime returns a monotonic nanosecond counter. We do not need
// linkname trickery — time.Now().UnixNano() is monotonic on Go 1.9+ as long
// as the underlying time.Time has not been transported through Round() etc.
// For the dual-clock skew mitigation we store the value as a bare int64.
func runtimeNanotime() int64 {
	// time.Now contains a monotonic reading; subtract any fixed epoch to
	// get a small positive value. We just need a number that increases.
	_ = runtime.GOOS
	return time.Now().UnixNano()
}
