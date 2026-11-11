package isolatedstate

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	CurrentSchemaVersion = 1
	schemaVersionKey     = "schema_version"
)

//go:embed schema.sql
var initialSchemaSQL string

type migration struct {
	version int
	sql     string
}

var schemaMigrations = []migration{
	{version: 1, sql: initialSchemaSQL},
}

// Store is one process-local handle to the shared isolated state database.
// SQLite WAL and BEGIN IMMEDIATE coordinate independent LabLink processes.
type Store struct {
	db   *sql.DB
	path string
}

// DefaultDBPath returns the isolated state path under LABLINK_HOME.
func DefaultDBPath() string {
	if home := strings.TrimSpace(os.Getenv("LABLINK_HOME")); home != "" {
		return filepath.Join(home, "isolated.db")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".", ".lablink", "isolated.db")
	}
	return filepath.Join(home, ".lablink", "isolated.db")
}

// Open opens the shared database, configures SQLite, and applies every
// forward migration in one transaction. No database backup is created.
func Open(path string) (*Store, error) {
	return openWithMigrations(path, schemaMigrations)
}

func openWithMigrations(path string, migrations []migration) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultDBPath()
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("isolatedstate: mkdir %s: %w", dir, err)
		}
	}

	dsn := fmt.Sprintf(
		"file:%s?_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)&_txlock=immediate",
		path,
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("isolatedstate: open: %w", err)
	}
	closeOnError := func(err error) (*Store, error) {
		_ = db.Close()
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return closeOnError(fmt.Errorf("isolatedstate: ping: %w", err))
	}
	for _, pragma := range []string{
		"PRAGMA busy_timeout=5000",
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA foreign_keys=ON",
	} {
		if err := execOpenPragma(db, pragma); err != nil {
			return closeOnError(fmt.Errorf("isolatedstate: %s: %w", pragma, err))
		}
	}

	if err := applyMigrations(context.Background(), db, migrations); err != nil {
		return closeOnError(err)
	}
	return &Store{db: db, path: path}, nil
}

func execOpenPragma(db *sql.DB, pragma string) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := db.Exec(pragma)
		if err == nil {
			return nil
		}
		message := strings.ToLower(err.Error())
		if (!strings.Contains(message, "sqlite_busy") &&
			!strings.Contains(message, "database is locked")) ||
			time.Now().After(deadline) {
			return err
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func applyMigrations(ctx context.Context, db *sql.DB, migrations []migration) error {
	migrations = append([]migration(nil), migrations...)
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})
	for i, m := range migrations {
		if m.version != i+1 {
			return fmt.Errorf("isolatedstate: migrations must be contiguous from version 1; found version %d at index %d", m.version, i)
		}
		if strings.TrimSpace(m.sql) == "" {
			return fmt.Errorf("isolatedstate: migration %d is empty", m.version)
		}
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("isolatedstate: begin migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	current, err := schemaVersionInTx(ctx, tx)
	if err != nil {
		return err
	}
	if current > len(migrations) {
		return fmt.Errorf(
			"isolatedstate: database schema version %d is newer than supported version %d",
			current, len(migrations),
		)
	}

	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if m.version != current+1 {
			return fmt.Errorf("isolatedstate: missing migration from version %d to %d", current, m.version)
		}
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			return fmt.Errorf("isolatedstate: apply migration %d: %w", m.version, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO schema_meta(key, value) VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			schemaVersionKey, strconv.Itoa(m.version),
		); err != nil {
			return fmt.Errorf("isolatedstate: record migration %d: %w", m.version, err)
		}
		current = m.version
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("isolatedstate: commit migration: %w", err)
	}
	return nil
}

func schemaVersionInTx(ctx context.Context, tx *sql.Tx) (int, error) {
	var exists int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sqlite_master
		WHERE type='table' AND name='schema_meta'`).Scan(&exists); err != nil {
		return 0, fmt.Errorf("isolatedstate: find schema metadata: %w", err)
	}
	if exists == 0 {
		return 0, nil
	}

	var value string
	err := tx.QueryRowContext(ctx,
		`SELECT value FROM schema_meta WHERE key=?`, schemaVersionKey,
	).Scan(&value)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("isolatedstate: schema_meta exists without %q", schemaVersionKey)
	}
	if err != nil {
		return 0, fmt.Errorf("isolatedstate: read schema version: %w", err)
	}
	version, err := strconv.Atoi(value)
	if err != nil || version < 0 {
		return 0, fmt.Errorf("isolatedstate: invalid schema version %q", value)
	}
	return version, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var value string
	if err := s.db.QueryRowContext(ctx,
		`SELECT value FROM schema_meta WHERE key=?`, schemaVersionKey,
	).Scan(&value); err != nil {
		return 0, err
	}
	version, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("isolatedstate: invalid schema version %q", value)
	}
	return version, nil
}

func (s *Store) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	return s.db.BeginTx(ctx, opts)
}

func (s *Store) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(ctx, query, args...)
}

func (s *Store) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, query, args...)
}

func (s *Store) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return s.db.QueryRowContext(ctx, query, args...)
}
