package isolatedstate

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

const CurrentSchemaVersion = 1

//go:embed schema.sql
var schemaSQL string

type Store struct {
	db   *sql.DB
	path string
}

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

func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultDBPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", fmt.Sprintf(
		"file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)",
		path))
	if err != nil {
		return nil, err
	}
	store := &Store{db: db, path: path}
	if err := store.initialize(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) initialize(ctx context.Context) error {
	var exists int
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sqlite_master
		WHERE type='table' AND name='schema_meta'
	`).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		if _, err := s.db.ExecContext(ctx, schemaSQL); err != nil {
			return err
		}
		_, err := s.db.ExecContext(ctx,
			`INSERT INTO schema_meta(key,value) VALUES ('schema_version',?)`,
			strconv.Itoa(CurrentSchemaVersion))
		return err
	}
	version, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if version != CurrentSchemaVersion {
		return fmt.Errorf(
			"isolatedstate: schema %d is unsupported; back up and remove the disposable isolated.db before using schema %d",
			version, CurrentSchemaVersion)
	}
	return nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Path() string { return s.path }

func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var raw string
	if err := s.db.QueryRowContext(ctx,
		`SELECT value FROM schema_meta WHERE key='schema_version'`,
	).Scan(&raw); err != nil {
		return 0, err
	}
	return strconv.Atoi(raw)
}

func (s *Store) QueryContext(
	ctx context.Context,
	query string,
	args ...any,
) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, query, args...)
}

func noRows(kind, id string, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("isolatedstate: %s %q not found", kind, id)
	}
	return err
}
