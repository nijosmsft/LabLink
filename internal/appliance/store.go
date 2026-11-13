package appliance

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
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

type Store struct {
	db   *sql.DB
	path string
	now  func() time.Time
	mu   sync.RWMutex
}

func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultDBPath
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
	store := &Store{db: db, path: path, now: time.Now}
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
		WHERE type='table' AND name='appliance_meta'
	`).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		if _, err := s.db.ExecContext(ctx, schemaSQL); err != nil {
			return err
		}
		_, err := s.db.ExecContext(ctx,
			`INSERT INTO appliance_meta(key,value) VALUES ('schema_version',?)`,
			strconv.Itoa(CurrentSchemaVersion))
		return err
	}
	version, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if version != CurrentSchemaVersion {
		return &StoreError{
			Code: CodeUnsupportedSchema,
			Message: fmt.Sprintf(
				"schema %d is unsupported; replace the disposable appliance database with schema %d",
				version, CurrentSchemaVersion),
		}
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
		`SELECT value FROM appliance_meta WHERE key='schema_version'`,
	).Scan(&raw); err != nil {
		return 0, err
	}
	return strconv.Atoi(raw)
}

func (s *Store) JournalMode(ctx context.Context) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&value)
	return value, err
}

func (s *Store) ForeignKeysEnabled(ctx context.Context) (bool, error) {
	var value int
	err := s.db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&value)
	return value == 1, err
}

func (s *Store) BusyTimeout(ctx context.Context) (int, error) {
	var value int
	err := s.db.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&value)
	return value, err
}

func (s *Store) Status(ctx context.Context) (Status, error) {
	var value Status
	var ready int
	err := s.db.QueryRowContext(ctx, `
		SELECT ready,error_text,updated_at_unix
		FROM appliance_status WHERE singleton=1
	`).Scan(&ready, &value.Error, &value.UpdatedAtUnix)
	value.Ready = ready != 0
	return value, err
}

func (s *Store) SetReadiness(
	ctx context.Context,
	ready bool,
	errorText string,
) error {
	readyValue := 0
	if ready {
		readyValue = 1
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE appliance_status
		SET ready=?,error_text=?,updated_at_unix=?
		WHERE singleton=1
	`, readyValue, strings.TrimSpace(errorText), s.now().Unix())
	return err
}

func (s *Store) Snapshot(ctx context.Context) (StaticSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result StaticSnapshot
	var err error
	if result.Status, err = s.Status(ctx); err != nil {
		return result, err
	}
	if result.Networks, err = listNetworks(ctx, s.db); err != nil {
		return result, err
	}
	if result.Guests, err = listGuests(ctx, s.db); err != nil {
		return result, err
	}
	if result.Relays, err = listRelays(ctx, s.db); err != nil {
		return result, err
	}
	if result.NAT, err = listNAT(ctx, s.db); err != nil {
		return result, err
	}
	return result, nil
}

func (s *Store) ReplaceStaticConfig(
	ctx context.Context,
	config StaticConfig,
) error {
	if err := ValidateStaticConfig(config); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, table := range []string{"nat_state", "relays", "guests", "networks"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return err
		}
	}
	for _, value := range config.Networks {
		dns := strings.TrimSpace(value.DNSServersJSON)
		if dns == "" {
			dns = "[]"
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO networks(
				id,cidr,gateway_ipv4,nic_mac,interface_name,dns_servers_json,
				state,last_error
			) VALUES(?,?,?,?,NULLIF(?,''),?,'active','')
		`, value.ID, value.CIDR, value.GatewayIPv4, value.NICMAC,
			value.InterfaceName, dns); err != nil {
			return err
		}
	}
	for _, value := range config.Guests {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO guests(id,network_id,ipv4,mac,state,last_error)
			VALUES(?,?,?,?,'active','')
		`, value.ID, value.NetworkID, value.IPv4, value.MAC); err != nil {
			return err
		}
	}
	for _, value := range config.Relays {
		targetPort := value.TargetPort
		if targetPort == 0 {
			targetPort = RelayTargetPort
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO relays(
				id,vm_id,listen_port,target_ipv4,target_port,state,
				bound_main_ip,last_bind_error
			) VALUES(?,?,?,?,?,'pending','','')
		`, value.ID, value.VMID, value.ListenPort,
			value.TargetIPv4, targetPort); err != nil {
			return err
		}
	}
	for _, value := range config.NAT {
		state := "disabled"
		if value.Enabled {
			state = "enabled"
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO nat_state(vm_id,state,conntrack_mark,last_error)
			VALUES(?,?,?,'')
		`, value.VMID, state, value.ConntrackMark); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE appliance_status
		SET ready=0,error_text='',updated_at_unix=?
		WHERE singleton=1
	`, s.now().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) BindNetworkInterface(
	ctx context.Context,
	networkID, interfaceName string,
) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE networks SET interface_name=? WHERE id=?`,
		interfaceName, networkID)
	return err
}

func (s *Store) Relay(ctx context.Context, id string) (Relay, bool, error) {
	var value Relay
	err := s.db.QueryRowContext(ctx, `
		SELECT id,vm_id,listen_port,target_ipv4,target_port,state,
			COALESCE(bound_main_ip,''),COALESCE(last_bind_error,'')
		FROM relays WHERE id=?
	`, id).Scan(&value.ID, &value.VMID, &value.ListenPort,
		&value.TargetIPv4, &value.TargetPort, &value.State,
		&value.BoundMainIP, &value.LastBindError)
	if errors.Is(err, sql.ErrNoRows) {
		return Relay{}, false, nil
	}
	return value, err == nil, err
}

func (s *Store) SetRelayBindStatus(
	ctx context.Context,
	id, boundMainIP, bindError, state string,
) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE relays SET state=?,bound_main_ip=?,last_bind_error=?
		WHERE id=?
	`, state, boundMainIP, bindError, id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return storeError(CodeNotFound, "relay %q not found", id)
	}
	return nil
}

func (s *Store) NAT(ctx context.Context, vmID string) (NATState, bool, error) {
	var value NATState
	err := s.db.QueryRowContext(ctx, `
		SELECT vm_id,state,conntrack_mark,COALESCE(last_error,'')
		FROM nat_state WHERE vm_id=?
	`, vmID).Scan(&value.VMID, &value.State,
		&value.ConntrackMark, &value.LastError)
	if errors.Is(err, sql.ErrNoRows) {
		return NATState{}, false, nil
	}
	return value, err == nil, err
}

func listNetworks(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]Network, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id,cidr,gateway_ipv4,nic_mac,COALESCE(interface_name,''),
			dns_servers_json,state,COALESCE(last_error,'')
		FROM networks ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []Network
	for rows.Next() {
		var value Network
		if err := rows.Scan(&value.ID, &value.CIDR, &value.GatewayIPv4,
			&value.NICMAC, &value.InterfaceName, &value.DNSServersJSON,
			&value.State, &value.LastError); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func listGuests(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]Guest, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id,network_id,ipv4,mac,state,COALESCE(last_error,'')
		FROM guests ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []Guest
	for rows.Next() {
		var value Guest
		if err := rows.Scan(&value.ID, &value.NetworkID, &value.IPv4,
			&value.MAC, &value.State, &value.LastError); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func listRelays(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]Relay, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id,vm_id,listen_port,target_ipv4,target_port,state,
			COALESCE(bound_main_ip,''),COALESCE(last_bind_error,'')
		FROM relays ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []Relay
	for rows.Next() {
		var value Relay
		if err := rows.Scan(&value.ID, &value.VMID, &value.ListenPort,
			&value.TargetIPv4, &value.TargetPort, &value.State,
			&value.BoundMainIP, &value.LastBindError); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func listNAT(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]NATState, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT vm_id,state,conntrack_mark,COALESCE(last_error,'')
		FROM nat_state ORDER BY vm_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []NATState
	for rows.Next() {
		var value NATState
		if err := rows.Scan(&value.VMID, &value.State,
			&value.ConntrackMark, &value.LastError); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func storeError(code ErrorCode, format string, args ...any) error {
	return &StoreError{Code: code, Message: fmt.Sprintf(format, args...)}
}
