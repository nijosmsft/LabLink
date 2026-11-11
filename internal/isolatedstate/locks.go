package isolatedstate

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

var (
	ErrLockNotHeld        = errors.New("isolatedstate: lock is not held by this lease")
	ErrLockOrderViolation = errors.New("isolatedstate: lock order violation")
)

type LockContentionError struct {
	Key         string
	Holder      ProcessIdentity
	OperationID string
	Fence       int64
	ExpiresAt   UnixSeconds
}

func (e *LockContentionError) Error() string {
	return fmt.Sprintf(
		"isolatedstate: lock %s held by %s pid %d for operation %s at fence %d until %d",
		e.Key, e.Holder.Hostname, e.Holder.PID, e.OperationID, e.Fence, e.ExpiresAt,
	)
}

type StaleFenceError struct {
	Key              string
	LeaseFence       int64
	CurrentFence     int64
	CurrentHolder    string
	CurrentOperation string
}

func (e *StaleFenceError) Error() string {
	return fmt.Sprintf(
		"isolatedstate: stale fence for %s: lease %d, current %d held by %s for %s",
		e.Key, e.LeaseFence, e.CurrentFence, e.CurrentHolder, e.CurrentOperation,
	)
}

type ProcessLivenessFunc func(context.Context, ProcessIdentity) (alive bool, proven bool, err error)

type LockManagerOptions struct {
	Identity ProcessIdentity
	Now      func() time.Time
	Liveness ProcessLivenessFunc
}

type LockAcquireRequest struct {
	Key         string
	OperationID string
	TTL         time.Duration
}

type LockManager struct {
	store    *Store
	identity ProcessIdentity
	now      func() time.Time
	liveness ProcessLivenessFunc

	mu   sync.Mutex
	held map[string]LockLease
}

var (
	processIdentityOnce sync.Once
	processIdentity     ProcessIdentity
	processIdentityErr  error
)

func NewProcessIdentity() (ProcessIdentity, error) {
	processIdentityOnce.Do(func() {
		processIdentity, processIdentityErr = generateProcessIdentity()
	})
	return processIdentity, processIdentityErr
}

func generateProcessIdentity() (ProcessIdentity, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("isolatedstate: hostname: %w", err)
	}
	pid := os.Getpid()
	current, err := process.NewProcess(int32(pid))
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("isolatedstate: current process: %w", err)
	}
	startMillis, err := current.CreateTime()
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("isolatedstate: current process start: %w", err)
	}
	cookieBytes := make([]byte, 32)
	if _, err := rand.Read(cookieBytes); err != nil {
		return ProcessIdentity{}, fmt.Errorf("isolatedstate: process cookie: %w", err)
	}
	return ProcessIdentity{
		Hostname:     canonicalHostname(hostname),
		PID:          pid,
		ProcessStart: UnixSeconds(startMillis / 1000),
		Cookie:       hex.EncodeToString(cookieBytes),
	}, nil
}

func NewLockManager(store *Store, options LockManagerOptions) (*LockManager, error) {
	if store == nil || store.db == nil {
		return nil, errors.New("isolatedstate: lock manager requires an open store")
	}
	identity := options.Identity
	if identity.Cookie == "" {
		var err error
		identity, err = NewProcessIdentity()
		if err != nil {
			return nil, err
		}
	}
	identity.Hostname = canonicalHostname(identity.Hostname)
	identity.Cookie = canonicalToken(identity.Cookie)
	if identity.Hostname == "" || identity.PID <= 0 || identity.ProcessStart <= 0 || identity.Cookie == "" {
		return nil, errors.New("isolatedstate: incomplete process identity")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	liveness := options.Liveness
	if liveness == nil {
		liveness = localProcessLiveness
	}
	return &LockManager{
		store: store, identity: identity, now: now, liveness: liveness,
		held: make(map[string]LockLease),
	}, nil
}

func HostLockKey(physicalHostID string) (string, error) {
	id, err := canonicalLockID(physicalHostID)
	if err != nil {
		return "", err
	}
	return "host:" + id + ":orchestrator-create", nil
}

func OrchestratorLockKey(orchestratorID string) (string, error) {
	return simpleLockKey("orchestrator", orchestratorID)
}

func AllocationLockKey(orchestratorID string) (string, error) {
	return simpleLockKey("allocation", orchestratorID)
}

func NetworkLockKey(networkID string) (string, error) {
	return simpleLockKey("network", networkID)
}

func VMLockKey(vmID string) (string, error) {
	return simpleLockKey("vm", vmID)
}

func RelayLockKey(relayID string) (string, error) {
	return simpleLockKey("relay", relayID)
}

func NATLockKey(vmID string) (string, error) {
	return simpleLockKey("nat", vmID)
}

func CanonicalLockKey(key string) (string, LockLevel, error) {
	parts := strings.Split(canonicalToken(key), ":")
	if len(parts) == 3 && parts[0] == "host" && parts[2] == "orchestrator-create" {
		id, err := canonicalLockID(parts[1])
		if err != nil {
			return "", 0, err
		}
		return "host:" + id + ":orchestrator-create", LockLevelHost, nil
	}
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("isolatedstate: invalid lock key %q", key)
	}
	id, err := canonicalLockID(parts[1])
	if err != nil {
		return "", 0, err
	}
	var level LockLevel
	switch parts[0] {
	case "orchestrator":
		level = LockLevelOrchestrator
	case "allocation":
		level = LockLevelAllocation
	case "network":
		level = LockLevelNetwork
	case "vm":
		level = LockLevelVM
	case "relay", "nat":
		level = LockLevelChild
	default:
		return "", 0, fmt.Errorf("isolatedstate: unknown lock key kind %q", parts[0])
	}
	return parts[0] + ":" + id, level, nil
}

func (m *LockManager) Identity() ProcessIdentity {
	return m.identity
}

func (m *LockManager) Acquire(ctx context.Context, request LockAcquireRequest) (LockLease, error) {
	key, level, err := CanonicalLockKey(request.Key)
	if err != nil {
		return LockLease{}, err
	}
	request.OperationID = canonicalID(request.OperationID)
	if request.OperationID == "" {
		return LockLease{}, errors.New("isolatedstate: lock operation ID must not be empty")
	}
	if request.TTL <= 0 {
		return LockLease{}, errors.New("isolatedstate: lock TTL must be positive")
	}
	nowTime := m.now()
	now := UnixSeconds(nowTime.Unix())
	expires := UnixSeconds(nowTime.Add(request.TTL).Unix())

	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.held[key]; ok {
		if existing.OperationID != request.OperationID {
			return LockLease{}, &LockContentionError{
				Key: key, Holder: m.identity, OperationID: existing.OperationID,
				Fence: existing.Fence, ExpiresAt: existing.ExpiresAt,
			}
		}
		if existing.ExpiresAt > now {
			return existing, nil
		}
		delete(m.held, key)
	}
	if err := validateLockOrder(m.held, level); err != nil {
		return LockLease{}, err
	}

	tx, err := m.store.db.BeginTx(ctx, nil)
	if err != nil {
		return LockLease{}, fmt.Errorf("isolatedstate: begin lock acquire: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	current, found, err := readLock(ctx, tx, key)
	if err != nil {
		return LockLease{}, err
	}
	if found && lockOwnedBy(current, m.identity, request.OperationID) && current.ExpiresAt > now {
		lease := LockLease{Lock: current, Level: level}
		m.held[key] = lease
		return lease, nil
	}
	if found {
		reclaimable := current.ExpiresAt <= now
		if current.HolderHostname == m.identity.Hostname {
			alive, proven, probeErr := m.liveness(ctx, ProcessIdentity{
				Hostname: current.HolderHostname, PID: current.HolderPID,
				ProcessStart: current.HolderProcessStart, Cookie: current.HolderCookie,
			})
			if probeErr != nil || !proven {
				reclaimable = false
			} else if !alive {
				reclaimable = true
			}
		}
		if !reclaimable {
			return LockLease{}, contentionFromLock(current)
		}
	}

	fence, err := nextFence(ctx, tx, key)
	if err != nil {
		return LockLease{}, err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO locks (
			lock_key, holder_cookie, holder_hostname, holder_pid,
			holder_process_start_unix, operation_id, fence, acquired_at_unix,
			heartbeat_at_unix, expires_at_unix
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(lock_key) DO UPDATE SET
			holder_cookie=excluded.holder_cookie,
			holder_hostname=excluded.holder_hostname,
			holder_pid=excluded.holder_pid,
			holder_process_start_unix=excluded.holder_process_start_unix,
			operation_id=excluded.operation_id,
			fence=excluded.fence,
			acquired_at_unix=excluded.acquired_at_unix,
			heartbeat_at_unix=excluded.heartbeat_at_unix,
			expires_at_unix=excluded.expires_at_unix`,
		key, m.identity.Cookie, m.identity.Hostname, m.identity.PID,
		m.identity.ProcessStart, request.OperationID, fence, now, now, expires,
	)
	if err != nil {
		return LockLease{}, fmt.Errorf("isolatedstate: acquire lock: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return LockLease{}, fmt.Errorf("isolatedstate: commit lock acquire: %w", err)
	}
	lease := LockLease{
		Lock: Lock{
			LockKey: key, HolderCookie: m.identity.Cookie,
			HolderHostname: m.identity.Hostname, HolderPID: m.identity.PID,
			HolderProcessStart: m.identity.ProcessStart,
			OperationID:        request.OperationID, Fence: fence,
			AcquiredAt: now, HeartbeatAt: now, ExpiresAt: expires,
		},
		Level: level,
	}
	m.held[key] = lease
	return lease, nil
}

// Reclaim acquires a lock only when normal lease-expiry or proven process-death
// rules permit replacing its prior holder. A successful reclaim advances the
// same durable fencing sequence as any other acquisition.
func (m *LockManager) Reclaim(ctx context.Context, request LockAcquireRequest) (LockLease, error) {
	return m.Acquire(ctx, request)
}

func (m *LockManager) Renew(
	ctx context.Context,
	lease LockLease,
	ttl time.Duration,
) (LockLease, error) {
	if ttl <= 0 {
		return LockLease{}, errors.New("isolatedstate: lock TTL must be positive")
	}
	key, level, err := CanonicalLockKey(lease.LockKey)
	if err != nil {
		return LockLease{}, err
	}
	nowTime := m.now()
	now := UnixSeconds(nowTime.Unix())
	expires := UnixSeconds(nowTime.Add(ttl).Unix())

	m.mu.Lock()
	defer m.mu.Unlock()
	currentHeld, ok := m.held[key]
	if !ok || currentHeld.Fence != lease.Fence {
		return LockLease{}, ErrLockNotHeld
	}
	tx, err := m.store.db.BeginTx(ctx, nil)
	if err != nil {
		return LockLease{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, found, err := readLock(ctx, tx, key)
	if err != nil {
		return LockLease{}, err
	}
	if !found || !lockOwnedBy(current, m.identity, lease.OperationID) ||
		current.Fence != lease.Fence || current.ExpiresAt <= now {
		return LockLease{}, staleFenceFromLock(key, lease.Fence, current, found)
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE locks SET heartbeat_at_unix=?, expires_at_unix=?
		WHERE lock_key=? AND holder_cookie=? AND fence=? AND operation_id=?`,
		now, expires, key, m.identity.Cookie, lease.Fence, lease.OperationID,
	)
	if err != nil {
		return LockLease{}, fmt.Errorf("isolatedstate: renew lock: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return LockLease{}, err
	}
	lease.LockKey = key
	lease.Level = level
	lease.HeartbeatAt = now
	lease.ExpiresAt = expires
	m.held[key] = lease
	return lease, nil
}

func (m *LockManager) Release(ctx context.Context, lease LockLease) error {
	key, _, err := CanonicalLockKey(lease.LockKey)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	tx, err := m.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		DELETE FROM locks
		WHERE lock_key=? AND holder_cookie=? AND holder_hostname=? AND holder_pid=?
		  AND holder_process_start_unix=? AND operation_id=? AND fence=?`,
		key, m.identity.Cookie, m.identity.Hostname, m.identity.PID,
		m.identity.ProcessStart, lease.OperationID, lease.Fence,
	)
	if err != nil {
		return fmt.Errorf("isolatedstate: release lock: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		current, found, readErr := readLock(ctx, tx, key)
		if readErr != nil {
			return readErr
		}
		return staleFenceFromLock(key, lease.Fence, current, found)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	delete(m.held, key)
	return nil
}

func (m *LockManager) HeldLocks() []LockLease {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]LockLease, 0, len(m.held))
	for _, lease := range m.held {
		result = append(result, lease)
	}
	return result
}

func validateLockOrder(held map[string]LockLease, requested LockLevel) error {
	var highest LockLevel
	for _, lease := range held {
		if lease.Level > highest {
			highest = lease.Level
		}
	}
	if requested < highest {
		return fmt.Errorf("%w: cannot acquire level %d while holding level %d",
			ErrLockOrderViolation, requested, highest)
	}
	return nil
}

func readLock(ctx context.Context, tx *sql.Tx, key string) (Lock, bool, error) {
	var lock Lock
	err := tx.QueryRowContext(ctx, `
		SELECT lock_key, holder_cookie, holder_hostname, holder_pid,
		       holder_process_start_unix, operation_id, fence, acquired_at_unix,
		       heartbeat_at_unix, expires_at_unix
		FROM locks WHERE lock_key=?`,
		key,
	).Scan(
		&lock.LockKey, &lock.HolderCookie, &lock.HolderHostname, &lock.HolderPID,
		&lock.HolderProcessStart, &lock.OperationID, &lock.Fence,
		&lock.AcquiredAt, &lock.HeartbeatAt, &lock.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Lock{}, false, nil
	}
	if err != nil {
		return Lock{}, false, fmt.Errorf("isolatedstate: read lock: %w", err)
	}
	return lock, true, nil
}

func nextFence(ctx context.Context, tx *sql.Tx, key string) (int64, error) {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO lock_fences(lock_key, last_fence) VALUES (?, 1)
		ON CONFLICT(lock_key) DO UPDATE SET last_fence=last_fence+1`,
		key,
	)
	if err != nil {
		return 0, fmt.Errorf("isolatedstate: advance lock fence: %w", err)
	}
	var fence int64
	if err := tx.QueryRowContext(ctx,
		`SELECT last_fence FROM lock_fences WHERE lock_key=?`, key,
	).Scan(&fence); err != nil {
		return 0, fmt.Errorf("isolatedstate: read lock fence: %w", err)
	}
	return fence, nil
}

func localProcessLiveness(
	_ context.Context,
	identity ProcessIdentity,
) (alive bool, proven bool, err error) {
	current, err := process.NewProcess(int32(identity.PID))
	if err != nil {
		if errors.Is(err, process.ErrorProcessNotRunning) {
			return false, true, nil
		}
		return false, false, err
	}
	running, err := current.IsRunning()
	if err != nil {
		return false, false, err
	}
	if !running {
		return false, true, nil
	}
	startMillis, err := current.CreateTime()
	if err != nil {
		return false, false, err
	}
	if UnixSeconds(startMillis/1000) != identity.ProcessStart {
		return false, true, nil
	}
	return true, true, nil
}

func lockOwnedBy(lock Lock, identity ProcessIdentity, operationID string) bool {
	return lock.HolderCookie == identity.Cookie &&
		lock.HolderHostname == identity.Hostname &&
		lock.HolderPID == identity.PID &&
		lock.HolderProcessStart == identity.ProcessStart &&
		lock.OperationID == operationID
}

func contentionFromLock(lock Lock) error {
	return &LockContentionError{
		Key: lock.LockKey,
		Holder: ProcessIdentity{
			Hostname: lock.HolderHostname, PID: lock.HolderPID,
			ProcessStart: lock.HolderProcessStart, Cookie: lock.HolderCookie,
		},
		OperationID: lock.OperationID, Fence: lock.Fence, ExpiresAt: lock.ExpiresAt,
	}
}

func staleFenceFromLock(key string, leaseFence int64, current Lock, found bool) error {
	if !found {
		return &StaleFenceError{Key: key, LeaseFence: leaseFence}
	}
	return &StaleFenceError{
		Key: key, LeaseFence: leaseFence, CurrentFence: current.Fence,
		CurrentHolder: current.HolderCookie, CurrentOperation: current.OperationID,
	}
}

func simpleLockKey(kind, id string) (string, error) {
	canonical, err := canonicalLockID(id)
	if err != nil {
		return "", err
	}
	return kind + ":" + canonical, nil
}

func canonicalLockID(value string) (string, error) {
	value = canonicalID(value)
	if value == "" || strings.Contains(value, ":") {
		return "", fmt.Errorf("isolatedstate: invalid lock resource ID %q", value)
	}
	return value, nil
}

func canonicalHostname(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
