package isolatedstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrNATNotFound                = errors.New("isolatedstate: NAT allocation not found")
	ErrGuestPendingUpdateNotFound = errors.New("isolatedstate: guest pending update not found")
)

func (s *Store) PutNAT(ctx context.Context, value NATAllocation) error {
	value.VMID = canonicalID(value.VMID)
	value.OrchestratorID = canonicalID(value.OrchestratorID)
	value.UpdatedAt = nowUnix(value.UpdatedAt)
	if value.VMID == "" || value.OrchestratorID == "" || value.ConntrackMark <= 0 {
		return errors.New("isolatedstate: incomplete NAT identity")
	}
	switch value.DesiredState {
	case NATDesiredEnabled, NATDesiredDisabled:
	default:
		return fmt.Errorf("isolatedstate: invalid NAT desired state %q", value.DesiredState)
	}
	switch value.ObservedState {
	case NATObservedEnabled, NATObservedDraining, NATObservedDisabled:
	default:
		return fmt.Errorf("isolatedstate: invalid NAT observed state %q", value.ObservedState)
	}
	if value.ObservedState != NATObservedDraining {
		value.DrainStartedAt = nil
	}
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO nat_allocations (
			vm_id, orchestrator_id, desired_state, observed_state,
			conntrack_mark, desired_generation, applied_generation,
			observed_generation, drain_started_unix, updated_at_unix
		)
		SELECT ?,?,?,?,?,?,?,?,?,?
		WHERE EXISTS (
			SELECT 1 FROM isolated_vms
			WHERE id=? AND orchestrator_id=?
		)
		ON CONFLICT(vm_id) DO UPDATE SET
			desired_state=excluded.desired_state,
			observed_state=excluded.observed_state,
			desired_generation=excluded.desired_generation,
			applied_generation=excluded.applied_generation,
			observed_generation=excluded.observed_generation,
			drain_started_unix=excluded.drain_started_unix,
			updated_at_unix=excluded.updated_at_unix
		WHERE nat_allocations.orchestrator_id=excluded.orchestrator_id
		  AND nat_allocations.conntrack_mark=excluded.conntrack_mark`,
		value.VMID, value.OrchestratorID, value.DesiredState,
		value.ObservedState, value.ConntrackMark, value.DesiredGeneration,
		value.AppliedGeneration, value.ObservedGeneration,
		value.DrainStartedAt, value.UpdatedAt, value.VMID,
		value.OrchestratorID)
	if err != nil {
		return fmt.Errorf("isolatedstate: put NAT allocation: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("isolatedstate: NAT allocation rows affected: %w", err)
	}
	if affected != 1 {
		return errors.New("isolatedstate: NAT guest, orchestrator, or conntrack-mark identity mismatch")
	}
	return nil
}

func (s *Store) GetNAT(ctx context.Context, vmID string) (NATAllocation, error) {
	var value NATAllocation
	err := s.db.QueryRowContext(ctx, `
		SELECT vm_id, orchestrator_id, desired_state, observed_state,
		       conntrack_mark, desired_generation, applied_generation,
		       observed_generation, drain_started_unix, updated_at_unix
		FROM nat_allocations WHERE vm_id=?`, canonicalID(vmID)).Scan(
		&value.VMID, &value.OrchestratorID, &value.DesiredState,
		&value.ObservedState, &value.ConntrackMark, &value.DesiredGeneration,
		&value.AppliedGeneration, &value.ObservedGeneration,
		&value.DrainStartedAt, &value.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return NATAllocation{}, ErrNATNotFound
	}
	if err != nil {
		return NATAllocation{}, fmt.Errorf("isolatedstate: get NAT allocation: %w", err)
	}
	return value, nil
}

func (s *Store) ListNAT(
	ctx context.Context,
	orchestratorID, networkID, state string,
) ([]NATAllocation, error) {
	query := `
		SELECT n.vm_id, n.orchestrator_id, n.desired_state, n.observed_state,
		       n.conntrack_mark, n.desired_generation, n.applied_generation,
		       n.observed_generation, n.drain_started_unix, n.updated_at_unix
		FROM nat_allocations n
		JOIN isolated_vms v ON v.id=n.vm_id
		WHERE v.retired_at_unix IS NULL`
	var args []any
	if orchestratorID = canonicalID(orchestratorID); orchestratorID != "" {
		query += " AND n.orchestrator_id=?"
		args = append(args, orchestratorID)
	}
	if networkID = canonicalID(networkID); networkID != "" {
		query += " AND v.network_id=?"
		args = append(args, networkID)
	}
	if state = strings.ToLower(strings.TrimSpace(state)); state != "" {
		switch state {
		case "enabled", "draining", "disabled":
		default:
			return nil, fmt.Errorf("isolatedstate: invalid NAT state filter %q", state)
		}
		query += " AND (n.desired_state=? OR n.observed_state=?)"
		args = append(args, state, state)
	}
	query += " ORDER BY n.updated_at_unix, n.vm_id"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("isolatedstate: list NAT allocations: %w", err)
	}
	defer rows.Close()
	var values []NATAllocation
	for rows.Next() {
		var value NATAllocation
		if err := rows.Scan(
			&value.VMID, &value.OrchestratorID, &value.DesiredState,
			&value.ObservedState, &value.ConntrackMark,
			&value.DesiredGeneration, &value.AppliedGeneration,
			&value.ObservedGeneration, &value.DrainStartedAt,
			&value.UpdatedAt,
		); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) GetGuestPendingUpdate(
	ctx context.Context,
	vmID, updateKind string,
) (GuestPendingUpdate, error) {
	var value GuestPendingUpdate
	err := s.db.QueryRowContext(ctx, `
		SELECT vm_id, update_kind, desired_generation, payload_json,
		       created_at_unix, last_attempt_unix, last_error
		FROM guest_pending_updates
		WHERE vm_id=? AND update_kind=?`,
		canonicalID(vmID), strings.ToLower(strings.TrimSpace(updateKind))).Scan(
		&value.VMID, &value.UpdateKind, &value.DesiredGeneration,
		&value.PayloadJSON, &value.CreatedAt, &value.LastAttemptAt,
		&value.LastError)
	if errors.Is(err, sql.ErrNoRows) {
		return GuestPendingUpdate{}, ErrGuestPendingUpdateNotFound
	}
	if err != nil {
		return GuestPendingUpdate{}, fmt.Errorf("isolatedstate: get guest pending update: %w", err)
	}
	return value, nil
}
