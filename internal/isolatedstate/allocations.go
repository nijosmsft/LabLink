package isolatedstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrAllocationNotFound = errors.New("isolatedstate: active allocation not found")

type AllocationConflictError struct {
	Requested ActiveResourceAllocation
	Existing  ActiveResourceAllocation
}

func (e *AllocationConflictError) Error() string {
	return fmt.Sprintf(
		"isolatedstate: allocation %s/%s/%s belongs to resource %s",
		e.Requested.Kind, e.Requested.ScopeID, e.Requested.Value, e.Existing.ResourceID,
	)
}

type ReleaseAllocationRequest struct {
	Kind               string
	ScopeID            string
	Value              string
	ResourceID         string
	ReleaseOperationID string
	ReleasedAt         UnixSeconds
}

// CommitAllocations atomically imports an appliance-confirmed reservation into
// the local active mirror. Exact replays are idempotent; any differing live
// owner aborts the complete transaction.
func (s *Store) CommitAllocations(ctx context.Context, allocations []ActiveResourceAllocation) error {
	if len(allocations) == 0 {
		return nil
	}
	seenValues := make(map[string]struct{}, len(allocations))
	seenResources := make(map[string]struct{}, len(allocations))
	for i := range allocations {
		if err := normalizeAllocation(&allocations[i]); err != nil {
			return fmt.Errorf("allocation %d: %w", i, err)
		}
		valueKey := allocations[i].Kind + "\x00" + allocations[i].ScopeID + "\x00" + allocations[i].Value
		if _, ok := seenValues[valueKey]; ok {
			return fmt.Errorf("allocation %d: duplicate kind/scope/value in request", i)
		}
		seenValues[valueKey] = struct{}{}
		resourceKey := allocations[i].Kind + "\x00" + allocations[i].ResourceID
		if _, ok := seenResources[resourceKey]; ok {
			return fmt.Errorf("allocation %d: duplicate kind/resource in request", i)
		}
		seenResources[resourceKey] = struct{}{}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("isolatedstate: begin allocation import: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, allocation := range allocations {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO active_resource_allocations (
				kind, scope_id, value, resource_id, appliance_reservation_id,
				allocated_at_unix
			) VALUES (?, ?, ?, ?, ?, ?)`,
			allocation.Kind, allocation.ScopeID, allocation.Value,
			allocation.ResourceID, allocation.ApplianceReservationID,
			allocation.AllocatedAt,
		)
		if err == nil {
			continue
		}

		existing, findErr := findConflictingAllocation(ctx, tx, allocation)
		if findErr != nil {
			return fmt.Errorf("isolatedstate: commit allocation: %w", err)
		}
		if allocationsEqual(existing, allocation) {
			continue
		}
		return &AllocationConflictError{Requested: allocation, Existing: existing}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("isolatedstate: commit allocation import: %w", err)
	}
	return nil
}

func (s *Store) GetActiveAllocation(
	ctx context.Context,
	kind, scopeID, value string,
) (ActiveResourceAllocation, error) {
	var allocation ActiveResourceAllocation
	err := s.db.QueryRowContext(ctx, `
		SELECT kind, scope_id, value, resource_id, appliance_reservation_id,
		       allocated_at_unix
		FROM active_resource_allocations
		WHERE kind=? AND scope_id=? AND value=?`,
		canonicalToken(kind), canonicalID(scopeID), strings.TrimSpace(value),
	).Scan(
		&allocation.Kind, &allocation.ScopeID, &allocation.Value,
		&allocation.ResourceID, &allocation.ApplianceReservationID,
		&allocation.AllocatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ActiveResourceAllocation{}, ErrAllocationNotFound
	}
	if err != nil {
		return ActiveResourceAllocation{}, fmt.Errorf("isolatedstate: get allocation: %w", err)
	}
	return allocation, nil
}

// ReleaseAllocation moves the live mirror row to immutable history and
// removes it from the active uniqueness set in one transaction.
func (s *Store) ReleaseAllocation(
	ctx context.Context,
	request ReleaseAllocationRequest,
) (ResourceAllocationHistory, error) {
	request.Kind = canonicalToken(request.Kind)
	request.ScopeID = canonicalID(request.ScopeID)
	request.Value = strings.TrimSpace(request.Value)
	request.ResourceID = canonicalID(request.ResourceID)
	request.ReleaseOperationID = canonicalID(request.ReleaseOperationID)
	if request.Kind == "" || request.ScopeID == "" || request.Value == "" ||
		request.ResourceID == "" || request.ReleaseOperationID == "" {
		return ResourceAllocationHistory{}, errors.New("isolatedstate: release allocation fields must not be empty")
	}
	if request.ReleasedAt == 0 {
		request.ReleasedAt = UnixSeconds(time.Now().Unix())
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ResourceAllocationHistory{}, fmt.Errorf("isolatedstate: begin allocation release: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var active ActiveResourceAllocation
	err = tx.QueryRowContext(ctx, `
		SELECT kind, scope_id, value, resource_id, appliance_reservation_id,
		       allocated_at_unix
		FROM active_resource_allocations
		WHERE kind=? AND scope_id=? AND value=? AND resource_id=?`,
		request.Kind, request.ScopeID, request.Value, request.ResourceID,
	).Scan(
		&active.Kind, &active.ScopeID, &active.Value, &active.ResourceID,
		&active.ApplianceReservationID, &active.AllocatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		history, historyErr := findAllocationRelease(ctx, tx, request)
		if historyErr == nil {
			return history, nil
		}
		if !errors.Is(historyErr, sql.ErrNoRows) {
			return ResourceAllocationHistory{}, historyErr
		}
		return ResourceAllocationHistory{}, ErrAllocationNotFound
	}
	if err != nil {
		return ResourceAllocationHistory{}, fmt.Errorf("isolatedstate: read allocation for release: %w", err)
	}

	result, err := tx.ExecContext(ctx, `
		INSERT INTO resource_allocation_history (
			kind, scope_id, value, resource_id, appliance_reservation_id,
			allocated_at_unix, released_at_unix, release_operation_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		active.Kind, active.ScopeID, active.Value, active.ResourceID,
		active.ApplianceReservationID, active.AllocatedAt, request.ReleasedAt,
		request.ReleaseOperationID,
	)
	if err != nil {
		return ResourceAllocationHistory{}, fmt.Errorf("isolatedstate: archive allocation: %w", err)
	}
	sequence, err := result.LastInsertId()
	if err != nil {
		return ResourceAllocationHistory{}, fmt.Errorf("isolatedstate: allocation history sequence: %w", err)
	}
	deleteResult, err := tx.ExecContext(ctx, `
		DELETE FROM active_resource_allocations
		WHERE kind=? AND scope_id=? AND value=? AND resource_id=?`,
		active.Kind, active.ScopeID, active.Value, active.ResourceID,
	)
	if err != nil {
		return ResourceAllocationHistory{}, fmt.Errorf("isolatedstate: delete active allocation: %w", err)
	}
	deleted, err := deleteResult.RowsAffected()
	if err != nil || deleted != 1 {
		return ResourceAllocationHistory{}, fmt.Errorf("isolatedstate: active allocation changed during release")
	}
	if err := tx.Commit(); err != nil {
		return ResourceAllocationHistory{}, fmt.Errorf("isolatedstate: commit allocation release: %w", err)
	}

	return ResourceAllocationHistory{
		Sequence:               sequence,
		Kind:                   active.Kind,
		ScopeID:                active.ScopeID,
		Value:                  active.Value,
		ResourceID:             active.ResourceID,
		ApplianceReservationID: active.ApplianceReservationID,
		AllocatedAt:            active.AllocatedAt,
		ReleasedAt:             request.ReleasedAt,
		ReleaseOperationID:     request.ReleaseOperationID,
	}, nil
}

func findAllocationRelease(
	ctx context.Context,
	tx *sql.Tx,
	request ReleaseAllocationRequest,
) (ResourceAllocationHistory, error) {
	var history ResourceAllocationHistory
	err := tx.QueryRowContext(ctx, `
		SELECT seq, kind, scope_id, value, resource_id,
		       appliance_reservation_id, allocated_at_unix, released_at_unix,
		       release_operation_id
		FROM resource_allocation_history
		WHERE kind=? AND scope_id=? AND value=? AND resource_id=?
		  AND release_operation_id=?
		ORDER BY seq DESC LIMIT 1`,
		request.Kind, request.ScopeID, request.Value, request.ResourceID,
		request.ReleaseOperationID,
	).Scan(
		&history.Sequence, &history.Kind, &history.ScopeID, &history.Value,
		&history.ResourceID, &history.ApplianceReservationID,
		&history.AllocatedAt, &history.ReleasedAt, &history.ReleaseOperationID,
	)
	if err != nil {
		return ResourceAllocationHistory{}, err
	}
	return history, nil
}

func normalizeAllocation(allocation *ActiveResourceAllocation) error {
	allocation.Kind = canonicalToken(allocation.Kind)
	allocation.ScopeID = canonicalID(allocation.ScopeID)
	allocation.Value = strings.TrimSpace(allocation.Value)
	allocation.ResourceID = canonicalID(allocation.ResourceID)
	allocation.ApplianceReservationID = canonicalID(allocation.ApplianceReservationID)
	if allocation.Kind == "" || allocation.ScopeID == "" || allocation.Value == "" ||
		allocation.ResourceID == "" || allocation.ApplianceReservationID == "" {
		return errors.New("kind, scope, value, resource, and appliance reservation must not be empty")
	}
	if allocation.AllocatedAt == 0 {
		allocation.AllocatedAt = UnixSeconds(time.Now().Unix())
	}
	return nil
}

func findConflictingAllocation(
	ctx context.Context,
	tx *sql.Tx,
	requested ActiveResourceAllocation,
) (ActiveResourceAllocation, error) {
	var existing ActiveResourceAllocation
	err := tx.QueryRowContext(ctx, `
		SELECT kind, scope_id, value, resource_id, appliance_reservation_id,
		       allocated_at_unix
		FROM active_resource_allocations
		WHERE (kind=? AND scope_id=? AND value=?)
		   OR (kind=? AND resource_id=?)
		ORDER BY CASE WHEN kind=? AND scope_id=? AND value=? THEN 0 ELSE 1 END
		LIMIT 1`,
		requested.Kind, requested.ScopeID, requested.Value,
		requested.Kind, requested.ResourceID,
		requested.Kind, requested.ScopeID, requested.Value,
	).Scan(
		&existing.Kind, &existing.ScopeID, &existing.Value, &existing.ResourceID,
		&existing.ApplianceReservationID, &existing.AllocatedAt,
	)
	return existing, err
}

func allocationsEqual(left, right ActiveResourceAllocation) bool {
	return left.Kind == right.Kind &&
		left.ScopeID == right.ScopeID &&
		left.Value == right.Value &&
		left.ResourceID == right.ResourceID &&
		left.ApplianceReservationID == right.ApplianceReservationID
}
