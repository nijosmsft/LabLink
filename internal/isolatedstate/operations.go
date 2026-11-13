package isolatedstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

var (
	ErrOperationNotFound   = errors.New("isolatedstate: operation not found")
	ErrResumeExactRequired = errors.New("isolatedstate: resume_exact is required when reusing an operation ID")
)

const (
	ConflictGeneration        = "GENERATION_CONFLICT"
	ConflictFence             = "FENCE_REJECTED"
	ConflictParentFrozen      = "PARENT_FROZEN"
	ConflictResumeArguments   = "RESUME_ARGUMENT_MISMATCH"
	ConflictInvalidGeneration = "INVALID_GENERATION"
)

type ResumeArgumentMismatchError struct {
	OperationID string
	StoredHash  string
	RequestHash string
}

func (e *ResumeArgumentMismatchError) Error() string {
	return fmt.Sprintf(
		"isolatedstate: %s for operation %s: stored hash %s, request hash %s",
		ConflictResumeArguments, e.OperationID, e.StoredHash, e.RequestHash,
	)
}

type BeginOperationRequest struct {
	ID              string
	Kind            string
	ResourceType    string
	ResourceID      string
	HostNode        *string
	OrchestratorID  *string
	NetworkID       *string
	CanonicalInputs any
	PlanRevision    *string
	ResumeExact     bool
	CreatedAt       UnixSeconds
}

type BeginOperationResult struct {
	Operation Operation
	Replay    bool
}

type GenerationState struct {
	ResourceType       string
	ResourceID         string
	DesiredGeneration  Generation
	AppliedGeneration  Generation
	ObservedGeneration Generation
	ParentState        OrchestratorLifecycleState
	HostFence          int64
}

type GenerationMutation struct {
	ResourceType       string
	ResourceID         string
	ExpectedGeneration Generation
	NewGeneration      Generation
	ExpectedFence      int64
	Authorization      *MutationAuthorization
	UpdatedAt          UnixSeconds
}

type GenerationRecord struct {
	ResourceType string
	ResourceID   string
	Generation   Generation
	UpdatedAt    UnixSeconds
}

type MutationAuthorization struct {
	OrchestratorID string
	OperationID    string
	PlanRevision   string
	PlanHash       string
	MutationID     string
	Action         string
	ResourceType   string
	ResourceID     string
	HostFence      int64
	LeaseID        string
}

type MutationConflictError struct {
	Code         string
	Message      string
	Current      GenerationState
	Expected     Generation
	Proposed     Generation
	CurrentFence int64
	RequestFence int64
}

func (e *MutationConflictError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("isolatedstate: %s: %s", e.Code, e.Message)
	}
	return "isolatedstate: " + e.Code
}

type PhaseStart struct {
	OperationID string
	PhaseIndex  int
	PhaseName   string
	Generation  *Generation
	StartedAt   UnixSeconds
}

type PhaseFinish struct {
	OperationID string
	PhaseIndex  int
	Attempt     int
	Status      OperationPhaseStatus
	Detail      any
	ErrorText   *string
	FinishedAt  UnixSeconds
}

type OperationEventInput struct {
	OperationID string
	At          UnixSeconds
	PhaseName   *string
	Level       string
	Message     string
	Detail      any
}

type OperationUpdate struct {
	OperationID  string
	Status       OperationStatus
	CurrentPhase string
	Result       any
	ErrorCode    *string
	ErrorText    *string
	UpdatedAt    UnixSeconds
}

// CanonicalJSON returns deterministic JSON with sorted object keys, preserved
// integer spelling, no insignificant whitespace, and no HTML escaping.
func CanonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("isolatedstate: marshal canonical input: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, fmt.Errorf("isolatedstate: decode canonical input: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalized); err != nil {
		return nil, fmt.Errorf("isolatedstate: encode canonical input: %w", err)
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}

func SemanticHash(value any) (string, error) {
	canonical, err := CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// StableMutationID derives the durable per-phase identity specified by the
// isolated orchestration protocol.
func StableMutationID(parentOperationID, resourceID, semanticAction, stablePhaseKey string) string {
	hash := sha256.New()
	_, _ = io.WriteString(hash, "lablink-isolated-mutation-v1")
	_, _ = io.WriteString(hash, canonicalID(parentOperationID))
	_, _ = io.WriteString(hash, canonicalID(resourceID))
	_, _ = io.WriteString(hash, canonicalToken(semanticAction))
	_, _ = io.WriteString(hash, strings.TrimSpace(stablePhaseKey))
	return hex.EncodeToString(hash.Sum(nil))
}

// StableOperationID derives a deterministic canonical UUID for a nested
// durable operation. It intentionally remains compatible with the strict
// operation UUID validator without weakening validation for caller input.
func StableOperationID(parentOperationID, resourceID, semanticAction, stablePhaseKey string) string {
	hash := sha256.New()
	_, _ = io.WriteString(hash, "lablink-isolated-operation-v1")
	_, _ = io.WriteString(hash, canonicalID(parentOperationID))
	_, _ = io.WriteString(hash, canonicalID(resourceID))
	_, _ = io.WriteString(hash, canonicalToken(semanticAction))
	_, _ = io.WriteString(hash, strings.TrimSpace(stablePhaseKey))
	value := hash.Sum(nil)[:16]
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	compact := hex.EncodeToString(value)
	return compact[0:8] + "-" + compact[8:12] + "-" + compact[12:16] + "-" +
		compact[16:20] + "-" + compact[20:32]
}

func (s *Store) BeginOperation(
	ctx context.Context,
	request BeginOperationRequest,
) (BeginOperationResult, error) {
	request.ID = canonicalID(request.ID)
	request.Kind = canonicalToken(request.Kind)
	request.ResourceType = canonicalToken(request.ResourceType)
	request.ResourceID = canonicalID(request.ResourceID)
	if request.ID == "" || request.Kind == "" || request.ResourceType == "" || request.ResourceID == "" {
		return BeginOperationResult{}, errors.New("isolatedstate: operation identity fields must not be empty")
	}
	canonical, err := CanonicalJSON(map[string]any{
		"kind":            request.Kind,
		"resource_type":   request.ResourceType,
		"resource_id":     request.ResourceID,
		"host_node":       canonicalNullableID(request.HostNode),
		"orchestrator_id": canonicalNullableID(request.OrchestratorID),
		"network_id":      canonicalNullableID(request.NetworkID),
		"inputs":          request.CanonicalInputs,
	})
	if err != nil {
		return BeginOperationResult{}, err
	}
	sum := sha256.Sum256(canonical)
	argumentHash := hex.EncodeToString(sum[:])
	if request.CreatedAt == 0 {
		request.CreatedAt = UnixSeconds(time.Now().Unix())
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return BeginOperationResult{}, fmt.Errorf("isolatedstate: begin operation transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	existing, err := getOperation(ctx, tx, request.ID)
	if err == nil {
		if !request.ResumeExact {
			return BeginOperationResult{}, ErrResumeExactRequired
		}
		if existing.ArgumentHash != argumentHash {
			return BeginOperationResult{}, &ResumeArgumentMismatchError{
				OperationID: request.ID,
				StoredHash:  existing.ArgumentHash,
				RequestHash: argumentHash,
			}
		}
		return BeginOperationResult{Operation: existing, Replay: true}, nil
	}
	if !errors.Is(err, ErrOperationNotFound) {
		return BeginOperationResult{}, err
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO operations (
			id, kind, resource_type, resource_id, host_node, orchestrator_id,
			network_id, argument_hash, request_json, plan_revision, status,
			current_phase, created_at_unix, updated_at_unix
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?)`,
		request.ID, request.Kind, request.ResourceType, request.ResourceID,
		canonicalNullableID(request.HostNode), canonicalNullableID(request.OrchestratorID),
		canonicalNullableID(request.NetworkID), argumentHash, string(canonical),
		nullableTrimmed(request.PlanRevision), OperationPlanned,
		request.CreatedAt, request.CreatedAt,
	)
	if err != nil {
		return BeginOperationResult{}, fmt.Errorf("isolatedstate: insert operation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return BeginOperationResult{}, fmt.Errorf("isolatedstate: commit operation: %w", err)
	}
	return BeginOperationResult{
		Operation: Operation{
			ID:             request.ID,
			Kind:           request.Kind,
			ResourceType:   request.ResourceType,
			ResourceID:     request.ResourceID,
			HostNode:       canonicalNullableID(request.HostNode),
			OrchestratorID: canonicalNullableID(request.OrchestratorID),
			NetworkID:      canonicalNullableID(request.NetworkID),
			ArgumentHash:   argumentHash,
			RequestJSON:    string(canonical),
			PlanRevision:   nullableTrimmed(request.PlanRevision),
			Status:         OperationPlanned,
			CreatedAt:      request.CreatedAt,
			UpdatedAt:      request.CreatedAt,
		},
	}, nil
}

func (s *Store) GetOperation(ctx context.Context, operationID string) (Operation, error) {
	return getOperation(ctx, s.db, canonicalID(operationID))
}

// OperationPhaseSucceeded reports whether any completed attempt of the exact
// phase succeeded. Durable workflow resumes use it to skip proven phases only.
func (s *Store) OperationPhaseSucceeded(
	ctx context.Context,
	operationID string,
	phaseIndex int,
	phaseName string,
) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM operation_phases
		WHERE operation_id=? AND phase_index=? AND phase_name=? AND status=?`,
		canonicalID(operationID), phaseIndex, canonicalToken(phaseName),
		PhaseSucceeded,
	).Scan(&count)
	return count > 0, err
}

// LoadSucceededPhaseDetail decodes the newest successful attempt's detail
// into target. It returns false when no successful attempt exists.
func (s *Store) LoadSucceededPhaseDetail(
	ctx context.Context,
	operationID string,
	phaseIndex int,
	phaseName string,
	target any,
) (bool, error) {
	var detail sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT detail_json FROM operation_phases
		WHERE operation_id=? AND phase_index=? AND phase_name=? AND status=?
		ORDER BY attempt DESC LIMIT 1`,
		canonicalID(operationID), phaseIndex, canonicalToken(phaseName),
		PhaseSucceeded,
	).Scan(&detail)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if target == nil || !detail.Valid || strings.TrimSpace(detail.String) == "" {
		return true, nil
	}
	if err := json.Unmarshal([]byte(detail.String), target); err != nil {
		return false, fmt.Errorf("isolatedstate: decode succeeded phase detail: %w", err)
	}
	return true, nil
}

func (s *Store) UpdateOperation(ctx context.Context, update OperationUpdate) (Operation, error) {
	update.OperationID = canonicalID(update.OperationID)
	update.CurrentPhase = canonicalToken(update.CurrentPhase)
	switch update.Status {
	case OperationPlanned, OperationApprovalRequired, OperationRunning,
		OperationPaused, OperationSucceeded, OperationFailed, OperationCancelled:
	default:
		return Operation{}, fmt.Errorf("isolatedstate: invalid operation status %q", update.Status)
	}
	if update.OperationID == "" {
		return Operation{}, errors.New("isolatedstate: operation ID must not be empty")
	}
	if update.UpdatedAt == 0 {
		update.UpdatedAt = UnixSeconds(time.Now().Unix())
	}
	var resultJSON *string
	if update.Result != nil {
		canonical, err := CanonicalJSON(update.Result)
		if err != nil {
			return Operation{}, err
		}
		value := string(canonical)
		resultJSON = &value
	}
	var finishedAt *UnixSeconds
	if update.Status == OperationSucceeded || update.Status == OperationFailed ||
		update.Status == OperationCancelled {
		finished := update.UpdatedAt
		finishedAt = &finished
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, fmt.Errorf("isolatedstate: begin operation update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		UPDATE operations
		SET status=?, current_phase=?, result_json=?, error_code=?, error_text=?,
		    updated_at_unix=?, finished_at_unix=?
		WHERE id=?`,
		update.Status, update.CurrentPhase, resultJSON, nullableTrimmed(update.ErrorCode),
		nullableTrimmed(update.ErrorText), update.UpdatedAt, finishedAt,
		update.OperationID,
	)
	if err != nil {
		return Operation{}, fmt.Errorf("isolatedstate: update operation: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return Operation{}, ErrOperationNotFound
	}
	operation, err := getOperation(ctx, tx, update.OperationID)
	if err != nil {
		return Operation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, fmt.Errorf("isolatedstate: commit operation update: %w", err)
	}
	return operation, nil
}

func (s *Store) StartOperationPhase(ctx context.Context, phase PhaseStart) (OperationPhase, error) {
	phase.OperationID = canonicalID(phase.OperationID)
	phase.PhaseName = canonicalToken(phase.PhaseName)
	if phase.OperationID == "" || phase.PhaseName == "" || phase.PhaseIndex < 0 {
		return OperationPhase{}, errors.New("isolatedstate: invalid operation phase")
	}
	if phase.StartedAt == 0 {
		phase.StartedAt = UnixSeconds(time.Now().Unix())
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OperationPhase{}, fmt.Errorf("isolatedstate: begin phase: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var attempt int
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(attempt), 0) + 1
		FROM operation_phases
		WHERE operation_id=? AND phase_index=?`,
		phase.OperationID, phase.PhaseIndex,
	).Scan(&attempt); err != nil {
		return OperationPhase{}, fmt.Errorf("isolatedstate: next phase attempt: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO operation_phases (
			operation_id, phase_index, phase_name, generation, status, attempt,
			started_at_unix
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		phase.OperationID, phase.PhaseIndex, phase.PhaseName, phase.Generation,
		PhaseRunning, attempt, phase.StartedAt,
	)
	if err != nil {
		return OperationPhase{}, fmt.Errorf("isolatedstate: insert phase: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE operations
		SET status=?, current_phase=?, updated_at_unix=?
		WHERE id=?`,
		OperationRunning, phase.PhaseName, phase.StartedAt, phase.OperationID,
	)
	if err != nil {
		return OperationPhase{}, fmt.Errorf("isolatedstate: update operation phase: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return OperationPhase{}, ErrOperationNotFound
	}
	if err := tx.Commit(); err != nil {
		return OperationPhase{}, fmt.Errorf("isolatedstate: commit phase: %w", err)
	}
	started := phase.StartedAt
	return OperationPhase{
		OperationID: phase.OperationID,
		PhaseIndex:  phase.PhaseIndex,
		PhaseName:   phase.PhaseName,
		Generation:  phase.Generation,
		Status:      PhaseRunning,
		Attempt:     attempt,
		StartedAt:   &started,
	}, nil
}

func (s *Store) FinishOperationPhase(ctx context.Context, finish PhaseFinish) error {
	if finish.Status != PhaseSucceeded && finish.Status != PhaseFailed && finish.Status != PhaseSkipped {
		return errors.New("isolatedstate: phase finish status must be succeeded, failed, or skipped")
	}
	if finish.FinishedAt == 0 {
		finish.FinishedAt = UnixSeconds(time.Now().Unix())
	}
	var detail *string
	if finish.Detail != nil {
		canonical, err := CanonicalJSON(finish.Detail)
		if err != nil {
			return err
		}
		value := string(canonical)
		detail = &value
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("isolatedstate: begin phase finish: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		UPDATE operation_phases
		SET status=?, finished_at_unix=?, detail_json=?, error_text=?
		WHERE operation_id=? AND phase_index=? AND attempt=? AND status=?`,
		finish.Status, finish.FinishedAt, detail, finish.ErrorText,
		canonicalID(finish.OperationID), finish.PhaseIndex, finish.Attempt, PhaseRunning,
	)
	if err != nil {
		return fmt.Errorf("isolatedstate: finish operation phase: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("isolatedstate: running operation phase not found")
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE operations SET updated_at_unix=? WHERE id=?`,
		finish.FinishedAt, canonicalID(finish.OperationID),
	); err != nil {
		return fmt.Errorf("isolatedstate: update operation after phase: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("isolatedstate: commit phase finish: %w", err)
	}
	return nil
}

func (s *Store) AppendOperationEvent(ctx context.Context, event OperationEventInput) (OperationEvent, error) {
	event.OperationID = canonicalID(event.OperationID)
	event.Level = canonicalToken(event.Level)
	event.Message = strings.TrimSpace(event.Message)
	if event.OperationID == "" || event.Level == "" || event.Message == "" {
		return OperationEvent{}, errors.New("isolatedstate: invalid operation event")
	}
	if event.At == 0 {
		event.At = UnixSeconds(time.Now().Unix())
	}
	var detail *string
	if event.Detail != nil {
		canonical, err := CanonicalJSON(event.Detail)
		if err != nil {
			return OperationEvent{}, err
		}
		value := string(canonical)
		detail = &value
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OperationEvent{}, fmt.Errorf("isolatedstate: begin operation event: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		INSERT INTO operation_events (
			operation_id, at_unix, phase_name, level, message, detail_json
		) VALUES (?, ?, ?, ?, ?, ?)`,
		event.OperationID, event.At, nullableTrimmed(event.PhaseName),
		event.Level, event.Message, detail,
	)
	if err != nil {
		return OperationEvent{}, fmt.Errorf("isolatedstate: append operation event: %w", err)
	}
	sequence, err := result.LastInsertId()
	if err != nil {
		return OperationEvent{}, fmt.Errorf("isolatedstate: operation event sequence: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return OperationEvent{}, fmt.Errorf("isolatedstate: commit operation event: %w", err)
	}
	return OperationEvent{
		Sequence: sequence, OperationID: event.OperationID, At: event.At,
		PhaseName: nullableTrimmed(event.PhaseName), Level: event.Level,
		Message: event.Message, DetailJSON: detail,
	}, nil
}

func (s *Store) AdvanceDesiredGeneration(
	ctx context.Context,
	mutation GenerationMutation,
) (GenerationState, error) {
	spec, err := generationSpecFor(mutation.ResourceType)
	if err != nil {
		return GenerationState{}, err
	}
	mutation.ResourceID = canonicalID(mutation.ResourceID)
	if mutation.ResourceID == "" {
		return GenerationState{}, errors.New("isolatedstate: resource ID must not be empty")
	}
	if mutation.NewGeneration != mutation.ExpectedGeneration+1 {
		return GenerationState{}, &MutationConflictError{
			Code: ConflictInvalidGeneration, Expected: mutation.ExpectedGeneration,
			Proposed: mutation.NewGeneration,
			Message:  "new generation must equal expected generation plus one",
		}
	}
	if mutation.UpdatedAt == 0 {
		mutation.UpdatedAt = UnixSeconds(time.Now().Unix())
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return GenerationState{}, fmt.Errorf("isolatedstate: begin generation mutation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	current, orchestratorID, err := readGenerationState(ctx, tx, spec, mutation.ResourceID)
	if err != nil {
		return GenerationState{}, err
	}
	if current.HostFence != mutation.ExpectedFence {
		return GenerationState{}, &MutationConflictError{
			Code: ConflictFence, Current: current, CurrentFence: current.HostFence,
			RequestFence: mutation.ExpectedFence,
			Message:      fmt.Sprintf("current fence is %d, request fence is %d", current.HostFence, mutation.ExpectedFence),
		}
	}
	if parentBlocksMutation(current.ParentState) {
		if err := authorizeCascadeMutation(ctx, tx, orchestratorID, mutation.Authorization, current); err != nil {
			return GenerationState{}, err
		}
	}
	if current.DesiredGeneration != mutation.ExpectedGeneration {
		return GenerationState{}, &MutationConflictError{
			Code: ConflictGeneration, Current: current,
			Expected: mutation.ExpectedGeneration, Proposed: mutation.NewGeneration,
			Message: fmt.Sprintf("current desired generation is %d", current.DesiredGeneration),
		}
	}
	query := fmt.Sprintf(`
		UPDATE %s
		SET desired_generation=?, updated_at_unix=?
		WHERE %s=? AND desired_generation=?`,
		spec.table, spec.idColumn,
	)
	result, err := tx.ExecContext(ctx, query,
		mutation.NewGeneration, mutation.UpdatedAt, mutation.ResourceID,
		mutation.ExpectedGeneration,
	)
	if err != nil {
		return GenerationState{}, fmt.Errorf("isolatedstate: advance desired generation: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return GenerationState{}, &MutationConflictError{
			Code: ConflictGeneration, Current: current,
			Expected: mutation.ExpectedGeneration, Proposed: mutation.NewGeneration,
			Message: "generation changed concurrently",
		}
	}
	current.DesiredGeneration = mutation.NewGeneration
	if err := tx.Commit(); err != nil {
		return GenerationState{}, fmt.Errorf("isolatedstate: commit desired generation: %w", err)
	}
	return current, nil
}

func (s *Store) RecordAppliedGeneration(
	ctx context.Context,
	record GenerationRecord,
) (GenerationState, error) {
	return s.recordGeneration(ctx, record, "applied_generation")
}

func (s *Store) RecordObservedGeneration(
	ctx context.Context,
	record GenerationRecord,
) (GenerationState, error) {
	return s.recordGeneration(ctx, record, "observed_generation")
}

func (s *Store) recordGeneration(
	ctx context.Context,
	record GenerationRecord,
	column string,
) (GenerationState, error) {
	spec, err := generationSpecFor(record.ResourceType)
	if err != nil {
		return GenerationState{}, err
	}
	record.ResourceID = canonicalID(record.ResourceID)
	if record.UpdatedAt == 0 {
		record.UpdatedAt = UnixSeconds(time.Now().Unix())
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return GenerationState{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, _, err := readGenerationState(ctx, tx, spec, record.ResourceID)
	if err != nil {
		return GenerationState{}, err
	}
	var prior Generation
	if column == "applied_generation" {
		prior = current.AppliedGeneration
	} else {
		prior = current.ObservedGeneration
	}
	if record.Generation < prior || record.Generation > current.DesiredGeneration {
		return GenerationState{}, &MutationConflictError{
			Code: ConflictGeneration, Current: current, Expected: prior,
			Proposed: record.Generation,
			Message:  fmt.Sprintf("%s must be monotonic and not exceed desired generation", column),
		}
	}
	if record.Generation != prior {
		query := fmt.Sprintf(`
			UPDATE %s SET %s=?, updated_at_unix=? WHERE %s=? AND %s=?`,
			spec.table, column, spec.idColumn, column,
		)
		result, err := tx.ExecContext(ctx, query,
			record.Generation, record.UpdatedAt, record.ResourceID, prior,
		)
		if err != nil {
			return GenerationState{}, fmt.Errorf("isolatedstate: record %s: %w", column, err)
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return GenerationState{}, &MutationConflictError{
				Code: ConflictGeneration, Current: current, Expected: prior,
				Proposed: record.Generation, Message: "generation changed concurrently",
			}
		}
	}
	if column == "applied_generation" {
		current.AppliedGeneration = record.Generation
	} else {
		current.ObservedGeneration = record.Generation
	}
	if err := tx.Commit(); err != nil {
		return GenerationState{}, err
	}
	return current, nil
}

func (s *Store) InstallCascadeAuthority(ctx context.Context, authority CascadeAuthority) error {
	authority.OrchestratorID = canonicalID(authority.OrchestratorID)
	authority.OperationID = canonicalID(authority.OperationID)
	authority.PlanRevision = strings.TrimSpace(authority.PlanRevision)
	authority.PlanHash = canonicalToken(authority.PlanHash)
	authority.LeaseID = canonicalID(authority.LeaseID)
	if authority.OrchestratorID == "" || authority.OperationID == "" ||
		authority.PlanRevision == "" || authority.PlanHash == "" || authority.LeaseID == "" {
		return errors.New("isolatedstate: incomplete cascade authority")
	}
	if authority.InstalledAt == 0 {
		authority.InstalledAt = UnixSeconds(time.Now().Unix())
	}
	seenMutations := make(map[string]struct{}, len(authority.Items))
	seenActions := make(map[string]struct{}, len(authority.Items))
	for index := range authority.Items {
		item := &authority.Items[index]
		item.MutationID = canonicalToken(item.MutationID)
		item.Action = canonicalToken(item.Action)
		item.ResourceType = canonicalToken(item.ResourceType)
		item.ResourceID = canonicalID(item.ResourceID)
		if item.MutationID == "" || item.Action == "" || item.ResourceType == "" || item.ResourceID == "" {
			return errors.New("isolatedstate: incomplete cascade authority item")
		}
		if _, exists := seenMutations[item.MutationID]; exists {
			return errors.New("isolatedstate: duplicate cascade mutation ID")
		}
		seenMutations[item.MutationID] = struct{}{}
		actionKey := item.Action + "\x00" + item.ResourceType + "\x00" + item.ResourceID
		if _, exists := seenActions[actionKey]; exists {
			return errors.New("isolatedstate: duplicate cascade cleanup item")
		}
		seenActions[actionKey] = struct{}{}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var currentGeneration Generation
	var currentFence int64
	var lifecycle OrchestratorLifecycleState
	err = tx.QueryRowContext(ctx, `
		SELECT desired_generation, host_fence, lifecycle_state
		FROM orchestrators WHERE id=?`,
		authority.OrchestratorID,
	).Scan(&currentGeneration, &currentFence, &lifecycle)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("isolatedstate: cascade parent orchestrator not found")
	}
	if err != nil {
		return fmt.Errorf("isolatedstate: read cascade parent: %w", err)
	}
	if !parentBlocksMutation(lifecycle) {
		return errors.New("isolatedstate: cascade authority requires a frozen, deleting, lost, or deleted parent")
	}
	if currentGeneration != authority.FrozenGeneration || currentFence != authority.HostFence {
		return &MutationConflictError{
			Code: ConflictFence,
			Message: fmt.Sprintf(
				"cascade authority generation/fence is %d/%d, current is %d/%d",
				authority.FrozenGeneration, authority.HostFence, currentGeneration, currentFence,
			),
			Current: GenerationState{
				ResourceType: "orchestrator", ResourceID: authority.OrchestratorID,
				DesiredGeneration: currentGeneration, ParentState: lifecycle, HostFence: currentFence,
			},
			CurrentFence: currentFence, RequestFence: authority.HostFence,
		}
	}
	var (
		existingOperation string
		existingRevision  string
		existingPlanHash  string
		existingFence     int64
		existingLease     string
	)
	existingErr := tx.QueryRowContext(ctx, `
		SELECT operation_id, plan_revision, plan_hash, host_fence, lease_id
		FROM cascade_authorities WHERE orchestrator_id=?`,
		authority.OrchestratorID,
	).Scan(
		&existingOperation, &existingRevision, &existingPlanHash,
		&existingFence, &existingLease,
	)
	sameAuthority := existingErr == nil &&
		existingOperation == authority.OperationID &&
		existingRevision == authority.PlanRevision &&
		existingPlanHash == authority.PlanHash &&
		existingFence == authority.HostFence &&
		existingLease == authority.LeaseID
	if existingErr != nil && !errors.Is(existingErr, sql.ErrNoRows) {
		return fmt.Errorf("isolatedstate: read existing cascade authority: %w", existingErr)
	}
	if sameAuthority {
		var existingItems int
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM cascade_authority_items
			WHERE orchestrator_id=?`,
			authority.OrchestratorID,
		).Scan(&existingItems); err != nil {
			return fmt.Errorf("isolatedstate: count cascade authority items: %w", err)
		}
		if existingItems != len(authority.Items) {
			return errors.New("isolatedstate: cascade authority replay changed the enumerated items")
		}
	} else if _, err := tx.ExecContext(ctx,
		`DELETE FROM cascade_authority_items WHERE orchestrator_id=?`,
		authority.OrchestratorID,
	); err != nil {
		return fmt.Errorf("isolatedstate: replace cascade items: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO cascade_authorities (
			orchestrator_id, frozen_generation, operation_id, plan_revision,
			plan_hash, host_fence, lease_id, installed_at_unix
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(orchestrator_id) DO UPDATE SET
			frozen_generation=excluded.frozen_generation,
			operation_id=excluded.operation_id,
			plan_revision=excluded.plan_revision,
			plan_hash=excluded.plan_hash,
			host_fence=excluded.host_fence,
			lease_id=excluded.lease_id,
			installed_at_unix=excluded.installed_at_unix`,
		authority.OrchestratorID, authority.FrozenGeneration, authority.OperationID,
		authority.PlanRevision, authority.PlanHash, authority.HostFence,
		authority.LeaseID, authority.InstalledAt,
	)
	if err != nil {
		return fmt.Errorf("isolatedstate: install cascade authority: %w", err)
	}
	for _, item := range authority.Items {
		if sameAuthority {
			var (
				action, resourceType, resourceID string
				hostIdentity, applianceIdentity  *string
				expectedGeneration               Generation
			)
			err := tx.QueryRowContext(ctx, `
				SELECT action, resource_type, resource_id, expected_host_identity,
				       expected_appliance_identity, expected_generation
				FROM cascade_authority_items
				WHERE orchestrator_id=? AND mutation_id=?`,
				authority.OrchestratorID, item.MutationID,
			).Scan(
				&action, &resourceType, &resourceID, &hostIdentity,
				&applianceIdentity, &expectedGeneration,
			)
			if err != nil {
				return fmt.Errorf("isolatedstate: read cascade authority item replay: %w", err)
			}
			if action != item.Action || resourceType != item.ResourceType ||
				resourceID != item.ResourceID ||
				!equalNullableString(hostIdentity, nullableTrimmed(item.ExpectedHostIdentity)) ||
				!equalNullableString(applianceIdentity, nullableTrimmed(item.ExpectedApplianceIdentity)) ||
				expectedGeneration != item.ExpectedGeneration {
				return errors.New("isolatedstate: cascade authority replay changed an enumerated item")
			}
			continue
		}
		_, err := tx.ExecContext(ctx, `
				INSERT INTO cascade_authority_items (
					orchestrator_id, mutation_id, action, resource_type, resource_id,
					expected_host_identity, expected_appliance_identity,
					expected_generation, completed_at_unix
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			authority.OrchestratorID, item.MutationID, item.Action,
			item.ResourceType, item.ResourceID, nullableTrimmed(item.ExpectedHostIdentity),
			nullableTrimmed(item.ExpectedApplianceIdentity), item.ExpectedGeneration,
			item.CompletedAt,
		)
		if err != nil {
			return fmt.Errorf("isolatedstate: insert cascade authority item: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("isolatedstate: commit cascade authority: %w", err)
	}
	return nil
}

func (s *Store) CompleteCascadeItem(
	ctx context.Context,
	orchestratorID, mutationID string,
	completedAt UnixSeconds,
) error {
	if completedAt == 0 {
		completedAt = UnixSeconds(time.Now().Unix())
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("isolatedstate: begin cascade completion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		UPDATE cascade_authority_items
		SET completed_at_unix=COALESCE(completed_at_unix, ?)
		WHERE orchestrator_id=? AND mutation_id=?`,
		completedAt, canonicalID(orchestratorID), canonicalToken(mutationID),
	)
	if err != nil {
		return fmt.Errorf("isolatedstate: complete cascade item: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("isolatedstate: cascade authority item not found")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("isolatedstate: commit cascade completion: %w", err)
	}
	return nil
}

type generationSpec struct {
	resourceType string
	table        string
	idColumn     string
}

func generationSpecFor(resourceType string) (generationSpec, error) {
	switch canonicalToken(resourceType) {
	case "orchestrator":
		return generationSpec{"orchestrator", "orchestrators", "id"}, nil
	case "network":
		return generationSpec{"network", "private_networks", "id"}, nil
	case "vm":
		return generationSpec{"vm", "isolated_vms", "id"}, nil
	case "relay":
		return generationSpec{"relay", "relay_allocations", "id"}, nil
	case "nat":
		return generationSpec{"nat", "nat_allocations", "vm_id"}, nil
	default:
		return generationSpec{}, fmt.Errorf("isolatedstate: unsupported generation resource type %q", resourceType)
	}
}

func readGenerationState(
	ctx context.Context,
	tx *sql.Tx,
	spec generationSpec,
	resourceID string,
) (GenerationState, string, error) {
	var query string
	if spec.resourceType == "orchestrator" {
		query = `
			SELECT id, desired_generation, applied_generation, observed_generation,
			       lifecycle_state, host_fence
			FROM orchestrators WHERE id=?`
	} else {
		query = fmt.Sprintf(`
			SELECT r.orchestrator_id, r.desired_generation, r.applied_generation,
			       r.observed_generation, o.lifecycle_state, o.host_fence
			FROM %s r
			JOIN orchestrators o ON o.id=r.orchestrator_id
			WHERE r.%s=?`,
			spec.table, spec.idColumn,
		)
	}
	var orchestratorID string
	state := GenerationState{ResourceType: spec.resourceType, ResourceID: resourceID}
	err := tx.QueryRowContext(ctx, query, resourceID).Scan(
		&orchestratorID, &state.DesiredGeneration, &state.AppliedGeneration,
		&state.ObservedGeneration, &state.ParentState, &state.HostFence,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return GenerationState{}, "", fmt.Errorf("isolatedstate: %s %s not found", spec.resourceType, resourceID)
	}
	if err != nil {
		return GenerationState{}, "", fmt.Errorf("isolatedstate: read generation state: %w", err)
	}
	if spec.resourceType == "orchestrator" {
		orchestratorID = resourceID
	}
	return state, orchestratorID, nil
}

func authorizeCascadeMutation(
	ctx context.Context,
	tx *sql.Tx,
	orchestratorID string,
	authorization *MutationAuthorization,
	current GenerationState,
) error {
	if authorization == nil {
		return &MutationConflictError{
			Code: ConflictParentFrozen, Current: current,
			Message: "parent lifecycle requires exact cascade authority",
		}
	}
	if canonicalID(authorization.OrchestratorID) != orchestratorID {
		return &MutationConflictError{
			Code: ConflictParentFrozen, Current: current,
			Message: "cascade authority names a different parent orchestrator",
		}
	}
	var count int
	err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM cascade_authorities a
		JOIN cascade_authority_items i
		  ON i.orchestrator_id=a.orchestrator_id
		WHERE a.orchestrator_id=?
		  AND a.operation_id=? AND a.plan_revision=? AND a.plan_hash=?
		  AND a.host_fence=? AND a.lease_id=?
		  AND i.mutation_id=? AND i.action=?
		  AND i.resource_type=? AND i.resource_id=?
		  AND i.expected_generation=?
		  AND i.completed_at_unix IS NULL`,
		orchestratorID, canonicalID(authorization.OperationID),
		strings.TrimSpace(authorization.PlanRevision), canonicalToken(authorization.PlanHash),
		authorization.HostFence, canonicalID(authorization.LeaseID),
		canonicalToken(authorization.MutationID), canonicalToken(authorization.Action),
		canonicalToken(authorization.ResourceType), canonicalID(authorization.ResourceID),
		current.DesiredGeneration,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("isolatedstate: verify cascade authority: %w", err)
	}
	if count != 1 || authorization.HostFence != current.HostFence {
		return &MutationConflictError{
			Code: ConflictParentFrozen, Current: current,
			Message: "cascade authority does not match the current unfinished revision item",
		}
	}
	return nil
}

func parentBlocksMutation(state OrchestratorLifecycleState) bool {
	switch state {
	case OrchestratorFrozen, OrchestratorDeleting, OrchestratorLost, OrchestratorDeleted:
		return true
	default:
		return false
	}
}

type operationQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func getOperation(ctx context.Context, db operationQuerier, operationID string) (Operation, error) {
	var operation Operation
	err := db.QueryRowContext(ctx, `
		SELECT id, kind, resource_type, resource_id, host_node, orchestrator_id,
		       network_id, argument_hash, request_json, plan_revision, status,
		       current_phase, result_json, error_code, error_text,
		       created_at_unix, updated_at_unix, finished_at_unix
		FROM operations WHERE id=?`,
		operationID,
	).Scan(
		&operation.ID, &operation.Kind, &operation.ResourceType, &operation.ResourceID,
		&operation.HostNode, &operation.OrchestratorID, &operation.NetworkID,
		&operation.ArgumentHash, &operation.RequestJSON, &operation.PlanRevision,
		&operation.Status, &operation.CurrentPhase, &operation.ResultJSON,
		&operation.ErrorCode, &operation.ErrorText, &operation.CreatedAt,
		&operation.UpdatedAt, &operation.FinishedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Operation{}, ErrOperationNotFound
	}
	if err != nil {
		return Operation{}, fmt.Errorf("isolatedstate: get operation: %w", err)
	}
	return operation, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("isolatedstate: canonical input contains multiple JSON values")
		}
		return fmt.Errorf("isolatedstate: canonical input trailing data: %w", err)
	}
	return nil
}

func canonicalToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func canonicalID(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func canonicalNullableID(value *string) *string {
	if value == nil {
		return nil
	}
	canonical := canonicalID(*value)
	if canonical == "" {
		return nil
	}
	return &canonical
}

func nullableTrimmed(value *string) *string {
	if value == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func equalNullableString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
