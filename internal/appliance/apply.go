package appliance

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
)

const (
	NFTablesArtifact       = "nftables"
	compiledHashToken      = "{{LABLINK_COMPILED_HASH}}"
	ApplianceRuleSignature = "lablink-appliance-managed-v1"
)

type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

type CommandExecutor interface {
	Run(context.Context, string, ...string) (CommandResult, error)
}

type FileSystem interface {
	ReadFile(string) ([]byte, error)
	WriteFileAtomic(string, []byte, fs.FileMode) error
	Exists(string) (bool, error)
}

type CompiledApply struct {
	Intent              Intent
	InventoryGeneration uint64
	SnapshotHash        string
	CompiledHash        string
	Artifacts           map[string][]byte
	EnableForwarding    bool
}

type ApplyCompiler interface {
	Compile(context.Context, DesiredSnapshot, Intent) (CompiledApply, error)
}

type Verification struct {
	Matched bool
	Detail  string
}

type ApplyTarget interface {
	ActivateEmergency(context.Context) error
	Apply(context.Context, CompiledApply) error
	Verify(context.Context, CompiledApply) (Verification, error)
}

type ConflictKind string

const (
	ConflictService       ConflictKind = "service"
	ConflictRuleset       ConflictKind = "ruleset"
	ConflictConfiguration ConflictKind = "configuration"

	UFWServiceName       = "ufw.service"
	FirewalldServiceName = "firewalld.service"
)

func AutomaticallyNeutralizedFirewallManagerServices() []string {
	return []string{UFWServiceName, FirewalldServiceName}
}

type Conflict struct {
	Kind    ConflictKind `json:"kind"`
	Name    string       `json:"name"`
	Detail  string       `json:"detail"`
	Enabled bool         `json:"enabled,omitempty"`
	Active  bool         `json:"active,omitempty"`
}

type ConflictAction struct {
	Service string `json:"service"`
	Action  string `json:"action"`
}

type ConflictPlan struct {
	Revision  string           `json:"revision"`
	Conflicts []Conflict       `json:"conflicts"`
	Actions   []ConflictAction `json:"actions"`
}

type ConflictDetector interface {
	Scan(context.Context) (ConflictPlan, error)
}

type LinuxCompilerConfig struct {
	MainInterface string
}

type EmergencyPolicyConfig struct {
	Executor CommandExecutor
	Files    FileSystem
	Path     string
}

type LinuxTargetConfig struct {
	Executor      CommandExecutor
	Files         FileSystem
	RulesetPath   string
	EmergencyPath string
}

type ConflictScannerConfig struct {
	Executor CommandExecutor
	Files    FileSystem
}

type ApplyHooks struct {
	AfterCompile func(CompiledApply) error
	BeforeApply  func(CompiledApply) error
	AfterApply   func(CompiledApply) error
	AfterVerify  func(CompiledApply) error
	BeforeCommit func(CompiledApply) error
}

type ApplyManagerOptions struct {
	Store     *Store
	Compiler  ApplyCompiler
	Target    ApplyTarget
	Conflicts ConflictDetector
	Hooks     ApplyHooks
}

type ApplyManager struct {
	store     *Store
	compiler  ApplyCompiler
	target    ApplyTarget
	conflicts ConflictDetector
	hooks     ApplyHooks

	compileMu sync.Mutex
	applyGate sync.Mutex

	admissionMu   sync.Mutex
	admissionCond *sync.Cond
	handoff       bool
	admitted      int
}

type StartupResult struct {
	Recovered    int
	ConflictPlan *ConflictPlan
}

func NewApplyManager(options ApplyManagerOptions) (*ApplyManager, error) {
	if options.Store == nil || options.Compiler == nil || options.Target == nil {
		return nil, storeError(CodeInvalidArgument, "store, compiler, and target are required")
	}
	manager := &ApplyManager{
		store:     options.Store,
		compiler:  options.Compiler,
		target:    options.Target,
		conflicts: options.Conflicts,
		hooks:     options.Hooks,
	}
	manager.admissionCond = sync.NewCond(&manager.admissionMu)
	return manager, nil
}

func (m *ApplyManager) Start(ctx context.Context) (StartupResult, error) {
	result := StartupResult{}
	if err := m.store.SetReadiness(ctx, false, "appliance startup recovery"); err != nil {
		return result, err
	}
	if err := m.target.ActivateEmergency(ctx); err != nil {
		readinessErr := fmt.Sprintf("emergency policy failed: %v", err)
		_ = m.store.SetReadiness(ctx, false, readinessErr)
		return result, storeError(CodeApplyFailed, "%s", readinessErr)
	}
	if m.conflicts != nil {
		plan, err := m.conflicts.Scan(ctx)
		if err != nil {
			_ = m.store.SetReadiness(ctx, false, "firewall conflict scan failed: "+err.Error())
			return result, err
		}
		if len(plan.Conflicts) != 0 {
			result.ConflictPlan = &plan
			_ = m.store.SetReadiness(ctx, false,
				fmt.Sprintf("firewall conflict remains after bootstrap neutralization; plan %s", plan.Revision))
			return result, storeError(CodeApplyFailed,
				"firewall conflict remains after bootstrap neutralization; plan %s", plan.Revision)
		}
	}
	recovered, err := m.Recover(ctx)
	result.Recovered = recovered
	if err != nil {
		return result, err
	}
	if err := m.Reconcile(ctx); err != nil {
		return result, err
	}
	return result, nil
}

func (m *ApplyManager) Recover(ctx context.Context) (int, error) {
	intents, err := m.store.RecoveryIntents(ctx)
	if err != nil {
		return 0, err
	}
	recovered := 0
	for _, intent := range intents {
		var err error
		if intent.SystemTransition {
			err = m.recoverSystemIntent(ctx, intent)
		} else {
			_, err = m.ApplyIntent(ctx, intent.MutationID)
		}
		if err != nil {
			return recovered, err
		}
		recovered++
	}
	return recovered, nil
}

func (m *ApplyManager) ApplyIntent(ctx context.Context, mutationID string) (AppliedOperation, error) {
	intent, found, err := m.store.Intent(ctx, mutationID)
	if err != nil {
		return AppliedOperation{}, err
	}
	if !found {
		return AppliedOperation{}, storeError(CodeNotFound, "intent %q not found", mutationID)
	}
	if intent.SystemTransition {
		return AppliedOperation{}, storeError(CodeInvalidArgument,
			"system transition %q cannot use the external apply path", mutationID)
	}
	if intent.Phase == "complete" {
		return AppliedOperation{}, storeError(CodeNotFound, "intent %q is already complete", mutationID)
	}
	if err := m.store.SetReadiness(ctx, false,
		fmt.Sprintf("apply intent %s is %s", mutationID, intent.Phase)); err != nil {
		return AppliedOperation{}, err
	}

	compiled, err := m.compile(ctx, intent)
	if err != nil {
		m.failIntent(ctx, intent, "compile failed: "+err.Error())
		return AppliedOperation{}, err
	}
	if err := callHook(m.hooks.AfterCompile, compiled); err != nil {
		return AppliedOperation{}, err
	}
	if err := m.store.UpdateIntent(ctx, intent.MutationID, intent.SemanticHash,
		"compiled", compiled.CompiledHash, ""); err != nil {
		return AppliedOperation{}, err
	}

	release, err := m.admit(ctx)
	if err != nil {
		m.failIntent(ctx, intent, err.Error())
		return AppliedOperation{}, err
	}
	defer release()
	releaseStore := m.store.beginExternalApply()
	defer releaseStore()

	return m.applyPreparedIntent(ctx, intent, compiled, fenceValidationAdmitted)
}

func (m *ApplyManager) completeNATDrain(
	ctx context.Context,
	completion natDrainCompletion,
) error {
	// This is the only lease-independent mutation path. It is appliance
	// internal, serialized with external apply and authority installation,
	// and revalidates the exact durable NAT/guest/network identity.
	if err := ctx.Err(); err != nil {
		return err
	}
	m.applyGate.Lock()
	defer m.applyGate.Unlock()
	releaseStore := m.store.beginExternalApply()
	defer releaseStore()

	stage, err := m.store.stageNATDrainCompletionLocked(ctx, completion)
	if err != nil {
		return err
	}
	if stage.Replay && stage.Intent.MutationID == "" {
		return nil
	}
	intent := stage.Intent
	if intent.MutationID == "" {
		intent, _, err = m.store.Intent(ctx,
			drainCompletionHeader(completion.Network,
				completion.Guest, completion.NAT).MutationID)
		if err != nil {
			return err
		}
	}
	return m.applySystemIntentLocked(ctx, intent)
}

func (m *ApplyManager) recoverSystemIntent(ctx context.Context, intent Intent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.applyGate.Lock()
	defer m.applyGate.Unlock()
	releaseStore := m.store.beginExternalApply()
	defer releaseStore()
	current, found, err := m.store.Intent(ctx, intent.MutationID)
	if err != nil {
		return err
	}
	if !found || !current.SystemTransition {
		return storeError(CodeNotFound,
			"system transition %q is no longer pending", intent.MutationID)
	}
	return m.applySystemIntentLocked(ctx, current)
}

func (m *ApplyManager) applySystemIntentLocked(ctx context.Context, intent Intent) error {
	if !intent.SystemTransition {
		return storeError(CodeInvalidArgument,
			"intent %q is not an internal system transition", intent.MutationID)
	}
	if err := m.store.SetReadiness(ctx, false,
		fmt.Sprintf("internal NAT drain completion %s pending", intent.MutationID)); err != nil {
		return err
	}
	compiled, err := m.compile(ctx, intent)
	if err != nil {
		m.failIntent(ctx, intent, "compile failed: "+err.Error())
		return err
	}
	if err := callHook(m.hooks.AfterCompile, compiled); err != nil {
		return err
	}
	if err := m.store.UpdateIntent(ctx, intent.MutationID, intent.SemanticHash,
		"compiled", compiled.CompiledHash, ""); err != nil {
		return err
	}
	_, err = m.applyPreparedIntent(ctx, intent, compiled, fenceValidationSystem)
	return err
}

func (m *ApplyManager) applyPreparedIntent(
	ctx context.Context,
	intent Intent,
	compiled CompiledApply,
	mode fenceValidationMode,
) (AppliedOperation, error) {
	current, _, err := m.store.validateCompiledIntent(ctx, compiled, mode)
	if err != nil {
		m.failIntent(ctx, intent, err.Error())
		return AppliedOperation{}, err
	}
	compiled.Intent = current
	if err := m.store.UpdateIntent(ctx, intent.MutationID, intent.SemanticHash,
		"applying", compiled.CompiledHash, ""); err != nil {
		return AppliedOperation{}, err
	}

	verification, verifyErr := m.target.Verify(ctx, compiled)
	if verifyErr != nil || !verification.Matched {
		if err := callHook(m.hooks.BeforeApply, compiled); err != nil {
			return AppliedOperation{}, err
		}
		if err := m.target.Apply(ctx, compiled); err != nil {
			_ = m.target.ActivateEmergency(ctx)
			m.failIntent(ctx, intent, "apply failed: "+err.Error())
			return AppliedOperation{}, storeError(CodeApplyFailed, "%v", err)
		}
		if err := callHook(m.hooks.AfterApply, compiled); err != nil {
			return AppliedOperation{}, err
		}
		verification, verifyErr = m.target.Verify(ctx, compiled)
	}
	if verifyErr != nil || !verification.Matched {
		_ = m.target.ActivateEmergency(ctx)
		detail := verification.Detail
		if verifyErr != nil {
			detail = verifyErr.Error()
		}
		if detail == "" {
			detail = "external state did not match compiled state"
		}
		m.failIntent(ctx, intent, "verify failed: "+detail)
		return AppliedOperation{}, storeError(CodeVerifyFailed, "%s", detail)
	}
	if err := callHook(m.hooks.AfterVerify, compiled); err != nil {
		return AppliedOperation{}, err
	}

	latestSnapshot, snapshotErr := m.store.Snapshot(ctx)
	if snapshotErr != nil {
		return AppliedOperation{}, snapshotErr
	}
	if latestHash, hashErr := HashDesiredSnapshot(latestSnapshot); hashErr != nil {
		return AppliedOperation{}, hashErr
	} else if latestHash != compiled.SnapshotHash {
		_ = m.target.ActivateEmergency(ctx)
		m.failIntent(ctx, intent, "desired snapshot changed during external apply")
		return AppliedOperation{}, storeError(CodeStaleCompilation,
			"snapshot changed before commit")
	}
	if err := callHook(m.hooks.BeforeCommit, compiled); err != nil {
		return AppliedOperation{}, err
	}
	resultJSON, _ := json.Marshal(map[string]any{
		"compiled_hash":        compiled.CompiledHash,
		"inventory_generation": compiled.InventoryGeneration,
		"verified":             true,
	})
	operation, err := m.store.commitIntent(ctx, CommitIntentRequest{
		MutationID:   current.MutationID,
		SemanticHash: current.SemanticHash,
		CompiledHash: compiled.CompiledHash,
		HostFence:    current.Fence,
		Result:       resultJSON,
	}, mode)
	if err != nil {
		m.failIntent(ctx, intent, "commit failed: "+err.Error())
		return AppliedOperation{}, err
	}
	if err := m.refreshReadiness(ctx); err != nil {
		return AppliedOperation{}, err
	}
	return operation, nil
}

func (m *ApplyManager) Reconcile(ctx context.Context) error {
	m.compileMu.Lock()
	snapshot, err := m.store.Snapshot(ctx)
	if err != nil {
		m.compileMu.Unlock()
		return err
	}
	intent := Intent{
		MutationID:        "startup-reconcile",
		ResourceKind:      "appliance",
		ResourceID:        "appliance",
		ParentGeneration:  snapshot.Authority.ParentGeneration,
		Fence:             snapshot.Authority.Fence,
		DesiredGeneration: snapshot.Status.InventoryGeneration,
		SemanticHash:      "startup-reconcile",
	}
	compiled, err := m.compiler.Compile(ctx, snapshot, intent)
	if err == nil {
		compiled = finalizeCompiled(snapshot, intent, compiled)
	}
	m.compileMu.Unlock()
	if err != nil {
		_ = m.store.SetReadiness(ctx, false, "reconcile compile failed: "+err.Error())
		return err
	}

	release, err := m.admit(ctx)
	if err != nil {
		return err
	}
	defer release()
	releaseStore := m.store.beginExternalApply()
	defer releaseStore()
	if err := m.store.ValidateCompiledSnapshot(ctx, compiled); err != nil {
		return err
	}
	if err := m.target.Apply(ctx, compiled); err != nil {
		_ = m.target.ActivateEmergency(ctx)
		_ = m.store.SetReadiness(ctx, false, "reconcile apply failed: "+err.Error())
		return storeError(CodeApplyFailed, "%v", err)
	}
	verification, err := m.target.Verify(ctx, compiled)
	if err != nil || !verification.Matched {
		_ = m.target.ActivateEmergency(ctx)
		detail := verification.Detail
		if err != nil {
			detail = err.Error()
		}
		_ = m.store.SetReadiness(ctx, false, "reconcile verify failed: "+detail)
		return storeError(CodeVerifyFailed, "%s", detail)
	}
	return m.refreshReadiness(ctx)
}

func (m *ApplyManager) VerifyCurrent(ctx context.Context) (Verification, CompiledApply, error) {
	m.compileMu.Lock()
	snapshot, err := m.store.Snapshot(ctx)
	if err != nil {
		m.compileMu.Unlock()
		return Verification{}, CompiledApply{}, err
	}
	intent := Intent{
		MutationID:        "read-only-verify",
		ResourceKind:      "appliance",
		ResourceID:        "appliance",
		ParentGeneration:  snapshot.Authority.ParentGeneration,
		Fence:             snapshot.Authority.Fence,
		DesiredGeneration: snapshot.Status.InventoryGeneration,
		SemanticHash:      "read-only-verify",
	}
	compiled, err := m.compiler.Compile(ctx, snapshot, intent)
	if err == nil {
		compiled = finalizeCompiled(snapshot, intent, compiled)
	}
	m.compileMu.Unlock()
	if err != nil {
		return Verification{}, CompiledApply{}, err
	}
	verification, err := m.target.Verify(ctx, compiled)
	return verification, compiled, err
}

func (m *ApplyManager) InstallAuthority(ctx context.Context, expectedFence uint64, next Authority) error {
	m.admissionMu.Lock()
	if m.handoff {
		m.admissionMu.Unlock()
		return storeError(CodeFenceRejected, "authority handoff is already pending")
	}
	m.handoff = true
	m.admissionMu.Unlock()

	if err := m.store.SetHandoffPending(ctx, expectedFence, true); err != nil {
		m.clearHandoff()
		return err
	}

	m.admissionMu.Lock()
	for m.admitted != 0 {
		m.admissionCond.Wait()
	}
	m.admissionMu.Unlock()

	m.applyGate.Lock()
	next.HandoffPending = false
	err := m.store.InstallAuthority(ctx, next)
	if err != nil {
		_ = m.store.SetHandoffPending(context.Background(), expectedFence, false)
	}
	m.applyGate.Unlock()
	m.clearHandoff()
	return err
}

func (m *ApplyManager) compile(ctx context.Context, intent Intent) (CompiledApply, error) {
	m.compileMu.Lock()
	defer m.compileMu.Unlock()
	snapshot, err := m.store.Snapshot(ctx)
	if err != nil {
		return CompiledApply{}, err
	}
	compiled, err := m.compiler.Compile(ctx, snapshot, intent)
	if err != nil {
		return CompiledApply{}, err
	}
	return finalizeCompiled(snapshot, intent, compiled), nil
}

func finalizeCompiled(snapshot DesiredSnapshot, intent Intent, compiled CompiledApply) CompiledApply {
	compiled.Intent = intent
	compiled.InventoryGeneration = snapshot.Status.InventoryGeneration
	compiled.SnapshotHash, _ = HashDesiredSnapshot(snapshot)
	compiled.CompiledHash = hashCompiled(compiled)
	if compiled.Artifacts == nil {
		compiled.Artifacts = map[string][]byte{}
	}
	for key, artifact := range compiled.Artifacts {
		compiled.Artifacts[key] = []byte(strings.ReplaceAll(
			string(artifact), compiledHashToken, compiled.CompiledHash))
	}
	return compiled
}

func hashCompiled(compiled CompiledApply) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("lablink-appliance-compiled-v1\x00"))
	_, _ = hash.Write([]byte(compiled.SnapshotHash))
	if compiled.EnableForwarding {
		_, _ = hash.Write([]byte{1})
	} else {
		_, _ = hash.Write([]byte{0})
	}
	keys := make([]string, 0, len(compiled.Artifacts))
	for key := range compiled.Artifacts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(key))
		_, _ = hash.Write([]byte{0})
		artifact := string(compiled.Artifacts[key])
		if compiled.CompiledHash != "" {
			artifact = strings.ReplaceAll(artifact, compiled.CompiledHash, compiledHashToken)
		}
		_, _ = hash.Write([]byte(artifact))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func HashDesiredSnapshot(snapshot DesiredSnapshot) (string, error) {
	type desiredNetwork struct {
		ID, CIDR, GatewayIPv4, NICMAC, InterfaceName, DNSServersJSON, State string
		DesiredGeneration, ParentGeneration, Incarnation                    uint64
		RetiredAtUnix                                                       *int64
	}
	type desiredGuest struct {
		ID, NetworkID, IPv4, MAC, State                  string
		DesiredGeneration, ParentGeneration, Incarnation uint64
		RetiredAtUnix                                    *int64
	}
	type desiredRelay struct {
		ID, VMID, TargetIPv4, State string
		ListenPort, TargetPort      int64
		DesiredGeneration           uint64
		ParentGeneration            uint64
		Incarnation                 uint64
		RetiredAtUnix               *int64
	}
	type desiredNAT struct {
		VMID                                string
		State                               string
		ConntrackMark                       int64
		DesiredGeneration, ParentGeneration uint64
	}
	canonical := struct {
		ParentGeneration uint64
		ParentState      string
		Networks         []desiredNetwork
		Guests           []desiredGuest
		Relays           []desiredRelay
		NAT              []desiredNAT
	}{
		ParentGeneration: snapshot.Authority.ParentGeneration,
		ParentState:      snapshot.Authority.ParentState,
	}
	for _, value := range snapshot.Networks {
		canonical.Networks = append(canonical.Networks, desiredNetwork{
			value.ID, value.CIDR, value.GatewayIPv4, value.NICMAC,
			value.InterfaceName, value.DNSServersJSON, value.State,
			value.DesiredGeneration, value.ParentGeneration, value.Incarnation,
			value.RetiredAtUnix,
		})
	}
	for _, value := range snapshot.Guests {
		canonical.Guests = append(canonical.Guests, desiredGuest{
			value.ID, value.NetworkID, value.IPv4, value.MAC, value.State,
			value.DesiredGeneration, value.ParentGeneration, value.Incarnation,
			value.RetiredAtUnix,
		})
	}
	for _, value := range snapshot.Relays {
		canonical.Relays = append(canonical.Relays, desiredRelay{
			value.ID, value.VMID, value.TargetIPv4, value.State,
			value.ListenPort, value.TargetPort, value.DesiredGeneration,
			value.ParentGeneration, value.Incarnation, value.RetiredAtUnix,
		})
	}
	for _, value := range snapshot.NAT {
		canonical.NAT = append(canonical.NAT, desiredNAT{
			value.VMID, value.State, value.ConntrackMark,
			value.DesiredGeneration, value.ParentGeneration,
		})
	}
	sort.Slice(canonical.Networks, func(i, j int) bool { return canonical.Networks[i].ID < canonical.Networks[j].ID })
	sort.Slice(canonical.Guests, func(i, j int) bool { return canonical.Guests[i].ID < canonical.Guests[j].ID })
	sort.Slice(canonical.Relays, func(i, j int) bool { return canonical.Relays[i].ID < canonical.Relays[j].ID })
	sort.Slice(canonical.NAT, func(i, j int) bool { return canonical.NAT[i].VMID < canonical.NAT[j].VMID })
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func (m *ApplyManager) admit(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.admissionMu.Lock()
	if m.handoff {
		m.admissionMu.Unlock()
		return nil, storeError(CodeFenceRejected, "authority handoff is pending")
	}
	m.admitted++
	m.admissionMu.Unlock()

	m.applyGate.Lock()
	return func() {
		m.applyGate.Unlock()
		m.admissionMu.Lock()
		m.admitted--
		m.admissionCond.Broadcast()
		m.admissionMu.Unlock()
	}, nil
}

func (m *ApplyManager) clearHandoff() {
	m.admissionMu.Lock()
	m.handoff = false
	m.admissionCond.Broadcast()
	m.admissionMu.Unlock()
}

func (m *ApplyManager) failIntent(ctx context.Context, intent Intent, detail string) {
	_ = m.store.UpdateIntent(ctx, intent.MutationID, intent.SemanticHash,
		"failed", "", detail)
	_ = m.store.SetReadiness(ctx, false, detail)
}

func (m *ApplyManager) refreshReadiness(ctx context.Context) error {
	converged, detail, err := m.store.Converged(ctx)
	if err != nil {
		return err
	}
	if !converged {
		if detail == "" {
			detail = "desired, applied, and observed generations are not converged"
		}
		return m.store.SetReadiness(ctx, false, detail)
	}
	return m.store.SetReadiness(ctx, true, "")
}

func callHook(hook func(CompiledApply) error, compiled CompiledApply) error {
	if hook == nil {
		return nil
	}
	return hook(compiled)
}

func (s *Store) ValidateCompiledIntent(
	ctx context.Context,
	compiled CompiledApply,
) (Intent, DesiredSnapshot, error) {
	return s.validateCompiledIntent(ctx, compiled, fenceValidationExternal)
}

func (s *Store) validateCompiledIntent(
	ctx context.Context,
	compiled CompiledApply,
	mode fenceValidationMode,
) (Intent, DesiredSnapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Intent{}, DesiredSnapshot{}, err
	}
	defer func() { _ = tx.Rollback() }()
	intent, found, err := lookupIntent(ctx, tx, compiled.Intent.MutationID)
	if err != nil {
		return Intent{}, DesiredSnapshot{}, err
	}
	if !found {
		return Intent{}, DesiredSnapshot{}, storeError(CodeNotFound,
			"intent %q not found", compiled.Intent.MutationID)
	}
	if intent.SemanticHash != compiled.Intent.SemanticHash {
		return Intent{}, DesiredSnapshot{}, resumeMismatch(intent.MutationID)
	}
	if mode == fenceValidationSystem {
		if err := validateNATSystemIntent(ctx, tx, intent); err != nil {
			return Intent{}, DesiredSnapshot{}, err
		}
	} else if intent.SystemTransition {
		return Intent{}, DesiredSnapshot{}, storeError(CodeInvalidArgument,
			"system transition %q cannot use an external authority", intent.MutationID)
	}
	header := MutationHeader{
		MutationID:               intent.MutationID,
		SemanticHash:             intent.SemanticHash,
		ResourceID:               intent.ResourceID,
		ExpectedGeneration:       intent.DesiredGeneration - 1,
		ParentResourceID:         intent.ParentResourceID,
		HostFence:                intent.Fence,
		ExpectedParentGeneration: intent.ParentGeneration,
		CascadeOperationID:       intent.CascadeOperationID,
		CascadePlanRevision:      intent.CascadePlanRevision,
		CascadePlanHash:          intent.CascadePlanHash,
		CascadeItemID:            intent.CascadeItemID,
		CascadeResourceKind:      intent.CascadeResourceKind,
		CascadeAction:            intent.CascadeAction,
	}
	var authority Authority
	switch mode {
	case fenceValidationAdmitted:
		authority, err = validateAdmittedFence(ctx, tx, header, s.now())
	case fenceValidationSystem:
		authority, err = validateSystemAuthority(ctx, tx)
	default:
		authority, err = validateFence(ctx, tx, header, s.now())
	}
	if err != nil {
		return Intent{}, DesiredSnapshot{}, err
	}
	if err := validateParentGeneration(ctx, tx, authority, intent.ResourceKind, header); err != nil {
		return Intent{}, DesiredSnapshot{}, err
	}
	generation, err := resourceGeneration(ctx, tx, intent.ResourceKind, intent.ResourceID)
	if err != nil {
		return Intent{}, DesiredSnapshot{}, err
	}
	if generation != intent.DesiredGeneration {
		return Intent{}, DesiredSnapshot{}, storeError(CodeGenerationConflict,
			"%s %s desired generation is %d; intent requires %d",
			intent.ResourceKind, intent.ResourceID, generation, intent.DesiredGeneration)
	}
	snapshot, err := snapshotInTransaction(ctx, tx)
	if err != nil {
		return Intent{}, DesiredSnapshot{}, err
	}
	hash, err := HashDesiredSnapshot(snapshot)
	if err != nil {
		return Intent{}, DesiredSnapshot{}, err
	}
	if hash != compiled.SnapshotHash ||
		snapshot.Status.InventoryGeneration != compiled.InventoryGeneration {
		return Intent{}, DesiredSnapshot{}, storeError(CodeStaleCompilation,
			"compiled snapshot %s at generation %d is stale; current snapshot is %s at generation %d",
			compiled.SnapshotHash, compiled.InventoryGeneration, hash,
			snapshot.Status.InventoryGeneration)
	}
	if intent.CompiledHash != "" && intent.CompiledHash != compiled.CompiledHash {
		return Intent{}, DesiredSnapshot{}, storeError(CodeStaleCompilation,
			"intent compiled hash changed")
	}
	if err := tx.Commit(); err != nil {
		return Intent{}, DesiredSnapshot{}, err
	}
	return intent, snapshot, nil
}

func (s *Store) ValidateCompiledSnapshot(ctx context.Context, compiled CompiledApply) error {
	snapshot, err := s.Snapshot(ctx)
	if err != nil {
		return err
	}
	if err := validateRuntimeAuthorityValue(snapshot.Authority); err != nil {
		return err
	}
	if snapshot.Authority.Fence != compiled.Intent.Fence ||
		snapshot.Authority.ParentGeneration != compiled.Intent.ParentGeneration {
		return storeError(CodeFenceRejected, "authority changed before external apply")
	}
	hash, err := HashDesiredSnapshot(snapshot)
	if err != nil {
		return err
	}
	if hash != compiled.SnapshotHash {
		return storeError(CodeStaleCompilation, "desired snapshot changed before external apply")
	}
	return nil
}

func snapshotInTransaction(ctx context.Context, tx *sql.Tx) (DesiredSnapshot, error) {
	var snapshot DesiredSnapshot
	var err error
	if snapshot.Status, err = readStatus(ctx, tx); err != nil {
		return DesiredSnapshot{}, err
	}
	if snapshot.Authority, err = readAuthority(ctx, tx); err != nil {
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
	return snapshot, nil
}

func (s *Store) SetHandoffPending(ctx context.Context, expectedFence uint64, pending bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() { _ = tx.Rollback() }()
	authority, err := readAuthority(ctx, tx)
	if err != nil {
		return err
	}
	if authority.Fence != expectedFence {
		return storeError(CodeFenceRejected, "host fence is %d; expected %d",
			authority.Fence, expectedFence)
	}
	if pending && authority.HandoffPending {
		return storeError(CodeFenceRejected, "authority handoff is already pending")
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE appliance_authority
		SET handoff_pending = ?, updated_at_unix = ?
		WHERE singleton = 1
	`, boolInt(pending), s.now().Unix())
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) beginExternalApply() func() {
	s.externalApply.Lock()
	return s.externalApply.Unlock
}

func (s *Store) Converged(ctx context.Context) (bool, string, error) {
	intents, err := s.RecoveryIntents(ctx)
	if err != nil {
		return false, "", err
	}
	if len(intents) != 0 {
		return false, fmt.Sprintf("%d incomplete apply intent(s)", len(intents)), nil
	}
	snapshot, err := s.Snapshot(ctx)
	if err != nil {
		return false, "", err
	}
	for _, network := range snapshot.Networks {
		if network.RetiredAtUnix == nil &&
			(network.DesiredGeneration != network.AppliedGeneration ||
				network.DesiredGeneration != network.ObservedGeneration) {
			return false, "network " + network.ID + " is not converged", nil
		}
	}
	for _, guest := range snapshot.Guests {
		if guest.RetiredAtUnix == nil &&
			(guest.DesiredGeneration != guest.AppliedGeneration ||
				guest.DesiredGeneration != guest.ObservedGeneration) {
			return false, "guest " + guest.ID + " is not converged", nil
		}
	}
	for _, relay := range snapshot.Relays {
		if relay.RetiredAtUnix == nil &&
			(relay.DesiredGeneration != relay.AppliedGeneration ||
				relay.DesiredGeneration != relay.ObservedGeneration) {
			return false, "relay " + relay.ID + " is not converged", nil
		}
	}
	for _, nat := range snapshot.NAT {
		if nat.DesiredGeneration != nat.AppliedGeneration ||
			nat.DesiredGeneration != nat.ObservedGeneration {
			return false, "NAT " + nat.VMID + " is not converged", nil
		}
	}
	return true, "", nil
}
