package appliance

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

type fakeCompiler struct{}

func (fakeCompiler) Compile(
	_ context.Context,
	_ DesiredSnapshot,
	intent Intent,
) (CompiledApply, error) {
	return CompiledApply{
		Intent: intent,
		Artifacts: map[string][]byte{
			NFTablesArtifact: []byte("flush ruleset\n# compiled=" + compiledHashToken),
		},
		EnableForwarding: true,
	}, nil
}

type fakeTarget struct {
	mu             sync.Mutex
	currentHash    string
	emergencyCalls int
	applyCalls     int
	verifyCalls    int
	failVerify     bool
	applyStarted   chan struct{}
	continueApply  chan struct{}
	startOnce      sync.Once
}

func (t *fakeTarget) ActivateEmergency(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.emergencyCalls++
	t.currentHash = ""
	return nil
}

func (t *fakeTarget) Apply(_ context.Context, compiled CompiledApply) error {
	t.mu.Lock()
	t.applyCalls++
	t.mu.Unlock()
	if t.applyStarted != nil {
		t.startOnce.Do(func() { close(t.applyStarted) })
	}
	if t.continueApply != nil {
		<-t.continueApply
	}
	t.mu.Lock()
	t.currentHash = compiled.CompiledHash
	t.mu.Unlock()
	return nil
}

func (t *fakeTarget) Verify(
	_ context.Context,
	compiled CompiledApply,
) (Verification, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.verifyCalls++
	if t.failVerify {
		return Verification{Detail: "forced verification mismatch"}, nil
	}
	return Verification{
		Matched: t.currentHash == compiled.CompiledHash,
		Detail:  "compiled hash mismatch",
	}, nil
}

func (t *fakeTarget) counts() (emergency, apply int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.emergencyCalls, t.applyCalls
}

type fakeConflicts struct {
	plan ConflictPlan
	err  error
}

func (f fakeConflicts) Scan(context.Context) (ConflictPlan, error) {
	return f.plan, f.err
}

func stageApplyTestNetwork(
	t *testing.T,
	store *Store,
	id, mutationID string,
	fence, parentGeneration, expectedGeneration uint64,
) {
	t.Helper()
	mac := "02:00:00:00:40:01"
	if id != "network-1" {
		mac = "02:00:00:00:40:02"
	}
	if expectedGeneration == 0 {
		mustReserve(t, store, fence, parentGeneration, Reservation{
			ID:           id + "-reservation",
			ResourceKind: "network",
			ResourceID:   id,
			MAC:          mac,
		})
	}
	header := mutation(mutationID, "hash-"+mutationID, fence, parentGeneration)
	header.ResourceID = id
	header.ExpectedGeneration = expectedGeneration
	header.NewGeneration = expectedGeneration + 1
	_, err := store.StageNetwork(context.Background(), header, Network{
		ID:             id,
		CIDR:           "10.90.0.0/26",
		GatewayIPv4:    "10.90.0.1",
		NICMAC:         mac,
		InterfaceName:  "eth1",
		DNSServersJSON: "[]",
	})
	if err != nil {
		t.Fatalf("StageNetwork(%s): %v", id, err)
	}
}

func newTestApplyManager(t *testing.T, store *Store, target ApplyTarget, hooks ApplyHooks) *ApplyManager {
	t.Helper()
	manager, err := NewApplyManager(ApplyManagerOptions{
		Store:    store,
		Compiler: fakeCompiler{},
		Target:   target,
		Hooks:    hooks,
	})
	if err != nil {
		t.Fatalf("NewApplyManager: %v", err)
	}
	return manager
}

func TestCrashAfterExternalApplyRecoversWithoutDuplicateEffect(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "appliance.db"))
	installTestAuthority(t, store, 7, 2)
	stageApplyTestNetwork(t, store, "network-1", "crash-intent", 7, 2, 0)
	target := &fakeTarget{}
	crash := errors.New("simulated crash after external apply")
	manager := newTestApplyManager(t, store, target, ApplyHooks{
		AfterApply: func(CompiledApply) error { return crash },
	})

	if _, err := manager.ApplyIntent(context.Background(), "crash-intent"); !errors.Is(err, crash) {
		t.Fatalf("ApplyIntent error = %v, want simulated crash", err)
	}
	_, applies := target.counts()
	if applies != 1 {
		t.Fatalf("apply calls after crash = %d, want 1", applies)
	}
	intent, found, err := store.Intent(context.Background(), "crash-intent")
	if err != nil || !found || intent.Phase != "applying" {
		t.Fatalf("crashed intent = found:%v phase:%q err:%v", found, intent.Phase, err)
	}

	restarted := newTestApplyManager(t, store, target, ApplyHooks{})
	recovered, err := restarted.Recover(context.Background())
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if recovered != 1 {
		t.Fatalf("recovered = %d, want 1", recovered)
	}
	_, applies = target.counts()
	if applies != 1 {
		t.Fatalf("apply calls after recovery = %d, want no duplicate effect", applies)
	}
	network, found, err := store.Network(context.Background(), "network-1")
	if err != nil || !found {
		t.Fatalf("Network: found=%v err=%v", found, err)
	}
	if network.DesiredGeneration != 1 || network.AppliedGeneration != 1 ||
		network.ObservedGeneration != 1 {
		t.Fatalf("network generations after recovery = %+v", network)
	}
}

func TestStaleCompilationRejectedBeforeExternalEffect(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "appliance.db"))
	installTestAuthority(t, store, 4, 1)
	stageApplyTestNetwork(t, store, "network-1", "generation-1", 4, 1, 0)
	target := &fakeTarget{}
	manager := newTestApplyManager(t, store, target, ApplyHooks{
		AfterCompile: func(CompiledApply) error {
			stageApplyTestNetwork(t, store, "network-1", "generation-2", 4, 1, 1)
			return nil
		},
	})

	_, err := manager.ApplyIntent(context.Background(), "generation-1")
	if ErrorCodeOf(err) != CodeGenerationConflict &&
		ErrorCodeOf(err) != CodeStaleCompilation {
		t.Fatalf("stale apply error = %v, want generation/stale rejection", err)
	}
	_, applies := target.counts()
	if applies != 0 {
		t.Fatalf("stale compilation performed %d external apply calls", applies)
	}
}

func TestAuthorityHandoffWaitsForAdmittedApplyAndRejectsOldWriter(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "appliance.db"))
	installTestAuthority(t, store, 7, 2)
	stageApplyTestNetwork(t, store, "network-1", "first-intent", 7, 2, 0)
	stageApplyTestNetwork(t, store, "network-2", "stale-intent", 7, 2, 0)
	target := &fakeTarget{
		applyStarted:  make(chan struct{}),
		continueApply: make(chan struct{}),
	}
	manager := newTestApplyManager(t, store, target, ApplyHooks{})
	applyDone := make(chan error, 1)
	go func() {
		_, err := manager.ApplyIntent(context.Background(), "first-intent")
		applyDone <- err
	}()
	<-target.applyStarted

	handoffDone := make(chan error, 1)
	go func() {
		handoffDone <- manager.InstallAuthority(context.Background(), 7, Authority{
			PhysicalHostID:      "host-1",
			HostLeaseID:         "lease-2",
			HostLeaseSecretHash: "new-secret-hash",
			Fence:               8,
			ParentGeneration:    2,
			ParentState:         "active",
		})
	}()
	select {
	case err := <-handoffDone:
		t.Fatalf("handoff completed before admitted apply drained: %v", err)
	default:
	}
	close(target.continueApply)
	if err := <-applyDone; err != nil {
		t.Fatalf("admitted ApplyIntent: %v", err)
	}
	if err := <-handoffDone; err != nil {
		t.Fatalf("InstallAuthority: %v", err)
	}

	_, before := target.counts()
	_, err := manager.ApplyIntent(context.Background(), "stale-intent")
	if ErrorCodeOf(err) != CodeFenceRejected {
		t.Fatalf("old writer error = %v, want %s", err, CodeFenceRejected)
	}
	_, after := target.counts()
	if after != before {
		t.Fatalf("old writer performed an external effect: before=%d after=%d", before, after)
	}
}

func TestFailedVerifyLeavesEmergencyPolicyAndReadinessBlocked(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "appliance.db"))
	installTestAuthority(t, store, 3, 1)
	stageApplyTestNetwork(t, store, "network-1", "verify-failure", 3, 1, 0)
	target := &fakeTarget{failVerify: true}
	manager := newTestApplyManager(t, store, target, ApplyHooks{})

	_, err := manager.ApplyIntent(context.Background(), "verify-failure")
	if ErrorCodeOf(err) != CodeVerifyFailed {
		t.Fatalf("ApplyIntent error = %v, want %s", err, CodeVerifyFailed)
	}
	emergency, applies := target.counts()
	if applies != 1 || emergency == 0 {
		t.Fatalf("apply=%d emergency=%d, want apply once and fail closed", applies, emergency)
	}
	status, err := store.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Ready || status.Error == "" {
		t.Fatalf("status after failed verify = %+v", status)
	}
	intent, found, err := store.Intent(context.Background(), "verify-failure")
	if err != nil || !found || intent.Phase != "failed" {
		t.Fatalf("failed intent = found:%v phase:%q err:%v", found, intent.Phase, err)
	}
}

func TestStartupLoadsEmergencyBeforeReturningConflictPlan(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "appliance.db"))
	target := &fakeTarget{}
	plan := ConflictPlan{
		Revision:         "revision-1",
		ApprovalRequired: true,
		Conflicts: []Conflict{{
			Kind: ConflictService, Name: "docker.service", Active: true,
		}},
	}
	manager, err := NewApplyManager(ApplyManagerOptions{
		Store:     store,
		Compiler:  fakeCompiler{},
		Target:    target,
		Conflicts: fakeConflicts{plan: plan},
	})
	if err != nil {
		t.Fatalf("NewApplyManager: %v", err)
	}
	result, err := manager.Start(context.Background())
	if !IsApprovalRequired(err) {
		t.Fatalf("Start error = %v, want approval required", err)
	}
	if result.ConflictPlan == nil || result.ConflictPlan.Revision != plan.Revision {
		t.Fatalf("conflict result = %+v", result)
	}
	emergency, applies := target.counts()
	if emergency != 1 || applies != 0 {
		t.Fatalf("startup emergency=%d apply=%d, want 1 and 0", emergency, applies)
	}
}

func TestRestartLoadsEmergencyRecoversIntentAndBecomesReady(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "appliance.db"))
	installTestAuthority(t, store, 9, 3)
	stageApplyTestNetwork(t, store, "network-1", "restart-intent", 9, 3, 0)
	target := &fakeTarget{}
	manager := newTestApplyManager(t, store, target, ApplyHooks{})

	result, err := manager.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if result.Recovered != 1 {
		t.Fatalf("recovered = %d, want 1", result.Recovered)
	}
	emergency, applies := target.counts()
	if emergency != 1 || applies < 1 {
		t.Fatalf("restart emergency=%d apply=%d", emergency, applies)
	}
	status, err := store.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.Ready || status.Error != "" {
		t.Fatalf("restart status = %+v", status)
	}
}
