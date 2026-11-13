package appliance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
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
	SnapshotHash     string
	CompiledHash     string
	Artifacts        map[string][]byte
	EnableForwarding bool
}

type ApplyCompiler interface {
	Compile(context.Context, StaticSnapshot) (CompiledApply, error)
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
	mu        sync.Mutex
}

type StartupResult struct {
	ConflictPlan *ConflictPlan
}

func NewApplyManager(options ApplyManagerOptions) (*ApplyManager, error) {
	if options.Store == nil || options.Compiler == nil || options.Target == nil {
		return nil, storeError(
			CodeInvalidArgument, "store, compiler, and target are required")
	}
	return &ApplyManager{
		store: options.Store, compiler: options.Compiler,
		target: options.Target, conflicts: options.Conflicts,
		hooks: options.Hooks,
	}, nil
}

func (m *ApplyManager) Start(ctx context.Context) (StartupResult, error) {
	result := StartupResult{}
	if err := m.store.SetReadiness(
		ctx, false, "appliance startup recovery",
	); err != nil {
		return result, err
	}
	if err := m.target.ActivateEmergency(ctx); err != nil {
		detail := fmt.Sprintf("emergency policy failed: %v", err)
		_ = m.store.SetReadiness(ctx, false, detail)
		return result, storeError(CodeApplyFailed, "%s", detail)
	}
	if m.conflicts != nil {
		plan, err := m.conflicts.Scan(ctx)
		if err != nil {
			_ = m.store.SetReadiness(
				ctx, false, "firewall conflict scan failed: "+err.Error())
			return result, err
		}
		if len(plan.Conflicts) != 0 {
			result.ConflictPlan = &plan
			detail := fmt.Sprintf(
				"firewall conflict remains after bootstrap neutralization; plan %s",
				plan.Revision)
			_ = m.store.SetReadiness(ctx, false, detail)
			return result, storeError(CodeApplyFailed, "%s", detail)
		}
	}
	return result, m.ApplyStaticConfig(ctx)
}

func (m *ApplyManager) ApplyStaticConfig(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	snapshot, err := m.store.Snapshot(ctx)
	if err != nil {
		return err
	}
	compiled, err := m.compiler.Compile(ctx, snapshot)
	if err != nil {
		_ = m.store.SetReadiness(ctx, false, err.Error())
		return err
	}
	if m.hooks.AfterCompile != nil {
		if err := m.hooks.AfterCompile(compiled); err != nil {
			return err
		}
	}
	if m.hooks.BeforeApply != nil {
		if err := m.hooks.BeforeApply(compiled); err != nil {
			return err
		}
	}
	if err := m.target.Apply(ctx, compiled); err != nil {
		_ = m.store.SetReadiness(ctx, false, err.Error())
		return storeError(CodeApplyFailed, "%v", err)
	}
	if m.hooks.AfterApply != nil {
		if err := m.hooks.AfterApply(compiled); err != nil {
			return err
		}
	}
	verification, err := m.target.Verify(ctx, compiled)
	if err != nil {
		_ = m.store.SetReadiness(ctx, false, err.Error())
		return storeError(CodeVerifyFailed, "%v", err)
	}
	if !verification.Matched {
		_ = m.store.SetReadiness(ctx, false, verification.Detail)
		return storeError(CodeVerifyFailed, "%s", verification.Detail)
	}
	if m.hooks.AfterVerify != nil {
		if err := m.hooks.AfterVerify(compiled); err != nil {
			return err
		}
	}
	return m.store.SetReadiness(ctx, true, "")
}

func (m *ApplyManager) VerifyCurrent(
	ctx context.Context,
) (Verification, CompiledApply, error) {
	snapshot, err := m.store.Snapshot(ctx)
	if err != nil {
		return Verification{}, CompiledApply{}, err
	}
	compiled, err := m.compiler.Compile(ctx, snapshot)
	if err != nil {
		return Verification{}, CompiledApply{}, err
	}
	verification, err := m.target.Verify(ctx, compiled)
	return verification, compiled, err
}

func HashStaticSnapshot(snapshot StaticSnapshot) (string, error) {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	return hashBytes(data), nil
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
