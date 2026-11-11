//go:build !linux

package appliance

import (
	"context"
	"errors"
	"io/fs"
)

var ErrUnsupportedPlatform = errors.New("appliance: Linux appliance operations are unsupported on this platform")

type OSCommandExecutor struct{}

func (OSCommandExecutor) Run(context.Context, string, ...string) (CommandResult, error) {
	return CommandResult{}, ErrUnsupportedPlatform
}

type OSFileSystem struct{}

func (OSFileSystem) ReadFile(string) ([]byte, error) {
	return nil, ErrUnsupportedPlatform
}

func (OSFileSystem) WriteFileAtomic(string, []byte, fs.FileMode) error {
	return ErrUnsupportedPlatform
}

func (OSFileSystem) Exists(string) (bool, error) {
	return false, ErrUnsupportedPlatform
}

type LinuxCompiler struct{}

func NewLinuxCompiler(LinuxCompilerConfig) (*LinuxCompiler, error) {
	return nil, ErrUnsupportedPlatform
}

func (*LinuxCompiler) Compile(context.Context, DesiredSnapshot, Intent) (CompiledApply, error) {
	return CompiledApply{}, ErrUnsupportedPlatform
}

type EmergencyPolicy struct{}

func NewEmergencyPolicy(EmergencyPolicyConfig) (*EmergencyPolicy, error) {
	return nil, ErrUnsupportedPlatform
}

func (*EmergencyPolicy) Ruleset() string {
	return ""
}

func (*EmergencyPolicy) Activate(context.Context) error {
	return ErrUnsupportedPlatform
}

type LinuxApplyTarget struct{}

func NewLinuxApplyTarget(LinuxTargetConfig) (*LinuxApplyTarget, error) {
	return nil, ErrUnsupportedPlatform
}

func (*LinuxApplyTarget) ActivateEmergency(context.Context) error {
	return ErrUnsupportedPlatform
}

func (*LinuxApplyTarget) Apply(context.Context, CompiledApply) error {
	return ErrUnsupportedPlatform
}

func (*LinuxApplyTarget) Verify(context.Context, CompiledApply) (Verification, error) {
	return Verification{}, ErrUnsupportedPlatform
}

type ConflictScanner struct{}

func NewConflictScanner(ConflictScannerConfig) (*ConflictScanner, error) {
	return nil, ErrUnsupportedPlatform
}

func (*ConflictScanner) Scan(context.Context) (ConflictPlan, error) {
	return ConflictPlan{}, ErrUnsupportedPlatform
}
