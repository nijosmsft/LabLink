package mcptools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/registry"
)

type windowsVMCreateFailure struct {
	PartialVMCreated    bool     `json:"partial_vm_created"`
	RequestedName       string   `json:"requested_name"`
	ObservedName        string   `json:"observed_name"`
	VMID                string   `json:"vm_id"`
	State               string   `json:"state"`
	Status              string   `json:"status"`
	VHDPaths            []string `json:"vhd_paths"`
	VMLocation          string   `json:"vm_location,omitempty"`
	VMConfigPath        string   `json:"vm_config_path,omitempty"`
	RequestedVHDPath    string   `json:"requested_vhd_path"`
	RequestedVMLocation string   `json:"requested_vm_location"`
	FailurePhase        string   `json:"failure_phase"`
	OriginalError       string   `json:"original_error"`
	CleanupOnFailure    bool     `json:"cleanup_on_failure"`
	CleanupAttempted    bool     `json:"cleanup_attempted"`
	CleanupSucceeded    bool     `json:"cleanup_succeeded"`
	CleanupError        string   `json:"cleanup_error"`
	DiagnosticError     string   `json:"diagnostic_error,omitempty"`
}

type windowsVMCleanupResult struct {
	CleanupSucceeded bool   `json:"cleanup_succeeded"`
	CleanupError     string `json:"cleanup_error"`
}

func newWindowsVMCreationOwnership(plan *windowsVMPlan) error {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return fmt.Errorf("generate VM creation ownership marker: %w", err)
	}
	id := hex.EncodeToString(token[:])
	plan.CreationOwnershipMarker = "lablink-create-owner:" + id
	plan.CreationOwnershipPath = filepath.Join(plan.VMLocation, ".lablink-create-owner-"+id+".txt")
	return nil
}

func prepareWindowsVMCreationOwnership(
	ctx context.Context,
	plan windowsVMPlan,
	reg *registry.Registry,
	pool *agentclient.Pool,
) error {
	target, err := resolvePlanTarget(plan.Target, reg)
	if err != nil {
		return err
	}
	managedRoot := windowsVMManagedRoot(plan)
	if managedRoot == "" {
		return fmt.Errorf("cleanup_on_failure requires vm_root or an explicit vm_location with a parent directory")
	}
	script := fmt.Sprintf(`
$managedRoot = %s
$vmLocation = %s
$vhdPath = %s
$markerPath = %s
$marker = %s
function Get-CanonicalPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    return [IO.Path]::GetFullPath($Path).TrimEnd('\')
}
function Test-PathWithin([string]$Child, [string]$Parent) {
    $childPath = Get-CanonicalPath $Child
    $parentPath = Get-CanonicalPath $Parent
    return $childPath -and $parentPath -and
        $childPath.StartsWith($parentPath + '\', [StringComparison]::OrdinalIgnoreCase)
}
$rootPath = Get-CanonicalPath $managedRoot
$locationPath = Get-CanonicalPath $vmLocation
$diskPath = Get-CanonicalPath $vhdPath
$ownerPath = Get-CanonicalPath $markerPath
if (-not (Test-PathWithin $locationPath $rootPath)) {
    throw "UNSAFE_VM_LOCATION: requested VM location is not below the managed root"
}
if (-not (Test-PathWithin $diskPath $locationPath)) {
    throw "UNSAFE_VHD_PATH: requested VHD is not below the exact VM location"
}
if (-not (Test-PathWithin $ownerPath $locationPath)) {
    throw "UNSAFE_OWNER_PATH: ownership marker is not below the exact VM location"
}
if (-not (Test-Path -LiteralPath $diskPath -PathType Leaf)) {
    throw "VHD_NOT_FOUND: provisioned VHD '$diskPath' was not found"
}
$encoding = [Text.UTF8Encoding]::new($false)
$stream = [IO.File]::Open($ownerPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $writer = [IO.StreamWriter]::new($stream, $encoding)
    try { $writer.Write($marker); $writer.Flush() } finally { $writer.Dispose() }
} finally {
    if ($stream) { $stream.Dispose() }
}
`, hyperv.PSLit(managedRoot), hyperv.PSLit(plan.VMLocation), hyperv.PSLit(plan.VHDPath),
		hyperv.PSLit(plan.CreationOwnershipPath), hyperv.PSLit(plan.CreationOwnershipMarker))
	_, _, err = runPS(ctx, reg, pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return fmt.Errorf("prepare exact cleanup ownership: %w", err)
	}
	return nil
}

func removeWindowsVMCreationOwnership(
	ctx context.Context,
	plan windowsVMPlan,
	reg *registry.Registry,
	pool *agentclient.Pool,
) {
	if plan.CreationOwnershipPath == "" {
		return
	}
	target, err := resolvePlanTarget(plan.Target, reg)
	if err != nil {
		return
	}
	script := fmt.Sprintf(`$p=%s; if (Test-Path -LiteralPath $p -PathType Leaf) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }`,
		hyperv.PSLit(plan.CreationOwnershipPath))
	_, _, _ = runPS(ctx, reg, pool, target, script, vmDefaultTimeoutSec)
}

func windowsVMManagedRoot(plan windowsVMPlan) string {
	if strings.TrimSpace(plan.VMRoot) != "" {
		return plan.VMRoot
	}
	if strings.TrimSpace(plan.VMLocation) != "" {
		return filepath.Dir(plan.VMLocation)
	}
	return ""
}

func windowsVMCreateFailureResult(
	ctx context.Context,
	plan windowsVMPlan,
	created *mcp.CallToolResult,
	createErr error,
	reg *registry.Registry,
	pool *agentclient.Pool,
	creds *credentials.Store,
) *mcp.CallToolResult {
	original := strings.TrimSpace(toolResultText(created))
	if createErr != nil {
		if original != "" {
			original += ": "
		}
		original += createErr.Error()
	}
	if original == "" {
		original = "create_vm failed"
	}
	secretValues := []string{plan.FirstBootScript}
	if credential, err := creds.Get(plan.AdminPasswordCredential); err == nil {
		secretValues = append(secretValues, credential.Password)
	}
	original = redactSecrets(original, secretValues)

	failure := windowsVMCreateFailure{
		RequestedName:       plan.Name,
		VHDPaths:            []string{},
		RequestedVHDPath:    plan.VHDPath,
		RequestedVMLocation: plan.VMLocation,
		FailurePhase:        "create_or_configure_vm",
		OriginalError:       original,
		CleanupOnFailure:    plan.CleanupOnFailure,
	}
	if err := diagnoseWindowsVMCreateFailure(ctx, plan, reg, pool, &failure); err != nil {
		failure.DiagnosticError = redactSecrets(err.Error(), secretValues)
	}
	if plan.CleanupOnFailure {
		failure.CleanupAttempted = true
		cleanup, err := cleanupWindowsVMCreateFailure(ctx, plan, reg, pool)
		if err != nil {
			failure.CleanupError = redactSecrets(err.Error(), secretValues)
		} else {
			failure.CleanupSucceeded = cleanup.CleanupSucceeded
			failure.CleanupError = redactSecrets(cleanup.CleanupError, secretValues)
		}
	}
	body, _ := json.MarshalIndent(failure, "", "  ")
	return mcp.NewToolResultError(fmt.Sprintf("%s\n\n```json\n%s\n```", original, body))
}

func diagnoseWindowsVMCreateFailure(
	ctx context.Context,
	plan windowsVMPlan,
	reg *registry.Registry,
	pool *agentclient.Pool,
	failure *windowsVMCreateFailure,
) error {
	target, err := resolvePlanTarget(plan.Target, reg)
	if err != nil {
		return err
	}
	script := fmt.Sprintf(`
$name = %s
$requestedVHDPath = [IO.Path]::GetFullPath(%s).TrimEnd('\')
$vm = Get-VM -ErrorAction SilentlyContinue |
    Where-Object { [string]::Equals([string]$_.Name, $name, [StringComparison]::OrdinalIgnoreCase) } |
    Select-Object -First 1
if (-not $vm) {
    [pscustomobject]@{ partial_vm_created = $false; vhd_paths = @() } | ConvertTo-Json -Depth 4
    return
}
$drives = @($vm | Get-VMHardDiskDrive -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.Path })
$partialVMCreated = [bool]($drives | Where-Object {
    [string]::Equals([IO.Path]::GetFullPath($_).TrimEnd('\'), $requestedVHDPath, [StringComparison]::OrdinalIgnoreCase)
})
[pscustomobject]@{
    partial_vm_created = $partialVMCreated
    observed_name = [string]$vm.Name
    vm_id = [string]$vm.Id
    state = [string]$vm.State
    status = [string]$vm.Status
    vhd_paths = $drives
    vm_location = [string]$vm.Path
    vm_config_path = [string]$vm.ConfigurationLocation
} | ConvertTo-Json -Depth 4
`, hyperv.PSLit(plan.Name), hyperv.PSLit(plan.VHDPath))
	out, _, err := runPS(ctx, reg, pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return fmt.Errorf("diagnose exact-name partial VM: %w", err)
	}
	var observed windowsVMCreateFailure
	if err := json.Unmarshal([]byte(jsonExtract(out)), &observed); err != nil {
		return fmt.Errorf("parse partial VM diagnostics: %w", err)
	}
	failure.PartialVMCreated = observed.PartialVMCreated
	failure.ObservedName = observed.ObservedName
	failure.VMID = observed.VMID
	failure.State = observed.State
	failure.Status = observed.Status
	failure.VHDPaths = observed.VHDPaths
	if failure.VHDPaths == nil {
		failure.VHDPaths = []string{}
	}
	failure.VMLocation = observed.VMLocation
	failure.VMConfigPath = observed.VMConfigPath
	return nil
}

func cleanupWindowsVMCreateFailure(
	ctx context.Context,
	plan windowsVMPlan,
	reg *registry.Registry,
	pool *agentclient.Pool,
) (windowsVMCleanupResult, error) {
	target, err := resolvePlanTarget(plan.Target, reg)
	if err != nil {
		return windowsVMCleanupResult{}, err
	}
	managedRoot := windowsVMManagedRoot(plan)
	script := fmt.Sprintf(`
$name = %s
$managedRoot = %s
$vmLocation = %s
$vhdPath = %s
$markerPath = %s
$marker = %s
$result = [ordered]@{ cleanup_succeeded = $false; cleanup_error = '' }
function Get-CanonicalPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    return [IO.Path]::GetFullPath($Path).TrimEnd('\')
}
function Test-PathWithin([string]$Child, [string]$Parent) {
    $childPath = Get-CanonicalPath $Child
    $parentPath = Get-CanonicalPath $Parent
    return $childPath -and $parentPath -and
        $childPath.StartsWith($parentPath + '\', [StringComparison]::OrdinalIgnoreCase)
}
function Test-PathAtOrWithin([string]$Child, [string]$Parent) {
    $childPath = Get-CanonicalPath $Child
    $parentPath = Get-CanonicalPath $Parent
    return $childPath -and $parentPath -and (
        $childPath.Equals($parentPath, [StringComparison]::OrdinalIgnoreCase) -or
        $childPath.StartsWith($parentPath + '\', [StringComparison]::OrdinalIgnoreCase)
    )
}
try {
    $rootPath = Get-CanonicalPath $managedRoot
    $locationPath = Get-CanonicalPath $vmLocation
    $diskPath = Get-CanonicalPath $vhdPath
    $ownerPath = Get-CanonicalPath $markerPath
    if (-not $rootPath -or -not (Test-PathWithin $locationPath $rootPath)) {
        throw "UNSAFE_VM_LOCATION: exact VM location is not below the managed root"
    }
    if (-not (Test-PathWithin $diskPath $locationPath)) {
        throw "UNSAFE_VHD_PATH: exact requested VHD is not below the VM location"
    }
    if (-not (Test-PathWithin $ownerPath $locationPath)) {
        throw "UNSAFE_OWNER_PATH: exact ownership marker is not below the VM location"
    }
    if (-not (Test-Path -LiteralPath $ownerPath -PathType Leaf)) {
        throw "OWNERSHIP_NOT_PROVEN: exact request ownership marker is missing"
    }
    $observedMarker = [IO.File]::ReadAllText($ownerPath)
    if (-not [string]::Equals($observedMarker, $marker, [StringComparison]::Ordinal)) {
        throw "OWNERSHIP_NOT_PROVEN: request ownership marker does not match"
    }
    $vm = Get-VM -ErrorAction SilentlyContinue |
        Where-Object { [string]::Equals([string]$_.Name, $name, [StringComparison]::OrdinalIgnoreCase) } |
        Select-Object -First 1
    if ($vm) {
        if (-not [string]::Equals([string]$vm.Notes, $marker, [StringComparison]::Ordinal)) {
            throw "OWNERSHIP_NOT_PROVEN: same-name VM does not carry the exact request marker"
        }
        $drives = @($vm | Get-VMHardDiskDrive -ErrorAction Stop)
        if ($drives.Count -ne 1 -or
            -not [string]::Equals((Get-CanonicalPath ([string]$drives[0].Path)), $diskPath, [StringComparison]::OrdinalIgnoreCase)) {
            throw "OWNERSHIP_NOT_PROVEN: same-name VM does not carry only the exact requested OS VHD"
        }
        if (-not (Test-PathAtOrWithin (Get-CanonicalPath ([string]$vm.Path)) $locationPath)) {
            throw "OWNERSHIP_NOT_PROVEN: same-name VM configuration is outside the exact requested location"
        }
        $configurationLocation = Get-CanonicalPath ([string]$vm.ConfigurationLocation)
        if ($configurationLocation -and -not (Test-PathAtOrWithin $configurationLocation $locationPath)) {
            throw "OWNERSHIP_NOT_PROVEN: same-name VM configuration location is outside the exact requested location"
        }
        if ([string]$vm.State -ne 'Off') {
            throw "OWNERSHIP_NOT_PROVEN: partial VM is not Off"
        }
        Remove-VM -VM $vm -Force -Confirm:$false -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $diskPath -PathType Leaf) {
        Remove-Item -LiteralPath $diskPath -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $ownerPath -PathType Leaf) {
        Remove-Item -LiteralPath $ownerPath -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $locationPath -PathType Container) {
        $remainingEntries = @(Get-ChildItem -LiteralPath $locationPath -Force -ErrorAction Stop)
        if ($remainingEntries.Count -eq 0) {
            Remove-Item -LiteralPath $locationPath -Force -ErrorAction Stop
        }
    }
    $remainingVM = Get-VM -ErrorAction SilentlyContinue |
        Where-Object { [string]::Equals([string]$_.Name, $name, [StringComparison]::OrdinalIgnoreCase) } |
        Select-Object -First 1
    if ($remainingVM -or (Test-Path -LiteralPath $diskPath) -or (Test-Path -LiteralPath $ownerPath)) {
        throw "CLEANUP_INCOMPLETE: exact owned VM artifacts remain"
    }
    $result.cleanup_succeeded = $true
} catch {
    $result.cleanup_error = [string]$_.Exception.Message
}
[pscustomobject]$result | ConvertTo-Json -Depth 4
`, hyperv.PSLit(plan.Name), hyperv.PSLit(managedRoot), hyperv.PSLit(plan.VMLocation),
		hyperv.PSLit(plan.VHDPath), hyperv.PSLit(plan.CreationOwnershipPath),
		hyperv.PSLit(plan.CreationOwnershipMarker))
	out, _, err := runPS(ctx, reg, pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return windowsVMCleanupResult{}, fmt.Errorf("run exact partial VM cleanup: %w", err)
	}
	var result windowsVMCleanupResult
	if err := json.Unmarshal([]byte(jsonExtract(out)), &result); err != nil {
		return windowsVMCleanupResult{}, fmt.Errorf("parse exact partial VM cleanup: %w", err)
	}
	return result, nil
}
