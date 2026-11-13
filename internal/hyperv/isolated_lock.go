package hyperv

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const (
	IsolatedLockHost IsolatedLockLevel = iota + 1
	IsolatedLockOrchestrator
	IsolatedLockAllocation
	IsolatedLockNetwork
	IsolatedLockVM
	IsolatedLockChild
)

type IsolatedLockLevel int

type IsolatedResourceLockKey struct {
	Level IsolatedLockLevel
	Key   string
}

func HostOrchestratorCreateLockKey(physicalHostID string) (IsolatedResourceLockKey, error) {
	if err := validateHostID(physicalHostID); err != nil {
		return IsolatedResourceLockKey{}, err
	}
	return IsolatedResourceLockKey{
		Level: IsolatedLockHost,
		Key:   "host:" + physicalHostID + ":orchestrator-create",
	}, nil
}

func OrchestratorLockKey(orchestratorID string) (IsolatedResourceLockKey, error) {
	return isolatedResourceLockKey(IsolatedLockOrchestrator, "orchestrator", orchestratorID)
}

func AllocationLockKey(orchestratorID string) (IsolatedResourceLockKey, error) {
	return isolatedResourceLockKey(IsolatedLockAllocation, "allocation", orchestratorID)
}

func NetworkLockKey(networkID string) (IsolatedResourceLockKey, error) {
	return isolatedResourceLockKey(IsolatedLockNetwork, "network", networkID)
}

func VMLockKey(vmID string) (IsolatedResourceLockKey, error) {
	return isolatedResourceLockKey(IsolatedLockVM, "vm", vmID)
}

func ChildLockKey(kind, id string) (IsolatedResourceLockKey, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind != "relay" && kind != "nat" {
		return IsolatedResourceLockKey{}, fmt.Errorf("child lock kind must be relay or nat")
	}
	return isolatedResourceLockKey(IsolatedLockChild, kind, id)
}

func (k IsolatedResourceLockKey) CanAcquireAfter(parent IsolatedResourceLockKey) bool {
	return k.Level > parent.Level
}

func isolatedResourceLockKey(level IsolatedLockLevel, kind, id string) (IsolatedResourceLockKey, error) {
	if err := validateIsolatedID(kind, id); err != nil {
		return IsolatedResourceLockKey{}, err
	}
	return IsolatedResourceLockKey{Level: level, Key: kind + ":" + strings.ToLower(id)}, nil
}

type IsolatedHostLeaseParams struct {
	PhysicalHostID  string
	LeaseID         string
	LeaseSecret     string
	HolderIdentity  string
	OperationID     string
	DurationSeconds int
	Fence           int64
}

type IsolatedMutationGuard struct {
	PhysicalHostID   string
	LeaseID          string
	LeaseSecret      string
	Fence            int64
	OrchestratorID   string
	OperationID      string
	MutationID       string
	ResourceType     string
	ResourceID       string
	Action           string
	CascadeAuthority *CascadeAuthority
}

type IsolatedHostLeaseResult struct {
	Status             string `json:"status"`
	Acquired           bool   `json:"acquired"`
	Renewed            bool   `json:"renewed"`
	Reclaimed          bool   `json:"reclaimed"`
	Released           bool   `json:"released"`
	LeaseID            string `json:"lease_id"`
	Fence              int64  `json:"fence"`
	ExpiresUTC         string `json:"expires_utc"`
	CurrentLeaseID     string `json:"current_lease_id,omitempty"`
	CurrentOperationID string `json:"current_operation_id,omitempty"`
	CurrentFence       int64  `json:"current_fence,omitempty"`
	CurrentExpiresUTC  string `json:"current_expires_utc,omitempty"`
}

var leaseSecretRE = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

func BuildAcquireIsolatedHostLockScript(p IsolatedHostLeaseParams) (string, error) {
	if err := validateHostLeaseParams(p, false); err != nil {
		return "", err
	}
	if p.DurationSeconds <= 0 {
		p.DurationSeconds = 120
	}
	body := PreflightScript() + isolatedLockPowerShell() + fmt.Sprintf(`
$physicalHostID = %s
$leaseID = %s
$leaseSecret = %s
$holderIdentity = %s
$operationID = %s
$durationSeconds = %d
$paths = Get-LabLinkIsolatedLockPaths $physicalHostID
New-Item -ItemType Directory -Force -Path $paths.root | Out-Null
Protect-LabLinkLockPath $paths.root $true
$currentBeforeWait = Read-LabLinkJSON $paths.current
$nowBeforeWait = [DateTime]::UtcNow
if ($currentBeforeWait -and [string]$currentBeforeWait.state -ceq 'active' -and
    (Convert-LabLinkUtc ([string]$currentBeforeWait.expires_utc)) -gt $nowBeforeWait -and
    [string]$currentBeforeWait.lease_id -cne $leaseID) {
    [pscustomobject]@{
        status='lock_busy'; acquired=$false; renewed=$false; reclaimed=$false
        lease_id=$leaseID; fence=0; expires_utc=$null
        current_lease_id=[string]$currentBeforeWait.lease_id
        current_operation_id=[string]$currentBeforeWait.operation_id
        current_fence=[int64]$currentBeforeWait.fence
        current_expires_utc=[string]$currentBeforeWait.expires_utc
    } | ConvertTo-Json -Compress
    return
}
$admission = $null
try {
    $admission = Open-LabLinkExclusiveFile $paths.admission 30000
} catch {
    $owner = Read-LabLinkJSON $paths.current
    throw "HOST_LOCK_ADMISSION_TIMEOUT: owner_operation=$([string]$owner.operation_id) owner_lease=$([string]$owner.lease_id) owner_fence=$([int64]$owner.fence) owner_expires=$([string]$owner.expires_utc)"
}
$external = $null
try {
    Assert-LabLinkPhysicalHostID $physicalHostID
    $current = Read-LabLinkJSON $paths.current
    $now = [DateTime]::UtcNow
    $sameLease = [bool]($current -and [string]$current.lease_id -ceq $leaseID)
    $activeOther = [bool](
        $current -and [string]$current.state -ceq 'active' -and
        (Convert-LabLinkUtc ([string]$current.expires_utc)) -gt $now -and
        -not $sameLease
    )
    if ($activeOther) {
        [pscustomobject]@{
            status='lock_busy'; acquired=$false; renewed=$false; reclaimed=$false
            lease_id=$leaseID; fence=0; expires_utc=$null
            current_lease_id=[string]$current.lease_id
            current_operation_id=[string]$current.operation_id
            current_fence=[int64]$current.fence
            current_expires_utc=[string]$current.expires_utc
        } | ConvertTo-Json -Compress
        return
    }
    if ($sameLease) {
        if ([string]$current.secret_hash -cne (Get-LabLinkSecretHash $leaseSecret)) {
            throw 'LEASE_SECRET_REJECTED: lease secret does not match the current host lease'
        }
        if ((Convert-LabLinkUtc ([string]$current.expires_utc)) -le $now) {
            throw 'LEASE_EXPIRED: the current lease expired and must be reclaimed with a new lease ID'
        }
        $current.expires_utc = $now.AddSeconds($durationSeconds).ToString('o')
        $current.holder_identity = $holderIdentity
        $current.operation_id = $operationID
        Write-LabLinkJSONAtomic $paths.current $current
        [pscustomobject]@{
            status='lock_renewed'; acquired=$true; renewed=$true; reclaimed=$false
            lease_id=$leaseID; fence=[int64]$current.fence
            expires_utc=[string]$current.expires_utc
        } | ConvertTo-Json -Compress
        return
    }

    $pending = [ordered]@{
        kind='lease_handoff'; proposed_lease_id=$leaseID
        proposed_fence=if ($current) { [int64]$current.fence + 1 } else { 1 }
        operation_id=$operationID; published_utc=$now.ToString('o')
    }
    Write-LabLinkJSONAtomic $paths.handoff $pending
    try {
        $external = Open-LabLinkExclusiveFile $paths.external 30000
    } catch {
        $owner = Read-LabLinkJSON $paths.current
        throw "HOST_LOCK_EXTERNAL_TIMEOUT: owner_operation=$([string]$owner.operation_id) owner_lease=$([string]$owner.lease_id) owner_fence=$([int64]$owner.fence) owner_expires=$([string]$owner.expires_utc)"
    }
    $latest = Read-LabLinkJSON $paths.current
    if ($latest -and [string]$latest.state -ceq 'active' -and
        (Convert-LabLinkUtc ([string]$latest.expires_utc)) -gt [DateTime]::UtcNow) {
        throw 'LOCK_RACE: host lease changed while reclamation was waiting for the external mutation gate'
    }
    $nextFence = if ($latest) { [int64]$latest.fence + 1 } else { 1 }
    $reclaimed = [bool]$latest
    $record = [ordered]@{
        schema_version=1; physical_host_id=$physicalHostID; state='active'
        lease_id=$leaseID; secret_hash=(Get-LabLinkSecretHash $leaseSecret)
        holder_identity=$holderIdentity; operation_id=$operationID; fence=$nextFence
        acquired_utc=[DateTime]::UtcNow.ToString('o')
        expires_utc=[DateTime]::UtcNow.AddSeconds($durationSeconds).ToString('o')
    }
    Write-LabLinkJSONAtomic $paths.current $record
    Remove-Item -LiteralPath $paths.handoff -Force -ErrorAction SilentlyContinue
    [pscustomobject]@{
        status=if ($reclaimed) { 'lock_reclaimed' } else { 'lock_acquired' }
        acquired=$true; renewed=$false; reclaimed=$reclaimed
        lease_id=$leaseID; fence=$nextFence; expires_utc=[string]$record.expires_utc
    } | ConvertTo-Json -Compress
} finally {
    if ($external) { $external.Dispose() }
    if ($admission) { $admission.Dispose() }
}
`, PSLit(p.PhysicalHostID), PSLit(p.LeaseID), PSLit(strings.ToLower(p.LeaseSecret)),
		PSLit(p.HolderIdentity), PSLit(p.OperationID), p.DurationSeconds)
	return wrapTagged(body), nil
}

func BuildRenewIsolatedHostLockScript(p IsolatedHostLeaseParams) (string, error) {
	if err := validateHostLeaseParams(p, true); err != nil {
		return "", err
	}
	if p.DurationSeconds <= 0 {
		p.DurationSeconds = 120
	}
	body := PreflightScript() + isolatedLockPowerShell() + fmt.Sprintf(`
$physicalHostID = %s
$leaseID = %s
$leaseSecret = %s
$expectedFence = [int64]%d
$durationSeconds = %d
$paths = Get-LabLinkIsolatedLockPaths $physicalHostID
$admission = Open-LabLinkExclusiveFile $paths.admission 30000
$external = $null
try {
    Assert-LabLinkPhysicalHostID $physicalHostID
    if (Test-Path -LiteralPath $paths.handoff) { throw 'HANDOFF_PENDING: host lease handoff is pending' }
    $external = Open-LabLinkExclusiveFile $paths.external 30000
    $current = Read-LabLinkJSON $paths.current
    Assert-LabLinkLease $current $physicalHostID $leaseID $leaseSecret $expectedFence
    $current.expires_utc = [DateTime]::UtcNow.AddSeconds($durationSeconds).ToString('o')
    Write-LabLinkJSONAtomic $paths.current $current
    [pscustomobject]@{
        status='lock_renewed'; acquired=$true; renewed=$true; reclaimed=$false
        lease_id=$leaseID; fence=$expectedFence; expires_utc=[string]$current.expires_utc
    } | ConvertTo-Json -Compress
} finally {
    if ($external) { $external.Dispose() }
    $admission.Dispose()
}
`, PSLit(p.PhysicalHostID), PSLit(p.LeaseID), PSLit(strings.ToLower(p.LeaseSecret)),
		p.Fence, p.DurationSeconds)
	return wrapTagged(body), nil
}

func BuildReleaseIsolatedHostLockScript(p IsolatedHostLeaseParams) (string, error) {
	if err := validateHostLeaseParams(p, true); err != nil {
		return "", err
	}
	body := PreflightScript() + isolatedLockPowerShell() + fmt.Sprintf(`
$physicalHostID = %s
$leaseID = %s
$leaseSecret = %s
$expectedFence = [int64]%d
$paths = Get-LabLinkIsolatedLockPaths $physicalHostID
$admission = Open-LabLinkExclusiveFile $paths.admission 30000
$external = $null
try {
    Assert-LabLinkPhysicalHostID $physicalHostID
    $current = Read-LabLinkJSON $paths.current
    Assert-LabLinkLease $current $physicalHostID $leaseID $leaseSecret $expectedFence
    $pending = [ordered]@{
        kind='lease_release'; proposed_lease_id=$leaseID
        proposed_fence=$expectedFence + 1; published_utc=[DateTime]::UtcNow.ToString('o')
    }
    Write-LabLinkJSONAtomic $paths.handoff $pending
    $external = Open-LabLinkExclusiveFile $paths.external 30000
    $current = Read-LabLinkJSON $paths.current
    Assert-LabLinkLease $current $physicalHostID $leaseID $leaseSecret $expectedFence
    $current.state = 'released'
    $current.fence = $expectedFence + 1
    $current.expires_utc = [DateTime]::UtcNow.ToString('o')
    Write-LabLinkJSONAtomic $paths.current $current
    Remove-Item -LiteralPath $paths.handoff -Force -ErrorAction SilentlyContinue
    [pscustomobject]@{
        status='lock_released'; released=$true; lease_id=$leaseID
        fence=[int64]$current.fence; expires_utc=[string]$current.expires_utc
    } | ConvertTo-Json -Compress
} finally {
    if ($external) { $external.Dispose() }
    $admission.Dispose()
}
`, PSLit(p.PhysicalHostID), PSLit(p.LeaseID), PSLit(strings.ToLower(p.LeaseSecret)), p.Fence)
	return wrapTagged(body), nil
}

func ParseIsolatedHostLeaseResult(text string) (IsolatedHostLeaseResult, error) {
	var result IsolatedHostLeaseResult
	text = strings.TrimSpace(extractJSON(text))
	if text == "" {
		return result, fmt.Errorf("isolated host lease result is empty")
	}
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		return result, err
	}
	return result, nil
}

func validateHostLeaseParams(p IsolatedHostLeaseParams, requireFence bool) error {
	if err := validateHostID(p.PhysicalHostID); err != nil {
		return err
	}
	if err := validateIsolatedID("lease", p.LeaseID); err != nil {
		return err
	}
	if !leaseSecretRE.MatchString(p.LeaseSecret) {
		return fmt.Errorf("lease secret must be a 256-bit hexadecimal value")
	}
	if strings.TrimSpace(p.HolderIdentity) == "" && !requireFence {
		return fmt.Errorf("lease holder identity is required")
	}
	if p.OperationID != "" {
		if err := validateIsolatedID("operation", p.OperationID); err != nil {
			return err
		}
	} else if !requireFence {
		return fmt.Errorf("operation ID is required")
	}
	if requireFence && p.Fence <= 0 {
		return fmt.Errorf("positive host fence is required")
	}
	return nil
}

func validateMutationGuard(g IsolatedMutationGuard) error {
	if err := validateHostID(g.PhysicalHostID); err != nil {
		return err
	}
	for kind, value := range map[string]string{
		"lease":        g.LeaseID,
		"orchestrator": g.OrchestratorID,
		"operation":    g.OperationID,
		"resource":     g.ResourceID,
	} {
		if err := validateIsolatedID(kind, value); err != nil {
			return err
		}
	}
	if err := validateMutationID(g.MutationID); err != nil {
		return err
	}
	if !leaseSecretRE.MatchString(g.LeaseSecret) {
		return fmt.Errorf("lease secret must be a 256-bit hexadecimal value")
	}
	if g.Fence <= 0 || strings.TrimSpace(g.ResourceType) == "" || strings.TrimSpace(g.Action) == "" {
		return fmt.Errorf("incomplete isolated mutation guard")
	}
	if err := validateCascadeAuthority(g.CascadeAuthority); err != nil {
		return err
	}
	return nil
}

func isolatedMutationGuardPowerShell(g IsolatedMutationGuard) (string, error) {
	if err := validateMutationGuard(g); err != nil {
		return "", err
	}
	cascade := ""
	if g.CascadeAuthority != nil {
		data, err := json.Marshal(g.CascadeAuthority)
		if err != nil {
			return "", err
		}
		cascade = string(data)
	}
	return isolatedLockPowerShell() + fmt.Sprintf(`
$guardPhysicalHostID = %s
$guardLeaseID = %s
$guardLeaseSecret = %s
$guardFence = [int64]%d
$guardOrchestratorID = %s
$guardOperationID = %s
$guardMutationID = %s
$guardResourceType = %s
$guardResourceID = %s
$guardAction = %s
$guardCascadeJSON = %s
$__isolatedGate = Enter-LabLinkIsolatedMutation $guardPhysicalHostID $guardLeaseID $guardLeaseSecret $guardFence
`, PSLit(g.PhysicalHostID), PSLit(g.LeaseID), PSLit(strings.ToLower(g.LeaseSecret)), g.Fence,
		PSLit(g.OrchestratorID), PSLit(g.OperationID), PSLit(g.MutationID),
		PSLit(g.ResourceType), PSLit(g.ResourceID), PSLit(g.Action), PSLit(cascade)), nil
}

func isolatedParentGuardPowerShell() string {
	return `
function Assert-LabLinkParentAllowsMutation($Metadata) {
    if ([string]$Metadata.physical_host_id -cne $guardPhysicalHostID -or
        [string]$Metadata.orchestrator_id -cne $guardOrchestratorID) {
        throw 'PARENT_IDENTITY_MISMATCH: orchestrator metadata does not match the mutation guard'
    }
    if ([int64]$Metadata.host_fence -ne $guardFence) {
        throw "FENCE_REJECTED: parent metadata fence $($Metadata.host_fence) does not match current fence $guardFence"
    }
    $state = [string]$Metadata.lifecycle_state
    if ($state -notin @('frozen','deleting','lost','deleted')) { return $null }
    if (-not $guardCascadeJSON) { throw "PARENT_FROZEN: orchestrator is $state" }
    $supplied = $guardCascadeJSON | ConvertFrom-Json
    $installed = $Metadata.cascade_authority
    if (-not $installed -or
        [string]$supplied.orchestrator_id -cne $guardOrchestratorID -or
        [string]$supplied.operation_id -cne $guardOperationID -or
        [string]$supplied.plan_revision -cne [string]$installed.plan_revision -or
        [string]$supplied.plan_hash -cne [string]$installed.plan_hash -or
        [string]$supplied.lease_id -cne $guardLeaseID -or
        [int64]$supplied.host_fence -ne $guardFence -or
        [string]$installed.orchestrator_id -cne $guardOrchestratorID -or
        [string]$installed.operation_id -cne $guardOperationID -or
        [string]$installed.lease_id -cne $guardLeaseID -or
        [int64]$installed.host_fence -ne $guardFence) {
        throw 'CASCADE_AUTHORITY_REJECTED: supplied cascade authority is not the installed revision'
    }
    $item = @($installed.items | Where-Object {
        -not [bool]$_.completed -and
        [string]$_.resource_type -ceq $guardResourceType -and
        [string]$_.resource_id -ceq $guardResourceID -and
        [string]$_.action -ceq $guardAction
    })
    if ($item.Count -ne 1) {
        throw 'CASCADE_AUTHORITY_REJECTED: cleanup action is not exactly enumerated'
    }
    return $item[0]
}
`
}

func isolatedLockPowerShell() string {
	return `
function Get-LabLinkPhysicalHostID {
    $machineGuid = [string](Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop)
    $smbiosUUID = [string](Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop).UUID
    function Normalize-LabLinkHardwareUUID([string]$Name, [string]$Value) {
        $value = $Value.Trim().Trim('{}').ToLowerInvariant()
        if ($value -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
            throw "HOST_IDENTITY_INVALID: $Name is missing or not a canonical UUID"
        }
        $compact = $value.Replace('-','')
        if ($compact.Trim('0').Length -eq 0 -or $compact.Trim('f').Length -eq 0 -or
            $value -in @('03000200-0400-0500-0006-000700080009','00020003-0004-0005-0006-000700080009')) {
            throw "HOST_IDENTITY_INVALID: $Name is a placeholder UUID"
        }
        return $value
    }
    $machineGuid = Normalize-LabLinkHardwareUUID 'MachineGuid' $machineGuid
    $smbiosUUID = Normalize-LabLinkHardwareUUID 'SMBIOS UUID' $smbiosUUID
    $tuple = 'lablink-physical-host/v1' + [char]0 + $machineGuid + [char]0 + $smbiosUUID
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($tuple)))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Assert-LabLinkPhysicalHostID([string]$Expected) {
    $observed = Get-LabLinkPhysicalHostID
    if ($observed -cne $Expected) {
        throw "HOST_IDENTITY_CHANGED: expected physical host $Expected, observed $observed"
    }
}
function Get-LabLinkSecretHash([string]$Secret) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Secret)))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Get-LabLinkIsolatedLockPaths([string]$PhysicalHostID) {
    $root = Join-Path $env:ProgramData ('LabLink\locks\isolated-orchestrator-' + $PhysicalHostID.Substring(0,16))
    return [pscustomobject]@{
        root=$root
        current=(Join-Path $root 'current.json')
        handoff=(Join-Path $root 'handoff_pending.json')
        admission=(Join-Path $root 'admission.lock')
        external=(Join-Path $root 'external-mutation.lock')
    }
}
function Open-LabLinkExclusiveFile([string]$Path, [int]$TimeoutMilliseconds) {
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while ($true) {
        try {
            return [IO.FileStream]::new($Path,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        } catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) { throw "LOCK_TIMEOUT: timed out acquiring '$Path'" }
            Start-Sleep -Milliseconds 50
        }
    }
}
function Read-LabLinkJSON([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return Get-Content -Raw -LiteralPath $Path -ErrorAction Stop | ConvertFrom-Json
}
function Write-LabLinkJSONAtomic([string]$Path, $Value) {
    $temporary = $Path + '.new'
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 20 -Compress))
    $stream = [IO.FileStream]::new($temporary,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    Protect-LabLinkLockPath $temporary $false
    Move-Item -LiteralPath $temporary -Destination $Path -Force
    Protect-LabLinkLockPath $Path $false
}
function Protect-LabLinkLockPath([string]$Path,[bool]$Container) {
    $inherit = & icacls.exe $Path /inheritance:r 2>&1
    if ($LASTEXITCODE -ne 0) { throw "LOCK_ACL_FAILED: $inherit" }
    $systemGrant = if ($Container) { '*S-1-5-18:(OI)(CI)F' } else { '*S-1-5-18:F' }
    $adminGrant = if ($Container) { '*S-1-5-32-544:(OI)(CI)F' } else { '*S-1-5-32-544:F' }
    $grant = & icacls.exe $Path /grant:r $systemGrant $adminGrant 2>&1
    if ($LASTEXITCODE -ne 0) { throw "LOCK_ACL_FAILED: $grant" }
}
function Convert-LabLinkUtc([string]$Value) {
    return [DateTime]::Parse($Value,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
}
function Assert-LabLinkLease($Current,[string]$PhysicalHostID,[string]$LeaseID,[string]$LeaseSecret,[int64]$Fence) {
    if (-not $Current -or [string]$Current.state -cne 'active') { throw 'LEASE_NOT_ACTIVE: no active isolated host lease' }
    if ([string]$Current.physical_host_id -cne $PhysicalHostID) { throw 'HOST_IDENTITY_CHANGED: lock metadata belongs to another physical host' }
    if ([string]$Current.lease_id -cne $LeaseID) { throw 'LEASE_REJECTED: lease ID is no longer current' }
    if ([int64]$Current.fence -ne $Fence) { throw "FENCE_REJECTED: expected fence $Fence, current fence $($Current.fence)" }
    if ([string]$Current.secret_hash -cne (Get-LabLinkSecretHash $LeaseSecret)) { throw 'LEASE_SECRET_REJECTED: lease secret mismatch' }
    if ((Convert-LabLinkUtc ([string]$Current.expires_utc)) -le [DateTime]::UtcNow) { throw 'LEASE_EXPIRED: isolated host lease expired' }
}
function Enter-LabLinkIsolatedMutation([string]$PhysicalHostID,[string]$LeaseID,[string]$LeaseSecret,[int64]$Fence) {
    $paths = Get-LabLinkIsolatedLockPaths $PhysicalHostID
    $admission = Open-LabLinkExclusiveFile $paths.admission 30000
    $external = $null
    try {
        Assert-LabLinkPhysicalHostID $PhysicalHostID
        if (Test-Path -LiteralPath $paths.handoff) { throw 'HANDOFF_PENDING: isolated host admission is closed' }
        $current = Read-LabLinkJSON $paths.current
        Assert-LabLinkLease $current $PhysicalHostID $LeaseID $LeaseSecret $Fence
        $external = Open-LabLinkExclusiveFile $paths.external 30000
        if (Test-Path -LiteralPath $paths.handoff) { throw 'HANDOFF_PENDING: isolated host admission closed while waiting' }
        $current = Read-LabLinkJSON $paths.current
        Assert-LabLinkLease $current $PhysicalHostID $LeaseID $LeaseSecret $Fence
        return $external
    } catch {
        if ($external) { $external.Dispose() }
        throw
    } finally {
        $admission.Dispose()
    }
}
`
}
