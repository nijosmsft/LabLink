package hyperv

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	HyperVVMGroupSID          = "S-1-5-83-0"
	HyperVWorkerCapabilitySID = "S-1-15-3-1024-2268835264-3721307629-241982045-173645152-1490879176-104643441-2915960892-1612460704"
	LinuxVMMetadataPrefix     = "LABLINK_MANAGED_VM:"
	LinuxVMOwnershipFile      = ".lablink-linux-vm-ownership.json"
	LinuxVMOwnershipSchema    = 2
	LinuxVMCleanupAttached    = "cidata_attached"
	LinuxVMCleanupDetached    = "cidata_detached"
	LinuxVMCleanupComplete    = "complete"
	LinuxVMMetadataSchema     = 2
)

type LinuxVMOwnership struct {
	SchemaVersion int    `json:"schema_version"`
	VMName        string `json:"vm_name"`
	ManagedRoot   string `json:"managed_root"`
	VMLocation    string `json:"vm_location"`
	ChildVHDX     string `json:"child_vhdx"`
	ISOPath       string `json:"iso_path"`
	StageDir      string `json:"stage_dir"`
}

type LinuxVMOwnershipParams struct {
	Ownership LinuxVMOwnership
}

func normalizeLinuxVMOwnership(ownership LinuxVMOwnership) (LinuxVMOwnership, error) {
	if ownership.SchemaVersion == 0 {
		ownership.SchemaVersion = LinuxVMOwnershipSchema
	}
	if ownership.SchemaVersion != LinuxVMOwnershipSchema ||
		strings.TrimSpace(ownership.VMName) == "" ||
		strings.TrimSpace(ownership.ManagedRoot) == "" ||
		strings.TrimSpace(ownership.VMLocation) == "" ||
		strings.TrimSpace(ownership.ChildVHDX) == "" ||
		strings.TrimSpace(ownership.ISOPath) == "" ||
		strings.TrimSpace(ownership.StageDir) == "" {
		return LinuxVMOwnership{}, fmt.Errorf("incomplete Linux VM artifact ownership")
	}
	return ownership, nil
}

func restrictiveACLPowerShell() string {
	return `
function Set-LabLinkRestrictedAcl([string]$Path, [bool]$Container) {
    $inheritance = & icacls.exe $Path /inheritance:r 2>&1
    if ($LASTEXITCODE -ne 0) { throw "ACL_INHERITANCE_FAILED: '$Path': $inheritance" }
    $systemGrant = if ($Container) { '*S-1-5-18:(OI)(CI)F' } else { '*S-1-5-18:F' }
    $adminGrant = if ($Container) { '*S-1-5-32-544:(OI)(CI)F' } else { '*S-1-5-32-544:F' }
    $grant = & icacls.exe $Path /grant:r $systemGrant $adminGrant 2>&1
    if ($LASTEXITCODE -ne 0) { throw "ACL_GRANT_FAILED: '$Path': $grant" }
    Assert-LabLinkRestrictedAcl $Path @('S-1-5-18','S-1-5-32-544')
}
function Assert-LabLinkRestrictedAcl(
    [string]$Path,
    [string[]]$AllowedSids,
    [string[]]$ReadOnlySids=@(),
    [string[]]$OptionalInheritOnlySids=@(),
    [string[]]$OptionalSids=@()
) {
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) { throw "ACL_INHERITANCE_VERIFY_FAILED: '$Path'" }
    $seen = @{}
    $rights = @{}
    foreach ($rule in @($acl.Access)) {
        if ($rule.IsInherited) { throw "ACL_INHERITED_RULE_FOUND: '$Path'" }
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw "ACL_DENY_RULE_FOUND: '$Path'"
        }
        try {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        } catch {
            throw "ACL_IDENTITY_UNRESOLVED: '$Path': $($rule.IdentityReference)"
        }
        if ($sid -notin $AllowedSids -and
            $sid -notin $OptionalInheritOnlySids -and
            $sid -notin $OptionalSids) {
            throw "ACL_UNEXPECTED_IDENTITY: '$Path': $sid"
        }
        if ($sid -in $OptionalInheritOnlySids -and
            $rule.InheritanceFlags -eq [Security.AccessControl.InheritanceFlags]::None) {
            throw "ACL_OPTIONAL_IDENTITY_NOT_INHERIT_ONLY: '$Path': $sid"
        }
        $seen[$sid] = $true
        $rights[$sid] = [int64]$rights[$sid] -bor [int64]$rule.FileSystemRights
    }
    foreach ($sid in $AllowedSids) {
        if (-not $seen[$sid]) { throw "ACL_REQUIRED_IDENTITY_MISSING: '$Path': $sid" }
    }
    $fullControl = [int64][Security.AccessControl.FileSystemRights]::FullControl
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        if ($sid -in $AllowedSids -and ($rights[$sid] -band $fullControl) -ne $fullControl) {
            throw "ACL_REQUIRED_FULL_CONTROL_MISSING: '$Path': $sid"
        }
    }
    $writeMask = [int64](
        [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    )
    foreach ($sid in $ReadOnlySids) {
        if (($rights[$sid] -band $writeMask) -ne 0) { throw "ACL_READONLY_IDENTITY_HAS_WRITE: '$Path': $sid" }
    }
}
`
}

func BuildPersistLinuxVMOwnershipScript(p LinuxVMOwnershipParams) (string, error) {
	ownership, err := normalizeLinuxVMOwnership(p.Ownership)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(ownership)
	if err != nil {
		return "", err
	}
	body := fmt.Sprintf(`
$managedRoot = [IO.Path]::GetFullPath(%s).TrimEnd('\')
$vmLocation = [IO.Path]::GetFullPath(%s).TrimEnd('\')
$ownershipPath = Join-Path $vmLocation %s
$ownershipJson = %s
if (-not $vmLocation.StartsWith($managedRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "OWNERSHIP_PATH_OUTSIDE_MANAGED_ROOT: '$vmLocation'"
}
New-Item -ItemType Directory -Force -Path $vmLocation | Out-Null
%s
Set-LabLinkRestrictedAcl $vmLocation $true
$temporaryPath = $ownershipPath + '.new'
if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction Stop }
[IO.File]::WriteAllText($temporaryPath, $ownershipJson, [Text.UTF8Encoding]::new($false))
Move-Item -LiteralPath $temporaryPath -Destination $ownershipPath -Force -ErrorAction Stop
[pscustomobject]@{ status='ownership_persisted'; ownership_path=$ownershipPath } | ConvertTo-Json -Compress
`, PSLit(ownership.ManagedRoot), PSLit(ownership.VMLocation), PSLit(LinuxVMOwnershipFile),
		PSLit(string(data)), restrictiveACLPowerShell())
	return wrapTagged(body), nil
}

func BuildPrepareLinuxVMStageScript(p LinuxVMOwnershipParams) (string, error) {
	ownership, err := normalizeLinuxVMOwnership(p.Ownership)
	if err != nil {
		return "", err
	}
	body := fmt.Sprintf(`
$ownershipPath = Join-Path %s %s
$stageDir = %s
if (-not (Test-Path -LiteralPath $ownershipPath -PathType Leaf)) { throw "OWNERSHIP_RECORD_MISSING: '$ownershipPath'" }
$record = Get-Content -Raw -LiteralPath $ownershipPath -ErrorAction Stop | ConvertFrom-Json
if ([int]$record.schema_version -ne %d -or [string]$record.vm_name -cne %s -or
    [IO.Path]::GetFullPath([string]$record.stage_dir) -cne [IO.Path]::GetFullPath($stageDir)) {
    throw "OWNERSHIP_RECORD_MISMATCH: '$ownershipPath'"
}
if (Test-Path -LiteralPath $stageDir) { Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction Stop }
New-Item -ItemType Directory -Path $stageDir -ErrorAction Stop | Out-Null
%s
Set-LabLinkRestrictedAcl $stageDir $true
[pscustomobject]@{ status='stage_ready'; stage_dir=$stageDir } | ConvertTo-Json -Compress
`, PSLit(ownership.VMLocation), PSLit(LinuxVMOwnershipFile), PSLit(ownership.StageDir),
		LinuxVMOwnershipSchema, PSLit(ownership.VMName), restrictiveACLPowerShell())
	return wrapTagged(body), nil
}

func BuildCleanupLinuxVMStageScript(p LinuxVMOwnershipParams) (string, error) {
	ownership, err := normalizeLinuxVMOwnership(p.Ownership)
	if err != nil {
		return "", err
	}
	body := fmt.Sprintf(`
$ownershipPath = Join-Path %s %s
$stageDir = %s
if (-not (Test-Path -LiteralPath $ownershipPath -PathType Leaf)) { throw "OWNERSHIP_RECORD_MISSING: '$ownershipPath'" }
$record = Get-Content -Raw -LiteralPath $ownershipPath -ErrorAction Stop | ConvertFrom-Json
$expected = %s | ConvertFrom-Json
if ([int]$record.schema_version -ne [int]$expected.schema_version -or
    [string]$record.vm_name -cne [string]$expected.vm_name) {
    throw "OWNERSHIP_RECORD_MISMATCH: '$ownershipPath'"
}
foreach ($property in @('managed_root','vm_location','child_vhdx','iso_path','stage_dir')) {
    if ([IO.Path]::GetFullPath([string]$record.$property) -cne [IO.Path]::GetFullPath([string]$expected.$property)) {
        throw "OWNERSHIP_RECORD_MISMATCH: '$ownershipPath' property '$property'"
    }
}
if (Test-Path -LiteralPath $stageDir -PathType Container) {
    Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction Stop
}
if (Test-Path -LiteralPath $stageDir) { throw "CIDATA_STAGE_CLEANUP_INCOMPLETE: '$stageDir'" }
[pscustomobject]@{ status='stage_clean'; stage_dir=$stageDir; absent=$true } | ConvertTo-Json -Compress
`, PSLit(ownership.VMLocation), PSLit(LinuxVMOwnershipFile), PSLit(ownership.StageDir),
		PSLit(mustJSON(ownership)))
	return wrapTagged(body), nil
}

type LinuxVMMetadata struct {
	SchemaVersion     int    `json:"schema_version"`
	GuestOS           string `json:"guest_os"`
	VMName            string `json:"vm_name"`
	NodeName          string `json:"node_name"`
	ManagedRoot       string `json:"managed_root"`
	ParentVHDX        string `json:"parent_vhdx"`
	ChildVHDX         string `json:"child_vhdx"`
	ExpectedCIDATAISO string `json:"expected_cidata_iso"`
	CleanupPhase      string `json:"cleanup_phase"`
	Registered        bool   `json:"registered"`
}

func MarshalLinuxVMMetadata(metadata LinuxVMMetadata) (string, error) {
	if metadata.SchemaVersion == 0 {
		metadata.SchemaVersion = LinuxVMMetadataSchema
	}
	if metadata.GuestOS != "linux" || strings.TrimSpace(metadata.VMName) == "" ||
		strings.TrimSpace(metadata.NodeName) == "" || strings.TrimSpace(metadata.ManagedRoot) == "" ||
		strings.TrimSpace(metadata.ParentVHDX) == "" || strings.TrimSpace(metadata.ChildVHDX) == "" ||
		strings.TrimSpace(metadata.ExpectedCIDATAISO) == "" {
		return "", fmt.Errorf("incomplete managed Linux VM metadata")
	}
	if metadata.CleanupPhase == "" {
		metadata.CleanupPhase = LinuxVMCleanupAttached
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	return LinuxVMMetadataPrefix + string(data), nil
}

type CIDATAISOParams struct {
	SourceDir     string
	ISOPath       string
	OwnershipPath string
}

const cidataIMAPILockPowerShell = `
function Open-LabLinkExclusiveFileLock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][int]$TimeoutMilliseconds,
        [Parameter(Mandatory=$true)][int]$PollMilliseconds
    )
    if ($TimeoutMilliseconds -le 0 -or $PollMilliseconds -le 0) {
        throw 'CIDATA_IMAPI_LOCK_INVALID_TIMEOUT'
    }
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while ($true) {
        try {
            return [IO.FileStream]::new(
                $Path,
                [IO.FileMode]::OpenOrCreate,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None)
        } catch [IO.IOException] {
            $remainingMilliseconds = [int][Math]::Ceiling(($deadline - [DateTime]::UtcNow).TotalMilliseconds)
            if ($remainingMilliseconds -le 0) {
                throw "CIDATA_IMAPI_LOCK_TIMEOUT: '$Path'"
            }
            Start-Sleep -Milliseconds ([Math]::Min($PollMilliseconds, $remainingMilliseconds))
        }
    }
}
`

// BuildCIDATAISOScript creates a standard NoCloud seed ISO with Windows
// IMAPI2FS. Every seed and payload file remains at the ISO root.
func BuildCIDATAISOScript(p CIDATAISOParams) (string, error) {
	if strings.TrimSpace(p.SourceDir) == "" || strings.TrimSpace(p.ISOPath) == "" ||
		strings.TrimSpace(p.OwnershipPath) == "" {
		return "", fmt.Errorf("CIDATA source directory, ISO path, and ownership path are required")
	}
	body := fmt.Sprintf(`
$sourceDir = %s
$isoPath = %s
$ownershipPath = %s
if (-not (Test-Path -LiteralPath $sourceDir -PathType Container)) { throw "CIDATA_SOURCE_MISSING: '$sourceDir'" }
if (-not (Test-Path -LiteralPath $ownershipPath -PathType Leaf)) { throw "OWNERSHIP_RECORD_MISSING: '$ownershipPath'" }
$ownership = Get-Content -Raw -LiteralPath $ownershipPath -ErrorAction Stop | ConvertFrom-Json
if ([IO.Path]::GetFullPath([string]$ownership.iso_path) -cne [IO.Path]::GetFullPath($isoPath) -or
    [IO.Path]::GetFullPath([string]$ownership.stage_dir) -cne [IO.Path]::GetFullPath($sourceDir)) {
    throw "OWNERSHIP_RECORD_MISMATCH: '$ownershipPath'"
}
$required = @('meta-data','user-data','lablink-agent','ca.crt','server.crt','server.key','agent.token','install-lablink.sh')
foreach ($name in $required) {
    $path = Join-Path $sourceDir $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "CIDATA_FILE_MISSING: '$name'" }
}
$parent = Split-Path -Parent $isoPath
if (Test-Path -LiteralPath $isoPath) { throw "CIDATA_ISO_EXISTS: '$isoPath'" }
%s
Assert-LabLinkRestrictedAcl $parent @('S-1-5-18','S-1-5-32-544')
Assert-LabLinkRestrictedAcl $sourceDir @('S-1-5-18','S-1-5-32-544')

if (-not ('LabLinkISOFile' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices.ComTypes;

public static class LabLinkISOFile {
    public static void Create(string path, object comStream, int blockSize, int totalBlocks) {
        byte[] buffer = new byte[blockSize];
        IStream stream = (IStream)comStream;
        using (FileStream file = File.Open(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
            IntPtr read = System.Runtime.InteropServices.Marshal.AllocHGlobal(sizeof(int));
            try {
                for (int block = 0; block < totalBlocks; block++) {
                    System.Runtime.InteropServices.Marshal.WriteInt32(read, 0);
                    stream.Read(buffer, blockSize, read);
                    int count = System.Runtime.InteropServices.Marshal.ReadInt32(read);
                    if (count <= 0) break;
                    file.Write(buffer, 0, count);
                }
            } finally {
                System.Runtime.InteropServices.Marshal.FreeHGlobal(read);
            }
        }
    }
}
'@
}
%s
$imapiLockRoot = Join-Path $env:ProgramData 'LabLink\locks'
$imapiLockPath = Join-Path $imapiLockRoot 'cidata-imapi.lock'
New-Item -ItemType Directory -Force -Path $imapiLockRoot | Out-Null
$imapiLockHandle = $null
try {
    $imapiLockHandle = Open-LabLinkExclusiveFileLock -Path $imapiLockPath -TimeoutMilliseconds 120000 -PollMilliseconds 100
    $fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    $fsi.FileSystemsToCreate = 3
    $fsi.VolumeName = 'CIDATA'
    $fsi.FreeMediaBlocks = 1048576
    $fsi.Root.AddTree($sourceDir, $false)
    $result = $fsi.CreateResultImage()
    [LabLinkISOFile]::Create($isoPath, $result.ImageStream, $result.BlockSize, $result.TotalBlocks)
} finally {
    if ($null -ne $imapiLockHandle) {
        $imapiLockHandle.Dispose()
        $imapiLockHandle = $null
    }
}
if ((Get-Item -LiteralPath $isoPath).Length -le 0) { throw "CIDATA_ISO_EMPTY: '$isoPath'" }
Set-LabLinkRestrictedAcl $isoPath $false
[pscustomobject]@{
    status='created'; iso_path=$isoPath; volume_label='CIDATA'; filesystem='ISO9660+Joliet'
    files=@(Get-ChildItem -LiteralPath $sourceDir -File | Sort-Object Name | ForEach-Object Name)
    size_bytes=(Get-Item -LiteralPath $isoPath).Length
} | ConvertTo-Json -Depth 4 -Compress
`, PSLit(p.SourceDir), PSLit(p.ISOPath), PSLit(p.OwnershipPath), restrictiveACLPowerShell(), cidataIMAPILockPowerShell)
	return wrapTagged(body), nil
}

type CreateLinuxVMParams struct {
	Name                      string
	VMLocation                string
	ParentVHDX                string
	ChildVHDX                 string
	ISOPath                   string
	VSwitch                   string
	MemoryMB                  float64
	CPUCount                  float64
	DynamicMemory             bool
	DynamicMinMB              float64
	DynamicMaxMB              float64
	DynamicBufferPct          float64
	DiskSizeGB                float64
	MinHostReservePct         float64
	AllowHostResourcePressure bool
	ManagedMetadata           string
}

type ConfigureExistingLinuxVMParams struct {
	Name             string
	Metadata         LinuxVMMetadata
	Ownership        LinuxVMOwnership
	MemoryMB         float64
	CPUCount         float64
	DynamicMemory    bool
	DynamicMinMB     float64
	DynamicMaxMB     float64
	DynamicBufferPct float64
}

func BuildValidateExistingLinuxVMStorageScript(name string, expected LinuxVMMetadata) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("VM name is required")
	}
	metadataText, err := MarshalLinuxVMMetadata(expected)
	if err != nil {
		return "", err
	}
	expectedMetadata := strings.TrimPrefix(metadataText, LinuxVMMetadataPrefix)
	body := fmt.Sprintf(`
$name = %s
$metadataPrefix = %s
$expected = %s | ConvertFrom-Json
function Test-LabLinkSamePath([string]$First, [string]$Second) {
    if ([string]::IsNullOrWhiteSpace($First) -or [string]::IsNullOrWhiteSpace($Second)) { return $false }
    return [IO.Path]::GetFullPath($First).Equals(
        [IO.Path]::GetFullPath($Second),
        [StringComparison]::OrdinalIgnoreCase
    )
}
$vm = Get-VM -Name $name -ErrorAction Stop
$notes = [string]$vm.Notes
if (-not $notes.StartsWith($metadataPrefix, [StringComparison]::Ordinal)) {
    throw "VM_MANAGED_METADATA_MISSING: '$name'"
}
$metadata = $notes.Substring($metadataPrefix.Length) | ConvertFrom-Json
if ([int]$metadata.schema_version -ne [int]$expected.schema_version -or
    [string]$metadata.guest_os -cne 'linux' -or
    -not [string]::Equals([string]$metadata.vm_name, [string]$expected.vm_name, [StringComparison]::OrdinalIgnoreCase) -or
    -not (Test-LabLinkSamePath ([string]$metadata.parent_vhdx) ([string]$expected.parent_vhdx)) -or
    -not (Test-LabLinkSamePath ([string]$metadata.child_vhdx) ([string]$expected.child_vhdx))) {
    throw "VM_MANAGED_STORAGE_METADATA_MISMATCH: '$name'"
}
$parentVHDX = [string]$expected.parent_vhdx
$childVHDX = [string]$expected.child_vhdx
foreach ($path in @($parentVHDX,$childVHDX)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "REQUIRED_FILE_MISSING: '$path'" }
}
$hardDisks = @(Get-VMHardDiskDrive -VMName $name -ErrorAction Stop)
if ($hardDisks.Count -ne 1 -or -not (Test-LabLinkSamePath ([string]$hardDisks[0].Path) $childVHDX)) {
    throw "VM_CHILD_VHD_MISMATCH: '$name'"
}
$child = Get-VHD -Path $childVHDX -ErrorAction Stop
if (-not (Test-LabLinkSamePath ([string]$child.ParentPath) $parentVHDX)) {
    throw "VM_PARENT_VHD_MISMATCH: '$name'"
}
[pscustomobject]@{
    status='storage_validated'; name=$name; state=[string]$vm.State
    child_vhdx=$childVHDX; parent_vhdx=$parentVHDX; configuration_changed=$false
} | ConvertTo-Json -Compress
`, PSLit(name), PSLit(LinuxVMMetadataPrefix), PSLit(expectedMetadata))
	return wrapTagged(body), nil
}

func BuildConfigureExistingLinuxVMScript(p ConfigureExistingLinuxVMParams) (string, error) {
	ownership, err := normalizeLinuxVMOwnership(p.Ownership)
	if err != nil {
		return "", err
	}
	metadataText, err := MarshalLinuxVMMetadata(p.Metadata)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(p.Name) == "" ||
		!strings.EqualFold(p.Name, p.Metadata.VMName) ||
		!strings.EqualFold(p.Name, ownership.VMName) ||
		p.Metadata.CleanupPhase != LinuxVMCleanupAttached ||
		!strings.EqualFold(p.Metadata.ManagedRoot, ownership.ManagedRoot) ||
		!strings.EqualFold(p.Metadata.ChildVHDX, ownership.ChildVHDX) ||
		!strings.EqualFold(p.Metadata.ExpectedCIDATAISO, ownership.ISOPath) {
		return "", fmt.Errorf("existing Linux VM metadata and ownership must identify the same attached-phase VM")
	}
	mem := p.MemoryMB
	if mem <= 0 {
		mem = 4096
	}
	cpu := p.CPUCount
	if cpu <= 0 {
		cpu = 2
	}
	expectedMetadata := strings.TrimPrefix(metadataText, LinuxVMMetadataPrefix)
	body := fmt.Sprintf(`
$name = %s
$metadataPrefix = %s
$expectedMetadata = %s | ConvertFrom-Json
$expectedOwnership = %s | ConvertFrom-Json
$vmLocation = [IO.Path]::GetFullPath([string]$expectedOwnership.vm_location).TrimEnd('\')
$ownershipPath = Join-Path $vmLocation %s
$memory = %s
$cpu = %d
$dynamicMemory = %s
$dynamicMin = %s
$dynamicMax = %s
$dynamicBuffer = %d
function Test-LabLinkSamePath([string]$First, [string]$Second) {
    if ([string]::IsNullOrWhiteSpace($First) -or [string]::IsNullOrWhiteSpace($Second)) { return $false }
    return [IO.Path]::GetFullPath($First).Equals(
        [IO.Path]::GetFullPath($Second),
        [StringComparison]::OrdinalIgnoreCase
    )
}
$vm = Get-VM -Name $name -ErrorAction Stop
$vmState = [string]$vm.State
if ($vmState -notin @('Off','Running')) {
    throw "VM_RESUME_STATE_UNSAFE: '$name' is $vmState"
}
$notes = [string]$vm.Notes
if (-not $notes.StartsWith($metadataPrefix, [StringComparison]::Ordinal)) {
    throw "VM_MANAGED_METADATA_MISSING: '$name'"
}
$metadata = $notes.Substring($metadataPrefix.Length) | ConvertFrom-Json
if ([int]$metadata.schema_version -ne [int]$expectedMetadata.schema_version -or
    [string]$metadata.guest_os -cne 'linux' -or
    -not [string]::Equals([string]$metadata.vm_name, [string]$expectedMetadata.vm_name, [StringComparison]::OrdinalIgnoreCase) -or
    -not [string]::Equals([string]$metadata.node_name, [string]$expectedMetadata.node_name, [StringComparison]::OrdinalIgnoreCase) -or
    [string]$metadata.cleanup_phase -cne %s -or
    -not (Test-LabLinkSamePath ([string]$metadata.managed_root) ([string]$expectedMetadata.managed_root)) -or
    -not (Test-LabLinkSamePath ([string]$metadata.parent_vhdx) ([string]$expectedMetadata.parent_vhdx)) -or
    -not (Test-LabLinkSamePath ([string]$metadata.child_vhdx) ([string]$expectedMetadata.child_vhdx)) -or
    -not (Test-LabLinkSamePath ([string]$metadata.expected_cidata_iso) ([string]$expectedMetadata.expected_cidata_iso))) {
    throw "VM_MANAGED_METADATA_MISMATCH: '$name'"
}
if (-not (Test-Path -LiteralPath $ownershipPath -PathType Leaf)) {
    throw "OWNERSHIP_RECORD_MISSING: '$ownershipPath'"
}
$ownership = Get-Content -Raw -LiteralPath $ownershipPath -ErrorAction Stop | ConvertFrom-Json
if ([int]$ownership.schema_version -ne [int]$expectedOwnership.schema_version -or
    [string]$ownership.vm_name -cne [string]$expectedOwnership.vm_name) {
    throw "OWNERSHIP_RECORD_MISMATCH: '$ownershipPath'"
}
foreach ($property in @('managed_root','vm_location','child_vhdx','iso_path','stage_dir')) {
    if (-not (Test-LabLinkSamePath ([string]$ownership.$property) ([string]$expectedOwnership.$property))) {
        throw "OWNERSHIP_RECORD_MISMATCH: '$ownershipPath' property '$property'"
    }
}
$parentVHDX = [string]$expectedMetadata.parent_vhdx
$childVHDX = [string]$expectedMetadata.child_vhdx
$isoPath = [string]$expectedMetadata.expected_cidata_iso
foreach ($path in @($parentVHDX,$childVHDX,$isoPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "REQUIRED_FILE_MISSING: '$path'" }
}
if ((Get-Item -LiteralPath $parentVHDX).IsReadOnly -ne $true) {
    throw "PARENT_VHDX_NOT_READONLY: '$parentVHDX'"
}
$hardDisks = @(Get-VMHardDiskDrive -VMName $name -ErrorAction Stop)
if ($hardDisks.Count -ne 1 -or -not (Test-LabLinkSamePath ([string]$hardDisks[0].Path) $childVHDX)) {
    throw "VM_CHILD_VHD_MISMATCH: '$name'"
}
$child = Get-VHD -Path $childVHDX -ErrorAction Stop
if (-not (Test-LabLinkSamePath ([string]$child.ParentPath) $parentVHDX)) {
    throw "VM_PARENT_VHD_MISMATCH: '$name'"
}
$dvdDrives = @(Get-VMDvdDrive -VMName $name -ErrorAction SilentlyContinue | Where-Object Path)
$expectedDVD = @()
foreach ($drive in $dvdDrives) {
    if (-not (Test-LabLinkSamePath ([string]$drive.Path) $isoPath)) {
        throw "VM_RESUME_CIDATA_MISMATCH: '$name' has unexpected attached ISO '$($drive.Path)'"
    }
    $expectedDVD += $drive
}
if ($expectedDVD.Count -gt 1) { throw "VM_RESUME_CIDATA_DUPLICATE: '$name'" }
if ($vmState -eq 'Running') {
    if ($expectedDVD.Count -ne 1) {
        throw "VM_RESUME_RUNNING_CIDATA_MISSING: '$name' is running without the persisted CIDATA ISO attached"
    }
    [pscustomobject]@{
        status='validated_running'; name=$name; state=$vmState; cidata_iso=$isoPath
        cidata_attached=$true; configuration_changed=$false
    } | ConvertTo-Json -Depth 5 -Compress
    return
}
Set-VMProcessor -VMName $name -Count $cpu
if ($dynamicMemory) {
    $memArgs = @{ VMName=$name; DynamicMemoryEnabled=$true; StartupBytes=$memory }
    if ($dynamicMin -gt 0) { $memArgs.MinimumBytes=$dynamicMin }
    if ($dynamicMax -gt 0) { $memArgs.MaximumBytes=$dynamicMax }
    if ($dynamicBuffer -gt 0) { $memArgs.Buffer=$dynamicBuffer }
    Set-VMMemory @memArgs
} else {
    Set-VMMemory -VMName $name -DynamicMemoryEnabled $false -StartupBytes $memory
}
Set-VMFirmware -VMName $name -EnableSecureBoot On -SecureBootTemplate 'MicrosoftUEFICertificateAuthority'
$vmAccount = [Security.Principal.NTAccount]::new('NT VIRTUAL MACHINE', ([string]$vm.Id))
try {
    $vmSid = $vmAccount.Translate([Security.Principal.SecurityIdentifier]).Value
} catch {
    throw "CIDATA_VM_IDENTITY_RESOLUTION_FAILED: '$($vmAccount.Value)'"
}
$directoryGrant = & icacls.exe $vmLocation /grant:r ("*$vmSid" + ':(OI)(CI)RX') 2>&1
if ($LASTEXITCODE -ne 0) { throw "VM_DIRECTORY_ACL_GRANT_FAILED: '$vmLocation': $directoryGrant" }
$isoGrant = & icacls.exe $isoPath /grant:r ("*$vmSid" + ':(R)') 2>&1
if ($LASTEXITCODE -ne 0) { throw "CIDATA_VM_ACL_GRANT_FAILED: '$isoPath': $isoGrant" }
%s
Assert-LabLinkRestrictedAcl $vmLocation @('S-1-5-18','S-1-5-32-544',$vmSid) @($vmSid) @('S-1-3-0') @(%s,%s)
Assert-LabLinkRestrictedAcl $isoPath @('S-1-5-18','S-1-5-32-544',$vmSid) @($vmSid)
$attachedNow = $false
if ($expectedDVD.Count -eq 0) {
    Add-VMDvdDrive -VMName $name -Path $isoPath
    $attachedNow = $true
}
$vhd = Get-VMHardDiskDrive -VMName $name | Where-Object {
    Test-LabLinkSamePath ([string]$_.Path) $childVHDX
} | Select-Object -First 1
$dvd = Get-VMDvdDrive -VMName $name | Where-Object {
    $_.Path -and (Test-LabLinkSamePath ([string]$_.Path) $isoPath)
} | Select-Object -First 1
if (-not $vhd -or -not $dvd) { throw "VM_BOOT_DEVICE_MISSING: failed to attach VHD or CIDATA" }
Set-VMFirmware -VMName $name -BootOrder $vhd,$dvd
Enable-VMIntegrationService -VMName $name -Name 'Key-Value Pair Exchange' -ErrorAction SilentlyContinue
[pscustomobject]@{
    status='configured'; name=$name; state=$vmState; cidata_iso=$isoPath; cidata_attached=$attachedNow
    secure_boot_template='MicrosoftUEFICertificateAuthority'; boot_order=@('VHD','DVD')
} | ConvertTo-Json -Depth 5 -Compress
`, PSLit(p.Name), PSLit(LinuxVMMetadataPrefix), PSLit(expectedMetadata), PSLit(mustJSON(ownership)),
		PSLit(LinuxVMOwnershipFile), mbBytes(mem), int64(cpu), PSBool(p.DynamicMemory),
		mbBytes(p.DynamicMinMB), mbBytes(p.DynamicMaxMB), int64(p.DynamicBufferPct),
		PSLit(LinuxVMCleanupAttached), restrictiveACLPowerShell(),
		PSLit(HyperVVMGroupSID), PSLit(HyperVWorkerCapabilitySID))
	return wrapTagged(body), nil
}

func BuildCreateLinuxVMScript(p CreateLinuxVMParams) (string, error) {
	if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.VMLocation) == "" ||
		strings.TrimSpace(p.ParentVHDX) == "" || strings.TrimSpace(p.ChildVHDX) == "" ||
		strings.TrimSpace(p.ISOPath) == "" || strings.TrimSpace(p.VSwitch) == "" ||
		!strings.HasPrefix(p.ManagedMetadata, LinuxVMMetadataPrefix) {
		return "", fmt.Errorf("name, VM location, parent/child VHDX, CIDATA ISO, and vSwitch are required")
	}
	mem := p.MemoryMB
	if mem <= 0 {
		mem = 4096
	}
	cpu := p.CPUCount
	if cpu <= 0 {
		cpu = 2
	}
	resourceScript, err := ResourceSafetyScript(ResourceSafetyParams{
		MemoryMB: mem, StoragePath: p.ChildVHDX, ReserveVHDPath: p.ParentVHDX,
		ReserveRemainingGrowth: false, StorageReserveBytes: int64(p.DiskSizeGB * 1024 * 1024 * 1024),
		MinHostReservePct:         p.MinHostReservePct,
		AllowHostResourcePressure: p.AllowHostResourcePressure,
	})
	if err != nil {
		return "", err
	}
	body := PreflightScript() + fmt.Sprintf(`
$name = %s
$vmLocation = %s
$parentVHDX = %s
$childVHDX = %s
$isoPath = %s
$vswitch = %s
$memory = %s
$cpu = %d
$dynamicMemory = %s
$dynamicMin = %s
$dynamicMax = %s
$dynamicBuffer = %d
$diskSize = %s
$managedMetadata = %s
%s
if (Get-VM -Name $name -ErrorAction SilentlyContinue) { throw "VM_EXISTS: '$name'" }
foreach ($path in @($parentVHDX,$isoPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "REQUIRED_FILE_MISSING: '$path'" }
}
if (-not (Get-VMSwitch -Name $vswitch -ErrorAction SilentlyContinue)) { throw "VSWITCH_NOT_FOUND: '$vswitch'" }
if ((Get-Item -LiteralPath $parentVHDX).IsReadOnly -ne $true) { throw "PARENT_VHDX_NOT_READONLY: '$parentVHDX'" }
if (Test-Path -LiteralPath $childVHDX) { throw "CHILD_VHDX_EXISTS: '$childVHDX'" }
New-Item -ItemType Directory -Force -Path $vmLocation,(Split-Path -Parent $childVHDX) | Out-Null
$parentSize = [int64](Get-VHD -Path $parentVHDX).Size
if ($diskSize -ne $parentSize) { throw "PARENT_VHDX_SIZE_MISMATCH: prepared parent is $parentSize bytes, requested $diskSize" }
New-VHD -Path $childVHDX -ParentPath $parentVHDX -Differencing | Out-Null
New-VM -Name $name -Generation 2 -Path $vmLocation -MemoryStartupBytes $memory -VHDPath $childVHDX -SwitchName $vswitch | Out-Null
Set-VM -Name $name -Notes $managedMetadata
Set-VMProcessor -VMName $name -Count $cpu
if ($dynamicMemory) {
    $memArgs = @{ VMName=$name; DynamicMemoryEnabled=$true; StartupBytes=$memory }
    if ($dynamicMin -gt 0) { $memArgs.MinimumBytes=$dynamicMin }
    if ($dynamicMax -gt 0) { $memArgs.MaximumBytes=$dynamicMax }
    if ($dynamicBuffer -gt 0) { $memArgs.Buffer=$dynamicBuffer }
    Set-VMMemory @memArgs
} else {
    Set-VMMemory -VMName $name -DynamicMemoryEnabled $false -StartupBytes $memory
}
Set-VMFirmware -VMName $name -EnableSecureBoot On -SecureBootTemplate 'MicrosoftUEFICertificateAuthority'
$vm = Get-VM -Name $name -ErrorAction Stop
$vmAccount = [Security.Principal.NTAccount]::new('NT VIRTUAL MACHINE', ([string]$vm.Id))
try {
    $vmSid = $vmAccount.Translate([Security.Principal.SecurityIdentifier]).Value
} catch {
    throw "CIDATA_VM_IDENTITY_RESOLUTION_FAILED: '$($vmAccount.Value)'"
}
$directoryGrant = & icacls.exe $vmLocation /grant:r ("*$vmSid" + ':(OI)(CI)RX') 2>&1
if ($LASTEXITCODE -ne 0) { throw "VM_DIRECTORY_ACL_GRANT_FAILED: '$vmLocation': $directoryGrant" }
$isoGrant = & icacls.exe $isoPath /grant:r ("*$vmSid" + ':(R)') 2>&1
if ($LASTEXITCODE -ne 0) { throw "CIDATA_VM_ACL_GRANT_FAILED: '$isoPath': $isoGrant" }
%s
Assert-LabLinkRestrictedAcl $vmLocation @('S-1-5-18','S-1-5-32-544',$vmSid) @($vmSid) @('S-1-3-0') @(%s,%s)
Assert-LabLinkRestrictedAcl $isoPath @('S-1-5-18','S-1-5-32-544',$vmSid) @($vmSid)
Add-VMDvdDrive -VMName $name -Path $isoPath
$vhd = Get-VMHardDiskDrive -VMName $name | Select-Object -First 1
$dvd = Get-VMDvdDrive -VMName $name | Where-Object Path -eq $isoPath | Select-Object -First 1
if (-not $vhd -or -not $dvd) { throw "VM_BOOT_DEVICE_MISSING: failed to attach VHD or CIDATA" }
Set-VMFirmware -VMName $name -BootOrder $vhd,$dvd
Enable-VMIntegrationService -VMName $name -Name 'Key-Value Pair Exchange' -ErrorAction SilentlyContinue
[pscustomobject]@{
    status='created'; name=$name; vm_location=$vmLocation; vhd_path=$childVHDX
    cidata_iso=$isoPath; secure_boot_template='MicrosoftUEFICertificateAuthority'
    boot_order=@('VHD','DVD'); resource_safety=[pscustomobject]$resourceSafety
} | ConvertTo-Json -Depth 8 -Compress
`, PSLit(p.Name), PSLit(p.VMLocation), PSLit(p.ParentVHDX), PSLit(p.ChildVHDX),
		PSLit(p.ISOPath), PSLit(p.VSwitch), mbBytes(mem), int64(cpu), PSBool(p.DynamicMemory),
		mbBytes(p.DynamicMinMB), mbBytes(p.DynamicMaxMB), int64(p.DynamicBufferPct),
		gbBytes(p.DiskSizeGB), PSLit(p.ManagedMetadata), resourceScript,
		restrictiveACLPowerShell(), PSLit(HyperVVMGroupSID), PSLit(HyperVWorkerCapabilitySID))
	return wrapTagged(body), nil
}

func BuildReadLinuxVMMetadataScript(name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("VM name is required")
	}
	body := fmt.Sprintf(`
$name = %s
$prefix = %s
$vm = Get-VM -Name $name -ErrorAction SilentlyContinue
if (-not $vm) {
    [pscustomobject]@{ exists=$false } | ConvertTo-Json -Compress
    return
}
$notes = [string]$vm.Notes
if (-not $notes.StartsWith($prefix, [StringComparison]::Ordinal)) {
    throw "VM_MANAGED_METADATA_MISSING: existing VM '$name' has no LabLink managed metadata"
}
$metadata = $notes.Substring($prefix.Length) | ConvertFrom-Json
$attached = @(Get-VMDvdDrive -VMName $name -ErrorAction SilentlyContinue |
    Where-Object Path | ForEach-Object { [string]$_.Path })
[pscustomobject]@{
    exists=$true; metadata=$metadata; attached_isos=$attached
    expected_iso_exists=(Test-Path -LiteralPath ([string]$metadata.expected_cidata_iso) -PathType Leaf)
} | ConvertTo-Json -Depth 6 -Compress
`, PSLit(name), PSLit(LinuxVMMetadataPrefix))
	return wrapTagged(body), nil
}

func BuildInspectVMManagementScript(name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("VM name is required")
	}
	body := fmt.Sprintf(`
$name = %s
$prefix = %s
$vm = Get-VM -Name $name -ErrorAction SilentlyContinue
if (-not $vm) {
    [pscustomobject]@{ exists=$false } | ConvertTo-Json -Compress
    return
}
$metadata = $null
$notes = [string]$vm.Notes
if ($notes.StartsWith($prefix, [StringComparison]::Ordinal)) {
    $metadata = $notes.Substring($prefix.Length) | ConvertFrom-Json
}
$attached = @(Get-VMDvdDrive -VMName $name -ErrorAction SilentlyContinue |
    Where-Object Path | ForEach-Object { [string]$_.Path })
$ownershipPath = if ($metadata) {
    Join-Path (Split-Path -Parent ([string]$metadata.child_vhdx)) %s
} else {
    $null
}
[pscustomobject]@{
    exists=$true; state=[string]$vm.State; metadata=$metadata; attached_isos=$attached
    expected_iso_exists=[bool]($metadata -and (Test-Path -LiteralPath ([string]$metadata.expected_cidata_iso) -PathType Leaf))
    ownership_exists=[bool]($ownershipPath -and (Test-Path -LiteralPath $ownershipPath -PathType Leaf))
} | ConvertTo-Json -Depth 6 -Compress
`, PSLit(name), PSLit(LinuxVMMetadataPrefix), PSLit(LinuxVMOwnershipFile))
	return wrapTagged(body), nil
}

type ReconcileLinuxVMArtifactsParams struct {
	Name      string
	Ownership LinuxVMOwnership
}

func BuildReconcileLinuxVMArtifactsScript(p ReconcileLinuxVMArtifactsParams) (string, error) {
	ownership, err := normalizeLinuxVMOwnership(p.Ownership)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(p.Name) == "" || !strings.EqualFold(p.Name, ownership.VMName) {
		return "", fmt.Errorf("VM name must match Linux VM ownership")
	}
	body := fmt.Sprintf(`
$name = %s
$vmLocation = [IO.Path]::GetFullPath(%s).TrimEnd('\')
$ownershipPath = Join-Path $vmLocation %s
$expected = %s | ConvertFrom-Json
$metadataPrefix = %s
$vm = Get-VM -Name $name -ErrorAction SilentlyContinue
$record = $null
if (Test-Path -LiteralPath $ownershipPath -PathType Leaf) {
    $record = Get-Content -Raw -LiteralPath $ownershipPath -ErrorAction Stop | ConvertFrom-Json
    foreach ($property in @('managed_root','vm_location','child_vhdx','iso_path','stage_dir')) {
        if ([IO.Path]::GetFullPath([string]$record.$property) -cne [IO.Path]::GetFullPath([string]$expected.$property)) {
            throw "OWNERSHIP_RECORD_MISMATCH: '$ownershipPath' property '$property'"
        }
    }
    if ([int]$record.schema_version -ne %d -or [string]$record.vm_name -cne [string]$expected.vm_name) {
        throw "OWNERSHIP_RECORD_MISMATCH: '$ownershipPath'"
    }
}
$deleted = @()
$retained = @()
if ($record -and (Test-Path -LiteralPath ([string]$record.stage_dir) -PathType Container)) {
    Remove-Item -LiteralPath ([string]$record.stage_dir) -Recurse -Force -ErrorAction Stop
    $deleted += [string]$record.stage_dir
}
if (-not $vm -and $record) {
    foreach ($artifact in @([string]$record.iso_path,[string]$record.child_vhdx)) {
        if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) { continue }
        $referenced = @(
            Get-VM -ErrorAction SilentlyContinue | ForEach-Object {
                @($_ | Get-VMHardDiskDrive -ErrorAction SilentlyContinue) + @($_ | Get-VMDvdDrive -ErrorAction SilentlyContinue)
            } | Where-Object {
                $_.Path -and [IO.Path]::GetFullPath([string]$_.Path).Equals([IO.Path]::GetFullPath($artifact), [StringComparison]::OrdinalIgnoreCase)
            }
        ).Count -gt 0
        if ($referenced) {
            $retained += $artifact
        } else {
            Remove-Item -LiteralPath $artifact -Force -ErrorAction Stop
            $deleted += $artifact
        }
    }
    if ($retained.Count -eq 0) {
        Remove-Item -LiteralPath $ownershipPath -Force -ErrorAction Stop
        $deleted += $ownershipPath
    }
} elseif ($vm -and $record) {
    $notes = [string]$vm.Notes
    if ($notes.StartsWith($metadataPrefix, [StringComparison]::Ordinal)) {
        $metadata = $notes.Substring($metadataPrefix.Length) | ConvertFrom-Json
        if ([string]$metadata.cleanup_phase -in @(%s,%s)) {
            $attached = @(Get-VMDvdDrive -VMName $name -ErrorAction SilentlyContinue | Where-Object {
                $_.Path -and [IO.Path]::GetFullPath([string]$_.Path).Equals([IO.Path]::GetFullPath([string]$record.iso_path), [StringComparison]::OrdinalIgnoreCase)
            })
            if ($attached.Count -ne 0) { throw "CIDATA_PHASE_ATTACHMENT_MISMATCH: '$name'" }
            if (Test-Path -LiteralPath ([string]$record.iso_path) -PathType Leaf) {
                Remove-Item -LiteralPath ([string]$record.iso_path) -Force -ErrorAction Stop
                $deleted += [string]$record.iso_path
            }
            Remove-Item -LiteralPath $ownershipPath -Force -ErrorAction Stop
            $deleted += $ownershipPath
        } else {
            $retained += [string]$record.iso_path
        }
    } else {
        $retained += [string]$record.iso_path
    }
}
[pscustomobject]@{
    status='reconciled'; vm_exists=[bool]$vm; ownership_exists=[bool]$record
    deleted=$deleted; retained=$retained; ownership_path=$ownershipPath
} | ConvertTo-Json -Depth 5 -Compress
`, PSLit(p.Name), PSLit(ownership.VMLocation), PSLit(LinuxVMOwnershipFile),
		PSLit(mustJSON(ownership)), PSLit(LinuxVMMetadataPrefix), LinuxVMOwnershipSchema,
		PSLit(LinuxVMCleanupDetached), PSLit(LinuxVMCleanupComplete))
	return wrapTagged(body), nil
}

func mustJSON(value any) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func BuildSetLinuxVMRegistrationScript(name string, registered bool) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("VM name is required")
	}
	body := fmt.Sprintf(`
$name = %s
$prefix = %s
$vm = Get-VM -Name $name -ErrorAction Stop
$notes = [string]$vm.Notes
if (-not $notes.StartsWith($prefix, [StringComparison]::Ordinal)) {
    throw "VM_MANAGED_METADATA_MISSING: '$name'"
}
$metadata = $notes.Substring($prefix.Length) | ConvertFrom-Json
$metadata.registered = %s
Set-VM -Name $name -Notes ($prefix + ($metadata | ConvertTo-Json -Depth 6 -Compress))
[pscustomobject]@{ status='metadata_updated'; registered=[bool]$metadata.registered; cleanup_phase=[string]$metadata.cleanup_phase } | ConvertTo-Json -Compress
`, PSLit(name), PSLit(LinuxVMMetadataPrefix), PSBool(registered))
	return wrapTagged(body), nil
}

func BuildLinuxVMStartAndDiscoverScript(name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("VM name is required")
	}
	body := fmt.Sprintf(`
$name = %s
$vm = Get-VM -Name $name -ErrorAction Stop
Enable-VMIntegrationService -VMName $name -Name 'Key-Value Pair Exchange' -ErrorAction SilentlyContinue
if ($vm.State -ne 'Running') { Start-VM -Name $name -ErrorAction Stop | Out-Null }
$deadline = (Get-Date).AddMinutes(15)
do {
    $ip = Get-VMNetworkAdapter -VMName $name -ErrorAction SilentlyContinue |
        ForEach-Object IPAddresses |
        Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -notmatch '^169\.254\.' -and $_ -ne '127.0.0.1' } |
        Select-Object -First 1
    if ($ip) { break }
    Start-Sleep -Seconds 5
} while ((Get-Date) -lt $deadline)
if (-not $ip) { throw "VM_KVP_IP_TIMEOUT: '$name' did not report DHCP IPv4 through Hyper-V KVP" }
[pscustomobject]@{ status='running'; state=[string](Get-VM -Name $name).State; ip_address=$ip; discovery='hyperv-kvp' } | ConvertTo-Json -Compress
`, PSLit(name))
	return wrapTagged(body), nil
}

func BuildLinuxVMCIDATACleanupScript(name, isoPath string) (string, error) {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(isoPath) == "" {
		return "", fmt.Errorf("VM name and CIDATA ISO path are required")
	}
	body := fmt.Sprintf(`
$name = %s
$isoPath = %s
$prefix = %s
$vm = Get-VM -Name $name -ErrorAction Stop
$notes = [string]$vm.Notes
if (-not $notes.StartsWith($prefix, [StringComparison]::Ordinal)) {
    throw "VM_MANAGED_METADATA_MISSING: '$name'"
}
$metadata = $notes.Substring($prefix.Length) | ConvertFrom-Json
if ([IO.Path]::GetFullPath([string]$metadata.expected_cidata_iso) -cne [IO.Path]::GetFullPath($isoPath)) {
    throw "CIDATA_METADATA_MISMATCH: refusing cleanup outside the persisted expected ISO"
}
$drives = @(Get-VMDvdDrive -VMName $name -ErrorAction SilentlyContinue | Where-Object Path -eq $isoPath)
foreach ($drive in $drives) { Remove-VMDvdDrive -VMName $name -ControllerNumber $drive.ControllerNumber -ControllerLocation $drive.ControllerLocation }
$metadata.cleanup_phase = %s
Set-VM -Name $name -Notes ($prefix + ($metadata | ConvertTo-Json -Depth 6 -Compress))
$deleted = $false
if (Test-Path -LiteralPath $isoPath -PathType Leaf) {
    Remove-Item -LiteralPath $isoPath -Force -ErrorAction Stop
    $deleted = $true
}
$metadata.cleanup_phase = %s
Set-VM -Name $name -Notes ($prefix + ($metadata | ConvertTo-Json -Depth 6 -Compress))
$ownershipPath = Join-Path (Split-Path -Parent $isoPath) %s
if (Test-Path -LiteralPath $ownershipPath -PathType Leaf) {
    Remove-Item -LiteralPath $ownershipPath -Force -ErrorAction Stop
}
[pscustomobject]@{
    status='clean'; detached=$drives.Count; deleted_iso=$deleted
    expected_iso=$isoPath; cleanup_phase=[string]$metadata.cleanup_phase
    registered=[bool]$metadata.registered
} | ConvertTo-Json -Compress
`, PSLit(name), PSLit(isoPath), PSLit(LinuxVMMetadataPrefix),
		PSLit(LinuxVMCleanupDetached), PSLit(LinuxVMCleanupComplete), PSLit(LinuxVMOwnershipFile))
	return wrapTagged(body), nil
}

type CleanupOwnedLinuxVMArtifactsParams struct {
	ISOPath   string
	ChildVHDX string
	DeleteISO bool
	DeleteVHD bool
}

func BuildCleanupOwnedLinuxVMArtifactsScript(p CleanupOwnedLinuxVMArtifactsParams) (string, error) {
	if !p.DeleteISO && !p.DeleteVHD {
		return "", nil
	}
	if p.DeleteISO && strings.TrimSpace(p.ISOPath) == "" || p.DeleteVHD && strings.TrimSpace(p.ChildVHDX) == "" {
		return "", fmt.Errorf("owned artifact cleanup path is required")
	}
	body := fmt.Sprintf(`
$isoPath = %s
$childVHDX = %s
$deleteISO = %s
$deleteVHD = %s
$deleted = @()
$retained = @()
if ($deleteISO -and (Test-Path -LiteralPath $isoPath -PathType Leaf)) {
    $isoInUse = @(Get-VM | Get-VMDvdDrive -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -and [IO.Path]::GetFullPath([string]$_.Path).Equals([IO.Path]::GetFullPath($isoPath), [StringComparison]::OrdinalIgnoreCase)
    }).Count -gt 0
    if (-not $isoInUse) {
        Remove-Item -LiteralPath $isoPath -Force
        $deleted += $isoPath
    } else {
        $retained += $isoPath
    }
}
if ($deleteVHD -and (Test-Path -LiteralPath $childVHDX -PathType Leaf)) {
    $vhdInUse = @(Get-VM | Get-VMHardDiskDrive -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -and [IO.Path]::GetFullPath([string]$_.Path).Equals([IO.Path]::GetFullPath($childVHDX), [StringComparison]::OrdinalIgnoreCase)
    }).Count -gt 0
    if (-not $vhdInUse) {
        Remove-Item -LiteralPath $childVHDX -Force
        $deleted += $childVHDX
    } else {
        $retained += $childVHDX
    }
}
[pscustomobject]@{ status='owned_artifacts_cleaned'; deleted=$deleted; retained_referenced=$retained } | ConvertTo-Json -Compress
`, PSLit(p.ISOPath), PSLit(p.ChildVHDX), PSBool(p.DeleteISO), PSBool(p.DeleteVHD))
	return wrapTagged(body), nil
}
