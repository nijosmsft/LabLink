package hyperv

import (
	"fmt"
	"strings"
)

type DeleteVMParams struct {
	Name          string
	ManagedRoot   string
	DryRun        bool
	ForceStop     bool
	DeleteStorage bool
}

// BuildDeleteVMScript builds a dry-run-first VM deletion script. Storage
// deletion is restricted to the VM's own configuration directory beneath the
// approved managed root. Differencing parent paths are reported but never
// deleted.
func BuildDeleteVMScript(p DeleteVMParams) (string, error) {
	if strings.TrimSpace(p.Name) == "" {
		return "", fmt.Errorf("vm name is required")
	}
	if p.DeleteStorage && strings.TrimSpace(p.ManagedRoot) == "" {
		return "", fmt.Errorf("managed_root is required when delete_storage=true")
	}

	var b strings.Builder
	b.WriteString(PreflightScript())
	fmt.Fprintf(&b, "$name = %s\n", PSLit(p.Name))
	fmt.Fprintf(&b, "$managedRoot = %s\n", PSLit(p.ManagedRoot))
	fmt.Fprintf(&b, "$dryRun = %s\n", PSBool(p.DryRun))
	fmt.Fprintf(&b, "$forceStop = %s\n", PSBool(p.ForceStop))
	fmt.Fprintf(&b, "$deleteStorage = %s\n", PSBool(p.DeleteStorage))
	b.WriteString(`
$vm = Get-VM -Name $name -ErrorAction SilentlyContinue
if (-not $vm) { throw "VM_NOT_FOUND: VM '$name' does not exist" }

function Get-CanonicalPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    return [IO.Path]::GetFullPath($Path).TrimEnd('\')
}
function Test-PathWithin([string]$Child, [string]$Parent) {
    $childPath = Get-CanonicalPath $Child
    $parentPath = Get-CanonicalPath $Parent
    if (-not $childPath -or -not $parentPath) { return $false }
    return $childPath.StartsWith($parentPath + '\', [StringComparison]::OrdinalIgnoreCase)
}
function Test-PathAtOrWithin([string]$Child, [string]$Parent) {
    $childPath = Get-CanonicalPath $Child
    $parentPath = Get-CanonicalPath $Parent
    return $childPath.Equals($parentPath, [StringComparison]::OrdinalIgnoreCase) -or
        $childPath.StartsWith($parentPath + '\', [StringComparison]::OrdinalIgnoreCase)
}

$vmPath = Get-CanonicalPath $vm.Path
$rootPath = Get-CanonicalPath $managedRoot
$vmStoragePath = Get-CanonicalPath (Join-Path $rootPath $name)
$drives = @($vm | Get-VMHardDiskDrive -ErrorAction SilentlyContinue)
$disks = @($drives | ForEach-Object {
    $vhd = Get-VHD -Path $_.Path -ErrorAction SilentlyContinue
    [pscustomobject]@{
        path = Get-CanonicalPath $_.Path
        type = if ($vhd) { [string]$vhd.VhdType } else { 'Unknown' }
        parent_path = if ($vhd) { Get-CanonicalPath $vhd.ParentPath } else { '' }
        storage_deletable = [bool](
            $deleteStorage -and
            (Test-PathWithin $_.Path $rootPath) -and
            (Test-PathAtOrWithin $_.Path $vmStoragePath)
        )
    }
})
$checkpoints = @($vm | Get-VMSnapshot -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
$storageSafe = [bool]((-not $deleteStorage) -or (
    (Test-PathWithin $vmStoragePath $rootPath) -and
    (Test-PathAtOrWithin $vmPath $vmStoragePath) -and
    -not ($disks | Where-Object { -not $_.storage_deletable })
))

$summary = [ordered]@{
    name = $vm.Name
    state = [string]$vm.State
    vm_path = $vmPath
    vm_storage_path = $vmStoragePath
    managed_root = $rootPath
    disks = $disks
    checkpoints = $checkpoints
    dry_run = $dryRun
    force_stop = $forceStop
    delete_storage = $deleteStorage
    storage_safe = $storageSafe
    action = if ($dryRun) { 'would_delete' } else { 'deleted' }
}

if ($dryRun) {
    [pscustomobject]$summary | ConvertTo-Json -Depth 8
    return
}
if ($vm.State -ne 'Off') {
    if (-not $forceStop) {
        throw "VM_RUNNING: VM '$name' is $($vm.State); pass force_stop=true to turn it off"
    }
    Stop-VM -Name $name -TurnOff -Force
}
if ($deleteStorage -and -not $storageSafe) {
    throw "UNSAFE_STORAGE_PATH: VM config and every deletable VHD must be below managed_root and the VM's own config directory"
}

Get-VMSnapshot -VMName $name -ErrorAction SilentlyContinue | Remove-VMSnapshot -Confirm:$false
Remove-VM -Name $name -Force

$deleted = @()
if ($deleteStorage) {
    foreach ($disk in $disks) {
        # parent_path is informational only and is never considered for deletion.
        if ($disk.storage_deletable -and (Test-Path -LiteralPath $disk.path)) {
            Remove-Item -LiteralPath $disk.path -Force
            $deleted += $disk.path
        }
    }
    if ((Test-PathWithin $vmStoragePath $rootPath) -and (Test-Path -LiteralPath $vmStoragePath)) {
        Remove-Item -LiteralPath $vmStoragePath -Recurse -Force
        $deleted += $vmStoragePath
    }
}
$summary.deleted_paths = $deleted
[pscustomobject]$summary | ConvertTo-Json -Depth 8
`)
	return wrapTagged(b.String()), nil
}
