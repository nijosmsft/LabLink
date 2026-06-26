package unattend

import (
	"fmt"
	"strings"

	"github.com/nijosmsft/lablink/internal/hyperv"
)

// InjectionMethod selects how the answer file reaches the guest.
type InjectionMethod string

const (
	// MethodMountVHD (default) offline-services a sysprepped/generalized OS
	// disk by mounting it and dropping the answer file into \Windows\Panther.
	MethodMountVHD InjectionMethod = "mount-vhd"
	// MethodAutoUnattendISO builds a tiny ISO with Autounattend.xml at its root
	// for a CLEAN INSTALL from a Windows ISO. Deferred in Phase 1 (see
	// BuildIsoInjectScript).
	MethodAutoUnattendISO InjectionMethod = "autounattend-iso"
)

// MountInjectParams configures BuildMountInjectScript (Method A).
type MountInjectParams struct {
	// VHDPath is the OS disk to inject into. When BaseVHD is set this is the
	// path of the differencing CHILD to create (the base is never mutated).
	VHDPath string
	// BaseVHD, when set, is a shared golden/sysprepped base. The tool creates a
	// differencing child at VHDPath and injects into the child only — it never
	// writes into the base (network reviewer finding #3).
	BaseVHD string
	// UnattendRemote is the path on the TARGET where the rendered answer file
	// was staged (pushed) before injection.
	UnattendRemote string
	// FirstBootRemote, when set, is the path on the target where the first-boot
	// PowerShell script was staged; it is copied to \Windows\Setup\Scripts.
	FirstBootRemote string
}

// BuildMountInjectScript builds the Method A injection script. Key safety
// properties (network reviewer findings #3):
//   - never injects into a shared base VHD: creates a differencing child first
//     when BaseVHD is set;
//   - locates the Windows volume by CONTENT (Windows\System32\Config\SYSTEM),
//     not by drive letter;
//   - assigns a temporary drive letter when a partition has none and removes it
//     afterwards;
//   - tracks and dismounts ONLY the VHD this tool mounted, in a finally block.
func BuildMountInjectScript(p MountInjectParams) (string, error) {
	if strings.TrimSpace(p.VHDPath) == "" {
		return "", fmt.Errorf("vhd_path is required for mount-vhd injection")
	}
	if strings.TrimSpace(p.UnattendRemote) == "" {
		return "", fmt.Errorf("staged unattend path is required")
	}

	var b strings.Builder
	b.WriteString(hyperv.PreflightScript())
	fmt.Fprintf(&b, "$vhdPath = %s\n", hyperv.PSLit(p.VHDPath))
	fmt.Fprintf(&b, "$baseVhd = %s\n", hyperv.PSLit(p.BaseVHD))
	fmt.Fprintf(&b, "$unattendSrc = %s\n", hyperv.PSLit(p.UnattendRemote))
	fmt.Fprintf(&b, "$firstBootSrc = %s\n", hyperv.PSLit(p.FirstBootRemote))

	b.WriteString(`
$mountedByUs = $false
$assignedLetters = @()
$winDrive = $null
try {
    if (-not (Test-Path $unattendSrc)) { throw "UNATTEND_NOT_STAGED: '$unattendSrc' not found on target" }

    if ($baseVhd) {
        if (-not (Test-Path $baseVhd)) { throw "BASE_VHD_NOT_FOUND: '$baseVhd' not found" }
        if (Test-Path $vhdPath) { throw "VHD_EXISTS: differencing child '$vhdPath' already exists" }
        $parent = Split-Path -Parent $vhdPath
        if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
        # Never inject into the shared base — create a differencing child.
        New-VHD -Path $vhdPath -ParentPath $baseVhd -Differencing | Out-Null
    }
    if (-not (Test-Path $vhdPath)) { throw "VHD_NOT_FOUND: '$vhdPath' not found" }

    # Only mount if not already mounted (so we only dismount what we mounted).
    $disk = Get-VHD -Path $vhdPath | ForEach-Object { if ($_.DiskNumber -ne $null -and $_.DiskNumber -ge 0) { Get-Disk -Number $_.DiskNumber -ErrorAction SilentlyContinue } }
    if (-not $disk) {
        $disk = Mount-VHD -Path $vhdPath -Passthrough | Get-Disk
        $mountedByUs = $true
    }

    # Locate the Windows volume by CONTENT, assigning temp drive letters when a
    # partition has none.
    foreach ($part in (Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue)) {
        $letter = $part.DriveLetter
        if (-not $letter) {
            try {
                $part | Add-PartitionAccessPath -AssignDriveLetter -ErrorAction Stop
                $part = Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber
                $letter = $part.DriveLetter
                if ($letter) { $assignedLetters += ,@($part.DiskNumber, $part.PartitionNumber, $letter) }
            } catch { continue }
        }
        if (-not $letter) { continue }
        if (Test-Path "${letter}:\Windows\System32\Config\SYSTEM") {
            $winDrive = "${letter}:"
            break
        }
    }
    if (-not $winDrive) { throw "WINDOWS_VOLUME_NOT_FOUND: no partition contains Windows\System32\Config\SYSTEM" }

    New-Item -ItemType Directory -Force -Path "$winDrive\Windows\Panther" | Out-Null
    Copy-Item $unattendSrc "$winDrive\Windows\Panther\unattend.xml" -Force
    if ($firstBootSrc -and (Test-Path $firstBootSrc)) {
        New-Item -ItemType Directory -Force -Path "$winDrive\Windows\Setup\Scripts" | Out-Null
        Copy-Item $firstBootSrc "$winDrive\Windows\Setup\Scripts\FirstBoot.ps1" -Force
    }

    # Scrub the staged (cleartext-password) copies from the target host now that
    # they live inside the VHD; the on-VHD copy is consumed+scrubbed by Windows
    # during specialize/first-logon.
    Remove-Item $unattendSrc -Force -ErrorAction SilentlyContinue
    if ($firstBootSrc) { Remove-Item $firstBootSrc -Force -ErrorAction SilentlyContinue }

    [pscustomobject]@{
        injected_to    = "$winDrive\Windows\Panther\unattend.xml"
        windows_volume = $winDrive
        vhd_path       = $vhdPath
        differencing   = [bool]$baseVhd
        method         = 'mount-vhd'
        action         = 'injected'
    } | ConvertTo-Json -Depth 4
}
finally {
    # Remove only drive letters we assigned.
    foreach ($a in $assignedLetters) {
        try { Remove-PartitionAccessPath -DiskNumber $a[0] -PartitionNumber $a[1] -AccessPath ($a[2] + ':\') -ErrorAction SilentlyContinue } catch {}
    }
    # Dismount only if we mounted it.
    if ($mountedByUs) {
        try { Dismount-VHD -Path $vhdPath -ErrorAction SilentlyContinue } catch {}
    }
}
`)
	return hyperv.WrapTagged(b.String()), nil
}

// BuildIsoInjectScript is the Method B (clean install) entry point. A correct
// clean-install answer file additionally needs a full windowsPE pass
// (UEFI/GPT partitioning, image selection, install target) plus a vetted ISO
// writer (oscdimg or a bundled fallback). That is DEFERRED in Phase 1: this
// returns a tagged, non-destructive error rather than shipping a half
// clean-install path (network reviewer finding #4).
func BuildIsoInjectScript(_ MountInjectParams) (string, error) {
	return "", fmt.Errorf("METHOD_B_DEFERRED: autounattend-iso clean-install injection is not implemented in Phase 1 (needs windowsPE partitioning/image-selection + a vetted oscdimg/bundled ISO writer). Use injection_method=mount-vhd with a sysprepped base VHD")
}
