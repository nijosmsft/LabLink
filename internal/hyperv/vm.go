package hyperv

import (
	"fmt"
	"strings"
)

// CreateVMParams configures BuildCreateVMScript for a Gen2 Windows VM.
type CreateVMParams struct {
	Name       string
	VMLocation string // -Path for VM config; empty unless UseHostDefaults

	// Exactly one of VHDPath (attach existing) or NewVHDPath (+NewVHDSizeGB).
	VHDPath      string
	NewVHDPath   string
	NewVHDSizeGB float64

	MemoryMB float64 // startup memory (default applied by caller)

	// Dynamic-memory policy. When DynamicMemory is true, Min/Max/Buffer apply.
	DynamicMemory       bool
	DynamicMinMB        float64
	DynamicMaxMB        float64
	DynamicBufferPct    float64
	CPUCount            float64
	VSwitch             string
	ISOPath             string
	SecureBoot          bool
	SecureBootTemplate  string // default MicrosoftWindows
	UseHostDefaults     bool   // permit Hyper-V default VM location when VMLocation empty
	RequiredFreeSpaceGB float64
}

// BuildCreateVMScript builds the create_vm mutation script with the network
// reviewer's completeness items: Gen2 secure boot template, deterministic DVD
// selection by ISO path, dynamic-memory min/max/buffer, path + free-space
// validation, VM-off and VHD-not-in-use checks.
func BuildCreateVMScript(p CreateVMParams) (string, error) {
	if strings.TrimSpace(p.Name) == "" {
		return "", fmt.Errorf("vm name is required")
	}
	hasExisting := strings.TrimSpace(p.VHDPath) != ""
	hasNew := strings.TrimSpace(p.NewVHDPath) != ""
	if hasExisting == hasNew {
		return "", fmt.Errorf("provide exactly one of vhd_path or new_vhd_path")
	}
	if hasNew && p.NewVHDSizeGB <= 0 {
		return "", fmt.Errorf("new_vhd_size_gb must be > 0 when new_vhd_path is set")
	}
	// OQ-6: require explicit VM location on shared/remote hosts unless the
	// caller opts into the Hyper-V host default.
	if strings.TrimSpace(p.VMLocation) == "" && !p.UseHostDefaults {
		return "", fmt.Errorf("vm_location is required unless use_host_defaults=true (avoids surprising disk placement on shared lab hosts)")
	}
	sbTemplate := strings.TrimSpace(p.SecureBootTemplate)
	if sbTemplate == "" {
		sbTemplate = "MicrosoftWindows"
	}
	cpu := p.CPUCount
	if cpu <= 0 {
		cpu = 2
	}
	mem := p.MemoryMB
	if mem <= 0 {
		mem = 4096
	}

	var b strings.Builder
	b.WriteString(PreflightScript())
	fmt.Fprintf(&b, "$name = %s\n", PSLit(p.Name))
	fmt.Fprintf(&b, "$vmLocation = %s\n", PSLit(p.VMLocation))
	fmt.Fprintf(&b, "$vhdPath = %s\n", PSLit(p.VHDPath))
	fmt.Fprintf(&b, "$newVhdPath = %s\n", PSLit(p.NewVHDPath))
	fmt.Fprintf(&b, "$newVhdSizeBytes = %s\n", gbBytes(p.NewVHDSizeGB))
	fmt.Fprintf(&b, "$memStartupBytes = %s\n", mbBytes(mem))
	fmt.Fprintf(&b, "$dynamicMemory = %s\n", PSBool(p.DynamicMemory))
	fmt.Fprintf(&b, "$dynMinBytes = %s\n", mbBytes(p.DynamicMinMB))
	fmt.Fprintf(&b, "$dynMaxBytes = %s\n", mbBytes(p.DynamicMaxMB))
	fmt.Fprintf(&b, "$dynBufferPct = %d\n", int64(p.DynamicBufferPct))
	fmt.Fprintf(&b, "$cpuCount = %d\n", int64(cpu))
	fmt.Fprintf(&b, "$vswitch = %s\n", PSLit(p.VSwitch))
	fmt.Fprintf(&b, "$isoPath = %s\n", PSLit(p.ISOPath))
	fmt.Fprintf(&b, "$secureBoot = %s\n", PSBool(p.SecureBoot))
	fmt.Fprintf(&b, "$secureBootTemplate = %s\n", PSLit(sbTemplate))
	fmt.Fprintf(&b, "$requiredFreeGB = %d\n", int64(p.RequiredFreeSpaceGB))

	b.WriteString(`
# Idempotency: refuse to clobber an existing VM.
if (Get-VM -Name $name -ErrorAction SilentlyContinue) {
    throw "VM_EXISTS: VM '$name' already exists (no silent clobber)"
}

# Validate paths and free space before mutating.
if ($vmLocation) {
    if (-not (Test-Path $vmLocation)) { New-Item -ItemType Directory -Force -Path $vmLocation | Out-Null }
}
if ($vhdPath) {
    if (-not (Test-Path $vhdPath)) { throw "VHD_NOT_FOUND: existing VHD '$vhdPath' not found" }
    # Ensure the VHD is not already attached/in use by another VM.
    $inUse = Get-VM | Get-VMHardDiskDrive -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -eq $vhdPath }
    if ($inUse) { throw "VHD_IN_USE: VHD '$vhdPath' is already attached to a VM" }
} else {
    $parent = Split-Path -Parent $newVhdPath
    if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    if (Test-Path $newVhdPath) { throw "VHD_EXISTS: new VHD path '$newVhdPath' already exists" }
    # Free-space check on the new VHD's target volume.
    $targetForSpace = if ($parent) { $parent } else { (Get-Location).Path }
    $qualifier = (Split-Path -Qualifier $targetForSpace) -replace ':',''
    if ($qualifier) {
        $vol = Get-Volume -DriveLetter $qualifier -ErrorAction SilentlyContinue
        $needBytes = [math]::Max($newVhdSizeBytes, ($requiredFreeGB * 1GB))
        if ($vol -and $vol.SizeRemaining -lt $needBytes) {
            throw "INSUFFICIENT_SPACE: volume ${qualifier}: has $([math]::Round($vol.SizeRemaining/1GB,1)) GB free, need $([math]::Round($needBytes/1GB,1)) GB"
        }
    }
}
if ($isoPath -and -not (Test-Path $isoPath)) { throw "ISO_NOT_FOUND: install ISO '$isoPath' not found" }
if ($vswitch -and -not (Get-VMSwitch -Name $vswitch -ErrorAction SilentlyContinue)) {
    throw "VSWITCH_NOT_FOUND: vSwitch '$vswitch' not found (create it first or pick another)"
}

$vmArgs = @{ Name = $name; Generation = 2; MemoryStartupBytes = $memStartupBytes }
if ($vmLocation) { $vmArgs.Path = $vmLocation }
if ($vhdPath)    { $vmArgs.VHDPath = $vhdPath }
else             { $vmArgs.NewVHDPath = $newVhdPath; $vmArgs.NewVHDSizeBytes = $newVhdSizeBytes }
if ($vswitch)    { $vmArgs.SwitchName = $vswitch }
New-VM @vmArgs | Out-Null

Set-VMProcessor -VMName $name -Count $cpuCount

if ($dynamicMemory) {
    $memArgs = @{ VMName = $name; DynamicMemoryEnabled = $true; StartupBytes = $memStartupBytes }
    if ($dynMinBytes -gt 0) { $memArgs.MinimumBytes = $dynMinBytes }
    if ($dynMaxBytes -gt 0) { $memArgs.MaximumBytes = $dynMaxBytes }
    if ($dynBufferPct -gt 0) { $memArgs.Buffer = $dynBufferPct }
    Set-VMMemory @memArgs
} else {
    Set-VMMemory -VMName $name -DynamicMemoryEnabled $false -StartupBytes $memStartupBytes
}

# Gen2 secure boot with explicit template.
if ($secureBoot) {
    Set-VMFirmware -VMName $name -EnableSecureBoot On -SecureBootTemplate $secureBootTemplate
} else {
    Set-VMFirmware -VMName $name -EnableSecureBoot Off
}

# Attach the install ISO and deterministically set it as first boot device by
# matching the DVD drive that carries THIS ISO path (not just "the DVD drive").
if ($isoPath) {
    Add-VMDvdDrive -VMName $name -Path $isoPath
    $dvd = Get-VMDvdDrive -VMName $name | Where-Object { $_.Path -eq $isoPath } | Select-Object -First 1
    if (-not $dvd) { throw "DVD_ATTACH_FAILED: could not locate DVD drive for ISO '$isoPath'" }
    Set-VMFirmware -VMName $name -FirstBootDevice $dvd
}

$vm = Get-VM -Name $name
$disk = ($vm | Get-VMHardDiskDrive | Select-Object -First 1).Path
[pscustomobject]@{
    target     = 'self'
    name       = $vm.Name
    generation = $vm.Generation
    state      = "$($vm.State)"
    memory_mb  = [int]($memStartupBytes/1MB)
    cpu_count  = $cpuCount
    vswitch    = $vswitch
    vhd_path   = $disk
    secure_boot = [bool]$secureBoot
    action     = 'created'
} | ConvertTo-Json -Depth 4
`)
	return wrapTagged(b.String()), nil
}
