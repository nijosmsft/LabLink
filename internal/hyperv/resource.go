package hyperv

import (
	"fmt"
	"strings"
)

type ResourceSafetyParams struct {
	MemoryMB                  float64
	StoragePath               string
	ReserveVHDPath            string
	ReserveRemainingGrowth    bool
	StorageReserveBytes       int64
	MinHostReservePct         float64
	AllowHostResourcePressure bool
}

// ResourceSafetyScript returns a PowerShell fragment that populates
// $resourceSafety and throws before mutation when projected free memory or
// target-volume capacity would fall below the configured reserve.
func ResourceSafetyScript(p ResourceSafetyParams) (string, error) {
	pct := p.MinHostReservePct
	if pct <= 0 {
		pct = 10
	}
	if pct >= 100 {
		return "", fmt.Errorf("min_host_reserve_pct must be below 100")
	}
	if strings.TrimSpace(p.StoragePath) == "" {
		return "", fmt.Errorf("storage path is required for resource safety")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "$resourceMemBytes = %s\n", mbBytes(p.MemoryMB))
	fmt.Fprintf(&b, "$resourceStoragePath = %s\n", PSLit(p.StoragePath))
	fmt.Fprintf(&b, "$resourceReserveVhd = %s\n", PSLit(p.ReserveVHDPath))
	fmt.Fprintf(&b, "$resourceReserveRemainingGrowth = %s\n", PSBool(p.ReserveRemainingGrowth))
	fmt.Fprintf(&b, "$resourceStorageReserveBytes = %d\n", p.StorageReserveBytes)
	fmt.Fprintf(&b, "$resourceMinPct = %s\n", psNumber(pct))
	fmt.Fprintf(&b, "$allowHostResourcePressure = %s\n", PSBool(p.AllowHostResourcePressure))
	b.WriteString(`
$computer = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$totalMemory = [double]$computer.TotalPhysicalMemory
$availableMemory = [double]$os.FreePhysicalMemory * 1KB
$projectedMemory = $availableMemory - $resourceMemBytes
$minimumMemory = $totalMemory * ($resourceMinPct / 100.0)

$storageParent = Split-Path -Parent $resourceStoragePath
if (-not $storageParent) { $storageParent = $resourceStoragePath }
$storageQualifier = (Split-Path -Qualifier $storageParent) -replace ':',''
if (-not $storageQualifier) { throw "RESOURCE_VOLUME_UNKNOWN: cannot resolve target volume for '$resourceStoragePath'" }
$volume = Get-Volume -DriveLetter $storageQualifier -ErrorAction SilentlyContinue
if (-not $volume) { throw "RESOURCE_VOLUME_NOT_FOUND: volume '$storageQualifier' for '$resourceStoragePath' was not found" }

if ($resourceReserveVhd) {
    if (-not (Test-Path -LiteralPath $resourceReserveVhd)) {
        throw "RESOURCE_VHD_NOT_FOUND: '$resourceReserveVhd' was not found"
    }
    $reserveVhd = Get-VHD -Path $resourceReserveVhd
    $vhdReserve = if ($resourceReserveRemainingGrowth) {
        [math]::Max(0, [double]$reserveVhd.Size - [double]$reserveVhd.FileSize)
    } else {
        [double]$reserveVhd.Size
    }
    $resourceStorageReserveBytes = [math]::Max([double]$resourceStorageReserveBytes, $vhdReserve)
}
$projectedStorage = [double]$volume.SizeRemaining - [double]$resourceStorageReserveBytes
$minimumStorage = [double]$volume.Size * ($resourceMinPct / 100.0)

$memorySafe = $projectedMemory -ge $minimumMemory
$storageSafe = $projectedStorage -ge $minimumStorage
$resourceSafety = [ordered]@{
    minimum_free_pct = $resourceMinPct
    override = [bool]$allowHostResourcePressure
    memory = [ordered]@{
        total_gb = [math]::Round($totalMemory / 1GB, 2)
        available_before_gb = [math]::Round($availableMemory / 1GB, 2)
        requested_startup_gb = [math]::Round($resourceMemBytes / 1GB, 2)
        projected_free_gb = [math]::Round($projectedMemory / 1GB, 2)
        minimum_free_gb = [math]::Round($minimumMemory / 1GB, 2)
        safe = [bool]$memorySafe
    }
    storage = [ordered]@{
        drive = $storageQualifier
        size_gb = [math]::Round([double]$volume.Size / 1GB, 2)
        free_before_gb = [math]::Round([double]$volume.SizeRemaining / 1GB, 2)
        reserved_growth_gb = [math]::Round([double]$resourceStorageReserveBytes / 1GB, 2)
        projected_free_gb = [math]::Round($projectedStorage / 1GB, 2)
        minimum_free_gb = [math]::Round($minimumStorage / 1GB, 2)
        safe = [bool]$storageSafe
    }
    safe = [bool]($memorySafe -and $storageSafe)
}
if (-not $allowHostResourcePressure) {
    if (-not $memorySafe) {
        throw "HOST_MEMORY_RESERVE: projected free memory $([math]::Round($projectedMemory/1GB,2)) GB is below the $resourceMinPct% reserve ($([math]::Round($minimumMemory/1GB,2)) GB); pass allow_host_resource_pressure=true to override"
    }
    if (-not $storageSafe) {
        throw "HOST_STORAGE_RESERVE: projected free space on ${storageQualifier}: $([math]::Round($projectedStorage/1GB,2)) GB is below the $resourceMinPct% reserve ($([math]::Round($minimumStorage/1GB,2)) GB); pass allow_host_resource_pressure=true to override"
    }
}
`)
	return b.String(), nil
}

func BuildResourceSafetyScript(p ResourceSafetyParams) (string, error) {
	fragment, err := ResourceSafetyScript(p)
	if err != nil {
		return "", err
	}
	return wrapTagged(fragment + "\n[pscustomobject]$resourceSafety | ConvertTo-Json -Depth 8\n"), nil
}

func psNumber(value float64) string {
	return fmt.Sprintf("%.4f", value)
}
