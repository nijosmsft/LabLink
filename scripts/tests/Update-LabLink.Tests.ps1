<#
.SYNOPSIS
    Self-tests for the Resolve-DestinationDir logic in Update-LabLink.ps1.

.DESCRIPTION
    Bare-PowerShell assertions; no Pester required.  The resolution logic is
    tested inline rather than by dot-sourcing Update-LabLink.ps1, because
    dot-sourcing that script would execute its main body.

    Mirrors the Resolve-DestinationDir function in Update-LabLink.ps1 (the
    co-located and sibling-bin checks); keep these two in sync.

.NOTES
    Run from the repo root:
        pwsh -NoProfile -File scripts\tests\Update-LabLink.Tests.ps1
#>

$ErrorCount = 0

function Assert-Equal {
    param(
        [string]$Expected,
        [string]$Actual,
        [string]$TestName
    )
    if ($Expected -ne $Actual) {
        Write-Host "FAIL: $TestName" -ForegroundColor Red
        Write-Host "  Expected: $Expected"
        Write-Host "  Actual:   $Actual"
        $script:ErrorCount++
    } else {
        Write-Host "PASS: $TestName" -ForegroundColor Green
    }
}

# Inline the co-located + sibling-bin resolution candidates from
# Resolve-DestinationDir in Update-LabLink.ps1.  Accepts an explicit
# $Root so tests can stub $PSScriptRoot without modifying an automatic variable.
function Resolve-ColocatedOrSiblingBin {
    param([string]$Root)

    $colocated = Join-Path $Root 'lablink-agent.exe'
    if (Test-Path $colocated) {
        return $Root
    }
    $siblingBin = Join-Path (Split-Path $Root -Parent) 'bin'
    if (Test-Path (Join-Path $siblingBin 'lablink-agent.exe')) {
        return $siblingBin
    }
    return $null
}

# ---------------------------------------------------------------------------
# Test scaffolding helpers
# ---------------------------------------------------------------------------

$TmpBase = Join-Path $env:TEMP "lablink-dest-tests-$([System.IO.Path]::GetRandomFileName())"

function New-TestDir {
    param([string]$Name)
    $d = Join-Path $TmpBase $Name
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    return $d
}

function New-StubExe {
    param([string]$Dir, [string]$Name = 'lablink-agent.exe')
    $p = Join-Path $Dir $Name
    [System.IO.File]::WriteAllText($p, 'stub')
    return $p
}

# ---------------------------------------------------------------------------
# Test 1: script co-located with the agent binary
# ---------------------------------------------------------------------------

$dir1 = New-TestDir 'test1-colocated'
New-StubExe -Dir $dir1 | Out-Null

Assert-Equal $dir1 (Resolve-ColocatedOrSiblingBin -Root $dir1) `
    'Resolve: co-located binary returns script root'

# ---------------------------------------------------------------------------
# Test 2: script lives in a scripts/ subdir; binaries are in the sibling bin/
# ---------------------------------------------------------------------------

$dir2Root    = New-TestDir 'test2-sibling-parent'
$dir2Scripts = Join-Path $dir2Root 'scripts'
$dir2Bin     = Join-Path $dir2Root 'bin'
New-Item -ItemType Directory -Path $dir2Scripts -Force | Out-Null
New-Item -ItemType Directory -Path $dir2Bin     -Force | Out-Null
New-StubExe -Dir $dir2Bin | Out-Null

Assert-Equal $dir2Bin (Resolve-ColocatedOrSiblingBin -Root $dir2Scripts) `
    'Resolve: sibling bin/ directory when script is in scripts/'

# ---------------------------------------------------------------------------
# Test 3: neither co-located nor sibling bin/ present -> falls through (null)
# ---------------------------------------------------------------------------

$dir3 = New-TestDir 'test3-empty'

Assert-Equal $null (Resolve-ColocatedOrSiblingBin -Root $dir3) `
    'Resolve: returns null when no binary found (falls through to mcp-config / default)'

# ---------------------------------------------------------------------------
# Test 4: co-located check takes precedence over sibling bin/
# ---------------------------------------------------------------------------

$dir4Root    = New-TestDir 'test4-both'
$dir4Scripts = Join-Path $dir4Root 'scripts'
$dir4Bin     = Join-Path $dir4Root 'bin'
New-Item -ItemType Directory -Path $dir4Scripts -Force | Out-Null
New-Item -ItemType Directory -Path $dir4Bin     -Force | Out-Null
New-StubExe -Dir $dir4Scripts | Out-Null   # co-located
New-StubExe -Dir $dir4Bin     | Out-Null   # sibling bin/ also present

Assert-Equal $dir4Scripts (Resolve-ColocatedOrSiblingBin -Root $dir4Scripts) `
    'Resolve: co-located takes precedence over sibling bin/'

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

Remove-Item -Recurse -Force $TmpBase -ErrorAction SilentlyContinue

if ($ErrorCount -gt 0) {
    Write-Host ""
    Write-Host "$ErrorCount test(s) FAILED." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "All $( 4 ) tests passed." -ForegroundColor Green
