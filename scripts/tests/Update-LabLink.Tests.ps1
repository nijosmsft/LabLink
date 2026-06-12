<#
.SYNOPSIS
    Self-tests for the Resolve-DestinationDir logic in Update-LabLink.ps1.

.DESCRIPTION
    Bare-PowerShell assertions; no Pester required.  Dot-sources Update-LabLink.ps1
    to load its functions, then calls the real Resolve-DestinationDir directly.
    The main flow is guarded by an InvocationName check in Update-LabLink.ps1 so
    dot-sourcing is safe (the main body does not execute).

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

# ---------------------------------------------------------------------------
# Dot-source the production script to import its functions.
# The InvocationName guard ensures the main body does not run.
# ---------------------------------------------------------------------------
$productionScript = Join-Path $PSScriptRoot ".." "Update-LabLink.ps1"
. $productionScript

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

# Ensure $DestinationDir (loaded from the dot-sourced param block) is empty
# so the first branch of Resolve-DestinationDir never fires during tests.
$DestinationDir = ''

# ---------------------------------------------------------------------------
# Test 1: script co-located with the agent binary
# ---------------------------------------------------------------------------

$dir1 = New-TestDir 'test1-colocated'
New-StubExe -Dir $dir1 | Out-Null

Assert-Equal $dir1 (Resolve-DestinationDir -ScriptRoot $dir1) `
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

Assert-Equal $dir2Bin (Resolve-DestinationDir -ScriptRoot $dir2Scripts) `
    'Resolve: sibling bin/ directory when script is in scripts/'

# ---------------------------------------------------------------------------
# Test 3: neither co-located nor sibling bin/ present -> falls through (null or default)
# ---------------------------------------------------------------------------

$dir3 = New-TestDir 'test3-empty'
# Override $McpConfigPath so the mcp-config branch finds nothing in the temp dir.
$savedMcpConfigPath = $McpConfigPath
$McpConfigPath = Join-Path $dir3 'no-mcp-config.json'
$result3 = Resolve-DestinationDir -ScriptRoot $dir3
# Should fall through to $DefaultInstall (non-null); just verify it is not the temp dir.
$McpConfigPath = $savedMcpConfigPath
if ($result3 -eq $null -or $result3 -eq $dir3 -or $result3 -eq $dir2Bin) {
    Write-Host "FAIL: Resolve: falls through to default when no binary found" -ForegroundColor Red
    Write-Host "  Got: $result3"
    $script:ErrorCount++
} else {
    Write-Host "PASS: Resolve: falls through to default when no binary found" -ForegroundColor Green
}

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

Assert-Equal $dir4Scripts (Resolve-DestinationDir -ScriptRoot $dir4Scripts) `
    'Resolve: co-located takes precedence over sibling bin/'

# ---------------------------------------------------------------------------
# Test 5: service-name branch -- quoted ImagePath
# Verify: (a) CIM filter uses the correct service name, (b) exe dir is returned.
# ---------------------------------------------------------------------------

$dir5 = New-TestDir 'test5-service-quoted'
New-StubExe -Dir $dir5 | Out-Null

$script:lastCimFilter = $null

# Shadow Get-CimInstance for this test only.
function Get-CimInstance {
    param([string]$ClassName, [string]$Filter)
    $script:lastCimFilter = $Filter
    return [pscustomobject]@{ PathName = "`"$dir5\lablink-agent.exe`" --listen :9091" }
}

# Use a root that has no agent so the co-located/sibling checks fall through.
$dir5Root = New-TestDir 'test5-noagent'
$result5 = Resolve-DestinationDir -ScriptRoot $dir5Root

Remove-Item Function:\Get-CimInstance -ErrorAction SilentlyContinue

Assert-Equal $dir5 $result5 `
    'Resolve: service ImagePath (quoted) returns correct directory'

$expectedFilter = "Name='$ServiceName'"
Assert-Equal $expectedFilter $script:lastCimFilter `
    "Resolve: CIM filter uses correct service name '$ServiceName'"

# ---------------------------------------------------------------------------
# Test 6: service-name branch -- unquoted ImagePath
# ---------------------------------------------------------------------------

$dir6 = New-TestDir 'test6-service-unquoted'
New-StubExe -Dir $dir6 | Out-Null

$script:lastCimFilter = $null

function Get-CimInstance {
    param([string]$ClassName, [string]$Filter)
    $script:lastCimFilter = $Filter
    return [pscustomobject]@{ PathName = "$dir6\lablink-agent.exe --listen :9091" }
}

$dir6Root = New-TestDir 'test6-noagent'
$result6 = Resolve-DestinationDir -ScriptRoot $dir6Root

Remove-Item Function:\Get-CimInstance -ErrorAction SilentlyContinue

Assert-Equal $dir6 $result6 `
    'Resolve: service ImagePath (unquoted, no spaces in path) returns correct directory'

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
Write-Host "All $( 6 ) tests passed." -ForegroundColor Green
