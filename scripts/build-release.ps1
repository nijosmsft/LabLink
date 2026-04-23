<#
.SYNOPSIS
    Build LabLink release artifacts and stage them under .\release\.

.DESCRIPTION
    Cross-compiles every binary for the supported platforms, then assembles
    a redistributable zip per (OS, ARCH) under release\, plus a SHA256SUMS
    file. Designed to be called locally and from CI; produces the same
    layout in either case.

    On a fresh dev box the typical use is:

        .\scripts\build-release.ps1 -Version v0.1.0

.PARAMETER Version
    Semver string baked into the binaries via -ldflags. Defaults to "dev".

.PARAMETER OutDir
    Directory to place the assembled artifacts. Defaults to .\release.

.PARAMETER Platforms
    Comma-separated list of OS/ARCH targets. Defaults to
    "windows/amd64,linux/amd64".
#>
[CmdletBinding()]
param(
    [string]$Version = "dev",
    [string]$OutDir  = (Join-Path $PSScriptRoot '..\release'),
    [string]$Platforms = "windows/amd64,linux/amd64"
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

if (Test-Path $OutDir) {
    Remove-Item -Recurse -Force $OutDir
}
New-Item -ItemType Directory -Path $OutDir | Out-Null

# Ldflags inject the version into both binaries and trim the local repo path
# from compiled paths so artifacts are reproducible across machines.
$ldflags = "-s -w " +
           "-X main.serverVersion=$Version " +
           "-X main.agentVersion=$Version"

# (BinaryBaseName, PackageImportPath, IncludeOnPlatforms[])
$binaries = @(
    @{ Name = 'LabLinkServer'; Pkg = './cmd/server';     Targets = @('windows','linux') }
    @{ Name = 'LabLinkAgent';  Pkg = './cmd/agent';      Targets = @('windows','linux') }
    @{ Name = 'LabLinkProbe';  Pkg = './cmd/probe';      Targets = @('windows','linux') }
    @{ Name = 'lablink-ca';    Pkg = './cmd/lablink-ca'; Targets = @('windows','linux') }
)

# Files copied into every release alongside the binaries.
$bundleFiles = @(
    'README.md',
    'LICENSE',
    'SECURITY.md',
    'configs/mcp.example.json',
    'docs/quickstart.md',
    'scripts/bootstrap-operator.ps1',
    'scripts/bootstrap-windows-node.ps1',
    'scripts/install-agent.ps1',
    'scripts/deploy-agent.ps1'
)

function Build-Target {
    param([string]$Os, [string]$Arch, [string]$Stage)

    $binDir = Join-Path $Stage 'bin'
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null

    foreach ($b in $binaries) {
        if ($b.Targets -notcontains $Os) { continue }
        $ext = if ($Os -eq 'windows') { '.exe' } else { '' }
        $out = Join-Path $binDir ("{0}{1}" -f $b.Name, $ext)
        Write-Host "  build $($b.Name) [$Os/$Arch]"
        $env:GOOS   = $Os
        $env:GOARCH = $Arch
        $env:CGO_ENABLED = '0'
        & go build -trimpath -ldflags $ldflags -o $out $b.Pkg
        if ($LASTEXITCODE -ne 0) { throw "go build failed for $($b.Name) [$Os/$Arch]" }
    }
}

function Stage-Bundle {
    param([string]$Stage)

    foreach ($rel in $bundleFiles) {
        $src = Join-Path $repoRoot $rel
        if (-not (Test-Path $src)) {
            Write-Warning "missing bundle file: $rel (skipping)"
            continue
        }
        $dst = Join-Path $Stage $rel
        $dstDir = Split-Path -Parent $dst
        if (-not (Test-Path $dstDir)) { New-Item -ItemType Directory -Path $dstDir -Force | Out-Null }
        Copy-Item -Force $src $dst
    }
}

$sums = @()

foreach ($plat in $Platforms.Split(',')) {
    $plat = $plat.Trim()
    if (-not $plat) { continue }
    $parts = $plat.Split('/')
    if ($parts.Length -ne 2) { throw "invalid platform: $plat" }
    $os   = $parts[0]
    $arch = $parts[1]

    Write-Host "==> $os/$arch"
    $stageRoot = Join-Path $OutDir ".stage-$os-$arch"
    $stage     = Join-Path $stageRoot ("lablink-$Version-$os-$arch")
    if (Test-Path $stageRoot) { Remove-Item -Recurse -Force $stageRoot }
    New-Item -ItemType Directory -Path $stage | Out-Null

    Build-Target -Os $os -Arch $arch -Stage $stage
    Stage-Bundle -Stage $stage

    $zipName = "lablink-$Version-$os-$arch.zip"
    $zipPath = Join-Path $OutDir $zipName
    if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath
    Write-Host "  packaged $zipName"

    $hash = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLower()
    $sums += "$hash  $zipName"

    Remove-Item -Recurse -Force $stageRoot
}

$sumsFile = Join-Path $OutDir 'SHA256SUMS.txt'
$sums | Set-Content -Encoding ASCII $sumsFile
Write-Host ""
Write-Host "Release artifacts in ${OutDir}:" -ForegroundColor Green
Get-ChildItem $OutDir | ForEach-Object { Write-Host "  $($_.Name)" }
