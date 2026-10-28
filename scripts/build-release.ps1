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

# Common ldflags: strip debug info. Per-binary `-X main.<key>=<value>` is
# appended in Build-Target so each binary only learns about its own
# version constant (previous form set serverVersion + agentVersion on
# every binary, which silently no-op'd against probe/ca and made it
# impossible to bake a stale agent version into the agent alone).
$baseLdflags = "-s -w"

# Name      = release binary base name (kebab, ships as <name>[.exe]).
# Pkg       = Go import path of the cmd dir.
# LdflagKey = name of the `var <key> = "..."` constant in the binary's
#             main package whose value should be replaced with $Version.
# Targets   = list of GOOS values to build this binary for.
$binaries = @(
    @{ Name = 'lablink-server'; Pkg = './cmd/lablink-server'; LdflagKey = 'serverVersion'; Targets = @('windows','linux') }
    @{ Name = 'lablink-agent';  Pkg = './cmd/lablink-agent';  LdflagKey = 'agentVersion';  Targets = @('windows','linux') }
    @{ Name = 'lablink-probe';  Pkg = './cmd/lablink-probe';  LdflagKey = 'probeVersion';  Targets = @('windows','linux') }
    @{ Name = 'lablink-ca';     Pkg = './cmd/lablink-ca';     LdflagKey = 'caVersion';     Targets = @('windows','linux') }
    @{ Name = 'lablink-secret'; Pkg = './cmd/lablink-secret'; LdflagKey = 'secretVersion'; Targets = @('windows','linux') }
)

$sharedRoot = Join-Path $OutDir '.shared'
$sharedLinuxAgent = Join-Path $sharedRoot 'lablink-agent-linux-amd64'
New-Item -ItemType Directory -Path $sharedRoot -Force | Out-Null
$env:GOOS = 'linux'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'
$sharedAgentLdflags = "$baseLdflags -X main.agentVersion=$Version"
Write-Host "  build lablink-agent [linux/amd64 shared payload]"
& go build -trimpath -ldflags $sharedAgentLdflags -o $sharedLinuxAgent './cmd/lablink-agent'
if ($LASTEXITCODE -ne 0) { throw "go build failed for shared lablink-agent [linux/amd64]" }

# Files copied into every release alongside the binaries.
$bundleFiles = @(
    'README.md',
    'LICENSE',
    'SECURITY.md',
    'configs/mcp.example.json',
    'configs/vm-defaults.example.json',
    'docs/quickstart.md',
    'docs/linux-vm.md',
    'scripts/bootstrap-operator.ps1',
    'scripts/bootstrap-windows-node.ps1',
    'scripts/build-manual-package.ps1',
    'scripts/install.ps1',
    'scripts/install-agent.ps1',
    'scripts/deploy-agent.ps1',
    'scripts/Update-LabLink.ps1'
)

function Join-ByteArrays {
    param([Parameter(Mandatory)][byte[][]]$Arrays)

    $length = 0
    foreach ($array in $Arrays) { $length += $array.Length }
    $result = New-Object byte[] $length
    $offset = 0
    foreach ($array in $Arrays) {
        [Buffer]::BlockCopy($array, 0, $result, $offset, $array.Length)
        $offset += $array.Length
    }
    return $result
}

function Protect-LabLinkPackage {
    param(
        [Parameter(Mandatory)][string]$InputZip,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][string]$Password
    )

    $magic = [Text.Encoding]::ASCII.GetBytes('LLPKG001')
    $salt = New-Object byte[] 16
    $iv = New-Object byte[] 16
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($salt)
        $rng.GetBytes($iv)
    }
    finally {
        $rng.Dispose()
    }

    $derive = [Security.Cryptography.Rfc2898DeriveBytes]::new(
        $Password,
        $salt,
        100000,
        [Security.Cryptography.HashAlgorithmName]::SHA256
    )
    try {
        $encryptionKey = $derive.GetBytes(32)
        $macKey = $derive.GetBytes(32)
    }
    finally {
        $derive.Dispose()
    }

    $plaintext = [IO.File]::ReadAllBytes($InputZip)
    $aes = [Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize = 256
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $encryptionKey
        $aes.IV = $iv
        $encryptor = $aes.CreateEncryptor()
        try {
            $ciphertext = $encryptor.TransformFinalBlock($plaintext, 0, $plaintext.Length)
        }
        finally {
            $encryptor.Dispose()
        }
    }
    finally {
        $aes.Dispose()
    }

    $authenticated = Join-ByteArrays -Arrays @($magic, $salt, $iv, $ciphertext)
    $hmac = [Security.Cryptography.HMACSHA256]::new($macKey)
    try {
        $tag = $hmac.ComputeHash($authenticated)
    }
    finally {
        $hmac.Dispose()
    }
    [IO.File]::WriteAllBytes($OutputPath, (Join-ByteArrays -Arrays @($authenticated, $tag)))
}

function Build-Target {
    param([string]$Os, [string]$Arch, [string]$Stage)

    $binDir = Join-Path $Stage 'bin'
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null

    foreach ($b in $binaries) {
        if ($b.Targets -notcontains $Os) { continue }
        $ext = if ($Os -eq 'windows') { '.exe' } else { '' }
        $out = Join-Path $binDir ("{0}{1}" -f $b.Name, $ext)
        if ($b.Name -eq 'lablink-agent' -and $Os -eq 'linux' -and $Arch -eq 'amd64') {
            Write-Host "  copy lablink-agent [linux/amd64 shared payload]"
            Copy-Item -LiteralPath $sharedLinuxAgent -Destination $out -Force
            continue
        }
        $ldflags = "$baseLdflags -X main.$($b.LdflagKey)=$Version"
        Write-Host "  build $($b.Name) [$Os/$Arch]"
        $env:GOOS   = $Os
        $env:GOARCH = $Arch
        $env:CGO_ENABLED = '0'
        & go build -trimpath -ldflags $ldflags -o $out $b.Pkg
        if ($LASTEXITCODE -ne 0) { throw "go build failed for $($b.Name) [$Os/$Arch]" }
    }

    # The Windows MCP server provisions Linux guests, so its archive also
    # carries the exact same version of the linux/amd64 agent in a distinct
    # path. The native Linux archive layout remains unchanged.
    if ($Os -eq 'windows' -and $Arch -eq 'amd64') {
        $linuxAgentDir = Join-Path $binDir 'linux-amd64'
        New-Item -ItemType Directory -Path $linuxAgentDir -Force | Out-Null
        $linuxAgent = Join-Path $linuxAgentDir 'lablink-agent'
        Write-Host "  copy lablink-agent [linux/amd64 guest payload]"
        Copy-Item -LiteralPath $sharedLinuxAgent -Destination $linuxAgent -Force
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

    $artifactName = $zipName
    $artifactPath = $zipPath
    if ($os -eq 'windows') {
        $artifactName = "$zipName.enc"
        $artifactPath = Join-Path $OutDir $artifactName
        if (Test-Path $artifactPath) { Remove-Item -Force $artifactPath }
        Protect-LabLinkPackage -InputZip $zipPath -OutputPath $artifactPath -Password 'lablink'
        Remove-Item -LiteralPath $zipPath -Force
    }
    Write-Host "  packaged $artifactName"

    $hash = (Get-FileHash $artifactPath -Algorithm SHA256).Hash.ToLower()
    $sums += "$hash  $artifactName"

    Remove-Item -Recurse -Force $stageRoot
}

$installerSource = Join-Path $repoRoot 'scripts\install.ps1'
$installerOut = Join-Path $OutDir 'install.ps1'
Copy-Item -LiteralPath $installerSource -Destination $installerOut -Force
$installerHash = (Get-FileHash $installerOut -Algorithm SHA256).Hash.ToLower()
$sums += "$installerHash  install.ps1"

$sumsFile = Join-Path $OutDir 'SHA256SUMS.txt'
$sums | Set-Content -Encoding ASCII $sumsFile
Remove-Item -LiteralPath $sharedRoot -Recurse -Force
Write-Host ""
Write-Host "Release artifacts in ${OutDir}:" -ForegroundColor Green
Get-ChildItem $OutDir | ForEach-Object { Write-Host "  $($_.Name)" }
