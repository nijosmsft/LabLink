<#
.SYNOPSIS
    Install the LabLink operator package on Windows.

.DESCRIPTION
    Adds the requested Microsoft Defender exclusions, obtains an AES-protected
    LabLink Windows package, verifies and decrypts it under C:\LabLink, installs
    it in a versioned directory, updates the stable "current" junction, runs
    bootstrap-operator.ps1, and writes an AI prompt for MCP configuration.

.PARAMETER PackagePath
    Optional path to a previously downloaded
    lablink-vX.Y.Z-windows-amd64.zip.enc package. When omitted, the installer
    downloads the latest stable GitHub release.

.PARAMETER Prerelease
    Download the newest non-draft prerelease instead of the latest stable
    release. Ignored when PackagePath is supplied.

.PARAMETER InstallRoot
    Stable installation root. Defaults to C:\LabLink.
#>
[CmdletBinding()]
param(
    [string]$PackagePath,
    [switch]$Prerelease,
    [string]$InstallRoot = 'C:\LabLink'
)

$ErrorActionPreference = 'Stop'
$Repo = 'nijosmsft/LabLink'
$PackagePassword = 'lablink'
$PackageMagic = [Text.Encoding]::ASCII.GetBytes('LLPKG001')
$PBKDF2Iterations = 100000

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'LabLink installation must run from an elevated PowerShell prompt.'
    }
}

function Test-FixedTimeEqual {
    param(
        [Parameter(Mandatory)][byte[]]$Left,
        [Parameter(Mandatory)][byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) { return $false }
    $difference = 0
    for ($i = 0; $i -lt $Left.Length; $i++) {
        $difference = $difference -bor ($Left[$i] -bxor $Right[$i])
    }
    return $difference -eq 0
}

function Expand-ProtectedLabLinkPackage {
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutputZip,
        [Parameter(Mandatory)][string]$Password
    )

    $container = [IO.File]::ReadAllBytes($InputPath)
    $minimumLength = $PackageMagic.Length + 16 + 16 + 32 + 16
    if ($container.Length -lt $minimumLength) {
        throw "Protected package is truncated: $InputPath"
    }

    $offset = 0
    $magic = New-Object byte[] $PackageMagic.Length
    [Buffer]::BlockCopy($container, $offset, $magic, 0, $magic.Length)
    $offset += $magic.Length
    if (-not (Test-FixedTimeEqual -Left $magic -Right $PackageMagic)) {
        throw "Protected package has an invalid LabLink header: $InputPath"
    }

    $salt = New-Object byte[] 16
    $iv = New-Object byte[] 16
    [Buffer]::BlockCopy($container, $offset, $salt, 0, 16)
    $offset += 16
    [Buffer]::BlockCopy($container, $offset, $iv, 0, 16)
    $offset += 16

    $tagLength = 32
    $cipherLength = $container.Length - $offset - $tagLength
    if ($cipherLength -le 0) { throw "Protected package has no encrypted payload: $InputPath" }
    $ciphertext = New-Object byte[] $cipherLength
    $tag = New-Object byte[] $tagLength
    [Buffer]::BlockCopy($container, $offset, $ciphertext, 0, $cipherLength)
    [Buffer]::BlockCopy($container, $offset + $cipherLength, $tag, 0, $tagLength)

    $derive = [Security.Cryptography.Rfc2898DeriveBytes]::new(
        $Password,
        $salt,
        $PBKDF2Iterations,
        [Security.Cryptography.HashAlgorithmName]::SHA256
    )
    try {
        $encryptionKey = $derive.GetBytes(32)
        $macKey = $derive.GetBytes(32)
    }
    finally {
        $derive.Dispose()
    }

    $authenticated = New-Object byte[] ($container.Length - $tagLength)
    [Buffer]::BlockCopy($container, 0, $authenticated, 0, $authenticated.Length)
    $hmac = [Security.Cryptography.HMACSHA256]::new($macKey)
    try {
        $computedTag = $hmac.ComputeHash($authenticated)
    }
    finally {
        $hmac.Dispose()
    }
    if (-not (Test-FixedTimeEqual -Left $computedTag -Right $tag)) {
        throw 'Protected package authentication failed. The package is corrupt or the password is incorrect.'
    }

    $aes = [Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize = 256
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $encryptionKey
        $aes.IV = $iv
        $decryptor = $aes.CreateDecryptor()
        try {
            $plaintext = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
        }
        finally {
            $decryptor.Dispose()
        }
    }
    finally {
        $aes.Dispose()
    }
    [IO.File]::WriteAllBytes($OutputZip, $plaintext)
}

function Invoke-GitHubApi {
    param([Parameter(Mandatory)][string]$Uri)

    $headers = @{ 'User-Agent' = 'LabLink-Installer' }
    $token = if ($env:GH_TOKEN) { $env:GH_TOKEN } else { $env:GITHUB_TOKEN }
    if ($token) {
        $headers.Authorization = "Bearer $token"
    }

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            return Invoke-RestMethod -Headers $headers -Uri $Uri
        }
        catch {
            $response = $_.Exception.Response
            $statusCode = if ($response) { [int]$response.StatusCode } else { 0 }
            $rateLimited = $statusCode -eq 403 -or $statusCode -eq 429 -or
                $_.Exception.Message -match 'rate limit'
            if (-not $rateLimited) {
                throw "GitHub release query failed: $($_.Exception.Message)"
            }

            $resetText = ''
            if ($response -and $response.Headers) {
                $resetValue = $response.Headers['X-RateLimit-Reset']
                if ($resetValue) {
                    try {
                        $resetTime = [DateTimeOffset]::FromUnixTimeSeconds([int64]$resetValue).ToLocalTime()
                        $resetText = " The limit is expected to reset at $($resetTime.ToString('yyyy-MM-dd HH:mm:ss zzz'))."
                    }
                    catch {}
                }
            }
            if ($attempt -lt 3) {
                $delay = 5 * $attempt
                Write-Warning "GitHub API rate limit reached; retrying in $delay seconds ($attempt/3).$resetText"
                Start-Sleep -Seconds $delay
                continue
            }

            throw @"
GitHub API rate limit reached after 3 attempts.$resetText
Wait for the limit to reset, set GH_TOKEN to an authenticated GitHub token, or
download the protected Windows package and SHA256SUMS.txt from
https://github.com/$Repo/releases and run:

  .\install.ps1 -PackagePath <path-to-lablink-version-windows-amd64.zip.enc>
"@
        }
    }
}

function Get-LabLinkRelease {
    param([switch]$IncludePrerelease)

    if (-not $IncludePrerelease) {
        return Invoke-GitHubApi -Uri "https://api.github.com/repos/$Repo/releases/latest"
    }
    $releases = Invoke-GitHubApi -Uri "https://api.github.com/repos/$Repo/releases?per_page=100"
    $release = $releases | Where-Object { -not $_.draft -and $_.prerelease } | Select-Object -First 1
    if (-not $release) { throw "No LabLink prerelease is available in $Repo." }
    return $release
}

function Get-ExpectedHash {
    param(
        [Parameter(Mandatory)][string]$SumsPath,
        [Parameter(Mandatory)][string]$FileName
    )

    foreach ($line in Get-Content -LiteralPath $SumsPath) {
        $parts = $line.Trim() -split '\s+', 2
        if ($parts.Count -eq 2 -and $parts[1].Trim().TrimStart('*') -eq $FileName) {
            return $parts[0].Trim().ToLowerInvariant()
        }
    }
    throw "SHA256SUMS.txt does not contain an entry for $FileName."
}

function Set-LabLinkDefenderExclusions {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$ServerPath
    )

    if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Warning 'Microsoft Defender cmdlets are unavailable; no exclusions were configured.'
        return
    }
    Add-MpPreference -ExclusionPath $Root
    Add-MpPreference -ExclusionProcess $ServerPath

    $preferences = Get-MpPreference
    if (@($preferences.ExclusionPath) -notcontains $Root) {
        throw "Microsoft Defender path exclusion was not applied for $Root"
    }
    if (@($preferences.ExclusionProcess) -notcontains $ServerPath) {
        throw "Microsoft Defender process exclusion was not applied for $ServerPath"
    }
}

function Set-CurrentJunction {
    param(
        [Parameter(Mandatory)][string]$CurrentPath,
        [Parameter(Mandatory)][string]$TargetPath
    )

    if (Test-Path -LiteralPath $CurrentPath) {
        $item = Get-Item -LiteralPath $CurrentPath -Force
        if (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Refusing to replace non-junction path: $CurrentPath"
        }
        $item.Delete()
    }
    New-Item -ItemType Junction -Path $CurrentPath -Target $TargetPath | Out-Null
}

Assert-Administrator
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$currentPath = Join-Path $InstallRoot 'current'
$stableServerPath = Join-Path $currentPath 'bin\lablink-server.exe'
New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
Set-LabLinkDefenderExclusions -Root $InstallRoot -ServerPath $stableServerPath

$packagesDir = Join-Path $InstallRoot 'packages'
$workDir = Join-Path $InstallRoot ('.install\' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $packagesDir,$workDir -Force | Out-Null

try {
    $sumsPath = $null
    if ($PackagePath) {
        $sourcePackage = (Resolve-Path -LiteralPath $PackagePath).Path
        $packageName = Split-Path -Leaf $sourcePackage
        if ($packageName -notmatch '^lablink-(?<version>v.+)-windows-amd64\.zip\.enc$') {
            throw "Package name must match lablink-vX.Y.Z-windows-amd64.zip.enc: $packageName"
        }
        $version = $Matches.version
        $protectedPackage = Join-Path $packagesDir $packageName
        if ($sourcePackage -ne $protectedPackage) {
            Copy-Item -LiteralPath $sourcePackage -Destination $protectedPackage -Force
        }
        $candidateSums = Join-Path (Split-Path -Parent $sourcePackage) 'SHA256SUMS.txt'
        if (Test-Path -LiteralPath $candidateSums) {
            $sumsPath = $candidateSums
        }
    }
    else {
        $release = Get-LabLinkRelease -IncludePrerelease:$Prerelease
        $version = [string]$release.tag_name
        $packageName = "lablink-$version-windows-amd64.zip.enc"
        $packageAsset = $release.assets | Where-Object { $_.name -eq $packageName } | Select-Object -First 1
        $sumsAsset = $release.assets | Where-Object { $_.name -eq 'SHA256SUMS.txt' } | Select-Object -First 1
        if ((-not $packageAsset -or -not $sumsAsset) -and -not $Prerelease) {
            Write-Warning "Latest stable release $version predates the protected Windows package; selecting the newest compatible prerelease."
            $release = Get-LabLinkRelease -IncludePrerelease
            $version = [string]$release.tag_name
            $packageName = "lablink-$version-windows-amd64.zip.enc"
            $packageAsset = $release.assets | Where-Object { $_.name -eq $packageName } | Select-Object -First 1
            $sumsAsset = $release.assets | Where-Object { $_.name -eq 'SHA256SUMS.txt' } | Select-Object -First 1
        }
        if (-not $packageAsset -or -not $sumsAsset) {
            throw "Release $version does not contain $packageName and SHA256SUMS.txt."
        }
        $protectedPackage = Join-Path $packagesDir $packageName
        $sumsPath = Join-Path $workDir 'SHA256SUMS.txt'
        Write-Host "Downloading LabLink $version..." -ForegroundColor Cyan
        Invoke-WebRequest -UseBasicParsing -Uri $packageAsset.browser_download_url -OutFile $protectedPackage
        Invoke-WebRequest -UseBasicParsing -Uri $sumsAsset.browser_download_url -OutFile $sumsPath
    }

    if ($sumsPath) {
        $expected = Get-ExpectedHash -SumsPath $sumsPath -FileName $packageName
        $actual = (Get-FileHash -LiteralPath $protectedPackage -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "SHA256 mismatch for ${packageName}: expected $expected, got $actual."
        }
    }
    else {
        Write-Warning 'No sibling SHA256SUMS.txt was supplied; relying on the authenticated package container.'
    }

    $plainZip = Join-Path $workDir 'package.zip'
    Write-Host "Decrypting protected package under $InstallRoot..." -ForegroundColor Cyan
    Expand-ProtectedLabLinkPackage -InputPath $protectedPackage -OutputZip $plainZip -Password $PackagePassword

    $destination = Join-Path $InstallRoot $version
    if (-not (Test-Path -LiteralPath (Join-Path $destination 'bin\lablink-server.exe'))) {
        $staging = Join-Path $workDir 'extracted'
        New-Item -ItemType Directory -Path $staging -Force | Out-Null
        Expand-Archive -LiteralPath $plainZip -DestinationPath $staging -Force
        foreach ($required in @(
            'bin\lablink-server.exe',
            'bin\lablink-ca.exe',
            'scripts\bootstrap-operator.ps1'
        )) {
            if (-not (Test-Path -LiteralPath (Join-Path $staging $required))) {
                throw "Protected package is missing $required"
            }
        }
        if (Test-Path -LiteralPath $destination) {
            throw "Installation directory already exists but is incomplete: $destination"
        }
        Move-Item -LiteralPath $staging -Destination $destination
    }

    Set-CurrentJunction -CurrentPath $currentPath -TargetPath $destination

    $bootstrap = Join-Path $currentPath 'scripts\bootstrap-operator.ps1'
    & $bootstrap `
        -ServerBinary $stableServerPath `
        -CaBinary (Join-Path $currentPath 'bin\lablink-ca.exe')
    if ($LASTEXITCODE -ne 0) {
        throw "bootstrap-operator.ps1 failed with exit code $LASTEXITCODE"
    }

    $mcpSnippetPath = Join-Path $HOME '.lablink\mcp.example.json'
    $mcpSnippet = Get-Content -LiteralPath $mcpSnippetPath -Raw
    $promptPath = Join-Path $InstallRoot 'configure-mcp-prompt.txt'
    $prompt = @"
Configure the LabLink MCP server in my AI client's MCP configuration using the
following generated entry. Preserve the command path exactly so future LabLink
upgrades follow C:\LabLink\current. Then restart or reload the MCP client.

$mcpSnippet
"@
    Set-Content -LiteralPath $promptPath -Value $prompt -Encoding utf8

    Write-Host ""
    Write-Host "LabLink $version installed successfully." -ForegroundColor Green
    Write-Host "  Current server: $stableServerPath"
    Write-Host "  MCP snippet:    $mcpSnippetPath"
    Write-Host "  AI prompt:      $promptPath"
    Write-Host ""
    Write-Host "Copy and paste the prompt below into your AI agent to finish bootstrapping LabLink:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host $prompt -ForegroundColor Cyan
}
finally {
    if (Test-Path -LiteralPath $workDir) {
        Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
