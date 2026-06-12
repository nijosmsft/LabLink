<#
.SYNOPSIS
    One-command release pull for LabLink binaries.

.DESCRIPTION
    Closes the gap of LabLink being a Go project with no `pip install --upgrade`
    equivalent.

    The script:
      1. Resolves the target version (latest by default, or an explicit tag).
      2. Resolves the install destination from -DestinationDir, from the
         lablink entry in ~/.copilot/mcp-config.json, or from
         $env:LOCALAPPDATA\lablink\bin\.
      3. Compares with the currently installed version and exits idempotently
         if already at the target.
      4. Downloads the released windows-amd64 zip + SHA256SUMS.txt with
         `gh release download` into a fresh temp directory.
      5. Verifies the zip's SHA256 against the published sums file.
      6. Extracts the zip and stops any running lablink-* processes (with
         confirmation unless -Force).
      7. Atomically swaps each binary in place (renames existing -> .old,
         copies the new file, deletes .old on success or rolls back on
         failure).
      8. If -UpdateMcpConfig, rewrites the lablink.command path in
         ~/.copilot/mcp-config.json (backing up the original first).
      9. Confirms the install by running lablink-server.exe --version.
     10. Cleans up the temp directory and prints a one-block summary.

    Requires the `gh` CLI (https://cli.github.com/) authenticated against
    a github.com account with read access to nijosmsft/LabLink.

.PARAMETER Version
    Release tag to install (for example `v0.3.0`). Defaults to `latest`, which
    resolves to the most recent published release tag.

.PARAMETER DestinationDir
    Directory to install the binaries into. When omitted, the script tries to
    use the parent directory of the lablink.command path from
    ~/.copilot/mcp-config.json. If neither is available, falls back to
    $env:LOCALAPPDATA\lablink\bin\.

.PARAMETER UpdateMcpConfig
    When set, rewrites the lablink entry in ~/.copilot/mcp-config.json so its
    `command` field points at the freshly installed lablink-server.exe.
    A timestamped backup of the original config is written next to it.

.PARAMETER Force
    Skip interactive confirmation when running lablink-* processes need to be
    stopped. Without -Force, the script lists the processes and prompts.

.EXAMPLE
    .\scripts\Update-LabLink.ps1

    Pull the latest release into the directory the current MCP config is
    already pointing at (or the per-user default), verify, and install.

.EXAMPLE
    .\scripts\Update-LabLink.ps1 -Version v0.3.0 -UpdateMcpConfig -Force

    Install v0.3.0 specifically, update ~/.copilot/mcp-config.json to point
    at the new binary, and don't prompt before stopping running lablink-*
    processes.
#>
[CmdletBinding()]
param(
    [string]$Version = 'latest',

    [string]$DestinationDir,

    [switch]$UpdateMcpConfig,

    [switch]$Force,

    [switch]$SkipServiceStop
)

$ErrorActionPreference = 'Stop'

$Repo            = 'nijosmsft/LabLink'
$McpConfigPath   = Join-Path $env:USERPROFILE '.copilot\mcp-config.json'
$DefaultInstall  = Join-Path $env:LOCALAPPDATA 'lablink\bin'
$ServerBinary    = 'lablink-server.exe'
$ManagedBinaries = @('lablink-server.exe', 'lablink-agent.exe', 'lablink-probe.exe', 'lablink-ca.exe')
$ServiceName = 'LabLink Agent'

# Tracks whether Stop-LabLinkProcesses shut down the Windows service so the
# restart step at the end knows whether to bring it back up.
$script:serviceWasStopped = $false
$script:installRecord     = @()

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Info {
    param([string]$Message)
    Write-Host "    $Message" -ForegroundColor DarkGray
}

function Write-Ok {
    param([string]$Message)
    Write-Host "    $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "    $Message" -ForegroundColor Yellow
}

function Assert-GhCli {
    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if (-not $gh) {
        throw "gh CLI not found on PATH. Install from https://cli.github.com/ and run 'gh auth login'."
    }
}

function Resolve-LatestVersion {
    Write-Step "Resolving latest release tag from $Repo"
    $raw = & gh release view --repo $Repo --json tagName 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "gh release view failed: $raw"
    }
    $json = $raw | ConvertFrom-Json
    if (-not $json.tagName) {
        throw "No tagName in 'gh release view' response."
    }
    Write-Info "latest = $($json.tagName)"
    return $json.tagName
}

function Get-CurrentInstalledVersion {
    param([Parameter(Mandatory)][string]$BinaryPath)

    if (-not (Test-Path $BinaryPath)) {
        return $null
    }

    try {
        $output = & $BinaryPath --version 2>&1
    } catch {
        return $null
    }
    if ($LASTEXITCODE -ne 0) {
        return $null
    }

    $line = ($output | Select-Object -First 1).ToString().Trim()
    if ($line -match '\bv?([0-9][0-9A-Za-z.\-+]*)\s*$') {
        return $matches[1]
    }
    return $null
}

function Get-McpConfigServerPath {
    if (-not (Test-Path $McpConfigPath)) {
        return $null
    }
    try {
        $cfg = Get-Content $McpConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop -Depth 99
    } catch {
        Write-Warn "Could not parse ${McpConfigPath}: $($_.Exception.Message)"
        return $null
    }
    if (-not $cfg) { return $null }

    $lablink = $null
    if ($cfg.PSObject.Properties.Name -contains 'lablink') {
        $lablink = $cfg.lablink
    } elseif ($cfg.PSObject.Properties.Name -contains 'mcpServers' -and $cfg.mcpServers -and ($cfg.mcpServers.PSObject.Properties.Name -contains 'lablink')) {
        $lablink = $cfg.mcpServers.lablink
    }
    if (-not $lablink) { return $null }
    if (-not $lablink.command) { return $null }
    return [string]$lablink.command
}

function Resolve-DestinationDir {
    param([string]$ScriptRoot = $PSScriptRoot)

    if (-not [string]::IsNullOrWhiteSpace($DestinationDir)) {
        Write-Info "destination from -DestinationDir: $DestinationDir"
        return $DestinationDir
    }

    # (a) Script co-located with binaries: handles the lab-node case where the
    #     script is deployed at C:\LabLink\ alongside the agent binary.
    $colocated = Join-Path $ScriptRoot 'lablink-agent.exe'
    if (Test-Path $colocated) {
        Write-Info "Using script-co-located install dir: $ScriptRoot"
        return $ScriptRoot
    }
    $siblingBin = Join-Path (Split-Path $ScriptRoot -Parent) 'bin'
    if (Test-Path (Join-Path $siblingBin 'lablink-agent.exe')) {
        Write-Info "Using sibling bin/ from script root: $siblingBin"
        return $siblingBin
    }

    # (b) lablink-agent service is installed: derive the install dir from its
    #     ImagePath. Uses Get-CimInstance (Get-WmiObject is deprecated on PS 7+).
    try {
        $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        if ($svc -and $svc.PathName) {
            $rawPath = $svc.PathName
            if ($rawPath -match '^"([^"]+)"') {
                # Quoted form: '"C:\LabLink\lablink-agent.exe" -args' -- take the first quoted segment.
                $exe = $Matches[1]
            } else {
                # Unquoted form: 'C:\LabLink\lablink-agent.exe -args' -- split on first space.
                # NOTE: an unquoted path containing a space (e.g. 'C:\Program Files\...\foo.exe -args')
                # would parse incorrectly. Conventionally sc.exe / New-Service always quote such paths.
                $exe = ($rawPath -split ' ', 2)[0]
            }
            if ($exe -and (Test-Path $exe)) {
                $svcDir = Split-Path $exe -Parent
                Write-Info "Using lablink-agent service ImagePath dir: $svcDir"
                return $svcDir
            }
        }
    } catch {
        # service not installed or WMI unavailable — fall through
    }

    $cmd = Get-McpConfigServerPath
    if ($cmd) {
        $parent = Split-Path -Parent $cmd
        if ($parent) {
            Write-Info "destination from mcp-config.json: $parent"
            return $parent
        }
    }
    Write-Info "destination from default: $DefaultInstall"
    return $DefaultInstall
}

function Download-Release {
    param(
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][string]$TempDir
    )

    $zipPattern  = "lablink-$Version-windows-amd64.zip"
    $sumsPattern = 'SHA256SUMS.txt'

    Write-Step "Downloading $zipPattern + $sumsPattern from $Repo@$Version"
    if (-not (Test-Path $TempDir)) {
        New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
    }

    $output = & gh release download $Version --repo $Repo --pattern $zipPattern --pattern $sumsPattern --dir $TempDir --clobber 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "gh release download failed: $output"
    }

    $zipPath  = Join-Path $TempDir $zipPattern
    $sumsPath = Join-Path $TempDir $sumsPattern
    if (-not (Test-Path $zipPath))  { throw "Expected $zipPath after download." }
    if (-not (Test-Path $sumsPath)) { throw "Expected $sumsPath after download." }

    Write-Info "zip:  $zipPath"
    Write-Info "sums: $sumsPath"
    return [pscustomobject]@{ Zip = $zipPath; Sums = $sumsPath }
}

function Verify-Sha256 {
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$SumsPath
    )

    Write-Step "Verifying SHA256 against $(Split-Path $SumsPath -Leaf)"
    $zipName = Split-Path $ZipPath -Leaf
    $expected = $null
    foreach ($line in Get-Content $SumsPath) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        $parts = $trimmed -split '\s+', 2
        if ($parts.Count -lt 2) { continue }
        $hash = $parts[0].Trim().ToLowerInvariant()
        $name = $parts[1].Trim().TrimStart('*')
        if ($name -eq $zipName) {
            $expected = $hash
            break
        }
    }

    if (-not $expected) {
        throw "No SHA256 entry for $zipName in $SumsPath."
    }

    $actual = (Get-FileHash $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "SHA256 mismatch for ${zipName}: expected $expected, got $actual."
    }
    Write-Ok "SHA256 OK ($actual)"
}

function Stop-LabLinkProcesses {
    param([switch]$Force, [switch]$SkipServiceStop)

    # Stop the Windows service first so SCM cannot restart the process between
    # the kill and the binary swap.  On operator machines (no service) pass
    # -SkipServiceStop to bypass this step.
    if (-not $SkipServiceStop) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -in @('Running', 'StartPending', 'ContinuePending', 'Paused', 'PausePending')) {
            Write-Step "Stopping Windows service '$ServiceName'"
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            Start-Sleep -Seconds 1
            $script:serviceWasStopped = $true
            Write-Ok "service '$ServiceName' stopped"
        }
    }

    $names = $ManagedBinaries | ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_) }
    $running = Get-Process -Name $names -ErrorAction SilentlyContinue
    if (-not $running) {
        return
    }

    Write-Step "Stopping running lablink-* processes"
    foreach ($p in $running) {
        $path = try { $p.Path } catch { '<unknown path>' }
        Write-Warn "$($p.ProcessName) (PID $($p.Id)) -> $path"
    }

    if (-not $Force) {
        $answer = Read-Host 'Stop these processes? [y/N]'
        if ($answer -notmatch '^(y|yes)$') {
            throw 'Aborted by user. Re-run with -Force to bypass the prompt.'
        }
    }

    foreach ($p in $running) {
        try {
            Stop-Process -Id $p.Id -Force -ErrorAction Stop
            Write-Ok "stopped PID $($p.Id)"
        } catch {
            throw "Failed to stop PID $($p.Id) ($($p.ProcessName)): $($_.Exception.Message)"
        }
    }
    Start-Sleep -Seconds 1
}

function Install-Binaries {
    param(
        [Parameter(Mandatory)][string]$ExtractedBinDir,
        [Parameter(Mandatory)][string]$DestinationDir
    )

    Write-Step "Installing binaries into $DestinationDir"
    if (-not (Test-Path $DestinationDir)) {
        New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
    }

    $script:installRecord = @()
    $installed = @()
    try {
        foreach ($name in $ManagedBinaries) {
            $src = Join-Path $ExtractedBinDir $name
            if (-not (Test-Path $src)) {
                Write-Warn "skip $name (not in release zip)"
                continue
            }
            $dst = Join-Path $DestinationDir $name
            $old = "$dst.old"
            if (Test-Path $old) { Remove-Item -Force $old }

            $hadPrior = [bool](Test-Path $dst)
            if ($hadPrior) {
                Rename-Item -Path $dst -NewName ([System.IO.Path]::GetFileName($old)) -Force
            }

            # Record before copying so rollback is accurate even if Copy-Item fails.
            $script:installRecord += @{ Path = $dst; HadPrior = $hadPrior }

            Copy-Item -Path $src -Destination $dst -Force
            $installed += $dst
            Write-Ok "installed $name"
        }
    } catch {
        Write-Warn "install failed: $($_.Exception.Message). Rolling back."
        foreach ($entry in $script:installRecord) {
            $dst = $entry.Path
            if (Test-Path $dst) { Remove-Item -Force $dst -ErrorAction SilentlyContinue }
            if ($entry.HadPrior) {
                $old = "$dst.old"
                if (Test-Path $old) { Rename-Item -Path $old -NewName ([System.IO.Path]::GetFileName($dst)) -Force }
            }
        }
        throw
    }

    # .old files are intentionally preserved here. Call Commit-Install only
    # after Start-Service + Confirm-Install both succeed, or Rollback-Install on failure.
    return [pscustomobject]@{ Installed = $installed }
}

function Commit-Install {
    param([Parameter(Mandatory)]$InstallResult)
    foreach ($entry in $script:installRecord) {
        if ($entry.HadPrior) {
            $old = "$($entry.Path).old"
            if (Test-Path $old) { Remove-Item -Force $old -ErrorAction SilentlyContinue }
        }
    }
    $script:installRecord = @()
}

function Rollback-Install {
    param([Parameter(Mandatory)]$InstallResult)
    Write-Warn "Rolling back binary swap."
    foreach ($entry in $script:installRecord) {
        $dst = $entry.Path
        if (Test-Path $dst) { Remove-Item -Force $dst -ErrorAction SilentlyContinue }
        if ($entry.HadPrior) {
            $old = "$dst.old"
            if (Test-Path $old) {
                Rename-Item -Path $old -NewName ([System.IO.Path]::GetFileName($dst)) -Force
                Write-Info "restored $([System.IO.Path]::GetFileName($dst))"
            }
        } else {
            Write-Info "removed new-only install $([System.IO.Path]::GetFileName($dst))"
        }
    }
}

function Update-McpConfigPath {
    param(
        [Parameter(Mandatory)][string]$DestinationDir,
        [Parameter(Mandatory)][string]$NewServerPath
    )

    if (-not (Test-Path $McpConfigPath)) {
        Write-Warn "No mcp-config.json at $McpConfigPath. Skipping -UpdateMcpConfig."
        return $false
    }

    $raw = Get-Content $McpConfigPath -Raw
    $cfg = $raw | ConvertFrom-Json -Depth 99

    $lablink = $null
    $owner   = $null
    if ($cfg.PSObject.Properties.Name -contains 'lablink') {
        $lablink = $cfg.lablink
        $owner   = $cfg
    } elseif ($cfg.PSObject.Properties.Name -contains 'mcpServers' -and $cfg.mcpServers -and ($cfg.mcpServers.PSObject.Properties.Name -contains 'lablink')) {
        $lablink = $cfg.mcpServers.lablink
        $owner   = $cfg.mcpServers
    }

    if (-not $lablink) {
        Write-Warn "No 'lablink' MCP entry in $McpConfigPath. Skipping rewrite."
        return $false
    }

    $oldCommand = [string]$lablink.command
    if ($oldCommand -eq $NewServerPath) {
        Write-Info "mcp-config.json already points at $NewServerPath. No rewrite needed."
        return $false
    }

    $stamp  = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $backup = "$McpConfigPath.bak.$stamp"
    Copy-Item -Path $McpConfigPath -Destination $backup -Force
    Write-Ok "backed up to $backup"

    $lablink.command = $NewServerPath
    $owner.lablink   = $lablink
    $cfg | ConvertTo-Json -Depth 99 | Set-Content -Path $McpConfigPath -Encoding UTF8

    Write-Host "    lablink.command:" -ForegroundColor DarkGray
    Write-Host "      old: $oldCommand" -ForegroundColor DarkGray
    Write-Host "      new: $NewServerPath" -ForegroundColor Green
    return $true
}

function Confirm-Install {
    param(
        [Parameter(Mandatory)][string]$BinaryPath,
        [Parameter(Mandatory)][string]$ExpectedVersion
    )

    Write-Step "Confirming install via $BinaryPath --version"
    if (-not (Test-Path $BinaryPath)) {
        throw "Installed binary not found at $BinaryPath."
    }

    $output = & $BinaryPath --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$BinaryPath --version failed: $output"
    }

    $line = ($output | Select-Object -First 1).ToString().Trim()
    Write-Info $line
    $expectedTrimmed = $ExpectedVersion.TrimStart('v')
    if ($line -notmatch [regex]::Escape($expectedTrimmed)) {
        throw "Version mismatch: expected $expectedTrimmed, got '$line'."
    }
    Write-Ok "version matches"
    return $line
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if ($MyInvocation.InvocationName -ne '.') {
try {
    Assert-GhCli

    if ($Version -eq 'latest') {
        $Version = Resolve-LatestVersion
    }
    if (-not $Version.StartsWith('v')) {
        $Version = "v$Version"
    }

    $destination = Resolve-DestinationDir
    $serverPath  = Join-Path $destination $ServerBinary

    $currentVersion = Get-CurrentInstalledVersion -BinaryPath $serverPath
    if ($currentVersion) {
        Write-Info "currently installed: v$currentVersion"
    } else {
        Write-Info "currently installed: (none detected at $serverPath)"
    }

    $targetTrim = $Version.TrimStart('v')
    if ($currentVersion -and $currentVersion -eq $targetTrim) {
        Write-Host ""
        Write-Host "Already at $Version. Nothing to do." -ForegroundColor Green
        exit 0
    }

    $stamp   = (Get-Date).ToString('yyyyMMddHHmmss')
    $tempDir = Join-Path $env:TEMP "lablink-update-$stamp"
    if (Test-Path $tempDir) { Remove-Item -Recurse -Force $tempDir }
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    $downloadedPath = $null
    try {
        $downloaded = Download-Release -Version $Version -TempDir $tempDir
        Verify-Sha256 -ZipPath $downloaded.Zip -SumsPath $downloaded.Sums

        $extractDir = Join-Path $tempDir 'extracted'
        if (Test-Path $extractDir) { Remove-Item -Recurse -Force $extractDir }
        New-Item -ItemType Directory -Path $extractDir -Force | Out-Null

        Write-Step "Extracting zip to $extractDir"
        Expand-Archive -Path $downloaded.Zip -DestinationPath $extractDir -Force

        $binDir = Join-Path $extractDir 'bin'
        if (-not (Test-Path $binDir)) {
            $rootDir = Get-ChildItem -Path $extractDir -Directory | Select-Object -First 1
            if ($rootDir) {
                $candidate = Join-Path $rootDir.FullName 'bin'
                if (Test-Path $candidate) { $binDir = $candidate }
            }
        }
        if (-not (Test-Path $binDir)) {
            throw "Could not find bin\ directory inside extracted release zip."
        }
        Write-Info "release bin: $binDir"

        $script:serviceRestartHandled = $false
        $installResult = $null

        try {
            Stop-LabLinkProcesses -Force:$Force -SkipServiceStop:$SkipServiceStop

            $installResult = Install-Binaries -ExtractedBinDir $binDir -DestinationDir $destination
            $installed = $installResult.Installed

            if ($script:serviceWasStopped) {
                Write-Step "Restarting Windows service '$ServiceName'"
                try {
                    Start-Service -Name $ServiceName -ErrorAction Stop
                    Write-Ok "service '$ServiceName' restarted"
                } catch {
                    $startWithNewErr = $_.Exception.Message
                    Write-Warn "Start-Service failed with new binary: $startWithNewErr. Rolling back install."
                    Rollback-Install -InstallResult $installResult
                    $installResult = $null
                    try {
                        Start-Service -Name $ServiceName -ErrorAction Stop
                        $script:serviceRestartHandled = $true
                    } catch {
                        throw ("ACTION REQUIRED: lablink-agent service failed to start with both new and old" +
                               " binaries. Manual recovery needed. Binaries at: $destination." +
                               " Start-Service error: $($_.Exception.Message)")
                    }
                    Write-Warn "Update rolled back: new binary failed to start. Prior version is running."
                    throw ("Update rolled back: Start-Service failed for new binary ($startWithNewErr)." +
                           " Prior version is running at $destination.")
                }
            }

            $mcpUpdated = $false
            if ($UpdateMcpConfig) {
                $mcpUpdated = Update-McpConfigPath -DestinationDir $destination -NewServerPath $serverPath
            }

            try {
                $confirmedLine = Confirm-Install -BinaryPath $serverPath -ExpectedVersion $Version
            } catch {
                $confirmErr = $_.Exception.Message
                Write-Warn "Confirm-Install failed: $confirmErr. Rolling back install."
                if ($script:serviceWasStopped) {
                    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                }
                Rollback-Install -InstallResult $installResult
                $installResult = $null
                if ($script:serviceWasStopped) {
                    try {
                        Start-Service -Name $ServiceName -ErrorAction Stop
                        $script:serviceRestartHandled = $true
                    } catch {
                        throw ("ACTION REQUIRED: lablink-agent service failed to start after rollback." +
                               " Manual recovery needed. Binaries at: $destination." +
                               " Start-Service error: $($_.Exception.Message)")
                    }
                    Write-Warn "Update rolled back: Confirm-Install failed. Prior version is running."
                    throw "Update rolled back: Confirm-Install failed ($confirmErr). Prior version is running at $destination."
                }
                throw
            }

            Commit-Install -InstallResult $installResult
            $script:serviceRestartHandled = $true

        } finally {
            # Safety net: if any step failed or was aborted after Stop-Service, restart the
            # service so it is never left stopped. Skip when -SkipServiceStop was passed
            # (operator machines with no service).
            if (-not $SkipServiceStop -and $script:serviceWasStopped -and -not $script:serviceRestartHandled) {
                try {
                    Start-Service -Name $ServiceName -ErrorAction Stop
                    Write-Info "lablink-agent service restarted"
                } catch {
                    Write-Warn "ACTION REQUIRED: failed to restart lablink-agent service after update flow: $($_.Exception.Message)"
                }
            }
        }

        Write-Host ""
        Write-Host "Update complete." -ForegroundColor Green
        Write-Host "  Old version:       $(if ($currentVersion) { "v$currentVersion" } else { '(none)' })"
        Write-Host "  New version:       $Version"
        Write-Host "  Install directory: $destination"
        Write-Host "  mcp-config:        $(if ($mcpUpdated) { 'updated' } elseif ($UpdateMcpConfig) { 'not modified (already current or missing)' } else { 'not requested' })"
        Write-Host "  --version output:  $confirmedLine"
        Write-Host "  Installed:"
        foreach ($f in $installed) {
            $size = (Get-Item $f).Length
            $kb   = [Math]::Round($size / 1KB, 1)
            Write-Host ("    {0}  ({1} KB)" -f $f, $kb)
        }
    } finally {
        if (Test-Path $tempDir) {
            try { Remove-Item -Recurse -Force $tempDir -ErrorAction Stop } catch {
                Write-Warn "Could not remove temp dir ${tempDir}: $($_.Exception.Message)"
            }
        }
    }
} catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
} # end if ($MyInvocation.InvocationName -ne '.')
