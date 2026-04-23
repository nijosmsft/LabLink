<#
.SYNOPSIS
    Install the LabLink agent as a Windows service on the local machine.

.DESCRIPTION
    Run this script on the target machine after copying LabLinkAgent.exe to C:\LabLink.
    It writes the auth token to an ACL-protected file, installs the service, creates a firewall rule,
    and starts the agent.

.PARAMETER Token
    Pre-shared key for authentication.

.PARAMETER Port
    gRPC listen port (default 9091).

.PARAMETER AgentDir
    Directory containing LabLinkAgent.exe (default C:\LabLink).

.PARAMETER TokenFile
    Path to the token file used by the LabLink Agent service.

.PARAMETER Transport
    Agent transport mode: mtls (default) or insecure.

.PARAMETER TlsCA
    CA certificate bundle PEM for mTLS mode.

.PARAMETER TlsCert
    Server certificate chain PEM for mTLS mode.

.PARAMETER TlsKey
    Server private key PEM for mTLS mode.

.PARAMETER AllowInsecure
    Explicitly opt into the plaintext fallback transport when Transport=insecure.

.EXAMPLE
    .\install-agent.ps1 -Token "my-secret-token" -Transport mtls -TlsCA C:\LabLink\tls\ca.crt -TlsCert C:\LabLink\tls\server.crt -TlsKey C:\LabLink\tls\server.key

.EXAMPLE
    .\install-agent.ps1 -Token "my-secret-token" -Transport insecure -AllowInsecure
#>
param(
    [Parameter(Mandatory)]
    [string]$Token,

    [int]$Port = 9091,

    [string]$AgentDir = 'C:\LabLink',

    [string]$TokenFile = 'C:\LabLink\agent.token',

    [ValidateSet('mtls', 'insecure')]
    [string]$Transport = 'mtls',

    [string]$TlsCA = 'C:\LabLink\tls\ca.crt',

    [string]$TlsCert = 'C:\LabLink\tls\server.crt',

    [string]$TlsKey = 'C:\LabLink\tls\server.key',

    [switch]$AllowInsecure
)

$ErrorActionPreference = 'Stop'
$exe = Join-Path $AgentDir 'LabLinkAgent.exe'
$svcName = 'LabLink Agent'
$previousSvcName = 'lablink-agent'
$fwRuleName = 'LabLink Agent'
$legacyFwRuleName = 'lablink-agent'

function Protect-LabLinkSecretFile {
    param([Parameter(Mandatory)][string]$Path)

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    icacls $Path /inheritance:r /grant:r "${currentUser}:F" 'Administrators:F' 'SYSTEM:F' | Out-Null
}

if (-not (Test-Path $exe)) {
    Write-Error "Agent binary not found at $exe. Copy LabLinkAgent.exe to $AgentDir first."
    exit 1
}

if ($Transport -eq 'insecure') {
    if (-not $AllowInsecure) {
        throw "LabLink's plaintext fallback transport is disabled by default. Re-run with -Transport insecure -AllowInsecure to opt in."
    }
} else {
    foreach ($path in @($TlsCA, $TlsCert, $TlsKey)) {
        if (-not (Test-Path $path)) {
            throw "Required TLS file not found: $path"
        }
    }

    if (Test-Path $TlsKey) {
        icacls $TlsKey /inheritance:r /grant:r 'SYSTEM:F' 'Administrators:F' | Out-Null
    }
}

# Stop existing service/process. NOTE: device-interaction-agent is intentionally
# left alone — it predates LabLink and may be owned by other tooling.
foreach ($name in @($svcName, $previousSvcName)) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Write-Host "Stopping existing service..." -ForegroundColor Yellow
        Stop-Service -Name $name -Force
        Start-Sleep 2
    }
}

# Write token to disk.
$tokenDir = Split-Path -Parent $TokenFile
if ($tokenDir -and -not (Test-Path $tokenDir)) {
    New-Item -ItemType Directory -Path $tokenDir -Force | Out-Null
}
Write-Host "Writing token file..." -ForegroundColor Cyan
Set-Content -Path $TokenFile -Value $Token -NoNewline -Encoding ascii
Protect-LabLinkSecretFile -Path $TokenFile
foreach ($registryPath in @('HKLM:\SOFTWARE\LabLink', 'HKLM:\SOFTWARE\device-interaction')) {
    if (Test-Path $registryPath) {
        Remove-ItemProperty -Path $registryPath -Name 'AuthToken' -ErrorAction SilentlyContinue
    }
}
Write-Host "  Done" -ForegroundColor DarkGray

# Uninstall old service if present.
if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {
    Write-Host "Removing old service..." -ForegroundColor Cyan
    $ErrorActionPreference = 'SilentlyContinue'
    & $exe --uninstall *>$null
    $ErrorActionPreference = 'Stop'
    Start-Sleep 1
}

foreach ($legacyName in @($previousSvcName)) {
    if (Get-Service -Name $legacyName -ErrorAction SilentlyContinue) {
        Write-Host "Removing legacy service '$legacyName'..." -ForegroundColor Cyan
        sc.exe delete $legacyName | Out-Null
        Start-Sleep 1
    }
}

$installArgs = @('--install', '--listen', ":$Port", '--transport', $Transport, '--auth-token-file', $TokenFile)
if ($Transport -eq 'insecure') {
    $installArgs += '--allow-insecure'
} else {
    $installArgs += @('--tls-ca', $TlsCA, '--tls-cert', $TlsCert, '--tls-key', $TlsKey)
}

# Install service.
Write-Host "Installing service (port $Port, transport $Transport)..." -ForegroundColor Cyan
$ErrorActionPreference = 'SilentlyContinue'
& $exe @installArgs *>$null
$ErrorActionPreference = 'Stop'

# Firewall rule.
Write-Host "Configuring firewall..." -ForegroundColor Cyan
$existing = Get-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue
if (-not $existing) {
    $existing = Get-NetFirewallRule -DisplayName $legacyFwRuleName -ErrorAction SilentlyContinue
}
if ($existing) {
    $existing | Get-NetFirewallPortFilter | Set-NetFirewallPortFilter -LocalPort $Port
    $existing | Get-NetFirewallApplicationFilter | Set-NetFirewallApplicationFilter -Program $exe
    Write-Host "  Firewall rule updated" -ForegroundColor DarkGray
} else {
    New-NetFirewallRule `
        -DisplayName $fwRuleName `
        -Description 'Allow inbound gRPC for LabLink agent' `
        -Direction Inbound -Protocol TCP -LocalPort $Port `
        -Program $exe -Action Allow -Profile Any | Out-Null
    Write-Host "  Firewall rule created" -ForegroundColor DarkGray
}

# Start service.
Write-Host "Starting service..." -ForegroundColor Cyan
Start-Service -Name $svcName
Start-Sleep 1

$svc = Get-Service -Name $svcName
if ($svc.Status -eq 'Running') {
    Write-Host "`nAgent installed and running on port $Port using $Transport" -ForegroundColor Green
} else {
    Write-Host "`nService installed but status: $($svc.Status)" -ForegroundColor Yellow
}
