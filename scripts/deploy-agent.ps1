<#
.SYNOPSIS
    Deploy the LabLink agent to remote machines.

.DESCRIPTION
    Copies the agent binary, writes the auth token to an ACL-protected file,
    installs as a Windows service, and starts it.

.PARAMETER Machines
    Comma-separated list of machine IPs or hostnames.

.PARAMETER AgentBinary
    Path to the agent binary. Defaults to bin/LabLinkAgent.exe.

.PARAMETER Token
    Pre-shared key for authentication. Written to a protected token file on each node.

.PARAMETER Port
    gRPC listen port (default 9091).

.PARAMETER Credential
    PSCredential for WinRM (Windows machines).

.PARAMETER RemoteTokenFile
    Path to the token file written on the remote node.

.PARAMETER Transport
    Agent transport mode: mtls (default) or insecure.

.PARAMETER TlsCA
    Local CA certificate bundle PEM to copy when Transport=mtls.

.PARAMETER TlsCert
    Local server certificate chain PEM to copy when Transport=mtls.

.PARAMETER TlsKey
    Local server private key PEM to copy when Transport=mtls.

.PARAMETER AllowInsecure
    Explicitly opt into the plaintext fallback transport when Transport=insecure.

.PARAMETER NoService
    Skip service installation; start the agent as a detached process instead.
#>
param(
    [Parameter(Mandatory)]
    [string[]]$Machines,

    [string]$AgentBinary = "$PSScriptRoot\..\bin\LabLinkAgent.exe",

    [Parameter(Mandatory)]
    [string]$Token,

    [int]$Port = 9091,

    [PSCredential]$Credential,

    [string]$RemoteTokenFile = 'C:\LabLink\agent.token',

    [ValidateSet('mtls', 'insecure')]
    [string]$Transport = 'mtls',

    [string]$TlsCA,

    [string]$TlsCert,

    [string]$TlsKey,

    [switch]$AllowInsecure,

    [switch]$NoService
)

$ErrorActionPreference = 'Stop'
$RemoteDir = 'C:\LabLink'
$RemoteTlsDir = Join-Path $RemoteDir 'tls'
$RemoteCA = Join-Path $RemoteTlsDir 'ca.crt'
$RemoteCert = Join-Path $RemoteTlsDir 'server.crt'
$RemoteKey = Join-Path $RemoteTlsDir 'server.key'
$RemoteAgentExe = Join-Path $RemoteDir 'LabLinkAgent.exe'
$LegacyRemoteDir = 'C:\device-interaction'
$ServiceName = 'LabLink Agent'
$PreviousServiceName = 'lablink-agent'
$FirewallRuleName = 'LabLink Agent'
$LegacyFirewallRuleName = 'lablink-agent'

if ($Transport -eq 'insecure') {
    if (-not $AllowInsecure) {
        throw "LabLink's plaintext fallback transport is disabled by default. Re-run with -Transport insecure -AllowInsecure to opt in."
    }
} else {
    foreach ($path in @($TlsCA, $TlsCert, $TlsKey)) {
        if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path $path)) {
            throw "Transport mtls requires existing -TlsCA, -TlsCert, and -TlsKey files."
        }
    }
}

foreach ($machine in $Machines) {
    Write-Host "Deploying to $machine..." -ForegroundColor Cyan

    $session = New-PSSession -ComputerName $machine -Credential $Credential
    try {
        Invoke-Command -Session $session -ScriptBlock {
            param($dir, $tlsDir, $legacyDir, $svcName, $previousSvcName)
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            if (-not (Test-Path $tlsDir)) { New-Item -ItemType Directory -Path $tlsDir -Force | Out-Null }

            # NOTE: device-interaction-agent is intentionally left alone — it
            # predates LabLink and may be owned by other tooling on this host.
            foreach ($name in @($svcName, $previousSvcName)) {
                $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
                if ($svc -and $svc.Status -eq 'Running') {
                    Stop-Service -Name $name -Force
                    Start-Sleep 2
                }
            }

            Get-Process -Name 'LabLinkAgent', 'agent' -ErrorAction SilentlyContinue |
                Where-Object { $_.Path -in @((Join-Path $dir 'LabLinkAgent.exe'), (Join-Path $dir 'agent.exe'), (Join-Path $legacyDir 'agent.exe')) } |
                Stop-Process -Force
        } -ArgumentList $RemoteDir, $RemoteTlsDir, $LegacyRemoteDir, $ServiceName, $PreviousServiceName

        Copy-Item -Path $AgentBinary -Destination $RemoteAgentExe -ToSession $session -Force
        $installScript = Join-Path $PSScriptRoot 'install-agent.ps1'
        if (Test-Path $installScript) {
            Copy-Item -Path $installScript -Destination "$RemoteDir\install-agent.ps1" -ToSession $session -Force
        }

        if ($Transport -eq 'mtls') {
            Copy-Item -Path $TlsCA -Destination $RemoteCA -ToSession $session -Force
            Copy-Item -Path $TlsCert -Destination $RemoteCert -ToSession $session -Force
            Copy-Item -Path $TlsKey -Destination $RemoteKey -ToSession $session -Force
        }

        if ($NoService) {
            Invoke-Command -Session $session -ScriptBlock {
                param($dir, $port, $token, $tokenFile, $transport, $allowInsecure, $tlsCA, $tlsCert, $tlsKey, $fwRuleName, $legacyFwRuleName)
                $exe = Join-Path $dir 'LabLinkAgent.exe'
                $tokenDir = Split-Path -Parent $tokenFile
                if ($tokenDir -and -not (Test-Path $tokenDir)) {
                    New-Item -ItemType Directory -Path $tokenDir -Force | Out-Null
                }
                Set-Content -Path $tokenFile -Value $token -NoNewline -Encoding ascii
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                icacls $tokenFile /inheritance:r /grant:r "${currentUser}:F" 'Administrators:F' 'SYSTEM:F' | Out-Null

                $existing = Get-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue
                if (-not $existing) {
                    $existing = Get-NetFirewallRule -DisplayName $legacyFwRuleName -ErrorAction SilentlyContinue
                }
                if ($existing) {
                    $existing | Get-NetFirewallPortFilter | Set-NetFirewallPortFilter -LocalPort $port
                    $existing | Get-NetFirewallApplicationFilter | Set-NetFirewallApplicationFilter -Program $exe
                } else {
                    New-NetFirewallRule `
                        -DisplayName $fwRuleName `
                        -Description 'Allow inbound gRPC for LabLink agent' `
                        -Direction Inbound -Protocol TCP -LocalPort $port `
                        -Program $exe -Action Allow -Profile Any | Out-Null
                }

                $args = @('--listen', ":$port", '--transport', $transport, '--auth-token-file', $tokenFile)
                if ($transport -eq 'insecure') {
                    if ($allowInsecure) {
                        $args += '--allow-insecure'
                    }
                } else {
                    icacls $tlsKey /inheritance:r /grant:r "${currentUser}:F" 'SYSTEM:F' 'Administrators:F' | Out-Null
                    $args += @('--tls-ca', $tlsCA, '--tls-cert', $tlsCert, '--tls-key', $tlsKey)
                }

                Start-Process -FilePath $exe -ArgumentList $args -WorkingDirectory $dir -WindowStyle Hidden
                Write-Host "  Agent started as detached process" -ForegroundColor Green
            } -ArgumentList $RemoteDir, $Port, $Token, $RemoteTokenFile, $Transport, [bool]$AllowInsecure, $RemoteCA, $RemoteCert, $RemoteKey, $FirewallRuleName, $LegacyFirewallRuleName
        } else {
            Invoke-Command -Session $session -ScriptBlock {
                param($dir, $token, $tokenFile, $port, $transport, $allowInsecure, $tlsCA, $tlsCert, $tlsKey)
                $script = Join-Path $dir 'install-agent.ps1'
                $params = @{
                    Token = $token
                    TokenFile = $tokenFile
                    Port = $port
                    AgentDir = $dir
                    Transport = $transport
                }
                if ($transport -eq 'insecure') {
                    if ($allowInsecure) {
                        $params.AllowInsecure = $true
                    }
                } else {
                    $params.TlsCA = $tlsCA
                    $params.TlsCert = $tlsCert
                    $params.TlsKey = $tlsKey
                }

                & $script @params
            } -ArgumentList $RemoteDir, $Token, $RemoteTokenFile, $Port, $Transport, [bool]$AllowInsecure, $RemoteCA, $RemoteCert, $RemoteKey
        }
    }
    finally {
        Remove-PSSession $session
    }
}

Write-Host "`nDeployment complete." -ForegroundColor Green
