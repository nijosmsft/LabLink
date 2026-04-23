<#
.SYNOPSIS
    Prepare a local LabLink operator workstation for AI infrastructure.

.DESCRIPTION
    Initializes a local PKI, issues an mTLS client certificate, creates a shared
    auth token file, and writes an MCP config snippet that can be copied into an
    AI client's `.mcp.json`.
#>
param(
    [string]$HomeDir = (Join-Path $HOME '.lablink'),

    [string]$PkiDir,

    [string]$ClientName = 'default',

    [string]$TokenFile,

    [string]$McpConfigOut,

    [string]$ServerBinary = "$PSScriptRoot\..\bin\LabLinkServer.exe",

    [string]$CaBinary = "$PSScriptRoot\..\bin\lablink-ca.exe",

    [switch]$RotateClientCert,

    [switch]$RotateToken
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($PkiDir)) {
    $PkiDir = Join-Path $HomeDir 'pki'
}
if ([string]::IsNullOrWhiteSpace($TokenFile)) {
    $TokenFile = Join-Path $HomeDir 'agent.token'
}
if ([string]::IsNullOrWhiteSpace($McpConfigOut)) {
    $McpConfigOut = Join-Path $HomeDir 'mcp.example.json'
}

$clientDir = Join-Path $PkiDir "clients\$ClientName"
$caBundle = Join-Path $PkiDir 'ca-bundle\ca.crt'
$clientCert = Join-Path $clientDir 'client.crt'
$clientKey = Join-Path $clientDir 'client.key'

function New-LabLinkToken {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    return [Convert]::ToBase64String($bytes)
}

function Protect-LabLinkSecretFile {
    param([Parameter(Mandatory)][string]$Path)

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    icacls $Path /inheritance:r /grant:r "${currentUser}:F" 'Administrators:F' 'SYSTEM:F' | Out-Null
}

foreach ($path in @($ServerBinary, $CaBinary)) {
    if (-not (Test-Path $path)) {
        throw "Required binary not found: $path"
    }
}

foreach ($path in @($HomeDir, $PkiDir, $clientDir, (Split-Path -Parent $TokenFile), (Split-Path -Parent $McpConfigOut))) {
    if ($path -and -not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}

if (-not (Test-Path $caBundle)) {
    Write-Host "Initializing local LabLink PKI..." -ForegroundColor Cyan
    & $CaBinary init -pki-dir $PkiDir
}

if ($RotateClientCert -or -not (Test-Path $clientCert) -or -not (Test-Path $clientKey)) {
    Write-Host "Issuing operator client certificate '$ClientName'..." -ForegroundColor Cyan
    & $CaBinary issue-client -pki-dir $PkiDir -name $ClientName
    if ($LASTEXITCODE -ne 0) {
        throw "lablink-ca issue-client failed (exit code $LASTEXITCODE)"
    }
}
if (Test-Path $clientKey) {
    Protect-LabLinkSecretFile -Path $clientKey
}

if ($RotateToken -or -not (Test-Path $TokenFile)) {
    Write-Host "Generating shared auth token..." -ForegroundColor Cyan
    Set-Content -Path $TokenFile -Value (New-LabLinkToken) -NoNewline -Encoding ascii
}
Protect-LabLinkSecretFile -Path $TokenFile

$mcpConfig = [ordered]@{
    mcpServers = [ordered]@{
        lablink = [ordered]@{
            type = 'stdio'
            command = (Resolve-Path $ServerBinary).Path
            env = [ordered]@{
                LABLINK_AGENT_TOKEN_FILE = (Resolve-Path $TokenFile).Path
                LABLINK_TRANSPORT = 'mtls'
                LABLINK_TLS_CA = (Resolve-Path $caBundle).Path
                LABLINK_TLS_CERT = (Resolve-Path $clientCert).Path
                LABLINK_TLS_KEY = (Resolve-Path $clientKey).Path
            }
        }
    }
}

$mcpConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $McpConfigOut -Encoding utf8

Write-Host "`nLabLink operator bootstrap complete." -ForegroundColor Green
Write-Host "  PKI Dir:        $PkiDir" -ForegroundColor DarkGray
Write-Host "  CA Bundle:      $caBundle" -ForegroundColor DarkGray
Write-Host "  Client Cert:    $clientCert" -ForegroundColor DarkGray
Write-Host "  Client Key:     $clientKey" -ForegroundColor DarkGray
Write-Host "  Token File:     $TokenFile" -ForegroundColor DarkGray
Write-Host "  MCP Snippet:    $McpConfigOut" -ForegroundColor DarkGray
Write-Host "`nNext step: run scripts\bootstrap-windows-node.ps1 for your first Windows node." -ForegroundColor Cyan
