<#
.SYNOPSIS
    Bootstrap one or more Windows nodes for LabLink.

.DESCRIPTION
    Ensures local operator assets exist (PKI, token, MCP snippet), then for
    each machine: issues a server certificate, deploys lablink-agent.exe over
    WinRM with mTLS, verifies the node with lablink-probe.exe when available,
    and pre-registers it in ~\.lablink\nodes.json. Runs sequentially. A
    failure on one node is reported but does not stop subsequent nodes.

.PARAMETER Machine
    One or more machine names reachable over WinRM. The same name is used
    for the node entry and the TLS SAN unless -NodeName / -TlsServerName
    overrides are supplied.

.PARAMETER IPv4Address
    Optional, one entry per -Machine (positionally aligned). If omitted for
    a machine, its IPv4 address is resolved via DNS.

.PARAMETER NodeName
    Optional, one entry per -Machine. Defaults to the machine name.

.PARAMETER TlsServerName
    Optional, one entry per -Machine. Defaults to the node name.
#>
param(
    [Parameter(Mandatory)]
    [string[]]$Machine,

    [Alias('Address')]
    [string[]]$IPv4Address,

    [string[]]$NodeName,

    [string]$Role = 'server',

    [PSCredential]$Credential,

    [int]$Port = 9091,

    [string[]]$TlsServerName,

    [string]$HomeDir = (Join-Path $HOME '.lablink'),

    [string]$PkiDir,

    [string]$ClientName = 'default',

    [string]$TokenFile,

    [string]$McpConfigOut,

    [string]$NodesFile,

    [string]$AgentBinary = "$PSScriptRoot\..\bin\lablink-agent.exe",

    [string]$CaBinary = "$PSScriptRoot\..\bin\lablink-ca.exe",

    [string]$ProbeBinary = "$PSScriptRoot\..\bin\lablink-probe.exe",

    [switch]$RotateServerCert,

    [switch]$RotateToken,

    [switch]$SkipRegister,

    # When set, do NOT touch WinRM. Instead build a hand-carry install
    # package per machine (delegates to build-manual-package.ps1).
    [switch]$Manual,

    [string]$ManualOutDir,

    [switch]$ManualNoZip
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
if ([string]::IsNullOrWhiteSpace($NodesFile)) {
    $NodesFile = Join-Path $HomeDir 'nodes.json'
}

# Validate per-machine list lengths up front so the caller catches mistakes
# before we touch anything remote.
function Test-AlignedList {
    param([string]$Name, [string[]]$Values, [int]$Expected)
    if ($Values -and $Values.Count -gt 0 -and $Values.Count -ne $Expected) {
        throw "$Name has $($Values.Count) entries but $Expected machines were specified."
    }
}
Test-AlignedList 'IPv4Address'   $IPv4Address   $Machine.Count
Test-AlignedList 'NodeName'      $NodeName      $Machine.Count
Test-AlignedList 'TlsServerName' $TlsServerName $Machine.Count

# In manual mode we hand off entirely to build-manual-package.ps1: no WinRM
# credential, no remote deploy, no probe. The package builder reuses the same
# operator bootstrap, signs server certs from the same PKI, and writes to the
# same nodes.json so the experience converges with the WinRM path once the
# remote owner runs install.ps1.
if ($Manual) {
    $builder = Join-Path $PSScriptRoot 'build-manual-package.ps1'
    if (-not (Test-Path $builder)) {
        throw "Required file not found: $builder"
    }
    $builderArgs = @{
        Machine    = $Machine
        Role       = $Role
        Port       = $Port
        HomeDir    = $HomeDir
        PkiDir     = $PkiDir
        ClientName = $ClientName
        TokenFile  = $TokenFile
        NodesFile  = $NodesFile
        AgentBinary = $AgentBinary
        CaBinary    = $CaBinary
    }
    if ($IPv4Address)   { $builderArgs.IPv4Address   = $IPv4Address }
    if ($NodeName)      { $builderArgs.NodeName      = $NodeName }
    if ($TlsServerName) { $builderArgs.TlsServerName = $TlsServerName }
    if ($ManualOutDir)  { $builderArgs.OutDir        = $ManualOutDir }
    if ($RotateServerCert) { $builderArgs.RotateServerCert = $true }
    if ($RotateToken)      { $builderArgs.RotateToken      = $true }
    if ($SkipRegister)     { $builderArgs.NoRegister       = $true }
    if ($ManualNoZip)      { $builderArgs.NoZip            = $true }
    & $builder @builderArgs
    exit $LASTEXITCODE
}

if (-not $Credential) {
    $msg = if ($Machine.Count -eq 1) {
        "Enter the WinRM credential for $($Machine[0])"
    } else {
        "Enter the shared WinRM credential for $($Machine.Count) machines"
    }
    $Credential = Get-Credential -Message $msg
}

foreach ($path in @(
        $AgentBinary,
        $CaBinary,
        (Join-Path $PSScriptRoot 'bootstrap-operator.ps1'),
        (Join-Path $PSScriptRoot 'deploy-agent.ps1')
)) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

# Shared, once-only operator bootstrap.
$bootstrapOperatorArgs = @{
    HomeDir      = $HomeDir
    PkiDir       = $PkiDir
    ClientName   = $ClientName
    TokenFile    = $TokenFile
    McpConfigOut = $McpConfigOut
}
if ($RotateToken) {
    $bootstrapOperatorArgs.RotateToken = $true
}
& (Join-Path $PSScriptRoot 'bootstrap-operator.ps1') @bootstrapOperatorArgs

$caBundle   = Join-Path $PkiDir 'ca-bundle\ca.crt'
$clientCert = Join-Path $PkiDir "clients\$ClientName\client.crt"
$clientKey  = Join-Path $PkiDir "clients\$ClientName\client.key"

$token = (Get-Content $TokenFile -Raw).Trim()
if ([string]::IsNullOrWhiteSpace($token)) {
    throw "Token file $TokenFile is empty."
}

$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Load nodes.json once; updated in memory per node and saved at the end.
$registryData = $null
if (-not $SkipRegister) {
    $nodesDir = Split-Path -Parent $NodesFile
    if ($nodesDir -and -not (Test-Path $nodesDir)) {
        New-Item -ItemType Directory -Path $nodesDir -Force | Out-Null
    }
    if (Test-Path $NodesFile) {
        $registryData = Get-Content $NodesFile -Raw | ConvertFrom-Json -Depth 20
    } else {
        $registryData = [pscustomobject]@{}
    }
    foreach ($key in @('nodes', 'topologies', 'node_contexts')) {
        if (-not $registryData.PSObject.Properties[$key]) {
            Add-Member -InputObject $registryData -MemberType NoteProperty -Name $key -Value ([pscustomobject]@{})
        }
    }
}

$results = @()

for ($i = 0; $i -lt $Machine.Count; $i++) {
    $machineName = $Machine[$i]

    # NOTE: PowerShell variables are case-insensitive, so loop locals MUST NOT
    # collide with [string[]] parameters above (e.g. $nodeName vs $NodeName)
    # or assignments are coerced back into String[] and downstream cmdlets
    # like Add-Member -Name fail with "Cannot convert 'String[]' to 'String'".
    $node = if ($NodeName -and $NodeName.Count -gt $i -and -not [string]::IsNullOrWhiteSpace($NodeName[$i])) {
        $NodeName[$i]
    } else { $machineName }

    $tls = if ($TlsServerName -and $TlsServerName.Count -gt $i -and -not [string]::IsNullOrWhiteSpace($TlsServerName[$i])) {
        $TlsServerName[$i]
    } else { $node }

    $ipv4 = if ($IPv4Address -and $IPv4Address.Count -gt $i -and -not [string]::IsNullOrWhiteSpace($IPv4Address[$i])) {
        $IPv4Address[$i]
    } else { $null }

    Write-Host ""
    Write-Host "=== [$($i + 1)/$($Machine.Count)] $machineName ===" -ForegroundColor Yellow

    try {
        if ([string]::IsNullOrWhiteSpace($ipv4)) {
            Write-Host "Resolving IPv4 address for $machineName..." -ForegroundColor Cyan
            $resolved = $null
            try {
                $resolved = Resolve-DnsName -Name $machineName -Type A -ErrorAction Stop |
                    Where-Object { $_.IPAddress } |
                    Select-Object -First 1
            } catch {}
            if (-not $resolved) {
                throw "Could not resolve an IPv4 address for '$machineName'. Pass -IPv4Address."
            }
            $ipv4 = $resolved.IPAddress
            Write-Host "  Resolved $machineName -> $ipv4" -ForegroundColor DarkGray
        }

        $serverDir  = Join-Path $PkiDir "issued\servers\$node"
        $serverCsr  = Join-Path $serverDir 'server.csr'
        $serverKey  = Join-Path $serverDir 'server.key'
        $serverCert = Join-Path $serverDir 'server.crt'

        if (-not (Test-Path $serverDir)) {
            New-Item -ItemType Directory -Path $serverDir -Force | Out-Null
        }
        if ($RotateServerCert) {
            Remove-Item $serverCsr, $serverKey, $serverCert -ErrorAction SilentlyContinue
        }

        if (-not (Test-Path $serverCsr) -or -not (Test-Path $serverKey)) {
            Write-Host "Generating server CSR for $node..." -ForegroundColor Cyan
            & $AgentBinary --generate-server-csr --tls-server-name $tls --csr-out $serverCsr --key-out $serverKey
            if ($LASTEXITCODE -ne 0) { throw "LabLinkAgent --generate-server-csr failed (exit $LASTEXITCODE)" }
        }
        icacls $serverKey /inheritance:r /grant:r "${currentUser}:F" 'Administrators:F' 'SYSTEM:F' | Out-Null

        if (-not (Test-Path $serverCert)) {
            Write-Host "Signing server certificate for $node..." -ForegroundColor Cyan
            & $CaBinary sign-server-csr -pki-dir $PkiDir -csr $serverCsr -cert-out $serverCert
            if ($LASTEXITCODE -ne 0) { throw "lablink-ca sign-server-csr failed (exit $LASTEXITCODE)" }
        }

        Write-Host "Deploying LabLink Agent to $machineName..." -ForegroundColor Cyan
        & (Join-Path $PSScriptRoot 'deploy-agent.ps1') `
            -Machines $machineName `
            -AgentBinary $AgentBinary `
            -Token $token `
            -Port $Port `
            -Credential $Credential `
            -Transport mtls `
            -TlsCA $caBundle `
            -TlsCert $serverCert `
            -TlsKey $serverKey
        if ($LASTEXITCODE -ne 0) { throw "deploy-agent failed (exit $LASTEXITCODE)" }

        $resolvedAddress = if ($ipv4 -match ':\d+$') { $ipv4 } else { "${ipv4}:$Port" }

        if (Test-Path $ProbeBinary) {
            Write-Host "Verifying $resolvedAddress with lablink-probe.exe..." -ForegroundColor Cyan
            $oldTokenFile  = $env:LABLINK_AGENT_TOKEN_FILE
            $oldTransport  = $env:LABLINK_TRANSPORT
            $oldCA         = $env:LABLINK_TLS_CA
            $oldCert       = $env:LABLINK_TLS_CERT
            $oldKey        = $env:LABLINK_TLS_KEY
            $oldServerName = $env:LABLINK_TLS_SERVER_NAME
            try {
                $env:LABLINK_AGENT_TOKEN_FILE = $TokenFile
                $env:LABLINK_TRANSPORT        = 'mtls'
                $env:LABLINK_TLS_CA           = $caBundle
                $env:LABLINK_TLS_CERT         = $clientCert
                $env:LABLINK_TLS_KEY          = $clientKey
                $env:LABLINK_TLS_SERVER_NAME  = $tls
                & $ProbeBinary $resolvedAddress
                if ($LASTEXITCODE -ne 0) { throw "LabLinkProbe failed (exit $LASTEXITCODE)" }
            } finally {
                $env:LABLINK_AGENT_TOKEN_FILE = $oldTokenFile
                $env:LABLINK_TRANSPORT        = $oldTransport
                $env:LABLINK_TLS_CA           = $oldCA
                $env:LABLINK_TLS_CERT         = $oldCert
                $env:LABLINK_TLS_KEY          = $oldKey
                $env:LABLINK_TLS_SERVER_NAME  = $oldServerName
            }
        }

        if (-not $SkipRegister) {
            $existing = $registryData.nodes.PSObject.Properties[$node]
            $nodeEntry = [ordered]@{}
            if ($existing -and $existing.Value) {
                foreach ($prop in $existing.Value.PSObject.Properties) {
                    $nodeEntry[$prop.Name] = $prop.Value
                }
            }
            $nodeEntry['name']            = $node
            $nodeEntry['address']         = $resolvedAddress
            if (-not [string]::IsNullOrWhiteSpace($Role)) {
                $nodeEntry['role']        = $Role
            }
            $nodeEntry['transport_mode']  = 'mtls'
            $nodeEntry['tls_server_name'] = $tls
            Add-Member -InputObject $registryData.nodes -MemberType NoteProperty -Name $node -Value ([pscustomobject]$nodeEntry) -Force
        }

        $results += [pscustomobject]@{
            Machine = $machineName
            Node    = $node
            Address = $resolvedAddress
            Status  = 'OK'
            Error   = ''
        }
    } catch {
        Write-Host "FAILED: $machineName -> $($_.Exception.Message)" -ForegroundColor Red
        $results += [pscustomobject]@{
            Machine = $machineName
            Node    = $node
            Address = ''
            Status  = 'FAILED'
            Error   = $_.Exception.Message
        }
    }
}

if (-not $SkipRegister) {
    $registryData | ConvertTo-Json -Depth 20 | Set-Content -Path $NodesFile -Encoding utf8
}

Write-Host ""
Write-Host "LabLink node bootstrap summary:" -ForegroundColor Green
$results | Format-Table Machine, Node, Address, Status, Error -AutoSize | Out-Host

$ok     = ($results | Where-Object Status -eq 'OK').Count
$failed = ($results | Where-Object Status -eq 'FAILED').Count
Write-Host "  Succeeded:       $ok"     -ForegroundColor DarkGray
Write-Host "  Failed:          $failed" -ForegroundColor DarkGray
Write-Host "  Token File:      $TokenFile"   -ForegroundColor DarkGray
Write-Host "  MCP Snippet:     $McpConfigOut" -ForegroundColor DarkGray
if (-not $SkipRegister) {
    Write-Host "  Nodes Registry:  $NodesFile" -ForegroundColor DarkGray
}

if ($failed -gt 0) {
    exit 1
}
