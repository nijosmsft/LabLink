<#
.SYNOPSIS
    Build a self-contained, hand-carry install package for one or more LabLink
    nodes that cannot be reached from the operator over WinRM.

.DESCRIPTION
    For each machine, this script (running on the operator):
      1. Issues a server certificate signed by the local LabLink CA.
      2. Assembles a per-node directory containing the agent binary, the CA
         bundle, the server cert + key, the auth token, and a one-shot
         install.ps1 that wires them together via install-agent.ps1.
      3. Optionally zips each per-node directory.
      4. Optionally pre-registers the node in the operator's nodes.json so it
         is recognized by the MCP server as soon as the remote install
         finishes.

    Hand the resulting zip (or directory) to whoever owns the remote machine.
    They copy it to the node, extract it somewhere with admin rights, and run
    install.ps1 as Administrator. No WinRM, no shared credential, no remote
    PowerShell. The operator never needs to touch the node directly.

.PARAMETER Machine
    One or more machine names (or IPs) used to label the per-node packages.
    The first entry is also the default for -NodeName and -TlsServerName.

.PARAMETER IPv4Address
    Optional, one entry per -Machine (positionally aligned). When omitted, the
    script tries to resolve each machine over DNS so it can populate the
    nodes.json entry. If neither resolves nor is provided, the address field
    is left blank in metadata.json and the operator must fill it in later.

.PARAMETER NodeName
    Optional, one entry per -Machine. Defaults to the machine name. Becomes
    the directory name and the registry key.

.PARAMETER TlsServerName
    Optional, one entry per -Machine. Defaults to the node name. Embedded as
    the SAN of the server certificate the agent presents.

.PARAMETER OutDir
    Where the per-node packages are written. Defaults to ~/.lablink/manual.

.PARAMETER Zip
    When set (default), each per-node directory is also zipped to
    <OutDir>\<node>.zip for easy hand-off.

.PARAMETER NoRegister
    Skip pre-registration in nodes.json. By default the operator's nodes.json
    is updated so the node is recognized immediately after the remote install
    completes.

.EXAMPLE
    # Build packages for two air-gapped client nodes.
    .\scripts\build-manual-package.ps1 -Machine WIN-NODE-01,WIN-NODE-02 -Role client

    # Operator hands lablink-WIN-NODE-01.zip to the owner of WIN-NODE-01.
    # Owner extracts it on the node and runs:
    #   .\install.ps1
#>
param(
    [Parameter(Mandatory)]
    [string[]]$Machine,

    [Alias('Address')]
    [string[]]$IPv4Address,

    [string[]]$NodeName,

    [string[]]$TlsServerName,

    [string]$Role = 'server',

    [int]$Port = 9091,

    [string]$HomeDir = (Join-Path $HOME '.lablink'),

    [string]$PkiDir,

    [string]$ClientName = 'default',

    [string]$TokenFile,

    [string]$NodesFile,

    [string]$OutDir,

    [string]$AgentBinary = "$PSScriptRoot\..\bin\lablink-agent.exe",

    [string]$CaBinary = "$PSScriptRoot\..\bin\lablink-ca.exe",

    [string]$InstallScript = "$PSScriptRoot\install-agent.ps1",

    [switch]$RotateServerCert,

    [switch]$RotateToken,

    [switch]$NoZip,

    [switch]$NoRegister
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($PkiDir))    { $PkiDir    = Join-Path $HomeDir 'pki' }
if ([string]::IsNullOrWhiteSpace($TokenFile)) { $TokenFile = Join-Path $HomeDir 'agent.token' }
if ([string]::IsNullOrWhiteSpace($NodesFile)) { $NodesFile = Join-Path $HomeDir 'nodes.json' }
if ([string]::IsNullOrWhiteSpace($OutDir))    { $OutDir    = Join-Path $HomeDir 'manual' }

function Test-AlignedList {
    param([string]$Name, [string[]]$Values, [int]$Expected)
    if ($Values -and $Values.Count -gt 0 -and $Values.Count -ne $Expected) {
        throw "$Name has $($Values.Count) entries but $Expected machines were specified."
    }
}
Test-AlignedList 'IPv4Address'   $IPv4Address   $Machine.Count
Test-AlignedList 'NodeName'      $NodeName      $Machine.Count
Test-AlignedList 'TlsServerName' $TlsServerName $Machine.Count

foreach ($path in @($AgentBinary, $CaBinary, $InstallScript,
                    (Join-Path $PSScriptRoot 'bootstrap-operator.ps1'))) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

# Make sure CA + token + operator MCP snippet exist before we cut server certs.
$bootstrapOperatorArgs = @{
    HomeDir    = $HomeDir
    PkiDir     = $PkiDir
    ClientName = $ClientName
    TokenFile  = $TokenFile
}
if ($RotateToken) { $bootstrapOperatorArgs.RotateToken = $true }
& (Join-Path $PSScriptRoot 'bootstrap-operator.ps1') @bootstrapOperatorArgs | Out-Null

$caBundle = Join-Path $PkiDir 'ca-bundle\ca.crt'
foreach ($must in @($caBundle, $TokenFile)) {
    if (-not (Test-Path $must)) { throw "Required operator asset missing: $must" }
}

$token = (Get-Content $TokenFile -Raw).Trim()
if ([string]::IsNullOrWhiteSpace($token)) {
    throw "Token file $TokenFile is empty."
}

if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

$registryData = $null
if (-not $NoRegister) {
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

    # See bootstrap-windows-node.ps1: do NOT name these the same as the
    # [string[]] parameters or PowerShell's case-insensitive variables will
    # coerce them back into String[] and break Add-Member -Name.
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
            try {
                $resolved = Resolve-DnsName -Name $machineName -Type A -ErrorAction Stop |
                    Where-Object { $_.IPAddress } | Select-Object -First 1
                if ($resolved) { $ipv4 = $resolved.IPAddress }
            } catch {}
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
            if ($LASTEXITCODE -ne 0) { throw "lablink-agent --generate-server-csr failed (exit $LASTEXITCODE)" }
        }

        if (-not (Test-Path $serverCert)) {
            Write-Host "Signing server certificate for $node..." -ForegroundColor Cyan
            & $CaBinary sign-server-csr -pki-dir $PkiDir -csr $serverCsr -cert-out $serverCert
            if ($LASTEXITCODE -ne 0) { throw "lablink-ca sign-server-csr failed (exit $LASTEXITCODE)" }
        }

        # Assemble the per-node package directory.
        $packageDir = Join-Path $OutDir $node
        if (Test-Path $packageDir) {
            Remove-Item $packageDir -Recurse -Force
        }
        New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
        $tlsDir = Join-Path $packageDir 'tls'
        New-Item -ItemType Directory -Path $tlsDir -Force | Out-Null

        Copy-Item $AgentBinary  (Join-Path $packageDir 'lablink-agent.exe') -Force
        Copy-Item $InstallScript (Join-Path $packageDir 'install-agent.ps1') -Force
        $updateScriptPath = Join-Path $PSScriptRoot 'Update-LabLink.ps1'
        if (Test-Path $updateScriptPath) {
            $dst = Join-Path $packageDir 'Update-LabLink.ps1'
            Copy-Item $updateScriptPath $dst -Force
            if (-not (Test-Path $dst)) { throw "post-copy verify failed: $dst" }
        }
        Copy-Item $caBundle     (Join-Path $tlsDir 'ca.crt')    -Force
        Copy-Item $serverCert   (Join-Path $tlsDir 'server.crt') -Force
        Copy-Item $serverKey    (Join-Path $tlsDir 'server.key') -Force
        Set-Content -Path (Join-Path $packageDir 'agent.token') -Value $token -NoNewline -Encoding ascii

        $address = if ([string]::IsNullOrWhiteSpace($ipv4)) { '' } elseif ($ipv4 -match ':\d+$') { $ipv4 } else { "${ipv4}:$Port" }
        $metadata = [ordered]@{
            schema_version  = 1
            node            = $node
            machine         = $machineName
            address         = $address
            port            = $Port
            transport_mode  = 'mtls'
            tls_server_name = $tls
            role            = $Role
            generated_at    = (Get-Date).ToString('o')
        }
        $metadata | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $packageDir 'metadata.json') -Encoding utf8

        # install.ps1 is a tiny wrapper around install-agent.ps1 that uses the
        # files bundled in the package. Operators do not have to remember any
        # paths or flags on the node side.
        $installWrapper = @'
<#
LabLink manual install wrapper.

Run this as Administrator on the node. It expects the package layout that
build-manual-package.ps1 produced (lablink-agent.exe, install-agent.ps1,
agent.token, tls\ca.crt, tls\server.crt, tls\server.key, metadata.json all
sitting next to this script).
#>
param(
    [string]$AgentDir = 'C:\LabLink',
    [int]$Port,
    [switch]$KeepBundleInPlace
)

$ErrorActionPreference = 'Stop'
$pkgRoot = $PSScriptRoot

$metaPath = Join-Path $pkgRoot 'metadata.json'
if (-not (Test-Path $metaPath)) {
    throw "metadata.json not found next to install.ps1 (looked in $pkgRoot)."
}
$meta = Get-Content $metaPath -Raw | ConvertFrom-Json
if (-not $Port) { $Port = [int]$meta.port }

# Mirror the bundled assets into AgentDir so install-agent.ps1 (which expects
# C:\LabLink\... by default) finds them where it expects them.
if (-not (Test-Path $AgentDir)) { New-Item -ItemType Directory -Path $AgentDir -Force | Out-Null }
$tlsDest = Join-Path $AgentDir 'tls'
if (-not (Test-Path $tlsDest)) { New-Item -ItemType Directory -Path $tlsDest -Force | Out-Null }

Copy-Item (Join-Path $pkgRoot 'lablink-agent.exe') (Join-Path $AgentDir 'lablink-agent.exe') -Force
$updateSrc = Join-Path $pkgRoot 'Update-LabLink.ps1'
if (Test-Path $updateSrc) {
    Copy-Item $updateSrc (Join-Path $AgentDir 'Update-LabLink.ps1') -Force
}
Copy-Item (Join-Path $pkgRoot 'tls\ca.crt')      (Join-Path $tlsDest 'ca.crt')    -Force
Copy-Item (Join-Path $pkgRoot 'tls\server.crt')  (Join-Path $tlsDest 'server.crt') -Force
Copy-Item (Join-Path $pkgRoot 'tls\server.key')  (Join-Path $tlsDest 'server.key') -Force

$tokenPath = Join-Path $pkgRoot 'agent.token'
if (-not (Test-Path $tokenPath)) { throw "agent.token missing from package." }
$token = (Get-Content $tokenPath -Raw).Trim()
if ([string]::IsNullOrWhiteSpace($token)) { throw "agent.token is empty." }

& (Join-Path $pkgRoot 'install-agent.ps1') `
    -Token $token `
    -Port $Port `
    -AgentDir $AgentDir `
    -TokenFile (Join-Path $AgentDir 'agent.token') `
    -Transport mtls `
    -TlsCA (Join-Path $tlsDest 'ca.crt') `
    -TlsCert (Join-Path $tlsDest 'server.crt') `
    -TlsKey (Join-Path $tlsDest 'server.key')

if ($LASTEXITCODE -ne 0) { throw "install-agent.ps1 failed (exit $LASTEXITCODE)" }

if (-not $KeepBundleInPlace) {
    # The token and key were copied to AgentDir with restricted ACLs by
    # install-agent.ps1; the bundle copy is now redundant and worth deleting.
    Remove-Item (Join-Path $pkgRoot 'agent.token')      -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $pkgRoot 'tls\server.key')   -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "LabLink agent install complete." -ForegroundColor Green
Write-Host "  Node:    $($meta.node)"
Write-Host "  Listen:  :$Port (mTLS)"
Write-Host "  AgentDir: $AgentDir"
Write-Host ""
Write-Host "Tell the operator the node is ready. They can verify with lablink-probe.exe."
'@
        Set-Content -Path (Join-Path $packageDir 'install.ps1') -Value $installWrapper -Encoding utf8

        $readme = @"
LabLink manual install package
==============================

Node:            $node
Machine:         $machineName
Listen address:  $(if ($address) { $address } else { "(unknown — operator must register manually)" })
Transport:       mTLS
Generated:       $($metadata.generated_at)

How to install (run on the remote machine, as Administrator):

  1. Extract this archive somewhere with write access (e.g. C:\Temp\lablink).
  2. Open an elevated PowerShell prompt in that directory.
  3. Run:  .\install.ps1
     - Use -AgentDir <path> to install somewhere other than C:\LabLink.
     - Use -Port <n>           to override the bundled port ($Port).

The script copies lablink-agent.exe + the TLS material into AgentDir, writes
the auth token with restricted ACLs, installs the Windows service, opens the
firewall, and starts it. After it succeeds, tell the operator; they can
verify with lablink-probe.exe and the node will already be registered in
their nodes.json.

Files in this package:
  lablink-agent.exe       Agent binary (Windows amd64)
  install.ps1             One-shot installer (run this)
  install-agent.ps1       Underlying installer (called by install.ps1)
  Update-LabLink.ps1      Upgrade helper; run on the node to update the agent
  agent.token             Pre-shared bearer token (deleted after install)
  tls\ca.crt              Operator CA bundle
  tls\server.crt          Server certificate signed by the operator CA
  tls\server.key          Server private key (deleted after install)
  metadata.json           Node identity (used by install.ps1 + the operator)

After installation succeeds you can safely delete the extracted directory.
"@
        Set-Content -Path (Join-Path $packageDir 'README.txt') -Value $readme -Encoding utf8

        $zipPath = $null
        if (-not $NoZip) {
            $zipPath = Join-Path $OutDir "lablink-$node.zip"
            if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
            Compress-Archive -Path (Join-Path $packageDir '*') -DestinationPath $zipPath -Force
        }

        if (-not $NoRegister) {
            $existing = $registryData.nodes.PSObject.Properties[$node]
            $nodeEntry = [ordered]@{}
            if ($existing -and $existing.Value) {
                foreach ($prop in $existing.Value.PSObject.Properties) {
                    $nodeEntry[$prop.Name] = $prop.Value
                }
            }
            $nodeEntry['name']            = $node
            if ($address) { $nodeEntry['address'] = $address }
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
            Address = $address
            Package = if ($zipPath) { $zipPath } else { $packageDir }
            Status  = 'OK'
            Error   = ''
        }
    } catch {
        Write-Host "FAILED: $machineName -> $($_.Exception.Message)" -ForegroundColor Red
        $results += [pscustomobject]@{
            Machine = $machineName
            Node    = $node
            Address = ''
            Package = ''
            Status  = 'FAILED'
            Error   = $_.Exception.Message
        }
    }
}

if (-not $NoRegister) {
    $registryData | ConvertTo-Json -Depth 20 | Set-Content -Path $NodesFile -Encoding utf8
}

Write-Host ""
Write-Host "LabLink manual package summary:" -ForegroundColor Green
$results | Format-Table Machine, Node, Address, Status, Package, Error -AutoSize | Out-Host

$failed = ($results | Where-Object Status -eq 'FAILED').Count
Write-Host "  Output dir:     $OutDir" -ForegroundColor DarkGray
if (-not $NoRegister) {
    Write-Host "  Nodes Registry: $NodesFile (pre-populated; entries activate once each agent is reachable)" -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "Next: hand each lablink-<node>.zip to the owner of that machine and have them" -ForegroundColor Cyan
Write-Host "      run install.ps1 from an elevated PowerShell. No WinRM access required." -ForegroundColor Cyan

if ($failed -gt 0) { exit 1 }
