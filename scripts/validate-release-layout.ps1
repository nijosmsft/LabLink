[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ReleaseDir,
    [Parameter(Mandatory=$true)][string]$Version
)

$ErrorActionPreference = 'Stop'
$ReleaseDir = (Resolve-Path $ReleaseDir).Path
$windows = Join-Path $ReleaseDir "lablink-$Version-windows-amd64.zip"
$linux = Join-Path $ReleaseDir "lablink-$Version-linux-amd64.zip"
foreach ($archive in @($windows, $linux)) {
    if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
        throw "missing release archive: $archive"
    }
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
function Get-Entries([string]$path) {
    $zip = [IO.Compression.ZipFile]::OpenRead($path)
    try { return @($zip.Entries | ForEach-Object { $_.FullName.Replace('\','/') }) }
    finally { $zip.Dispose() }
}

function Get-EntryBytes([string]$path, [string]$entryName) {
    $zip = [IO.Compression.ZipFile]::OpenRead($path)
    try {
        $entry = $zip.Entries | Where-Object {
            $_.FullName.Replace('\','/') -ceq $entryName
        } | Select-Object -First 1
        if (-not $entry) { throw "$path is missing $entryName" }
        $stream = $entry.Open()
        try {
            $memory = [IO.MemoryStream]::new()
            $stream.CopyTo($memory)
            return $memory.ToArray()
        } finally { $stream.Dispose() }
    } finally { $zip.Dispose() }
}

function Get-BytesSHA256([byte[]]$bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

$windowsEntries = @(Get-Entries $windows)
$linuxEntries = @(Get-Entries $linux)
foreach ($required in @(
    'bin/lablink-server.exe',
    'bin/lablink-agent.exe',
    'bin/lablink-secret.exe',
    'bin/linux-amd64/lablink-agent',
    'configs/vm-defaults.example.json',
    'docs/linux-vm.md'
)) {
    if ($windowsEntries -notcontains $required) {
        throw "Windows archive missing $required"
    }
}
foreach ($required in @(
    'bin/lablink-server',
    'bin/lablink-agent',
    'bin/lablink-secret',
    'bin/lablink-probe',
    'bin/lablink-ca',
    'configs/vm-defaults.example.json',
    'docs/linux-vm.md'
)) {
    if ($linuxEntries -notcontains $required) {
        throw "Linux archive missing $required"
    }
}
if ($linuxEntries | Where-Object { $_ -like 'bin/linux-amd64/*' }) {
    throw 'Linux archive layout unexpectedly contains the Windows guest-payload subdirectory'
}

$windowsGuestAgent = Get-EntryBytes $windows 'bin/linux-amd64/lablink-agent'
$linuxNativeAgent = Get-EntryBytes $linux 'bin/lablink-agent'
$windowsGuestHash = Get-BytesSHA256 $windowsGuestAgent
$linuxNativeHash = Get-BytesSHA256 $linuxNativeAgent
if ($windowsGuestHash -ne $linuxNativeHash) {
    throw "embedded Windows guest agent does not match Linux archive agent: $windowsGuestHash != $linuxNativeHash"
}
$versionBytes = [Text.Encoding]::UTF8.GetBytes($Version)
function Test-ContainsBytes([byte[]]$haystack, [byte[]]$needle) {
    for ($i = 0; $i -le $haystack.Length - $needle.Length; $i++) {
        $match = $true
        for ($j = 0; $j -lt $needle.Length; $j++) {
            if ($haystack[$i + $j] -ne $needle[$j]) { $match = $false; break }
        }
        if ($match) { return $true }
    }
    return $false
}
foreach ($check in @(
    @{ Archive=$windows; Entry='bin/lablink-server.exe' },
    @{ Archive=$windows; Entry='bin/lablink-agent.exe' },
    @{ Archive=$windows; Entry='bin/lablink-probe.exe' },
    @{ Archive=$windows; Entry='bin/lablink-ca.exe' },
    @{ Archive=$windows; Entry='bin/lablink-secret.exe' },
    @{ Archive=$windows; Entry='bin/linux-amd64/lablink-agent' },
    @{ Archive=$linux; Entry='bin/lablink-server' },
    @{ Archive=$linux; Entry='bin/lablink-agent' },
    @{ Archive=$linux; Entry='bin/lablink-probe' },
    @{ Archive=$linux; Entry='bin/lablink-ca' },
    @{ Archive=$linux; Entry='bin/lablink-secret' }
)) {
    $bytes = Get-EntryBytes $check.Archive $check.Entry
    if (-not (Test-ContainsBytes $bytes $versionBytes)) {
        throw "$($check.Entry) does not contain expected version $Version"
    }
}

[pscustomobject]@{
    status = 'ok'
    windows_archive = $windows
    linux_archive = $linux
    windows_linux_agent = 'bin/linux-amd64/lablink-agent'
    linux_agent_sha256 = $linuxNativeHash
    version = $Version
} | ConvertTo-Json -Compress
