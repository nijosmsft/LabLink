$ErrorActionPreference='Stop'
$installer=Join-Path $PSScriptRoot '..\Install-LocalHyperV.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($installer,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Local Hyper-V installer parse failed'}
foreach($name in @('Get-LabLinkServiceExecutable','Assert-LabLinkHyperVRoots','Assert-LabLinkOperatorIdentity','Set-LabLinkHyperVDefenderExclusions')){
    $definition=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    if(-not $definition){throw "Missing installer helper: $name"}
    . ([scriptblock]::Create($definition.Extent.Text))
}
. (Join-Path $PSScriptRoot '..\Update-LabLink.ps1')

function Assert-Test([bool]$Condition,[string]$Name){
    if(-not $Condition){throw "FAIL: $Name"}
    Write-Output "PASS: $Name"
}

$script:prefs=[pscustomobject]@{ExclusionPath=@('C:\Protected\Code');ExclusionProcess=@()}
$script:additions=0
function Get-MpPreference {
    [CmdletBinding()]param()
    return $script:prefs
}
function Add-MpPreference {
    [CmdletBinding()]param([string]$ExclusionPath,[string]$ExclusionProcess)
    $script:additions++
    if($ExclusionPath){$script:prefs.ExclusionPath+=@($ExclusionPath)}
    if($ExclusionProcess){$script:prefs.ExclusionProcess+=@($ExclusionProcess)}
}
$roots=@('C:\Protected\Code','C:\Protected\Data','E:\VMs','E:\Images')
$agent='C:\Protected\Code\bin\lablink-agent.exe'
Set-LabLinkHyperVDefenderExclusions $roots $agent
Assert-Test ($script:additions -eq 4) 'adds only missing exclusions, including custom data roots'
Set-LabLinkHyperVDefenderExclusions $roots $agent
Assert-Test ($script:additions -eq 4) 'preserves existing/manual exclusions without duplicate additions'
$script:prefs=[pscustomobject]@{ExclusionPath=@();ExclusionProcess=@()}
function Add-MpPreference {
    [CmdletBinding()]param([string]$ExclusionPath,[string]$ExclusionProcess)
}
$rejected=$false
try {Set-LabLinkHyperVDefenderExclusions $roots $agent} catch {$rejected=$_.Exception.Message -like '*not applied*'}
Assert-Test $rejected 'fails explicitly when security policy does not apply exclusions'
Remove-Item Function:\Get-MpPreference
Remove-Item Function:\Add-MpPreference

Assert-LabLinkHyperVRoots 'C:\Protected\Code' 'C:\Protected\Data' 'C:\Protected\Data\VMs' 'C:\Protected\Data\Images'
Assert-Test $true 'accepts separate protected code/data roots'
foreach($invalid in @(
    @('C:\','C:\Data','C:\Data\VMs','C:\Data\Images'),
    @('C:\Code','C:\Code\Data','C:\VMs','C:\Images'),
    @('C:\Code','C:\Data','C:\Data\pki\VMs','C:\Images'),
    @('C:\Code','C:\Data','C:\VMs','C:\VMs\Images')
)){
    $rejected=$false
    try {Assert-LabLinkHyperVRoots @invalid} catch {$rejected=$true}
    Assert-Test $rejected 'rejects unsafe/overlapping managed roots before exclusions'
}
Assert-Test ((Get-LabLinkServiceExecutable '"C:\Program Files\LabLinkHyperV\bin\lablink-agent.exe" --hyperv-only') -eq 'C:\Program Files\LabLinkHyperV\bin\lablink-agent.exe') 'parses quoted protected service path'
Assert-Test ((Get-LabLinkServiceExecutable 'E:\Service\bin\lablink-agent.exe --hyperv-only') -eq 'E:\Service\bin\lablink-agent.exe') 'parses unquoted space-free service path'

function Get-CimInstance {
    [CmdletBinding()]param([string]$ClassName,[string]$Filter)
    return [pscustomobject]@{StartName='NT SERVICE\LabLinkHyperV';PathName='"C:\Program Files\LabLinkHyperV\bin\lablink-agent.exe" --hyperv-only'}
}
$installed=Get-InstalledLocalHyperV
Assert-Test ($installed.AgentPath -eq 'C:\Program Files\LabLinkHyperV\bin\lablink-agent.exe') 'discovers protected service separately from operator'
Remove-Item Function:\Get-CimInstance

function Test-Path {
    [CmdletBinding()]param([string]$LiteralPath)
    throw 'Unexpected protected-directory access'
}
try {
    Assert-Test ((Resolve-LocalHyperVOperatorHome $null '') -eq (Join-Path $HOME '.lablink')) 'operator-only update never probes protected installation record'
    Assert-Test ((Resolve-LocalHyperVOperatorHome $installed 'C:\OriginalOperator') -eq 'C:\OriginalOperator') 'explicit original operator home avoids protected record probing'
} finally {
    Remove-Item Function:\Test-Path
}

$script:stopped=@()
function Get-Process {
    [CmdletBinding()]param([string[]]$Name)
    @(
        [pscustomobject]@{Id=101;Path='C:\LabLink\bin\lablink-server.exe';ProcessName='lablink-server'},
        [pscustomobject]@{Id=102;Path='C:\Program Files\LabLinkHyperV\bin\lablink-agent.exe';ProcessName='lablink-agent'},
        [pscustomobject]@{Id=103;Path='C:\LabLink\bin-other\lablink-server.exe';ProcessName='lablink-server'}
    )
}
function Stop-Process {
    [CmdletBinding()]param([int]$Id,[switch]$Force)
    $script:stopped+=@($Id)
}
function Start-Sleep {param($Seconds)}
Stop-LabLinkProcesses -Force -SkipServiceStop -DestinationDir 'C:\LabLink\bin'
Assert-Test ($script:stopped.Count -eq 1 -and $script:stopped[0] -eq 101) 'operator process stop leaves protected and unrelated agents running'
Remove-Item Function:\Get-Process
Remove-Item Function:\Stop-Process
Remove-Item Function:\Start-Sleep

$fixture=Join-Path $env:TEMP ('lablink-split-update-test-'+[Guid]::NewGuid().ToString('N'))
try {
    $package=Join-Path $fixture 'package'
    $scripts=Join-Path $package 'scripts'
    $destination=Join-Path $fixture 'operator\bin'
    New-Item -ItemType Directory -Path $scripts,$destination,(Join-Path $package 'bin\linux-amd64') -Force|Out-Null
    [IO.File]::WriteAllText((Join-Path $scripts 'Install-LocalHyperV.ps1'),'param($PackageRoot,$OperatorHome);$global:capturedHyperVUpdate=@($PackageRoot,$OperatorHome)')
    [IO.File]::WriteAllText((Join-Path $scripts 'Update-LabLink.ps1'),'updated operator updater')
    [IO.File]::WriteAllText((Join-Path $scripts 'install.ps1'),'updated operator installer')
    [IO.File]::WriteAllText((Join-Path $package 'bin\linux-amd64\lablink-agent'),'linux payload')
    Update-LocalHyperV -PackageRoot $package -OperatorHomePath 'C:\OperatorHome'
    Assert-Test ($global:capturedHyperVUpdate[0] -eq $package -and $global:capturedHyperVUpdate[1] -eq 'C:\OperatorHome') 'service update delegates to new package with original operator home'
    Install-OperatorSupport -PackageRoot $package -DestinationDir $destination
    Assert-Test ((Test-Path -LiteralPath (Join-Path $fixture 'operator\scripts\Install-LocalHyperV.ps1')) -and (Test-Path -LiteralPath (Join-Path $fixture 'operator\scripts\install.ps1')) -and (Test-Path -LiteralPath (Join-Path $destination 'linux-amd64\lablink-agent'))) 'operator update refreshes split-path installers and guest payload'
    $homePath=Join-Path $fixture 'identity-operator'
    $dataPath=Join-Path $fixture 'identity-state'
    New-Item -ItemType Directory -Path (Join-Path $homePath 'pki\ca-bundle'),(Join-Path $dataPath 'tls') -Force|Out-Null
    foreach($path in @((Join-Path $homePath 'agent.token'),(Join-Path $dataPath 'agent.token'))){[IO.File]::WriteAllText($path,'test-identity-token')}
    foreach($path in @((Join-Path $homePath 'pki\ca-bundle\ca.crt'),(Join-Path $dataPath 'tls\ca.crt'))){[IO.File]::WriteAllText($path,'test-public-ca')}
    Assert-LabLinkOperatorIdentity $homePath $dataPath
    [IO.File]::WriteAllText((Join-Path $homePath 'agent.token'),'different-test-token')
    $rejected=$false
    try {Assert-LabLinkOperatorIdentity $homePath $dataPath} catch {$rejected=$_.Exception.Message -like '*does not match*'}
    Assert-Test $rejected 'rejects unintended operator identity replacement'
} finally {
    Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction Stop
    Remove-Variable capturedHyperVUpdate -Scope Global -ErrorAction SilentlyContinue
}
