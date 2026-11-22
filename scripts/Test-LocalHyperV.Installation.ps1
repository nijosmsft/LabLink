[CmdletBinding()]
param(
    [string]$InstallerPath = (Join-Path $PSScriptRoot 'Install-LocalHyperV.ps1'),
    [string]$TestRoot = (Join-Path $env:ProgramData 'LabLinkInstallerACLTests'),
    [string]$ServiceIdentity = 'NT SERVICE\LabLinkHyperV'
)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $TestRoot){throw 'Use a fresh disposable ACL test directory.'}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($InstallerPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Installer has PowerShell parse errors'}
$definition=$ast.Find({param($n) $n -is [Management.Automation.Language.StringConstantExpressionAst] -and $n.Value -like '*public static class LabLinkAccountRights*'},$true)
if(-not $definition){throw 'Installer account/ACL implementation missing'}
Add-Type -TypeDefinition $definition.Value
$function=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Set-PrivateDirectory'},$true)
if(-not $function){throw 'Installer directory protection function missing'}
. ([scriptblock]::Create($function.Extent.Text))
$script:serviceSid=([Security.Principal.NTAccount]$ServiceIdentity).Translate([Security.Principal.SecurityIdentifier]).Value
$VMRoot=Join-Path $TestRoot 'VMs'
$ImageRoot=Join-Path $TestRoot 'Images'
New-Item -ItemType Directory -Path $TestRoot | Out-Null
$result=[Collections.Generic.List[object]]::new()
try {
    $clean=Join-Path $TestRoot 'clean'
    Set-PrivateDirectory $clean 'F'
    $acl=Get-Acl -LiteralPath $clean
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544'){throw 'Fresh directory owner is not Administrators'}
    $result.Add([pscustomobject]@{test='protected fresh creation';ok=$true})

    Set-PrivateDirectory $ImageRoot 'F'
    $image=Join-Path $ImageRoot 'parent.vhdx'
    New-Item -ItemType File -Path $image | Out-Null
    & icacls.exe $image /grant:r '*S-1-5-83-0:R' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot prepare image reader regression fixture'}
    $operation=Join-Path $ImageRoot 'staging\operation'
    New-Item -ItemType Directory -Path $operation -Force | Out-Null
    & icacls.exe $operation /grant:r '*S-1-3-0:(OI)(CI)(IO)F' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot prepare staging CreatorOwner regression fixture'}
    $disk=Join-Path $operation 'staging.vhdx'
    New-Item -ItemType File -Path $disk | Out-Null
    & icacls.exe $disk /grant:r '*S-1-5-83-0:F' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot prepare operation disk regression fixture'}
    Set-PrivateDirectory $ImageRoot 'F'
    & icacls.exe $image /grant:r '*S-1-5-83-0:W' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot prepare writable image regression fixture'}
    $rejected=$false
    try {Set-PrivateDirectory $ImageRoot 'F'} catch {$rejected=$_.Exception.Message -like '*non-service permissions*'}
    if(-not $rejected){throw 'A VM-writeable approved parent was accepted'}
    $result.Add([pscustomobject]@{test='preserve VM image readers but reject VM image writers';ok=$true})

    $badGrant=Join-Path $TestRoot 'explicit-user-grant'
    New-Item -ItemType Directory -Path $badGrant | Out-Null
    & icacls.exe $badGrant /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-1-0:(OI)(CI)F' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot prepare explicit-ACE regression fixture'}
    $rejected=$false
    try {Set-PrivateDirectory $badGrant 'F'} catch {$rejected=$_.Exception.Message -like '*non-service permissions*'}
    if(-not $rejected){throw 'An explicit Everyone FullControl grant survived setup'}
    $result.Add([pscustomobject]@{test='reject pre-existing explicit untrusted ACE';ok=$true})

    $badOwner=Join-Path $TestRoot 'untrusted-owner'
    New-Item -ItemType Directory -Path $badOwner | Out-Null
    & icacls.exe $badOwner /setowner '*S-1-5-32-545' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot prepare owner regression fixture'}
    $rejected=$false
    try {Set-PrivateDirectory $badOwner 'F'} catch {$rejected=$_.Exception.Message -like '*untrusted account*'}
    if(-not $rejected){throw 'An untrusted existing directory owner survived setup'}
    $result.Add([pscustomobject]@{test='reject pre-created untrusted owner';ok=$true})

    $parent=Join-Path $TestRoot 'replaceable-parent'
    New-Item -ItemType Directory -Path $parent | Out-Null
    & icacls.exe $parent /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-1-0:(DC)' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot prepare writable-parent regression fixture'}
    $rejected=$false
    try {Set-PrivateDirectory (Join-Path $parent 'state') 'F'} catch {$rejected=$_.Exception.Message -like '*replaceable ancestor*'}
    if(-not $rejected){throw 'An untrusted parent DELETE_CHILD grant was accepted'}
    $result.Add([pscustomobject]@{test='reject replaceable ancestor';ok=$true})

    foreach($command in @('"C:\Program Files\LabLinkHyperV\bin\lablink-agent.exe" --hyperv-only','E:\LabLinkHyperV\bin\lablink-agent.exe --hyperv-only')) {
        $executable=[LabLinkAccountRights]::Executable($command)
        if((Split-Path -Leaf $executable) -ine 'lablink-agent.exe'){throw 'Service command-line parsing failed'}
    }
    $result.Add([pscustomobject]@{test='quoted and unquoted service paths';ok=$true})

    $link=Join-Path $TestRoot 'junction'
    New-Item -ItemType Junction -Path $link -Target $clean | Out-Null
    $rejected=$false
    try {Set-PrivateDirectory $link 'F'} catch {$rejected=$_.Exception.Message -like '*reparse point*'}
    if(-not $rejected){throw 'A junction install root was accepted'}
    $result.Add([pscustomobject]@{test='reject reparse-point root';ok=$true})
    (Get-Item -LiteralPath $link -Force).Delete()
    $result | ConvertTo-Json -Compress
} finally {
    if(Test-Path -LiteralPath (Join-Path $TestRoot 'junction')){
        (Get-Item -LiteralPath (Join-Path $TestRoot 'junction') -Force).Delete()
    }
    Remove-Item -LiteralPath $TestRoot -Recurse -Force -ErrorAction Stop
}
