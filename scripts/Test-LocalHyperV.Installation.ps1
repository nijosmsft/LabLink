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
if($ServiceIdentity -like 'NT SERVICE\*'){
    $sidOutput=& sc.exe showsid $ServiceIdentity.Substring(11)
    if($LASTEXITCODE -ne 0){throw 'Cannot derive the test virtual-service SID'}
    $match=[regex]::Match(($sidOutput -join "`n"),'S-1-5-80(?:-\d+){5}')
    if(-not $match.Success){throw 'Test virtual-service SID missing'}
    $script:serviceSid=$match.Value
}else{
    $script:serviceSid=([Security.Principal.NTAccount]$ServiceIdentity).Translate([Security.Principal.SecurityIdentifier]).Value
}
$VMRoot=Join-Path $TestRoot 'VMs'
$ImageRoot=Join-Path $TestRoot 'Images'
New-Item -ItemType Directory -Path $TestRoot | Out-Null
$result=[Collections.Generic.List[object]]::new()
$testVM=$null
try {
    $clean=Join-Path $TestRoot 'clean'
    Set-PrivateDirectory $clean 'F'
    $acl=Get-Acl -LiteralPath $clean
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544'){throw 'Fresh directory owner is not Administrators'}
    $result.Add([pscustomobject]@{test='protected fresh creation';ok=$true})

    Set-PrivateDirectory $VMRoot 'F'
    $testVM=New-VM -Name ('ll-acl-'+[Guid]::NewGuid().ToString('N').Substring(0,6)) -Path $VMRoot -NoVHD -MemoryStartupBytes 256MB
    $vmOwner=([Security.Principal.NTAccount]('NT VIRTUAL MACHINE\'+$testVM.Id)).Translate([Security.Principal.SecurityIdentifier]).Value
    $checkpoint=Join-Path $VMRoot 'checkpoint.avhdx'
    New-Item -ItemType File -Path $checkpoint | Out-Null
    & icacls.exe $checkpoint /setowner ("*$vmOwner") | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot prepare VM-owned checkpoint fixture'}
    Set-PrivateDirectory $VMRoot 'F'
    $codeRoot=Join-Path $TestRoot 'strict-code-owner'
    Set-PrivateDirectory $codeRoot 'RX'
    $codeFile=Join-Path $codeRoot 'agent.exe'
    New-Item -ItemType File -Path $codeFile | Out-Null
    & icacls.exe $codeFile /setowner ("*$vmOwner") | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot prepare VM-owned code fixture'}
    $rejected=$false
    try {Set-PrivateDirectory $codeRoot 'RX'} catch {$rejected=$_.Exception.Message -like '*untrusted account*'}
    if(-not $rejected){throw 'VM ownership was accepted outside the VM storage root'}
    $result.Add([pscustomobject]@{test='accept VM-owned checkpoints only in VM storage';ok=$true})

    Set-PrivateDirectory $ImageRoot 'F'
    $image=Join-Path $ImageRoot 'parent.vhdx'
    New-Item -ItemType File -Path $image | Out-Null
    & icacls.exe $image /grant:r '*S-1-5-83-0:R' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot prepare image reader regression fixture'}
    $operation=Join-Path $ImageRoot 'staging\operation'
    New-Item -ItemType Directory -Path $operation -Force | Out-Null
    & icacls.exe $operation /grant:r '*S-1-3-0:(OI)(CI)(IO)F' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot prepare staging CreatorOwner regression fixture'}
    $operationAcl=Get-Acl -LiteralPath $operation
    $operationAcl.SetSecurityDescriptorSddlForm(
        $operationAcl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)+'(A;OICIIO;GA;;;CO)',
        [Security.AccessControl.AccessControlSections]::Access)
    Set-Acl -LiteralPath $operation -AclObject $operationAcl
    $disk=Join-Path $operation 'staging.vhdx'
    New-Item -ItemType File -Path $disk | Out-Null
    & icacls.exe $disk /grant:r '*S-1-5-83-0:F' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot prepare operation disk regression fixture'}
    Set-PrivateDirectory $ImageRoot 'F'
    & icacls.exe $image /grant:r '*S-1-5-83-0:W' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot prepare writable image regression fixture'}
    Set-PrivateDirectory $ImageRoot 'F'
    $remaining=@((Get-Acl -LiteralPath $image).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) |
        Where-Object {$_.IdentityReference.Value -eq 'S-1-5-83-0' -and $_.AccessControlType -eq 'Allow' -and
            ([long]$_.FileSystemRights -band [long][Security.AccessControl.FileSystemRights]::Write)})
    if($remaining.Count){throw 'VM write access to an approved parent survived repair'}
    $result.Add([pscustomobject]@{test='preserve VM image readers and repair VM image writers';ok=$true})

    $badGrant=Join-Path $TestRoot 'explicit-user-grant'
    New-Item -ItemType Directory -Path $badGrant | Out-Null
    & icacls.exe $badGrant /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-1-0:(OI)(CI)F' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot prepare explicit-ACE regression fixture'}
    $syntheticCloudSid=[Security.Principal.SecurityIdentifier]::new('S-1-12-1-100-200-300-400')
    $grantAcl=Get-Acl -LiteralPath $badGrant
    $grantAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $syntheticCloudSid,[Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
        [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $badGrant -AclObject $grantAcl
    $badChild=Join-Path $badGrant 'child.txt'
    New-Item -ItemType File -Path $badChild | Out-Null
    & icacls.exe $badChild /grant:r '*S-1-1-0:F' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot prepare explicit child-ACE regression fixture'}
    Set-PrivateDirectory $badGrant 'F'
    foreach($path in @($badGrant,$badChild)){
        $remaining=@((Get-Acl -LiteralPath $path).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) |
            Where-Object {$_.IdentityReference.Value -in @('S-1-1-0',$syntheticCloudSid.Value) -and $_.AccessControlType -eq 'Allow'})
        if($remaining.Count){throw 'An extra Everyone/cloud-account grant survived repair'}
    }
    $result.Add([pscustomobject]@{test='repair pre-existing root and child untrusted ACEs';ok=$true})

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
    if($testVM){Remove-VM -VM $testVM -Force -ErrorAction Stop}
    if(Test-Path -LiteralPath (Join-Path $TestRoot 'junction')){
        (Get-Item -LiteralPath (Join-Path $TestRoot 'junction') -Force).Delete()
    }
    Remove-Item -LiteralPath $TestRoot -Recurse -Force -ErrorAction Stop
}
