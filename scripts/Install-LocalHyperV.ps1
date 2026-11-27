<#
.SYNOPSIS
Install the opt-in, non-SYSTEM local Hyper-V management service.
.DESCRIPTION
Run elevated. The operator MCP server remains a normal user process with its
full remote tool catalog. This installs a loopback-only, mTLS-authenticated
agent under NT SERVICE\LabLinkHyperV, not local Administrators.
Backup/restore and volume-maintenance privileges are machine-wide privileges.
The service therefore accepts only structured, policy-validated VM operations.
VM data and existing guests are preserved on uninstall.
#>
[CmdletBinding()]
param(
    [string]$PackageRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$OperatorHome = (Join-Path $HOME '.lablink'),
    [string]$InstallRoot = (Join-Path $env:ProgramFiles 'LabLinkHyperV'),
    [string]$StateRoot = (Join-Path $env:ProgramData 'LabLinkHyperV'),
    [string]$VMRoot,
    [string]$ImageRoot,
    [string[]]$WindowsBaseVHD = @(),
    [string[]]$VSwitch = @('Default Switch'),
    [int]$Port = 19091,
    [string]$VMCredential = 'local-vm-admin',
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$name = 'LabLinkHyperV'
$account = "NT SERVICE\$name"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Local Hyper-V service setup requires an elevated PowerShell prompt.'
}
if ($Port -lt 1024 -or $Port -gt 65535) { throw 'Choose a local service port between 1024 and 65535.' }
$group = Get-LocalGroup -SID 'S-1-5-32-578' -ErrorAction Stop
$service = Get-Service -Name $name -ErrorAction SilentlyContinue
function Initialize-LabLinkAccountRights {
Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class LabLinkAccountRights {
 [StructLayout(LayoutKind.Sequential)] struct ATTRIBUTES {
   public uint Length; public IntPtr Root,Name; public uint Flags; public IntPtr Descriptor,Quality;
 }
 [StructLayout(LayoutKind.Sequential)] struct TEXT {
   public ushort Length,MaximumLength; public IntPtr Buffer;
 }
 [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr name,ref ATTRIBUTES attrs,uint access,out IntPtr policy);
 [DllImport("advapi32.dll")] static extern uint LsaAddAccountRights(IntPtr policy,byte[] sid,TEXT[] rights,uint count);
 [DllImport("advapi32.dll")] static extern uint LsaRemoveAccountRights(IntPtr policy,byte[] sid,[MarshalAs(UnmanagedType.Bool)] bool all,TEXT[] rights,uint count);
 [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr policy);
 [DllImport("advapi32.dll")] static extern uint LsaNtStatusToWinError(uint status);
 [StructLayout(LayoutKind.Sequential)] struct SECURITY_ATTRIBUTES {
   public int Length; public IntPtr Descriptor;
   [MarshalAs(UnmanagedType.Bool)] public bool Inherit;
 }
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl,uint revision,out IntPtr descriptor,out uint size);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 static extern bool CreateDirectory(string path,ref SECURITY_ATTRIBUTES security);
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
 [DllImport("shell32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 static extern IntPtr CommandLineToArgvW(string command,out int count);
 public static string Executable(string command) {
   int count; IntPtr args=CommandLineToArgvW(command,out count);
   if(args==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
   try {
     if(count==0) throw new ArgumentException("Service command line is empty");
     return Marshal.PtrToStringUni(Marshal.ReadIntPtr(args));
   } finally {LocalFree(args);}
 }
 public static void CreateProtectedDirectory(string path,string sddl) {
   IntPtr descriptor; uint size;
   if(!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl,1,out descriptor,out size)) throw new Win32Exception(Marshal.GetLastWin32Error());
   try {
     var security=new SECURITY_ATTRIBUTES{Length=Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)),Descriptor=descriptor};
     if(!CreateDirectory(path,ref security)) {
       int error=Marshal.GetLastWin32Error();
       if(error!=183) throw new Win32Exception(error,"Cannot create protected installation directory");
     }
   } finally {LocalFree(descriptor);}
 }
 public static void Set(byte[] sid,string name,bool remove) {
   var attrs=new ATTRIBUTES(); attrs.Length=(uint)Marshal.SizeOf(attrs);
   IntPtr policy; uint status=LsaOpenPolicy(IntPtr.Zero,ref attrs,0x810,out policy);
   if(status!=0) throw new Win32Exception((int)LsaNtStatusToWinError(status));
   IntPtr text=Marshal.StringToHGlobalUni(name);
   try {
     var right=new TEXT {Length=(ushort)(name.Length*2),MaximumLength=(ushort)((name.Length+1)*2),Buffer=text};
     status=remove?LsaRemoveAccountRights(policy,sid,false,new[]{right},1):LsaAddAccountRights(policy,sid,new[]{right},1);
     if(status!=0 && !(remove && status==0xC0000034)) throw new Win32Exception((int)LsaNtStatusToWinError(status));
   } finally {Marshal.FreeHGlobal(text); LsaClose(policy);}
 }
}
'@
}
function Get-LabLinkServiceExecutable([string]$CommandLine) {
    if ($CommandLine -match '^\s*"([^"]+)"(?:\s|$)') { return $Matches[1] }
    if ($CommandLine -match '^\s*([^\s"]+)(?:\s|$)') { return $Matches[1] }
    throw 'Existing service command line has no valid executable path.'
}
function Assert-LabLinkOperatorIdentity([string]$HomePath,[string]$DataRoot) {
    $currentToken=Join-Path $DataRoot 'agent.token'
    $currentCA=Join-Path $DataRoot 'tls\ca.crt'
    $newToken=Join-Path $HomePath 'agent.token'
    $newCA=Join-Path $HomePath 'pki\ca-bundle\ca.crt'
    foreach ($path in @($currentToken,$currentCA,$newToken,$newCA)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'Cannot verify the original operator identity. Specify its existing -OperatorHome; identity migration is not an upgrade.'
        }
    }
    if ([IO.File]::ReadAllText($currentToken).Trim() -cne [IO.File]::ReadAllText($newToken).Trim() -or
        (Get-FileHash -LiteralPath $currentCA -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $newCA -Algorithm SHA256).Hash) {
        throw 'OperatorHome does not match the installed CA/token identity. Specify the original operator home; identity migration requires explicit recovery.'
    }
}
function Assert-LabLinkHyperVRoots([string]$Code,[string]$State,[string]$VMs,[string]$Images) {
    $paths=@($Code,$State,$VMs,$Images) | ForEach-Object {[IO.Path]::GetFullPath($_).TrimEnd('\')}
    foreach ($path in $paths) {
        if ($path -notmatch '^[A-Za-z]:\\.' -or $path -match '^[A-Za-z]:$') { throw 'Use explicit local service roots, not drive roots or UNC paths.' }
    }
    foreach ($data in $paths[1..3]) {
        if ($data -ieq $paths[0] -or $data.StartsWith($paths[0]+'\',[StringComparison]::OrdinalIgnoreCase) -or $paths[0].StartsWith($data+'\',[StringComparison]::OrdinalIgnoreCase)) {
            throw 'Service-writable data must not overlap protected executable storage.'
        }
    }
    if ($paths[2] -ieq $paths[3] -or $paths[2].StartsWith($paths[3]+'\',[StringComparison]::OrdinalIgnoreCase) -or $paths[3].StartsWith($paths[2]+'\',[StringComparison]::OrdinalIgnoreCase)) {
        throw 'VM and image roots must not overlap.'
    }
    foreach ($root in $paths[2..3]) {
        if ($root -ieq $paths[1] -or $paths[1].StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Guest storage must not contain private service state.' }
        foreach ($private in @('Temp','VMEnrollment','pki','tls','staging')) {
            $reserved=$paths[1]+'\'+$private
            if ($root -ieq $reserved -or $root.StartsWith($reserved+'\',[StringComparison]::OrdinalIgnoreCase) -or $reserved.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) {
                throw 'Guest storage must not overlap private service state.'
            }
        }
    }
}
function Set-LabLinkHyperVDefenderExclusions([string[]]$Roots,[string]$AgentPath) {
    foreach ($command in @('Get-MpPreference','Add-MpPreference')) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "Cannot prepare Defender exclusions: $command is unavailable."
        }
    }
    $paths=@($Roots | ForEach-Object {[IO.Path]::GetFullPath($_).TrimEnd('\')} | Select-Object -Unique)
    $preferences=Get-MpPreference -ErrorAction Stop
    foreach ($path in $paths) {
        if (@($preferences.ExclusionPath) -notcontains $path) {
            Add-MpPreference -ExclusionPath $path -ErrorAction Stop
        }
    }
    if (@($preferences.ExclusionProcess) -notcontains $AgentPath) {
        Add-MpPreference -ExclusionProcess $AgentPath -ErrorAction Stop
    }
    $preferences=Get-MpPreference -ErrorAction Stop
    foreach ($path in $paths) {
        if (@($preferences.ExclusionPath) -notcontains $path) {
            throw "Defender path exclusion was not applied for $path. Check device security policy."
        }
    }
    if (@($preferences.ExclusionProcess) -notcontains $AgentPath) {
        throw "Defender process exclusion was not applied for $AgentPath. Check device security policy."
    }
}
function Set-PrivateDirectory([string]$Path,[string]$ServiceAccess) {
    $Path = [IO.Path]::GetFullPath($Path)
    if ($Path.StartsWith('\\') -or $Path.Length -le 3) { throw 'Use an explicit local service directory, not a drive root or UNC path.' }
    $trusted = @('S-1-5-18','S-1-5-32-544',$script:serviceSid,'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $replacementRights = [long]([Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership)
    for ($parent = Split-Path -Parent $Path; $parent; $parent = Split-Path -Parent $parent) {
        $parentItem = Get-Item -LiteralPath $parent -Force -ErrorAction Stop
        if ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Install path traverses a reparse point: $parent" }
        $parentAcl = Get-Acl -LiteralPath $parent -ErrorAction Stop
        if ($parentAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
            throw "Install path has an untrusted ancestor owner: $parent"
        }
        foreach ($rule in @($parentAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))) {
            if ($rule.AccessControlType -eq 'Allow' -and
                -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
                $rule.IdentityReference.Value -notin $trusted -and
                ([long]$rule.FileSystemRights -band $replacementRights)) {
                throw "Install path has a replaceable ancestor: $parent"
            }
        }
    }
    $access = if ($ServiceAccess -eq 'F') { 'FA' } else { 'FRFX' }
    $sddl = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;$access;;;$script:serviceSid)"
    $secure = [Security.AccessControl.DirectorySecurity]::new()
    $secure.SetSecurityDescriptorSddlForm($sddl)
    if (-not (Test-Path -LiteralPath $Path)) {
        if ($PSVersionTable.PSEdition -eq 'Core') {
            [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($Path),$secure)
        } else {
            [IO.Directory]::CreateDirectory($Path,$secure) | Out-Null
        }
    }
    $pending = [Collections.Generic.Stack[string]]::new()
    $repairs = [Collections.Generic.List[object]]::new()
    $pending.Push($Path)
    while ($pending.Count) {
        $entry = $pending.Pop()
        $item = Get-Item -LiteralPath $entry -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Installation tree contains a reparse point: $entry" }
        $acl = Get-Acl -LiteralPath $entry -ErrorAction Stop
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        $vmOwned = $VMRoot -and $entry.StartsWith($VMRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -and
            $owner -match '^S-1-5-83-1-(?:\d+-){3}\d+$'
        if ($owner -notin $trusted -and -not $vmOwned) { throw "Refusing an existing service path owned by an untrusted account: $entry" }
        $preserved = [Collections.Generic.List[object]]::new()
        foreach ($rule in @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))) {
            $sid = $rule.IdentityReference.Value
            $vmIdentity = $sid.StartsWith('S-1-5-83-') -or $sid -eq 'S-1-15-3-1024-2268835264-3721307629-241982045-173645152-1490879176-104643441-2915960892-1612460704'
            $creatorOnly = $sid -eq 'S-1-3-0' -and ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)
            $imageChild = $ImageRoot -and $entry.StartsWith($ImageRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)
            $operationDisk = $ImageRoot -and $entry.StartsWith($ImageRoot.TrimEnd('\')+'\staging\',[StringComparison]::OrdinalIgnoreCase)
            $vmAccess = (($VMRoot -and $entry.StartsWith($VMRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) -or $operationDisk) -and
                ($vmIdentity -or $creatorOnly)
            $imageRead = $imageChild -and ($creatorOnly -or ($vmIdentity -and
                (([long]$rule.FileSystemRights -band (-bnot [long][Security.AccessControl.FileSystemRights]::ReadAndExecute -band -bnot [long][Security.AccessControl.FileSystemRights]::Synchronize)) -eq 0)))
            if (($vmAccess -or $imageRead) -and $rule.AccessControlType -eq 'Allow') {
                $preserved.Add($rule)
            }
        }
        $inheritance = if ($item.PSIsContainer) { 'OICI' } else { '' }
        # Replace only the DACL, preserving VM ownership and audit information.
        $acl.SetSecurityDescriptorSddlForm(
            "D:P(A;$inheritance;FA;;;SY)(A;$inheritance;FA;;;BA)(A;$inheritance;$access;;;$script:serviceSid)",
            [Security.AccessControl.AccessControlSections]::Access)
        foreach ($rule in $preserved) { $acl.AddAccessRule($rule) }
        $repairs.Add([pscustomobject]@{Path=$entry;Acl=$acl})
        if ($item.PSIsContainer) {
            foreach ($child in @(Get-ChildItem -LiteralPath $entry -Force -ErrorAction Stop)) { $pending.Push($child.FullName) }
        }
    }
    foreach ($repair in $repairs) {
        Set-Acl -LiteralPath $repair.Path -AclObject $repair.Acl -ErrorAction Stop
    }
    Set-Acl -LiteralPath $Path -AclObject $secure -ErrorAction Stop
}
$createdService=$false
$oldPolicy=$null
$policyExists=$false
$addedMembership=$false
$grantedRights=[Collections.Generic.List[string]]::new()
$previousTemp=$env:TEMP
$previousTmp=$env:TMP
$setupTemp=$null
$upgradeBackup=$null
$backupReady=$false
$retainBackup=$false
$serviceStopped=$false
$wasRunning=$service -and $service.Status -ne 'Stopped'
$operatorServer=Join-Path $PackageRoot 'bin\lablink-server.exe'
$ca=Join-Path $PackageRoot 'bin\lablink-ca.exe'
try {
if ($Uninstall -and -not $service) { throw 'The restricted Hyper-V service is not installed.' }
if ($service) {
    $cim = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($cim.StartName -ine $account) { throw 'Existing service identity does not match the restricted Hyper-V account.' }
    $existingExe=Get-LabLinkServiceExecutable $cim.PathName
    if ((Split-Path -Leaf $existingExe) -ine 'lablink-agent.exe') { throw 'Existing service executable is not the managed LabLink agent.' }
    $existingInstall = Split-Path -Parent (Split-Path -Parent $existingExe)
    if (-not $PSBoundParameters.ContainsKey('InstallRoot')) { $InstallRoot = $existingInstall }
    if ($InstallRoot -ine $existingInstall) { throw 'Changing the service installation root requires uninstall/reinstall.' }
    $installationRecord=Join-Path $InstallRoot 'installation.json'
    if (-not $PSBoundParameters.ContainsKey('OperatorHome') -and (Test-Path -LiteralPath $installationRecord)) {
        $OperatorHome=([IO.File]::ReadAllText($installationRecord)|ConvertFrom-Json).operator_home
        if (-not $OperatorHome) { throw 'Existing installation record has no operator home.' }
    }
    $policyExists=Test-Path -LiteralPath (Join-Path $InstallRoot 'hyperv-policy.json')
    if (-not $policyExists -and -not $Uninstall) { throw 'Existing service installation is incomplete; run this script with -Uninstall before retrying.' }
    if ($policyExists) {
    $oldPolicy = [IO.File]::ReadAllText((Join-Path $InstallRoot 'hyperv-policy.json')) | ConvertFrom-Json
    foreach ($setting in @(@('StateRoot','state_dir'),@('VMRoot','vm_root'),@('ImageRoot','image_root'))) {
        $old = $oldPolicy.($setting[1])
        if (-not $PSBoundParameters.ContainsKey($setting[0])) { Set-Variable -Name $setting[0] -Value $old }
        elseif ((Get-Variable -Name $setting[0] -ValueOnly) -ine $old) { throw "Changing $($setting[0]) requires explicit data migration; uninstall/reinstall instead." }
    }
    if (-not $PSBoundParameters.ContainsKey('WindowsBaseVHD')) {
        $WindowsBaseVHD = if ($oldPolicy.source_base_vhds) { @($oldPolicy.source_base_vhds) } else { @($oldPolicy.base_vhds) }
    }
    if (-not $PSBoundParameters.ContainsKey('VSwitch')) { $VSwitch = @($oldPolicy.vswitches) }
    $listen = [regex]::Match($cim.PathName,'--listen\s+"?127\.0\.0\.1:(\d+)')
    if (-not $listen.Success) { throw 'Existing service is not configured for numeric loopback.' }
    $oldPort = [int]$listen.Groups[1].Value
    if (-not $PSBoundParameters.ContainsKey('Port')) { $Port = $oldPort }
    elseif ($Port -ne $oldPort) { throw 'Changing the local endpoint port requires uninstall/reinstall.' }
    }
} elseif (-not $Uninstall) {
    foreach ($switch in $VSwitch) { Get-VMSwitch -Name $switch -ErrorAction Stop | Out-Null }
    foreach ($image in $WindowsBaseVHD) {
        # A shared parent can already back other running differencing VMs.
        # Provisioning always creates and modifies a new child, never the base.
        Get-VHD -Path $image -ErrorAction Stop | Out-Null
    }
}
if ($service -and $policyExists -and -not $Uninstall) {
    Assert-LabLinkOperatorIdentity $OperatorHome $StateRoot
}
if (-not $Uninstall) {
    foreach ($required in @('bin\lablink-agent.exe','bin\lablink-server.exe','bin\lablink-ca.exe','bin\linux-amd64\lablink-agent')) {
        if (-not (Test-Path -LiteralPath (Join-Path $PackageRoot $required))) { throw "Operator package is missing $required" }
    }
} elseif ($policyExists -and -not (Test-Path -LiteralPath $operatorServer)) {
    throw 'The operator lablink-server.exe is required to unregister this host.'
}
$sidOutput=& sc.exe showsid $name
if ($LASTEXITCODE -ne 0) { throw 'Cannot derive the restricted service SID.' }
$sidMatch=[regex]::Match(($sidOutput -join "`n"),'S-1-5-80(?:-\d+){5}')
if (-not $sidMatch.Success) { throw 'Restricted service SID is missing from sc.exe showsid.' }
$script:serviceSid=$sidMatch.Value
$sidObject=[Security.Principal.SecurityIdentifier]::new($script:serviceSid)
$binarySid=New-Object byte[] $sidObject.BinaryLength
$sidObject.GetBinaryForm($binarySid,0)
if (-not $VMRoot) { $VMRoot = Join-Path $StateRoot 'VMs' }
if (-not $ImageRoot) { $ImageRoot = Join-Path $StateRoot 'Images' }
Assert-LabLinkHyperVRoots $InstallRoot $StateRoot $VMRoot $ImageRoot
if ([IO.Path]::GetFullPath($PackageRoot).TrimEnd('\') -ieq [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')) {
    throw 'PackageRoot must reference the operator installation, not the protected service directory.'
}
Set-PrivateDirectory $InstallRoot 'RX'
Set-PrivateDirectory $StateRoot 'F'
Set-PrivateDirectory (Join-Path $StateRoot 'Temp') 'F'
Set-PrivateDirectory $VMRoot 'F'
Set-PrivateDirectory $ImageRoot 'F'
$exe=Join-Path $InstallRoot 'bin\lablink-agent.exe'
Set-LabLinkHyperVDefenderExclusions @($InstallRoot,$StateRoot,$VMRoot,$ImageRoot) $exe
$setupTemp=Join-Path (Join-Path $StateRoot 'Temp') ('setup-'+[Guid]::NewGuid().ToString('N'))
Set-PrivateDirectory $setupTemp 'F'
$env:TEMP=$setupTemp
$env:TMP=$setupTemp
Initialize-LabLinkAccountRights
if ($wasRunning) {
    Stop-Service -Name $name -ErrorAction Stop
    $serviceStopped=$true
}
if ($service -and -not $Uninstall) {
    $upgradeBackup=Join-Path $InstallRoot ('.upgrade-'+[Guid]::NewGuid().ToString('N'))
    Set-PrivateDirectory $upgradeBackup 'RX'
    foreach ($entry in @('bin\lablink-agent.exe','bin\linux-amd64\lablink-agent','assets','hyperv-policy.json','installation.json')) {
        $source=Join-Path $InstallRoot $entry
        if (Test-Path -LiteralPath $source) {
            $saved=Join-Path $upgradeBackup $entry
            New-Item -ItemType Directory -Path (Split-Path -Parent $saved) -Force | Out-Null
            Copy-Item -LiteralPath $source -Destination $saved -Recurse -Force -ErrorAction Stop
        }
    }
    foreach ($entry in @('tls','pki','agent.token')) {
        $source=Join-Path $StateRoot $entry
        if (Test-Path -LiteralPath $source) {
            $saved=Join-Path $upgradeBackup ("identity\"+$entry)
            New-Item -ItemType Directory -Path (Split-Path -Parent $saved) -Force | Out-Null
            Copy-Item -LiteralPath $source -Destination $saved -Recurse -Force -ErrorAction Stop
        }
    }
    $backupReady=$true
}
if (-not $Uninstall) {
    $bin=Join-Path $InstallRoot 'bin'
    Set-PrivateDirectory $bin 'RX'
    Copy-Item -LiteralPath (Join-Path $PackageRoot 'bin\lablink-agent.exe') -Destination $exe -Force
}
if (-not $service -and -not $Uninstall) {
    $exe = Join-Path $InstallRoot 'bin\lablink-agent.exe'
    $policy = Join-Path $InstallRoot 'hyperv-policy.json'
    $tls = Join-Path $StateRoot 'tls'
    & $exe --install --hyperv-only `
        --hyperv-policy $policy --listen "127.0.0.1:$Port" --transport mtls `
        --auth-token-file "$StateRoot\agent.token" --tls-ca "$tls\ca.crt" `
        --tls-cert "$tls\server.crt" --tls-key "$tls\server.key"
    if ($LASTEXITCODE -ne 0) { throw 'Restricted service creation failed.' }
    $createdService=$true
}
$rights = @('SeServiceLogonRight','SeManageVolumePrivilege','SeBackupPrivilege','SeRestorePrivilege')
if ($Uninstall) {
    if ($policyExists) {
        & $operatorServer --unregister-local-hyperv --home $OperatorHome --name 'local-hyperv'
        if ($LASTEXITCODE -ne 0) { throw 'Restricted host registry cleanup failed.' }
    }
    foreach ($right in $rights) { [LabLinkAccountRights]::Set($binarySid,$right,$true) }
    if (@(Get-LocalGroupMember -Group $group | Where-Object SID -eq $script:serviceSid)) {
        Remove-LocalGroupMember -Group $group -Member $account -ErrorAction Stop
    }
    foreach ($image in $WindowsBaseVHD) {
        if (Test-Path -LiteralPath $image) {
            & icacls.exe $image /remove:g ("*$script:serviceSid") | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Cannot remove service-only image grant for $image" }
        }
    }
    & sc.exe delete $name | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Restricted service removal failed.' }
    Write-Host "Removed $name. VM data and state were preserved at $StateRoot."
    return
}
foreach ($right in $rights) {
    [LabLinkAccountRights]::Set($binarySid,$right,$false)
    $grantedRights.Add($right)
}
if (-not @(Get-LocalGroupMember -Group $group | Where-Object SID -eq $script:serviceSid)) {
    Add-LocalGroupMember -Group $group -Member $account
    $addedMembership=$true
}
if (@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object SID -eq $script:serviceSid)) {
    throw 'LabLinkHyperV must not be a member of local Administrators.'
}
foreach ($directory in @('Temp','VMEnrollment','pki','tls')) {
    Set-PrivateDirectory (Join-Path $StateRoot $directory) 'F'
}
$sourceWindowsBases=@($WindowsBaseVHD)
$approvedWindowsBases=[Collections.Generic.List[string]]::new()
if ($WindowsBaseVHD.Count) {
    $baseDirectory=Join-Path $ImageRoot 'WindowsBases'
    Set-PrivateDirectory $baseDirectory 'F'
    foreach ($sourceImage in $WindowsBaseVHD) {
        $info=Get-VHD -Path $sourceImage -ErrorAction Stop
        if ($info.ParentPath) { throw 'Use a standalone Windows base image, not an external differencing chain.' }
        $hash=(Get-FileHash -LiteralPath $sourceImage -Algorithm SHA256).Hash.ToLowerInvariant()
        $extension=[IO.Path]::GetExtension($sourceImage).ToLowerInvariant()
        if ($extension -notin @('.vhd','.vhdx')) { throw 'Windows base image must be a VHD or VHDX.' }
        $destination=Join-Path $baseDirectory ($hash+$extension)
        if (-not (Test-Path -LiteralPath $destination)) {
            $temporary=Join-Path $baseDirectory ([Guid]::NewGuid().ToString('N')+'.copy')
            try {
                Copy-Item -LiteralPath $sourceImage -Destination $temporary -ErrorAction Stop
                if ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash -ine $hash) { throw 'Windows image changed while creating the protected snapshot.' }
                Move-Item -LiteralPath $temporary -Destination $destination -ErrorAction Stop
            } finally {
                if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction Stop }
            }
        } elseif ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ine $hash) {
            throw 'Existing protected Windows image snapshot has an unexpected digest.'
        }
        (Get-Item -LiteralPath $destination).IsReadOnly=$true
        if ((Get-VHD -Path $destination -ErrorAction Stop).ParentPath) { throw 'Protected Windows image must not depend on an external parent.' }
        $approvedWindowsBases.Add($destination)
    }
}
$WindowsBaseVHD=@($approvedWindowsBases.ToArray())
$linuxBin=Join-Path $InstallRoot 'bin\linux-amd64'
Set-PrivateDirectory $linuxBin 'RX'
Copy-Item -LiteralPath (Join-Path $PackageRoot 'bin\linux-amd64\lablink-agent') -Destination $linuxBin -Force
if (Test-Path -LiteralPath (Join-Path $PackageRoot 'assets')) {
    Copy-Item -LiteralPath (Join-Path $PackageRoot 'assets') -Destination $InstallRoot -Recurse -Force
}
$pki = Join-Path $OperatorHome 'pki'
$nodeName = 'local-hyperv'
$identityStage=Join-Path $setupTemp 'identity'
Set-PrivateDirectory $identityStage 'F'
$serverCSR=Join-Path $StateRoot 'tls\server.csr'
if (-not (Test-Path -LiteralPath (Join-Path $StateRoot 'tls\server.key'))) {
    $serverCSR=Join-Path $identityStage 'server.csr'
    & (Join-Path $InstallRoot 'bin\lablink-agent.exe') --generate-server-csr --tls-server-name $nodeName --csr-out $serverCSR --key-out (Join-Path $identityStage 'server.key')
    if ($LASTEXITCODE -ne 0) { throw 'Restricted host CSR generation failed.' }
}
if (-not (Test-Path -LiteralPath $serverCSR)) {
    throw 'Existing restricted server key has no matching CSR; restore the identity before upgrading.'
}
& $ca sign-server-csr -pki-dir $pki -csr $serverCSR -cert-out (Join-Path $identityStage 'server.crt')
if ($LASTEXITCODE -ne 0) { throw 'Restricted host server identity issuance failed.' }
& $ca issue-client -pki-dir $pki -name $name -cert-out (Join-Path $identityStage 'client.crt') -key-out (Join-Path $identityStage 'client.key')
if ($LASTEXITCODE -ne 0) { throw 'Restricted host guest-client identity issuance failed.' }
foreach ($required in @('server.crt','client.crt','client.key')) {
    if (-not (Test-Path -LiteralPath (Join-Path $identityStage $required) -PathType Leaf)) { throw "Certificate issuance did not produce $required." }
}
foreach ($file in @(Get-ChildItem -LiteralPath $identityStage -File)) {
    Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $StateRoot ('tls\'+$file.Name)) -Force
}
Copy-Item -LiteralPath (Join-Path $OperatorHome 'agent.token') -Destination (Join-Path $StateRoot 'agent.token') -Force
Copy-Item -LiteralPath (Join-Path $pki 'ca-bundle\ca.crt') -Destination (Join-Path $StateRoot 'tls\ca.crt') -Force
foreach ($directory in @('ca-bundle','issuing')) {
    Copy-Item -LiteralPath (Join-Path $pki $directory) -Destination (Join-Path $StateRoot 'pki') -Recurse -Force
}
$policyObject = [ordered]@{
    state_dir=$StateRoot;vm_root=$VMRoot;image_root=$ImageRoot
    base_vhds=@($WindowsBaseVHD);source_base_vhds=@($sourceWindowsBases);vswitches=@($VSwitch)
    install_root=$InstallRoot;pki_dir=(Join-Path $StateRoot 'pki')
}
[IO.File]::WriteAllText((Join-Path $InstallRoot 'hyperv-policy.json'),($policyObject | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $InstallRoot 'installation.json'),(@{operator_home=[IO.Path]::GetFullPath($OperatorHome)}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
& sc.exe privs $name 'SeChangeNotifyPrivilege/SeManageVolumePrivilege/SeBackupPrivilege/SeRestorePrivilege' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot restrict the service token privilege list.' }
if (-not [Diagnostics.EventLog]::SourceExists($name)) {
    New-EventLog -LogName Application -Source $name
}
Start-Service -Name $name
$enrollArgs = @('--register-local-hyperv','--home',$OperatorHome,'--name',$nodeName,'--address',"127.0.0.1:$Port",
    '--vm-root',$VMRoot,'--image-root',$ImageRoot,'--vswitch',$VSwitch[0],'--vm-credential',$VMCredential)
if ($WindowsBaseVHD.Count) { $enrollArgs += @('--windows-base',$WindowsBaseVHD[0]) }
if ($oldPolicy -and $oldPolicy.base_vhds.Count) { $enrollArgs += @('--previous-windows-base',$oldPolicy.base_vhds[0]) }
& $operatorServer @enrollArgs
if ($LASTEXITCODE -ne 0) { throw 'Restricted host enrollment failed; inspect service logs before retrying.' }
foreach ($obsolete in @('lablink-server.exe','lablink-ca.exe','lablink-probe.exe','lablink-secret.exe')) {
    $old=Join-Path $InstallRoot ("bin\"+$obsolete)
    if (Test-Path -LiteralPath $old) { Remove-Item -LiteralPath $old -Force -ErrorAction Stop }
}
Write-Host "Installed $name as $account (Hyper-V-only, loopback mTLS)."
Write-Host "Local VM root: $VMRoot"
Write-Host "Local image cache: $ImageRoot"
Write-Host 'The existing operator MCP server keeps its full remote and guest tools.'
} catch {
    $failure=$_
    $cleanup=[Collections.Generic.List[string]]::new()
    if ($backupReady) {
        try {
            $current=Get-Service -Name $name -ErrorAction Stop
            if ($current.Status -ne 'Stopped') { Stop-Service -Name $name -ErrorAction Stop }
            foreach ($entry in @('bin\lablink-agent.exe','bin\linux-amd64\lablink-agent','assets','hyperv-policy.json','installation.json')) {
                $saved=Join-Path $upgradeBackup $entry
                $destination=Join-Path $InstallRoot $entry
                if (Test-Path -LiteralPath $destination) { Remove-Item -LiteralPath $destination -Recurse -Force -ErrorAction Stop }
                if (Test-Path -LiteralPath $saved) {
                    New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
                    Copy-Item -LiteralPath $saved -Destination $destination -Recurse -Force -ErrorAction Stop
                }
            }
            foreach ($entry in @('tls','pki','agent.token')) {
                $saved=Join-Path $upgradeBackup ("identity\"+$entry)
                $destination=Join-Path $StateRoot $entry
                if (Test-Path -LiteralPath $destination) { Remove-Item -LiteralPath $destination -Recurse -Force -ErrorAction Stop }
                if (Test-Path -LiteralPath $saved) {
                    Copy-Item -LiteralPath $saved -Destination $destination -Recurse -Force -ErrorAction Stop
                }
            }
        } catch {
            $retainBackup=$true
            $cleanup.Add("restore protected service files (backup $upgradeBackup): $($_.Exception.Message)")
        }
    }
    if ($wasRunning -and $serviceStopped -and -not $createdService -and -not $Uninstall) {
        try {Start-Service -Name $name -ErrorAction Stop}
        catch {$cleanup.Add("restart existing service: $($_.Exception.Message)")}
    }
    if ($createdService) {
        try {
            $current=Get-Service -Name $name -ErrorAction SilentlyContinue
            if ($current -and $current.Status -ne 'Stopped') { Stop-Service -Name $name -ErrorAction Stop }
        } catch { $cleanup.Add("stop service: $($_.Exception.Message)") }
        if ($binarySid) {
            foreach ($right in $grantedRights) {
                try {[LabLinkAccountRights]::Set($binarySid,$right,$true)}
                catch {$cleanup.Add("remove ${right}: $($_.Exception.Message)")}
            }
        }
        if ($addedMembership) {
            try {Remove-LocalGroupMember -Group $group -Member $account -ErrorAction Stop}
            catch {$cleanup.Add("remove membership: $($_.Exception.Message)")}
        }
        & sc.exe delete $name | Out-Null
        if ($LASTEXITCODE -ne 0) {$cleanup.Add('delete new service')}
        if (Test-Path -LiteralPath (Join-Path $InstallRoot 'hyperv-policy.json')) {
            & $operatorServer --unregister-local-hyperv --home $OperatorHome --name 'local-hyperv'
            if ($LASTEXITCODE -ne 0) {$cleanup.Add('remove new endpoint registration')}
        }
    }
    if ($cleanup.Count) {throw "$($failure.Exception.Message); setup rollback also failed: $($cleanup -join '; ')"}
    throw $failure
} finally {
    $env:TEMP=$previousTemp
    $env:TMP=$previousTmp
    if ($setupTemp -and (Test-Path -LiteralPath $setupTemp)) {
        Remove-Item -LiteralPath $setupTemp -Recurse -Force -ErrorAction Stop
    }
    if ($upgradeBackup -and -not $retainBackup -and (Test-Path -LiteralPath $upgradeBackup)) {
        Remove-Item -LiteralPath $upgradeBackup -Recurse -Force -ErrorAction Stop
    }
}
