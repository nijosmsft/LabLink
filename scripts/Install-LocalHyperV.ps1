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
    [LabLinkAccountRights]::CreateProtectedDirectory($Path,$sddl)
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($Path)
    while ($pending.Count) {
        $entry = $pending.Pop()
        $item = Get-Item -LiteralPath $entry -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Installation tree contains a reparse point: $entry" }
        $acl = Get-Acl -LiteralPath $entry -ErrorAction Stop
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $trusted) { throw "Refusing an existing service path owned by an untrusted account: $entry" }
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
            if ($sid -notin $trusted -and -not $vmAccess -and -not $imageRead -and $rule.AccessControlType -eq 'Allow') {
                throw "Refusing existing non-service permissions at $entry ($sid). Select a clean protected directory."
            }
        }
        if ($item.PSIsContainer) {
            foreach ($child in @(Get-ChildItem -LiteralPath $entry -Force -ErrorAction Stop)) { $pending.Push($child.FullName) }
        }
    }
    $secure = [Security.AccessControl.DirectorySecurity]::new()
    $secure.SetSecurityDescriptorSddlForm($sddl)
    Set-Acl -LiteralPath $Path -AclObject $secure -ErrorAction Stop
}
$createdService=$false
$addedMembership=$false
$grantedRights=[Collections.Generic.List[string]]::new()
try {
if ($Uninstall -and -not $service) { throw 'The restricted Hyper-V service is not installed.' }
if ($service) {
    $cim = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($cim.StartName -ine $account) { throw 'Existing service identity does not match the restricted Hyper-V account.' }
    $existingExe=[LabLinkAccountRights]::Executable($cim.PathName)
    if ((Split-Path -Leaf $existingExe) -ine 'lablink-agent.exe') { throw 'Existing service executable is not the managed LabLink agent.' }
    $existingInstall = Split-Path -Parent (Split-Path -Parent $existingExe)
    if (-not $PSBoundParameters.ContainsKey('InstallRoot')) { $InstallRoot = $existingInstall }
    if ($InstallRoot -ine $existingInstall) { throw 'Changing the service installation root requires uninstall/reinstall.' }
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
    if ($service.Status -ne 'Stopped') { Stop-Service -Name $name -ErrorAction Stop }
} elseif (-not $Uninstall) {
    foreach ($required in @('bin\lablink-agent.exe','bin\lablink-server.exe','bin\lablink-ca.exe','bin\linux-amd64\lablink-agent')) {
        if (-not (Test-Path -LiteralPath (Join-Path $PackageRoot $required))) { throw "Package is missing $required" }
    }
    foreach ($switch in $VSwitch) { Get-VMSwitch -Name $switch -ErrorAction Stop | Out-Null }
    foreach ($image in $WindowsBaseVHD) {
        # A shared parent can already back other running differencing VMs.
        # Provisioning always creates and modifies a new child, never the base.
        Get-VHD -Path $image -ErrorAction Stop | Out-Null
    }
    # Create the service before resolving its virtual account SID. It is not
    # started until code, policy, keys, rights, and storage ACLs are installed.
    $exe = Join-Path $InstallRoot 'bin\lablink-agent.exe'
    $policy = Join-Path $InstallRoot 'hyperv-policy.json'
    $tls = Join-Path $StateRoot 'tls'
    $command = "`"$exe`" --hyperv-only --hyperv-policy `"$policy`" --listen 127.0.0.1:$Port --transport mtls --auth-token-file `"$StateRoot\agent.token`" --tls-ca `"$tls\ca.crt`" --tls-cert `"$tls\server.crt`" --tls-key `"$tls\server.key`""
    & (Join-Path $PackageRoot 'bin\lablink-agent.exe') --install --hyperv-only `
        --hyperv-policy $policy --listen "127.0.0.1:$Port" --transport mtls `
        --auth-token-file "$StateRoot\agent.token" --tls-ca "$tls\ca.crt" `
        --tls-cert "$tls\server.crt" --tls-key "$tls\server.key"
    if ($LASTEXITCODE -ne 0) { throw 'Restricted service creation failed.' }
    $createdService=$true
}
$sidObject = ([Security.Principal.NTAccount]$account).Translate([Security.Principal.SecurityIdentifier])
$script:serviceSid = $sidObject.Value
$binarySid = New-Object byte[] $sidObject.BinaryLength
$sidObject.GetBinaryForm($binarySid,0)
$rights = @('SeServiceLogonRight','SeManageVolumePrivilege','SeBackupPrivilege','SeRestorePrivilege')
if ($Uninstall) {
    if ($policyExists) {
        & (Join-Path $InstallRoot 'bin\lablink-server.exe') --unregister-local-hyperv --home $OperatorHome --name 'local-hyperv'
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
if (-not $VMRoot) { $VMRoot = Join-Path $StateRoot 'VMs' }
if (-not $ImageRoot) { $ImageRoot = Join-Path $StateRoot 'Images' }
Set-PrivateDirectory $InstallRoot 'RX'
Set-PrivateDirectory $StateRoot 'F'
foreach ($directory in @('Temp','VMEnrollment','pki','tls')) {
    Set-PrivateDirectory (Join-Path $StateRoot $directory) 'F'
}
Set-PrivateDirectory $VMRoot 'F'
Set-PrivateDirectory $ImageRoot 'F'
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
Copy-Item -Path (Join-Path $PackageRoot 'bin') -Destination $InstallRoot -Recurse -Force
if (Test-Path -LiteralPath (Join-Path $PackageRoot 'assets')) {
    Copy-Item -LiteralPath (Join-Path $PackageRoot 'assets') -Destination $InstallRoot -Recurse -Force
}
$pki = Join-Path $OperatorHome 'pki'
$ca = Join-Path $InstallRoot 'bin\lablink-ca.exe'
$nodeName = 'local-hyperv'
if (-not (Test-Path -LiteralPath (Join-Path $StateRoot 'tls\server.key'))) {
    & (Join-Path $InstallRoot 'bin\lablink-agent.exe') --generate-server-csr --tls-server-name $nodeName --csr-out (Join-Path $StateRoot 'tls\server.csr') --key-out (Join-Path $StateRoot 'tls\server.key')
    if ($LASTEXITCODE -ne 0) { throw 'Restricted host CSR generation failed.' }
}
if (-not (Test-Path -LiteralPath (Join-Path $StateRoot 'tls\server.csr'))) {
    throw 'Existing restricted server key has no matching CSR; restore the identity before upgrading.'
}
& $ca sign-server-csr -pki-dir $pki -csr (Join-Path $StateRoot 'tls\server.csr') -cert-out (Join-Path $StateRoot 'tls\server.crt')
if ($LASTEXITCODE -ne 0) { throw 'Restricted host server identity issuance failed.' }
& $ca issue-client -pki-dir $pki -name $name
if ($LASTEXITCODE -ne 0) { throw 'Restricted host guest-client identity issuance failed.' }
Copy-Item -LiteralPath (Join-Path $OperatorHome 'agent.token') -Destination (Join-Path $StateRoot 'agent.token') -Force
Copy-Item -LiteralPath (Join-Path $pki 'ca-bundle\ca.crt') -Destination (Join-Path $StateRoot 'tls\ca.crt') -Force
foreach ($file in @('client.crt','client.key')) {
    Copy-Item -LiteralPath (Join-Path $pki "clients\$name\$file") -Destination (Join-Path $StateRoot "tls\$file") -Force
}
foreach ($directory in @('ca-bundle','issuing')) {
    Copy-Item -LiteralPath (Join-Path $pki $directory) -Destination (Join-Path $StateRoot 'pki') -Recurse -Force
}
$policyObject = [ordered]@{
    state_dir=$StateRoot;vm_root=$VMRoot;image_root=$ImageRoot
    base_vhds=@($WindowsBaseVHD);source_base_vhds=@($sourceWindowsBases);vswitches=@($VSwitch)
    install_root=$InstallRoot;pki_dir=(Join-Path $StateRoot 'pki')
}
[IO.File]::WriteAllText((Join-Path $InstallRoot 'hyperv-policy.json'),($policyObject | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
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
& (Join-Path $InstallRoot 'bin\lablink-server.exe') @enrollArgs
if ($LASTEXITCODE -ne 0) { throw 'Restricted host enrollment failed; inspect service logs before retrying.' }
Write-Host "Installed $name as $account (Hyper-V-only, loopback mTLS)."
Write-Host "Local VM root: $VMRoot"
Write-Host "Local image cache: $ImageRoot"
Write-Host 'The existing operator MCP server keeps its full remote and guest tools.'
} catch {
    $failure=$_
    $cleanup=[Collections.Generic.List[string]]::new()
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
            & (Join-Path $PackageRoot 'bin\lablink-server.exe') --unregister-local-hyperv --home $OperatorHome --name 'local-hyperv'
            if ($LASTEXITCODE -ne 0) {$cleanup.Add('remove new endpoint registration')}
        }
    }
    if ($cleanup.Count) {throw "$($failure.Exception.Message); setup rollback also failed: $($cleanup -join '; ')"}
    throw $failure
}
