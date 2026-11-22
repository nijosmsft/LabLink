package hyperv

// RestrictedDiskAccessScript keeps VHD provisioning inside the service logon
// session. It does not create host-global drive letters or change guest ACLs.
func RestrictedDiskAccessScript() string {
	return `
Add-Type @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class LabLinkGuestVolume {
 [StructLayout(LayoutKind.Sequential)] struct FILE_INFO {
   public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;
   public uint VolumeSerial,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
 }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)]
 static extern bool GetFileInformationByHandle(SafeFileHandle file,out FILE_INFO info);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 public static extern bool DefineDosDevice(uint flags,string name,string path);
 public static void CheckPath(string path) {
   string root=Path.GetPathRoot(path),part=root;
   foreach(string item in path.Substring(root.Length).Split(new[]{'\\'},StringSplitOptions.RemoveEmptyEntries)) {
     part=Path.Combine(part,item);
     using(var handle=CreateFile(part,0x80,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero)) {
       if(handle.IsInvalid) {
         int error=Marshal.GetLastWin32Error();
         if(error==2 || error==3) return;
         throw new Win32Exception(error,"Cannot validate guest destination");
       }
       FILE_INFO info;
       if(!GetFileInformationByHandle(handle,out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
       if((info.Attributes&0x400)!=0) throw new IOException("Guest provisioning path crosses a reparse point");
     }
   }
 }
}
'@
function Get-LabLinkGuestAlias([int]$DiskNumber) {
    $volumes=@(Get-Partition -DiskNumber $DiskNumber -ErrorAction Stop |
      ForEach-Object AccessPaths | Where-Object {$_ -like '\\?\Volume{*'})
    foreach($volume in $volumes) {
        $target='\??\'+$volume.Substring(4).TrimEnd('\')
        foreach($code in 90..68) {
            $drive=([char]$code).ToString()+':'
            if([IO.DriveInfo]::GetDrives().Name -contains ($drive+'\')) { continue }
            if(-not [LabLinkGuestVolume]::DefineDosDevice(9,$drive,$target)) {
                throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
            }
            try {
                [LabLinkGuestVolume]::CheckPath($drive+'\Windows\System32\ntoskrnl.exe')
                if(Test-Path -LiteralPath ($drive+'\Windows\System32\ntoskrnl.exe')) {
                    return [pscustomobject]@{Drive=$drive;Target=$target}
                }
            } catch {
                [LabLinkGuestVolume]::DefineDosDevice(15,$drive,$target) | Out-Null
                throw
            }
            if(-not [LabLinkGuestVolume]::DefineDosDevice(15,$drive,$target)) {
                throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
            }
            break
        }
    }
    throw 'WINDOWS_VOLUME_NOT_FOUND: no Windows partition on the managed child VHD'
}
function Copy-LabLinkGuestItem([string]$Source,[string]$Destination,[bool]$Directory) {
    [LabLinkGuestVolume]::CheckPath($Destination)
    if($Directory) {
        foreach($item in @(Get-ChildItem -LiteralPath $Source -Recurse -Force -ErrorAction Stop)) {
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Source payload contains a reparse point'}
            $relative=$item.FullName.Substring($Source.TrimEnd('\').Length).TrimStart('\')
            [LabLinkGuestVolume]::CheckPath((Join-Path $Destination $relative))
        }
        $output=& robocopy.exe $Source $Destination /E /B /COPY:DAT /DCOPY:DA /XJ /R:0 /W:0 /NFL /NDL /NJH /NJS
        if($LASTEXITCODE -ge 8){throw "Guest payload copy failed ($LASTEXITCODE): $output"}
    } else {
        $stage=Join-Path $env:TEMP ('lablink-guest-copy-'+[Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $stage -ErrorAction Stop | Out-Null
        try {
            $name=Split-Path -Leaf $Destination
            Copy-Item -LiteralPath $Source -Destination (Join-Path $stage $name) -ErrorAction Stop
            $output=& robocopy.exe $stage (Split-Path -Parent $Destination) $name /B /COPY:DAT /XJ /R:0 /W:0 /NFL /NDL /NJH /NJS
            if($LASTEXITCODE -ge 8){throw "Guest file copy failed ($LASTEXITCODE): $output"}
        } finally { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction Stop }
    }
}
`
}

func ServiceStatePath(subdirectory string) string {
	return `$(if($env:LABLINK_HYPERV_RESTRICTED -eq '1') { Join-Path $env:LABLINK_HYPERV_STATE_DIR '` +
		subdirectory + `' } else { Join-Path $env:ProgramData 'LabLink\` + subdirectory + `' })`
}
