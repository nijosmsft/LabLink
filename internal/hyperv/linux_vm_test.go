package hyperv

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCIDATAISOBuilder(t *testing.T) {
	script, err := BuildCIDATAISOScript(CIDATAISOParams{
		SourceDir: `E:\vm\.lablink-cidata-stage`, ISOPath: `E:\vm\cidata.iso`,
		OwnershipPath: `E:\vm\` + LinuxVMOwnershipFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertNoPowerShellFormattingError(t, script)
	for _, want := range []string{
		"IMAPI2FS.MsftFileSystemImage", "FileSystemsToCreate = 3", "VolumeName = 'CIDATA'",
		"meta-data", "user-data", "lablink-agent", "server.key", "filesystem='ISO9660+Joliet'",
		"CreateResultImage", "public static class LabLinkISOFile",
		"IStream stream = (IStream)comStream", "[LabLinkISOFile]::Create",
		"Assert-LabLinkRestrictedAcl $parent",
		"Set-LabLinkRestrictedAcl $isoPath $false", "OWNERSHIP_RECORD_MISMATCH",
		"Join-Path $env:ProgramData 'LabLink\\locks'",
		"Join-Path $imapiLockRoot 'cidata-imapi.lock'",
		"[IO.FileMode]::OpenOrCreate", "[IO.FileAccess]::ReadWrite", "[IO.FileShare]::None",
		"-TimeoutMilliseconds 120000", "-PollMilliseconds 100",
		"CIDATA_IMAPI_LOCK_TIMEOUT", "$imapiLockHandle.Dispose()",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("ISO builder missing %q", want)
		}
	}
	verifyParent := strings.Index(script, "Assert-LabLinkRestrictedAcl $parent")
	openISO := strings.Index(script, "[LabLinkISOFile]::Create($isoPath")
	restrictISO := strings.Index(script, "Set-LabLinkRestrictedAcl $isoPath $false")
	if verifyParent < 0 || openISO < 0 || restrictISO < 0 || !(verifyParent < openISO && openISO < restrictISO) {
		t.Fatalf("CIDATA ACL checks do not fail closed around ISO creation:\n%s", script)
	}
	if strings.Contains(script, "icacls.exe $Path /inheritance:r | Out-Null") ||
		!strings.Contains(script, "if ($LASTEXITCODE -ne 0)") {
		t.Fatal("CIDATA ACL setup ignores icacls exit status")
	}
	acquireLock := strings.Index(script, "$imapiLockHandle = Open-LabLinkExclusiveFileLock")
	createCOM := strings.Index(script, "$fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage")
	addTree := strings.Index(script, "$fsi.Root.AddTree($sourceDir, $false)")
	createImage := strings.Index(script, "$result = $fsi.CreateResultImage()")
	writeISO := strings.Index(script, "[LabLinkISOFile]::Create($isoPath")
	if writeISO < 0 {
		t.Fatalf("CIDATA ISO stream write is missing:\n%s", script)
	}
	finally := strings.Index(script[writeISO:], "} finally {")
	dispose := strings.Index(script[writeISO:], "$imapiLockHandle.Dispose()")
	if acquireLock < 0 || createCOM < 0 || addTree < 0 || createImage < 0 || writeISO < 0 ||
		finally < 0 || dispose < 0 ||
		!(acquireLock < createCOM && createCOM < addTree && addTree < createImage && createImage < writeISO && finally < dispose) {
		t.Fatalf("CIDATA IMAPI lock does not bracket the complete authoring critical section:\n%s", script)
	}
	if strings.Count(script, "$fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage") != 1 {
		t.Fatal("CIDATA authoring must not blindly retry IMAPI COM activation")
	}
	if strings.Contains(script, "Remove-Item -LiteralPath $imapiLockPath") ||
		strings.Contains(script, "Remove-Item -Path $imapiLockPath") {
		t.Fatal("CIDATA IMAPI lock file must persist and must not be deleted")
	}
	if runtime.GOOS == "windows" {
		command := `$text=[Console]::In.ReadToEnd(); $tokens=$null; $errors=$null; ` +
			`[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors) | Out-Null; ` +
			`if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_.Message }; exit 1 }`
		cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command)
		cmd.Stdin = strings.NewReader(script)
		if output, parseErr := cmd.CombinedOutput(); parseErr != nil {
			t.Fatalf("CIDATA PowerShell parse failed: %v\n%s", parseErr, output)
		}
	}
}

func TestCIDATAIMAPIFileLockSerializesWithoutIMAPI(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows FileStream sharing semantics are Windows-specific")
	}
	lockPath := filepath.Join(".", fmt.Sprintf(".cidata-imapi-lock-test-%d-%d.lock", os.Getpid(), time.Now().UnixNano()))
	absoluteLockPath, err := filepath.Abs(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(absoluteLockPath)

	holderScript := cidataIMAPILockPowerShell + `
$handle = Open-LabLinkExclusiveFileLock -Path ` + PSLit(absoluteLockPath) + ` -TimeoutMilliseconds 2000 -PollMilliseconds 25
try {
    [Console]::Out.WriteLine('LOCKED')
    [Console]::Out.Flush()
    Start-Sleep -Milliseconds 800
} finally {
    $handle.Dispose()
}
`
	holder := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", holderScript)
	stdout, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	holder.Stderr = holder.Stdout
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "LOCKED" {
		_ = holder.Process.Kill()
		_ = holder.Wait()
		t.Fatalf("lock holder did not acquire lock: line=%q err=%v", line, err)
	}

	contenderScript := cidataIMAPILockPowerShell + `
$handle = Open-LabLinkExclusiveFileLock -Path ` + PSLit(absoluteLockPath) + ` -TimeoutMilliseconds 150 -PollMilliseconds 25
try { 'unexpected' } finally { if ($null -ne $handle) { $handle.Dispose() } }
`
	output, contenderErr := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", contenderScript).CombinedOutput()
	if contenderErr == nil || !strings.Contains(string(output), "CIDATA_IMAPI_LOCK_TIMEOUT") {
		_ = holder.Process.Kill()
		_ = holder.Wait()
		t.Fatalf("contender did not fail with bounded lock timeout: err=%v output=%s", contenderErr, output)
	}
	if err := holder.Wait(); err != nil {
		t.Fatalf("lock holder failed: %v", err)
	}

	reacquireScript := cidataIMAPILockPowerShell + `
$handle = Open-LabLinkExclusiveFileLock -Path ` + PSLit(absoluteLockPath) + ` -TimeoutMilliseconds 500 -PollMilliseconds 25
try { 'reacquired' } finally { $handle.Dispose() }
`
	output, err = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", reacquireScript).CombinedOutput()
	if err != nil || !strings.Contains(string(output), "reacquired") {
		t.Fatalf("released OS handle did not permit reacquisition: err=%v output=%s", err, output)
	}
}

func TestLinuxVMOwnershipPersistedBeforeSecretStaging(t *testing.T) {
	ownership := LinuxVMOwnership{
		VMName: "vm", ManagedRoot: `E:\VM`, VMLocation: `E:\VM\vm`,
		ChildVHDX: `E:\VM\vm\vm.vhdx`, ISOPath: `E:\VM\vm\cidata.iso`,
		StageDir: `E:\VM\vm\.lablink-cidata-stage`,
	}
	persist, err := BuildPersistLinuxVMOwnershipScript(LinuxVMOwnershipParams{Ownership: ownership})
	if err != nil {
		t.Fatal(err)
	}
	assertNoPowerShellFormattingError(t, persist)
	stage, err := BuildPrepareLinuxVMStageScript(LinuxVMOwnershipParams{Ownership: ownership})
	if err != nil {
		t.Fatal(err)
	}
	assertNoPowerShellFormattingError(t, stage)
	for _, script := range []string{persist, stage} {
		if !strings.Contains(script, "Set-LabLinkRestrictedAcl") ||
			!strings.Contains(script, "Assert-LabLinkRestrictedAcl") ||
			!strings.Contains(script, "if ($LASTEXITCODE -ne 0)") {
			t.Fatalf("restricted ACL is not applied and verified fail-closed:\n%s", script)
		}
	}
	if strings.Index(persist, "Set-LabLinkRestrictedAcl $vmLocation $true") >
		strings.Index(persist, "[IO.File]::WriteAllText") {
		t.Fatal("managed staging directory ACL is not secured before ownership is written")
	}
	if strings.Index(stage, "Set-LabLinkRestrictedAcl $stageDir $true") >
		strings.Index(stage, "status='stage_ready'") {
		t.Fatal("secret staging is reported ready before ACL verification")
	}

	cleanup, err := BuildCleanupLinuxVMStageScript(LinuxVMOwnershipParams{Ownership: ownership})
	if err != nil {
		t.Fatal(err)
	}
	assertNoPowerShellFormattingError(t, cleanup)
	for _, want := range []string{
		"OWNERSHIP_RECORD_MISSING", "OWNERSHIP_RECORD_MISMATCH",
		"Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction Stop",
		"CIDATA_STAGE_CLEANUP_INCOMPLETE", "status='stage_clean'", "absent=$true",
	} {
		if !strings.Contains(cleanup, want) {
			t.Errorf("stage cleanup missing %q", want)
		}
	}
	if strings.Index(cleanup, "Remove-Item -LiteralPath $stageDir") >
		strings.Index(cleanup, "CIDATA_STAGE_CLEANUP_INCOMPLETE") {
		t.Fatal("stage cleanup verifies absence before removal")
	}
}

func TestLinuxVMReconcileUsesOnlyOwnedExactPaths(t *testing.T) {
	ownership := LinuxVMOwnership{
		VMName: "vm", ManagedRoot: `E:\VM`, VMLocation: `E:\VM\vm`,
		ChildVHDX: `E:\VM\vm\vm.vhdx`, ISOPath: `E:\VM\vm\cidata.iso`,
		StageDir: `E:\VM\vm\.lablink-cidata-stage`,
	}
	script, err := BuildReconcileLinuxVMArtifactsScript(ReconcileLinuxVMArtifactsParams{Name: "vm", Ownership: ownership})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"OWNERSHIP_RECORD_MISMATCH", "Get-VMHardDiskDrive", "Get-VMDvdDrive",
		"Remove-Item -LiteralPath $artifact", "Remove-Item -LiteralPath $ownershipPath",
		"cleanup_phase", LinuxVMOwnershipFile,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("reconcile script missing %q", want)
		}
	}

	for _, forbidden := range []string{"Get-ChildItem", "*.iso", "cidata-*", "Remove-Item $artifact"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("reconcile script uses non-exact cleanup %q", forbidden)
		}
	}
}

func TestLinuxVMReconcileCoversPersistedCrashPhases(t *testing.T) {
	ownership := LinuxVMOwnership{
		VMName: "vm", ManagedRoot: `E:\VM`, VMLocation: `E:\VM\vm`,
		ChildVHDX: `E:\VM\vm\vm.vhdx`, ISOPath: `E:\VM\vm\cidata.iso`,
		StageDir: `E:\VM\vm\.lablink-cidata-stage`,
	}
	script, err := BuildReconcileLinuxVMArtifactsScript(ReconcileLinuxVMArtifactsParams{Name: "vm", Ownership: ownership})
	if err != nil {
		t.Fatal(err)
	}
	for crashPoint, want := range map[string]string{
		"after ownership before ISO":  "if (-not $vm -and $record)",
		"after ISO or child creation": "foreach ($artifact in @([string]$record.iso_path,[string]$record.child_vhdx))",
		"after VM creation":           "} elseif ($vm -and $record) {",
		"after ISO detachment":        "[string]$metadata.cleanup_phase -in @(",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("%s is not reconciled; missing %q", crashPoint, want)
		}
	}
}

func TestCreateLinuxVMScriptSecureBootAndOrder(t *testing.T) {
	metadata, err := MarshalLinuxVMMetadata(LinuxVMMetadata{
		GuestOS: "linux", VMName: "vm", NodeName: "vm", ManagedRoot: `E:\VM`,
		ParentVHDX: `E:\Images\base.vhdx`, ChildVHDX: `E:\VM\vm\vm.vhdx`,
		ExpectedCIDATAISO: `E:\VM\vm\seed.iso`,
	})
	if err != nil {
		t.Fatal(err)
	}
	script, err := BuildCreateLinuxVMScript(CreateLinuxVMParams{
		Name: "vm", VMLocation: `E:\VM\vm`, ParentVHDX: `E:\Images\base.vhdx`,
		ChildVHDX: `E:\VM\vm\vm.vhdx`, ISOPath: `E:\VM\vm\seed.iso`,
		VSwitch: "ext", MemoryMB: 4096, CPUCount: 2, DiskSizeGB: 64,
		ManagedMetadata: metadata,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertNoPowerShellFormattingError(t, script)
	for _, want := range []string{
		"New-VHD -Path $childVHDX -ParentPath $parentVHDX -Differencing",
		"MicrosoftUEFICertificateAuthority", "Set-VMFirmware -VMName $name -BootOrder $vhd,$dvd",
		"Key-Value Pair Exchange", "PARENT_VHDX_SIZE_MISMATCH", "Set-VM -Name $name -Notes $managedMetadata",
		"CIDATA_VM_ACL_GRANT_FAILED", "VM_DIRECTORY_ACL_GRANT_FAILED",
		"Assert-LabLinkRestrictedAcl $vmLocation", "Assert-LabLinkRestrictedAcl $isoPath",
		"ACL_OPTIONAL_IDENTITY_NOT_INHERIT_ONLY", "@('S-1-3-0')",
		HyperVVMGroupSID, HyperVWorkerCapabilitySID,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("Linux VM script missing %q", want)
		}
		if strings.Index(script, "CIDATA_VM_ACL_GRANT_FAILED") > strings.Index(script, "Add-VMDvdDrive") {
			t.Fatal("VM identity is granted ISO access only after attachment")
		}
	}
	if strings.Contains(script, "MicrosoftWindows'") {
		t.Fatal("Linux VM script used the Windows-only secure boot template")
	}
	for _, forbidden := range []string{"ModifySystemSettings", "ChassisAssetTag", "BIOSSerialNumber", "ChassisSerialNumber"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("Linux VM script contains obsolete firmware emulation %q", forbidden)
		}
	}
	isoACL := "Assert-LabLinkRestrictedAcl $isoPath @('S-1-5-18','S-1-5-32-544',$vmSid) @($vmSid)"
	if !strings.Contains(script, isoACL) {
		t.Fatal("secret CIDATA ISO ACL unexpectedly allows Hyper-V group/capability identities")
	}
}

func TestConfigureExistingLinuxVMIsIdempotent(t *testing.T) {
	metadata := LinuxVMMetadata{
		SchemaVersion: LinuxVMMetadataSchema, GuestOS: "linux", VMName: "vm", NodeName: "node",
		ManagedRoot: `E:\VM`, ParentVHDX: `E:\Images\base.vhdx`,
		ChildVHDX: `E:\VM\vm\vm.vhdx`, ExpectedCIDATAISO: `E:\VM\vm\cidata.iso`,
		CleanupPhase: LinuxVMCleanupAttached,
	}
	ownership := LinuxVMOwnership{
		VMName: "vm", ManagedRoot: `E:\VM`, VMLocation: `E:\VM\vm`,
		ChildVHDX: metadata.ChildVHDX, ISOPath: metadata.ExpectedCIDATAISO,
		StageDir: `E:\VM\vm\.lablink-cidata-stage`,
	}
	script, err := BuildConfigureExistingLinuxVMScript(ConfigureExistingLinuxVMParams{
		Name: "vm", Metadata: metadata, Ownership: ownership,
		MemoryMB: 4096, CPUCount: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertNoPowerShellFormattingError(t, script)
	for _, want := range []string{
		"VM_RESUME_STATE_UNSAFE", "VM_MANAGED_METADATA_MISMATCH", "OWNERSHIP_RECORD_MISMATCH",
		"VM_CHILD_VHD_MISMATCH", "VM_PARENT_VHD_MISMATCH", "VM_RESUME_CIDATA_MISMATCH",
		"if ($expectedDVD.Count -eq 0)", "Add-VMDvdDrive -VMName $name -Path $isoPath",
		"Set-VMFirmware -VMName $name -BootOrder $vhd,$dvd", "Key-Value Pair Exchange",
		"MicrosoftUEFICertificateAuthority",
		"Assert-LabLinkRestrictedAcl $vmLocation", "Assert-LabLinkRestrictedAcl $isoPath",
		"if ($vmState -eq 'Running')", "VM_RESUME_RUNNING_CIDATA_MISSING",
		"status='validated_running'", "configuration_changed=$false",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("existing VM configuration builder missing %q", want)
		}
	}
	if strings.Count(script, "Add-VMDvdDrive -VMName $name -Path $isoPath") != 1 {
		t.Fatal("existing VM configuration can attach duplicate CIDATA drives")
	}
	runningBranch := strings.Index(script, "if ($vmState -eq 'Running')")
	processorMutation := strings.Index(script, "Set-VMProcessor")
	if runningBranch < 0 || processorMutation < 0 || runningBranch > processorMutation {
		t.Fatal("running VM validation does not return before offline configuration mutations")
	}
	for _, forbidden := range []string{"ModifySystemSettings", "ChassisAssetTag", "BIOSSerialNumber", "ChassisSerialNumber"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("resume script contains obsolete firmware emulation %q", forbidden)
		}
	}
}

func TestValidateExistingLinuxVMStorageIsNonMutatingAndExact(t *testing.T) {
	metadata := LinuxVMMetadata{
		SchemaVersion: LinuxVMMetadataSchema, GuestOS: "linux", VMName: "vm", NodeName: "node",
		ManagedRoot: `E:\VM`, ParentVHDX: `F:\Cache\base.vhdx`,
		ChildVHDX: `E:\VM\vm\vm.vhdx`, ExpectedCIDATAISO: `E:\VM\vm\cidata.iso`,
		CleanupPhase: LinuxVMCleanupComplete,
	}
	script, err := BuildValidateExistingLinuxVMStorageScript("vm", metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"VM_MANAGED_STORAGE_METADATA_MISMATCH", "Get-VMHardDiskDrive",
		"$hardDisks.Count -ne 1", "VM_CHILD_VHD_MISMATCH",
		"Get-VHD -Path $childVHDX", "$child.ParentPath", "VM_PARENT_VHD_MISMATCH",
		"configuration_changed=$false",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("storage validation missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"Set-VM", "Start-VM", "Stop-VM", "Add-VMHardDiskDrive",
		"Remove-VMHardDiskDrive", "New-VHD", "Remove-Item",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("storage validation contains mutation %q", forbidden)
		}
	}
}

func TestLinuxVMCIDATACleanupIsResumable(t *testing.T) {
	script, err := BuildLinuxVMCIDATACleanupScript("vm", `E:\VM\vm\cidata.iso`)
	if err != nil {
		t.Fatal(err)
	}
	detached := strings.Index(script, "cleanup_phase = 'cidata_detached'")
	remove := strings.Index(script, "Remove-Item -LiteralPath $isoPath")
	complete := strings.Index(script, "cleanup_phase = 'complete'")
	if detached < 0 || remove < 0 || complete < 0 || !(detached < remove && remove < complete) {
		t.Fatalf("cleanup phases do not bracket ISO deletion:\n%s", script)
	}
	if !strings.Contains(script, "if (Test-Path -LiteralPath $isoPath -PathType Leaf)") ||
		!strings.Contains(script, "CIDATA_METADATA_MISMATCH") ||
		!strings.Contains(script, "registered=[bool]$metadata.registered") {
		t.Fatal("cleanup is not idempotent or does not preserve registration metadata")
	}
}

func TestOwnedArtifactCleanupNeverDeletesReferencedVHD(t *testing.T) {
	script, err := BuildCleanupOwnedLinuxVMArtifactsScript(CleanupOwnedLinuxVMArtifactsParams{
		ISOPath: `E:\VM\vm\seed.iso`, ChildVHDX: `E:\VM\vm\vm.vhdx`,
		DeleteISO: true, DeleteVHD: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"$isoInUse", "$vhdInUse", "Get-VMHardDiskDrive", "if (-not $vhdInUse)"} {
		if !strings.Contains(script, want) {
			t.Errorf("owned cleanup missing %q", want)
		}
	}
}

func TestLinuxVMStartUsesKVPWithoutScanning(t *testing.T) {
	script, err := BuildLinuxVMStartAndDiscoverScript("vm")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "VM_KVP_IP_TIMEOUT") || !strings.Contains(script, "Get-VMNetworkAdapter") {
		t.Fatal("start script does not use Hyper-V KVP")
	}
	for _, forbidden := range []string{"Test-Connection", "1..254", "nmap", "arp -a"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("start script contains network scanning primitive %q", forbidden)
		}
	}
}
