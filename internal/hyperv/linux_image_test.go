package hyperv

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/nijosmsft/lablink/internal/linuximage"
)

const testStagingID = "0123456789abcdef"

func TestLinuxImageHostPrerequisitesNeverInstallWSLOrReboot(t *testing.T) {
	script, err := BuildLinuxImagePrerequisiteProbeScript()
	if err != nil {
		t.Fatal(err)
	}
	assertNoPowerShellFormattingError(t, script)
	for _, want := range []string{"Start-BitsTransfer", "Convert-VHD", "Resize-VHD", "tar.exe", "filesystem_mutation=$false"} {
		if !strings.Contains(script, want) {
			t.Errorf("probe missing %q", want)
		}
	}
	for _, forbidden := range []string{"wsl.exe", "Enable-WindowsOptionalFeature", "Restart-Computer", "shutdown /r"} {
		if strings.Contains(strings.ToLower(script), strings.ToLower(forbidden)) {
			t.Errorf("physical-host probe must not contain %q", forbidden)
		}
	}
}

func TestLinuxImageBuilderSourcePreflightIsNonMutating(t *testing.T) {
	script, err := BuildLinuxImageBuilderSourcePreflightScript(
		`E:\Windows\base.vhdx`, `E:\VM`, "extswitch",
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"BUILDER_BASE_VHD_NOT_FOUND", "Get-VHD -Path $baseVHD",
		"BUILDER_VSWITCH_NOT_FOUND", "source_preconditions_valid=$true",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("builder source preflight missing %q", want)
		}
	}
	for _, forbidden := range []string{"New-VM", "New-VHD", "New-Item -ItemType Directory", "Start-BitsTransfer -Source"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("builder source preflight mutates with %q", forbidden)
		}
	}
}

func TestLinuxImageDownloadUsesOnlyCanonicalAzureArtifacts(t *testing.T) {
	script, err := BuildLinuxImageDownloadScript(LinuxImageDownloadParams{
		CacheRoot: `E:\LabLinkImages`, StagingID: testStagingID, DiskSizeGB: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertNoPowerShellFormattingError(t, script)
	for _, want := range []string{
		"Start-BitsTransfer", "-Asynchronous", "Get-BitsTransfer -AllUsers",
		linuximage.ImageURL, linuximage.SHA256SUMSURL, linuximage.SHA256SUMSSignatureURL,
		"azure_vhd_archive", "state.json", linuximage.TransformSchema,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("download script missing %q", want)
		}
	}
	if strings.Contains(script, "example.invalid") {
		t.Fatal("download script contains an arbitrary source")
	}
}

func TestLinuxImageVerifyAndConvertAzureVHD(t *testing.T) {
	verify, err := BuildLinuxImageVerifyScript(LinuxImageVerifyParams{
		CacheRoot: `E:\cache`, ExpectedImageHash: strings.Repeat("a", 64),
		CacheKey: "key", DiskSizeGB: 64,
		Verification: linuximage.VerificationState{
			Status: linuximage.VerificationVerified, Signer: linuximage.UbuntuSigningKeyFingerprint,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"IMAGE_SHA256_MISMATCH", "azure-vhd-archive", "Get-FileHash", "image_validated"} {
		if !strings.Contains(verify, want) {
			t.Errorf("verify script missing %q", want)
		}
	}
	convert, err := BuildLinuxImageConvertScript(LinuxImageConvertParams{
		SourceArchive: `E:\cache\source.tar.gz`, StageDir: `E:\stage\op`,
		DestinationVHDX: `E:\stage\op\prepared.vhdx`, StatePath: `E:\state.json`, DiskSizeGB: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"tar.exe -tzf", "AZURE_VHD_ARCHIVE_FILESET_INVALID", linuximage.ExtractedVHDFilename,
		"Convert-VHD", "-VHDType Dynamic", "-BlockSizeBytes 1MB", "-DeleteSource",
		"Resize-VHD", "VHDX_TYPE_INVALID", "disk_identifier",
		"[IO.FileAttributes]::SparseFile", "fsutil.exe sparse setflag $extractedVHD 0",
		"SOURCE_VHD_DESPARSE_FAILED", "SOURCE_VHD_STILL_SPARSE",
	} {
		if !strings.Contains(convert, want) {
			t.Errorf("convert script missing %q", want)
		}
	}
	for _, forbidden := range []string{"wsl.exe", "Enable-WindowsOptionalFeature", "Restart-Computer"} {
		if strings.Contains(strings.ToLower(convert), strings.ToLower(forbidden)) {
			t.Errorf("host conversion script contains forbidden %q", forbidden)
		}
	}
}

func linuxImageBuilderSetupScriptForTest(t *testing.T) string {
	t.Helper()
	script, err := BuildLinuxImageBuilderSetupScript(`C:\ProgramData\LabLink\builder.json`)
	if err != nil {
		t.Fatal(err)
	}
	assertNoPowerShellFormattingError(t, script)
	return script
}

func TestLinuxImageBuilderSetupPersistsFeatureRebootAndPinnedMetadata(t *testing.T) {
	script := linuxImageBuilderSetupScriptForTest(t)
	for _, want := range []string{
		"Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform", "-NoRestart",
		"features_enabled_reboot_required", linuximage.WSLRuntimeVersion,
		linuximage.WSLRuntimeProductVersion, linuximage.WSLMSIURL,
		linuximage.WSLMSISHA256, linuximage.WSLMSIFilename,
		linuximage.WSLMSIDisplayName, linuximage.WSLDistributionName,
		"schema_version -NotePropertyValue 2", "wsl_runtime",
		"LABLINK_BUILDER_EFFECTIVE_USER", "LABLINK_BUILDER_EFFECTIVE_USER_SID",
		"builder_user", "builder_user_sid", "BUILDER_USER_IDENTITY_MISMATCH",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("builder setup script missing %q", want)
		}
	}
	if strings.Contains(script, "Restart-Computer") || strings.Contains(script, "shutdown /r") {
		t.Fatal("builder setup script must persist reboot-required state before the orchestrator reboots")
	}
}

func TestLinuxImageBuilderSetupRejectsWSLStubAndUsesPinnedMSI(t *testing.T) {
	script := linuxImageBuilderSetupScriptForTest(t)
	for _, want := range []string{
		"Invoke-WSLNonTerminating @('--version')", "Get-LabLinkWSLProduct",
		"command_ready=$commandReady", "product_ready=$productReady",
		"WSL_RUNTIME_NOT_READY", "Start-BitsTransfer -Source $wslMSIURL",
		"-DisplayName $wslBITSDisplayName", "C:\\ProgramData\\LabLink\\wsl",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("stub/MSI bootstrap missing %q", want)
		}
	}
	if strings.Contains(script, "if (-not (Get-Command wsl.exe") &&
		strings.Contains(script, "WSL_UNSUPPORTED: wsl.exe is unavailable") {
		t.Fatal("wsl.exe presence alone must not be used as runtime detection")
	}
	for _, forbidden := range []string{
		"wsl.exe --install --no-distribution", "wsl.exe --update",
		"Invoke-WebRequest", "WebClient", "curl.exe", ".Replace([char]0,'')",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("builder setup contains forbidden bootstrap path %q", forbidden)
		}
	}
	if !strings.Contains(script, ".Replace(([char]0).ToString(), [string]::Empty)") {
		t.Fatal("WSL output NUL removal must select PowerShell's string,string Replace overload")
	}
}

func TestLinuxImageBuilderSetupFailsClosedOnMSITrustFailure(t *testing.T) {
	script := linuxImageBuilderSetupScriptForTest(t)
	for _, want := range []string{
		"Get-FileHash -Algorithm SHA256", "WSL_MSI_SHA256_MISMATCH",
		"Get-AuthenticodeSignature", "SignatureStatus]::Valid",
		"O=Microsoft Corporation", "WSL_MSI_SIGNATURE_INVALID",
		"wsl_msi_quarantined", "quarantine_path", ".bad",
		"WSL_MSI_VERIFICATION_FAILED",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("MSI trust handling missing %q", want)
		}
	}
}

func TestLinuxImageBuilderSetupHandlesMSIExitCodesWithoutUIOrElevation(t *testing.T) {
	script := linuxImageBuilderSetupScriptForTest(t)
	for _, want := range []string{
		"Start-Process -FilePath $msiexec", "'/i', $msiPath, '/qn', '/norestart', '/L*v', $msiLogPath",
		"-Wait -PassThru -WindowStyle Hidden",
		"$msiExit -eq 3010", "wsl_msi_installed_reboot_required",
		"$msiAttempt -le 2", "wsl_msi_retrying", "WSL_MSI_INSTALL_FAILED",
		"wsl_msi_installed", "wsl_msi_exit_code",
		"wsl_msi_attempt", "wsl_msi_log_path", "Get-BoundedWSLMSILogTail",
		"-Tail 40", "$tail.Length -gt 2000", "$runtime = Get-LabLinkWSLRuntime",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("MSI exit handling missing %q", want)
		}
	}
	for _, forbidden := range []string{"-Verb RunAs", "-Verb 'RunAs'", "/passive", "/qb", "Start-Process powershell"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("service setup contains UI/elevation path %q", forbidden)
		}
	}
}

func TestLinuxImageBuilderUserTaskUsesEphemeralPasswordLogonAndExactCleanup(t *testing.T) {
	payload := "Write-Output 'payload-marker'"
	script, err := BuildLinuxImageBuilderUserTaskScript(payload, 321)
	if err != nil {
		t.Fatal(err)
	}
	assertNoPowerShellFormattingError(t, script)
	for _, want := range []string{
		"[guid]::NewGuid().ToString('N')", `C:\ProgramData\LabLink\builder-user-jobs`,
		`$taskName = "LabLink-BuilderUser-$jobID"`, "$taskPath = '\\'",
		"LABLINK_BUILDER_USERNAME", "LABLINK_BUILDER_PASSWORD",
		"Resolve-LabLinkBuilderUser", "BUILDER_RID500_USER_NOT_FOUND",
		"BUILDER_RID500_USER_AMBIGUOUS", "BUILDER_RID500_USER_INACTIVE",
		"BUILDER_RID500_USER_NOT_ADMIN", "LABLINK_BUILDER_EFFECTIVE_USER",
		"LABLINK_BUILDER_EFFECTIVE_USER_SID", "identity.json",
		"Register-ScheduledTask", "-User $effectiveUser -Password $password -RunLevel Highest",
		"Start-ScheduledTask", "Get-ScheduledTaskInfo", "BUILDER_USER_TASK_TIMEOUT",
		"BUILDER_USER_TASK_RESULT_MISSING", "BUILDER_USER_TASK_RESULT_INVALID",
		"BUILDER_USER_TASK_FAILED", "Stop-ScheduledTask -TaskName $taskName -TaskPath $taskPath",
		"Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath",
		"Remove-Item -LiteralPath $jobDir -Recurse -Force",
		"BUILDER_USER_TASK_CLEANUP_FAILED", "$password = $null",
		"Remove-Item Env:LABLINK_BUILDER_PASSWORD",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("builder user wrapper missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"runas", "/savecred", "Stop-Process", "Get-Process", "taskkill",
		"payload-marker",
	} {
		if strings.Contains(strings.ToLower(script), strings.ToLower(forbidden)) {
			t.Errorf("builder user wrapper contains forbidden material %q", forbidden)
		}
	}
	actionStart := strings.Index(script, "$action = New-ScheduledTaskAction")
	if actionStart < 0 {
		t.Fatal("scheduled task action is missing")
	}
	actionEnd := strings.Index(script[actionStart:], "$settings =")
	if actionEnd < 0 ||
		strings.Contains(script[actionStart:actionStart+actionEnd], "BUILDER_PASSWORD") {
		t.Fatal("password environment variable leaked into scheduled task command line")
	}
	effectiveEnv := strings.Index(script, "$env:LABLINK_BUILDER_EFFECTIVE_USER = $effectiveUser")
	taskStart := strings.Index(script, "Start-ScheduledTask")
	if effectiveEnv < 0 || taskStart < 0 || effectiveEnv > taskStart {
		t.Fatal("effective builder identity is not set in the wrapper environment before task start")
	}
}

func TestLinuxImageBuilderAccountResolution(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell LocalAccounts resolver behavior is Windows-specific")
	}
	tests := []struct {
		name       string
		configured string
		users      string
		members    string
		want       []string
		wantError  string
	}{
		{
			name:       "preferred valid user",
			configured: "BuilderAdmin",
			users:      "@([pscustomobject]@{Name='Administrator';SID='S-1-5-21-1-500';Enabled=$true},[pscustomobject]@{Name='BuilderAdmin';SID='S-1-5-21-1-1001';Enabled=$true})",
			members:    "@([pscustomobject]@{SID='S-1-5-21-1-500'},[pscustomobject]@{SID='S-1-5-21-1-1001'})",
			want:       []string{`"account":"TESTBOX\\BuilderAdmin"`, `"sid":"S-1-5-21-1-1001"`, `"source":"configured"`},
		},
		{
			name:       "unmapped configured user uses exact RID-500",
			configured: "LocalAdminUser",
			users:      "@([pscustomobject]@{Name='RenamedAdministrator';SID='S-1-5-21-1-500';Enabled=$true},[pscustomobject]@{Name='OtherAdmin';SID='S-1-5-21-1-1002';Enabled=$true})",
			members:    "@([pscustomobject]@{SID='S-1-5-21-1-500'},[pscustomobject]@{SID='S-1-5-21-1-1002'})",
			want:       []string{`"account":"TESTBOX\\RenamedAdministrator"`, `"sid":"S-1-5-21-1-500"`, `"source":"rid-500-fallback"`},
		},
		{
			name:       "zero RID-500 users fails",
			configured: "Missing",
			users:      "@([pscustomobject]@{Name='OtherAdmin';SID='S-1-5-21-1-1002';Enabled=$true})",
			members:    "@([pscustomobject]@{SID='S-1-5-21-1-1002'})",
			wantError:  "BUILDER_RID500_USER_NOT_FOUND",
		},
		{
			name:       "multiple RID-500 users fail",
			configured: "Missing",
			users:      "@([pscustomobject]@{Name='AdministratorA';SID='S-1-5-21-1-500';Enabled=$true},[pscustomobject]@{Name='AdministratorB';SID='S-1-5-21-2-500';Enabled=$true})",
			members:    "@([pscustomobject]@{SID='S-1-5-21-1-500'},[pscustomobject]@{SID='S-1-5-21-2-500'})",
			wantError:  "BUILDER_RID500_USER_AMBIGUOUS",
		},
		{
			name:       "inactive RID-500 user fails",
			configured: "Missing",
			users:      "@([pscustomobject]@{Name='Administrator';SID='S-1-5-21-1-500';Enabled=$false})",
			members:    "@([pscustomobject]@{SID='S-1-5-21-1-500'})",
			wantError:  "BUILDER_RID500_USER_INACTIVE",
		},
		{
			name:       "RID-500 non-admin fails",
			configured: "Missing",
			users:      "@([pscustomobject]@{Name='Administrator';SID='S-1-5-21-1-500';Enabled=$true})",
			members:    "@()",
			wantError:  "BUILDER_RID500_USER_NOT_ADMIN",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := linuxImageBuilderAccountResolverPowerShell + `
$env:COMPUTERNAME = 'TESTBOX'
$script:TestUsers = ` + tt.users + `
$script:TestMembers = ` + tt.members + `
function Get-LocalUser { [CmdletBinding()] param() return @($script:TestUsers) }
function Get-LocalGroup {
    [CmdletBinding()] param($SID)
    return [pscustomobject]@{ Name='Administrators'; SID='S-1-5-32-544' }
}
function Get-LocalGroupMember {
    [CmdletBinding()] param($Group)
    return @($script:TestMembers)
}
try {
    Resolve-LabLinkBuilderUser '` + tt.configured + `' | ConvertTo-Json -Compress
} catch {
    Write-Output ('ERROR:' + $_.Exception.Message)
    exit 17
}
`
			cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
			output, err := cmd.CombinedOutput()
			text := strings.TrimSpace(string(output))
			if tt.wantError != "" {
				if err == nil || !strings.Contains(text, tt.wantError) {
					t.Fatalf("expected %s, err=%v output=%q", tt.wantError, err, text)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolver failed: %v output=%q", err, text)
			}
			for _, want := range tt.want {
				if !strings.Contains(text, want) {
					t.Errorf("resolver output missing %q: %s", want, text)
				}
			}
		})
	}
}

func TestLinuxImageGeneratedPowerShellParses(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows PowerShell parser validation is Windows-specific")
	}
	wrapper, err := BuildLinuxImageBuilderUserTaskScript("Write-Output 'payload'", 60)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := BuildLinuxImageBuilderSetupScript(`C:\ProgramData\LabLink\builder.json`)
	if err != nil {
		t.Fatal(err)
	}
	transform, err := BuildLinuxImageBuilderTransformScript(LinuxImageBuilderTransformParams{
		StatePath: `C:\ProgramData\LabLink\builder.json`, ExpectedSizeBytes: 64 * 1024 * 1024 * 1024,
		ExpectedTargetLocation: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, script := range map[string]string{
		"wrapper": wrapper, "setup": setup, "transform": transform,
	} {
		t.Run(name, func(t *testing.T) {
			command := `$text=[Console]::In.ReadToEnd(); $tokens=$null; $errors=$null; ` +
				`[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors) | Out-Null; ` +
				`if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_.Message }; exit 1 }`
			cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command)
			cmd.Stdin = strings.NewReader(script)
			if output, parseErr := cmd.CombinedOutput(); parseErr != nil {
				t.Fatalf("PowerShell parse failed: %v\n%s", parseErr, output)
			}
		})
	}
}

func TestLinuxImageBuilderStartRetriesOnlyExactFatalWorkerEvent(t *testing.T) {
	script, err := BuildLinuxImageBuilderStartScript("builder")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Microsoft-Windows-Hyper-V-Worker-Admin", "Id=18590", "ErrorCode0",
		"0x0*10", "$numericCode -eq 16", "$VMID.ToString()", "$attemptStarted",
		"Stop-VM -Name $name -TurnOff -Force", "$attempts -lt 2",
		"BUILDER_BOOT_FATAL_18590", "BUILDER_IP_TIMEOUT", "attempts=$attempts",
		"recovered=$recovered",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("builder start recovery missing %q", want)
		}
	}
	if strings.Count(script, "Start-VM -Name $name") != 1 {
		t.Fatal("builder start script must use one bounded start site")
	}
	for _, forbidden := range []string{"Stop-VM *", "Get-VM | Stop-VM", "Stop-Process", "taskkill", "Win32_Process"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("builder start script contains broad stop path %q", forbidden)
		}
	}
	timeout := strings.Index(script, `throw "BUILDER_IP_TIMEOUT`)
	retry := strings.Index(script, "if ($retryFatalStart) { continue }")
	if timeout < 0 || retry < 0 || retry > timeout {
		t.Fatal("arbitrary DHCP timeout can reach the fatal-start retry path")
	}
}

func TestLinuxImageBuilderSetupResumesBITSAndRecoversTerminalJobs(t *testing.T) {
	script := linuxImageBuilderSetupScriptForTest(t)
	for _, want := range []string{
		"Get-BitsTransfer -AllUsers", "WSL_BITS_JOB_SOURCE_MISMATCH",
		"WSL_BITS_JOB_AMBIGUOUS", "'Error','Cancelled','Canceled','Acknowledged'",
		"Remove-BitsTransfer", "'Suspended','TransientError'",
		"Resume-BitsTransfer", "Complete-BitsTransfer",
		"status='setup_pending'", "phase='wsl_msi_downloading'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("BITS recovery missing %q", want)
		}
	}
}

func TestLinuxImageBuilderSetupInstallsAndVerifiesUbuntuWSL2(t *testing.T) {
	script := linuxImageBuilderSetupScriptForTest(t)
	for _, want := range []string{
		"Get-LabLinkWSLDistributions", "$ErrorActionPreference = 'Continue'",
		"@('--list','--quiet')", "@('--install','-d',$distribution,'--web-download','--no-launch')",
		"distro_install_reboot_required", "@('--set-default-version','2')",
		"$distroAlreadyV2", "if (-not $distroAlreadyV2)",
		"@('--set-version',$distribution,'2')", "@('--set-default',$distribution)",
		"@('--list','--verbose')", "installed_distribution_version=2",
		"installed_distribution_default=$true", "builder_ready",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("distro setup missing %q", want)
		}
	}
	if strings.Contains(script, "--no-distribution") {
		t.Fatal("obsolete no-distribution WSL elevation path remains")
	}
}

func TestLinuxImageBuilderSetupPersistsExactEffectiveSID(t *testing.T) {
	script := linuxImageBuilderSetupScriptForTest(t)
	for _, want := range []string{
		"$state | Add-Member -NotePropertyName builder_user -NotePropertyValue $builderUser -Force",
		"$state | Add-Member -NotePropertyName builder_user_sid -NotePropertyValue $builderUserSID -Force",
		"[string]$State.builder_user_sid -cne $builderUserSID",
		"BUILDER_EFFECTIVE_IDENTITY_MISMATCH",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("builder setup identity persistence missing %q", want)
		}
	}
}

func TestLinuxImageBuilderRecordPersistsBuilderIdentity(t *testing.T) {
	record, err := BuildLinuxImageRecordBuilderScript(`E:\state.json`, "builder-profile", "builder-vm", "builder-node")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"phase -NotePropertyValue 'builder_ready'", "image_builder_profile", "builder_vm_name", "builder_node_name"} {
		if !strings.Contains(record, want) {
			t.Errorf("builder host-state script missing %q", want)
		}
	}
}

func TestLinuxImageBuilderReuseRequiresExactManagedIdentity(t *testing.T) {
	metadata := LinuxImageBuilderMetadata{
		SchemaVersion: 1, Target: "host1", Profile: "builder-profile",
		ProfileFingerprint: strings.Repeat("a", 64), VMName: "builder-vm", NodeName: "builder-node",
	}
	managed, err := LinuxImageBuilderManagedMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(managed, LinuxImageBuilderMetadataPrefix) {
		t.Fatalf("managed metadata = %q", managed)
	}
	script, err := BuildInspectLinuxImageBuilderScript("builder-vm", metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"BUILDER_OWNERSHIP_MISMATCH", "$vm.Notes -cne $expected",
		"ExposeVirtualizationExtensions", "DynamicMemoryEnabled",
		"VirtualizationBasedSecurityOptOut", "disk_paths",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("builder reuse script missing %q", want)
		}
	}
}

func TestLinuxImageBuilderAttachTransformDetachIdentitySafety(t *testing.T) {
	inventory, _ := BuildLinuxImageBuilderInventoryScript(`C:\ProgramData\LabLink\builder.json`)
	for _, want := range []string{"Get-Disk", "unique_id", "serial_number", "location", "pre_attach_disks"} {
		if !strings.Contains(inventory, want) {
			t.Errorf("inventory script missing %q", want)
		}
	}
	attach, _ := BuildLinuxImageBuilderAttachScript(LinuxImageBuilderAttachParams{
		VMName: "builder", VHDXPath: `E:\stage\owned.vhdx`, StatePath: `E:\state.json`, DiskSizeGB: 64,
	})
	for _, want := range []string{
		"BUILDER_DATA_DISK_UNEXPECTED", "STAGING_VHDX_IN_USE", "Add-VMHardDiskDrive",
		"ControllerLocation", "disk_identifier", "disk_attached",
	} {
		if !strings.Contains(attach, want) {
			t.Errorf("attach script missing %q", want)
		}
	}
	transform, _ := BuildLinuxImageBuilderTransformScript(LinuxImageBuilderTransformParams{
		StatePath: `C:\ProgramData\LabLink\builder.json`, ExpectedSizeBytes: 64 * 1024 * 1024 * 1024,
		ExpectedTargetLocation: 1,
	})
	for _, want := range []string{
		"PRE_ATTACH_DISK_INVENTORY_MISSING", "DISK_IDENTITY_MISMATCH", "UniqueId", "SerialNumber",
		"expectedTarget", "(?i)(target|port|lun)", `\\.\PHYSICALDRIVE`, "wsl.exe --mount", "--bare",
		"Ubuntu-24.04", "MULTIPLE_OR_MISSING_EXT4_ROOTS", "WSL_UNMOUNT_FAILED",
		"diagnostic_retained", "safe_to_detach", "wsl.exe --unmount",
		"WSL_PRE_MOUNT_INVENTORY_FAILED", "WSL_NEW_DISK_IDENTITY_MISMATCH",
		"WSL_NEW_DISK_RELATION_INVALID", "selected_wsl_disk",
		"BUILDER_USER_IDENTITY_MISMATCH", "BUILDER_USER_IDENTITY_MISSING",
		"LABLINK_BUILDER_EFFECTIVE_USER_SID", "builder_user_sid",
		"WindowsIdentity]::GetCurrent()",
	} {
		if !strings.Contains(transform, want) {
			t.Errorf("transform script missing %q", want)
		}
	}
	detach, _ := BuildLinuxImageBuilderDetachScript(LinuxImageBuilderDetachParams{
		VMName: "builder", VHDXPath: `E:\stage\owned.vhdx`, StatePath: `E:\state.json`,
	})
	stop := strings.Index(detach, "Stop-VM")
	remove := strings.Index(detach, "Remove-VMHardDiskDrive")
	if stop < 0 || remove < 0 || stop > remove {
		t.Fatal("builder must stop before the exact operation-owned disk is detached")
	}
	if !strings.Contains(detach, "BUILDER_OWNED_DISK_DUPLICATE") || !strings.Contains(detach, "BUILDER_DISK_DETACH_FAILED") {
		t.Fatal("detach script lacks exact-ownership checks")
	}
}

func TestLinuxImageBuilderTransformRequiresExactEffectiveSID(t *testing.T) {
	transform, err := BuildLinuxImageBuilderTransformScript(LinuxImageBuilderTransformParams{
		StatePath: `C:\ProgramData\LabLink\builder.json`, ExpectedSizeBytes: 64 * 1024 * 1024 * 1024,
		ExpectedTargetLocation: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"transform requires exact builder_user and builder_user_sid",
		"[string]$State.builder_user_sid -cne [string]$Identity.sid",
		"Assert-BuilderStateIdentity $state $builderIdentity",
		"LABLINK_BUILDER_EFFECTIVE_USER_SID",
	} {
		if !strings.Contains(transform, want) {
			t.Errorf("builder transform identity verification missing %q", want)
		}
	}
}

func TestLinuxImageBuilderBashWritesNoCloudAtomically(t *testing.T) {
	script, err := BuildLinuxImageBuilderTransformScript(LinuxImageBuilderTransformParams{
		StatePath: `C:\ProgramData\LabLink\builder.json`, ExpectedSizeBytes: 64 * 1024 * 1024 * 1024,
		ExpectedTargetLocation: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"base64 -d | bash", "bash -lc $bashCommand"} {
		if !strings.Contains(script, want) {
			t.Errorf("transform script missing %q", want)
		}
	}
	for _, want := range []string{
		`target_disk="${1:?target disk path is required}"`, "lsblk -rno PATH,TYPE,PKNAME,FSTYPE",
		`[ "$type" != part ]`, `[ "$pkname" != "$target_name" ]`, `[ "$fstype" = ext4 ]`,
		"grep -qx 'ID=ubuntu'", `[ "${#matches[@]}" -ne 1 ]`, "mount -o ro",
		"LABLINK_PARTITION_PARENT_INVALID", "99-lablink-nocloud.cfg",
		"datasource_list: [ NoCloud, None ]", `tmp="$target.lablink-tmp-$$"`,
		`mv -f "$tmp" "$target"`, "grep -Fxq", `umount "$root"`,
	} {
		if !strings.Contains(linuxImageTransformBash, want) {
			t.Errorf("builder bash missing %q", want)
		}
	}
}

func TestLinuxImagePublishRequiresHashAndBuilderProfile(t *testing.T) {
	imageHash := strings.Repeat("a", 64)
	cacheKey, _ := linuximage.CacheKey(imageHash, 64)
	finalVHDX := `E:\cache\prepared\key\image.vhdx`
	metadata := linuximage.ImageMetadata{
		SchemaVersion: linuximage.TransformSchema, CacheKey: cacheKey,
		Source: linuximage.FixedSource(), ImageSHA256: imageHash,
		PreparedSHA256: strings.Repeat("b", 64), DiskSizeGB: 64,
		PreparedVHDX: finalVHDX, BuilderProfile: "nested-builder",
		BuilderProfileFingerprint: strings.Repeat("c", 64),
		Verification: linuximage.VerificationState{
			Status: linuximage.VerificationVerified, Signer: linuximage.UbuntuSigningKeyFingerprint,
		},
	}
	publish, err := BuildLinuxImagePublishScript(LinuxImagePublishParams{
		StagedVHDX: `E:\stage\prepared.vhdx`, FinalVHDX: finalVHDX,
		MetadataPath: `E:\cache\prepared\key\metadata.json`, StatePath: `E:\cache\sources\source\state.json`,
		Metadata: metadata,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"STAGED_VHDX_HASH_MISMATCH", "Get-FileHash", "Set-ItemProperty", "prepared_sha256", "status='ready'"} {
		if !strings.Contains(publish, want) {
			t.Errorf("publish script missing %q", want)
		}
	}
	metadata.BuilderProfile = ""
	if _, err := BuildLinuxImagePublishScript(LinuxImagePublishParams{
		StagedVHDX: "a", FinalVHDX: "b", MetadataPath: "c", StatePath: "d", Metadata: metadata,
	}); err == nil {
		t.Fatal("expected publish to reject missing builder profile")
	}
}

func TestLinuxImageSameImageLockIsScopedAndExpiring(t *testing.T) {
	script, err := BuildLinuxImageAcquireLockScript(LinuxImageLockParams{
		CacheRoot: `E:\Images`, CacheKey: "abc", Owner: testStagingID,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`locks\`, "expires_at", "AddHours(2)", "Move-Item -LiteralPath $lockDir -Destination $stalePath"} {
		if !strings.Contains(script, want) {
			t.Errorf("lock script missing %q", want)
		}
	}
}

func TestLinuxImageBuilderIdentityLockHasExactOwnershipAndStaleRecovery(t *testing.T) {
	params := LinuxImageBuilderLockParams{Key: strings.Repeat("a", 64), Owner: testStagingID}
	acquire, err := BuildLinuxImageBuilderAcquireLockScript(params)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"linux-image-builder-locks", "owner.json", "acquired_utc",
		"Move-Item -LiteralPath $lockPath -Destination $stalePath",
		"builder_busy", "recovered_stale",
	} {
		if !strings.Contains(acquire, want) {
			t.Errorf("builder lock acquire missing %q", want)
		}
	}
	release, err := BuildLinuxImageBuilderReleaseLockScript(params)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(release, "[string]$existing.token -ceq $ownerToken") ||
		!strings.Contains(release, "lock_not_owned") {
		t.Fatal("builder lock release does not require exact owner token")
	}
}

func TestLinuxImageDownloadInvalidatesAllOldTransformSchemas(t *testing.T) {
	script, _ := BuildLinuxImageDownloadScript(LinuxImageDownloadParams{
		CacheRoot: `E:\LabLinkImages`, StagingID: testStagingID, DiskSizeGB: 64,
	})
	if !strings.Contains(script, "$existingState.schema_version -cne $schemaVersion") ||
		!strings.Contains(script, linuximage.TransformSchema) {
		t.Fatal("download script can adopt stale transform state")
	}
	for _, old := range []string{"lablink-linux-old-v0", "lablink-linux-old-v1"} {
		if strings.Contains(script, old) {
			t.Fatalf("download script embeds retired schema %q", old)
		}
	}
}

func assertNoPowerShellFormattingError(t *testing.T, script string) {
	t.Helper()
	if strings.Contains(script, "%!") {
		t.Fatalf("generated PowerShell contains a fmt formatting error:\n%s", script)
	}
}
