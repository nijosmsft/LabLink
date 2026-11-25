package hyperv

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/nijosmsft/lablink/internal/linuximage"
)

func runBuilderPowerShell(t *testing.T, script string) string {
	t.Helper()
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", "& ([scriptblock]::Create([Console]::In.ReadToEnd()))")
	cmd.Stdin = strings.NewReader("$ErrorActionPreference='Stop'\n" + script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("executable builder regression: %v\n%s", err, out)
	}
	return string(out)
}

func builderPowerShellFixture(t *testing.T) string {
	t.Helper()
	generated := linuxImageBuilderMachineSetupScriptForTest(t)
	start := strings.Index(generated, "function Get-BuilderState")
	end := strings.Index(generated, "$script:builderPhase = 'machine_checkpoint'")
	if start < 0 || end < start {
		t.Fatal("builder function boundaries missing")
	}
	return linuxImageBuilderDiagnosticsPowerShell + `
$wslRoot='C:\fixture\wsl'
$wslMSIFilename=` + PSLit(linuximage.WSLMSIFilename) + `
$wslMSIURL=` + PSLit(linuximage.WSLMSIURL) + `
$wslMSISHA256=` + PSLit(linuximage.WSLMSISHA256) + `
$wslProductVersion=` + PSLit(linuximage.WSLRuntimeProductVersion) + `
$wslVersion=` + PSLit(linuximage.WSLRuntimeVersion) + `
$wslBITSDisplayName='LabLink WSL fixture'
$distribution='Ubuntu-24.04';$statePath='C:\fixture\state.json'
$builderUser='TESTBOX\BuilderAdmin';$builderUserSID='S-1-5-21-1-1001'
` + generated[start:end] + `
$script:state=[pscustomobject]@{schema_version=2;builder_user=$builderUser;builder_user_sid=$builderUserSID;wsl_bits_job_id='legacy-user-job'}
$script:clock=[DateTime]::Parse('2026-11-25T03:30:00Z').ToUniversalTime()
$script:boot=$script:clock.AddMinutes(-1)
$script:jobs=@();$script:enumerated=0;$script:created=0;$script:removed=0;$script:completed=0;$script:resumed=0
$script:artifact=$false;$script:legacy=$false;$script:corrupt=$false;$script:badSigner=$false
$script:copied=0;$script:hashed=@();$script:quarantined=0
$script:installed=$false;$script:installs=0;$script:msiExit=3010;$script:wslCalls=0
$script:features='Enabled';$script:featureEnables=0;$script:failCreation=$false;$script:sleepCount=0
$script:copyCorrupt=$false;$script:waitTimeout=$false;$script:installer=$null
function Get-BuilderNow { return $script:clock }
function Get-BuilderState { return $script:state }
function Save-BuilderState([string]$Phase,[string]$ErrorText='',[hashtable]$Properties=@{}) {
    foreach($entry in $Properties.GetEnumerator()) {
        $script:state | Add-Member -NotePropertyName $entry.Key -NotePropertyValue $entry.Value -Force
    }
    $script:state | Add-Member -NotePropertyName phase -NotePropertyValue $Phase -Force
    $script:state=$script:state | ConvertTo-Json -Depth 12 | ConvertFrom-Json
}
function New-Item { [CmdletBinding()]param($ItemType,$Path,[switch]$Force) }
function Get-Item { [CmdletBinding()]param($LiteralPath,[switch]$Force) [pscustomobject]@{Attributes=0} }
function Set-Acl { [CmdletBinding()]param($LiteralPath,$AclObject) }
function Get-CimInstance { [CmdletBinding()]param($ClassName) [pscustomobject]@{LastBootUpTime=$script:boot} }
function Get-WindowsOptionalFeature {
    [CmdletBinding()]param([switch]$Online,$FeatureName)
    [pscustomobject]@{State=$script:features}
}
function Enable-WindowsOptionalFeature {
    [CmdletBinding()]param([switch]$Online,$FeatureName,[switch]$All,[switch]$NoRestart)
    $script:featureEnables++
}
function Get-LabLinkWSLProduct {
    if($script:installed) { [pscustomobject]@{version=$wslProductVersion} }
}
function Test-Path {
    [CmdletBinding()]param($LiteralPath,$PathType)
    if($LiteralPath -eq (Join-Path $wslRoot $wslMSIFilename)) {return $script:legacy}
    return $script:artifact
}
function Get-FileHash {
    [CmdletBinding()]param($Algorithm,$LiteralPath)
    $script:hashed+=,$LiteralPath
    [pscustomobject]@{Hash=$(if($script:corrupt){'bad'}else{$wslMSISHA256})}
}
function Get-AuthenticodeSignature {
    [CmdletBinding()]param($FilePath)
    [pscustomobject]@{Status=[Management.Automation.SignatureStatus]::Valid;SignerCertificate=[pscustomobject]@{
        Subject=$(if($script:badSigner){'O=Other Corporation'}else{'CN=Microsoft,O=Microsoft Corporation'})
    }}
}
function Copy-Item {
    [CmdletBinding()]param($LiteralPath,$Destination)
    $script:copied++;$script:artifact=$true
    if($script:copyCorrupt){$script:corrupt=$true}
}
function Move-Item { [CmdletBinding()]param($LiteralPath,$Destination,[switch]$Force) $script:quarantined++;$script:artifact=$false }
function Get-BitsTransfer { [CmdletBinding()]param() $script:enumerated++;return @($script:jobs) }
function Start-BitsTransfer {
    [CmdletBinding()]param($Source,$Destination,$DisplayName,$Description,[switch]$Asynchronous,$Priority,$RetryInterval,$RetryTimeout,$MaxDownloadTime)
    if($script:state.machine_preparation.transfer_token -cne $Description){throw 'intent not durable before creation'}
    if($MaxDownloadTime -le 0 -or $MaxDownloadTime -gt 1200){throw 'unbounded BITS lifetime'}
    $script:created++
    $job=[pscustomobject]@{
        JobId=([guid]::NewGuid().ToString());Description=$Description;OwnerAccount='S-1-5-18'
        JobState='Transferring';BytesTransferred=0;BytesTotal=100
        FileList=@([pscustomobject]@{RemoteName=$Source;LocalName=$Destination});ErrorCondition=0
    }
    $script:jobs+=,$job
    if($script:failCreation) {
        $script:failCreation=$false
        throw [Runtime.InteropServices.COMException]::new('BITS startup', [int]-2147023834)
    }
    return $job
}
function Remove-BitsTransfer {
    [CmdletBinding()]param($BitsJob,[switch]$Confirm)
    $script:removed++
    $script:jobs=@($script:jobs | Where-Object JobId -ne $BitsJob.JobId)
}
function Resume-BitsTransfer { [CmdletBinding()]param($BitsJob,[switch]$Asynchronous) $script:resumed++ }
function Complete-BitsTransfer {
    [CmdletBinding()]param($BitsJob)
    $script:completed++;$script:artifact=$true
    $script:jobs=@($script:jobs | Where-Object JobId -ne $BitsJob.JobId)
}
function Start-Sleep {param($Seconds) $script:sleepCount++;$script:clock=$script:clock.AddSeconds($Seconds)}
function Start-Process {
    [CmdletBinding()]param($FilePath,$ArgumentList,[switch]$PassThru,$WindowStyle)
    $script:installs++
    $process=[pscustomobject]@{Id=42;Handle=42;StartTime=$script:clock;ExitCode=$script:msiExit}
    $process | Add-Member ScriptMethod WaitForExit {param($Milliseconds) return (-not $script:waitTimeout)}
    $process | Add-Member ScriptMethod Refresh {if($this.ExitCode -in @(0,3010)){$script:installed=$true}}
    $script:installer=$process
    return $process
}
function Get-Process { [CmdletBinding()]param($Id) if($script:waitTimeout){return $script:installer} }
function wsl.exe {
    $script:wslCalls++;$global:LASTEXITCODE=0
    if($args[0] -eq '--version') {'WSL version: 3.0.3.0'}
    elseif($args[0] -eq '--list' -and $args[1] -eq '--quiet') {'Ubuntu-24.04'}
    elseif($args[0] -eq '--list') {'* Ubuntu-24.04 Running 2'}
}
$machinePhase=[scriptblock]::Create(` + PSLit(linuxImageBuilderMachinePhasePowerShell) + `)
function Assert-Fixture([bool]$Condition,[string]$Message) { if(-not $Condition){throw ('ASSERT: '+$Message)} }
`
}

func TestBuilderMachineAndUserPhasesExecuteAcrossReboot(t *testing.T) {
	user := linuxImageBuilderSetupScriptForTest(t)
	start := strings.Index(user, "$initialState = Get-BuilderState")
	end := strings.Index(user[start:], "\n} catch {\n    $failure = Format-BuilderError")
	if start < 0 || end < 0 {
		t.Fatal("user phase boundary missing")
	}
	runBuilderPowerShell(t, builderPowerShellFixture(t)+`
$script:features='Disabled'
$first=(& $machinePhase | ConvertFrom-Json)
Assert-Fixture ($first.status -eq 'reboot_required' -and $script:created -eq 0) 'features precede transfer'
Assert-Fixture ($script:featureEnables -eq 2) 'both features enabled'
$id=$script:state.machine_preparation.id
$script:features='Enabled';$script:boot=$script:boot.AddMinutes(2)
$second=(& $machinePhase | ConvertFrom-Json)
Assert-Fixture ($second.status -eq 'setup_pending' -and $script:created -eq 1) 'transfer pending'
$script:jobs[0].JobState='Transferred'
$third=(& $machinePhase | ConvertFrom-Json)
Assert-Fixture ($third.status -eq 'reboot_required' -and $script:installs -eq 1) '3010 checkpoint'
$reboots=$script:state.machine_preparation.reboots
$again=(& $machinePhase | ConvertFrom-Json)
Assert-Fixture ($again.status -eq 'reboot_required' -and $script:state.machine_preparation.reboots -eq $reboots) 'same boot replay'
$script:boot=$script:boot.AddMinutes(2)
$ready=(& $machinePhase | ConvertFrom-Json)
Assert-Fixture ($ready.status -eq 'machine_ready' -and $script:wslCalls -eq 0) 'machine never invokes WSL'
Assert-Fixture ($script:created -eq 1 -and $script:completed -eq 1 -and $script:installs -eq 1) 'no duplicate transfer/install'
$userPhase=[scriptblock]::Create(`+PSLit(user[start:start+end])+`)
$userReady=(& $userPhase | ConvertFrom-Json)
Assert-Fixture ($userReady.status -eq 'builder_ready' -and $script:wslCalls -gt 0) 'user WSL phase'
Assert-Fixture ($script:state.machine_preparation.id -eq $id -and $script:state.machine_preparation.completed) 'additive metadata survives user save'
Assert-Fixture ($script:state.schema_version -eq 2 -and $script:state.wsl_bits_job_id -eq 'legacy-user-job') 'legacy identity preserved'
`)
}

func TestBuilderBITSOwnershipRecoveryExecutes(t *testing.T) {
	for _, mode := range []string{"empty", "failed-transient", "foreign-owner", "mismatched-source", "mismatched-id", "mismatched-token", "permanent", "unrelated-name"} {
		t.Run(mode, func(t *testing.T) {
			runBuilderPowerShell(t, builderPowerShellFixture(t)+`
$null=& $machinePhase
$prep=$script:state.machine_preparation
$original=$script:jobs[0].JobId
$mode='`+mode+`'
switch($mode) {
    'empty' {$script:jobs[0].FileList=@()}
    'failed-transient' {$script:jobs[0].JobState='Error';$script:jobs[0].ErrorCondition=[int]-2147012894}
    'foreign-owner' {$script:jobs[0].OwnerAccount='S-1-5-19'}
    'mismatched-source' {$script:jobs[0].FileList[0].RemoteName='https://invalid.example/other'}
    'mismatched-id' {$prep.job_id=[guid]::NewGuid().ToString();Save-PreparationState 'fixture'}
    'mismatched-token' {$script:jobs[0].Description='not-the-recorded-token'}
    'permanent' {$script:jobs[0].JobState='Error';$script:jobs[0].ErrorCondition=[int]-2145844844}
    'unrelated-name' {
        $script:jobs[0].Description='legacy shared display name'
        $prep.job_id='';Save-PreparationState 'fixture'
    }
}
$failure=''
try {$null=& $machinePhase} catch {$failure=$_.Exception.Message}
if($mode -in @('empty','failed-transient')) {
    Assert-Fixture ($script:created -eq 2 -and $script:removed -eq 1 -and $script:state.machine_preparation.repairs -eq 1) 'bounded owned repair'
} elseif($mode -eq 'unrelated-name') {
    Assert-Fixture ($script:created -eq 2 -and $script:removed -eq 0 -and $script:jobs.Count -eq 2) 'legacy job preserved and ignored'
} else {
    Assert-Fixture ([bool]$failure -and $script:removed -eq 0 -and $script:created -eq 1 -and $script:jobs[0].JobId -eq $original) 'mismatch/permanent is untouched'
}
`)
		})
	}
}

func TestBuilderBITSCreationCrashRecoversExactToken(t *testing.T) {
	runBuilderPowerShell(t, builderPowerShellFixture(t)+`
$script:failCreation=$true
$pending=(& $machinePhase | ConvertFrom-Json)
Assert-Fixture ($pending.status -eq 'setup_pending' -and $script:created -eq 1 -and $script:jobs.Count -eq 1) 'creation crash adopts existing token'
Assert-Fixture ($script:sleepCount -eq 1 -and $script:removed -eq 0) 'bounded startup retry'
Assert-Fixture ($script:state.machine_preparation.job_id -eq $script:jobs[0].JobId) 'job ID saved after token recovery'
`)
}

func TestBuilderBITSDelayedPollingReconcilesBeforeStallDeadline(t *testing.T) {
	for _, mode := range []string{"completed", "progressing", "stalled", "foreign-owner", "mismatched-source", "mismatched-destination", "total-completed", "total-progressing"} {
		t.Run(mode, func(t *testing.T) {
			runBuilderPowerShell(t, builderPowerShellFixture(t)+`
$pending=(& $machinePhase | ConvertFrom-Json)
Assert-Fixture ($pending.status -eq 'setup_pending' -and $script:enumerated -eq 1) 'initial transfer pending'
$prep=$script:state.machine_preparation
$original=$script:jobs[0].JobId
$mode='`+mode+`'
$expectedFailure=''
switch($mode) {
    'completed' {$script:jobs[0].JobState='Transferred';$script:jobs[0].BytesTransferred=100}
    'progressing' {$script:jobs[0].BytesTransferred=50}
    'stalled' {$expectedFailure='WSL_BITS_PROGRESS_DEADLINE'}
    'foreign-owner' {
        $script:jobs[0].JobState='Transferred';$script:jobs[0].OwnerAccount='S-1-5-19'
        $expectedFailure='WSL_BITS_JOB_IDENTITY_MISMATCH'
    }
    'mismatched-source' {
        $script:jobs[0].JobState='Transferred';$script:jobs[0].FileList[0].RemoteName='https://invalid.example/other'
        $expectedFailure='WSL_BITS_JOB_SOURCE_MISMATCH'
    }
    'mismatched-destination' {
        $script:jobs[0].JobState='Transferred';$script:jobs[0].FileList[0].LocalName='C:\fixture\other.msi'
        $expectedFailure='WSL_BITS_JOB_SOURCE_MISMATCH'
    }
    'total-completed' {$script:jobs[0].JobState='Transferred';$expectedFailure='WSL_BITS_PROGRESS_DEADLINE'}
    'total-progressing' {$script:jobs[0].BytesTransferred=50;$expectedFailure='WSL_BITS_PROGRESS_DEADLINE'}
}
$totalExpired=$mode -like 'total-*'
$script:clock=$script:clock.AddMinutes($(if($totalExpired){21}else{6}))
$failure=''
try {$result=(& $machinePhase | ConvertFrom-Json)} catch {$failure=$_.Exception.Message}
Assert-Fixture ($script:created -eq 1 -and $script:removed -eq 0 -and $script:resumed -eq 0) 'delayed polling never replaces or resumes a job'
Assert-Fixture ($script:enumerated -eq $(if($totalExpired){1}else{2})) 'reconcile before stall check but not after absolute deadline'
if($mode -eq 'completed') {
    Assert-Fixture (-not $failure -and $result.status -eq 'reboot_required') 'completed transfer survives delayed polling'
    Assert-Fixture ($script:completed -eq 1 -and $script:installs -eq 1 -and $script:hashed.Count -eq 1) 'owned completed transfer verified and installed once'
} elseif($mode -eq 'progressing') {
    Assert-Fixture (-not $failure -and $result.status -eq 'setup_pending') 'observed progress survives delayed polling'
    Assert-Fixture ($script:state.machine_preparation.bytes_transferred -eq 50 -and
        $script:state.machine_preparation.progress_at -ceq $script:clock.ToString('o')) 'observed byte progress durably refreshes stall timer'
    Assert-Fixture ($script:completed -eq 0 -and $script:installs -eq 0 -and $script:jobs[0].JobId -eq $original) 'progressing job retained'
} else {
    Assert-Fixture ($failure.Contains($expectedFailure)) ('expected delayed-poll failure: '+$failure)
    Assert-Fixture ($script:completed -eq 0 -and $script:installs -eq 0 -and $script:jobs[0].JobId -eq $original) 'stalled expired or mismatched job untouched'
}
`)
		})
	}
}

func TestBuilderPersistedBudgetsExecute(t *testing.T) {
	for _, mode := range []string{"progress", "transfer", "preparation", "repair", "reboot", "startup"} {
		t.Run(mode, func(t *testing.T) {
			runBuilderPowerShell(t, builderPowerShellFixture(t)+`
$null=& $machinePhase
$prep=$script:state.machine_preparation
$mode='`+mode+`'
switch($mode) {
    'progress' {$script:clock=$script:clock.AddMinutes(6)}
    'transfer' {$prep.transfer_started_at=$script:clock.AddMinutes(-21).ToString('o')}
    'preparation' {$prep.deadline=$script:clock.AddSeconds(-1).ToString('o')}
    'repair' {$prep.repairs=2;$script:jobs[0].FileList=@()}
    'reboot' {$prep.reboots=4;$prep.reboot_boot_id='previous';$script:features='EnablePending'}
    'startup' {
        $prep.startup_started_at=$script:clock.AddSeconds(-121).ToString('o')
        function Get-BitsTransfer { [CmdletBinding()]param() throw [Runtime.InteropServices.COMException]::new('startup',[int]-2147023834) }
    }
}
Save-PreparationState 'fixture'
$failure=''
try {$null=& $machinePhase} catch {$failure=$_.Exception.Message}
Assert-Fixture ([bool]$failure -and $script:created -eq 1 -and $script:removed -eq 0 -and $script:featureEnables -eq 0) 'expired budget prevents new work'
`)
		})
	}
}

func TestBuilderMSITrustMigrationAndExitRecoveryExecute(t *testing.T) {
	for _, mode := range []string{"legacy", "bad-hash", "bad-signer", "copied-corrupt", "busy", "permanent", "interrupted", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			runBuilderPowerShell(t, builderPowerShellFixture(t)+`
$mode='`+mode+`'
$script:legacy=$true
switch($mode) {
    'bad-hash' {$script:corrupt=$true}
    'bad-signer' {$script:badSigner=$true}
    'copied-corrupt' {$script:copyCorrupt=$true}
    'busy' {$script:msiExit=1618}
    'permanent' {$script:msiExit=1603}
    'timeout' {$script:waitTimeout=$true}
    'interrupted' {
        $null=& $machinePhase
        $prep=$script:state.machine_preparation
        $prep.install_reboot_pending=$false;$prep.install_inflight=$true;$prep.install_pid=0
        $script:installed=$false
        Save-PreparationState 'fixture'
    }
}
$failure=''
try {$result=(& $machinePhase | ConvertFrom-Json)} catch {$failure=$_.Exception.Message}
if($mode -eq 'legacy') {
    Assert-Fixture ($result.status -eq 'reboot_required' -and $script:copied -eq 1 -and $script:hashed.Count -eq 2 -and $script:created -eq 0) 'legacy source and copy independently verified'
} elseif($mode -eq 'busy') {
    Assert-Fixture ($result.status -eq 'setup_pending' -and $script:installs -eq 1) 'busy deferred'
    $null=& $machinePhase
    Assert-Fixture ($script:installs -eq 1) 'busy delay retained'
    $script:clock=$script:clock.AddSeconds(31);$script:msiExit=0
    $ready=(& $machinePhase | ConvertFrom-Json)
    Assert-Fixture ($ready.status -eq 'machine_ready' -and $script:installs -eq 2) 'single busy retry'
} elseif($mode -in @('bad-hash','bad-signer')) {
    Assert-Fixture ([bool]$failure -and $script:copied -eq 0 -and $script:installs -eq 0 -and $script:created -eq 0 -and $script:quarantined -eq 0) 'legacy trust failure is permanent and nonmutating'
} elseif($mode -eq 'copied-corrupt') {
    Assert-Fixture ([bool]$failure -and $script:copied -eq 1 -and $script:quarantined -eq 1 -and $script:installs -eq 0) 'mutable copy reverified and only owned artifact quarantined'
} elseif($mode -eq 'timeout') {
    Assert-Fixture ($result.status -eq 'setup_pending' -and $script:installs -eq 1) 'installer timeout recorded'
    $script:clock=$script:clock.AddSeconds(301)
    try {$null=& $machinePhase} catch {$failure=$_.Exception.Message}
    Assert-Fixture ($failure.Contains('WSL_MSI_INSTALL_TIMEOUT') -and $script:installs -eq 1) 'live exact installer not duplicated'
} else {
    Assert-Fixture ([bool]$failure -and $script:installs -eq 1) 'permanent/unknown installer never repeated'
    try {$null=& $machinePhase} catch {}
    Assert-Fixture ($script:installs -eq 1) 'persisted nonretryable installer result preserved'
}
`)
		})
	}
}

func TestBuilderSystemGuardAndDiagnosticCommandsExecute(t *testing.T) {
	machine := linuxImageBuilderMachineSetupScriptForTest(t)
	out := runBuilderPowerShell(t, "$env:LABLINK_HYPERV_RESTRICTED='1'\n"+strings.Replace(machine, "    exit 1", "    return", 1))
	if !strings.Contains(out, "BUILDER_MACHINE_IDENTITY_UNSUPPORTED") {
		t.Fatalf("restricted host guard did not fail before mutation: %s", out)
	}
	runBuilderPowerShell(t, linuxImageBuilderDiagnosticsPowerShell+`
$password='test-secret-\quoted"'
$script:builderPhase='feature_probe'
function Get-WindowsOptionalFeature {
    throw [Runtime.InteropServices.COMException]::new(('failure '+$password),[int]-2147023651)
}
try {Invoke-BuilderStep 'Get-WindowsOptionalFeature' {Get-WindowsOptionalFeature}} catch {
    $text=Format-BuilderError $_
    if($text.Contains('test-secret') -or -not $text.Contains('Get-WindowsOptionalFeature') -or
        -not $text.Contains('0x800704DD') -or -not $text.Contains('feature_probe') -or $text.Contains('InvocationInfo')) {
        throw ('invalid diagnostic: '+$text)
    }
}
`)
}

func TestBuilderPrimaryAndCleanupErrorsBothExecute(t *testing.T) {
	wrapper, err := BuildLinuxImageBuilderUserTaskScript("throw 'test'", 30)
	if err != nil {
		t.Fatal(err)
	}
	start := strings.LastIndex(wrapper, "if ($cleanupErrors.Count -gt 0)")
	end := strings.Index(wrapper[start:], "\nif (-not [string]::IsNullOrEmpty($payloadOutput))")
	if start < 0 || end < 0 {
		t.Fatal("cleanup report block missing")
	}
	runBuilderPowerShell(t, `
$cleanupErrors=[Collections.Generic.List[string]]::new()
$cleanupErrors.Add('Unregister-ScheduledTask failed')
$primaryError=$null;$payloadExit=17;$payloadOutput='LABLINK_ERROR: actual command=Get-BitsTransfer hresult=0x800704DD'
$failure=''
try {
`+wrapper[start:start+end]+`
} catch {$failure=$_.Exception.Message}
if(-not $failure.Contains('Get-BitsTransfer') -or -not $failure.Contains('Unregister-ScheduledTask') -or
    -not $failure.Contains('0x800704DD')) {throw ('primary hidden: '+$failure)}
`)
}
