package hyperv

// Builder diagnostics deliberately exclude InvocationInfo text and bound parameters.
const linuxImageBuilderDiagnosticsPowerShell = `
$script:builderPhase = 'identity'
$script:builderCommand = 'WindowsIdentity.GetCurrent'
$script:builderBitsDiagnostic = $null
$script:builderStateValidated = $false
function Invoke-BuilderStep([string]$Name, [scriptblock]$Action) {
    $script:builderCommand = $Name
    & $Action
}
function Format-BuilderError($Record) {
    $identity = ''
    $identityName = ''
    try {
        $current = [Security.Principal.WindowsIdentity]::GetCurrent()
        $identity = [string]$current.User.Value
        $identityName = [string]$current.Name
    } catch {}
    $codes = @()
    for ($exception = $Record.Exception; $exception; $exception = $exception.InnerException) {
        $codes += ('0x{0:X8}' -f ([long]$exception.HResult -band 0xffffffffL))
    }
    $command = $script:builderCommand
    if ($Record.InvocationInfo -and $Record.InvocationInfo.MyCommand -and
        $Record.InvocationInfo.MyCommand.CommandType -in @('Cmdlet','Application')) {
        $command = [string]$Record.InvocationInfo.MyCommand.Name
    }
    $diagnostic = [ordered]@{
        phase=$script:builderPhase; command=$command; hresult=@($codes)
        error_id=[string]$Record.FullyQualifiedErrorId; identity_sid=$identity; identity_name=$identityName
        session_id=[Diagnostics.Process]::GetCurrentProcess().SessionId
        selected_user_sid=$builderUserSID; preparation_id=$prep.id; task_name=$taskName
        message=[string]$Record.Exception.Message; bits=$script:builderBitsDiagnostic
    }
    $text = $diagnostic | ConvertTo-Json -Depth 6 -Compress
    foreach ($secret in @($password, $env:LABLINK_BUILDER_PASSWORD)) {
        if (-not [string]::IsNullOrEmpty([string]$secret)) {
            # Redact both the JSON-escaped and original spelling.
            $encoded = ConvertTo-Json -InputObject ([string]$secret) -Compress
            $text = $text.Replace($encoded.Substring(1, $encoded.Length-2), '[REDACTED]').Replace([string]$secret, '[REDACTED]')
        }
    }
    return ('BUILDER_STEP_FAILED: ' + $text)
}
`

func wrapLinuxImageBuilder(body string) string {
	return wrapTagged(linuxImageBuilderDiagnosticsPowerShell + `
try {
` + body + `
} catch {
    $failure = Format-BuilderError $_
    if ($script:builderStateValidated) {
        try {
            $prep.failure = $failure
            Save-BuilderState 'preparation_failed' $failure @{ machine_preparation=$prep }
        } catch {
            $failure += '; checkpoint_error=' + (Format-BuilderError $_)
        }
    }
    throw $failure
}
`)
}

const linuxImageBuilderPreparationPowerShell = `
function Get-BuilderNow { return [DateTime]::UtcNow }
function Get-PreparationTime([string]$Value) {
    return [DateTime]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
}
function Get-BuilderBootID {
    return (Invoke-BuilderStep 'Get-CimInstance' {
        (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString('o')
    })
}
function Assert-PreparationState {
    if (-not $prep -or $prep.version -ne 1 -or [string]$prep.id -cnotmatch '^[a-f0-9]{32}$' -or
        [string]$prep.owner_sid -cne 'S-1-5-18' -or
        [string]$prep.source -cne $wslMSIURL -or [string]$prep.sha256 -cne $wslMSISHA256 -or
        [string]$prep.transfer_token -cnotmatch ('^LabLink-WSL:' + [regex]::Escape([string]$prep.id) + ':[a-f0-9]{32}$')) {
        throw 'BUILDER_PREPARATION_IDENTITY_INVALID: expected pinned, SYSTEM-owned version 1 preparation'
    }
    foreach ($field in @('repairs','reboots','install_attempts','deadline','completed','machine_ready','failure')) {
        if ($prep.PSObject.Properties.Name -notcontains $field -or $null -eq $prep.$field) {
            throw 'BUILDER_PREPARATION_STATE_INVALID: required checkpoint field is missing'
        }
    }
    $expectedPath = Join-Path $wslRoot ('preparations\' + $prep.id + '\' + $wslMSIFilename)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([string]$prep.destination, $expectedPath)) {
        throw 'BUILDER_PREPARATION_DESTINATION_MISMATCH: recorded destination is not the preparation-owned MSI'
    }
    if ($prep.repairs -lt 0 -or $prep.repairs -gt 2 -or $prep.reboots -lt 0 -or $prep.reboots -gt 4 -or
        $prep.install_attempts -lt 0 -or $prep.install_attempts -gt 2) {
        throw 'BUILDER_PREPARATION_BUDGET_INVALID: invalid persisted attempt count'
    }
    if ([string]$prep.failure) { throw ('BUILDER_PREPARATION_FAILED: ' + [string]$prep.failure) }
    if (-not $prep.completed -and (Get-BuilderNow) -ge (Get-PreparationTime ([string]$prep.deadline))) {
        throw 'BUILDER_PREPARATION_DEADLINE: preparation exceeded its persisted 60-minute deadline'
    }
}
function Save-PreparationState([string]$Phase) {
    $script:builderPhase = $Phase
    Save-BuilderState $Phase '' @{ machine_preparation=$prep }
}
function Write-BuilderPending([string]$Phase) {
    Save-PreparationState $Phase
    [pscustomobject]@{
        status='setup_pending'; phase=$Phase; bits_job_id=$prep.job_id
        preparation_id=$prep.id; bits=$script:builderBitsDiagnostic
    } | ConvertTo-Json -Depth 6 -Compress
}
function Request-BuilderReboot([string]$Phase) {
    $boot = Get-BuilderBootID
    if ([string]$prep.reboot_boot_id -cne $boot) {
        if ($prep.reboots -ge 4) { throw 'BUILDER_REBOOT_LIMIT: preparation requested more than four reboots' }
        $prep.reboots++
        $prep.reboot_boot_id = $boot
    }
    Save-PreparationState $Phase
    [pscustomobject]@{ status='reboot_required'; phase=$Phase; preparation_id=$prep.id; reboots=$prep.reboots } |
        ConvertTo-Json -Compress
}
function Test-BuilderTransientCode($Code) {
    $hex = '0x{0:X8}' -f ([long]$Code -band 0xffffffffL)
    return $hex -in @('0x80070426','0x800706BA','0x8007041D','0x80072EE2','0x80072EE7','0x80072EFD','0x80200010')
}
function Test-BuilderTransientError($Record) {
    for ($exception=$Record.Exception; $exception; $exception=$exception.InnerException) {
        if (Test-BuilderTransientCode $exception.HResult) { return $true }
    }
    return $false
}
`

const linuxImageBuilderDownloadPowerShell = `
function Set-BuilderBITSDiagnostic($Job) {
    $script:builderBitsDiagnostic = [ordered]@{
        id=[string]$Job.JobId; owner=[string]$Job.OwnerAccount; state=[string]$Job.JobState
        file_count=@($Job.FileList).Count; expected_source=$prep.source; expected_destination=$prep.destination
        files=@($Job.FileList | Select-Object -First 4 | ForEach-Object {
            $source = '[invalid URL]'
            try {
                $uri = [uri]::new([string]$_.RemoteName, [UriKind]::Absolute)
                $source = $uri.GetComponents(([UriComponents]::SchemeAndServer -bor [UriComponents]::Path), [UriFormat]::UriEscaped)
            } catch {}
            [pscustomobject]@{ source=$source; destination=[string]$_.LocalName }
        })
        bytes_transferred=[string]$Job.BytesTransferred; bytes_total=[string]$Job.BytesTotal
    }
    foreach ($name in @('ErrorCondition','ErrorCode','InternalErrorCode','ErrorContext')) {
        if ($Job.PSObject.Properties.Name -contains $name) {
            $script:builderBitsDiagnostic[$name] = [string]$Job.$name
        }
    }
}
function Assert-BuilderBITSOwner($Job) {
    Set-BuilderBITSDiagnostic $Job
    $owner = [string]$Job.OwnerAccount
    if ($owner -notmatch '^S-\d-') {
        $owner = [Security.Principal.NTAccount]::new($owner).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    if ($owner -cne $prep.owner_sid -or [string]$Job.Description -cne $prep.transfer_token -or
        ([string]$prep.job_id -and [string]$Job.JobId -ine [string]$prep.job_id)) {
        throw 'WSL_BITS_JOB_IDENTITY_MISMATCH: recorded job is not provably owned; left untouched'
    }
    $files = @($Job.FileList)
    if ($files.Count -gt 0 -and ($files.Count -ne 1 -or [string]$files[0].RemoteName -cne $prep.source -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals(
            [IO.Path]::GetFullPath([string]$files[0].LocalName), [string]$prep.destination))) {
        throw 'WSL_BITS_JOB_SOURCE_MISMATCH: nonempty job metadata differs; left untouched'
    }
}
function Repair-BuilderBITS($Job) {
    if ($prep.repairs -ge 2) { throw 'WSL_BITS_REPAIR_LIMIT: exceeded two ownership-proven repairs' }
    if ($Job) {
        Assert-BuilderBITSOwner $Job
        if ($Job.JobState -notin @('Cancelled','Canceled','Acknowledged')) {
            Invoke-BuilderStep 'Remove-BitsTransfer' {
                Remove-BitsTransfer -BitsJob $Job -Confirm:$false -ErrorAction Stop
            }
        }
    }
    $prep.repairs++
    $prep.bytes_transferred = 0
    $prep.job_id = ''
    $prep.transfer_token = 'LabLink-WSL:' + $prep.id + ':' + [guid]::NewGuid().ToString('N')
    Save-PreparationState 'wsl_msi_transfer_repair'
}
function Get-OrCreateBuilderBITS {
    $jobs = @(Invoke-BuilderStep 'Get-BitsTransfer' { Get-BitsTransfer -ErrorAction Stop })
    $tokenJobs = @($jobs | Where-Object { [string]$_.Description -ceq $prep.transfer_token })
    if ($tokenJobs.Count -gt 1) { throw 'WSL_BITS_JOB_AMBIGUOUS: multiple jobs have the exact preparation token; left untouched' }
    $matching = @($jobs | Where-Object {
        if ([string]$prep.job_id) { [string]$_.JobId -ieq [string]$prep.job_id }
        else { [string]$_.Description -ceq $prep.transfer_token }
    })
    if ($matching.Count -gt 1) { throw 'WSL_BITS_JOB_AMBIGUOUS: multiple jobs have the exact preparation token; left untouched' }
    if ([string]$prep.job_id -and $matching.Count -eq 0 -and $tokenJobs.Count -gt 0) {
        Set-BuilderBITSDiagnostic $tokenJobs[0]
        throw 'WSL_BITS_JOB_IDENTITY_MISMATCH: token belongs to a different job ID; left untouched'
    }
    $job = if ($matching.Count -eq 1) { $matching[0] } else { $null }
    if ($job) {
        Assert-BuilderBITSOwner $job
        $retryableError = $false
        foreach ($name in @('ErrorCondition','ErrorCode','InternalErrorCode')) {
            if ($job.PSObject.Properties.Name -contains $name -and $job.$name) {
                if (Test-BuilderTransientCode $job.$name) { $retryableError = $true }
            }
        }
        if (@($job.FileList).Count -eq 0 -or $job.JobState -in @('Cancelled','Canceled','Acknowledged') -or
            ($job.JobState -eq 'Error' -and $retryableError)) {
            Repair-BuilderBITS $job
            $job = $null
        } elseif ($job.JobState -eq 'Error') {
            throw 'WSL_BITS_PERMANENT_ERROR: recorded job failed with a non-transient error; left untouched'
        }
    } elseif ([string]$prep.job_id) {
        Repair-BuilderBITS $null
    }
    if (-not $job) {
        # The token and intent exist durably before BITS can create even an empty job.
        Save-PreparationState 'wsl_msi_transfer_creating'
        $remaining = [int][Math]::Max(1, 1200 - ((Get-BuilderNow) - (Get-PreparationTime ([string]$prep.transfer_started_at))).TotalSeconds)
        $job = Invoke-BuilderStep 'Start-BitsTransfer' {
            Start-BitsTransfer -Source $prep.source -Destination $prep.destination -DisplayName ($wslBITSDisplayName + ' ' + $prep.id) -Description $prep.transfer_token -Asynchronous -Priority Foreground -RetryInterval 60 -RetryTimeout 300 -MaxDownloadTime $remaining -ErrorAction Stop
        }
        Assert-BuilderBITSOwner $job
    }
    $prep.job_id = [string]$job.JobId
    Save-PreparationState 'wsl_msi_downloading'
    if ($job.JobState -eq 'Suspended') {
        Invoke-BuilderStep 'Resume-BitsTransfer' { Resume-BitsTransfer -BitsJob $job -Asynchronous -ErrorAction Stop } | Out-Null
    }
    if ($job.JobState -eq 'Transferred') {
        Invoke-BuilderStep 'Complete-BitsTransfer' { Complete-BitsTransfer -BitsJob $job -ErrorAction Stop }
        return $true
    }
    if ([long]$job.BytesTransferred -gt [long]$prep.bytes_transferred) {
        $prep.bytes_transferred = [long]$job.BytesTransferred
        $prep.progress_at = (Get-BuilderNow).ToString('o')
    }
    if (((Get-BuilderNow) - (Get-PreparationTime ([string]$prep.transfer_started_at))).TotalMinutes -ge 20 -or
        ((Get-BuilderNow) - (Get-PreparationTime ([string]$prep.progress_at))).TotalMinutes -ge 5) {
        throw 'WSL_BITS_PROGRESS_DEADLINE: transfer exceeded 20 minutes or five minutes without progress'
    }
    Save-PreparationState 'wsl_msi_downloading'
    return $false
}
function Ensure-WSLMSIDownload {
    if (-not [string]$prep.transfer_started_at) {
        $prep.transfer_started_at = (Get-BuilderNow).ToString('o')
        $prep.progress_at = $prep.transfer_started_at
        Save-PreparationState 'wsl_msi_transfer_intent'
    }
    for ($attempt=0; ; $attempt++) {
        # Reconcile the owned job's completion and byte progress before checking inactivity.
        if (((Get-BuilderNow) - (Get-PreparationTime ([string]$prep.transfer_started_at))).TotalMinutes -ge 20) {
            throw 'WSL_BITS_PROGRESS_DEADLINE: transfer exceeded 20 minutes or five minutes without progress'
        }
        try { return (Get-OrCreateBuilderBITS) } catch {
            if (-not (Test-BuilderTransientError $_)) { throw }
            if (-not [string]$prep.startup_started_at) { $prep.startup_started_at = (Get-BuilderNow).ToString('o') }
            if (((Get-BuilderNow) - (Get-PreparationTime ([string]$prep.startup_started_at))).TotalSeconds -ge 120) { throw }
            Save-PreparationState 'wsl_transfer_startup_retry'
            Start-Sleep -Seconds ([Math]::Min(15, [Math]::Pow(2, [Math]::Min($attempt+1, 4))))
            # Re-enumerate the exact token after an uncertain creation result.
        }
    }
}
`

const linuxImageBuilderMachinePhasePowerShell = `
$script:builderPhase = 'machine_checkpoint'
$initialState = Get-BuilderState
Assert-BuilderStateIdentity $initialState
$prep = $initialState.machine_preparation
if (-not $prep) {
    $id = [guid]::NewGuid().ToString('N')
    $now = Get-BuilderNow
    $prep = [pscustomobject]@{
        version=1; id=$id; owner_sid='S-1-5-18'; source=$wslMSIURL; sha256=$wslMSISHA256
        destination=(Join-Path $wslRoot ('preparations\' + $id + '\' + $wslMSIFilename))
        transfer_token=('LabLink-WSL:' + $id + ':' + [guid]::NewGuid().ToString('N')); job_id=''
        deadline=$now.AddMinutes(60).ToString('o'); transfer_started_at=''
        progress_at=''; bytes_transferred=0; startup_started_at=''
        repairs=0; reboots=0; reboot_boot_id=''; machine_ready=$false; completed=$false; failure=''
        install_attempts=0; install_inflight=$false; install_pid=0; install_process_started_at=''
        install_started_at=''; install_exit_code=$null; install_log_path=''; retry_after=''
        install_reboot_pending=$false
    }
    # Do not adopt legacy user jobs, even when their fixed display name matches.
    Save-BuilderState 'machine_preparation_created' '' @{ machine_preparation=$prep }
}
Assert-PreparationState
$script:builderStateValidated = $true
$msiPath = [string]$prep.destination
$preparationRoot = Split-Path -Parent $msiPath
foreach ($directory in @($wslRoot, (Split-Path -Parent $preparationRoot), $preparationRoot)) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    if ((Get-Item -LiteralPath $directory -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'BUILDER_PREPARATION_REPARSE_POINT: refusing redirected MSI storage'
    }
}
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
}
Invoke-BuilderStep 'Set-Acl' { Set-Acl -LiteralPath $preparationRoot -AclObject $acl -ErrorAction Stop }
$script:builderPhase = 'machine_features'
$needsReboot = $false
foreach ($feature in @('Microsoft-Windows-Subsystem-Linux','VirtualMachinePlatform')) {
    $featureState = Invoke-BuilderStep 'Get-WindowsOptionalFeature' {
        Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction Stop
    }
    if ($featureState.State -ne 'Enabled') {
        if ($featureState.State -ne 'EnablePending') {
            Invoke-BuilderStep 'Enable-WindowsOptionalFeature' {
                Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart -ErrorAction Stop
            } | Out-Null
        }
        $needsReboot = $true
    }
}
if ($needsReboot) { Request-BuilderReboot 'features_enabled_reboot_required'; return }

$script:builderPhase = 'machine_runtime_probe'
if ($prep.install_reboot_pending) {
    if ([string]$prep.reboot_boot_id -ceq (Get-BuilderBootID)) {
        Request-BuilderReboot 'wsl_msi_installed_reboot_required'; return
    }
    $prep.install_reboot_pending = $false
    Save-PreparationState 'wsl_msi_post_reboot'
    $product = Get-LabLinkWSLProduct
    if (-not $product -or -not (Test-VersionAtLeast ([string]$product.version) $wslProductVersion)) {
        throw 'WSL_RUNTIME_NOT_READY: pinned MSI runtime absent after required reboot'
    }
}
if ($prep.install_inflight) {
    $existing = if ($prep.install_pid) { Get-Process -Id $prep.install_pid -ErrorAction SilentlyContinue } else { $null }
    if ($existing -and $existing.StartTime.ToUniversalTime().ToString('o') -ceq [string]$prep.install_process_started_at) {
        if (((Get-BuilderNow) - (Get-PreparationTime ([string]$prep.install_started_at))).TotalSeconds -ge 300) {
            throw 'WSL_MSI_INSTALL_TIMEOUT: exact installer is still running; no overlapping retry'
        }
        Write-BuilderPending 'wsl_msi_installing'; return
    }
    # A controller/reboot interruption loses the process exit code. Probe, never blindly reinstall.
    $product = Get-LabLinkWSLProduct
    if (-not $product -or -not (Test-VersionAtLeast ([string]$product.version) $wslProductVersion)) {
        throw 'WSL_MSI_INSTALL_RESULT_UNKNOWN: interrupted installer has no verified runtime; no automatic retry'
    }
    $prep.install_inflight = $false
    $prep.install_pid = 0
    Save-PreparationState 'wsl_msi_reconciled'
}
$product = Get-LabLinkWSLProduct
if (-not $product -or -not (Test-VersionAtLeast ([string]$product.version) $wslProductVersion)) {
    if ($null -ne $prep.install_exit_code -and
        ($prep.install_exit_code -ne 1618 -or $prep.install_attempts -ge 2)) {
        throw "WSL_MSI_INSTALL_FAILED: persisted installer exit $($prep.install_exit_code) without a ready runtime; no blind retry"
    }
    $script:builderPhase = 'wsl_msi_verification'
    if (-not (Test-Path -LiteralPath $msiPath -PathType Leaf)) {
        $legacy = Join-Path $wslRoot $wslMSIFilename
        if (Test-Path -LiteralPath $legacy -PathType Leaf) {
            Get-VerifiedWSLMSI $legacy | Out-Null
            # Reverify the copy too: the legacy pathname can change after the first check.
            Invoke-BuilderStep 'Copy-Item' { Copy-Item -LiteralPath $legacy -Destination $msiPath -ErrorAction Stop }
        }
    }
    $msiReady = Test-WSLMSI
    if (-not $msiReady) {
        if (-not (Ensure-WSLMSIDownload)) { Write-BuilderPending 'wsl_msi_downloading'; return }
        if (-not (Test-WSLMSI)) { throw 'WSL_MSI_VERIFICATION_FAILED: completed transfer did not publish an MSI' }
    }
    if ($prep.retry_after -and (Get-BuilderNow) -lt (Get-PreparationTime ([string]$prep.retry_after))) {
        Write-BuilderPending 'wsl_msi_retrying'; return
    }
    if ($prep.install_attempts -ge 2) { throw 'WSL_MSI_INSTALL_FAILED: exhausted two installer attempts' }
    $prep.install_attempts++
    $prep.install_exit_code = $null
    $prep.install_inflight = $true
    $prep.install_started_at = (Get-BuilderNow).ToString('o')
    $prep.install_log_path = Join-Path $preparationRoot ('wsl-msi-attempt-{0}.log' -f $prep.install_attempts)
    Save-PreparationState 'wsl_msi_installing'
    $msiProcess = Invoke-BuilderStep 'Start-Process' {
        Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList @(
            '/i', ('"' + $msiPath + '"'), '/qn', '/norestart', '/L*v', ('"' + $prep.install_log_path + '"')
        ) -PassThru -WindowStyle Hidden -ErrorAction Stop
    }
    $null = $msiProcess.Handle
    $prep.install_pid = $msiProcess.Id
    $prep.install_process_started_at = $msiProcess.StartTime.ToUniversalTime().ToString('o')
    Save-PreparationState 'wsl_msi_installing'
    if (-not $msiProcess.WaitForExit(300000)) { Write-BuilderPending 'wsl_msi_installing'; return }
    $msiProcess.Refresh()
    $prep.install_exit_code = [int]$msiProcess.ExitCode
    $prep.install_inflight = $false
    $prep.install_pid = 0
    $prep.install_reboot_pending = ($prep.install_exit_code -eq 3010)
    if ($prep.install_exit_code -eq 1618) { $prep.retry_after = (Get-BuilderNow).AddSeconds(30).ToString('o') }
    Save-PreparationState 'wsl_msi_install_attempt_complete'
    if ($prep.install_exit_code -eq 3010) {
        Request-BuilderReboot 'wsl_msi_installed_reboot_required'; return
    }
    if ($prep.install_exit_code -eq 1618 -and $prep.install_attempts -lt 2) {
        Write-BuilderPending 'wsl_msi_retrying'; return
    }
    if ($prep.install_exit_code -ne 0) {
        throw "WSL_MSI_INSTALL_FAILED: exit $($prep.install_exit_code); log '$($prep.install_log_path)'"
    }
    $product = Get-LabLinkWSLProduct
    if (-not $product -or -not (Test-VersionAtLeast ([string]$product.version) $wslProductVersion)) {
        throw 'WSL_RUNTIME_NOT_READY: MSI returned success without a registered Microsoft WSL runtime'
    }
}
$prep.machine_ready = $true
Save-PreparationState 'machine_ready'
[pscustomobject]@{
    status='machine_ready'; phase='machine_ready'; preparation_id=$prep.id
    builder_user=$builderUser; builder_user_sid=$builderUserSID; machine_owner_sid=$prep.owner_sid
} | ConvertTo-Json -Compress
`
