package hyperv

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/nijosmsft/lablink/internal/linuximage"
)

var stagingIDPattern = regexp.MustCompile(`^[a-f0-9]{16,64}$`)

const LinuxImageBuilderMetadataPrefix = "LABLINK_LINUX_IMAGE_BUILDER_V1:"

const linuxImageTransformBash = `set -euo pipefail
target_disk="${1:?target disk path is required}"
case "$target_disk" in
  /dev/*) ;;
  *) echo "LABLINK_TARGET_DISK_PATH_INVALID=$target_disk" >&2; exit 43 ;;
esac
target_name="$(basename -- "$target_disk")"
probe=/mnt/lablink-probe
root=/mnt/lablink-image
mkdir -p "$probe" "$root"
matches=()
disk_rows=0
while read -r path type pkname fstype; do
  if [ "$path" = "$target_disk" ]; then
    if [ "$type" != disk ] || [ -n "$pkname" ]; then
      echo "LABLINK_TARGET_DISK_RELATION_INVALID=$path,$type,$pkname" >&2
      exit 43
    fi
    disk_rows=$((disk_rows + 1))
    continue
  fi
  if [ "$type" != part ] || [ "$pkname" != "$target_name" ]; then
    echo "LABLINK_PARTITION_PARENT_INVALID=$path,$type,$pkname,$target_name" >&2
    exit 43
  fi
  [ "$fstype" = ext4 ] || continue
  mount -o ro "$path" "$probe"
  if [ -f "$probe/etc/os-release" ] && grep -qx 'ID=ubuntu' "$probe/etc/os-release" && [ -d "$probe/etc/cloud" ]; then
    matches+=("$path")
  fi
  umount "$probe"
done < <(lsblk -rno PATH,TYPE,PKNAME,FSTYPE "$target_disk")
if [ "$disk_rows" -ne 1 ]; then
  echo "LABLINK_TARGET_DISK_ROW_COUNT=$disk_rows" >&2
  exit 43
fi
if [ "${#matches[@]}" -ne 1 ]; then
  echo "LABLINK_EXT4_ROOT_COUNT=${#matches[@]}" >&2
  exit 42
fi
mounted=0
cleanup() { if [ "$mounted" -eq 1 ]; then umount "$root"; fi; }
trap cleanup EXIT
mount "${matches[0]}" "$root"
mounted=1
target="$root/etc/cloud/cloud.cfg.d/99-lablink-nocloud.cfg"
mkdir -p "$(dirname "$target")"
tmp="$target.lablink-tmp-$$"
printf '%s\n' 'datasource_list: [ NoCloud, None ]' > "$tmp"
chmod 0644 "$tmp"
sync "$tmp"
mv -f "$tmp" "$target"
sync "$target"
grep -Fxq 'datasource_list: [ NoCloud, None ]' "$target"
umount "$root"
mounted=0
sync
echo "LABLINK_ROOT_PARTITION=${matches[0]}"`

func validateStagingID(id string) error {
	if !stagingIDPattern.MatchString(id) {
		return fmt.Errorf("staging ID must be 16-64 lowercase hexadecimal characters")
	}
	return nil
}

func BuildLinuxImagePrerequisiteProbeScript() (string, error) {
	body := `
$requiredCommands = @(
    'Start-BitsTransfer','Get-BitsTransfer','Resume-BitsTransfer','Complete-BitsTransfer',
    'Remove-BitsTransfer','Convert-VHD','Resize-VHD','Get-VHD','Get-VM','tar.exe'
)
$missing = @($requiredCommands | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
if ($missing.Count -gt 0) { throw "LINUX_IMAGE_PREREQUISITES_MISSING: $($missing -join ', ')" }
[pscustomobject]@{
    status='ready'; hyper_v=$true; bits=$true; conversion_tool='inbox-convert-vhd'
    archive_tool='inbox-tar'; filesystem_mutation=$false
} | ConvertTo-Json -Compress
`
	return wrapTagged(body), nil
}

func BuildLinuxImageBuilderSourcePreflightScript(baseVHD, vmRoot, vswitch string) (string, error) {
	if strings.TrimSpace(baseVHD) == "" || strings.TrimSpace(vmRoot) == "" || strings.TrimSpace(vswitch) == "" {
		return "", fmt.Errorf("builder base VHD, VM root, and vSwitch are required")
	}
	body := fmt.Sprintf(`
$baseVHD = %s
$vmRoot = %s
$vswitch = %s
$requiredCommands = @('Get-VM','Get-VHD','Get-VMSwitch','Convert-VHD','Resize-VHD','Start-BitsTransfer','tar.exe')
$missing = @($requiredCommands | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
if ($missing.Count -gt 0) { throw "LINUX_IMAGE_PREREQUISITES_MISSING: $($missing -join ', ')" }
if (-not (Test-Path -LiteralPath $baseVHD -PathType Leaf)) {
    throw "BUILDER_BASE_VHD_NOT_FOUND: '$baseVHD'"
}
$base = Get-VHD -Path $baseVHD -ErrorAction Stop
if ([string]::IsNullOrWhiteSpace([string]$base.Path)) {
    throw "BUILDER_BASE_VHD_INVALID: '$baseVHD'"
}
if (-not (Get-VMSwitch -Name $vswitch -ErrorAction SilentlyContinue)) {
    throw "BUILDER_VSWITCH_NOT_FOUND: '$vswitch'"
}
$rootQualifier = Split-Path -Qualifier $vmRoot
if ([string]::IsNullOrWhiteSpace($rootQualifier)) {
    throw "BUILDER_VM_ROOT_INVALID: '$vmRoot'"
}
[pscustomobject]@{
    status='builder_source_ready'; base_vhd=[IO.Path]::GetFullPath($baseVHD)
    vm_root=[IO.Path]::GetFullPath($vmRoot); vswitch=$vswitch; source_preconditions_valid=$true
} | ConvertTo-Json -Compress
`, PSLit(baseVHD), PSLit(vmRoot), PSLit(vswitch))
	return wrapTagged(body), nil
}

type LinuxImageDownloadParams struct {
	CacheRoot  string
	StagingID  string
	DiskSizeGB int
}

func BuildLinuxImageDownloadScript(p LinuxImageDownloadParams) (string, error) {
	if strings.TrimSpace(p.CacheRoot) == "" {
		return "", fmt.Errorf("image cache root is required")
	}
	if err := validateStagingID(p.StagingID); err != nil {
		return "", err
	}
	if err := linuximage.ValidateDiskSizeGB(p.DiskSizeGB); err != nil {
		return "", err
	}
	source := linuximage.FixedSource()
	body := fmt.Sprintf(`
$cacheRoot = %s
$candidateStagingID = %s
$sourceID = %s
$schemaVersion = %s
$diskSizeGB = %d
$sourceRoot = Join-Path $cacheRoot ('sources\' + $sourceID)
$stateDir = Join-Path $sourceRoot ('variants\disk-' + $diskSizeGB)
$downloadDir = Join-Path $sourceRoot 'downloads'
$statePath = Join-Path $stateDir 'state.json'
New-Item -ItemType Directory -Force -Path $downloadDir,$stateDir | Out-Null

$stagingID = $candidateStagingID
$existingState = $null
if (Test-Path -LiteralPath $statePath) {
    try {
        $existingState = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
        if ($existingState.schema_version -cne $schemaVersion) {
            $existingState = $null
        } elseif ($existingState.staging_id) {
            $stagingID = [string]$existingState.staging_id
        }
    } catch { throw "STATE_INVALID: cannot parse '$statePath': $($_.Exception.Message)" }
}
if ($existingState -and $existingState.phase -eq 'ready' -and
    $existingState.prepared_vhdx -and (Test-Path -LiteralPath ([string]$existingState.prepared_vhdx) -PathType Leaf)) {
    [pscustomobject]@{ status='ready'; all_complete=$true; ready=$true; state_path=$statePath; state=$existingState } |
        ConvertTo-Json -Depth 12 -Compress
    return
}
if ($existingState -and $existingState.image_path -and
    (Test-Path -LiteralPath ([string]$existingState.image_path) -PathType Leaf) -and
    $existingState.phase -in @('image_validated','converted','builder_ready','disk_attached','filesystem_updated','diagnostic_retained')) {
    [pscustomobject]@{ status='downloads_complete'; all_complete=$true; ready=$false; state_path=$statePath; state=$existingState } |
        ConvertTo-Json -Depth 12 -Compress
    return
}

function Ensure-BitsDownload([string]$kind, [string]$url, [string]$destination) {
    $displayName = "LabLink Linux Image $sourceID $kind"
    $trustedDestination = $false
    if ($existingState -and (Test-Path -LiteralPath $destination -PathType Leaf)) {
        $trustedRecord = @($existingState.jobs | Where-Object {
            [string]$_.kind -ceq $kind -and [string]$_.state -ceq 'Transferred' -and
            [string]$_.url -ceq $url -and $_.destination -and
            [IO.Path]::GetFullPath([string]$_.destination).Equals(
                [IO.Path]::GetFullPath($destination), [StringComparison]::OrdinalIgnoreCase)
        })
        $trustedDestination = $trustedRecord.Count -eq 1
    }
    $matchingJobs = @(Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $displayName } | Sort-Object CreationTime -Descending)
    foreach ($candidate in $matchingJobs) {
        $files = @($candidate.FileList)
        if ($files.Count -ne 1 -or [string]$files[0].RemoteName -cne $url -or
            -not [IO.Path]::GetFullPath([string]$files[0].LocalName).Equals(
                [IO.Path]::GetFullPath($destination), [StringComparison]::OrdinalIgnoreCase)) {
            throw "BITS_JOB_SOURCE_MISMATCH: '$displayName' does not match the fixed source and destination"
        }
        if ($candidate.JobState -in @('Error','Cancelled','Canceled')) {
            Remove-BitsTransfer -BitsJob $candidate -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
    $job = @($matchingJobs | Where-Object { $_.JobState -notin @('Error','Cancelled','Canceled') } |
        Select-Object -First 1)
    if ($job.Count -eq 1) { $job = $job[0] } else { $job = $null }
    if ($trustedDestination) {
        $length = (Get-Item -LiteralPath $destination).Length
        return [pscustomobject]@{ kind=$kind; url=$url; destination=$destination; state='Transferred'; bytes_transferred=$length; bytes_total=$length }
    }
    if (Test-Path -LiteralPath $destination -PathType Leaf) {
        Remove-Item -LiteralPath $destination -Force -ErrorAction Stop
    }
    if (-not $job) {
        $job = Start-BitsTransfer -Source $url -Destination $destination -DisplayName $displayName -Description $stagingID -Asynchronous
    } elseif ($job.JobState -in @('Suspended','TransientError')) {
        Resume-BitsTransfer -BitsJob $job -Asynchronous
        $job = Get-BitsTransfer -JobId $job.JobId
    }
    if ($job.JobState -eq 'Transferred') {
        Complete-BitsTransfer -BitsJob $job
        $length = (Get-Item -LiteralPath $destination).Length
        return [pscustomobject]@{ kind=$kind; url=$url; destination=$destination; id="$($job.JobId)"; display_name=$displayName; state='Transferred'; bytes_transferred=$length; bytes_total=$length }
    }
    $jobError = if ($job.JobState -eq 'Error') { "$($job.ErrorDescription)" } else { $null }
    $bytesTotal = if ([uint64]$job.BytesTotal -gt [uint64][int64]::MaxValue) { -1 } else { [int64]$job.BytesTotal }
    return [pscustomobject]@{ kind=$kind; url=$url; destination=$destination; id="$($job.JobId)"; display_name=$displayName; state="$($job.JobState)"; bytes_transferred=[int64]$job.BytesTransferred; bytes_total=$bytesTotal; error=$jobError }
}

$downloads = @(
    [pscustomobject]@{ kind='azure_vhd_archive'; url=%s; destination=(Join-Path $downloadDir %s) },
    [pscustomobject]@{ kind='manifest'; url=%s; destination=(Join-Path $downloadDir %s) },
    [pscustomobject]@{ kind='signature'; url=%s; destination=(Join-Path $downloadDir %s) }
)
$jobs = @($downloads | ForEach-Object { Ensure-BitsDownload $_.kind $_.url $_.destination })
$allComplete = @($jobs | Where-Object { $_.state -ne 'Transferred' }).Count -eq 0
$hasError = @($jobs | Where-Object { $_.state -eq 'Error' }).Count -gt 0
$phase = if ($hasError) { 'failed' } elseif ($allComplete) { 'signature_verification_required' } else { 'downloading' }
$state = [ordered]@{
    schema_version=$schemaVersion; source=%s | ConvertFrom-Json; phase=$phase; staging_id=$stagingID
    cache_root=$cacheRoot; disk_size_gb=$diskSizeGB; jobs=$jobs
    verification=[ordered]@{ status='pending' }; updated_at=(Get-Date).ToUniversalTime().ToString('o')
}
$tmpState = "$statePath.$candidateStagingID.tmp"
$state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmpState -Encoding UTF8
Move-Item -Force -LiteralPath $tmpState -Destination $statePath
[pscustomobject]@{
    status=$(if ($allComplete) { 'downloads_complete' } elseif ($hasError) { 'download_failed' } else { 'image_preparing' })
    state_path=$statePath; download_dir=$downloadDir; all_complete=$allComplete; state=$state
} | ConvertTo-Json -Depth 10 -Compress
`, PSLit(p.CacheRoot), PSLit(p.StagingID), PSLit(source.ID), PSLit(linuximage.TransformSchema), p.DiskSizeGB,
		PSLit(source.ImageURL), PSLit(source.ImageFilename),
		PSLit(source.SHA256SUMSURL), PSLit(source.ManifestFilename),
		PSLit(source.SHA256SUMSSignature), PSLit(source.SignatureFilename),
		PSLit(mustJSON(source)))
	return wrapTagged(body), nil
}

func BuildLinuxImageStatusScript(cacheRoot string, diskSizeGB int) (string, error) {
	if strings.TrimSpace(cacheRoot) == "" {
		return "", fmt.Errorf("image cache root is required")
	}
	if err := linuximage.ValidateDiskSizeGB(diskSizeGB); err != nil {
		return "", err
	}
	body := fmt.Sprintf(`
$cacheRoot = %s
$statePath = Join-Path $cacheRoot %s
if (-not (Test-Path -LiteralPath $statePath)) {
    [pscustomobject]@{ status='not_started'; state_path=$statePath } | ConvertTo-Json -Compress
    return
}
$state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
if ($state.schema_version -cne %s) {
    [pscustomobject]@{ status='stale_schema'; state_path=$statePath; expected_schema=%s; actual_schema=[string]$state.schema_version } | ConvertTo-Json -Compress
    return
}
if ($state.phase -eq 'ready') {
    $expectedContentDir = Join-Path $cacheRoot ('prepared\' + [string]$state.cache_key)
    $expectedVHDX = Join-Path $expectedContentDir %s
    $expectedMetadata = Join-Path $expectedContentDir 'metadata.json'
    if ([IO.Path]::GetFullPath([string]$state.prepared_vhdx) -cne [IO.Path]::GetFullPath($expectedVHDX) -or
        [IO.Path]::GetFullPath([string]$state.metadata_path) -cne [IO.Path]::GetFullPath($expectedMetadata)) {
        throw "READY_PATH_INVALID: state paths are outside the content-addressed cache location"
    }
    if (-not (Test-Path -LiteralPath $expectedVHDX -PathType Leaf) -or -not (Get-Item -LiteralPath $expectedVHDX).IsReadOnly) {
        throw "READY_IMAGE_INVALID: prepared VHDX is missing or writable"
    }
    if (-not (Test-Path -LiteralPath $expectedMetadata -PathType Leaf) -or -not (Get-Item -LiteralPath $expectedMetadata).IsReadOnly) {
        throw "READY_METADATA_INVALID: metadata.json is missing or writable"
    }
    $metadata = Get-Content -Raw -LiteralPath $expectedMetadata | ConvertFrom-Json
    $actualHash = (Get-FileHash -LiteralPath $expectedVHDX -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($metadata.cache_key -cne $state.cache_key -or $metadata.schema_version -cne %s -or
        [int]$metadata.disk_size_gb -ne [int]$state.disk_size_gb -or
        $metadata.prepared_vhdx -cne $expectedVHDX -or $metadata.source.id -cne %s -or
        $metadata.source.image_url -cne %s -or $metadata.image_sha256 -cne $state.image_sha256 -or
        $metadata.prepared_sha256 -cne $actualHash -or $state.prepared_sha256 -cne $actualHash -or
        [string]::IsNullOrWhiteSpace([string]$metadata.image_builder_profile) -or
        ([string]$metadata.builder_profile_fingerprint).Length -ne 64 -or
        $metadata.verification.status -cne 'verified' -or $metadata.verification.signer -cne %s) {
        throw "READY_METADATA_INVALID: cache key, source, prepared digest, or signer verification is invalid"
    }
    $vhd = Get-VHD -Path $expectedVHDX -ErrorAction Stop
    $expectedSize = [int64]$metadata.disk_size_gb * 1GB
    if ("$($vhd.VhdType)" -ne 'Dynamic' -or [int64]$vhd.BlockSize -ne 1MB -or [int64]$vhd.Size -ne $expectedSize) {
        throw "READY_IMAGE_INVALID: prepared VHDX type, block size, or virtual size is invalid"
    }
}
foreach ($entry in @($state.jobs)) {
    if (-not $entry.id -or $entry.state -eq 'Transferred') { continue }
    $job = Get-BitsTransfer -JobId ([guid]$entry.id) -ErrorAction SilentlyContinue
    if ($job) {
        $entry.state = "$($job.JobState)"; $entry.bytes_transferred = [int64]$job.BytesTransferred
        $entry.bytes_total = if ([uint64]$job.BytesTotal -gt [uint64][int64]::MaxValue) { -1 } else { [int64]$job.BytesTotal }
        if ($job.JobState -eq 'Error') { $entry.error = "$($job.ErrorDescription)" }
    }
}
[pscustomobject]@{ status="$($state.phase)"; state_path=$statePath; state=$state } | ConvertTo-Json -Depth 12 -Compress
`, PSLit(cacheRoot), PSLit(fmt.Sprintf(`sources\%s\variants\disk-%d\state.json`, linuximage.SourceID, diskSizeGB)),
		PSLit(linuximage.TransformSchema), PSLit(linuximage.TransformSchema), PSLit(linuximage.SourceID+".vhdx"),
		PSLit(linuximage.TransformSchema), PSLit(linuximage.SourceID), PSLit(linuximage.ImageURL),
		PSLit(linuximage.UbuntuSigningKeyFingerprint))
	return wrapTagged(body), nil
}

type LinuxImageVerifyParams struct {
	CacheRoot         string
	ExpectedImageHash string
	CacheKey          string
	DiskSizeGB        int
	Verification      linuximage.VerificationState
}

func BuildLinuxImageVerifyScript(p LinuxImageVerifyParams) (string, error) {
	if strings.TrimSpace(p.CacheRoot) == "" || strings.TrimSpace(p.ExpectedImageHash) == "" || strings.TrimSpace(p.CacheKey) == "" {
		return "", fmt.Errorf("cache root, expected image hash, and cache key are required")
	}
	if err := linuximage.ValidateDiskSizeGB(p.DiskSizeGB); err != nil {
		return "", err
	}
	if p.Verification.Status != linuximage.VerificationVerified ||
		!strings.EqualFold(p.Verification.Signer, linuximage.UbuntuSigningKeyFingerprint) {
		return "", fmt.Errorf("refusing image validation without the pinned verified Ubuntu signer")
	}
	verificationJSON, err := json.Marshal(p.Verification)
	if err != nil {
		return "", err
	}
	body := fmt.Sprintf(`
$cacheRoot = %s
$expectedImageHash = %s
$cacheKey = %s
$verification = %s | ConvertFrom-Json
$sourceRoot = Join-Path $cacheRoot %s
$stateDir = Join-Path $sourceRoot %s
$downloadDir = Join-Path $sourceRoot 'downloads'
$statePath = Join-Path $stateDir 'state.json'
$downloadImage = Join-Path $downloadDir %s
$imageBlobDir = Join-Path $cacheRoot ('blobs\sha256\' + $expectedImageHash)
$imageBlob = Join-Path $imageBlobDir %s
if (-not (Test-Path -LiteralPath $statePath)) { throw "STATE_MISSING: '$statePath'" }
function Move-LabLinkBadOwnedFile([string]$Path, [string]$Kind) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    Set-ItemProperty -LiteralPath $Path -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
    $quarantinePath = "$Path.bad-$Kind-$([guid]::NewGuid().ToString('N'))"
    Move-Item -LiteralPath $Path -Destination $quarantinePath -ErrorAction Stop
    return $quarantinePath
}
$imageCandidate = if (Test-Path -LiteralPath $imageBlob -PathType Leaf) { $imageBlob } else { $downloadImage }
if (-not (Test-Path -LiteralPath $imageCandidate -PathType Leaf)) { throw "IMAGE_MISSING: '$imageCandidate'" }
$actualImageHash = (Get-FileHash -LiteralPath $imageCandidate -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualImageHash -cne $expectedImageHash) {
    $quarantined = Move-LabLinkBadOwnedFile $imageCandidate 'azure-vhd-archive'
    throw "IMAGE_SHA256_MISMATCH: expected $expectedImageHash, got $actualImageHash; quarantined '$quarantined'"
}
if ($imageCandidate -ne $imageBlob) {
    New-Item -ItemType Directory -Force -Path $imageBlobDir | Out-Null
    $imageTmp = "$imageBlob.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        Copy-Item -LiteralPath $imageCandidate -Destination $imageTmp -ErrorAction Stop
        Move-Item -LiteralPath $imageTmp -Destination $imageBlob -ErrorAction Stop
    } catch {
        if (-not (Test-Path -LiteralPath $imageBlob -PathType Leaf)) { throw }
        if ((Get-FileHash -LiteralPath $imageBlob -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedImageHash) {
            $quarantined = Move-LabLinkBadOwnedFile $imageBlob 'azure-vhd-archive-blob'
            throw "IMAGE_PUBLISH_RACE: existing blob digest is invalid; quarantined '$quarantined'"
        }
    } finally { Remove-Item -LiteralPath $imageTmp -Force -ErrorAction SilentlyContinue }
}
Set-ItemProperty -LiteralPath $imageBlob -Name IsReadOnly -Value $true
$state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
$state | Add-Member -NotePropertyName phase -NotePropertyValue 'image_validated' -Force
$state | Add-Member -NotePropertyName image_sha256 -NotePropertyValue $expectedImageHash -Force
$state | Add-Member -NotePropertyName cache_key -NotePropertyValue $cacheKey -Force
$state | Add-Member -NotePropertyName disk_size_gb -NotePropertyValue %d -Force
$state | Add-Member -NotePropertyName image_path -NotePropertyValue $imageBlob -Force
$state | Add-Member -NotePropertyName verification -NotePropertyValue $verification -Force
$state | Add-Member -NotePropertyName error -NotePropertyValue $null -Force
$state | Add-Member -NotePropertyName updated_at -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force
$tmpState = "$statePath.$([guid]::NewGuid().ToString('N')).tmp"
$state | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $tmpState -Encoding UTF8
Move-Item -Force -LiteralPath $tmpState -Destination $statePath
[pscustomobject]@{ status='image_validated'; image_path=$imageBlob; image_sha256=$actualImageHash; cache_key=$cacheKey; state_path=$statePath } | ConvertTo-Json -Compress
`, PSLit(p.CacheRoot), PSLit(strings.ToLower(p.ExpectedImageHash)), PSLit(p.CacheKey),
		PSLit(string(verificationJSON)), PSLit(`sources\`+linuximage.SourceID),
		PSLit(fmt.Sprintf(`variants\disk-%d`, p.DiskSizeGB)), PSLit(linuximage.ImageFilename),
		PSLit(linuximage.ImageFilename), p.DiskSizeGB)
	return wrapTagged(body), nil
}

type LinuxImageConvertParams struct {
	SourceArchive   string
	DestinationVHDX string
	StatePath       string
	StageDir        string
	DiskSizeGB      int
}

func BuildLinuxImageConvertScript(p LinuxImageConvertParams) (string, error) {
	if strings.TrimSpace(p.SourceArchive) == "" || strings.TrimSpace(p.DestinationVHDX) == "" ||
		strings.TrimSpace(p.StageDir) == "" {
		return "", fmt.Errorf("source Azure VHD archive, stage directory, and destination VHDX are required")
	}
	if err := linuximage.ValidateDiskSizeGB(p.DiskSizeGB); err != nil {
		return "", err
	}
	body := fmt.Sprintf(`
$sourceArchive = %s
$stageDir = %s
$destinationVHDX = %s
$diskSizeBytes = %s
$expectedMember = %s
$extractedVHD = Join-Path $stageDir $expectedMember
if (-not (Test-Path -LiteralPath $sourceArchive -PathType Leaf)) { throw "SOURCE_AZURE_VHD_ARCHIVE_NOT_FOUND: '$sourceArchive'" }
New-Item -ItemType Directory -Force -Path $stageDir,(Split-Path -Parent $destinationVHDX) | Out-Null
if (-not (Test-Path -LiteralPath $destinationVHDX -PathType Leaf)) {
    $members = @(& tar.exe -tzf $sourceArchive)
    if ($LASTEXITCODE -ne 0) { throw "AZURE_VHD_ARCHIVE_LIST_FAILED: tar exited $LASTEXITCODE" }
    $normalized = @($members | ForEach-Object { ([string]$_).Replace('\','/').TrimStart('./') } | Where-Object { $_ })
    if ($normalized.Count -ne 1 -or $normalized[0] -cne $expectedMember -or
        $normalized[0].Contains('/') -or $normalized[0] -in @('.','..')) {
        throw "AZURE_VHD_ARCHIVE_FILESET_INVALID: expected exactly '$expectedMember', got '$($normalized -join ',')'"
    }
    & tar.exe -xzf $sourceArchive -C $stageDir -- $expectedMember
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $extractedVHD -PathType Leaf)) {
        throw "AZURE_VHD_ARCHIVE_EXTRACT_FAILED: '$expectedMember'"
    }
    $sourceItem = Get-Item -LiteralPath $extractedVHD
    if (($sourceItem.Attributes -band [IO.FileAttributes]::Compressed) -ne 0) {
        throw "SOURCE_VHD_COMPRESSED: Hyper-V does not support compressed virtual disks"
    }
    if (($sourceItem.Attributes -band [IO.FileAttributes]::Encrypted) -ne 0) {
        throw "SOURCE_VHD_ENCRYPTED: Hyper-V does not support EFS-encrypted virtual disks"
    }
    if (($sourceItem.Attributes -band [IO.FileAttributes]::SparseFile) -ne 0) {
        & fsutil.exe sparse setflag $extractedVHD 0 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "SOURCE_VHD_DESPARSE_FAILED: fsutil exited $LASTEXITCODE" }
        $sourceItem = Get-Item -LiteralPath $extractedVHD
        if (($sourceItem.Attributes -band [IO.FileAttributes]::SparseFile) -ne 0) {
            throw "SOURCE_VHD_STILL_SPARSE: fsutil did not clear the sparse-file attribute"
        }
    }
    Convert-VHD -Path $extractedVHD -DestinationPath $destinationVHDX -VHDType Dynamic -BlockSizeBytes 1MB -DeleteSource -ErrorAction Stop
}
$item = Get-Item -LiteralPath $destinationVHDX -ErrorAction Stop
if (($item.Attributes -band ([IO.FileAttributes]::Compressed -bor [IO.FileAttributes]::Encrypted -bor [IO.FileAttributes]::ReparsePoint)) -ne 0) {
    throw "VHDX_FILE_ATTRIBUTES_INVALID: compressed, encrypted, and reparse-point disks are forbidden"
}
$vhd = Get-VHD -Path $destinationVHDX -ErrorAction Stop
if ([int64]$vhd.Size -gt $diskSizeBytes) { throw "VHDX_DISK_SIZE_TOO_SMALL: requested size is below the source image virtual size" }
if ([int64]$vhd.Size -lt $diskSizeBytes) {
    Resize-VHD -Path $destinationVHDX -SizeBytes $diskSizeBytes -ErrorAction Stop
    $vhd = Get-VHD -Path $destinationVHDX -ErrorAction Stop
}
if ("$($vhd.VhdType)" -ne 'Dynamic') { throw "VHDX_TYPE_INVALID: expected Dynamic, got $($vhd.VhdType)" }
if ([int64]$vhd.BlockSize -ne 1MB) { throw "VHDX_BLOCK_SIZE_INVALID: expected 1048576, got $($vhd.BlockSize)" }
if ([int64]$vhd.Size -ne $diskSizeBytes) { throw "VHDX_SIZE_INVALID: expected $diskSizeBytes, got $($vhd.Size)" }
%s
[pscustomobject]@{
    status='converted'; vhdx_path=$destinationVHDX; disk_identifier=[string]$vhd.DiskIdentifier
    virtual_size=[int64]$vhd.Size; vhd_type="$($vhd.VhdType)"; block_size=[int64]$vhd.BlockSize
    source_format='azure-vhd-tar-gz'; output_format='vhdx'
} | ConvertTo-Json -Compress
`, PSLit(p.SourceArchive), PSLit(p.StageDir), PSLit(p.DestinationVHDX),
		gbBytes(float64(p.DiskSizeGB)), PSLit(linuximage.ExtractedVHDFilename),
		linuxImageStateUpdate(p.StatePath, "converted", map[string]string{"staged_vhdx": "$destinationVHDX"}))
	return wrapTagged(body), nil
}

type LinuxImageBuilderMetadata struct {
	SchemaVersion      int    `json:"schema_version"`
	Target             string `json:"target"`
	Profile            string `json:"profile"`
	ProfileFingerprint string `json:"profile_fingerprint"`
	VMName             string `json:"vm_name"`
	NodeName           string `json:"node_name"`
}

func LinuxImageBuilderManagedMetadata(m LinuxImageBuilderMetadata) (string, error) {
	if m.SchemaVersion != 1 || strings.TrimSpace(m.Target) == "" || strings.TrimSpace(m.Profile) == "" ||
		strings.TrimSpace(m.ProfileFingerprint) == "" || strings.TrimSpace(m.VMName) == "" ||
		strings.TrimSpace(m.NodeName) == "" {
		return "", fmt.Errorf("complete Linux image builder metadata is required")
	}
	if len(m.ProfileFingerprint) != 64 || !stagingIDPattern.MatchString(m.ProfileFingerprint) {
		return "", fmt.Errorf("Linux image builder profile fingerprint must be 64 lowercase hexadecimal characters")
	}
	data, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return LinuxImageBuilderMetadataPrefix + string(data), nil
}

func BuildInspectLinuxImageBuilderScript(name string, expected LinuxImageBuilderMetadata) (string, error) {
	metadata, err := LinuxImageBuilderManagedMetadata(expected)
	if err != nil {
		return "", err
	}
	body := fmt.Sprintf(`
$name = %s
$expected = %s
$vm = Get-VM -Name $name -ErrorAction SilentlyContinue
if (-not $vm) { [pscustomobject]@{ exists=$false } | ConvertTo-Json -Compress; return }
if ([string]$vm.Notes -cne $expected) {
    throw "BUILDER_OWNERSHIP_MISMATCH: existing VM '$name' was not created for this LabLink builder profile and target"
}
$drives = @(Get-VMHardDiskDrive -VMName $name -ErrorAction Stop)
[pscustomobject]@{
    exists=$true; state=[string]$vm.State; id=[string]$vm.Id; notes=[string]$vm.Notes
    disk_count=$drives.Count; disk_paths=@($drives | ForEach-Object { [string]$_.Path })
    expose_virtualization_extensions=[bool](Get-VMProcessor -VMName $name).ExposeVirtualizationExtensions
    dynamic_memory=[bool](Get-VMMemory -VMName $name).DynamicMemoryEnabled
    virtualization_based_security_opt_out=[bool](Get-VMSecurity -VMName $name).VirtualizationBasedSecurityOptOut
} | ConvertTo-Json -Depth 5 -Compress
`, PSLit(name), PSLit(metadata))
	return wrapTagged(body), nil
}

func BuildLinuxImageBuilderInventoryScript(statePath string) (string, error) {
	if strings.TrimSpace(statePath) == "" {
		return "", fmt.Errorf("builder state path is required")
	}
	body := fmt.Sprintf(`
$statePath = %s
$parent = Split-Path -Parent $statePath
New-Item -ItemType Directory -Force -Path $parent | Out-Null
$inventory = @(Get-Disk | ForEach-Object {
    [pscustomobject]@{
        number=[int]$_.Number; unique_id=[string]$_.UniqueId; serial_number=[string]$_.SerialNumber
        path=[string]$_.Path; location=[string]$_.Location; size=[int64]$_.Size
    }
})
$state = if (Test-Path -LiteralPath $statePath -PathType Leaf) {
    Get-Content -Raw -LiteralPath $statePath -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
} else {
    [pscustomobject]@{}
}
$state | Add-Member -NotePropertyName schema_version -NotePropertyValue 2 -Force
$state | Add-Member -NotePropertyName phase -NotePropertyValue 'pre_attach_inventory' -Force
$state | Add-Member -NotePropertyName pre_attach_disks -NotePropertyValue $inventory -Force
$state | Add-Member -NotePropertyName updated_at -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force
$tmp = "$statePath.$([guid]::NewGuid().ToString('N')).tmp"
[IO.File]::WriteAllText($tmp, ($state | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
Move-Item -Force -LiteralPath $tmp -Destination $statePath
[pscustomobject]@{ status='inventory_captured'; state_path=$statePath; disk_count=$inventory.Count; disks=$inventory } | ConvertTo-Json -Depth 8 -Compress
`, PSLit(statePath))
	return wrapTagged(body), nil
}

const linuxImageBuilderAccountResolverPowerShell = `
function Test-LabLinkLocalAdministrator([string]$SID) {
    if ([string]::IsNullOrWhiteSpace($SID)) { return $false }
    $administratorsSID = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $administrators = Get-LocalGroup -SID $administratorsSID -ErrorAction Stop
    $members = @(Get-LocalGroupMember -Group $administrators -ErrorAction Stop)
    return @($members | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.SID) -and
        [string]$_.SID -ceq $SID
    }).Count -eq 1
}
function Resolve-LabLinkBuilderUser([string]$ConfiguredUsername) {
    if ([string]::IsNullOrWhiteSpace($ConfiguredUsername)) {
        throw 'BUILDER_USER_ENV_MISSING: LABLINK_BUILDER_USERNAME is required'
    }
    $localUsers = @(Get-LocalUser -ErrorAction Stop)
    $configured = $ConfiguredUsername.Trim()
    $configuredLocalName = $null
    $separator = $configured.IndexOf('\')
    if ($separator -lt 0) {
        if ($configured.IndexOf('@') -lt 0) { $configuredLocalName = $configured }
    } else {
        $prefix = $configured.Substring(0, $separator)
        $suffix = $configured.Substring($separator + 1)
        if (($prefix -eq '.' -or [string]::Equals($prefix, $env:COMPUTERNAME, [StringComparison]::OrdinalIgnoreCase)) -and
            -not [string]::IsNullOrWhiteSpace($suffix) -and $suffix.IndexOf('\') -lt 0) {
            $configuredLocalName = $suffix
        }
    }

    $preferred = @()
    if (-not [string]::IsNullOrWhiteSpace($configuredLocalName)) {
        $preferred = @($localUsers | Where-Object {
            [string]::Equals([string]$_.Name, $configuredLocalName, [StringComparison]::OrdinalIgnoreCase)
        })
    }
    if ($preferred.Count -gt 1) {
        throw "BUILDER_PREFERRED_USER_AMBIGUOUS: configured local user '$ConfiguredUsername' matched $($preferred.Count) users"
    }
    if ($preferred.Count -eq 1) {
        $selected = $preferred[0]
        $selectedSID = [string]$selected.SID
        if (-not [bool]$selected.Enabled) {
            throw "BUILDER_PREFERRED_USER_INACTIVE: configured local user '$($selected.Name)' is disabled"
        }
        if ([string]::IsNullOrWhiteSpace($selectedSID)) {
            throw "BUILDER_PREFERRED_USER_SID_MISSING: configured local user '$($selected.Name)' has no SID"
        }
        if (-not (Test-LabLinkLocalAdministrator $selectedSID)) {
            throw "BUILDER_PREFERRED_USER_NOT_ADMIN: configured local user '$($selected.Name)' is not a direct member of local Administrators"
        }
        return [pscustomobject]@{
            account=("$env:COMPUTERNAME\$($selected.Name)")
            name=[string]$selected.Name
            sid=$selectedSID
            source='configured'
        }
    }

    $rid500 = @($localUsers | Where-Object { [string]$_.SID -match '-500$' })
    if ($rid500.Count -eq 0) {
        throw "BUILDER_RID500_USER_NOT_FOUND: configured user '$ConfiguredUsername' is unmapped and no local RID-500 user exists"
    }
    if ($rid500.Count -gt 1) {
        throw "BUILDER_RID500_USER_AMBIGUOUS: configured user '$ConfiguredUsername' is unmapped and $($rid500.Count) local RID-500 users exist"
    }
    $selected = $rid500[0]
    $selectedSID = [string]$selected.SID
    if (-not [bool]$selected.Enabled) {
        throw "BUILDER_RID500_USER_INACTIVE: local RID-500 user '$($selected.Name)' is disabled"
    }
    if (-not (Test-LabLinkLocalAdministrator $selectedSID)) {
        throw "BUILDER_RID500_USER_NOT_ADMIN: local RID-500 user '$($selected.Name)' is not a direct member of local Administrators"
    }
    return [pscustomobject]@{
        account=("$env:COMPUTERNAME\$($selected.Name)")
        name=[string]$selected.Name
        sid=$selectedSID
        source='rid-500-fallback'
    }
}
`

func BuildLinuxImageBuilderUserTaskScript(payload string, timeoutSeconds int) (string, error) {
	if strings.TrimSpace(payload) == "" {
		return "", fmt.Errorf("builder user payload is required")
	}
	if timeoutSeconds <= 0 || timeoutSeconds > 3600 {
		return "", fmt.Errorf("builder user task timeout must be between 1 and 3600 seconds")
	}
	payloadEncoded := base64.StdEncoding.EncodeToString([]byte(payload))
	runner := `
$ErrorActionPreference = 'Stop'
$payloadPath = Join-Path $PSScriptRoot 'payload.ps1'
$outputPath = Join-Path $PSScriptRoot 'payload-output.txt'
$resultPath = Join-Path $PSScriptRoot 'result.json'
$identityPath = Join-Path $PSScriptRoot 'identity.json'
$exitCode = -1
try {
    $identity = Get-Content -Raw -LiteralPath $identityPath -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace([string]$identity.user) -or
        [string]::IsNullOrWhiteSpace([string]$identity.sid)) {
        throw 'BUILDER_EFFECTIVE_IDENTITY_MISSING: identity file is incomplete'
    }
    $env:LABLINK_BUILDER_EFFECTIVE_USER = [string]$identity.user
    $env:LABLINK_BUILDER_EFFECTIVE_USER_SID = [string]$identity.sid
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $payloadPath *> $outputPath
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
} catch {
    [IO.File]::WriteAllText($outputPath, ("LABLINK_ERROR: " + $_.Exception.Message), [Text.UTF8Encoding]::new($false))
    $exitCode = -1
} finally {
    Remove-Item Env:LABLINK_BUILDER_EFFECTIVE_USER -ErrorAction SilentlyContinue
    Remove-Item Env:LABLINK_BUILDER_EFFECTIVE_USER_SID -ErrorAction SilentlyContinue
}
$result = [ordered]@{
    schema_version=1
    exit_code=[int]$exitCode
    completed_at=(Get-Date).ToUniversalTime().ToString('o')
}
$tmp = "$resultPath.$([guid]::NewGuid().ToString('N')).tmp"
[IO.File]::WriteAllText($tmp, ($result | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
Move-Item -Force -LiteralPath $tmp -Destination $resultPath
exit $exitCode
`
	runnerEncoded := base64.StdEncoding.EncodeToString([]byte(runner))
	body := fmt.Sprintf(`
%s
$username = [Environment]::GetEnvironmentVariable('LABLINK_BUILDER_USERNAME', 'Process')
$password = [Environment]::GetEnvironmentVariable('LABLINK_BUILDER_PASSWORD', 'Process')
$jobRoot = 'C:\ProgramData\LabLink\builder-user-jobs'
$jobID = [guid]::NewGuid().ToString('N')
$jobDir = Join-Path $jobRoot $jobID
$taskName = "LabLink-BuilderUser-$jobID"
$taskPath = '\'
$taskRegistered = $false
$taskRegistrationAttempted = $false
$payloadOutput = ''
$payloadExit = $null
$primaryError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()
try {
    if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrEmpty($password)) {
        throw 'BUILDER_USER_ENV_MISSING: LABLINK_BUILDER_USERNAME and LABLINK_BUILDER_PASSWORD are required'
    }
    $effectiveIdentity = Resolve-LabLinkBuilderUser $username
    $effectiveUser = [string]$effectiveIdentity.account
    $effectiveSID = [string]$effectiveIdentity.sid
    $env:LABLINK_BUILDER_EFFECTIVE_USER = $effectiveUser
    $env:LABLINK_BUILDER_EFFECTIVE_USER_SID = $effectiveSID
    New-Item -ItemType Directory -Force -Path $jobDir | Out-Null
    $payloadPath = Join-Path $jobDir 'payload.ps1'
    $runnerPath = Join-Path $jobDir 'runner.ps1'
    $identityPath = Join-Path $jobDir 'identity.json'
    $resultPath = Join-Path $jobDir 'result.json'
    $outputPath = Join-Path $jobDir 'payload-output.txt'
    [IO.File]::WriteAllBytes($payloadPath, [Convert]::FromBase64String(%s))
    [IO.File]::WriteAllBytes($runnerPath, [Convert]::FromBase64String(%s))
    [IO.File]::WriteAllText($identityPath, ([ordered]@{
        user=$effectiveUser; sid=$effectiveSID
    } | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $runnerPath)
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds %d) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    try {
        $taskRegistrationAttempted = $true
        Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Settings $settings -User $effectiveUser -Password $password -RunLevel Highest -Force -ErrorAction Stop | Out-Null
        $taskRegistered = $true
    } finally {
        $password = $null
        Remove-Item Env:LABLINK_BUILDER_PASSWORD -ErrorAction SilentlyContinue
        Remove-Item Env:LABLINK_BUILDER_USERNAME -ErrorAction SilentlyContinue
    }
    $startedAt = Get-Date
    Start-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
    $deadline = $startedAt.AddSeconds(%d)
    $terminalWithoutResult = 0
    while (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
        if ((Get-Date) -ge $deadline) {
            throw "BUILDER_USER_TASK_TIMEOUT: task '$taskName' exceeded %d seconds"
        }
        $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
        $info = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
        if ($task.State -ne 'Running' -and $info.LastRunTime -ge $startedAt.AddSeconds(-2)) {
            $terminalWithoutResult++
            if ($terminalWithoutResult -ge 3) {
                throw "BUILDER_USER_TASK_RESULT_MISSING: task '$taskName' completed without a result"
            }
        } else {
            $terminalWithoutResult = 0
        }
        Start-Sleep -Seconds 1
    }
    try {
        $result = Get-Content -Raw -LiteralPath $resultPath -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "BUILDER_USER_TASK_RESULT_INVALID: $($_.Exception.Message)"
    }
    if ($result.schema_version -ne 1 -or $result.PSObject.Properties.Name -notcontains 'exit_code') {
        throw 'BUILDER_USER_TASK_RESULT_INVALID: required fields are missing'
    }
    $parsedExit = 0
    if (-not [int]::TryParse(([string]$result.exit_code), [ref]$parsedExit)) {
        throw 'BUILDER_USER_TASK_RESULT_INVALID: exit_code is not an integer'
    }
    $payloadExit = $parsedExit
    if (Test-Path -LiteralPath $outputPath -PathType Leaf) {
        $outputInfo = Get-Item -LiteralPath $outputPath -ErrorAction Stop
        if ($outputInfo.Length -gt 1048576) {
            throw "BUILDER_USER_TASK_OUTPUT_TOO_LARGE: $($outputInfo.Length) bytes"
        }
        $payloadOutput = Get-Content -Raw -LiteralPath $outputPath -ErrorAction Stop
    }
} catch {
    $primaryError = $_.Exception.Message
} finally {
    $password = $null
    Remove-Item Env:LABLINK_BUILDER_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:LABLINK_BUILDER_USERNAME -ErrorAction SilentlyContinue
    Remove-Item Env:LABLINK_BUILDER_EFFECTIVE_USER -ErrorAction SilentlyContinue
    Remove-Item Env:LABLINK_BUILDER_EFFECTIVE_USER_SID -ErrorAction SilentlyContinue
    $registeredTask = $null
    if ($taskRegistrationAttempted) {
        $registeredTask = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
    }
    if ($registeredTask) {
        try {
            if ($registeredTask.State -eq 'Running') {
                Stop-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
            }
        } catch {
            $cleanupErrors.Add("stop exact scheduled task: $($_.Exception.Message)")
        }
        try {
            Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction Stop
        } catch {
            $cleanupErrors.Add("unregister exact scheduled task: $($_.Exception.Message)")
        }
    } elseif ($taskRegistered) {
        $cleanupErrors.Add('locate exact registered scheduled task for cleanup')
    }
    if (Test-Path -LiteralPath $jobDir) {
        try {
            Remove-Item -LiteralPath $jobDir -Recurse -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $jobDir) {
                throw 'exact job directory still exists'
            }
        } catch {
            $cleanupErrors.Add("delete exact builder user job directory: $($_.Exception.Message)")
        }
    }
}
if (-not [string]::IsNullOrEmpty($payloadOutput)) {
    Write-Output $payloadOutput
}
if ($cleanupErrors.Count -gt 0) {
    throw ("BUILDER_USER_TASK_CLEANUP_FAILED: " + ($cleanupErrors -join '; '))
}
if ($primaryError) {
    throw $primaryError
}
if ($null -eq $payloadExit) {
    throw 'BUILDER_USER_TASK_RESULT_MISSING: payload exit code was not returned'
}
if ($payloadExit -ne 0) {
    throw "BUILDER_USER_TASK_FAILED: payload exited $payloadExit"
}
`, linuxImageBuilderAccountResolverPowerShell, PSLit(payloadEncoded), PSLit(runnerEncoded), timeoutSeconds, timeoutSeconds, timeoutSeconds)
	return wrapTagged(body), nil
}

func BuildLinuxImageBuilderSetupScript(statePath string) (string, error) {
	if strings.TrimSpace(statePath) == "" {
		return "", fmt.Errorf("builder state path is required")
	}
	body := fmt.Sprintf(`
$statePath = %s
$parent = Split-Path -Parent $statePath
New-Item -ItemType Directory -Force -Path $parent | Out-Null
$wslVersion = %s
$wslProductVersion = %s
$wslMSIURL = %s
$wslMSISHA256 = %s
$wslMSIFilename = %s
$wslBITSDisplayName = %s
$distribution = %s
$wslRoot = 'C:\ProgramData\LabLink\wsl'
$msiPath = Join-Path $wslRoot $wslMSIFilename
$builderUser = [Environment]::GetEnvironmentVariable('LABLINK_BUILDER_EFFECTIVE_USER', 'Process')
$builderUserSID = [Environment]::GetEnvironmentVariable('LABLINK_BUILDER_EFFECTIVE_USER_SID', 'Process')
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ([string]::IsNullOrWhiteSpace($builderUser) -or [string]::IsNullOrWhiteSpace($builderUserSID)) {
    throw 'BUILDER_EFFECTIVE_IDENTITY_MISSING: effective user name and SID are required'
}
if ([string]$currentIdentity.User.Value -cne $builderUserSID -or [string]$currentIdentity.Name -cne $builderUser) {
    throw "BUILDER_EFFECTIVE_IDENTITY_MISMATCH: selected '$builderUser' ($builderUserSID), current '$($currentIdentity.Name)' ($($currentIdentity.User.Value))"
}

function Get-BuilderState {
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        return [pscustomobject]@{ schema_version=2 }
    }
    try {
        return Get-Content -Raw -LiteralPath $statePath -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "BUILDER_STATE_INVALID: cannot parse '$statePath': $($_.Exception.Message)"
    }
}
function Assert-BuilderStateIdentity($State, [bool]$Required=$false) {
    $hasUser = $State.PSObject.Properties.Name -contains 'builder_user'
    $hasSID = $State.PSObject.Properties.Name -contains 'builder_user_sid'
    if ($Required -or $hasUser -or $hasSID) {
        if (-not $hasUser -or -not $hasSID -or
            [string]::IsNullOrWhiteSpace([string]$State.builder_user) -or
            [string]::IsNullOrWhiteSpace([string]$State.builder_user_sid)) {
            throw 'BUILDER_USER_IDENTITY_MISSING: state requires exact builder_user and builder_user_sid'
        }
        if ([string]$State.builder_user_sid -cne $builderUserSID -or [string]$State.builder_user -cne $builderUser) {
            throw "BUILDER_USER_IDENTITY_MISMATCH: state belongs to '$($State.builder_user)' ($($State.builder_user_sid)), selected user is '$builderUser' ($builderUserSID)"
        }
    }
}
function Save-BuilderState([string]$Phase, [string]$ErrorText='', [hashtable]$Properties=@{}) {
    $state = Get-BuilderState
    Assert-BuilderStateIdentity $state
    $state | Add-Member -NotePropertyName schema_version -NotePropertyValue 2 -Force
    $state | Add-Member -NotePropertyName builder_user -NotePropertyValue $builderUser -Force
    $state | Add-Member -NotePropertyName builder_user_sid -NotePropertyValue $builderUserSID -Force
    $state | Add-Member -NotePropertyName phase -NotePropertyValue $Phase -Force
    $state | Add-Member -NotePropertyName error -NotePropertyValue $ErrorText -Force
    $state | Add-Member -NotePropertyName wsl_runtime -NotePropertyValue ([pscustomobject]@{
        version=$wslVersion; product_version=$wslProductVersion; msi_url=$wslMSIURL
        msi_filename=$wslMSIFilename; msi_sha256=$wslMSISHA256
        bits_display_name=$wslBITSDisplayName; distribution=$distribution
    }) -Force
    foreach ($entry in $Properties.GetEnumerator()) {
        $state | Add-Member -NotePropertyName ([string]$entry.Key) -NotePropertyValue $entry.Value -Force
    }
    $state | Add-Member -NotePropertyName updated_at -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force
    $tmp = "$statePath.$([guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText($tmp, ($state | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    Move-Item -Force -LiteralPath $tmp -Destination $statePath
}
function Invoke-WSLNonTerminating([string[]]$Arguments) {
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = @(& wsl.exe @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
    return [pscustomobject]@{
        exit_code=[int]$exitCode
        output=@($output | ForEach-Object {
            ([string]$_).Replace(([char]0).ToString(), [string]::Empty).TrimEnd()
        })
    }
}
function Test-RebootRequired($Result) {
    if ([int]$Result.exit_code -eq 3010) { return $true }
    $text = @($Result.output) -join [Environment]::NewLine
    return $text -match '(?i)(restart|reboot).{0,80}required|required.{0,80}(restart|reboot)'
}
function Get-LabLinkWSLProduct {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $products = @($paths | ForEach-Object {
        Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue
    } | Where-Object {
        [string]$_.DisplayName -eq 'Windows Subsystem for Linux' -and
        [string]$_.Publisher -match '^Microsoft( Corporation)?$'
    } | Sort-Object DisplayVersion -Descending)
    if ($products.Count -eq 0) { return $null }
    return [pscustomobject]@{
        name=[string]$products[0].DisplayName
        publisher=[string]$products[0].Publisher
        version=[string]$products[0].DisplayVersion
        product_code=[string]$products[0].PSChildName
    }
}
function Test-VersionAtLeast([string]$Actual, [string]$Required) {
    try { return ([version]$Actual -ge [version]$Required) } catch { return $false }
}
function Get-LabLinkWSLRuntime {
    $commandReady = $false
    $commandVersion = ''
    if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
        $versionResult = Invoke-WSLNonTerminating @('--version')
        if ($versionResult.exit_code -eq 0) {
            $versionLine = @($versionResult.output | Where-Object { $_ -match '(?i)^\s*WSL\s+version\s*:' } | Select-Object -First 1)
            if ($versionLine.Count -eq 1 -and $versionLine[0] -match '([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)') {
                $commandVersion = [string]$Matches[1]
                $commandReady = Test-VersionAtLeast $commandVersion $wslProductVersion
            }
        }
    }
    $product = Get-LabLinkWSLProduct
    $productReady = $false
    if ($product) { $productReady = Test-VersionAtLeast ([string]$product.version) $wslProductVersion }
    return [pscustomobject]@{
        ready=($commandReady -or $productReady)
        command_ready=$commandReady; command_version=$commandVersion
        product_ready=$productReady; product=$product
    }
}
function Quarantine-WSLMSI([string]$Reason) {
    if (-not (Test-Path -LiteralPath $msiPath -PathType Leaf)) { return $null }
    $quarantineRoot = Join-Path $wslRoot 'quarantine'
    New-Item -ItemType Directory -Force -Path $quarantineRoot | Out-Null
    $actualHash = ''
    try { $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $msiPath -ErrorAction Stop).Hash.ToLowerInvariant() } catch {}
    $quarantinePath = Join-Path $quarantineRoot (
        '{0}.{1}.{2}.bad' -f $wslMSIFilename,(Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffffffZ'),[guid]::NewGuid().ToString('N')
    )
    Move-Item -LiteralPath $msiPath -Destination $quarantinePath -Force -ErrorAction Stop
    Save-BuilderState 'wsl_msi_quarantined' $Reason @{
        quarantine_path=$quarantinePath; quarantined_sha256=$actualHash
    }
    return $quarantinePath
}
function Test-WSLMSI {
    if (-not (Test-Path -LiteralPath $msiPath -PathType Leaf)) { return $false }
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $msiPath -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($actualHash -cne $wslMSISHA256) {
        Quarantine-WSLMSI "WSL_MSI_SHA256_MISMATCH: expected $wslMSISHA256, got $actualHash" | Out-Null
        return $false
    }
    $signature = Get-AuthenticodeSignature -FilePath $msiPath -ErrorAction Stop
    $subject = if ($signature.SignerCertificate) { [string]$signature.SignerCertificate.Subject } else { '' }
    $microsoftSigner = [regex]::IsMatch(
        $subject, '(^|,\s*)O=Microsoft Corporation(,|$)',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or -not $microsoftSigner) {
        Quarantine-WSLMSI "WSL_MSI_SIGNATURE_INVALID: status=$($signature.Status), signer=$subject" | Out-Null
        return $false
    }
    Save-BuilderState 'wsl_msi_verified' '' @{
        wsl_msi_path=$msiPath; wsl_msi_actual_sha256=$actualHash; wsl_msi_signer=$subject
    }
    return $true
}
function Ensure-WSLMSIDownload {
    New-Item -ItemType Directory -Force -Path $wslRoot | Out-Null
    $matching = @(Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -ceq $wslBITSDisplayName } |
        Sort-Object CreationTime -Descending)
    $usable = @()
    foreach ($candidate in $matching) {
        $files = @($candidate.FileList)
        if ($files.Count -ne 1 -or [string]$files[0].RemoteName -cne $wslMSIURL -or
            -not [IO.Path]::GetFullPath([string]$files[0].LocalName).Equals(
                [IO.Path]::GetFullPath($msiPath), [StringComparison]::OrdinalIgnoreCase)) {
            throw "WSL_BITS_JOB_SOURCE_MISMATCH: '$wslBITSDisplayName' does not match the pinned URL and destination"
        }
        if ($candidate.JobState -in @('Error','Cancelled','Canceled','Acknowledged')) {
            Remove-BitsTransfer -BitsJob $candidate -Confirm:$false -ErrorAction SilentlyContinue
            continue
        }
        $usable += $candidate
    }
    if ($usable.Count -gt 1) {
        throw "WSL_BITS_JOB_AMBIGUOUS: multiple active '$wslBITSDisplayName' jobs exist"
    }
    $job = if ($usable.Count -eq 1) { $usable[0] } else { $null }
    if (-not $job) {
        $job = Start-BitsTransfer -Source $wslMSIURL -Destination $msiPath -DisplayName $wslBITSDisplayName -Description "Pinned WSL $wslVersion runtime for LabLink" -Asynchronous
    } elseif ($job.JobState -in @('Suspended','TransientError')) {
        Resume-BitsTransfer -BitsJob $job -Asynchronous -ErrorAction Stop
        $job = Get-BitsTransfer -JobId $job.JobId -ErrorAction Stop
    }
    if ($job.JobState -eq 'Transferred') {
        Complete-BitsTransfer -BitsJob $job -ErrorAction Stop
        return [pscustomobject]@{ complete=$true; state='Transferred'; id=[string]$job.JobId }
    }
    $bytesTotal = if ([uint64]$job.BytesTotal -gt [uint64][int64]::MaxValue) { -1 } else { [int64]$job.BytesTotal }
    return [pscustomobject]@{
        complete=$false; state=[string]$job.JobState; id=[string]$job.JobId
        bytes_transferred=[int64]$job.BytesTransferred; bytes_total=$bytesTotal
    }
}
function Get-LabLinkWSLDistributions {
    $result = Invoke-WSLNonTerminating @('--list','--quiet')
    $distributions = if ($result.exit_code -eq 0) {
        @($result.output | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
    } else { @() }
    return [pscustomobject]@{
        success=($result.exit_code -eq 0); exit_code=$result.exit_code
        distributions=@($distributions); output=@($result.output)
    }
}
function Get-BoundedWSLMSILogTail([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    $tail = @(Get-Content -LiteralPath $Path -Tail 40 -ErrorAction SilentlyContinue) -join ' | '
    if ($tail.Length -gt 2000) { return $tail.Substring($tail.Length - 2000) }
    return $tail
}

$initialState = Get-BuilderState
Assert-BuilderStateIdentity $initialState

$features = @('Microsoft-Windows-Subsystem-Linux','VirtualMachinePlatform')
$disabled = @($features | Where-Object { (Get-WindowsOptionalFeature -Online -FeatureName $_ -ErrorAction Stop).State -ne 'Enabled' })
if ($disabled.Count -gt 0) {
    foreach ($feature in $disabled) {
        Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart -ErrorAction Stop | Out-Null
    }
    Save-BuilderState 'features_enabled_reboot_required'
    [pscustomobject]@{ status='reboot_required'; phase='features_enabled_reboot_required'; features=$disabled } | ConvertTo-Json -Compress
    return
}

$runtime = Get-LabLinkWSLRuntime
if (-not $runtime.ready) {
    $msiReady = Test-WSLMSI
    if (-not $msiReady) {
        $download = Ensure-WSLMSIDownload
        if (-not $download.complete) {
            Save-BuilderState 'wsl_msi_downloading' '' @{
                wsl_bits_job_id=$download.id; wsl_bits_state=$download.state
                wsl_bits_bytes_transferred=$download.bytes_transferred; wsl_bits_bytes_total=$download.bytes_total
            }
            [pscustomobject]@{
                status='setup_pending'; phase='wsl_msi_downloading'; bits_job_id=$download.id
                bits_state=$download.state; bytes_transferred=$download.bytes_transferred
                bytes_total=$download.bytes_total; wsl_runtime_version=$wslVersion
            } | ConvertTo-Json -Compress
            return
        }
        if (-not (Test-WSLMSI)) {
            Save-BuilderState 'wsl_msi_verification_failed' 'Downloaded WSL MSI failed pinned hash or Microsoft signature verification'
            throw "WSL_MSI_VERIFICATION_FAILED: quarantined downloaded MSI"
        }
    }
    $msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
    for ($msiAttempt = 1; $msiAttempt -le 2; $msiAttempt++) {
        $msiLogPath = Join-Path $wslRoot ('wsl-msi-attempt-{0}.log' -f $msiAttempt)
        Remove-Item -LiteralPath $msiLogPath -Force -ErrorAction SilentlyContinue
        Save-BuilderState 'wsl_msi_installing' '' @{
            wsl_msi_attempt=$msiAttempt; wsl_msi_log_path=$msiLogPath
        }
        $msiProcess = Start-Process -FilePath $msiexec -ArgumentList @(
            '/i', $msiPath, '/qn', '/norestart', '/L*v', $msiLogPath
        ) -Wait -PassThru -WindowStyle Hidden
        $msiExit = [int]$msiProcess.ExitCode
        Save-BuilderState 'wsl_msi_install_attempt_complete' '' @{
            wsl_msi_attempt=$msiAttempt; wsl_msi_exit_code=$msiExit; wsl_msi_log_path=$msiLogPath
        }
        $runtime = Get-LabLinkWSLRuntime
        if ($msiExit -eq 3010) {
            Save-BuilderState 'wsl_msi_installed_reboot_required' '' @{
                wsl_msi_attempt=$msiAttempt; wsl_msi_exit_code=$msiExit; wsl_msi_log_path=$msiLogPath
            }
            [pscustomobject]@{
                status='reboot_required'; phase='wsl_msi_installed_reboot_required'
                wsl_msi_attempt=$msiAttempt; wsl_msi_exit_code=$msiExit
                wsl_msi_log_path=$msiLogPath; wsl_runtime_version=$wslVersion
            } | ConvertTo-Json -Compress
            return
        }
        if ($runtime.ready) {
            Save-BuilderState 'wsl_msi_installed' '' @{
                wsl_msi_attempt=$msiAttempt; wsl_msi_exit_code=$msiExit; wsl_msi_log_path=$msiLogPath
            }
            break
        }
        if ($msiExit -eq 0) {
            Save-BuilderState 'wsl_runtime_not_ready' 'Pinned MSI returned success but the WSL runtime is not ready' @{
                wsl_msi_attempt=$msiAttempt; wsl_msi_exit_code=$msiExit; wsl_msi_log_path=$msiLogPath
            }
            throw "WSL_RUNTIME_NOT_READY: pinned MSI returned success without a real WSL runtime; log '$msiLogPath'"
        }
        if ($msiAttempt -lt 2) {
            Save-BuilderState 'wsl_msi_retrying' "msiexec.exe exited $msiExit and WSL is still absent" @{
                wsl_msi_attempt=$msiAttempt; wsl_msi_exit_code=$msiExit; wsl_msi_log_path=$msiLogPath
            }
            continue
        }
        $failureTail = Get-BoundedWSLMSILogTail $msiLogPath
        Save-BuilderState 'wsl_msi_install_failed' "msiexec.exe exited $msiExit after $msiAttempt attempts" @{
            wsl_msi_attempt=$msiAttempt; wsl_msi_exit_code=$msiExit; wsl_msi_log_path=$msiLogPath
        }
        throw "WSL_MSI_INSTALL_FAILED: exit $msiExit after $msiAttempt attempts; log '$msiLogPath'; tail: $failureTail"
    }
}
Save-BuilderState 'wsl_runtime_ready' '' @{
    detected_wsl_command_version=$runtime.command_version
    detected_wsl_product_version=$(if ($runtime.product) { [string]$runtime.product.version } else { '' })
}

$defaultVersion = Invoke-WSLNonTerminating @('--set-default-version','2')
if (Test-RebootRequired $defaultVersion) {
    Save-BuilderState 'wsl_default_version_reboot_required'
    [pscustomobject]@{ status='reboot_required'; phase='wsl_default_version_reboot_required' } | ConvertTo-Json -Compress
    return
}
if ($defaultVersion.exit_code -ne 0) {
    Save-BuilderState 'wsl2_default_failed' (@($defaultVersion.output) -join [Environment]::NewLine)
    throw "WSL2_DEFAULT_FAILED: exit $($defaultVersion.exit_code)"
}

$distroList = Get-LabLinkWSLDistributions
if (@($distroList.distributions) -notcontains $distribution) {
    Save-BuilderState 'distro_installing'
    $install = Invoke-WSLNonTerminating @('--install','-d',$distribution,'--web-download','--no-launch')
    if (Test-RebootRequired $install) {
        Save-BuilderState 'distro_install_reboot_required' (@($install.output) -join [Environment]::NewLine)
        [pscustomobject]@{ status='reboot_required'; phase='distro_install_reboot_required'; distribution=$distribution } |
            ConvertTo-Json -Compress
        return
    }
    if ($install.exit_code -ne 0) {
        Save-BuilderState 'distro_install_failed' (@($install.output) -join [Environment]::NewLine) @{ distro_install_exit_code=$install.exit_code }
        throw "WSL_DISTRO_INSTALL_FAILED: $distribution web download exited $($install.exit_code)"
    }
    $distroList = Get-LabLinkWSLDistributions
    if (@($distroList.distributions) -notcontains $distribution) {
        Save-BuilderState 'distro_install_reboot_required' 'Distribution install returned success but registration is not visible yet'
        [pscustomobject]@{ status='reboot_required'; phase='distro_install_reboot_required'; distribution=$distribution } |
            ConvertTo-Json -Compress
        return
    }
}

$verboseBefore = Invoke-WSLNonTerminating @('--list','--verbose')
if ($verboseBefore.exit_code -ne 0) {
    Save-BuilderState 'distro_version_probe_failed' (@($verboseBefore.output) -join [Environment]::NewLine)
    throw "WSL_DISTRO_VERSION_PROBE_FAILED: exit $($verboseBefore.exit_code)"
}
$distroBeforeLine = @($verboseBefore.output | Where-Object {
    $_ -match ('^\s*\*?\s*' + [regex]::Escape($distribution) + '\s+.*\s+[12]\s*$')
} | Select-Object -First 1)
if ($distroBeforeLine.Count -ne 1) {
    Save-BuilderState 'distro_version_probe_failed' "Could not identify $distribution in list output: $(@($verboseBefore.output) -join ' | ')"
    throw "WSL_DISTRO_VERSION_PROBE_FAILED: $distribution was not listed"
}
$distroAlreadyV2 = $distroBeforeLine[0] -match '\s+2\s*$'
if (-not $distroAlreadyV2) {
    $setVersion = Invoke-WSLNonTerminating @('--set-version',$distribution,'2')
    if (Test-RebootRequired $setVersion) {
        Save-BuilderState 'distro_version_reboot_required' (@($setVersion.output) -join [Environment]::NewLine)
        [pscustomobject]@{ status='reboot_required'; phase='distro_version_reboot_required'; distribution=$distribution } |
            ConvertTo-Json -Compress
        return
    }
    if ($setVersion.exit_code -ne 0) {
        Save-BuilderState 'distro_version_failed' (@($setVersion.output) -join [Environment]::NewLine)
        throw "WSL_DISTRO_VERSION_FAILED: exit $($setVersion.exit_code)"
    }
}
$setDefault = Invoke-WSLNonTerminating @('--set-default',$distribution)
if ($setDefault.exit_code -ne 0) {
    Save-BuilderState 'distro_default_failed' (@($setDefault.output) -join [Environment]::NewLine)
    throw "WSL_DISTRO_DEFAULT_FAILED: exit $($setDefault.exit_code)"
}
$verboseList = Invoke-WSLNonTerminating @('--list','--verbose')
if ($verboseList.exit_code -ne 0) {
    Save-BuilderState 'distro_verification_failed' (@($verboseList.output) -join [Environment]::NewLine)
    throw "WSL_DISTRO_VERIFICATION_FAILED: wsl --list --verbose exited $($verboseList.exit_code)"
}
$distroLine = @($verboseList.output | Where-Object { $_ -match ('^\s*\*?\s*' + [regex]::Escape($distribution) + '\s+.*\s+[12]\s*$') } | Select-Object -First 1)
if ($distroLine.Count -ne 1 -or $distroLine[0] -notmatch '^\s*\*' -or $distroLine[0] -notmatch '\s+2\s*$') {
    Save-BuilderState 'distro_verification_failed' "Expected $distribution to be the default WSL2 distribution; list output: $(@($verboseList.output) -join ' | ')"
    throw "WSL_DISTRO_VERIFICATION_FAILED: $distribution is not the default version 2 distribution"
}
Save-BuilderState 'builder_ready' '' @{
    installed_distribution=$distribution; installed_distribution_version=2; installed_distribution_default=$true
}
[pscustomobject]@{
    status='builder_ready'; phase='builder_ready'; distribution=$distribution; distribution_version=2
    distribution_default=$true; wsl_runtime_version=$wslVersion
    builder_user=$builderUser; builder_user_sid=$builderUserSID
} | ConvertTo-Json -Compress
`, PSLit(statePath),
		PSLit(linuximage.WSLRuntimeVersion), PSLit(linuximage.WSLRuntimeProductVersion),
		PSLit(linuximage.WSLMSIURL), PSLit(linuximage.WSLMSISHA256),
		PSLit(linuximage.WSLMSIFilename), PSLit(linuximage.WSLMSIDisplayName),
		PSLit(linuximage.WSLDistributionName))
	return wrapTagged(body), nil
}

func BuildLinuxImageRecordBuilderScript(statePath, profile, vmName, nodeName string) (string, error) {
	if strings.TrimSpace(statePath) == "" || strings.TrimSpace(profile) == "" ||
		strings.TrimSpace(vmName) == "" || strings.TrimSpace(nodeName) == "" {
		return "", fmt.Errorf("state path and complete builder identity are required")
	}
	body := linuxImageStateUpdate(statePath, "builder_ready", map[string]string{
		"image_builder_profile": PSLit(profile),
		"builder_vm_name":       PSLit(vmName),
		"builder_node_name":     PSLit(nodeName),
	})
	body += "[pscustomobject]@{ status='builder_ready'; image_builder_profile=" + PSLit(profile) +
		"; builder_vm_name=" + PSLit(vmName) + "; builder_node_name=" + PSLit(nodeName) +
		" } | ConvertTo-Json -Compress\n"
	return wrapTagged(body), nil
}

type LinuxImageBuilderAttachParams struct {
	VMName     string
	VHDXPath   string
	StatePath  string
	DiskSizeGB int
}

func BuildLinuxImageBuilderAttachScript(p LinuxImageBuilderAttachParams) (string, error) {
	if strings.TrimSpace(p.VMName) == "" || strings.TrimSpace(p.VHDXPath) == "" || strings.TrimSpace(p.StatePath) == "" {
		return "", fmt.Errorf("builder VM, staging VHDX, and state path are required")
	}
	body := fmt.Sprintf(`
$name = %s
$vhdx = [IO.Path]::GetFullPath(%s)
$statePath = %s
$expectedSize = %s
$vm = Get-VM -Name $name -ErrorAction Stop
if (-not (Test-Path -LiteralPath $vhdx -PathType Leaf)) { throw "STAGING_VHDX_MISSING: '$vhdx'" }
if ($vm.State -ne 'Off') {
    Stop-VM -Name $name -Force -ErrorAction Stop | Out-Null
}
$allAttachments = @(Get-VM | Get-VMHardDiskDrive -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -and [IO.Path]::GetFullPath([string]$_.Path).Equals($vhdx, [StringComparison]::OrdinalIgnoreCase)
})
if ($allAttachments.Count -gt 1 -or ($allAttachments.Count -eq 1 -and $allAttachments[0].VMName -cne $name)) {
    throw "STAGING_VHDX_IN_USE: '$vhdx'"
}
$existing = @(Get-VMHardDiskDrive -VMName $name -ErrorAction Stop)
if ($allAttachments.Count -eq 0 -and $existing.Count -ne 1) {
    throw "BUILDER_DATA_DISK_UNEXPECTED: builder must have exactly one OS disk before operation-owned attach"
}
if ($allAttachments.Count -eq 1 -and $existing.Count -ne 2) {
    throw "BUILDER_DATA_DISK_UNEXPECTED: resumed builder must have only its OS disk and the exact operation-owned disk"
}
$vhd = Get-VHD -Path $vhdx -ErrorAction Stop
if ([int64]$vhd.Size -ne $expectedSize) { throw "STAGING_VHDX_SIZE_MISMATCH: expected $expectedSize, got $($vhd.Size)" }
if ($allAttachments.Count -eq 0) {
    $used = @($existing | Where-Object ControllerType -eq 'SCSI' | ForEach-Object { [int]$_.ControllerLocation })
    $location = 1
    while ($used -contains $location) { $location++ }
    Add-VMHardDiskDrive -VMName $name -ControllerType SCSI -ControllerNumber 0 -ControllerLocation $location -Path $vhdx -ErrorAction Stop
} else {
    $location = [int]$allAttachments[0].ControllerLocation
}
$owned = @(Get-VMHardDiskDrive -VMName $name -ErrorAction Stop | Where-Object {
    $_.Path -and [IO.Path]::GetFullPath([string]$_.Path).Equals($vhdx, [StringComparison]::OrdinalIgnoreCase)
})
if ($owned.Count -ne 1) { throw "STAGING_VHDX_ATTACH_IDENTITY_MISMATCH: '$vhdx'" }
%s
[pscustomobject]@{
    status='disk_attached'; vm_name=$name; vhdx_path=$vhdx; controller_type=[string]$owned[0].ControllerType
    controller_number=[int]$owned[0].ControllerNumber; controller_location=[int]$owned[0].ControllerLocation
    disk_identifier=[string]$vhd.DiskIdentifier; virtual_size=[int64]$vhd.Size
} | ConvertTo-Json -Compress
`, PSLit(p.VMName), PSLit(p.VHDXPath), PSLit(p.StatePath), gbBytes(float64(p.DiskSizeGB)),
		linuxImageStateUpdate(p.StatePath, "disk_attached", map[string]string{"attached_disk_path": "$vhdx"}))
	return wrapTagged(body), nil
}

func BuildLinuxImageBuilderStartScript(name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("builder VM name is required")
	}
	body := fmt.Sprintf(`
$name = %s
function Find-BuilderFatalStartEvent([datetime]$Since, [guid]$VMID) {
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Hyper-V-Worker-Admin'
        Id=18590
        StartTime=$Since
    } -ErrorAction SilentlyContinue | Sort-Object TimeCreated)
    foreach ($event in $events) {
        try {
            [xml]$xml = $event.ToXml()
            $data = @{}
            foreach ($item in @($xml.Event.EventData.Data)) {
                $data[[string]$item.Name] = [string]$item.'#text'
            }
            if (-not $data.ContainsKey('ErrorCode0')) { continue }
            $rawCode = ([string]$data['ErrorCode0']).Trim()
            $isFatalCode = $rawCode -match '^(?i:0x0*10)$'
            if (-not $isFatalCode) {
                $numericCode = [uint64]0
                $isFatalCode = [uint64]::TryParse($rawCode, [ref]$numericCode) -and $numericCode -eq 16
            }
            if (-not $isFatalCode) { continue }
            $identity = (@($event.Message) + @($data.Values)) -join ' '
            if ($identity.IndexOf($VMID.ToString(), [StringComparison]::OrdinalIgnoreCase) -lt 0 -and
                $identity.IndexOf($name, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                continue
            }
            return [pscustomobject]@{
                record_id=[long]$event.RecordId
                time_created=$event.TimeCreated.ToUniversalTime().ToString('o')
                error_code_0=$rawCode
            }
        } catch {
            continue
        }
    }
    return $null
}

$attempts = 0
$recovered = $false
$fatalEvent = $null
$ip = $null
while ($attempts -lt 2) {
    $attempts++
    $vm = Get-VM -Name $name -ErrorAction Stop
    $startedThisAttempt = $false
    $attemptStarted = Get-Date
    if ($vm.State -ne 'Running') {
        Start-VM -Name $name -ErrorAction Stop | Out-Null
        $startedThisAttempt = $true
    }
    $deadline = (Get-Date).AddMinutes(15)
    $retryFatalStart = $false
    do {
        $ip = Get-VMNetworkAdapter -VMName $name -ErrorAction SilentlyContinue |
            ForEach-Object IPAddresses |
            Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -notmatch '^169\.254\.' -and $_ -ne '127.0.0.1' } |
            Select-Object -First 1
        if ($ip) { break }
        if ($startedThisAttempt) {
            $detected = Find-BuilderFatalStartEvent $attemptStarted $vm.VMId
            if ($detected) {
                $fatalEvent = $detected
                if ($attempts -ge 2) {
                    throw "BUILDER_BOOT_FATAL_18590: '$name' failed twice with ErrorCode0 0x10"
                }
                Stop-VM -Name $name -TurnOff -Force -ErrorAction Stop | Out-Null
                $recovered = $true
                $retryFatalStart = $true
                break
            }
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    if ($ip) { break }
    if ($retryFatalStart) { continue }
    throw "BUILDER_IP_TIMEOUT: '$name'"
}
if (-not $ip) { throw "BUILDER_IP_TIMEOUT: '$name'" }
[pscustomobject]@{
    status='running'; state=[string](Get-VM -Name $name).State; ip_address=$ip
    attempts=$attempts; recovered=$recovered; fatal_event=$fatalEvent
} | ConvertTo-Json -Depth 5 -Compress
`, PSLit(name))
	return wrapTagged(body), nil
}

type LinuxImageBuilderTransformParams struct {
	StatePath              string
	ExpectedSizeBytes      int64
	ExpectedTargetLocation int
}

func BuildLinuxImageBuilderTransformScript(p LinuxImageBuilderTransformParams) (string, error) {
	if strings.TrimSpace(p.StatePath) == "" || p.ExpectedSizeBytes <= 0 || p.ExpectedTargetLocation < 0 {
		return "", fmt.Errorf("builder state path, expected disk size, and target location are required")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(linuxImageTransformBash))
	body := fmt.Sprintf(`
$statePath = %s
$expectedSize = [int64]%d
$expectedTarget = %d
function Get-EffectiveBuilderIdentity {
    $effectiveUser = [Environment]::GetEnvironmentVariable('LABLINK_BUILDER_EFFECTIVE_USER', 'Process')
    $effectiveSID = [Environment]::GetEnvironmentVariable('LABLINK_BUILDER_EFFECTIVE_USER_SID', 'Process')
    if ([string]::IsNullOrWhiteSpace($effectiveUser) -or [string]::IsNullOrWhiteSpace($effectiveSID)) {
        throw 'BUILDER_EFFECTIVE_IDENTITY_MISSING: effective user name and SID are required'
    }
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ([string]$current.User.Value -cne $effectiveSID -or [string]$current.Name -cne $effectiveUser) {
        throw "BUILDER_EFFECTIVE_IDENTITY_MISMATCH: selected '$effectiveUser' ($effectiveSID), current '$($current.Name)' ($($current.User.Value))"
    }
    return [pscustomobject]@{ user=$effectiveUser; sid=$effectiveSID }
}
function Assert-BuilderStateIdentity($State, $Identity) {
    if ($State.PSObject.Properties.Name -notcontains 'builder_user' -or
        $State.PSObject.Properties.Name -notcontains 'builder_user_sid' -or
        [string]::IsNullOrWhiteSpace([string]$State.builder_user) -or
        [string]::IsNullOrWhiteSpace([string]$State.builder_user_sid)) {
        throw 'BUILDER_USER_IDENTITY_MISSING: transform requires exact builder_user and builder_user_sid'
    }
    if ([string]$State.builder_user_sid -cne [string]$Identity.sid -or
        [string]$State.builder_user -cne [string]$Identity.user) {
        throw "BUILDER_USER_IDENTITY_MISMATCH: state belongs to '$($State.builder_user)' ($($State.builder_user_sid)), current user is '$($Identity.user)' ($($Identity.sid))"
    }
}
$builderIdentity = Get-EffectiveBuilderIdentity
function Save-BuilderState([string]$Phase, [string]$ErrorText='', [bool]$Diagnostic=$false, [bool]$SafeToDetach=$false) {
    $state = Get-Content -Raw -LiteralPath $statePath -ErrorAction Stop | ConvertFrom-Json
    Assert-BuilderStateIdentity $state $builderIdentity
    $state | Add-Member -NotePropertyName phase -NotePropertyValue $Phase -Force
    $state | Add-Member -NotePropertyName error -NotePropertyValue $ErrorText -Force
    $state | Add-Member -NotePropertyName diagnostic_retained -NotePropertyValue $Diagnostic -Force
    $state | Add-Member -NotePropertyName safe_to_detach -NotePropertyValue $SafeToDetach -Force
    $state | Add-Member -NotePropertyName updated_at -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force
    $tmp = "$statePath.$([guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText($tmp, ($state | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    Move-Item -Force -LiteralPath $tmp -Destination $statePath
}
$mounted = $false
$physicalPath = $null
try {
    $state = Get-Content -Raw -LiteralPath $statePath -ErrorAction Stop | ConvertFrom-Json
    Assert-BuilderStateIdentity $state $builderIdentity
    if (-not $state.pre_attach_disks) { throw "PRE_ATTACH_DISK_INVENTORY_MISSING" }
    $before = @{}
    foreach ($disk in @($state.pre_attach_disks)) {
        $identity = "$($disk.unique_id)|$($disk.serial_number)|$($disk.path)|$($disk.location)"
        $before[$identity] = $true
    }
    $newDisks = @(Get-Disk | Where-Object {
        $identity = "$([string]$_.UniqueId)|$([string]$_.SerialNumber)|$([string]$_.Path)|$([string]$_.Location)"
        -not $before.ContainsKey($identity)
    })
    $matches = @($newDisks | Where-Object {
        [int64]$_.Size -eq $expectedSize -and
        [string]$_.Location -match ("(?i)(target|port|lun)\s*" + [regex]::Escape([string]$expectedTarget) + "(\D|$)") -and
        -not [string]::IsNullOrWhiteSpace(([string]$_.UniqueId + [string]$_.SerialNumber + [string]$_.Path))
    })
    if ($matches.Count -ne 1) {
        throw "DISK_IDENTITY_MISMATCH: expected one new disk of $expectedSize bytes at SCSI slot $expectedTarget; new=$($newDisks.Count), matched=$($matches.Count)"
    }
    $disk = $matches[0]
    $physicalPath = "\\.\PHYSICALDRIVE$([int]$disk.Number)"
    $selectedIdentity = [pscustomobject]@{
        unique_id=[string]$disk.UniqueId; serial_number=[string]$disk.SerialNumber
        path=[string]$disk.Path; location=[string]$disk.Location; size=[int64]$disk.Size
    }
    $state | Add-Member -NotePropertyName selected_disk -NotePropertyValue $selectedIdentity -Force
    $tmp = "$statePath.$([guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText($tmp, ($state | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    Move-Item -Force -LiteralPath $tmp -Destination $statePath
    $beforeLSBLKText = & wsl.exe -d Ubuntu-24.04 --user root -- lsblk --json --bytes --output NAME,PATH,TYPE,PKNAME,FSTYPE,SIZE,MOUNTPOINT
    if ($LASTEXITCODE -ne 0) { throw "WSL_PRE_MOUNT_INVENTORY_FAILED: exit $LASTEXITCODE" }
    try { $beforeLSBLK = ($beforeLSBLKText -join [Environment]::NewLine) | ConvertFrom-Json -ErrorAction Stop } catch {
        throw "WSL_PRE_MOUNT_INVENTORY_INVALID: $($_.Exception.Message)"
    }
    $beforeDiskPaths = @{}
    foreach ($device in @($beforeLSBLK.blockdevices)) {
        if ([string]$device.type -cne 'disk') { continue }
        $devicePath = [string]$device.path
        if ([string]::IsNullOrWhiteSpace($devicePath) -or -not $devicePath.StartsWith('/dev/', [StringComparison]::Ordinal)) {
            throw "WSL_PRE_MOUNT_DISK_PATH_INVALID: '$devicePath'"
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$device.pkname)) {
            throw "WSL_PRE_MOUNT_DISK_PARENT_INVALID: '$devicePath' parent '$($device.pkname)'"
        }
        if ($beforeDiskPaths.ContainsKey($devicePath)) { throw "WSL_PRE_MOUNT_DISK_DUPLICATE: '$devicePath'" }
        $beforeDiskPaths[$devicePath] = $true
    }
    & wsl.exe --mount $physicalPath --bare
    if ($LASTEXITCODE -ne 0) { throw "WSL_MOUNT_FAILED: exit $LASTEXITCODE" }
    $mounted = $true
    $afterLSBLKText = & wsl.exe -d Ubuntu-24.04 --user root -- lsblk --json --bytes --output NAME,PATH,TYPE,PKNAME,FSTYPE,SIZE,MOUNTPOINT
    if ($LASTEXITCODE -ne 0) { throw "WSL_POST_MOUNT_INVENTORY_FAILED: exit $LASTEXITCODE" }
    try { $afterLSBLK = ($afterLSBLKText -join [Environment]::NewLine) | ConvertFrom-Json -ErrorAction Stop } catch {
        throw "WSL_POST_MOUNT_INVENTORY_INVALID: $($_.Exception.Message)"
    }
    $newWSLDisks = @($afterLSBLK.blockdevices | Where-Object {
        [string]$_.type -ceq 'disk' -and -not $beforeDiskPaths.ContainsKey([string]$_.path)
    })
    if ($newWSLDisks.Count -ne 1) {
        throw "WSL_NEW_DISK_IDENTITY_MISMATCH: expected exactly one newly added WSL disk; found $($newWSLDisks.Count)"
    }
    $wslDisk = $newWSLDisks[0]
    $wslDiskPath = [string]$wslDisk.path
    if ([string]::IsNullOrWhiteSpace($wslDiskPath) -or
        $wslDiskPath -notmatch '^/dev/[A-Za-z0-9._-]+$' -or
        [string]$wslDisk.type -cne 'disk' -or
        -not [string]::IsNullOrWhiteSpace([string]$wslDisk.pkname) -or
        [int64]$wslDisk.size -ne $expectedSize -or
        -not [string]::IsNullOrWhiteSpace([string]$wslDisk.mountpoint)) {
        throw "WSL_NEW_DISK_RELATION_INVALID: path='$wslDiskPath' type='$($wslDisk.type)' parent='$($wslDisk.pkname)' size='$($wslDisk.size)' mount='$($wslDisk.mountpoint)'"
    }
    $state = Get-Content -Raw -LiteralPath $statePath -ErrorAction Stop | ConvertFrom-Json
    $state | Add-Member -NotePropertyName selected_wsl_disk -NotePropertyValue ([pscustomobject]@{
        name=[string]$wslDisk.name; path=$wslDiskPath; type=[string]$wslDisk.type
        parent=[string]$wslDisk.pkname; size=[int64]$wslDisk.size
    }) -Force
    $tmp = "$statePath.$([guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText($tmp, ($state | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    Move-Item -Force -LiteralPath $tmp -Destination $statePath
    $bashCommand = "echo " + %s + " | base64 -d | bash -s -- " + $wslDiskPath
    & wsl.exe -d Ubuntu-24.04 --user root -- bash -lc $bashCommand
    $bashExit = $LASTEXITCODE
    if ($bashExit -eq 42) { throw "MULTIPLE_OR_MISSING_EXT4_ROOTS: content discovery did not find exactly one Ubuntu ext4 root" }
    if ($bashExit -eq 43) { throw "WSL_BLOCK_PARENT_RELATION_INVALID: target disk or partition parent relationship failed validation" }
    if ($bashExit -ne 0) { throw "WSL_IMAGE_TRANSFORM_FAILED: exit $bashExit" }
    & wsl.exe --unmount $physicalPath
    if ($LASTEXITCODE -ne 0) {
        Save-BuilderState 'diagnostic_retained' "WSL_UNMOUNT_FAILED: exit $LASTEXITCODE" $true $false
        [pscustomobject]@{ status='diagnostic_retained'; safe_to_detach=$false; error="WSL_UNMOUNT_FAILED: exit $LASTEXITCODE"; physical_path=$physicalPath; selected_disk=$selectedIdentity } | ConvertTo-Json -Depth 8 -Compress
        return
    }
    $mounted = $false
    Save-BuilderState 'filesystem_updated' '' $false $true
    [pscustomobject]@{ status='filesystem_updated'; safe_to_detach=$true; physical_path=$physicalPath; selected_disk=$selectedIdentity; selected_wsl_disk=$wslDiskPath } | ConvertTo-Json -Depth 8 -Compress
} catch {
    $message = $_.Exception.Message
    $safe = -not $mounted
    if ($mounted) {
        & wsl.exe --unmount $physicalPath 2>$null
        if ($LASTEXITCODE -eq 0) { $safe = $true; $mounted = $false }
    }
    Save-BuilderState 'diagnostic_retained' $message $true $safe
    [pscustomobject]@{ status='diagnostic_retained'; safe_to_detach=$safe; error=$message; physical_path=$physicalPath } | ConvertTo-Json -Depth 8 -Compress
}
`, PSLit(p.StatePath), p.ExpectedSizeBytes, p.ExpectedTargetLocation, PSLit(encoded))
	return wrapTagged(body), nil
}

type LinuxImageBuilderDetachParams struct {
	VMName    string
	VHDXPath  string
	StatePath string
	Retain    bool
	Reason    string
}

func BuildLinuxImageBuilderDetachScript(p LinuxImageBuilderDetachParams) (string, error) {
	if strings.TrimSpace(p.VMName) == "" || strings.TrimSpace(p.VHDXPath) == "" || strings.TrimSpace(p.StatePath) == "" {
		return "", fmt.Errorf("builder VM, staging VHDX, and state path are required")
	}
	detachedPhase := "filesystem_updated"
	detachedStatus := "disk_detached"
	detachedFields := map[string]string{"attached_disk_path": "$null"}
	if strings.TrimSpace(p.Reason) != "" {
		detachedPhase = "diagnostic_retained"
		detachedStatus = "diagnostic_detached"
		detachedFields["diagnostic_state"] = "$reason"
	}
	body := fmt.Sprintf(`
$name = %s
$vhdx = [IO.Path]::GetFullPath(%s)
$statePath = %s
$retain = %s
$reason = %s
$vm = Get-VM -Name $name -ErrorAction Stop
if ($vm.State -ne 'Off') { Stop-VM -Name $name -Force -ErrorAction Stop | Out-Null }
$owned = @(Get-VMHardDiskDrive -VMName $name -ErrorAction Stop | Where-Object {
    $_.Path -and [IO.Path]::GetFullPath([string]$_.Path).Equals($vhdx, [StringComparison]::OrdinalIgnoreCase)
})
if ($owned.Count -gt 1) { throw "BUILDER_OWNED_DISK_DUPLICATE: '$vhdx'" }
if ($retain) {
    if ($owned.Count -ne 1) { throw "DIAGNOSTIC_DISK_NOT_ATTACHED: '$vhdx'" }
    %s
    [pscustomobject]@{ status='diagnostic_retained'; detached=$false; vhdx_path=$vhdx; reason=$reason } | ConvertTo-Json -Compress
    return
}
foreach ($drive in $owned) {
    Remove-VMHardDiskDrive -VMHardDiskDrive $drive -ErrorAction Stop
}
$remaining = @(Get-VMHardDiskDrive -VMName $name -ErrorAction Stop | Where-Object {
    $_.Path -and [IO.Path]::GetFullPath([string]$_.Path).Equals($vhdx, [StringComparison]::OrdinalIgnoreCase)
})
if ($remaining.Count -ne 0) { throw "BUILDER_DISK_DETACH_FAILED: '$vhdx'" }
%s
[pscustomobject]@{ status=%s; detached=$true; vhdx_path=$vhdx; builder_state=[string](Get-VM -Name $name).State; reason=$reason } | ConvertTo-Json -Compress
`, PSLit(p.VMName), PSLit(p.VHDXPath), PSLit(p.StatePath), PSBool(p.Retain), PSLit(p.Reason),
		linuxImageStateUpdate(p.StatePath, "diagnostic_retained", map[string]string{"diagnostic_state": "$reason"}),
		linuxImageStateUpdate(p.StatePath, detachedPhase, detachedFields), PSLit(detachedStatus))
	return wrapTagged(body), nil
}

func BuildLinuxImageHashScript(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("VHDX path is required")
	}
	body := fmt.Sprintf(`
$path = %s
if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "VHDX_NOT_FOUND: '$path'" }
$hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
[pscustomobject]@{ path=$path; sha256=$hash; length=[int64](Get-Item -LiteralPath $path).Length } | ConvertTo-Json -Compress
`, PSLit(path))
	return wrapTagged(body), nil
}

type LinuxImagePublishParams struct {
	StagedVHDX   string
	FinalVHDX    string
	MetadataPath string
	StatePath    string
	Metadata     linuximage.ImageMetadata
}

func BuildLinuxImagePublishScript(p LinuxImagePublishParams) (string, error) {
	if strings.TrimSpace(p.StagedVHDX) == "" || strings.TrimSpace(p.FinalVHDX) == "" ||
		strings.TrimSpace(p.MetadataPath) == "" || strings.TrimSpace(p.StatePath) == "" {
		return "", fmt.Errorf("staged VHDX, final VHDX, metadata path, and state path are required")
	}
	if p.Metadata.Verification.Status != linuximage.VerificationVerified ||
		!strings.EqualFold(p.Metadata.Verification.Signer, linuximage.UbuntuSigningKeyFingerprint) {
		return "", fmt.Errorf("refusing to publish without the pinned verified Ubuntu signer")
	}
	if p.Metadata.SchemaVersion != linuximage.TransformSchema || len(p.Metadata.PreparedSHA256) != 64 ||
		strings.TrimSpace(p.Metadata.BuilderProfile) == "" || len(p.Metadata.BuilderProfileFingerprint) != 64 {
		return "", fmt.Errorf("refusing to publish incomplete transform metadata")
	}
	if err := p.Metadata.Source.Validate(); err != nil {
		return "", fmt.Errorf("refusing to publish invalid source metadata: %w", err)
	}
	expectedCacheKey, err := linuximage.CacheKey(p.Metadata.ImageSHA256, p.Metadata.DiskSizeGB)
	if err != nil {
		return "", err
	}
	if p.Metadata.CacheKey != expectedCacheKey || !strings.EqualFold(p.Metadata.PreparedVHDX, p.FinalVHDX) {
		return "", fmt.Errorf("refusing to publish metadata with an invalid cache key or final path")
	}
	metadataJSON, err := json.Marshal(p.Metadata)
	if err != nil {
		return "", err
	}
	body := fmt.Sprintf(`
$stagedVHDX = %s
$finalVHDX = %s
$metadataPath = %s
$statePath = %s
$metadataJSON = %s
$expectedSize = %s
$expectedHash = %s
if (-not (Test-Path -LiteralPath $stagedVHDX -PathType Leaf)) { throw "STAGED_VHDX_NOT_FOUND: '$stagedVHDX'" }
$staged = Get-VHD -Path $stagedVHDX -ErrorAction Stop
if ("$($staged.VhdType)" -ne 'Dynamic' -or [int64]$staged.BlockSize -ne 1MB -or [int64]$staged.Size -ne $expectedSize) {
    throw "STAGED_VHDX_INVALID: type, block size, or virtual size is invalid"
}
$actualHash = (Get-FileHash -LiteralPath $stagedVHDX -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -cne $expectedHash) { throw "STAGED_VHDX_HASH_MISMATCH: expected $expectedHash, got $actualHash" }
$contentDir = Split-Path -Parent $finalVHDX
New-Item -ItemType Directory -Force -Path $contentDir | Out-Null
if (-not (Test-Path -LiteralPath $finalVHDX -PathType Leaf)) {
    Move-Item -LiteralPath $stagedVHDX -Destination $finalVHDX
} else {
    $existingHash = (Get-FileHash -LiteralPath $finalVHDX -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($existingHash -cne $expectedHash) { throw "PUBLISHED_VHDX_INVALID: existing digest differs" }
    Remove-Item -LiteralPath $stagedVHDX -Force -ErrorAction SilentlyContinue
}
Set-ItemProperty -LiteralPath $finalVHDX -Name IsReadOnly -Value $true
$metadataTmp = "$metadataPath.tmp"
[IO.File]::WriteAllText($metadataTmp, $metadataJSON, [Text.UTF8Encoding]::new($false))
Move-Item -Force -LiteralPath $metadataTmp -Destination $metadataPath
Set-ItemProperty -LiteralPath $metadataPath -Name IsReadOnly -Value $true
$state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
$state | Add-Member -NotePropertyName phase -NotePropertyValue 'ready' -Force
$state | Add-Member -NotePropertyName cache_key -NotePropertyValue (($metadataJSON | ConvertFrom-Json).cache_key) -Force
$state | Add-Member -NotePropertyName prepared_vhdx -NotePropertyValue $finalVHDX -Force
$state | Add-Member -NotePropertyName prepared_sha256 -NotePropertyValue $expectedHash -Force
$state | Add-Member -NotePropertyName metadata_path -NotePropertyValue $metadataPath -Force
$state | Add-Member -NotePropertyName attached_disk_path -NotePropertyValue $null -Force
$state | Add-Member -NotePropertyName updated_at -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force
$stateTmp = "$statePath.$([guid]::NewGuid().ToString('N')).tmp"
$state | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $stateTmp -Encoding UTF8
Move-Item -Force -LiteralPath $stateTmp -Destination $statePath
[pscustomobject]@{ status='ready'; ready=$true; vhdx_path=$finalVHDX; metadata_path=$metadataPath; sha256=$expectedHash; read_only=(Get-Item -LiteralPath $finalVHDX).IsReadOnly } | ConvertTo-Json -Compress
`, PSLit(p.StagedVHDX), PSLit(p.FinalVHDX), PSLit(p.MetadataPath), PSLit(p.StatePath),
		PSLit(string(metadataJSON)), gbBytes(float64(p.Metadata.DiskSizeGB)), PSLit(strings.ToLower(p.Metadata.PreparedSHA256)))
	return wrapTagged(body), nil
}

type LinuxImageLockParams struct {
	CacheRoot string
	CacheKey  string
	Owner     string
}

type LinuxImageBuilderLockParams struct {
	Key        string
	Owner      string
	StaleAfter int
}

func BuildLinuxImageBuilderAcquireLockScript(p LinuxImageBuilderLockParams) (string, error) {
	if !stagingIDPattern.MatchString(strings.TrimSpace(p.Key)) {
		return "", fmt.Errorf("builder lock key must be 16-64 lowercase hexadecimal characters")
	}
	if err := validateStagingID(p.Owner); err != nil {
		return "", err
	}
	staleAfter := p.StaleAfter
	if staleAfter <= 0 {
		staleAfter = 7200
	}
	body := fmt.Sprintf(`
$lockRoot = Join-Path $env:ProgramData 'LabLink\linux-image-builder-locks'
$lockPath = Join-Path $lockRoot (%s + '.lock')
$ownerToken = %s
$staleAfter = %d
New-Item -ItemType Directory -Force -Path $lockRoot | Out-Null
$acquired = $false
$recovered = $false
for ($attempt = 0; $attempt -lt 3 -and -not $acquired; $attempt++) {
    $createdThisAttempt = $false
    try {
        New-Item -ItemType Directory -Path $lockPath -ErrorAction Stop | Out-Null
        $createdThisAttempt = $true
        $owner = [ordered]@{ token=$ownerToken; acquired_utc=[DateTime]::UtcNow.ToString('o') }
        try {
            [IO.File]::WriteAllText((Join-Path $lockPath 'owner.json'), ($owner | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
        } catch {
            Remove-Item -LiteralPath $lockPath -Recurse -Force -ErrorAction SilentlyContinue
            throw
        }
        $acquired = $true
        break
    } catch {
        if ($createdThisAttempt) { throw }
        $ownerPath = Join-Path $lockPath 'owner.json'
        $existing = $null
        try { $existing = Get-Content -Raw -LiteralPath $ownerPath -ErrorAction Stop | ConvertFrom-Json } catch {}
        $stamp = $null
        if ($existing -and $existing.token) {
            try { $stamp = [DateTime]::Parse([string]$existing.acquired_utc).ToUniversalTime() } catch {}
        }
        if (-not $stamp) { $stamp = (Get-Item -LiteralPath $lockPath -ErrorAction Stop).LastWriteTimeUtc }
        if (([DateTime]::UtcNow - $stamp).TotalSeconds -le $staleAfter) { break }
        $stalePath = "$lockPath.stale-$([guid]::NewGuid().ToString('N'))"
        if (Test-Path -LiteralPath $stalePath) { break }
        try {
            Move-Item -LiteralPath $lockPath -Destination $stalePath -ErrorAction Stop
            $recovered = $true
            Remove-Item -LiteralPath $stalePath -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            Start-Sleep -Milliseconds 50
        }
    }
}
[pscustomobject]@{
    status=if ($acquired) { 'lock_acquired' } else { 'builder_busy' }
    acquired=$acquired; owner=$ownerToken; recovered_stale=$recovered; lock_path=$lockPath
} | ConvertTo-Json -Compress
`, PSLit(strings.ToLower(strings.TrimSpace(p.Key))), PSLit(p.Owner), staleAfter)
	return wrapTagged(body), nil
}

func BuildLinuxImageBuilderReleaseLockScript(p LinuxImageBuilderLockParams) (string, error) {
	if !stagingIDPattern.MatchString(strings.TrimSpace(p.Key)) {
		return "", fmt.Errorf("builder lock key must be 16-64 lowercase hexadecimal characters")
	}
	if err := validateStagingID(p.Owner); err != nil {
		return "", err
	}
	body := fmt.Sprintf(`
$lockRoot = Join-Path $env:ProgramData 'LabLink\linux-image-builder-locks'
$lockPath = Join-Path $lockRoot (%s + '.lock')
$ownerToken = %s
$released = $false
if (Test-Path -LiteralPath $lockPath -PathType Container) {
    $ownerPath = Join-Path $lockPath 'owner.json'
    $existing = $null
    try { $existing = Get-Content -Raw -LiteralPath $ownerPath -ErrorAction Stop | ConvertFrom-Json } catch {}
    if ($existing -and [string]$existing.token -ceq $ownerToken) {
        Remove-Item -LiteralPath $lockPath -Recurse -Force
        $released = $true
    }
}
[pscustomobject]@{ status=if ($released) { 'lock_released' } else { 'lock_not_owned' }; released=$released; owner=$ownerToken } | ConvertTo-Json -Compress
`, PSLit(strings.ToLower(strings.TrimSpace(p.Key))), PSLit(p.Owner))
	return wrapTagged(body), nil
}

func BuildLinuxImageAcquireLockScript(p LinuxImageLockParams) (string, error) {
	if strings.TrimSpace(p.CacheRoot) == "" || strings.TrimSpace(p.CacheKey) == "" {
		return "", fmt.Errorf("cache root and cache key are required")
	}
	if err := validateStagingID(p.Owner); err != nil {
		return "", err
	}
	body := fmt.Sprintf(`
$lockDir = Join-Path %s ('locks\' + %s)
$owner = %s
$ownerPath = Join-Path $lockDir 'owner.json'
$acquired = $false
$recovered = $false
$existing = $null
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $lockDir) | Out-Null
for ($attempt = 0; $attempt -lt 3 -and -not $acquired; $attempt++) {
    $createdThisAttempt = $false
    try {
        New-Item -ItemType Directory -Path $lockDir -ErrorAction Stop | Out-Null
        $createdThisAttempt = $true
        $now = (Get-Date).ToUniversalTime()
        $record = [pscustomobject]@{ owner=$owner; created_at=$now.ToString('o'); expires_at=$now.AddHours(2).ToString('o') }
        $ownerTmp = Join-Path $lockDir ("owner.$owner.tmp")
        try {
            [IO.File]::WriteAllText($ownerTmp, ($record | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
            Move-Item -LiteralPath $ownerTmp -Destination $ownerPath -ErrorAction Stop
        } catch {
            Remove-Item -LiteralPath $ownerTmp -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $lockDir -Recurse -Force -ErrorAction SilentlyContinue
            throw
        }
        $acquired = $true
        break
    } catch {
        if ($createdThisAttempt) { throw }
        $existing = $null
        $expires = $null
        try {
            $existing = Get-Content -Raw -LiteralPath $ownerPath -ErrorAction Stop | ConvertFrom-Json
            if ($existing.owner -and $existing.expires_at) { $expires = [DateTime]::Parse([string]$existing.expires_at).ToUniversalTime() }
        } catch { $existing = $null; $expires = $null }
        if (-not $expires) { $expires = (Get-Item -LiteralPath $lockDir -ErrorAction Stop).LastWriteTimeUtc.AddHours(2) }
        if ($expires -ge [DateTime]::UtcNow) { break }
        $stalePath = "$lockDir.stale-$owner-$([guid]::NewGuid().ToString('N'))"
        try {
            Move-Item -LiteralPath $lockDir -Destination $stalePath -ErrorAction Stop
            $recovered = $true
            Remove-Item -LiteralPath $stalePath -Recurse -Force -ErrorAction SilentlyContinue
        } catch { Start-Sleep -Milliseconds 50 }
    }
}
[pscustomobject]@{
    status=if ($acquired) { 'lock_acquired' } else { 'image_preparing' }
    acquired=$acquired; lock_dir=$lockDir; owner=if ($acquired) { $owner } else { $existing.owner }; recovered_stale=$recovered
} | ConvertTo-Json -Compress
`, PSLit(p.CacheRoot), PSLit(p.CacheKey), PSLit(p.Owner))
	return wrapTagged(body), nil
}

func BuildLinuxImageReleaseLockScript(p LinuxImageLockParams) (string, error) {
	if strings.TrimSpace(p.CacheRoot) == "" || strings.TrimSpace(p.CacheKey) == "" {
		return "", fmt.Errorf("cache root and cache key are required")
	}
	if err := validateStagingID(p.Owner); err != nil {
		return "", err
	}
	body := fmt.Sprintf(`
$lockDir = Join-Path %s ('locks\' + %s)
$owner = %s
$ownerPath = Join-Path $lockDir 'owner.json'
if (-not (Test-Path -LiteralPath $ownerPath -PathType Leaf)) {
    [pscustomobject]@{ status='lock_not_owned'; released=$false; owner=$owner } | ConvertTo-Json -Compress
    return
}
$existing = Get-Content -Raw -LiteralPath $ownerPath -ErrorAction Stop | ConvertFrom-Json
if ([string]$existing.owner -cne $owner) { throw "LOCK_OWNER_MISMATCH: refusing to release another preparation owner" }
Remove-Item -LiteralPath $lockDir -Recurse -Force -ErrorAction SilentlyContinue
[pscustomobject]@{ status='lock_released'; released=$true; owner=$owner } | ConvertTo-Json -Compress
`, PSLit(p.CacheRoot), PSLit(p.CacheKey), PSLit(p.Owner))
	return wrapTagged(body), nil
}

func linuxImageStateUpdate(statePath, phase string, fields map[string]string) string {
	if strings.TrimSpace(statePath) == "" {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "$statePath = %s\n", PSLit(statePath))
	b.WriteString("if (-not (Test-Path -LiteralPath $statePath)) { throw \"STATE_MISSING: '$statePath'\" }\n")
	b.WriteString("$state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json\n")
	fmt.Fprintf(&b, "$state | Add-Member -NotePropertyName phase -NotePropertyValue %s -Force\n", PSLit(phase))
	for name, expression := range fields {
		fmt.Fprintf(&b, "$state | Add-Member -NotePropertyName %s -NotePropertyValue (%s) -Force\n", name, expression)
	}
	b.WriteString("$state | Add-Member -NotePropertyName updated_at -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force\n")
	b.WriteString("$stateTmp = \"$statePath.$([guid]::NewGuid().ToString('N')).tmp\"\n")
	b.WriteString("$state | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $stateTmp -Encoding UTF8\n")
	b.WriteString("Move-Item -Force -LiteralPath $stateTmp -Destination $statePath\n")
	return b.String()
}
