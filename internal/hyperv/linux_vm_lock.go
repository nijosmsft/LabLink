package hyperv

import (
	"fmt"
	"strings"
)

type LinuxVMLockParams struct {
	Key        string
	Owner      string
	StaleAfter int
}

func BuildLinuxVMAcquireLockScript(p LinuxVMLockParams) (string, error) {
	if strings.TrimSpace(p.Key) == "" || strings.TrimSpace(p.Owner) == "" {
		return "", fmt.Errorf("Linux VM lock key and owner are required")
	}
	staleAfter := p.StaleAfter
	if staleAfter <= 0 {
		staleAfter = 7200
	}
	body := fmt.Sprintf(`
$lockRoot = Join-Path $env:ProgramData 'LabLink\vm-locks'
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
        if ($existing -and $existing.acquired_utc) {
            try { $stamp = [DateTime]::Parse([string]$existing.acquired_utc).ToUniversalTime() } catch {}
        }
        if (-not $stamp) { $stamp = (Get-Item -LiteralPath $lockPath -ErrorAction Stop).LastWriteTimeUtc }
        if (([DateTime]::UtcNow - $stamp).TotalSeconds -le $staleAfter) { break }
        $staleID = if ($existing -and $existing.token) { [string]$existing.token } else { 'missing-' + $stamp.Ticks }
        $stalePath = "$lockPath.stale-$staleID"
        if (Test-Path -LiteralPath $stalePath) { break }
        try {
            Move-Item -LiteralPath $lockPath -Destination $stalePath -ErrorAction Stop
            $recovered = $true
        } catch {
            Start-Sleep -Milliseconds 50
        }
    }
}
[pscustomobject]@{
    status=if ($acquired) { 'lock_acquired' } else { 'lock_busy' }
    acquired=$acquired; owner=$ownerToken; recovered_stale=$recovered; lock_path=$lockPath
} | ConvertTo-Json -Compress
`, PSLit(strings.ToLower(p.Key)), PSLit(p.Owner), staleAfter)
	return wrapTagged(body), nil
}

func BuildLinuxVMReleaseLockScript(p LinuxVMLockParams) (string, error) {
	if strings.TrimSpace(p.Key) == "" || strings.TrimSpace(p.Owner) == "" {
		return "", fmt.Errorf("Linux VM lock key and owner are required")
	}
	body := fmt.Sprintf(`
$lockRoot = Join-Path $env:ProgramData 'LabLink\vm-locks'
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
`, PSLit(strings.ToLower(p.Key)), PSLit(p.Owner))
	return wrapTagged(body), nil
}
