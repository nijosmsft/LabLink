package hyperv

import (
	"encoding/json"
	"fmt"
	"strings"
)

type ClaimIsolatedVMParams struct {
	Guard              IsolatedMutationGuard
	OrchestratorVMGUID string
	VMName             string
	SwitchGUID         string
	AdapterName        string
	MAC                string
	Metadata           IsolatedVMMetadata
}

type InspectIsolatedVMParams struct {
	VMName       string
	ExpectedVMID string
	ExpectedGUID string
}

type StartIsolatedVMParams struct {
	VMName       string
	ExpectedVMID string
	ExpectedGUID string
	ExpectedIPv4 string
}

type DeleteIsolatedVMParams struct {
	Guard              IsolatedMutationGuard
	OrchestratorVMGUID string
	VMName             string
	ExpectedVMID       string
	ExpectedVMGUID     string
	ExpectedAdapterID  string
	ExpectedVHDPath    string
	ExpectedVMPath     string
	ExpectedCIDATAPath string
	ExpectedOwnership  string
	DeleteStorage      bool
}

type IsolatedVMMutationResult struct {
	Action          string `json:"action"`
	VMID            string `json:"vm_id"`
	VMName          string `json:"vm_name"`
	VMGUID          string `json:"vm_guid"`
	AdapterID       string `json:"adapter_id"`
	SwitchGUID      string `json:"switch_guid"`
	MAC             string `json:"mac"`
	TimeSyncEnabled bool   `json:"time_sync_enabled"`
	State           string `json:"state"`
	VHDPath         string `json:"vhd_path,omitempty"`
	VMPath          string `json:"vm_path,omitempty"`
	DeletedStorage  bool   `json:"deleted_storage,omitempty"`
}

func BuildClaimIsolatedVMScript(p ClaimIsolatedVMParams) (string, error) {
	if err := validateMutationGuard(p.Guard); err != nil {
		return "", err
	}
	if p.Guard.ResourceType != "vm" || p.Guard.ResourceID != p.Metadata.VMID ||
		p.Guard.Action != "claim_isolated_vm" {
		return "", fmt.Errorf("mutation guard does not authorize isolated VM claim")
	}
	if strings.TrimSpace(p.VMName) == "" || strings.TrimSpace(p.AdapterName) == "" {
		return "", fmt.Errorf("isolated VM name and adapter name are required")
	}
	if err := validateGUID("orchestrator VM", p.OrchestratorVMGUID); err != nil {
		return "", err
	}
	if err := validateGUID("switch", p.SwitchGUID); err != nil {
		return "", err
	}
	if !macRE.MatchString(strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(p.MAC, "-", ""), ":", ""))) {
		return "", fmt.Errorf("invalid isolated VM MAC %q", p.MAC)
	}
	if p.Metadata.LifecycleState == "" {
		p.Metadata.LifecycleState = "creating"
	}
	metadata, err := MarshalIsolatedVMMetadata(p.Metadata)
	if err != nil {
		return "", err
	}
	metadataJSON := strings.TrimPrefix(metadata, IsolatedVMMetadataPrefix)
	guard, err := isolatedMutationGuardPowerShell(p.Guard)
	if err != nil {
		return "", err
	}
	body := PreflightScript() + isolatedHostMetadataPowerShell() + isolatedParentGuardPowerShell() + guard + fmt.Sprintf(`
try {
    $expected = %s | ConvertFrom-Json
    $orchestratorVMGUID = %s
    $parent = Get-VM -Id $orchestratorVMGUID -ErrorAction Stop
    $parentMetadata = Get-LabLinkIsolatedVMNotes $parent %s
    $cascadeItem = Assert-LabLinkParentAllowsMutation $parentMetadata
    $vm = @(Get-VM -Name %s -ErrorAction SilentlyContinue)
    if ($vm.Count -ne 1) { throw 'VM_IDENTITY_MISMATCH: expected exactly one generated VM name' }
    if ([string]$vm[0].State -ne 'Off') { throw 'ISOLATED_VM_MUST_BE_OFF: claim and network fencing must precede boot' }
    $switch = @(Get-VMSwitch -ErrorAction Stop | Where-Object { [string]$_.Id -ieq %s })
    if ($switch.Count -ne 1 -or [string]$switch[0].SwitchType -ne 'Private') {
        throw 'SWITCH_IDENTITY_MISMATCH: exact private switch GUID was not found'
    }
    $adapters = @(Get-VMNetworkAdapter -VM $vm[0] -ErrorAction Stop)
    if ($adapters.Count -ne 1) { throw 'ISOLATED_VM_NIC_COUNT_INVALID: guest must have only one private NIC' }
    Rename-VMNetworkAdapter -VMNetworkAdapter $adapters[0] -NewName %s -ErrorAction Stop
    Connect-VMNetworkAdapter -VMNetworkAdapter $adapters[0] -SwitchName ([string]$switch[0].Name) -ErrorAction Stop
    Set-VMNetworkAdapter -VMNetworkAdapter $adapters[0] -StaticMacAddress %s -DhcpGuard On -RouterGuard On -ErrorAction Stop
    Enable-VMIntegrationService -VM $vm[0] -Name 'Time Synchronization' -ErrorAction Stop
    $adapter = @(Get-VMNetworkAdapter -VM $vm[0] -Name %s -ErrorAction Stop)
    if ($adapter.Count -ne 1) { throw 'ADAPTER_IDENTITY_MISMATCH' }
    $expected | Add-Member -NotePropertyName vm_guid -NotePropertyValue ([string]$vm[0].Id) -Force
    $expected | Add-Member -NotePropertyName adapter_id -NotePropertyValue ([string]$adapter[0].Id) -Force
    $expected | Add-Member -NotePropertyName switch_guid -NotePropertyValue ([string]$switch[0].Id) -Force
    Set-VM -VM $vm[0] -Notes (%s + ($expected | ConvertTo-Json -Depth 20 -Compress)) -ErrorAction Stop
    [pscustomobject]@{
        action='claimed'; vm_id=[string]$expected.vm_id; vm_name=[string]$vm[0].Name
        vm_guid=[string]$vm[0].Id; adapter_id=[string]$adapter[0].Id
        switch_guid=[string]$switch[0].Id; mac=([string]$adapter[0].MacAddress -replace '[-:]','').ToUpperInvariant()
        time_sync_enabled=[bool](Get-VMIntegrationService -VM $vm[0] -Name 'Time Synchronization').Enabled
        state=[string]$vm[0].State
    } | ConvertTo-Json -Compress
} finally {
    $__isolatedGate.Dispose()
}
`, PSLit(metadataJSON), PSLit(p.OrchestratorVMGUID), PSLit(IsolatedOrchestratorMetadataPrefix),
		PSLit(p.VMName), PSLit(p.SwitchGUID), PSLit(p.AdapterName), PSLit(p.MAC),
		PSLit(p.AdapterName), PSLit(IsolatedVMMetadataPrefix))
	return wrapTagged(body), nil
}

func BuildInspectIsolatedVMScript(p InspectIsolatedVMParams) (string, error) {
	if strings.TrimSpace(p.VMName) == "" || strings.TrimSpace(p.ExpectedVMID) == "" {
		return "", fmt.Errorf("isolated VM name and ID are required")
	}
	if p.ExpectedGUID != "" {
		if err := validateGUID("VM", p.ExpectedGUID); err != nil {
			return "", err
		}
	}
	body := fmt.Sprintf(`
$vm = @(Get-VM -Name %s -ErrorAction SilentlyContinue)
if ($vm.Count -eq 0) { [pscustomobject]@{ exists=$false } | ConvertTo-Json -Compress; return }
if ($vm.Count -ne 1) { throw 'VM_IDENTITY_MISMATCH: generated VM name is not unique' }
if (%s -and [string]$vm[0].Id -ine %s) { throw 'VM_IDENTITY_MISMATCH: VM GUID changed' }
$notes = [string]$vm[0].Notes
if (-not $notes.StartsWith(%s, [StringComparison]::Ordinal)) { throw 'VM_METADATA_MISSING' }
$metadata = $notes.Substring(%s.Length) | ConvertFrom-Json
if ([string]$metadata.vm_id -cne %s) { throw 'VM_IDENTITY_MISMATCH: immutable VM ID changed' }
$adapter = @(Get-VMNetworkAdapter -VM $vm[0] -ErrorAction Stop)
$disk = @(Get-VMHardDiskDrive -VM $vm[0] -ErrorAction Stop)
[pscustomobject]@{
 exists=$true; action='inspected'; vm_id=[string]$metadata.vm_id; vm_name=[string]$vm[0].Name
 vm_guid=[string]$vm[0].Id; adapter_id=if($adapter.Count -eq 1){[string]$adapter[0].Id}else{''}
 switch_guid=if($adapter.Count -eq 1){[string]$adapter[0].SwitchId}else{''}
 mac=if($adapter.Count -eq 1){([string]$adapter[0].MacAddress -replace '[-:]','').ToUpperInvariant()}else{''}
 time_sync_enabled=[bool](Get-VMIntegrationService -VM $vm[0] -Name 'Time Synchronization').Enabled
 state=[string]$vm[0].State; vhd_path=if($disk.Count -eq 1){[string]$disk[0].Path}else{''}
 vm_path=[string]$vm[0].Path; metadata=$metadata
} | ConvertTo-Json -Depth 20 -Compress
`, PSLit(p.VMName), PSBool(p.ExpectedGUID != ""), PSLit(p.ExpectedGUID),
		PSLit(IsolatedVMMetadataPrefix), PSLit(IsolatedVMMetadataPrefix),
		PSLit(p.ExpectedVMID))
	return wrapTagged(body), nil
}

func BuildStartIsolatedVMScript(p StartIsolatedVMParams) (string, error) {
	if strings.TrimSpace(p.ExpectedIPv4) == "" {
		return "", fmt.Errorf("expected isolated IPv4 is required")
	}
	if strings.TrimSpace(p.VMName) == "" || strings.TrimSpace(p.ExpectedVMID) == "" {
		return "", fmt.Errorf("isolated VM name and ID are required")
	}
	if err := validateGUID("VM", p.ExpectedGUID); err != nil {
		return "", err
	}
	body := fmt.Sprintf(`
$vm = Get-VM -Id %s -ErrorAction Stop
if ([string]$vm.Name -cne %s) { throw 'VM_IDENTITY_MISMATCH: generated VM name changed' }
$notes = [string]$vm.Notes
if (-not $notes.StartsWith(%s, [StringComparison]::Ordinal)) { throw 'VM_METADATA_MISSING' }
$metadata = $notes.Substring(%s.Length) | ConvertFrom-Json
if ([string]$metadata.vm_id -cne %s) { throw 'VM_IDENTITY_MISMATCH: immutable VM ID changed' }
if ([string]$vm.State -ne 'Running') { Start-VM -VM $vm -ErrorAction Stop | Out-Null }
[pscustomobject]@{ action='started'; vm_id=%s; vm_name=[string]$vm.Name; vm_guid=[string]$vm.Id; state=[string](Get-VM -Id $vm.Id).State; ip_address=%s } | ConvertTo-Json -Compress
`, PSLit(p.ExpectedGUID), PSLit(p.VMName), PSLit(IsolatedVMMetadataPrefix),
		PSLit(IsolatedVMMetadataPrefix), PSLit(p.ExpectedVMID),
		PSLit(p.ExpectedVMID), PSLit(p.ExpectedIPv4))
	return wrapTagged(body), nil
}

func BuildDeleteIsolatedVMScript(p DeleteIsolatedVMParams) (string, error) {
	if err := validateMutationGuard(p.Guard); err != nil {
		return "", err
	}
	if p.Guard.ResourceType != "vm" || p.Guard.ResourceID != p.ExpectedVMID ||
		p.Guard.Action != "delete_isolated_vm" {
		return "", fmt.Errorf("mutation guard does not authorize isolated VM deletion")
	}
	for kind, value := range map[string]string{
		"orchestrator VM": p.OrchestratorVMGUID, "VM": p.ExpectedVMGUID,
	} {
		if err := validateGUID(kind, value); err != nil {
			return "", err
		}
	}
	if err := validateAdapterID(p.ExpectedAdapterID); err != nil {
		return "", err
	}
	guard, err := isolatedMutationGuardPowerShell(p.Guard)
	if err != nil {
		return "", err
	}
	body := PreflightScript() + isolatedHostMetadataPowerShell() + isolatedParentGuardPowerShell() + guard + fmt.Sprintf(`
try {
    $parent = Get-VM -Id %s -ErrorAction Stop
    $parentMetadata = Get-LabLinkIsolatedVMNotes $parent %s
    $cascadeItem = Assert-LabLinkParentAllowsMutation $parentMetadata
    $deleteStorage = %s
    $expectedVHDPath = %s
    $expectedVMPath = %s
    $cidataPath = %s
    $ownershipPath = %s
    function Remove-LabLinkOwnedVMArtifacts {
        $deletedVHD = $false
        if ($deleteStorage -and (Test-Path -LiteralPath $expectedVHDPath -PathType Leaf)) {
            $referenced = @(Get-VM -ErrorAction SilentlyContinue | Get-VMHardDiskDrive -ErrorAction SilentlyContinue | Where-Object {
                $_.Path -and [IO.Path]::GetFullPath([string]$_.Path) -ieq [IO.Path]::GetFullPath($expectedVHDPath)
            }).Count -gt 0
            if ($referenced) { throw 'VM_STORAGE_IN_USE: exact owned child VHD is attached to another VM' }
            Remove-Item -LiteralPath $expectedVHDPath -Force -ErrorAction Stop
            $deletedVHD = $true
        }
        if ($deleteStorage -and $cidataPath -and (Test-Path -LiteralPath $cidataPath -PathType Leaf)) {
            Remove-Item -LiteralPath $cidataPath -Force -ErrorAction Stop
        }
        if ($deleteStorage -and $ownershipPath -and (Test-Path -LiteralPath $ownershipPath -PathType Leaf)) {
            Remove-Item -LiteralPath $ownershipPath -Force -ErrorAction Stop
        }
        if ($deleteStorage -and $expectedVMPath -and (Test-Path -LiteralPath $expectedVMPath -PathType Container)) {
            $files = @(Get-ChildItem -LiteralPath $expectedVMPath -Recurse -Force -File -ErrorAction Stop)
            $reparse = @(Get-ChildItem -LiteralPath $expectedVMPath -Recurse -Force -ErrorAction Stop | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
            if ($files.Count -eq 0 -and $reparse.Count -eq 0) {
                Remove-Item -LiteralPath $expectedVMPath -Recurse -Force -ErrorAction Stop
            }
        }
        return $deletedVHD
    }
    $vm = @(Get-VM -Name %s -ErrorAction SilentlyContinue)
    if ($vm.Count -eq 0) {
        $deletedStorage = Remove-LabLinkOwnedVMArtifacts
        [pscustomobject]@{ action='already_absent'; vm_id=%s; vhd_path=%s; deleted_storage=$deletedStorage } | ConvertTo-Json -Compress
        return
    }
    if ($vm.Count -ne 1 -or [string]$vm[0].Id -ine %s) { throw 'VM_IDENTITY_MISMATCH: exact VM GUID not found' }
    $notes = [string]$vm[0].Notes
    if (-not $notes.StartsWith(%s, [StringComparison]::Ordinal)) { throw 'VM_METADATA_MISSING' }
    $metadata = $notes.Substring(%s.Length) | ConvertFrom-Json
    if ([string]$metadata.vm_id -cne %s -or [string]$metadata.adapter_id -ine %s) { throw 'VM_IDENTITY_MISMATCH: metadata or adapter changed' }
    $disks = @(Get-VMHardDiskDrive -VM $vm[0] -ErrorAction Stop)
    if ($disks.Count -ne 1 -or [IO.Path]::GetFullPath([string]$disks[0].Path) -cne [IO.Path]::GetFullPath(%s)) {
        throw 'VM_STORAGE_IDENTITY_MISMATCH: exact owned child VHD not attached'
    }
    if ([string]$vm[0].State -ne 'Off') { Stop-VM -VM $vm[0] -TurnOff -Force -ErrorAction Stop }
    Remove-VM -VM $vm[0] -Force -ErrorAction Stop
    $deletedStorage = Remove-LabLinkOwnedVMArtifacts
    [pscustomobject]@{ action='deleted'; vm_id=%s; vm_guid=%s; vhd_path=%s; vm_path=%s; deleted_storage=$deletedStorage } | ConvertTo-Json -Compress
} finally {
    $__isolatedGate.Dispose()
}
`, PSLit(p.OrchestratorVMGUID), PSLit(IsolatedOrchestratorMetadataPrefix),
		PSBool(p.DeleteStorage), PSLit(p.ExpectedVHDPath), PSLit(p.ExpectedVMPath),
		PSLit(p.ExpectedCIDATAPath), PSLit(p.ExpectedOwnership), PSLit(p.VMName),
		PSLit(p.ExpectedVMID), PSLit(p.ExpectedVHDPath),
		PSLit(p.ExpectedVMGUID), PSLit(IsolatedVMMetadataPrefix),
		PSLit(IsolatedVMMetadataPrefix), PSLit(p.ExpectedVMID), PSLit(p.ExpectedAdapterID),
		PSLit(p.ExpectedVHDPath),
		PSLit(p.ExpectedVMID), PSLit(p.ExpectedVMGUID), PSLit(p.ExpectedVHDPath), PSLit(p.ExpectedVMPath))
	return wrapTagged(body), nil
}

func ParseIsolatedVMMutationResult(data string) (IsolatedVMMutationResult, error) {
	var result IsolatedVMMutationResult
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return result, fmt.Errorf("parse isolated VM mutation result: %w", err)
	}
	return result, nil
}
