package hyperv

import (
	"encoding/json"
	"fmt"
	"strings"
)

type CreateIsolatedPrivateSwitchParams struct {
	Guard              IsolatedMutationGuard
	OrchestratorVMGUID string
	Metadata           IsolatedNetworkMetadata
}

type DeleteIsolatedPrivateSwitchParams struct {
	Guard              IsolatedMutationGuard
	OrchestratorVMGUID string
	NetworkID          string
	SwitchName         string
	ExpectedSwitchGUID string
	ExpectedGeneration int64
}

type AttachIsolatedNICParams struct {
	Guard              IsolatedMutationGuard
	NetworkID          string
	ResourceType       string
	ResourceID         string
	OrchestratorVMGUID string
	VMGUID             string
	AdapterName        string
	ExpectedAdapterID  string
	SwitchGUID         string
	MAC                string
	Generation         int64
}

type RemoveIsolatedNICParams struct {
	Guard              IsolatedMutationGuard
	NetworkID          string
	ResourceType       string
	ResourceID         string
	OrchestratorVMGUID string
	VMGUID             string
	AdapterName        string
	ExpectedAdapterID  string
	ExpectedSwitchGUID string
	ExpectedMAC        string
	ExpectedGeneration int64
}

type ReconcileIsolatedAdapterMetadataParams struct {
	Guard              IsolatedMutationGuard
	NetworkID          string
	ResourceType       string
	ResourceID         string
	OrchestratorVMGUID string
	VMGUID             string
	AdapterName        string
	ExpectedAdapterID  string
	SwitchName         string
	ExpectedSwitchGUID string
	ExpectedMAC        string
	ExpectedGeneration int64
}

type CleanupIsolatedNetworkMetadataParams struct {
	Guard              IsolatedMutationGuard
	OrchestratorVMGUID string
	NetworkID          string
	AdapterID          string
	AdapterName        string
	SwitchGUID         string
	SwitchName         string
	MAC                string
	Generation         int64
}

type CleanupIsolatedOrchestratorMetadataParams struct {
	Guard              IsolatedMutationGuard
	OrchestratorVMGUID string
	HyperVName         string
}

type ReconcileStaleIsolatedMetadataParams struct {
	Guard              IsolatedMutationGuard
	OrchestratorVMGUID string
	HyperVName         string
	LifecycleState     string
}

type IsolatedMetadataCleanupResult struct {
	Action          string `json:"action"`
	OrchestratorID  string `json:"orchestrator_id"`
	NetworkID       string `json:"network_id,omitempty"`
	FilesRemoved    int    `json:"files_removed"`
	RootRemoved     bool   `json:"root_removed"`
	MetadataExisted bool   `json:"metadata_existed"`
}

type SetIsolatedParentLifecycleParams struct {
	Guard              IsolatedMutationGuard
	OrchestratorVMGUID string
	ExpectedGeneration int64
	NewGeneration      int64
	NewState           string
	CascadeAuthority   *CascadeAuthority
}

type RebindIsolatedParentFenceParams struct {
	Guard                 IsolatedMutationGuard
	OrchestratorVMGUID    string
	ExpectedPreviousFence int64
	ExpectedGeneration    int64
	PlanRevision          string
	PlanHash              string
}

type IsolatedSwitchMutationResult struct {
	Action       string `json:"action"`
	NetworkID    string `json:"network_id"`
	Name         string `json:"name"`
	SwitchGUID   string `json:"switch_guid"`
	Type         string `json:"type"`
	HostNICCount int    `json:"host_nic_count"`
	Generation   int64  `json:"generation"`
}

type IsolatedAdapterMutationResult struct {
	Action      string `json:"action"`
	ResourceID  string `json:"resource_id"`
	VMGUID      string `json:"vm_guid"`
	AdapterName string `json:"adapter_name"`
	AdapterID   string `json:"adapter_id"`
	SwitchGUID  string `json:"switch_guid"`
	MAC         string `json:"mac"`
	Generation  int64  `json:"generation"`
}

func BuildCreateIsolatedPrivateSwitchScript(p CreateIsolatedPrivateSwitchParams) (string, error) {
	if err := validateMutationGuard(p.Guard); err != nil {
		return "", err
	}
	if p.Guard.ResourceType != "network" || p.Guard.ResourceID != p.Metadata.NetworkID ||
		p.Guard.Action != "create_private_switch" {
		return "", fmt.Errorf("mutation guard does not authorize private switch creation")
	}
	if err := validateGUID("orchestrator VM", p.OrchestratorVMGUID); err != nil {
		return "", err
	}
	if p.Metadata.OrchestratorVMGUID == "" {
		p.Metadata.OrchestratorVMGUID = strings.ToLower(strings.Trim(p.OrchestratorVMGUID, "{}"))
	}
	if p.Metadata.State == "" {
		p.Metadata.State = "creating"
	}
	metadataJSON, err := MarshalIsolatedNetworkMetadata(p.Metadata)
	if err != nil {
		return "", err
	}
	guard, err := isolatedMutationGuardPowerShell(p.Guard)
	if err != nil {
		return "", err
	}
	body := PreflightScript() + isolatedHostMetadataPowerShell() + isolatedParentGuardPowerShell() + guard + fmt.Sprintf(`
try {
    $expected = %s | ConvertFrom-Json
    $orchestratorVMGUID = %s
    $vm = Get-VM -Id $orchestratorVMGUID -ErrorAction Stop
    $parentMetadata = Get-LabLinkIsolatedVMNotes $vm %s
    $cascadeItem = Assert-LabLinkParentAllowsMutation $parentMetadata
    if ([string]$vm.Id -cne $orchestratorVMGUID) { throw 'VM_IDENTITY_MISMATCH: orchestrator VM GUID changed' }

    $recordPath = Get-LabLinkNetworkMetadataPath $guardOrchestratorID $guardResourceID
    $record = Read-LabLinkOwnedMetadata $recordPath
    $switch = Get-VMSwitch -Name ([string]$expected.switch_name) -ErrorAction SilentlyContinue
    if ($record) {
        Assert-LabLinkNetworkRecord $record $expected
    } elseif ($switch) {
        throw "SWITCH_OWNERSHIP_MISMATCH: same-name switch '$($expected.switch_name)' has no exact LabLink ownership record"
    }

    $action = 'created'
    if ($switch) {
        if ([string]$switch.SwitchType -cne 'Private') {
            throw "SWITCH_IDENTITY_MISMATCH: same-name switch is $($switch.SwitchType), expected Private"
        }
        if ($record.switch_guid -and [string]$switch.Id -cne [string]$record.switch_guid) {
            throw 'SWITCH_IDENTITY_MISMATCH: same-name switch was replaced with another GUID'
        }
        $action = if ($record.switch_guid) { 'reused' } else { 'reconciled' }
    } else {
        if ($record -and $record.switch_guid) {
            throw 'SWITCH_IDENTITY_MISMATCH: owned switch GUID is absent; name reuse is not authorized'
        }
        $expected.state = 'creating'
        Write-LabLinkOwnedMetadata $recordPath $expected
        $switch = New-VMSwitch -Name ([string]$expected.switch_name) -SwitchType Private -ErrorAction Stop
    }

    $switch = Get-VMSwitch -Name ([string]$expected.switch_name) -ErrorAction Stop
    if ([string]$switch.SwitchType -cne 'Private') { throw 'PRIVATE_SWITCH_REQUIRED: isolated network switch is not Private' }
    $hostNICs = @(Get-VMNetworkAdapter -ManagementOS -SwitchName $switch.Name -ErrorAction SilentlyContinue)
    if ($hostNICs.Count -ne 0) { throw 'HOST_ADAPTER_PRESENT: a private isolated switch must not expose a management OS adapter' }
    $expected | Add-Member -NotePropertyName switch_guid -NotePropertyValue ([string]$switch.Id) -Force
    $expected.state = 'ready'
    Write-LabLinkOwnedMetadata $recordPath $expected
    [pscustomobject]@{
        action=$action; network_id=$guardResourceID; name=[string]$switch.Name
        switch_guid=[string]$switch.Id; type=[string]$switch.SwitchType
        host_nic_count=$hostNICs.Count; generation=[int64]$expected.generation
    } | ConvertTo-Json -Compress
} finally {
    $__isolatedGate.Dispose()
}
`, PSLit(metadataJSON), PSLit(strings.ToLower(strings.Trim(p.OrchestratorVMGUID, "{}"))),
		PSLit(IsolatedOrchestratorMetadataPrefix))
	return wrapTagged(body), nil
}

func BuildDeleteIsolatedPrivateSwitchScript(p DeleteIsolatedPrivateSwitchParams) (string, error) {
	if err := validateMutationGuard(p.Guard); err != nil {
		return "", err
	}
	if p.Guard.ResourceType != "network" || p.Guard.ResourceID != p.NetworkID ||
		p.Guard.Action != "delete_private_switch" {
		return "", fmt.Errorf("mutation guard does not authorize private switch deletion")
	}
	for kind, value := range map[string]string{
		"orchestrator VM": p.OrchestratorVMGUID,
		"switch":          p.ExpectedSwitchGUID,
	} {
		if err := validateGUID(kind, value); err != nil {
			return "", err
		}
	}
	if p.ExpectedGeneration <= 0 || strings.TrimSpace(p.SwitchName) == "" {
		return "", fmt.Errorf("switch name and expected generation are required")
	}
	guard, err := isolatedMutationGuardPowerShell(p.Guard)
	if err != nil {
		return "", err
	}
	body := PreflightScript() + isolatedHostMetadataPowerShell() + isolatedParentGuardPowerShell() + guard + fmt.Sprintf(`
try {
    $orchestratorVMGUID = %s
    $networkID = %s
    $switchName = %s
    $switchGUID = %s
    $expectedGeneration = [int64]%d
    $vm = Get-VM -Id $orchestratorVMGUID -ErrorAction Stop
    $parentMetadata = Get-LabLinkIsolatedVMNotes $vm %s
    $cascadeItem = Assert-LabLinkParentAllowsMutation $parentMetadata
    if ($cascadeItem -and (
        ([string]$cascadeItem.switch_guid -and [string]$cascadeItem.switch_guid -cne $switchGUID) -or
        [int64]$cascadeItem.generation -ne $expectedGeneration
    )) {
        throw 'CASCADE_AUTHORITY_REJECTED: approved switch identity or generation does not match deletion'
    }
    $recordPath = Get-LabLinkNetworkMetadataPath $guardOrchestratorID $networkID
    $record = Read-LabLinkOwnedMetadata $recordPath
    if (-not $record) { throw 'SWITCH_OWNERSHIP_MISSING: exact network metadata record is required for deletion' }
    if ([string]$record.physical_host_id -cne $guardPhysicalHostID -or
        [string]$record.orchestrator_id -cne $guardOrchestratorID -or
        [string]$record.network_id -cne $networkID -or
        [string]$record.switch_name -cne $switchName -or
        [string]$record.switch_guid -cne $switchGUID -or
        [int64]$record.generation -ne $expectedGeneration) {
        throw 'SWITCH_OWNERSHIP_MISMATCH: network metadata does not match the exact deletion identity'
    }
    $switch = @(Get-VMSwitch -ErrorAction SilentlyContinue | Where-Object { [string]$_.Id -ceq $switchGUID })
    if ($switch.Count -eq 0) {
        $record.state = 'deleted'
        Write-LabLinkOwnedMetadata $recordPath $record
        [pscustomobject]@{
            action='already_absent'; network_id=$networkID; name=$switchName
            switch_guid=$switchGUID; type='Private'; host_nic_count=0; generation=$expectedGeneration
        } | ConvertTo-Json -Compress
        return
    }
    if ($switch.Count -ne 1 -or [string]$switch[0].Name -cne $switchName -or [string]$switch[0].SwitchType -cne 'Private') {
        throw 'SWITCH_IDENTITY_MISMATCH: exact switch GUID has unexpected attributes'
    }
    $connected = @(Get-VMNetworkAdapter -All -ErrorAction SilentlyContinue | Where-Object { [string]$_.SwitchId -ceq $switchGUID })
    if ($connected.Count -ne 0) { throw "SWITCH_IN_USE: exact private switch still has $($connected.Count) VM adapter(s)" }
    $hostNICs = @(Get-VMNetworkAdapter -ManagementOS -SwitchName $switchName -ErrorAction SilentlyContinue)
    if ($hostNICs.Count -ne 0) { throw 'HOST_ADAPTER_PRESENT: refusing to delete a switch with a management OS adapter' }
    $switch[0] | Remove-VMSwitch -Force -ErrorAction Stop
    $record.state = 'deleted'
    Write-LabLinkOwnedMetadata $recordPath $record
    [pscustomobject]@{
        action='deleted'; network_id=$networkID; name=$switchName
        switch_guid=$switchGUID; type='Private'; host_nic_count=0; generation=$expectedGeneration
    } | ConvertTo-Json -Compress
} finally {
    $__isolatedGate.Dispose()
}
`, PSLit(strings.ToLower(strings.Trim(p.OrchestratorVMGUID, "{}"))), PSLit(p.NetworkID),
		PSLit(p.SwitchName), PSLit(strings.ToLower(strings.Trim(p.ExpectedSwitchGUID, "{}"))),
		p.ExpectedGeneration, PSLit(IsolatedOrchestratorMetadataPrefix))
	return wrapTagged(body), nil
}

func BuildAttachIsolatedNICScript(p AttachIsolatedNICParams) (string, error) {
	if err := validateAttachNICParams(p); err != nil {
		return "", err
	}
	guard, err := isolatedMutationGuardPowerShell(p.Guard)
	if err != nil {
		return "", err
	}
	owner, err := IsolatedOwnerMarker(p.Guard.OrchestratorID, p.ResourceType, p.ResourceID)
	if err != nil {
		return "", err
	}
	metadata := IsolatedAdapterMetadata{
		SchemaVersion: IsolatedMetadataSchema, PhysicalHostID: p.Guard.PhysicalHostID,
		OrchestratorID: p.Guard.OrchestratorID, NetworkID: p.NetworkID,
		ResourceID: p.ResourceID, ResourceType: p.ResourceType, OwnerMarker: owner,
		HostFence: p.Guard.Fence, MutationID: p.Guard.MutationID, Generation: p.Generation,
		State: "attaching", VMGUID: strings.ToLower(strings.Trim(p.VMGUID, "{}")),
		AdapterName: p.AdapterName, AdapterID: strings.TrimSpace(p.ExpectedAdapterID),
		MAC: normalizeMAC(p.MAC), SwitchGUID: strings.ToLower(strings.Trim(p.SwitchGUID, "{}")),
	}
	metadataJSON, err := MarshalIsolatedAdapterMetadata(metadata)
	if err != nil {
		return "", err
	}
	body := PreflightScript() + isolatedHostMetadataPowerShell() + isolatedParentGuardPowerShell() + guard + fmt.Sprintf(`
try {
    $expected = %s | ConvertFrom-Json
    $expectedAdapterID = %s
    $orchestratorVMGUID = %s
    $parentVM = Get-VM -Id $orchestratorVMGUID -ErrorAction Stop
    $parentMetadata = Get-LabLinkIsolatedVMNotes $parentVM %s
    $cascadeItem = Assert-LabLinkParentAllowsMutation $parentMetadata
    $vm = Get-VM -Id ([string]$expected.vm_guid) -ErrorAction Stop
    if ([string]$vm.Id -cne $orchestratorVMGUID) {
        $targetMetadata = Get-LabLinkIsolatedVMNotes $vm $null
        if ([string]$targetMetadata.physical_host_id -cne $guardPhysicalHostID -or
            [string]$targetMetadata.orchestrator_id -cne $guardOrchestratorID -or
            [string]$targetMetadata.vm_id -cne [string]$expected.resource_id) {
            throw 'VM_IDENTITY_MISMATCH: target guest metadata does not match the immutable resource'
        }
    }
    $switch = @(Get-VMSwitch -ErrorAction SilentlyContinue | Where-Object { [string]$_.Id -ceq [string]$expected.switch_guid })
    if ($switch.Count -ne 1 -or [string]$switch[0].SwitchType -cne 'Private') {
        throw 'SWITCH_IDENTITY_MISMATCH: exact private switch GUID was not found'
    }
    $recordPath = Get-LabLinkAdapterMetadataPath $guardOrchestratorID ([string]$expected.resource_id)
    $record = Read-LabLinkOwnedMetadata $recordPath
    $adapters = @(Get-VMNetworkAdapter -VM $vm -ErrorAction SilentlyContinue | Where-Object { [string]$_.Name -ceq [string]$expected.adapter_name })
    if ($adapters.Count -gt 1) { throw 'ADAPTER_IDENTITY_AMBIGUOUS: multiple same-name adapters exist' }
    if ($record) {
        Assert-LabLinkAdapterRecord $record $expected
    } elseif ($adapters.Count -ne 0) {
        throw 'ADAPTER_OWNERSHIP_MISMATCH: same-name adapter has no exact LabLink ownership record'
    }
    $action = 'attached'
    if ($adapters.Count -eq 0) {
        if ($record -and $record.adapter_id) {
            throw 'ADAPTER_IDENTITY_MISMATCH: owned adapter ID is absent; replacement by name is not authorized'
        }
        Write-LabLinkOwnedMetadata $recordPath $expected
        $adapter = Add-VMNetworkAdapter -VM $vm -Name ([string]$expected.adapter_name) -SwitchName ([string]$switch[0].Name) -StaticMacAddress ([string]$expected.mac) -Passthru -ErrorAction Stop
    } else {
        $adapter = $adapters[0]
        if ($expectedAdapterID -and [string]$adapter.Id -cne $expectedAdapterID) {
            throw 'ADAPTER_IDENTITY_MISMATCH: same-name adapter was replaced with another adapter ID'
        }
        if ($record.adapter_id -and [string]$adapter.Id -cne [string]$record.adapter_id) {
            throw 'ADAPTER_IDENTITY_MISMATCH: adapter ID does not match its ownership record'
        }
        if (-not $record.adapter_id) {
            $actualMAC = ([string]$adapter.MacAddress).Replace('-','').ToUpperInvariant()
            if ([bool]$adapter.DynamicMacAddressEnabled -or $actualMAC -cne ([string]$expected.mac).ToUpperInvariant()) {
                Remove-VMNetworkAdapter -VMNetworkAdapter $adapter -ErrorAction Stop
                $adapter = Add-VMNetworkAdapter -VM $vm -Name ([string]$expected.adapter_name) -SwitchName ([string]$switch[0].Name) -StaticMacAddress ([string]$expected.mac) -Passthru -ErrorAction Stop
            }
            $action = 'reconciled'
        } else {
            $action = 'reused'
        }
    }
    $adapter = Get-VMNetworkAdapter -VM $vm -Name ([string]$expected.adapter_name) -ErrorAction Stop
    if ([string]$adapter.SwitchId -cne [string]$expected.switch_guid -or
        ([string]$adapter.MacAddress).Replace('-','').ToUpperInvariant() -cne ([string]$expected.mac).ToUpperInvariant() -or
        [bool]$adapter.DynamicMacAddressEnabled) {
        throw 'ADAPTER_IDENTITY_MISMATCH: adapter switch, static MAC, or identity verification failed'
    }
    $expected | Add-Member -NotePropertyName adapter_id -NotePropertyValue ([string]$adapter.Id) -Force
    $expected.state = 'attached'
    Write-LabLinkOwnedMetadata $recordPath $expected
    Set-LabLinkVMAdapterMetadata $vm $expected
    [pscustomobject]@{
        action=$action; resource_id=[string]$expected.resource_id; vm_guid=[string]$vm.Id
        adapter_name=[string]$adapter.Name; adapter_id=[string]$adapter.Id
        switch_guid=[string]$adapter.SwitchId; mac=([string]$adapter.MacAddress).Replace('-','').ToUpperInvariant()
        generation=[int64]$expected.generation
    } | ConvertTo-Json -Compress
} finally {
    $__isolatedGate.Dispose()
}
`, PSLit(metadataJSON), PSLit(strings.TrimSpace(p.ExpectedAdapterID)),
		PSLit(strings.ToLower(strings.Trim(p.OrchestratorVMGUID, "{}"))),
		PSLit(IsolatedOrchestratorMetadataPrefix))
	return wrapTagged(body), nil
}

func BuildRemoveIsolatedNICScript(p RemoveIsolatedNICParams) (string, error) {
	if err := validateRemoveNICParams(p); err != nil {
		return "", err
	}
	guard, err := isolatedMutationGuardPowerShell(p.Guard)
	if err != nil {
		return "", err
	}
	owner, err := IsolatedOwnerMarker(
		p.Guard.OrchestratorID, p.ResourceType, p.ResourceID)
	if err != nil {
		return "", err
	}
	body := PreflightScript() + isolatedHostMetadataPowerShell() + isolatedParentGuardPowerShell() + guard + fmt.Sprintf(`
try {
    $networkID = %s
    $resourceType = %s
    $resourceID = %s
    $orchestratorVMGUID = %s
    $vmGUID = %s
    $adapterName = %s
    $adapterID = %s
    $switchGUID = %s
    $mac = %s
    $ownerMarker = %s
    $expectedGeneration = [int64]%d
    $parentVM = Get-VM -Id $orchestratorVMGUID -ErrorAction Stop
    $parentMetadata = Get-LabLinkIsolatedVMNotes $parentVM %s
    $cascadeItem = Assert-LabLinkParentAllowsMutation $parentMetadata
    if ($cascadeItem -and (
        ([string]$cascadeItem.vm_guid -and [string]$cascadeItem.vm_guid -cne $vmGUID) -or
        ([string]$cascadeItem.adapter_id -and [string]$cascadeItem.adapter_id -cne $adapterID) -or
        [int64]$cascadeItem.generation -ne $expectedGeneration
    )) {
        throw 'CASCADE_AUTHORITY_REJECTED: approved adapter identity or generation does not match removal'
    }
    $vm = Get-VM -Id $vmGUID -ErrorAction Stop
    if ($vmGUID -cne $orchestratorVMGUID) {
        $targetMetadata = Get-LabLinkIsolatedVMNotes $vm $null
        if ([string]$targetMetadata.physical_host_id -cne $guardPhysicalHostID -or
            [string]$targetMetadata.orchestrator_id -cne $guardOrchestratorID -or
            [string]$targetMetadata.vm_id -cne $resourceID) {
            throw 'VM_IDENTITY_MISMATCH: target guest metadata does not match the immutable resource'
        }
    }
    $recordPath = Get-LabLinkAdapterMetadataPath $guardOrchestratorID $resourceID
    $record = Read-LabLinkOwnedMetadata $recordPath
    if (-not $record -or [string]$record.physical_host_id -cne $guardPhysicalHostID -or
        [string]$record.orchestrator_id -cne $guardOrchestratorID -or
        [string]$record.network_id -cne $networkID -or [string]$record.resource_id -cne $resourceID -or
        [string]$record.resource_type -cne $resourceType -or
        [string]$record.owner_marker -cne $ownerMarker -or [string]$record.vm_guid -cne $vmGUID -or
        [string]$record.adapter_name -cne $adapterName -or [string]$record.adapter_id -cne $adapterID -or
        [string]$record.switch_guid -cne $switchGUID -or
        ([string]$record.mac).ToUpperInvariant() -cne $mac -or
        [int64]$record.generation -ne $expectedGeneration) {
        throw 'ADAPTER_OWNERSHIP_MISMATCH: exact adapter metadata is required for deletion'
    }
    $adapter = @(Get-VMNetworkAdapter -VM $vm -ErrorAction SilentlyContinue | Where-Object { [string]$_.Id -ceq $adapterID })
    if ($adapter.Count -eq 0) {
        $record.state = 'deleted'
        Write-LabLinkOwnedMetadata $recordPath $record
        [pscustomobject]@{
            action='already_absent'; resource_id=$resourceID; vm_guid=$vmGUID
            adapter_name=$adapterName; adapter_id=$adapterID; switch_guid=$switchGUID
            mac=$mac; generation=$expectedGeneration
        } | ConvertTo-Json -Compress
        return
    }
    if ($adapter.Count -ne 1 -or [string]$adapter[0].Name -cne $adapterName -or
        [string]$adapter[0].SwitchId -cne $switchGUID -or
        ([string]$adapter[0].MacAddress).Replace('-','').ToUpperInvariant() -cne $mac) {
        throw 'ADAPTER_IDENTITY_MISMATCH: exact adapter ID has unexpected attributes'
    }
    Remove-VMNetworkAdapter -VMNetworkAdapter $adapter[0] -ErrorAction Stop
    $record.state = 'deleted'
    Write-LabLinkOwnedMetadata $recordPath $record
    Remove-LabLinkVMAdapterMetadata $vm $networkID $adapterID
    [pscustomobject]@{
        action='removed'; resource_id=$resourceID; vm_guid=$vmGUID
        adapter_name=$adapterName; adapter_id=$adapterID; switch_guid=$switchGUID
        mac=$mac; generation=$expectedGeneration
    } | ConvertTo-Json -Compress
} finally {
    $__isolatedGate.Dispose()
}
`, PSLit(p.NetworkID), PSLit(p.ResourceType), PSLit(p.ResourceID),
		PSLit(strings.ToLower(strings.Trim(p.OrchestratorVMGUID, "{}"))),
		PSLit(strings.ToLower(strings.Trim(p.VMGUID, "{}"))), PSLit(p.AdapterName),
		PSLit(strings.TrimSpace(p.ExpectedAdapterID)),
		PSLit(strings.ToLower(strings.Trim(p.ExpectedSwitchGUID, "{}"))),
		PSLit(normalizeMAC(p.ExpectedMAC)), PSLit(owner), p.ExpectedGeneration,
		PSLit(IsolatedOrchestratorMetadataPrefix))
	return wrapTagged(body), nil
}

func BuildCleanupIsolatedNetworkMetadataScript(
	p CleanupIsolatedNetworkMetadataParams,
) (string, error) {
	if err := validateMutationGuard(p.Guard); err != nil {
		return "", err
	}
	if p.Guard.ResourceType != "network" || p.Guard.ResourceID != p.NetworkID ||
		p.Guard.Action != "cleanup_network_metadata" {
		return "", fmt.Errorf("mutation guard does not authorize network metadata cleanup")
	}
	if err := validateIsolatedID("network", p.NetworkID); err != nil {
		return "", err
	}
	for kind, value := range map[string]string{
		"orchestrator VM": p.OrchestratorVMGUID,
		"switch":          p.SwitchGUID,
	} {
		if err := validateGUID(kind, value); err != nil {
			return "", err
		}
	}
	if err := validateAdapterID(p.AdapterID); err != nil {
		return "", err
	}
	if p.Generation <= 0 || strings.TrimSpace(p.AdapterName) == "" ||
		strings.TrimSpace(p.SwitchName) == "" || !macRE.MatchString(normalizeMAC(p.MAC)) {
		return "", fmt.Errorf("incomplete network metadata cleanup parameters")
	}
	guard, err := isolatedMutationGuardPowerShell(p.Guard)
	if err != nil {
		return "", err
	}
	networkOwner, err := IsolatedOwnerMarker(p.Guard.OrchestratorID, "network", p.NetworkID)
	if err != nil {
		return "", err
	}
	body := PreflightScript() + isolatedHostMetadataPowerShell() + isolatedParentGuardPowerShell() + guard + fmt.Sprintf(`
try {
    $orchestratorVMGUID = %s
    $networkID = %s
    $adapterID = %s
    $adapterName = %s
    $switchGUID = %s
    $switchName = %s
    $mac = %s
    $generation = [int64]%d
    $networkOwner = %s
    $parentVM = Get-VM -Id $orchestratorVMGUID -ErrorAction Stop
    $parentMetadata = Get-LabLinkIsolatedVMNotes $parentVM %s
    [void](Assert-LabLinkParentAllowsMutation $parentMetadata)

    $switchByID = @(Get-VMSwitch -ErrorAction SilentlyContinue | Where-Object { [string]$_.Id -ceq $switchGUID })
    $switchByName = @(Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue)
    if ($switchByID.Count -ne 0 -or $switchByName.Count -ne 0) {
        throw 'NETWORK_METADATA_CLEANUP_REJECTED: exact switch still exists'
    }
    $adapterByID = @(Get-VMNetworkAdapter -VM $parentVM -ErrorAction SilentlyContinue | Where-Object { [string]$_.Id -ceq $adapterID })
    $adapterByName = @(Get-VMNetworkAdapter -VM $parentVM -ErrorAction SilentlyContinue | Where-Object { [string]$_.Name -ceq $adapterName })
    if ($adapterByID.Count -ne 0 -or $adapterByName.Count -ne 0) {
        throw 'NETWORK_METADATA_CLEANUP_REJECTED: exact adapter still exists'
    }

    $adapterPath = Get-LabLinkAdapterMetadataPath $guardOrchestratorID $networkID
    $networkPath = Get-LabLinkNetworkMetadataPath $guardOrchestratorID $networkID
    $adapterRecord = Read-LabLinkOwnedMetadata $adapterPath
    if ($adapterRecord -and (
        [string]$adapterRecord.physical_host_id -cne $guardPhysicalHostID -or
        [string]$adapterRecord.orchestrator_id -cne $guardOrchestratorID -or
        [string]$adapterRecord.network_id -cne $networkID -or
        [string]$adapterRecord.resource_id -cne $networkID -or
        [string]$adapterRecord.resource_type -cne 'network' -or
        [string]$adapterRecord.owner_marker -cne $networkOwner -or
        [string]$adapterRecord.vm_guid -cne $orchestratorVMGUID -or
        [string]$adapterRecord.adapter_id -cne $adapterID -or
        [string]$adapterRecord.adapter_name -cne $adapterName -or
        [string]$adapterRecord.switch_guid -cne $switchGUID -or
        ([string]$adapterRecord.mac).ToUpperInvariant() -cne $mac -or
        [int64]$adapterRecord.generation -ne $generation -or
        [string]$adapterRecord.state -cne 'deleted'
    )) {
        throw 'NETWORK_METADATA_CLEANUP_REJECTED: adapter ownership metadata is not the exact deleted resource'
    }
    $networkRecord = Read-LabLinkOwnedMetadata $networkPath
    if ($networkRecord -and (
        [string]$networkRecord.physical_host_id -cne $guardPhysicalHostID -or
        [string]$networkRecord.orchestrator_id -cne $guardOrchestratorID -or
        [string]$networkRecord.network_id -cne $networkID -or
        [string]$networkRecord.owner_marker -cne $networkOwner -or
        [string]$networkRecord.switch_guid -cne $switchGUID -or
        [string]$networkRecord.switch_name -cne $switchName -or
        [int64]$networkRecord.generation -ne $generation -or
        [string]$networkRecord.state -cne 'deleted'
    )) {
        throw 'NETWORK_METADATA_CLEANUP_REJECTED: network ownership metadata is not the exact deleted resource'
    }
    $removed = 0
    foreach ($path in @($adapterPath,$networkPath)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
            $removed++
        }
    }
    $root = Get-LabLinkIsolatedRoot $guardOrchestratorID
    foreach ($name in @('adapters','networks')) {
        $directory = Join-Path $root $name
        if ((Test-Path -LiteralPath $directory -PathType Container) -and
            @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop).Count -eq 0) {
            Remove-Item -LiteralPath $directory -Force -ErrorAction Stop
        }
    }
    [pscustomobject]@{
        action='network_metadata_cleaned'; orchestrator_id=$guardOrchestratorID
        network_id=$networkID; files_removed=$removed; root_removed=$false
        metadata_existed=[bool]($adapterRecord -or $networkRecord)
    } | ConvertTo-Json -Compress
} finally {
    $__isolatedGate.Dispose()
}
`, PSLit(strings.ToLower(strings.Trim(p.OrchestratorVMGUID, "{}"))), PSLit(p.NetworkID),
		PSLit(strings.TrimSpace(p.AdapterID)), PSLit(p.AdapterName),
		PSLit(strings.ToLower(strings.Trim(p.SwitchGUID, "{}"))), PSLit(p.SwitchName),
		PSLit(normalizeMAC(p.MAC)), p.Generation, PSLit(networkOwner),
		PSLit(IsolatedOrchestratorMetadataPrefix))
	return wrapTagged(body), nil
}

func BuildCleanupIsolatedOrchestratorMetadataScript(
	p CleanupIsolatedOrchestratorMetadataParams,
) (string, error) {
	if err := validateMutationGuard(p.Guard); err != nil {
		return "", err
	}
	if p.Guard.ResourceType != "orchestrator" ||
		p.Guard.ResourceID != p.Guard.OrchestratorID ||
		p.Guard.Action != "cleanup_orchestrator_metadata" {
		return "", fmt.Errorf("mutation guard does not authorize orchestrator metadata cleanup")
	}
	if err := validateGUID("orchestrator VM", p.OrchestratorVMGUID); err != nil {
		return "", err
	}
	if strings.TrimSpace(p.HyperVName) == "" {
		return "", fmt.Errorf("orchestrator Hyper-V name is required")
	}
	guard, err := isolatedMutationGuardPowerShell(p.Guard)
	if err != nil {
		return "", err
	}
	body := PreflightScript() + isolatedHostMetadataPowerShell() + guard + fmt.Sprintf(`
try {
    $orchestratorVMGUID = %s
    $hyperVName = %s
    if (@(Get-VM -Id $orchestratorVMGUID -ErrorAction SilentlyContinue).Count -ne 0 -or
        @(Get-VM -Name $hyperVName -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'ORCHESTRATOR_METADATA_CLEANUP_REJECTED: exact orchestrator VM still exists'
    }
    $root = Get-LabLinkIsolatedRoot $guardOrchestratorID
    $existed = Test-Path -LiteralPath $root -PathType Container
    if ($existed) {
        $files = @(Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction Stop)
        if ($files.Count -ne 0) {
            throw "ORCHESTRATOR_METADATA_NOT_EMPTY: exact metadata root still contains $($files.Count) file(s)"
        }
        $directories = @(Get-ChildItem -LiteralPath $root -Directory -Recurse -Force -ErrorAction Stop |
            Sort-Object { $_.FullName.Length } -Descending)
        foreach ($directory in $directories) {
            if (@(Get-ChildItem -LiteralPath $directory.FullName -Force -ErrorAction Stop).Count -eq 0) {
                Remove-Item -LiteralPath $directory.FullName -Force -ErrorAction Stop
            }
        }
        if (@(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop).Count -ne 0) {
            throw 'ORCHESTRATOR_METADATA_NOT_EMPTY: exact metadata root contains unexpected entries'
        }
        Remove-Item -LiteralPath $root -Force -ErrorAction Stop
    }
    [pscustomobject]@{
        action='orchestrator_metadata_cleaned'; orchestrator_id=$guardOrchestratorID
        files_removed=0; root_removed=$existed; metadata_existed=$existed
    } | ConvertTo-Json -Compress
} finally {
    $__isolatedGate.Dispose()
}
`, PSLit(strings.ToLower(strings.Trim(p.OrchestratorVMGUID, "{}"))), PSLit(p.HyperVName))
	return wrapTagged(body), nil
}

func BuildReconcileStaleIsolatedMetadataScript(
	p ReconcileStaleIsolatedMetadataParams,
) (string, error) {
	if err := validateMutationGuard(p.Guard); err != nil {
		return "", err
	}
	if p.Guard.ResourceType != "orchestrator" ||
		p.Guard.ResourceID != p.Guard.OrchestratorID ||
		p.Guard.Action != "reconcile_stale_orchestrator_metadata" {
		return "", fmt.Errorf("mutation guard does not authorize stale orchestrator metadata reconciliation")
	}
	if err := validateGUID("orchestrator VM", p.OrchestratorVMGUID); err != nil {
		return "", err
	}
	if strings.TrimSpace(p.HyperVName) == "" {
		return "", fmt.Errorf("orchestrator Hyper-V name is required")
	}
	state := strings.ToLower(strings.TrimSpace(p.LifecycleState))
	if state != "deleted" && state != "lost" {
		return "", fmt.Errorf("stale metadata reconciliation requires deleted or lost lifecycle state")
	}
	guard, err := isolatedMutationGuardPowerShell(p.Guard)
	if err != nil {
		return "", err
	}
	body := PreflightScript() + isolatedHostMetadataPowerShell() + guard + fmt.Sprintf(`
try {
    $orchestratorVMGUID = %s
    $hyperVName = %s
    if (@(Get-VM -Id $orchestratorVMGUID -ErrorAction SilentlyContinue).Count -ne 0 -or
        @(Get-VM -Name $hyperVName -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'STALE_METADATA_RESOURCE_PRESENT: deleted orchestrator VM identity still exists'
    }
    $root = Get-LabLinkIsolatedRoot $guardOrchestratorID
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        [pscustomobject]@{
            action='stale_metadata_absent'; orchestrator_id=$guardOrchestratorID
            files_removed=0; root_removed=$false; metadata_existed=$false
        } | ConvertTo-Json -Compress
        return
    }
    $networkDirectory = Join-Path $root 'networks'
    $adapterDirectory = Join-Path $root 'adapters'
    $uuidBody = '[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'
    $uuidPattern = '^' + $uuidBody + '$'
    $adapterIDPattern = '^(' + $uuidBody + '|microsoft:' + $uuidBody + '\\' + $uuidBody + ')$'
    $allFiles = @(Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction Stop)
    $validatedFiles = @()
    foreach ($file in $allFiles) {
        $parent = [IO.Path]::GetFullPath([string]$file.DirectoryName).TrimEnd('\')
        $networkParent = [IO.Path]::GetFullPath($networkDirectory).TrimEnd('\')
        $adapterParent = [IO.Path]::GetFullPath($adapterDirectory).TrimEnd('\')
        if ([string]$file.Extension -cne '.json' -or ($parent -cne $networkParent -and $parent -cne $adapterParent)) {
            throw "STALE_METADATA_AMBIGUOUS: unexpected metadata file $($file.FullName)"
        }
        $record = Get-Content -Raw -LiteralPath $file.FullName -ErrorAction Stop | ConvertFrom-Json
        if ([string]$record.physical_host_id -cne $guardPhysicalHostID -or
            [string]$record.orchestrator_id -cne $guardOrchestratorID) {
            throw "STALE_METADATA_OWNERSHIP_MISMATCH: $($file.FullName)"
        }
        if ($parent -ceq $networkParent) {
            $networkID = [string]$record.network_id
            if ($networkID -cnotmatch $uuidPattern -or
                [string]$record.switch_guid -cnotmatch $uuidPattern -or
                [string]::IsNullOrWhiteSpace([string]$record.switch_name) -or
                [string]$file.BaseName -cne $networkID -or
                [string]$record.owner_marker -cne ('lablink-isolated/' + $guardOrchestratorID + '/network/' + $networkID)) {
                throw "STALE_METADATA_OWNERSHIP_MISMATCH: $($file.FullName)"
            }
            if (@(Get-VMSwitch -ErrorAction SilentlyContinue | Where-Object {
                [string]$_.Id -ceq [string]$record.switch_guid -or [string]$_.Name -ceq [string]$record.switch_name
            }).Count -ne 0) {
                throw "STALE_METADATA_RESOURCE_PRESENT: network $networkID still has a switch"
            }
        } else {
            $resourceID = [string]$record.resource_id
            $resourceType = [string]$record.resource_type
            if ($resourceID -cnotmatch $uuidPattern -or
                [string]$record.network_id -cnotmatch $uuidPattern -or
                [string]$record.vm_guid -cnotmatch $uuidPattern -or
                [string]$record.adapter_id -notmatch $adapterIDPattern -or
                [string]$record.switch_guid -cnotmatch $uuidPattern -or
                [string]::IsNullOrWhiteSpace([string]$record.adapter_name) -or
                [string]$record.mac -notmatch '^[0-9A-Fa-f]{12}$' -or
                [string]$file.BaseName -cne $resourceID -or
                ($resourceType -cne 'network' -and $resourceType -cne 'vm') -or
                [string]$record.owner_marker -cne ('lablink-isolated/' + $guardOrchestratorID + '/' + $resourceType + '/' + $resourceID)) {
                throw "STALE_METADATA_OWNERSHIP_MISMATCH: $($file.FullName)"
            }
            if (@(Get-VM -Id ([string]$record.vm_guid) -ErrorAction SilentlyContinue).Count -ne 0) {
                throw "STALE_METADATA_RESOURCE_PRESENT: adapter owner VM $([string]$record.vm_guid) still exists"
            }
            if (@(Get-VMSwitch -ErrorAction SilentlyContinue | Where-Object {
                [string]$_.Id -ceq [string]$record.switch_guid
            }).Count -ne 0) {
                throw "STALE_METADATA_RESOURCE_PRESENT: adapter switch $([string]$record.switch_guid) still exists"
            }
        }
        $validatedFiles += $file.FullName
    }
    foreach ($path in $validatedFiles) {
        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
    }
    $directories = @(Get-ChildItem -LiteralPath $root -Directory -Recurse -Force -ErrorAction Stop |
        Sort-Object { $_.FullName.Length } -Descending)
    foreach ($directory in $directories) {
        if (@(Get-ChildItem -LiteralPath $directory.FullName -Force -ErrorAction Stop).Count -eq 0) {
            Remove-Item -LiteralPath $directory.FullName -Force -ErrorAction Stop
        }
    }
    if (@(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop).Count -ne 0) {
        throw 'STALE_METADATA_AMBIGUOUS: exact metadata root contains unexpected entries'
    }
    Remove-Item -LiteralPath $root -Force -ErrorAction Stop
    [pscustomobject]@{
        action='stale_metadata_cleaned'; orchestrator_id=$guardOrchestratorID
        files_removed=$validatedFiles.Count; root_removed=$true; metadata_existed=$true
    } | ConvertTo-Json -Compress
} finally {
    $__isolatedGate.Dispose()
}
`, PSLit(strings.ToLower(strings.Trim(p.OrchestratorVMGUID, "{}"))), PSLit(p.HyperVName))
	return wrapTagged(body), nil
}

func BuildReconcileIsolatedAdapterMetadataScript(
	p ReconcileIsolatedAdapterMetadataParams,
) (string, error) {
	if err := validateReconcileAdapterMetadataParams(p); err != nil {
		return "", err
	}
	guard, err := isolatedMutationGuardPowerShell(p.Guard)
	if err != nil {
		return "", err
	}
	owner, err := IsolatedOwnerMarker(p.Guard.OrchestratorID, p.ResourceType, p.ResourceID)
	if err != nil {
		return "", err
	}
	metadata := IsolatedAdapterMetadata{
		SchemaVersion: IsolatedMetadataSchema, PhysicalHostID: p.Guard.PhysicalHostID,
		OrchestratorID: p.Guard.OrchestratorID, NetworkID: p.NetworkID,
		ResourceID: p.ResourceID, ResourceType: p.ResourceType, OwnerMarker: owner,
		HostFence: p.Guard.Fence, MutationID: p.Guard.MutationID,
		Generation: p.ExpectedGeneration, State: "attached",
		VMGUID:      strings.ToLower(strings.Trim(p.VMGUID, "{}")),
		AdapterName: p.AdapterName, AdapterID: strings.TrimSpace(p.ExpectedAdapterID),
		MAC:        normalizeMAC(p.ExpectedMAC),
		SwitchGUID: strings.ToLower(strings.Trim(p.ExpectedSwitchGUID, "{}")),
	}
	metadataJSON, err := MarshalIsolatedAdapterMetadata(metadata)
	if err != nil {
		return "", err
	}
	body := PreflightScript() + isolatedHostMetadataPowerShell() + isolatedParentGuardPowerShell() + guard + fmt.Sprintf(`
try {
    $expected = %s | ConvertFrom-Json
    $orchestratorVMGUID = %s
    $switchName = %s
    $parentVM = Get-VM -Id $orchestratorVMGUID -ErrorAction Stop
    $parentMetadata = Get-LabLinkIsolatedVMNotes $parentVM %s
    $cascadeItem = Assert-LabLinkParentAllowsMutation $parentMetadata
    if ([string]$parentVM.Id -cne [string]$expected.vm_guid) {
        throw 'VM_IDENTITY_MISMATCH: adapter target is not the exact orchestrator VM'
    }

    $networkPath = Get-LabLinkNetworkMetadataPath $guardOrchestratorID ([string]$expected.network_id)
    $networkRecord = Read-LabLinkOwnedMetadata $networkPath
    if (-not $networkRecord -or
        [string]$networkRecord.physical_host_id -cne $guardPhysicalHostID -or
        [string]$networkRecord.orchestrator_id -cne $guardOrchestratorID -or
        [string]$networkRecord.network_id -cne [string]$expected.network_id -or
        [string]$networkRecord.owner_marker -cne [string]$expected.owner_marker -or
        [string]$networkRecord.switch_name -cne $switchName -or
        [string]$networkRecord.switch_guid -cne [string]$expected.switch_guid -or
        [string]$networkRecord.orchestrator_vm_guid -cne $orchestratorVMGUID -or
        [int64]$networkRecord.generation -ne [int64]$expected.generation) {
        throw 'ADAPTER_ADOPTION_REJECTED: exact network ownership record does not match'
    }

    $switch = @(Get-VMSwitch -ErrorAction SilentlyContinue | Where-Object {
        [string]$_.Id -ceq [string]$expected.switch_guid
    })
    if ($switch.Count -ne 1 -or [string]$switch[0].Name -cne $switchName -or
        [string]$switch[0].SwitchType -cne 'Private') {
        throw 'ADAPTER_ADOPTION_REJECTED: exact private switch identity is missing or ambiguous'
    }

    $byID = @(Get-VMNetworkAdapter -VM $parentVM -ErrorAction SilentlyContinue | Where-Object {
        [string]$_.Id -ceq [string]$expected.adapter_id
    })
    $byName = @(Get-VMNetworkAdapter -VM $parentVM -ErrorAction SilentlyContinue | Where-Object {
        [string]$_.Name -ceq [string]$expected.adapter_name
    })
    $byMAC = @(Get-VMNetworkAdapter -VM $parentVM -ErrorAction SilentlyContinue | Where-Object {
        ([string]$_.MacAddress).Replace('-','').ToUpperInvariant() -ceq ([string]$expected.mac).ToUpperInvariant()
    })
    if ($byID.Count -ne 1 -or $byName.Count -ne 1 -or $byMAC.Count -ne 1 -or
        [string]$byName[0].Id -cne [string]$expected.adapter_id -or
        [string]$byMAC[0].Id -cne [string]$expected.adapter_id) {
        throw 'ADAPTER_ADOPTION_REJECTED: exact adapter ID/name/MAC is missing or ambiguous'
    }
    $adapter = $byID[0]
    if ([string]$adapter.Name -cne [string]$expected.adapter_name -or
        [string]$adapter.SwitchId -cne [string]$expected.switch_guid -or
        ([string]$adapter.MacAddress).Replace('-','').ToUpperInvariant() -cne ([string]$expected.mac).ToUpperInvariant() -or
        [bool]$adapter.DynamicMacAddressEnabled) {
        throw 'ADAPTER_ADOPTION_REJECTED: adapter switch, static MAC, or immutable identity differs'
    }

    $refs = @($parentMetadata.private_adapters | Where-Object {
        [string]$_.network_id -ceq [string]$expected.network_id
    })
    if ($refs.Count -gt 1) {
        throw 'ADAPTER_ADOPTION_REJECTED: parent metadata has ambiguous network adapter references'
    }
    if ($refs.Count -eq 1 -and (
        [string]$refs[0].adapter_id -cne [string]$expected.adapter_id -or
        [string]$refs[0].switch_guid -cne [string]$expected.switch_guid -or
        ([string]$refs[0].mac).ToUpperInvariant() -cne ([string]$expected.mac).ToUpperInvariant()
    )) {
        throw 'ADAPTER_ADOPTION_REJECTED: parent metadata has foreign adapter identity'
    }

    $recordPath = Get-LabLinkAdapterMetadataPath $guardOrchestratorID ([string]$expected.resource_id)
    $record = Read-LabLinkOwnedMetadata $recordPath
    $action = 'adopted'
    if ($record) {
        Assert-LabLinkAdapterIdentity $record $expected
        if ([string]$record.adapter_id -cne [string]$expected.adapter_id -or
            [string]$record.owner_marker -cne [string]$expected.owner_marker) {
            throw 'ADAPTER_ADOPTION_REJECTED: existing adapter ownership record conflicts'
        }
        $action = 'reused'
    } else {
        Write-LabLinkOwnedMetadata $recordPath $expected
    }
    Set-LabLinkVMAdapterMetadata $parentVM $expected
    [pscustomobject]@{
        action=$action; resource_id=[string]$expected.resource_id
        vm_guid=[string]$parentVM.Id; adapter_name=[string]$adapter.Name
        adapter_id=[string]$adapter.Id; switch_guid=[string]$adapter.SwitchId
        mac=([string]$adapter.MacAddress).Replace('-','').ToUpperInvariant()
        generation=[int64]$expected.generation
    } | ConvertTo-Json -Compress
} finally {
    $__isolatedGate.Dispose()
}
`, PSLit(metadataJSON), PSLit(strings.ToLower(strings.Trim(p.OrchestratorVMGUID, "{}"))),
		PSLit(p.SwitchName), PSLit(IsolatedOrchestratorMetadataPrefix))
	return wrapTagged(body), nil
}

func BuildSetIsolatedParentLifecycleScript(p SetIsolatedParentLifecycleParams) (string, error) {
	if err := validateMutationGuard(p.Guard); err != nil {
		return "", err
	}
	if p.Guard.ResourceType != "orchestrator" || p.Guard.ResourceID != p.Guard.OrchestratorID ||
		p.Guard.Action != "set_parent_lifecycle" {
		return "", fmt.Errorf("mutation guard does not authorize parent lifecycle change")
	}
	if err := validateGUID("orchestrator VM", p.OrchestratorVMGUID); err != nil {
		return "", err
	}
	if p.NewState != "frozen" && p.NewState != "deleting" {
		return "", fmt.Errorf("parent lifecycle may only transition to frozen or deleting")
	}
	if p.ExpectedGeneration <= 0 || p.NewGeneration != p.ExpectedGeneration+1 {
		return "", fmt.Errorf("new generation must equal expected generation plus one")
	}
	if err := validateCascadeAuthority(p.CascadeAuthority); err != nil {
		return "", err
	}
	if p.CascadeAuthority == nil {
		return "", fmt.Errorf("cascade authority is required for parent freeze/deletion")
	}
	if p.CascadeAuthority.OrchestratorID != p.Guard.OrchestratorID ||
		p.CascadeAuthority.OperationID != p.Guard.OperationID ||
		p.CascadeAuthority.LeaseID != p.Guard.LeaseID ||
		p.CascadeAuthority.HostFence != p.Guard.Fence ||
		p.CascadeAuthority.FrozenGeneration != p.NewGeneration {
		return "", fmt.Errorf("cascade authority does not match the mutation lease and operation")
	}
	cascadeJSON, _ := json.Marshal(p.CascadeAuthority)
	guard, err := isolatedMutationGuardPowerShell(p.Guard)
	if err != nil {
		return "", err
	}
	body := PreflightScript() + isolatedHostMetadataPowerShell() + guard + fmt.Sprintf(`
try {
    $vm = Get-VM -Id %s -ErrorAction Stop
    $metadata = Get-LabLinkIsolatedVMNotes $vm %s
    if ([string]$metadata.physical_host_id -cne $guardPhysicalHostID -or
        [string]$metadata.orchestrator_id -cne $guardOrchestratorID) {
        throw 'PARENT_IDENTITY_MISMATCH: orchestrator identity changed'
    }
    $fresh = [int64]$metadata.generation -eq [int64]%d -and
        [string]$metadata.lifecycle_state -notin @('frozen','deleting','lost','deleted')
    $replay = [int64]$metadata.generation -eq [int64]%d -and
        [string]$metadata.lifecycle_state -eq %s -and
        $metadata.cascade_authority -and
        [string]$metadata.cascade_authority.plan_revision -ceq %s -and
        [string]$metadata.cascade_authority.plan_hash -ceq %s
    if (-not $fresh -and -not $replay) {
        throw 'PARENT_IDENTITY_MISMATCH: orchestrator lifecycle or generation changed'
    }
    if ([int64]$metadata.host_fence -gt $guardFence) {
        throw 'FENCE_REJECTED: parent metadata has a newer fence'
    }
    $metadata.host_fence = $guardFence
    $metadata.lifecycle_state = %s
    $metadata.generation = [int64]%d
    $metadata.cascade_authority = %s | ConvertFrom-Json
    Set-VM -VM $vm -Notes (%s + ($metadata | ConvertTo-Json -Depth 20 -Compress)) -ErrorAction Stop
    [pscustomobject]@{
        status='parent_frozen'; orchestrator_id=$guardOrchestratorID
        lifecycle_state=[string]$metadata.lifecycle_state; generation=[int64]$metadata.generation
        fence=$guardFence; plan_revision=[string]$metadata.cascade_authority.plan_revision
    } | ConvertTo-Json -Compress
} finally {
    $__isolatedGate.Dispose()
}
`, PSLit(strings.ToLower(strings.Trim(p.OrchestratorVMGUID, "{}"))),
		PSLit(IsolatedOrchestratorMetadataPrefix), p.ExpectedGeneration,
		p.NewGeneration, PSLit(p.NewState), PSLit(p.CascadeAuthority.PlanRevision),
		PSLit(p.CascadeAuthority.PlanHash), PSLit(p.NewState), p.NewGeneration,
		PSLit(string(cascadeJSON)), PSLit(IsolatedOrchestratorMetadataPrefix))
	return wrapTagged(body), nil
}

// BuildRebindIsolatedParentFenceScript installs a reclaimed host lease/fence
// in the exact orchestrator VM metadata. Frozen/deleting parents retain their
// unchanged approved enumeration while its lease and fence are rebound.
func BuildRebindIsolatedParentFenceScript(p RebindIsolatedParentFenceParams) (string, error) {
	if err := validateMutationGuard(p.Guard); err != nil {
		return "", err
	}
	if p.Guard.ResourceType != "orchestrator" || p.Guard.ResourceID != p.Guard.OrchestratorID ||
		p.Guard.Action != "rebind_parent_fence" {
		return "", fmt.Errorf("mutation guard does not authorize parent fence rebind")
	}
	if err := validateGUID("orchestrator VM", p.OrchestratorVMGUID); err != nil {
		return "", err
	}
	if p.ExpectedPreviousFence <= 0 || p.Guard.Fence <= p.ExpectedPreviousFence || p.ExpectedGeneration <= 0 {
		return "", fmt.Errorf("fence rebind requires an increasing fence and positive generation")
	}
	guard, err := isolatedMutationGuardPowerShell(p.Guard)
	if err != nil {
		return "", err
	}
	body := PreflightScript() + isolatedHostMetadataPowerShell() + guard + fmt.Sprintf(`
try {
    $vm = Get-VM -Id %s -ErrorAction Stop
    $metadata = Get-LabLinkIsolatedVMNotes $vm %s
    if ([string]$metadata.physical_host_id -cne $guardPhysicalHostID -or
        [string]$metadata.orchestrator_id -cne $guardOrchestratorID -or
        [int64]$metadata.host_fence -ne [int64]%d -or
        [int64]$metadata.generation -ne [int64]%d) {
        throw 'PARENT_IDENTITY_MISMATCH: orchestrator identity, previous fence, or generation changed'
    }
    $state = [string]$metadata.lifecycle_state
    if ($state -in @('lost','deleted')) { throw "PARENT_FROZEN: orchestrator is $state" }
    if ($state -in @('frozen','deleting')) {
        $authority = $metadata.cascade_authority
        if (-not $authority -or
            [string]$authority.operation_id -cne $guardOperationID -or
            [string]$authority.plan_revision -cne %s -or
            [string]$authority.plan_hash -cne %s) {
            throw 'CASCADE_AUTHORITY_REJECTED: interrupted cascade revision changed during fence rebind'
        }
        $authority.lease_id = $guardLeaseID
        $authority.host_fence = $guardFence
        $metadata.cascade_authority = $authority
    }
    $metadata.host_fence = $guardFence
    Set-VM -VM $vm -Notes (%s + ($metadata | ConvertTo-Json -Depth 20 -Compress)) -ErrorAction Stop
    [pscustomobject]@{
        status='parent_fence_rebound'; orchestrator_id=$guardOrchestratorID
        previous_fence=[int64]%d; fence=$guardFence; lifecycle_state=$state
        generation=[int64]$metadata.generation
    } | ConvertTo-Json -Compress
} finally {
    $__isolatedGate.Dispose()
}
`, PSLit(strings.ToLower(strings.Trim(p.OrchestratorVMGUID, "{}"))),
		PSLit(IsolatedOrchestratorMetadataPrefix), p.ExpectedPreviousFence,
		p.ExpectedGeneration, PSLit(p.PlanRevision), PSLit(p.PlanHash),
		PSLit(IsolatedOrchestratorMetadataPrefix), p.ExpectedPreviousFence)
	return wrapTagged(body), nil
}

func ParseIsolatedSwitchMutationResult(text string) (IsolatedSwitchMutationResult, error) {
	var result IsolatedSwitchMutationResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(extractJSON(text))), &result); err != nil {
		return result, err
	}
	return result, nil
}

func ParseIsolatedAdapterMutationResult(text string) (IsolatedAdapterMutationResult, error) {
	var result IsolatedAdapterMutationResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(extractJSON(text))), &result); err != nil {
		return result, err
	}
	return result, nil
}

func ParseIsolatedMetadataCleanupResult(text string) (IsolatedMetadataCleanupResult, error) {
	var result IsolatedMetadataCleanupResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(extractJSON(text))), &result); err != nil {
		return result, err
	}
	return result, nil
}

func validateAttachNICParams(p AttachIsolatedNICParams) error {
	if err := validateMutationGuard(p.Guard); err != nil {
		return err
	}
	if p.Guard.ResourceType != p.ResourceType || p.Guard.ResourceID != p.ResourceID ||
		p.Guard.Action != "attach_nic" {
		return fmt.Errorf("mutation guard does not authorize NIC attachment")
	}
	for kind, value := range map[string]string{
		"network": p.NetworkID, "resource": p.ResourceID,
	} {
		if err := validateIsolatedID(kind, value); err != nil {
			return err
		}
	}
	for kind, value := range map[string]string{
		"orchestrator VM": p.OrchestratorVMGUID, "VM": p.VMGUID, "switch": p.SwitchGUID,
	} {
		if err := validateGUID(kind, value); err != nil {
			return err
		}
	}
	if p.ExpectedAdapterID != "" {
		if err := validateAdapterID(p.ExpectedAdapterID); err != nil {
			return err
		}
	}
	if p.Generation <= 0 || strings.TrimSpace(p.AdapterName) == "" || !macRE.MatchString(normalizeMAC(p.MAC)) {
		return fmt.Errorf("incomplete isolated NIC attachment parameters")
	}
	return nil
}

func validateRemoveNICParams(p RemoveIsolatedNICParams) error {
	if err := validateMutationGuard(p.Guard); err != nil {
		return err
	}
	if p.Guard.ResourceType != p.ResourceType || p.Guard.ResourceID != p.ResourceID ||
		p.Guard.Action != "remove_nic" {
		return fmt.Errorf("mutation guard does not authorize NIC removal")
	}
	for kind, value := range map[string]string{"network": p.NetworkID, "resource": p.ResourceID} {
		if err := validateIsolatedID(kind, value); err != nil {
			return err
		}
	}
	for kind, value := range map[string]string{
		"orchestrator VM": p.OrchestratorVMGUID, "VM": p.VMGUID,
		"switch": p.ExpectedSwitchGUID,
	} {
		if err := validateGUID(kind, value); err != nil {
			return err
		}
	}
	if err := validateAdapterID(p.ExpectedAdapterID); err != nil {
		return err
	}
	if p.ExpectedGeneration <= 0 || strings.TrimSpace(p.AdapterName) == "" ||
		!macRE.MatchString(normalizeMAC(p.ExpectedMAC)) {
		return fmt.Errorf("incomplete isolated NIC removal parameters")
	}
	return nil
}

func validateReconcileAdapterMetadataParams(
	p ReconcileIsolatedAdapterMetadataParams,
) error {
	if err := validateMutationGuard(p.Guard); err != nil {
		return err
	}
	if p.Guard.ResourceType != p.ResourceType ||
		p.Guard.ResourceID != p.ResourceID ||
		p.Guard.Action != "reconcile_adapter_metadata" {
		return fmt.Errorf("mutation guard does not authorize adapter metadata reconciliation")
	}
	for kind, value := range map[string]string{
		"network": p.NetworkID, "resource": p.ResourceID,
	} {
		if err := validateIsolatedID(kind, value); err != nil {
			return err
		}
	}
	for kind, value := range map[string]string{
		"orchestrator VM": p.OrchestratorVMGUID,
		"VM":              p.VMGUID,
		"switch":          p.ExpectedSwitchGUID,
	} {
		if err := validateGUID(kind, value); err != nil {
			return err
		}
	}
	if err := validateAdapterID(p.ExpectedAdapterID); err != nil {
		return err
	}
	if p.ExpectedGeneration <= 0 ||
		strings.TrimSpace(p.AdapterName) == "" ||
		strings.TrimSpace(p.SwitchName) == "" ||
		!macRE.MatchString(normalizeMAC(p.ExpectedMAC)) {
		return fmt.Errorf("incomplete adapter metadata reconciliation parameters")
	}
	return nil
}

func normalizeMAC(value string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", ":", "", ".", "").Replace(strings.TrimSpace(value)))
}

func normalizedGUIDOrEmpty(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return strings.ToLower(strings.Trim(strings.TrimSpace(value), "{}"))
}

func isolatedHostMetadataPowerShell() string {
	return `
function Get-LabLinkIsolatedRoot([string]$OrchestratorID) {
    return Join-Path $env:ProgramData ('LabLink\isolated\' + $OrchestratorID)
}
function Get-LabLinkNetworkMetadataPath([string]$OrchestratorID,[string]$NetworkID) {
    return Join-Path (Join-Path (Get-LabLinkIsolatedRoot $OrchestratorID) 'networks') ($NetworkID + '.json')
}
function Get-LabLinkAdapterMetadataPath([string]$OrchestratorID,[string]$ResourceID) {
    return Join-Path (Join-Path (Get-LabLinkIsolatedRoot $OrchestratorID) 'adapters') ($ResourceID + '.json')
}
function Set-LabLinkOwnedMetadataACL([string]$Path) {
    $inherit = & icacls.exe $Path /inheritance:r 2>&1
    if ($LASTEXITCODE -ne 0) { throw "METADATA_ACL_FAILED: $inherit" }
    $grant = & icacls.exe $Path /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "METADATA_ACL_FAILED: $grant" }
}
function Read-LabLinkOwnedMetadata([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return Get-Content -Raw -LiteralPath $Path -ErrorAction Stop | ConvertFrom-Json
}
function Write-LabLinkOwnedMetadata([string]$Path,$Value) {
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    Set-LabLinkOwnedMetadataACL $parent
    $temporary = $Path + '.new'
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 20 -Compress))
    $stream = [IO.FileStream]::new($temporary,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    Set-LabLinkOwnedMetadataACL $temporary
    Move-Item -LiteralPath $temporary -Destination $Path -Force
    Set-LabLinkOwnedMetadataACL $Path
}
function Get-LabLinkIsolatedVMNotes($VM,[string]$RequiredPrefix) {
    $notes = [string]$VM.Notes
    $prefix = $RequiredPrefix
    if (-not $prefix) {
        if ($notes.StartsWith('LABLINK_ISOLATED_ORCHESTRATOR:',[StringComparison]::Ordinal)) {
            $prefix = 'LABLINK_ISOLATED_ORCHESTRATOR:'
        } elseif ($notes.StartsWith('LABLINK_ISOLATED_VM:',[StringComparison]::Ordinal)) {
            $prefix = 'LABLINK_ISOLATED_VM:'
        } else {
            throw 'VM_MANAGED_METADATA_MISSING: VM has no isolated LabLink metadata'
        }
    }
    if (-not $notes.StartsWith($prefix,[StringComparison]::Ordinal)) {
        throw 'VM_MANAGED_METADATA_MISMATCH: VM metadata prefix is not the expected isolated resource type'
    }
    return $notes.Substring($prefix.Length) | ConvertFrom-Json
}
function Assert-LabLinkNetworkRecord($Record,$Expected) {
    foreach ($property in @(
        'schema_version','physical_host_id','orchestrator_id','network_id','owner_marker',
        'mutation_id','generation','switch_name','orchestrator_vm_guid'
    )) {
        if ([string]$Record.$property -cne [string]$Expected.$property) {
            throw "SWITCH_OWNERSHIP_MISMATCH: network metadata property '$property' changed"
        }
    }
    if ([int64]$Record.host_fence -gt [int64]$Expected.host_fence) {
        throw "FENCE_REJECTED: network metadata fence is newer than the current fence"
    }
}
function Assert-LabLinkAdapterRecord($Record,$Expected) {
    foreach ($property in @(
        'schema_version','physical_host_id','orchestrator_id','network_id','resource_id',
        'resource_type','owner_marker','mutation_id','generation','vm_guid',
        'adapter_name','mac','switch_guid'
    )) {
        if ([string]$Record.$property -cne [string]$Expected.$property) {
            throw "ADAPTER_OWNERSHIP_MISMATCH: adapter metadata property '$property' changed"
        }
    }
    if ([int64]$Record.host_fence -gt [int64]$Expected.host_fence) {
        throw "FENCE_REJECTED: adapter metadata fence is newer than the current fence"
    }
}
function Assert-LabLinkAdapterIdentity($Record,$Expected) {
    foreach ($property in @(
        'schema_version','physical_host_id','orchestrator_id','network_id','resource_id',
        'resource_type','owner_marker','generation','vm_guid',
        'adapter_name','mac','switch_guid'
    )) {
        if ([string]$Record.$property -cne [string]$Expected.$property) {
            throw "ADAPTER_OWNERSHIP_MISMATCH: adapter metadata property '$property' changed"
        }
    }
    if ([int64]$Record.host_fence -gt [int64]$Expected.host_fence) {
        throw "FENCE_REJECTED: adapter metadata fence is newer than the current fence"
    }
}
function Set-LabLinkVMAdapterMetadata($VM,$AdapterRecord) {
    $notes = [string]$VM.Notes
    $isGuest = $false
    $prefix = if ($notes.StartsWith('LABLINK_ISOLATED_ORCHESTRATOR:',[StringComparison]::Ordinal)) {
        'LABLINK_ISOLATED_ORCHESTRATOR:'
    } elseif ($notes.StartsWith('LABLINK_ISOLATED_VM:',[StringComparison]::Ordinal)) {
        $isGuest = $true
        'LABLINK_ISOLATED_VM:'
    } else {
        throw 'VM_MANAGED_METADATA_MISSING: cannot persist adapter identity'
    }
    $metadata = $notes.Substring($prefix.Length) | ConvertFrom-Json
    if ($isGuest) {
        if ([string]$metadata.vm_id -cne [string]$AdapterRecord.resource_id -or
            [string]$metadata.network_id -cne [string]$AdapterRecord.network_id) {
            throw 'VM_IDENTITY_MISMATCH: guest metadata does not match adapter resource'
        }
        $metadata | Add-Member -NotePropertyName adapter_id -NotePropertyValue ([string]$AdapterRecord.adapter_id) -Force
        $metadata | Add-Member -NotePropertyName switch_guid -NotePropertyValue ([string]$AdapterRecord.switch_guid) -Force
        $metadata | Add-Member -NotePropertyName mac -NotePropertyValue ([string]$AdapterRecord.mac) -Force
        $metadata | Add-Member -NotePropertyName private_adapter_state -NotePropertyValue 'attached' -Force
    } else {
        $refs = @($metadata.private_adapters | Where-Object { [string]$_.network_id -cne [string]$AdapterRecord.network_id })
        $refs += [pscustomobject]@{
            network_id=[string]$AdapterRecord.network_id
            adapter_id=[string]$AdapterRecord.adapter_id
            mac=[string]$AdapterRecord.mac
            switch_guid=[string]$AdapterRecord.switch_guid
        }
        $metadata | Add-Member -NotePropertyName private_adapters -NotePropertyValue @($refs) -Force
    }
    Set-VM -VM $VM -Notes ($prefix + ($metadata | ConvertTo-Json -Depth 20 -Compress)) -ErrorAction Stop
}
function Remove-LabLinkVMAdapterMetadata($VM,[string]$NetworkID,[string]$AdapterID) {
    $notes = [string]$VM.Notes
    $isGuest = $false
    $prefix = if ($notes.StartsWith('LABLINK_ISOLATED_ORCHESTRATOR:',[StringComparison]::Ordinal)) {
        'LABLINK_ISOLATED_ORCHESTRATOR:'
    } elseif ($notes.StartsWith('LABLINK_ISOLATED_VM:',[StringComparison]::Ordinal)) {
        $isGuest = $true
        'LABLINK_ISOLATED_VM:'
    } else {
        throw 'VM_MANAGED_METADATA_MISSING: cannot remove adapter identity'
    }
    $metadata = $notes.Substring($prefix.Length) | ConvertFrom-Json
    if ($isGuest) {
        if ([string]$metadata.network_id -cne $NetworkID -or [string]$metadata.adapter_id -cne $AdapterID) {
            throw 'ADAPTER_IDENTITY_MISMATCH: guest metadata adapter identity changed'
        }
        $metadata | Add-Member -NotePropertyName private_adapter_state -NotePropertyValue 'deleted' -Force
    } else {
        $refs = @($metadata.private_adapters | Where-Object {
            [string]$_.network_id -cne $NetworkID -or [string]$_.adapter_id -cne $AdapterID
        })
        $metadata | Add-Member -NotePropertyName private_adapters -NotePropertyValue @($refs) -Force
    }
    Set-VM -VM $VM -Notes ($prefix + ($metadata | ConvertTo-Json -Depth 20 -Compress)) -ErrorAction Stop
}
`
}
