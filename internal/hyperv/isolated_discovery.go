package hyperv

import (
	"encoding/json"
	"fmt"
	"strings"
)

type IsolatedPhysicalHostObservation struct {
	PhysicalHostID    string `json:"physical_host_id"`
	MachineGUID       string `json:"machine_guid"`
	SMBIOSUUID        string `json:"smbios_uuid"`
	ComputerName      string `json:"computer_name"`
	OSCaption         string `json:"os_caption"`
	OSVersion         string `json:"os_version"`
	OSArchitecture    string `json:"os_architecture"`
	PowerShellVersion string `json:"powershell_version"`
	HyperVAvailable   bool   `json:"hyperv_available"`
}

type IsolatedRouteObservation struct {
	DestinationPrefix string `json:"destination_prefix"`
	InterfaceIndex    int    `json:"interface_index"`
	InterfaceAlias    string `json:"interface_alias"`
	NextHop           string `json:"next_hop"`
	RouteMetric       int    `json:"route_metric"`
}

type IsolatedNICCapacityObservation struct {
	VMGUID                 string `json:"vm_guid"`
	MaxSyntheticAdapters   int    `json:"max_synthetic_adapters"`
	MainAdapters           int    `json:"main_adapters"`
	ManagedPrivateAdapters int    `json:"managed_private_adapters"`
	OtherAdapters          int    `json:"other_adapters"`
	AvailablePrivateSlots  int    `json:"available_private_slots"`
}

type IsolatedSwitchObservation struct {
	Name              string                   `json:"name"`
	SwitchGUID        string                   `json:"switch_guid"`
	Type              string                   `json:"type"`
	AllowManagementOS bool                     `json:"allow_management_os"`
	HostNICCount      int                      `json:"host_nic_count"`
	ConnectedAdapters int                      `json:"connected_adapters"`
	OwnershipPath     string                   `json:"ownership_path,omitempty"`
	Ownership         *IsolatedNetworkMetadata `json:"ownership,omitempty"`
}

type IsolatedVMObservation struct {
	Name           string `json:"name"`
	VMGUID         string `json:"vm_guid"`
	State          string `json:"state"`
	MetadataKind   string `json:"metadata_kind,omitempty"`
	PhysicalHostID string `json:"physical_host_id,omitempty"`
	OrchestratorID string `json:"orchestrator_id,omitempty"`
	NetworkID      string `json:"network_id,omitempty"`
	ResourceID     string `json:"resource_id,omitempty"`
	HostFence      int64  `json:"host_fence,omitempty"`
	Generation     int64  `json:"generation,omitempty"`
	LifecycleState string `json:"lifecycle_state,omitempty"`
}

type IsolatedAdapterObservation struct {
	VMName        string                   `json:"vm_name"`
	VMGUID        string                   `json:"vm_guid"`
	Name          string                   `json:"name"`
	AdapterID     string                   `json:"adapter_id"`
	MAC           string                   `json:"mac"`
	SwitchName    string                   `json:"switch_name"`
	SwitchGUID    string                   `json:"switch_guid"`
	DynamicMAC    bool                     `json:"dynamic_mac"`
	OwnershipPath string                   `json:"ownership_path,omitempty"`
	Ownership     *IsolatedAdapterMetadata `json:"ownership,omitempty"`
}

type IsolatedHostDiscovery struct {
	Host           IsolatedPhysicalHostObservation `json:"host"`
	Routes         []IsolatedRouteObservation      `json:"routes"`
	Capacity       *IsolatedNICCapacityObservation `json:"capacity,omitempty"`
	Switches       []IsolatedSwitchObservation     `json:"switches"`
	VMs            []IsolatedVMObservation         `json:"vms"`
	Adapters       []IsolatedAdapterObservation    `json:"adapters"`
	MetadataErrors []string                        `json:"metadata_errors"`
}

type IsolatedDiscoveryParams struct {
	OrchestratorID       string
	OrchestratorVMGUID   string
	MaxSyntheticAdapters int
}

type UncertainCreateDecision string

const (
	UncertainCreateRetry    UncertainCreateDecision = "retry"
	UncertainCreateAdopt    UncertainCreateDecision = "adopt"
	UncertainCreateConflict UncertainCreateDecision = "conflict"
)

func BuildPhysicalHostIdentityScript() string {
	body := isolatedLockPowerShell() + `
$machineGuid = [string](Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop)
$smbiosUUID = [string](Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop).UUID
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
[pscustomobject]@{
    physical_host_id=(Get-LabLinkPhysicalHostID)
    machine_guid=$machineGuid.Trim().Trim('{}').ToLowerInvariant()
    smbios_uuid=$smbiosUUID.Trim().Trim('{}').ToLowerInvariant()
    computer_name=[string]$env:COMPUTERNAME
    os_caption=[string]$os.Caption
    os_version=[string]$os.Version
    os_architecture=[string]$os.OSArchitecture
    powershell_version=[string]$PSVersionTable.PSVersion
    hyperv_available=[bool](Get-Command Get-VM -ErrorAction SilentlyContinue)
} | ConvertTo-Json -Compress
`
	return wrapTagged(body)
}

func ParsePhysicalHostIdentityObservation(text string) (IsolatedPhysicalHostObservation, error) {
	var observation IsolatedPhysicalHostObservation
	if err := json.Unmarshal([]byte(strings.TrimSpace(extractJSON(text))), &observation); err != nil {
		return observation, err
	}
	if err := validateHostID(observation.PhysicalHostID); err != nil {
		return observation, err
	}
	return observation, nil
}

func BuildDiscoverIsolatedHostScript(p IsolatedDiscoveryParams) (string, error) {
	if p.OrchestratorID != "" {
		if err := validateIsolatedID("orchestrator", p.OrchestratorID); err != nil {
			return "", err
		}
	}
	if p.OrchestratorVMGUID != "" {
		if err := validateGUID("orchestrator VM", p.OrchestratorVMGUID); err != nil {
			return "", err
		}
	}
	if p.MaxSyntheticAdapters <= 0 {
		p.MaxSyntheticAdapters = 16
	}
	body := PreflightScript() + isolatedLockPowerShell() + isolatedHostMetadataPowerShell() + fmt.Sprintf(`
$orchestratorID = %s
$orchestratorVMGUID = %s
$maxSyntheticAdapters = %d
$machineGuid = [string](Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop)
$smbiosUUID = [string](Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop).UUID
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
$hostObservation = [ordered]@{
    physical_host_id=(Get-LabLinkPhysicalHostID)
    machine_guid=$machineGuid.Trim().Trim('{}').ToLowerInvariant()
    smbios_uuid=$smbiosUUID.Trim().Trim('{}').ToLowerInvariant()
    computer_name=[string]$env:COMPUTERNAME
    os_caption=[string]$os.Caption
    os_version=[string]$os.Version
    os_architecture=[string]$os.OSArchitecture
    powershell_version=[string]$PSVersionTable.PSVersion
    hyperv_available=$true
}
$metadataErrors = @()
$networkRecords = @{}
$networkRecordsByName = @{}
$adapterRecords = @{}
$adapterRecordsByVMAndName = @{}
if ($orchestratorID) {
    $root = Get-LabLinkIsolatedRoot $orchestratorID
    foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $root 'networks') -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
        try {
            $record = Get-Content -Raw -LiteralPath $file.FullName -ErrorAction Stop | ConvertFrom-Json
            $owned = [pscustomobject]@{ path=$file.FullName; record=$record }
            if ([string]$record.switch_guid) { $networkRecords[[string]$record.switch_guid] = $owned }
            $networkRecordsByName[[string]$record.switch_name] = $owned
        } catch { $metadataErrors += "NETWORK_METADATA_INVALID: $($file.FullName): $($_.Exception.Message)" }
    }
    foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $root 'adapters') -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
        try {
            $record = Get-Content -Raw -LiteralPath $file.FullName -ErrorAction Stop | ConvertFrom-Json
            $owned = [pscustomobject]@{ path=$file.FullName; record=$record }
            if ([string]$record.adapter_id) { $adapterRecords[[string]$record.adapter_id] = $owned }
            $adapterRecordsByVMAndName[([string]$record.vm_guid + '|' + [string]$record.adapter_name)] = $owned
        } catch { $metadataErrors += "ADAPTER_METADATA_INVALID: $($file.FullName): $($_.Exception.Message)" }
    }
}
$switches = @(
    foreach ($switch in @(Get-VMSwitch -ErrorAction SilentlyContinue)) {
        $switchID = [string]$switch.Id
        $owned = $networkRecords[$switchID]
        if (-not $owned) { $owned = $networkRecordsByName[[string]$switch.Name] }
        [pscustomobject]@{
            name=[string]$switch.Name; switch_guid=$switchID; type=[string]$switch.SwitchType
            allow_management_os=[bool]$switch.AllowManagementOS
            host_nic_count=@(Get-VMNetworkAdapter -ManagementOS -SwitchName $switch.Name -ErrorAction SilentlyContinue).Count
            connected_adapters=@(Get-VMNetworkAdapter -All -ErrorAction SilentlyContinue | Where-Object { [string]$_.SwitchId -ceq $switchID }).Count
            ownership_path=if ($owned) { [string]$owned.path } else { $null }
            ownership=if ($owned) { $owned.record } else { $null }
        }
    }
)
$vms = @(
    foreach ($vm in @(Get-VM -ErrorAction SilentlyContinue)) {
        $notes = [string]$vm.Notes
        $kind = $null; $metadata = $null
        try {
            if ($notes.StartsWith(%s,[StringComparison]::Ordinal)) {
                $kind='orchestrator'; $metadata=$notes.Substring(%d) | ConvertFrom-Json
            } elseif ($notes.StartsWith(%s,[StringComparison]::Ordinal)) {
                $kind='vm'; $metadata=$notes.Substring(%d) | ConvertFrom-Json
            }
        } catch { $metadataErrors += "VM_METADATA_INVALID: $($vm.Id): $($_.Exception.Message)" }
        [pscustomobject]@{
            name=[string]$vm.Name; vm_guid=[string]$vm.Id; state=[string]$vm.State
            metadata_kind=$kind
            physical_host_id=if ($metadata) { [string]$metadata.physical_host_id } else { $null }
            orchestrator_id=if ($metadata) { [string]$metadata.orchestrator_id } else { $null }
            network_id=if ($metadata) { [string]$metadata.network_id } else { $null }
            resource_id=if ($metadata -and $kind -eq 'vm') { [string]$metadata.vm_id } elseif ($metadata) { [string]$metadata.orchestrator_id } else { $null }
            host_fence=if ($metadata) { [int64]$metadata.host_fence } else { 0 }
            generation=if ($metadata) { [int64]$metadata.generation } else { 0 }
            lifecycle_state=if ($metadata) { [string]$metadata.lifecycle_state } else { $null }
        }
    }
)
$adapters = @(
    foreach ($vm in @(Get-VM -ErrorAction SilentlyContinue)) {
        foreach ($adapter in @(Get-VMNetworkAdapter -VM $vm -ErrorAction SilentlyContinue)) {
            $adapterID = [string]$adapter.Id
            $owned = $adapterRecords[$adapterID]
            if (-not $owned) { $owned = $adapterRecordsByVMAndName[([string]$vm.Id + '|' + [string]$adapter.Name)] }
            [pscustomobject]@{
                vm_name=[string]$vm.Name; vm_guid=[string]$vm.Id; name=[string]$adapter.Name
                adapter_id=$adapterID; mac=([string]$adapter.MacAddress).Replace('-','').ToUpperInvariant()
                switch_name=[string]$adapter.SwitchName; switch_guid=[string]$adapter.SwitchId
                dynamic_mac=[bool]$adapter.DynamicMacAddressEnabled
                ownership_path=if ($owned) { [string]$owned.path } else { $null }
                ownership=if ($owned) { $owned.record } else { $null }
            }
        }
    }
)
$capacity = $null
if ($orchestratorVMGUID) {
    $targetVM = Get-VM -Id $orchestratorVMGUID -ErrorAction SilentlyContinue
    if ($targetVM) {
        $targetAdapters = @(Get-VMNetworkAdapter -VM $targetVM -ErrorAction SilentlyContinue)
        $managed = @($targetAdapters | Where-Object { $adapterRecords.ContainsKey([string]$_.Id) }).Count
        $main = if ($targetAdapters.Count -gt 0) { 1 } else { 0 }
        $other = [math]::Max(0,$targetAdapters.Count - $main - $managed)
        $capacity = [ordered]@{
            vm_guid=[string]$targetVM.Id; max_synthetic_adapters=$maxSyntheticAdapters
            main_adapters=$main; managed_private_adapters=$managed; other_adapters=$other
            available_private_slots=[math]::Max(0,$maxSyntheticAdapters - $main - $managed - $other)
        }
    }
}
$routes = @(
    Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { [string]$_.DestinationPrefix -ne '0.0.0.0/0' } |
        ForEach-Object {
            [pscustomobject]@{
                destination_prefix=[string]$_.DestinationPrefix
                interface_index=[int]$_.InterfaceIndex
                interface_alias=[string]$_.InterfaceAlias
                next_hop=[string]$_.NextHop
                route_metric=[int]$_.RouteMetric
            }
        }
)
[pscustomobject]@{
    host=$hostObservation; routes=@($routes); capacity=$capacity
    switches=@($switches); vms=@($vms); adapters=@($adapters)
    metadata_errors=@($metadataErrors)
} | ConvertTo-Json -Depth 20
`, PSLit(p.OrchestratorID), PSLit(normalizedGUIDOrEmpty(p.OrchestratorVMGUID)),
		p.MaxSyntheticAdapters, PSLit(IsolatedOrchestratorMetadataPrefix),
		len(IsolatedOrchestratorMetadataPrefix), PSLit(IsolatedVMMetadataPrefix),
		len(IsolatedVMMetadataPrefix))
	return wrapTagged(body), nil
}

func ParseIsolatedHostDiscovery(text string) (IsolatedHostDiscovery, error) {
	var discovery IsolatedHostDiscovery
	if err := json.Unmarshal([]byte(strings.TrimSpace(extractJSON(text))), &discovery); err != nil {
		return discovery, err
	}
	if err := validateHostID(discovery.Host.PhysicalHostID); err != nil {
		return discovery, err
	}
	return discovery, nil
}

// ReconcileUncertainSwitchCreate decides whether a lost create result can be
// adopted. Name equality alone never authorizes adoption.
func ReconcileUncertainSwitchCreate(expected IsolatedNetworkMetadata, observations []IsolatedSwitchObservation) (UncertainCreateDecision, *IsolatedSwitchObservation, error) {
	if err := validateNetworkMetadata(expected); err != nil {
		return UncertainCreateConflict, nil, err
	}
	var sameName []IsolatedSwitchObservation
	var exact []IsolatedSwitchObservation
	for _, observation := range observations {
		if observation.Name != expected.SwitchName {
			continue
		}
		sameName = append(sameName, observation)
		if observation.Type != "Private" || observation.HostNICCount != 0 || observation.Ownership == nil {
			continue
		}
		owner := observation.Ownership
		if owner.PhysicalHostID == expected.PhysicalHostID &&
			owner.OrchestratorID == expected.OrchestratorID &&
			owner.NetworkID == expected.NetworkID &&
			owner.OwnerMarker == expected.OwnerMarker &&
			owner.MutationID == expected.MutationID &&
			(owner.SwitchGUID == "" || strings.EqualFold(owner.SwitchGUID, observation.SwitchGUID)) {
			exact = append(exact, observation)
		}
	}
	if len(exact) == 1 && len(sameName) == 1 {
		return UncertainCreateAdopt, &exact[0], nil
	}
	if len(sameName) == 0 {
		return UncertainCreateRetry, nil, nil
	}
	return UncertainCreateConflict, nil, fmt.Errorf("SWITCH_IDENTITY_AMBIGUOUS: same-name switch is unmanaged, replaced, or non-unique")
}

// ReconcileUncertainAdapterCreate uses VM GUID, adapter ID metadata, static
// MAC, and switch GUID. It never adopts a same-name adapter by name alone.
func ReconcileUncertainAdapterCreate(expected IsolatedAdapterMetadata, observations []IsolatedAdapterObservation) (UncertainCreateDecision, *IsolatedAdapterObservation, error) {
	if err := validateAdapterMetadata(expected); err != nil {
		return UncertainCreateConflict, nil, err
	}
	var sameName []IsolatedAdapterObservation
	var exact []IsolatedAdapterObservation
	for _, observation := range observations {
		if !strings.EqualFold(observation.VMGUID, expected.VMGUID) || observation.Name != expected.AdapterName {
			continue
		}
		sameName = append(sameName, observation)
		if observation.Ownership == nil || observation.DynamicMAC ||
			!strings.EqualFold(observation.SwitchGUID, expected.SwitchGUID) ||
			normalizeMAC(observation.MAC) != normalizeMAC(expected.MAC) {
			continue
		}
		owner := observation.Ownership
		if owner.PhysicalHostID == expected.PhysicalHostID &&
			owner.OrchestratorID == expected.OrchestratorID &&
			owner.NetworkID == expected.NetworkID &&
			owner.ResourceID == expected.ResourceID &&
			owner.MutationID == expected.MutationID &&
			(owner.AdapterID == "" || strings.EqualFold(owner.AdapterID, observation.AdapterID)) {
			exact = append(exact, observation)
		}
	}
	if len(exact) == 1 && len(sameName) == 1 {
		return UncertainCreateAdopt, &exact[0], nil
	}
	if len(sameName) == 0 {
		return UncertainCreateRetry, nil, nil
	}
	return UncertainCreateConflict, nil, fmt.Errorf("ADAPTER_IDENTITY_AMBIGUOUS: same-name adapter is unmanaged, replaced, or non-unique")
}
