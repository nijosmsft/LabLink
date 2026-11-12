package hyperv

import (
	"bytes"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

const (
	testHostID      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testOrchID      = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	testNetworkID   = "bbbbbbbb-aaaa-4ccc-8ddd-eeeeeeeeeeee"
	testVMID        = "cccccccc-aaaa-4ccc-8ddd-eeeeeeeeeeee"
	testLeaseID     = "dddddddd-aaaa-4ccc-8ddd-eeeeeeeeeeee"
	testOperationID = "eeeeeeee-aaaa-4ccc-8ddd-eeeeeeeeeeee"
	testMutationID  = "ffffffff-aaaa-4ccc-8ddd-eeeeeeeeeeee"
	testVMGUID      = "11111111-2222-4333-8444-555555555555"
	testSwitchGUID  = "22222222-3333-4444-8555-666666666666"
	testAdapterID   = "33333333-4444-4555-8666-777777777777"
	testSecret      = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func testGuard(resourceType, resourceID, action string) IsolatedMutationGuard {
	return IsolatedMutationGuard{
		PhysicalHostID: testHostID,
		LeaseID:        testLeaseID,
		LeaseSecret:    testSecret,
		Fence:          7,
		OrchestratorID: testOrchID,
		OperationID:    testOperationID,
		MutationID:     testMutationID,
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		Action:         action,
	}
}

func testNetworkMetadata(t *testing.T) IsolatedNetworkMetadata {
	t.Helper()
	owner, err := IsolatedOwnerMarker(testOrchID, "network", testNetworkID)
	if err != nil {
		t.Fatal(err)
	}
	return IsolatedNetworkMetadata{
		SchemaVersion:      IsolatedMetadataSchema,
		PhysicalHostID:     testHostID,
		OrchestratorID:     testOrchID,
		NetworkID:          testNetworkID,
		OwnerMarker:        owner,
		HostFence:          7,
		MutationID:         testMutationID,
		Generation:         1,
		State:              "creating",
		SwitchName:         "isolated-network-bbbbbbbbaaaa",
		OrchestratorVMGUID: testVMGUID,
	}
}

func testAdapterMetadata(t *testing.T) IsolatedAdapterMetadata {
	t.Helper()
	owner, err := IsolatedOwnerMarker(testOrchID, "network", testNetworkID)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := DeterministicIsolatedMAC(testNetworkID)
	if err != nil {
		t.Fatal(err)
	}
	return IsolatedAdapterMetadata{
		SchemaVersion:  IsolatedMetadataSchema,
		PhysicalHostID: testHostID,
		OrchestratorID: testOrchID,
		NetworkID:      testNetworkID,
		ResourceID:     testNetworkID,
		ResourceType:   "network",
		OwnerMarker:    owner,
		HostFence:      7,
		MutationID:     testMutationID,
		Generation:     1,
		State:          "attaching",
		VMGUID:         testVMGUID,
		AdapterName:    "network-bbbbbbbbaaaa",
		MAC:            mac,
		SwitchGUID:     testSwitchGUID,
	}
}

func TestIsolatedMetadataRoundTripAndDeterministicMAC(t *testing.T) {
	mac1, err := DeterministicIsolatedMAC(testNetworkID)
	if err != nil {
		t.Fatal(err)
	}
	mac2, err := DeterministicIsolatedMAC(testNetworkID)
	if err != nil {
		t.Fatal(err)
	}
	if mac1 != mac2 || !strings.HasPrefix(mac1, "02155D") || len(mac1) != 12 {
		t.Fatalf("deterministic locally administered MAC = %q, %q", mac1, mac2)
	}

	owner, err := IsolatedOwnerMarker(testOrchID, "orchestrator", testOrchID)
	if err != nil {
		t.Fatal(err)
	}
	metadata := IsolatedOrchestratorMetadata{
		SchemaVersion: IsolatedMetadataSchema, PhysicalHostID: testHostID,
		OrchestratorID: testOrchID, OwnerMarker: owner, HostFence: 7,
		LifecycleState: "ready", ManagedRoot: `D:\LabLink\isolated`,
		ExpectedVHDPaths: []string{`D:\LabLink\isolated\disk.vhdx`},
		NodeName:         "orchestrator-1", VMGUID: testVMGUID, Generation: 1,
	}
	notes, err := MarshalIsolatedOrchestratorMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(notes, IsolatedOrchestratorMetadataPrefix) {
		t.Fatalf("orchestrator metadata prefix missing: %s", notes)
	}
	got, err := ParseIsolatedOrchestratorMetadata(notes)
	if err != nil {
		t.Fatal(err)
	}
	if got.OrchestratorID != testOrchID || got.VMGUID != testVMGUID {
		t.Fatalf("metadata round trip mismatch: %+v", got)
	}

	vmOwner, err := IsolatedOwnerMarker(testOrchID, "vm", testVMID)
	if err != nil {
		t.Fatal(err)
	}
	pendingVM := IsolatedVMMetadata{
		SchemaVersion: IsolatedMetadataSchema, PhysicalHostID: testHostID,
		OrchestratorID: testOrchID, NetworkID: testNetworkID, VMID: testVMID,
		OwnerMarker: vmOwner, HostFence: 7, LifecycleState: "creating",
		ManagedRoot: `D:\LabLink\isolated`, ExpectedVHDPaths: []string{`D:\LabLink\isolated\guest.vhdx`},
		NodeName: "vm-ccccccccaaaa", IPv4: "192.168.240.10", MAC: mac1,
		SwitchGUID: testSwitchGUID, Incarnation: 1, Generation: 1,
	}
	if _, err := MarshalIsolatedVMMetadata(pendingVM); err != nil {
		t.Fatalf("pre-create VM metadata must permit not-yet-known VM/adapter IDs: %v", err)
	}
	pendingVM.LifecycleState = "ready"
	if _, err := MarshalIsolatedVMMetadata(pendingVM); err == nil {
		t.Fatal("ready VM metadata unexpectedly omitted immutable VM/adapter IDs")
	}
}

func TestIsolatedLockHierarchy(t *testing.T) {
	host, err := HostOrchestratorCreateLockKey(testHostID)
	if err != nil {
		t.Fatal(err)
	}
	orchestrator, _ := OrchestratorLockKey(testOrchID)
	allocation, _ := AllocationLockKey(testOrchID)
	network, _ := NetworkLockKey(testNetworkID)
	vm, _ := VMLockKey(testVMID)
	child, _ := ChildLockKey("relay", testOperationID)
	keys := []IsolatedResourceLockKey{host, orchestrator, allocation, network, vm, child}
	for i := 1; i < len(keys); i++ {
		if !keys[i].CanAcquireAfter(keys[i-1]) {
			t.Fatalf("%s cannot be acquired after %s", keys[i].Key, keys[i-1].Key)
		}
		if keys[i-1].CanAcquireAfter(keys[i]) {
			t.Fatalf("upward acquisition unexpectedly allowed: %s after %s", keys[i-1].Key, keys[i].Key)
		}
	}
}

func TestIsolatedHostLeaseScriptsRenewReclaimAndFence(t *testing.T) {
	base := IsolatedHostLeaseParams{
		PhysicalHostID: testHostID, LeaseID: testLeaseID, LeaseSecret: testSecret,
		HolderIdentity: "host:123:456:cookie", OperationID: testOperationID,
		DurationSeconds: 180,
	}
	acquire, err := BuildAcquireIsolatedHostLockScript(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"isolated-orchestrator-", "handoff_pending.json", "external-mutation.lock",
		"lock_reclaimed", "$nextFence", "Get-LabLinkPhysicalHostID",
		"LOCK_RACE", "Flush($true)",
	} {
		if !strings.Contains(acquire, want) {
			t.Errorf("acquire/reclaim script missing %q", want)
		}
	}
	base.Fence = 7
	renew, err := BuildRenewIsolatedHostLockScript(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"$expectedFence = [int64]7", "Assert-LabLinkLease",
		"FENCE_REJECTED", "LEASE_EXPIRED", "lock_renewed",
	} {
		if !strings.Contains(renew, want) {
			t.Errorf("renew script missing stale-fence defense %q", want)
		}
	}
	release, err := BuildReleaseIsolatedHostLockScript(base)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(release, "$current.fence = $expectedFence + 1") ||
		!strings.Contains(release, "lease_release") {
		t.Fatal("release does not fence stale holders under handoff")
	}

	result, err := ParseIsolatedHostLeaseResult(`noise
{"status":"lock_reclaimed","acquired":true,"reclaimed":true,"lease_id":"` + testLeaseID + `","fence":8,"expires_utc":"2026-01-01T00:00:00Z"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Reclaimed || result.Fence != 8 {
		t.Fatalf("lease result mismatch: %+v", result)
	}
}

func TestPrivateSwitchScriptIsPrivateExactAndNoHostAdapter(t *testing.T) {
	metadata := testNetworkMetadata(t)
	script, err := BuildCreateIsolatedPrivateSwitchScript(CreateIsolatedPrivateSwitchParams{
		Guard:              testGuard("network", testNetworkID, "create_private_switch"),
		OrchestratorVMGUID: testVMGUID,
		Metadata:           metadata,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"New-VMSwitch -Name ([string]$expected.switch_name) -SwitchType Private",
		"Get-VMNetworkAdapter -ManagementOS",
		"HOST_ADAPTER_PRESENT",
		"SWITCH_OWNERSHIP_MISMATCH",
		"same-name switch was replaced with another GUID",
		"Enter-LabLinkIsolatedMutation",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("private switch script missing %q", want)
		}
	}
	for _, forbidden := range []string{"-SwitchType Internal", "Remove-VMSwitch -Name"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("private switch script contains forbidden display-name/internal behavior %q", forbidden)
		}
	}
}

func TestPrivateSwitchDeleteRequiresExactGUIDAndCascadeChecks(t *testing.T) {
	authority := CascadeAuthority{
		OrchestratorID: testOrchID, FrozenGeneration: 2,
		OperationID: testOperationID, PlanRevision: "rev-1", PlanHash: "hash-1",
		HostFence: 7, LeaseID: testLeaseID,
		Items: []CascadeAuthorityItem{{
			ResourceType: "network", ResourceID: testNetworkID,
			Action: "delete_private_switch", Generation: 1, SwitchGUID: testSwitchGUID,
		}},
	}

	guard := testGuard("network", testNetworkID, "delete_private_switch")
	guard.CascadeAuthority = &authority
	script, err := BuildDeleteIsolatedPrivateSwitchScript(DeleteIsolatedPrivateSwitchParams{
		Guard: guard, OrchestratorVMGUID: testVMGUID, NetworkID: testNetworkID,
		SwitchName: "isolated-network-bbbbbbbbaaaa", ExpectedSwitchGUID: testSwitchGUID,
		ExpectedGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"CASCADE_AUTHORITY_REJECTED", "PARENT_FROZEN",
		"[string]$record.switch_guid -cne $switchGUID",
		"Where-Object { [string]$_.Id -ceq $switchGUID }",
		"$switch[0] | Remove-VMSwitch",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("exact switch delete script missing %q", want)
		}
	}
	if strings.Contains(script, "Remove-VMSwitch -Name") {
		t.Fatal("switch deletion must not be authorized by display name")
	}
}

func TestFreezeInstallsRevisionBoundCleanupOnlyAuthority(t *testing.T) {
	authority := CascadeAuthority{
		OrchestratorID: testOrchID, FrozenGeneration: 2,
		OperationID: testOperationID, PlanRevision: "rev-1", PlanHash: "hash-1",
		HostFence: 7, LeaseID: testLeaseID,
		Items: []CascadeAuthorityItem{{
			ResourceType: "network", ResourceID: testNetworkID,
			Action: "delete_private_switch", Generation: 1, SwitchGUID: testSwitchGUID,
		}},
	}
	script, err := BuildSetIsolatedParentLifecycleScript(SetIsolatedParentLifecycleParams{
		Guard:              testGuard("orchestrator", testOrchID, "set_parent_lifecycle"),
		OrchestratorVMGUID: testVMGUID, ExpectedGeneration: 1, NewGeneration: 2,
		NewState: "frozen", CascadeAuthority: &authority,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"lifecycle_state", "cascade_authority", "plan_revision", "Set-VM -VM $vm -Notes"} {
		if !strings.Contains(script, want) {
			t.Errorf("freeze script missing %q", want)
		}
	}

	authority.Items[0].Action = "attach_nic"
	if _, err := BuildSetIsolatedParentLifecycleScript(SetIsolatedParentLifecycleParams{
		Guard:              testGuard("orchestrator", testOrchID, "set_parent_lifecycle"),
		OrchestratorVMGUID: testVMGUID, ExpectedGeneration: 1, NewGeneration: 2,
		NewState: "frozen", CascadeAuthority: &authority,
	}); err == nil {
		t.Fatal("cascade authority unexpectedly allowed a non-cleanup action")
	}
}

func TestReclaimedFenceRebindPreservesCascadeRevision(t *testing.T) {
	guard := testGuard("orchestrator", testOrchID, "rebind_parent_fence")
	guard.Fence = 8
	script, err := BuildRebindIsolatedParentFenceScript(RebindIsolatedParentFenceParams{
		Guard: guard, OrchestratorVMGUID: testVMGUID,
		ExpectedPreviousFence: 7, ExpectedGeneration: 2,
		PlanRevision: "rev-1", PlanHash: "hash-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[int64]$metadata.host_fence -ne [int64]7",
		"$authority.lease_id = $guardLeaseID",
		"$authority.host_fence = $guardFence",
		"interrupted cascade revision changed",
		"parent_fence_rebound",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("fence rebind script missing %q", want)
		}
	}
}

func TestAdapterScriptsUseImmutableAdapterIdentity(t *testing.T) {
	mac, err := DeterministicIsolatedMAC(testNetworkID)
	if err != nil {
		t.Fatal(err)
	}
	attach, err := BuildAttachIsolatedNICScript(AttachIsolatedNICParams{
		Guard:     testGuard("network", testNetworkID, "attach_nic"),
		NetworkID: testNetworkID, ResourceType: "network", ResourceID: testNetworkID,
		OrchestratorVMGUID: testVMGUID, VMGUID: testVMGUID, AdapterName: "network-bbbbbbbbaaaa",
		SwitchGUID: testSwitchGUID, MAC: mac, Generation: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Add-VMNetworkAdapter -VM $vm", "Set-VMNetworkAdapter -StaticMacAddress",
		"[string]$adapter.Id", "[string]$adapter.SwitchId",
		"ADAPTER_OWNERSHIP_MISMATCH", "same-name adapter was replaced",
		"Set-LabLinkVMAdapterMetadata",
	} {
		if !strings.Contains(attach, want) {
			t.Errorf("attach script missing %q", want)
		}
	}

	removeGuard := testGuard("network", testNetworkID, "remove_nic")
	remove, err := BuildRemoveIsolatedNICScript(RemoveIsolatedNICParams{
		Guard: removeGuard, NetworkID: testNetworkID, ResourceType: "network",
		ResourceID: testNetworkID, OrchestratorVMGUID: testVMGUID,
		VMGUID: testVMGUID, AdapterName: "network-bbbbbbbbaaaa",
		ExpectedAdapterID: testAdapterID, ExpectedSwitchGUID: testSwitchGUID,
		ExpectedMAC: mac, ExpectedGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(remove, "Remove-VMNetworkAdapter -VMNetworkAdapter $adapter[0]") ||
		!strings.Contains(remove, "[string]$_.Id -ceq $adapterID") {
		t.Fatal("NIC removal is not bound to the exact adapter ID")
	}
	if strings.Contains(remove, "Remove-VMNetworkAdapter -VMName") {
		t.Fatal("NIC removal must not be authorized by VM/display name")
	}
}

func TestUncertainSwitchCreateReconciliationRejectsReplacement(t *testing.T) {
	expected := testNetworkMetadata(t)
	owned := expected
	owned.SwitchGUID = testSwitchGUID
	observed := IsolatedSwitchObservation{
		Name: expected.SwitchName, SwitchGUID: testSwitchGUID, Type: "Private",
		HostNICCount: 0, Ownership: &owned,
	}
	decision, adopted, err := ReconcileUncertainSwitchCreate(expected, []IsolatedSwitchObservation{observed})
	if err != nil || decision != UncertainCreateAdopt || adopted == nil {
		t.Fatalf("exact uncertain switch was not adopted: %s %+v %v", decision, adopted, err)
	}

	replacement := observed
	replacement.SwitchGUID = "44444444-5555-4666-8777-888888888888"
	decision, _, err = ReconcileUncertainSwitchCreate(expected, []IsolatedSwitchObservation{replacement})
	if err == nil || decision != UncertainCreateConflict {
		t.Fatalf("same-name replacement was not rejected: %s %v", decision, err)
	}

	decision, _, err = ReconcileUncertainSwitchCreate(expected, nil)
	if err != nil || decision != UncertainCreateRetry {
		t.Fatalf("absent uncertain switch should be retryable: %s %v", decision, err)
	}
}

func TestUncertainAdapterCreateUsesAdapterIDMACAndSwitch(t *testing.T) {
	expected := testAdapterMetadata(t)
	owned := expected
	owned.AdapterID = testAdapterID
	observed := IsolatedAdapterObservation{
		VMGUID: testVMGUID, Name: expected.AdapterName, AdapterID: testAdapterID,
		MAC: expected.MAC, SwitchGUID: testSwitchGUID, Ownership: &owned,
	}
	decision, adopted, err := ReconcileUncertainAdapterCreate(expected, []IsolatedAdapterObservation{observed})
	if err != nil || decision != UncertainCreateAdopt || adopted == nil {
		t.Fatalf("exact uncertain adapter was not adopted: %s %+v %v", decision, adopted, err)
	}
	replacement := observed
	replacement.AdapterID = "44444444-5555-4666-8777-888888888888"
	decision, _, err = ReconcileUncertainAdapterCreate(expected, []IsolatedAdapterObservation{replacement})
	if err == nil || decision != UncertainCreateConflict {
		t.Fatalf("same-name adapter replacement was not rejected: %s %v", decision, err)
	}
}

func TestDiscoveryScriptsAndParsersIncludeImmutableIDsAndCapacity(t *testing.T) {
	identityScript := BuildPhysicalHostIdentityScript()
	for _, want := range []string{"MachineGuid", "Win32_ComputerSystemProduct", "lablink-physical-host/v1", "physical_host_id"} {
		if !strings.Contains(identityScript, want) {
			t.Errorf("host identity script missing %q", want)
		}
	}
	observation, err := ParsePhysicalHostIdentityObservation(`{"physical_host_id":"` + testHostID + `","machine_guid":"11111111-2222-4333-8444-555555555555","smbios_uuid":"22222222-3333-4444-8555-666666666666"}`)
	if err != nil || observation.PhysicalHostID != testHostID {
		t.Fatalf("physical host parser failed: %+v %v", observation, err)
	}
	discoveryScript, err := BuildDiscoverIsolatedHostScript(IsolatedDiscoveryParams{
		OrchestratorID: testOrchID, OrchestratorVMGUID: testVMGUID,
		MaxSyntheticAdapters: 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"switch_guid", "adapter_id", "max_synthetic_adapters",
		"available_private_slots", "Get-NetRoute -AddressFamily IPv4",
		"DestinationPrefix -ne '0.0.0.0/0'", "metadata_errors",
	} {
		if !strings.Contains(discoveryScript, want) {
			t.Errorf("isolated discovery script missing %q", want)
		}
	}
	discovery, err := ParseIsolatedHostDiscovery(`{
	  "host":{"physical_host_id":"` + testHostID + `"},
	  "routes":[{"destination_prefix":"10.0.0.0/8","interface_index":4}],
	  "capacity":{"vm_guid":"` + testVMGUID + `","max_synthetic_adapters":16,"main_adapters":1,"managed_private_adapters":2,"other_adapters":1,"available_private_slots":12},
	  "switches":[],"vms":[],"adapters":[],"metadata_errors":[]
	}`)
	if err != nil || discovery.Capacity == nil || discovery.Capacity.AvailablePrivateSlots != 12 {
		t.Fatalf("isolated discovery parser failed: %+v %v", discovery, err)
	}
}

func TestBaseDiscoveryTypesCarryImmutableIDs(t *testing.T) {
	switches, err := ParseVSwitches(`[{"name":"S","id":"` + testSwitchGUID + `","type":"Private","allow_management_os":false}]`)
	if err != nil || len(switches) != 1 || switches[0].ID != testSwitchGUID {
		t.Fatalf("vSwitch GUID was not parsed: %+v %v", switches, err)
	}
	nics, err := ParseNICs(`[{"name":"Ethernet","interface_guid":"` + testAdapterID + `","interface_index":12}]`)
	if err != nil || len(nics) != 1 || nics[0].InterfaceGUID != testAdapterID || nics[0].InterfaceIndex != 12 {
		t.Fatalf("physical NIC identity was not parsed: %+v %v", nics, err)
	}
}

func TestIsolatedRenderedPowerShellParses(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows PowerShell parser is only available on Windows")
	}
	metadata := testNetworkMetadata(t)
	mac, err := DeterministicIsolatedMAC(testNetworkID)
	if err != nil {
		t.Fatal(err)
	}

	lease := IsolatedHostLeaseParams{
		PhysicalHostID: testHostID, LeaseID: testLeaseID, LeaseSecret: testSecret,
		HolderIdentity: "host:123:456:cookie", OperationID: testOperationID,
		DurationSeconds: 180, Fence: 7,
	}
	scripts := []string{BuildPhysicalHostIdentityScript()}
	for _, build := range []func() (string, error){
		func() (string, error) { return BuildAcquireIsolatedHostLockScript(lease) },
		func() (string, error) { return BuildRenewIsolatedHostLockScript(lease) },
		func() (string, error) { return BuildReleaseIsolatedHostLockScript(lease) },
		func() (string, error) {
			return BuildCreateIsolatedPrivateSwitchScript(CreateIsolatedPrivateSwitchParams{
				Guard:              testGuard("network", testNetworkID, "create_private_switch"),
				OrchestratorVMGUID: testVMGUID, Metadata: metadata,
			})
		},
		func() (string, error) {
			return BuildAttachIsolatedNICScript(AttachIsolatedNICParams{
				Guard:     testGuard("network", testNetworkID, "attach_nic"),
				NetworkID: testNetworkID, ResourceType: "network", ResourceID: testNetworkID,
				OrchestratorVMGUID: testVMGUID, VMGUID: testVMGUID, AdapterName: "network-bbbbbbbbaaaa",
				SwitchGUID: testSwitchGUID, MAC: mac, Generation: 1,
			})
		},
		func() (string, error) {
			return BuildDiscoverIsolatedHostScript(IsolatedDiscoveryParams{
				OrchestratorID: testOrchID, OrchestratorVMGUID: testVMGUID,
			})
		},
		func() (string, error) {
			authority := CascadeAuthority{
				OrchestratorID: testOrchID, FrozenGeneration: 2,
				OperationID: testOperationID, PlanRevision: "rev-1", PlanHash: "hash-1",
				HostFence: 7, LeaseID: testLeaseID,
				Items: []CascadeAuthorityItem{{
					ResourceType: "network", ResourceID: testNetworkID,
					Action: "delete_private_switch", Generation: 1,
				}},
			}
			return BuildSetIsolatedParentLifecycleScript(SetIsolatedParentLifecycleParams{
				Guard:              testGuard("orchestrator", testOrchID, "set_parent_lifecycle"),
				OrchestratorVMGUID: testVMGUID, ExpectedGeneration: 1, NewGeneration: 2,
				NewState: "frozen", CascadeAuthority: &authority,
			})
		},
		func() (string, error) {
			guard := testGuard("orchestrator", testOrchID, "rebind_parent_fence")
			guard.Fence = 8
			return BuildRebindIsolatedParentFenceScript(RebindIsolatedParentFenceParams{
				Guard: guard, OrchestratorVMGUID: testVMGUID,
				ExpectedPreviousFence: 7, ExpectedGeneration: 2,
				PlanRevision: "rev-1", PlanHash: "hash-1",
			})
		},
	} {
		script, err := build()
		if err != nil {
			t.Fatal(err)
		}
		scripts = append(scripts, script)
	}
	const delimiter = "\n#---LABLINK-SCRIPT-BOUNDARY---\n"
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$all=[Console]::In.ReadToEnd(); $i=0; foreach($script in ($all -split '#---LABLINK-SCRIPT-BOUNDARY---')) { $i++; try { [void][scriptblock]::Create($script) } catch { Write-Error ("script ${i}: " + $_.Exception.Message); exit 1 } }`)
	command.Stdin = strings.NewReader(strings.Join(scripts, delimiter))
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		t.Fatalf("generated PowerShell did not parse: %v\n%s", err, output.String())
	}
}

func TestManagedVMInspectionSupportsIsolatedOrchestratorMetadata(t *testing.T) {
	script, err := BuildInspectVMManagementScript("isolated-orchestrator")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		IsolatedOrchestratorMetadataPrefix,
		"expected_vhd_paths",
		"isolated orchestrator must have exactly one expected OS VHD",
		"managed_root=[string]$isolated.managed_root",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("inspection script missing %q", want)
		}
	}
}
