package hyperv

import (
	"strings"
	"testing"
)

func TestIsolatedVMClaimAndExactDeleteScripts(t *testing.T) {
	vmID := "44444444-4444-4444-8444-444444444444"
	orchestratorID := "11111111-1111-4111-8111-111111111111"
	guard := testGuard("vm", vmID, "claim_isolated_vm")
	claim, err := BuildClaimIsolatedVMScript(ClaimIsolatedVMParams{
		Guard:              guard,
		OrchestratorVMGUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		VMName:             "isolated-vm-444444444444",
		SwitchGUID:         "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		AdapterName:        "private-444444444444", MAC: "02155D010203",
		Metadata: IsolatedVMMetadata{
			PhysicalHostID: strings.Repeat("a", 64), OrchestratorID: orchestratorID,
			NetworkID: "22222222-2222-4222-8222-222222222222", VMID: vmID,
			OwnerMarker: IsolatedOwnerMarkerPrefix + orchestratorID + "/vm/" + vmID,
			HostFence:   1, LifecycleState: "creating", ManagedRoot: `E:\VM`,
			ExpectedVHDPaths: []string{`E:\VM\guest\guest.vhdx`}, NodeName: "vm-444444444444",
			IPv4: "192.168.240.10", MAC: "02155D010203", Incarnation: 1, Generation: 1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{
		"$adapters.Count -ne 1", "SwitchType -ne 'Private'", "StaticMacAddress",
		"Time Synchronization", "DhcpGuard On", "RouterGuard On",
	} {
		if !strings.Contains(claim, wanted) {
			t.Errorf("claim script missing %q", wanted)
		}
	}

	deleteGuard := testGuard("vm", vmID, "delete_isolated_vm")
	deleteScript, err := BuildDeleteIsolatedVMScript(DeleteIsolatedVMParams{
		Guard: deleteGuard, OrchestratorVMGUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		VMName: "isolated-vm-444444444444", ExpectedVMID: vmID,
		ExpectedVMGUID:    "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		ExpectedAdapterID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		ExpectedVHDPath:   `E:\VM\guest\guest.vhdx`, ExpectedVMPath: `E:\VM\guest`,
		DeleteStorage: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{
		"exact VM GUID", "adapter_id", "VM_STORAGE_IDENTITY_MISMATCH",
		"Remove-VM -VM $vm[0]", "VM_STORAGE_IN_USE", "Remove-Item -LiteralPath",
	} {
		if !strings.Contains(deleteScript, wanted) {
			t.Errorf("exact delete script missing %q", wanted)
		}
	}
	if strings.Contains(deleteScript, "Remove-Item -LiteralPath $parent") {
		t.Fatal("exact delete must not remove shared parent storage")
	}
}
