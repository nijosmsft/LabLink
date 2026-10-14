package hyperv

import (
	"strings"
	"testing"
)

func TestBuildDeleteVMScriptSafeguards(t *testing.T) {
	script, err := BuildDeleteVMScript(DeleteVMParams{
		Name: "vm1", ManagedRoot: `E:\VM`, DryRun: false,
		ForceStop: true, DeleteStorage: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"VM_RUNNING",
		"UNSAFE_STORAGE_PATH",
		"Stop-VM -Name $name -TurnOff -Force",
		"Remove-VMSnapshot",
		"parent_path is informational only",
		"Test-PathAtOrWithin $diskPath $vmStoragePath",
		"VM_PARENT_MISMATCH",
		"Get-VHDParentChain",
		"persisted_base_matches",
		"role = if ($isOS) { 'os' } else { 'data' }",
		"$mustValidateStorage",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("delete script missing %q", want)
		}
	}
	if strings.Contains(script, "Remove-Item -LiteralPath $disk.parent_path") {
		t.Fatal("delete script must never remove a differencing parent")
	}
	parentCheck := strings.Index(script, `throw "VM_PARENT_MISMATCH`)
	storageCheck := strings.Index(script, `throw "UNSAFE_STORAGE_PATH`)
	stop := strings.Index(script, "Stop-VM -Name $name")
	if parentCheck < 0 || storageCheck < 0 || stop < 0 || parentCheck > stop || storageCheck > stop {
		t.Fatal("managed identity/storage validation must complete before a running VM is stopped")
	}
	if strings.Contains(script, "$_.role -eq 'data' -and -not $_.persisted_base_matches") {
		t.Fatal("unrelated data-disk parents must not participate in persisted OS base identity")
	}
}

func TestBuildDeleteVMScriptRequiresManagedRootForStorage(t *testing.T) {
	if _, err := BuildDeleteVMScript(DeleteVMParams{Name: "vm", DeleteStorage: true}); err == nil {
		t.Fatal("expected managed_root requirement")
	}
}

func TestBuildDeleteVMScriptWalksCheckpointChainToPersistedBase(t *testing.T) {
	script, err := BuildDeleteVMScript(DeleteVMParams{
		Name: "linux", ManagedRoot: `E:\VM`, ExpectedParentVHDX: `E:\Images\base.vhdx`,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Get-VMFirmware", "BootOrder", "Get-VHDParentChain $diskPath",
		"$chain[-1].Equals((Get-CanonicalPath $expectedParentVHDX)",
		"VHD_PARENT_CYCLE",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("checkpoint-aware deletion validation missing %q", want)
		}
	}
}

func TestBuildDeleteVMScriptSeparatesDataDiskStorageFromOSIdentity(t *testing.T) {
	script, err := BuildDeleteVMScript(DeleteVMParams{
		Name: "linux", ManagedRoot: `E:\VM`, ExpectedParentVHDX: `E:\Images\base.vhdx`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "(-not $isOS) -or") {
		t.Fatal("data disks are not excluded from persisted base identity")
	}
	if !strings.Contains(script, "-not ($disks | Where-Object { -not $_.storage_deletable })") {
		t.Fatal("data disks are not independently included in storage safety validation")
	}
}
