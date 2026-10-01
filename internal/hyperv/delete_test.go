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
		"Test-PathAtOrWithin $_.Path $vmStoragePath",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("delete script missing %q", want)
		}
	}
	if strings.Contains(script, "Remove-Item -LiteralPath $disk.parent_path") {
		t.Fatal("delete script must never remove a differencing parent")
	}
}

func TestBuildDeleteVMScriptRequiresManagedRootForStorage(t *testing.T) {
	if _, err := BuildDeleteVMScript(DeleteVMParams{Name: "vm", DeleteStorage: true}); err == nil {
		t.Fatal("expected managed_root requirement")
	}
}
