package hyperv

import (
	"strings"
	"testing"

	"github.com/nijosmsft/lablink/internal/cascadeauth"
)

func TestBuildDeleteIsolatedOrchestratorVMScriptUsesExactGUIDAndReplay(t *testing.T) {
	authority := CascadeAuthority{
		OrchestratorID: testOrchID, FrozenGeneration: 2,
		OperationID: testOperationID, PlanRevision: "r1-delete",
		PlanHash: "delete-hash", HostFence: 7, LeaseID: testLeaseID,
		Items: []CascadeAuthorityItem{{
			ResourceType: "orchestrator", ResourceID: testOrchID,
			Action:     cascadeauth.ActionOrchestratorVMDelete,
			Generation: 2,
		}},
	}
	guard := testGuard(
		"orchestrator", testOrchID,
		string(cascadeauth.ActionOrchestratorVMDelete))
	guard.CascadeAuthority = &authority
	script, err := BuildDeleteIsolatedOrchestratorVMScript(
		DeleteIsolatedOrchestratorVMParams{
			Guard: guard, OrchestratorVMGUID: testVMGUID,
			HyperVName:         "isolated-orchestrator-aaaaaaaaaaaa",
			ExpectedGeneration: 2, ManagedRoot: `E:\VM`,
			ExpectedParentVHDX: `E:\Images\ubuntu.vhdx`,
			ForceStop:          true, DeleteStorage: true,
		})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Get-VM -Id $orchestratorVMGUID",
		"action='already_absent'",
		"ORCHESTRATOR_VM_OWNERSHIP_MISMATCH",
		"Remove-VM -VM $vm -Force",
		"CASCADE_AUTHORITY_REJECTED",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("exact orchestrator delete script missing %q", want)
		}
	}
	if strings.Contains(script, "Remove-VM -Name") {
		t.Fatal("orchestrator deletion must not remove a VM by name")
	}
}
