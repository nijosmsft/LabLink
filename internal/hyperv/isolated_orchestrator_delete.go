package hyperv

import (
	"fmt"
	"strings"

	"github.com/nijosmsft/lablink/internal/cascadeauth"
)

type DeleteIsolatedOrchestratorVMParams struct {
	Guard              IsolatedMutationGuard
	OrchestratorVMGUID string
	HyperVName         string
	ExpectedGeneration int64
	ManagedRoot        string
	ExpectedParentVHDX string
	ForceStop          bool
	DeleteStorage      bool
}

func BuildDeleteIsolatedOrchestratorVMScript(
	p DeleteIsolatedOrchestratorVMParams,
) (string, error) {
	if err := validateMutationGuard(p.Guard); err != nil {
		return "", err
	}
	if p.Guard.ResourceType != "orchestrator" ||
		p.Guard.ResourceID != p.Guard.OrchestratorID ||
		p.Guard.Action != string(cascadeauth.ActionOrchestratorVMDelete) {
		return "", fmt.Errorf("mutation guard does not authorize orchestrator VM deletion")
	}
	if err := validateGUID("orchestrator VM", p.OrchestratorVMGUID); err != nil {
		return "", err
	}
	if strings.TrimSpace(p.HyperVName) == "" || p.ExpectedGeneration <= 0 {
		return "", fmt.Errorf("orchestrator name and generation are required")
	}
	guard, err := isolatedMutationGuardPowerShell(p.Guard)
	if err != nil {
		return "", err
	}
	deleteBody, err := buildDeleteVMBody(DeleteVMParams{
		Name: p.HyperVName, ManagedRoot: p.ManagedRoot,
		ForceStop: p.ForceStop, DeleteStorage: p.DeleteStorage,
		ExpectedParentVHDX: p.ExpectedParentVHDX,
		ExpectedVMGUID:     p.OrchestratorVMGUID,
	})
	if err != nil {
		return "", err
	}
	body := PreflightScript() + isolatedHostMetadataPowerShell() +
		isolatedParentGuardPowerShell() + guard + fmt.Sprintf(`
try {
    $orchestratorVMGUID = %s
    $hyperVName = %s
    $expectedGeneration = [int64]%d
    $vmByID = @(Get-VM -Id $orchestratorVMGUID -ErrorAction SilentlyContinue)
    if ($vmByID.Count -eq 0) {
        if (@(Get-VM -Name $hyperVName -ErrorAction SilentlyContinue).Count -ne 0) {
            throw 'ORCHESTRATOR_VM_IDENTITY_MISMATCH: expected GUID is absent but the managed name is occupied'
        }
        $storageDeleted = $false
        if (%s) {
            $rootPath = [IO.Path]::GetFullPath(%s).TrimEnd('\')
            $vmStoragePath = [IO.Path]::GetFullPath((Join-Path $rootPath $hyperVName)).TrimEnd('\')
            if (-not $vmStoragePath.StartsWith($rootPath + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw 'UNSAFE_STORAGE_PATH: replay storage path is outside the managed root'
            }
            if (Test-Path -LiteralPath $vmStoragePath) {
                Remove-Item -LiteralPath $vmStoragePath -Recurse -Force -ErrorAction Stop
                $storageDeleted = $true
            }
        }
        [pscustomobject]@{
            action='already_absent'; orchestrator_id=$guardOrchestratorID
            vm_guid=$orchestratorVMGUID; storage_deleted=$storageDeleted
        } | ConvertTo-Json -Compress
        return
    }
    if ($vmByID.Count -ne 1 -or [string]$vmByID[0].Name -cne $hyperVName) {
        throw 'ORCHESTRATOR_VM_IDENTITY_MISMATCH: exact GUID/name pair changed'
    }
    $metadata = Get-LabLinkIsolatedVMNotes $vmByID[0] %s
    $cascadeItem = Assert-LabLinkParentAllowsMutation $metadata
    if ([string]$metadata.orchestrator_id -cne $guardOrchestratorID -or
        [string]$metadata.vm_guid -cne $orchestratorVMGUID -or
        [int64]$metadata.generation -ne $expectedGeneration -or
        [string]$metadata.managed_root -cne %s -or
        [string]$metadata.owner_marker -cne ('lablink-isolated/' + $guardOrchestratorID)) {
        throw 'ORCHESTRATOR_VM_OWNERSHIP_MISMATCH: persisted ownership metadata changed'
    }
    if ($cascadeItem -and [int64]$cascadeItem.generation -ne $expectedGeneration) {
        throw 'CASCADE_AUTHORITY_REJECTED: orchestrator VM generation is not approved'
    }
%s
} finally {
    $__isolatedGate.Dispose()
}
`, PSLit(normalizedGUIDOrEmpty(p.OrchestratorVMGUID)), PSLit(p.HyperVName),
		p.ExpectedGeneration, PSBool(p.DeleteStorage), PSLit(p.ManagedRoot),
		PSLit(IsolatedOrchestratorMetadataPrefix), PSLit(p.ManagedRoot),
		deleteBody)
	return wrapTagged(body), nil
}
