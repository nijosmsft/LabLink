package hyperv

import (
	"strings"
	"testing"
)

func TestPSLitEscaping(t *testing.T) {
	cases := map[string]string{
		"plain":   "'plain'",
		"a'b":     "'a''b'",
		"":        "''",
		"C:\\x":   "'C:\\x'",
		"it's it": "'it''s it'",
	}
	for in, want := range cases {
		if got := PSLit(in); got != want {
			t.Errorf("PSLit(%q) = %q, want %q", in, got, want)
		}
	}
	if PSBool(true) != "$true" || PSBool(false) != "$false" {
		t.Errorf("PSBool mismatch")
	}
}

func TestBuildListNicsScript_MgmtDetection(t *testing.T) {
	s := BuildListNicsScript(false, "10.1.2.3")
	if !strings.Contains(s, "$mgmtIP = '10.1.2.3'") {
		t.Errorf("mgmtIP literal not embedded: %s", s)
	}
	if !strings.Contains(s, "$includeVirtual = $false") {
		t.Errorf("expected include_virtual flag false")
	}
	if !strings.Contains(s, "Get-NetAdapter -Physical") {
		t.Errorf("expected physical enumeration branch present")
	}
	if !strings.Contains(s, "is_management_nic") || !strings.Contains(s, "recommended_for_external") {
		t.Errorf("expected management/recommended fields in output")
	}
	// include_virtual=true must flip the embedded flag.
	sv := BuildListNicsScript(true, "")
	if !strings.Contains(sv, "$includeVirtual = $true") {
		t.Errorf("include_virtual=true should embed $true flag")
	}
}

func TestBuildCreateVSwitchScript_MgmtNicGating(t *testing.T) {
	base := CreateVSwitchParams{
		Name: "LabExt", Type: "external", NetAdapter: "Ethernet 2",
		AllowManagementOS: true, IfExists: "reuse", MgmtIP: "10.0.0.5",
	}

	// Remote external defaults to blocking; the script must contain the guard.
	remote := base
	remote.IsRemote = true
	s, err := BuildCreateVSwitchScript(remote)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(s, "MGMT_NIC_BLOCKED") {
		t.Errorf("remote external script must embed MGMT_NIC_BLOCKED guard")
	}
	if !strings.Contains(s, "$allowMgmtDisruption = $false") {
		t.Errorf("expected disruption override to default false")
	}
	if !strings.Contains(s, "AllowManagementOS:$allowMgmtOS") {
		t.Errorf("New-VMSwitch must pass AllowManagementOS")
	}

	// Override flips the embedded flag to $true.
	override := remote
	override.AllowMgmtDisruption = true
	s2, _ := BuildCreateVSwitchScript(override)
	if !strings.Contains(s2, "$allowMgmtDisruption = $true") {
		t.Errorf("override should set $allowMgmtDisruption = $true")
	}
}

// TestBuildCreateVSwitchScript_ReplacePathMgmtNicGating covers the rejection
// finding #1: the management-NIC severance safeguard must also fire on the
// if_exists=replace path, because replacing/removing an existing EXTERNAL
// vSwitch bound to the management NIC can sever the agent connection on a
// remote target — even when the REQUESTED switch is internal/private.
func TestBuildCreateVSwitchScript_ReplacePathMgmtNicGating(t *testing.T) {
	// A replace request for an INTERNAL switch (so the CREATE-path external
	// guard does NOT apply) on a remote target must still embed a replace-path
	// guard that inspects the EXISTING switch's binding against the mgmt NIC.
	internalReplace := CreateVSwitchParams{
		Name: "LabSw", Type: "internal", IfExists: "replace",
		IsRemote: true, MgmtIP: "10.0.0.5",
	}
	s, err := BuildCreateVSwitchScript(internalReplace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The mgmt NIC must be resolved up front (not only inside the external
	// branch) so the replace path can reason about it.
	if !strings.Contains(s, "$mgmtNicDesc") {
		t.Errorf("replace path must resolve the management NIC description up front")
	}
	// The replace branch must guard against removing an existing external
	// switch bound to the management NIC, keyed on the existing switch binding.
	if !strings.Contains(s, "if ($ifExists -eq 'replace')") {
		t.Fatalf("expected a replace branch in the script")
	}
	if !strings.Contains(s, "MGMT_NIC_BLOCKED") {
		t.Errorf("replace path must embed the MGMT_NIC_BLOCKED severance guard")
	}
	if !strings.Contains(s, "$existing.NetAdapterInterfaceDescription -eq $mgmtNicDesc") {
		t.Errorf("replace guard must compare the EXISTING switch binding to the mgmt NIC")
	}
	// Blocked-by-default: the guard predicate must require the override be false.
	if !strings.Contains(s, "$isRemote -and -not $allowMgmtDisruption") {
		t.Errorf("replace guard must block by default (remote, override false)")
	}
	if !strings.Contains(s, "$allowMgmtDisruption = $false") {
		t.Errorf("expected disruption override to default false on replace path")
	}

	// Allowed-with-override: the same params with the override set must flip the
	// embedded flag to $true so the runtime guard is bypassed.
	allowed := internalReplace
	allowed.AllowMgmtDisruption = true
	s2, err := BuildCreateVSwitchScript(allowed)
	if err != nil {
		t.Fatalf("unexpected error with override: %v", err)
	}
	if !strings.Contains(s2, "$allowMgmtDisruption = $true") {
		t.Errorf("override should set $allowMgmtDisruption = $true on the replace path")
	}

	// Local replace (IsRemote=false) must not be gated by the severance check.
	localReplace := internalReplace
	localReplace.IsRemote = false
	if _, err := BuildCreateVSwitchScript(localReplace); err != nil {
		t.Errorf("local replace should build without error: %v", err)
	}
}

func TestBuildCreateVSwitchScript_Validation(t *testing.T) {
	if _, err := BuildCreateVSwitchScript(CreateVSwitchParams{Name: "x", Type: "bogus"}); err == nil {
		t.Errorf("expected error for invalid type")
	}
	if _, err := BuildCreateVSwitchScript(CreateVSwitchParams{Name: "x", Type: "external"}); err == nil {
		t.Errorf("expected error: external requires net_adapter")
	}
	// allow_management_os=false on a remote external switch is blocked w/o override.
	_, err := BuildCreateVSwitchScript(CreateVSwitchParams{
		Name: "x", Type: "external", NetAdapter: "nic0",
		AllowManagementOS: false, IsRemote: true,
	})
	if err == nil || !strings.Contains(err.Error(), "MGMT_OS_BLOCKED") {
		t.Errorf("expected MGMT_OS_BLOCKED, got %v", err)
	}
	// Internal switch needs no adapter and is fine locally.
	if _, err := BuildCreateVSwitchScript(CreateVSwitchParams{Name: "iSw", Type: "internal"}); err != nil {
		t.Errorf("internal switch should build: %v", err)
	}
}

func TestBuildCreateVMScript_Completeness(t *testing.T) {
	// Exactly-one VHD rule.
	if _, err := BuildCreateVMScript(CreateVMParams{Name: "vm", VMLocation: "D:\\vm"}); err == nil {
		t.Errorf("expected error when no VHD provided")
	}
	if _, err := BuildCreateVMScript(CreateVMParams{Name: "vm", VMLocation: "D:\\vm", VHDPath: "a.vhdx", NewVHDPath: "b.vhdx"}); err == nil {
		t.Errorf("expected error when both VHD options provided")
	}
	// vm_location required unless use_host_defaults.
	if _, err := BuildCreateVMScript(CreateVMParams{Name: "vm", VHDPath: "a.vhdx"}); err == nil {
		t.Errorf("expected error: vm_location required unless use_host_defaults")
	}

	s, err := BuildCreateVMScript(CreateVMParams{
		Name: "win01", VMLocation: "D:\\VMs", NewVHDPath: "D:\\VMs\\win01.vhdx",
		NewVHDSizeGB: 60, MemoryMB: 4096, CPUCount: 4, VSwitch: "LabExt",
		ISOPath: "D:\\iso\\win.iso", SecureBoot: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"Generation = 2",
		"Set-VMFirmware -VMName $name -EnableSecureBoot On -SecureBootTemplate $secureBootTemplate",
		"$secureBootTemplate = 'MicrosoftWindows'",
		"Where-Object { $_.Path -eq $isoPath }", // deterministic DVD by ISO path
		"VM_EXISTS",
		"INSUFFICIENT_SPACE",
		"VHD_IN_USE",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("create_vm script missing %q", want)
		}
	}

	// Dynamic memory policy wires min/max/buffer.
	sd, _ := BuildCreateVMScript(CreateVMParams{
		Name: "vm", VMLocation: "D:\\VMs", VHDPath: "a.vhdx",
		DynamicMemory: true, DynamicMinMB: 1024, DynamicMaxMB: 8192, DynamicBufferPct: 20,
	})
	if !strings.Contains(sd, "DynamicMemoryEnabled = $true") || !strings.Contains(sd, "$memArgs.MinimumBytes") {
		t.Errorf("dynamic-memory policy not wired: %s", sd)
	}
}

func TestParseVSwitchesAndNICs(t *testing.T) {
	vs, err := ParseVSwitches(`[{"name":"ExternalSwitch","type":"External","net_adapter":"Intel","allow_management_os":true}]`)
	if err != nil || len(vs) != 1 || vs[0].Name != "ExternalSwitch" {
		t.Fatalf("ParseVSwitches: %v %+v", err, vs)
	}
	// Single object (PowerShell collapses one-element arrays).
	one, err := ParseVSwitches(`{"name":"S","type":"Internal","net_adapter":null,"allow_management_os":false}`)
	if err != nil || len(one) != 1 || one[0].Type != "Internal" {
		t.Fatalf("ParseVSwitches single: %v %+v", err, one)
	}
	nics, err := ParseNICs("noise before\n" + `[{"name":"Ethernet 2","is_management_nic":true,"recommended_for_external":false}]` + "\ntrailing")
	if err != nil || len(nics) != 1 || !nics[0].IsManagementNIC {
		t.Fatalf("ParseNICs: %v %+v", err, nics)
	}
}
