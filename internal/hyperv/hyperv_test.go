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
