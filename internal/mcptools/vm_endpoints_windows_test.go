package mcptools

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestVMEndpointDiscoveryNativePowerShellUsesOnlyBoundNICAndNeverStartsVMs(t *testing.T) {
	script, err := buildVMEndpointDiscoveryScript([]vmEndpointBinding{
		{NodeName: "running", VMID: "11111111-1111-4111-8111-111111111111", MAC: "02155D000001"},
		{NodeName: "stopped", VMID: "22222222-2222-4222-8222-222222222222", MAC: "02155D000001"},
		{NodeName: "ambiguous", VMID: "33333333-3333-4333-8333-333333333333", VSwitch: "Default Switch"},
	})
	if err != nil {
		t.Fatal(err)
	}
	preface := `
$ErrorActionPreference = 'Stop'
function Get-VM {
    param([guid]$Id)
    $state = if ($Id.ToString().StartsWith('2222')) { 'Off' } else { 'Running' }
    [pscustomobject]@{ Id=$Id; State=$state }
}
function Get-VMNetworkAdapter {
    param($VM)
    $main = [pscustomobject]@{
        MacAddress='02155D000001'; SwitchName='Default Switch'
        IPAddresses=@('192.0.2.20','fe80::1234')
    }
    $private = [pscustomobject]@{
        MacAddress='02155D000002'; SwitchName='private'
        IPAddresses=@('192.168.240.1')
    }
    if ($VM.Id.ToString().StartsWith('3333')) { @($main,$main) }
    else { @($private,$main) }
}
function Start-VM { throw 'endpoint discovery must not start stopped VMs' }
`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", preface+script).CombinedOutput()
	if err != nil {
		t.Fatalf("native endpoint discovery failed: %v\n%s", err, output)
	}
	var observed []vmEndpointObservation
	if err := json.Unmarshal(output, &observed); err != nil {
		t.Fatalf("decode native output: %v\n%s", err, output)
	}
	if len(observed) != 3 || observed[0].NodeName != "running" ||
		observed[0].MAC != "02155D000001" || len(observed[0].Addresses) != 2 ||
		observed[0].Addresses[0] != "192.0.2.20" || observed[1].State != "Off" ||
		!strings.Contains(observed[2].Error, "ambiguous") {
		t.Fatalf("incorrect native VM/NIC discovery: %+v", observed)
	}
}
