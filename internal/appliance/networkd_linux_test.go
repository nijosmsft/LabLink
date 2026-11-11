//go:build linux

package appliance

import (
	"net/netip"
	"testing"
)

func TestPrivateNICPlanUsesTargetedNetworkctlCommands(t *testing.T) {
	spec := PrivateNICSpec{
		NetworkID:     "net-01",
		MAC:           "02:4c:4c:12:34:56",
		InterfaceName: "eth1",
		Subnet:        netip.MustParsePrefix("192.168.240.0/26"),
	}
	plan, err := PlanPrivateNICNetworkdApply(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Files) != 1 || len(plan.Commands) < 2 {
		t.Fatalf("incomplete plan: %+v", plan)
	}
	if plan.Commands[0].Path != "networkctl" || plan.Commands[0].Args[0] != "reload" {
		t.Fatalf("first command = %+v, want networkctl reload", plan.Commands[0])
	}
	if plan.Commands[1].Path != "networkctl" ||
		len(plan.Commands[1].Args) != 2 ||
		plan.Commands[1].Args[0] != "reconfigure" ||
		plan.Commands[1].Args[1] != "eth1" {
		t.Fatalf("second command = %+v, want targeted reconfigure", plan.Commands[1])
	}
	for _, command := range plan.Commands {
		if command.Path == "systemctl" {
			t.Fatalf("plan restarts networking globally: %+v", command)
		}
	}
}
