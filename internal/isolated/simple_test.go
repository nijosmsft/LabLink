package isolated

import (
	"net/netip"
	"strings"
	"testing"
)

func TestSimplePrivateNetworkHelpers(t *testing.T) {
	prefix, err := PrivateSubnet(0)
	if err != nil {
		t.Fatal(err)
	}
	if prefix.String() != "192.168.240.0/26" ||
		PrivateGateway(prefix).String() != "192.168.240.1" {
		t.Fatalf("unexpected private network: %s %s", prefix, PrivateGateway(prefix))
	}
	address, err := GuestAddress(prefix, FirstGuestAddressOffset)
	if err != nil || address.String() != "192.168.240.10" {
		t.Fatalf("unexpected first guest: %s %v", address, err)
	}
	conflicts := FindPrivateRouteConflicts(prefix, nil)
	if len(conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %+v", conflicts)
	}
	if _, err := GuestAddress(netip.Prefix{}, 10); err == nil {
		t.Fatal("invalid prefix accepted")
	}
}

func TestStaticNetworkScripts(t *testing.T) {
	windows, err := WindowsStaticNetworkScript(
		"192.168.240.10", 26, "192.168.240.1",
		"02155D000002", []string{"10.0.0.53"})
	if err != nil || !strings.Contains(windows, "Dhcp Disabled") {
		t.Fatalf("Windows script: %v %s", err, windows)
	}
	linux, err := LinuxStaticNetworkConfig(
		"192.168.240.11", 26, "192.168.240.1",
		"02155D000003", []string{"10.0.0.53"})
	if err != nil || !strings.Contains(linux, "dhcp4: false") {
		t.Fatalf("Linux network config: %v %s", err, linux)
	}
}
