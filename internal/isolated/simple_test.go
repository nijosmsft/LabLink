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

func TestLinuxStaticNetworkMACFormats(t *testing.T) {
	for _, mac := range []string{"02155D000003", "02:15:5d:00:00:03", "02-15-5D-00-00-03"} {
		t.Run(mac, func(t *testing.T) {
			config, err := LinuxStaticNetworkConfig(
				"192.168.240.11", 26, "192.168.240.1", mac, nil)
			if err != nil || !strings.Contains(config, `"02:15:5d:00:00:03"`) {
				t.Fatalf("network config: %q, %v", config, err)
			}
			bootstrap, err := LinuxStaticNetworkBootstrapScript(
				"192.168.240.11", 26, "192.168.240.1", mac, nil)
			if err != nil || !strings.Contains(bootstrap, `expected_mac="02:15:5d:00:00:03"`) {
				t.Fatalf("network bootstrap: %q, %v", bootstrap, err)
			}
		})
	}
	for _, mac := range []string{"", "02155Z000003", "02:15:5d:00:00:03:00:04"} {
		if _, err := LinuxStaticNetworkConfig(
			"192.168.240.11", 26, "192.168.240.1", mac, nil,
		); err == nil {
			t.Errorf("network config accepted invalid MAC %q", mac)
		}
		if _, err := LinuxStaticNetworkBootstrapScript(
			"192.168.240.11", 26, "192.168.240.1", mac, nil,
		); err == nil {
			t.Errorf("network bootstrap accepted invalid MAC %q", mac)
		}
	}
}
