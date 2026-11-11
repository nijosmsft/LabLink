package appliance

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRenderPrivateNetworkdUnitDeterministicAndMACScoped(t *testing.T) {
	spec := PrivateNICSpec{
		NetworkID:     "network/immutable:01",
		MAC:           "02-4C-4C-12-34-56",
		InterfaceName: "eth1",
		Subnet:        netip.MustParsePrefix("192.168.240.0/26"),
	}
	first, err := RenderPrivateNetworkdUnit(spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderPrivateNetworkdUnit(spec)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("render is not deterministic:\nfirst=%#v\nsecond=%#v", first, second)
	}
	if !strings.HasPrefix(first.Path, NetworkdDirectory+"/00-lablink-private-") ||
		!strings.HasSuffix(first.Path, ".network") {
		t.Fatalf("unexpected generated path %q", first.Path)
	}
	for _, want := range []string{
		"MACAddress=02:4c:4c:12:34:56",
		"Address=192.168.240.1/26",
		"DHCP=no",
		"IPv6AcceptRA=no",
		"LinkLocalAddressing=no",
		"DNSDefaultRoute=no",
	} {
		if !strings.Contains(first.Content, want) {
			t.Errorf("rendered unit missing %q:\n%s", want, first.Content)
		}
	}
	for _, forbidden := range []string{"Driver=hv_netvsc", "Gateway=", "DNS=", "IPForward="} {
		if strings.Contains(first.Content, forbidden) {
			t.Errorf("rendered unit unexpectedly contains %q:\n%s", forbidden, first.Content)
		}
	}
}

func TestRenderPrivateNetworkdUnitRequiresLocalUnicastMACAnd26(t *testing.T) {
	tests := []PrivateNICSpec{
		{NetworkID: "n1", MAC: "00:4c:4c:12:34:56", Subnet: netip.MustParsePrefix("192.168.240.0/26")},
		{NetworkID: "n1", MAC: "03:4c:4c:12:34:56", Subnet: netip.MustParsePrefix("192.168.240.0/26")},
		{NetworkID: "n1", MAC: "02:4c:4c:12:34:56", Subnet: netip.MustParsePrefix("192.168.240.0/24")},
	}
	for _, test := range tests {
		if _, err := RenderPrivateNetworkdUnit(test); err == nil {
			t.Errorf("RenderPrivateNetworkdUnit(%+v) succeeded, want error", test)
		}
	}
}

func TestRenderMainNetworkdUnitPreservesDHCPWithoutGenericDriverMatch(t *testing.T) {
	main := MainNICObservation{
		InterfaceName: "eth0",
		MAC:           "00:15:5d:01:02:03",
		AddressSource: MainAddressDHCP,
	}
	unit, err := RenderMainNetworkdUnit(main, DNSObservation{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(unit.Path, NetworkdDirectory+"/00-lablink-main-") {
		t.Fatalf("main unit does not sort before generic networkd files: %q", unit.Path)
	}
	for _, want := range []string{"MACAddress=00:15:5d:01:02:03", "DHCP=yes"} {
		if !strings.Contains(unit.Content, want) {
			t.Errorf("main unit missing %q:\n%s", want, unit.Content)
		}
	}
	if strings.Contains(unit.Content, "hv_netvsc") {
		t.Fatalf("main unit retained generic driver match:\n%s", unit.Content)
	}
	main.MAC = "00-15-5D-01-02-03"
	equivalent, err := RenderMainNetworkdUnit(main, DNSObservation{})
	if err != nil {
		t.Fatal(err)
	}
	if equivalent.Path != unit.Path {
		t.Fatalf("equivalent MAC formatting changed unit path: %q != %q", equivalent.Path, unit.Path)
	}
}

func TestRenderMainNetworkdUnitPreservesStaticAddressesRoutesAndDNS(t *testing.T) {
	main := MainNICObservation{
		InterfaceName: "eth0",
		MAC:           "00:15:5d:01:02:03",
		AddressSource: MainAddressStatic,
		IPv4Addresses: []AddressObservation{
			{Prefix: netip.MustParsePrefix("10.20.30.40/24")},
		},
		DefaultRoutes: []RouteObservation{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Gateway:     netip.MustParseAddr("10.20.30.1"),
			Interface:   "eth0",
			Metric:      100,
		}},
	}
	dns := DNSObservation{Servers: []netip.Addr{netip.MustParseAddr("10.20.30.2")}}
	unit, err := RenderMainNetworkdUnit(main, dns)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Address=10.20.30.40/24",
		"DNS=10.20.30.2",
		"Destination=0.0.0.0/0",
		"Gateway=10.20.30.1",
		"Metric=100",
	} {
		if !strings.Contains(unit.Content, want) {
			t.Errorf("main unit missing %q:\n%s", want, unit.Content)
		}
	}
}

func TestParseAndVerifyPrivateNetworkdLink(t *testing.T) {
	spec := PrivateNICSpec{
		NetworkID:     "net-01",
		MAC:           "02:4c:4c:12:34:56",
		InterfaceName: "eth1",
		Subnet:        netip.MustParsePrefix("192.168.240.0/26"),
	}
	unit, err := RenderPrivateNetworkdUnit(spec)
	if err != nil {
		t.Fatal(err)
	}
	addressJSON := []byte(`[
		{"ifname":"eth1","address":"02:4c:4c:12:34:56","addr_info":[
			{"family":"inet","local":"192.168.240.1","prefixlen":26,"scope":"global"}
		]}
	]`)
	routeJSON := []byte(`[
		{"dst":"192.168.240.0/26","dev":"eth1","protocol":"kernel","table":"main","family":"inet"}
	]`)
	status := "● 3: eth1\n       Network File: " + unit.Path + "\n"
	observation, err := ParseNetworkdLinkObservation("eth1", addressJSON, routeJSON, status)
	if err != nil {
		t.Fatal(err)
	}
	forwarding, err := ParseIPv4Forwarding("0\n")
	if err != nil {
		t.Fatal(err)
	}
	verification, err := VerifyPrePolicyPrivateNIC(spec, observation, forwarding)
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Valid {
		t.Fatalf("verification failed: %+v", verification.Issues)
	}
}

func TestVerifyPrivateNetworkdLinkRejectsGenericFileDHCPDNSAndDefaultRoute(t *testing.T) {
	spec := PrivateNICSpec{
		NetworkID:     "net-01",
		MAC:           "02:4c:4c:12:34:56",
		InterfaceName: "eth1",
		Subnet:        netip.MustParsePrefix("192.168.240.0/26"),
	}
	observation := NetworkdLinkObservation{
		InterfaceName: "eth1",
		MAC:           spec.MAC,
		IPv4Addresses: []AddressObservation{{
			Prefix:  netip.MustParsePrefix("192.168.240.1/26"),
			Dynamic: true,
		}},
		Routes: []RouteObservation{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Interface:   "eth1",
		}},
		DNSServers:           []netip.Addr{netip.MustParseAddr("10.0.0.2")},
		EffectiveNetworkFile: "/run/systemd/network/10-netplan-hyperv.network",
		DHCPLease:            true,
	}
	verification, err := VerifyPrePolicyPrivateNIC(spec, observation, ForwardingObservation{IPv4Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if verification.Valid {
		t.Fatal("verification unexpectedly accepted unsafe private interface")
	}
	fields := make(map[string]bool)
	for _, issue := range verification.Issues {
		fields[issue.Field] = true
	}
	for _, want := range []string{"network_file", "dhcp", "default_route", "dns", "ipv4_forwarding"} {
		if !fields[want] {
			t.Errorf("missing verification issue for %q: %+v", want, verification.Issues)
		}
	}
}
