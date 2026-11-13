package appliance

import (
	"net/netip"
	"testing"
)

func TestParseMainNICObservationUsesDefaultRouteAndStableMAC(t *testing.T) {
	addressJSON := []byte(`[
		{"ifname":"lo","address":"00:00:00:00:00:00","addr_info":[
			{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"}
		]},
		{"ifname":"eth0","address":"00:15:5D:01:02:03","addr_info":[
			{"family":"inet","local":"10.20.30.40","prefixlen":24,"scope":"global","flags":["dynamic"]}
		]},
		{"ifname":"eth1","address":"02:4c:4c:12:34:56","addr_info":[]}
	]`)
	routeJSON := []byte(`[
		{"dst":"default","gateway":"10.20.30.1","dev":"eth0","protocol":"dhcp","metric":100,"table":"main","family":"inet"},
		{"dst":"10.20.30.0/24","dev":"eth0","protocol":"kernel","table":"main","family":"inet"},
		{"dst":"10.20.30.1","dev":"eth0","protocol":"dhcp","table":100,"family":"inet"},
		{"dst":"192.168.128.0/17","gateway":"10.20.30.254","dev":"eth0","protocol":"dhcp","table":"main","family":"inet"}
	]`)
	observation, err := ParseMainNICObservation(addressJSON, routeJSON, "/run/systemd/network/10-netplan-hyperv.network")
	if err != nil {
		t.Fatal(err)
	}
	if observation.InterfaceName != "eth0" || observation.MAC != "00:15:5d:01:02:03" {
		t.Fatalf("wrong main identity: %+v", observation)
	}
	if observation.AddressSource != MainAddressDHCP {
		t.Fatalf("address source = %q, want DHCP", observation.AddressSource)
	}
	if len(observation.DefaultRoutes) != 1 || len(observation.NonDefaultRoutes) != 3 {
		t.Fatalf("unexpected route classification: %+v", observation)
	}
}

func TestFindMainRouteConflictsExcludesOnlyLiteralDefault(t *testing.T) {
	main := MainNICObservation{
		InterfaceName: "eth0",
		IPv4Addresses: []AddressObservation{{
			Prefix: netip.MustParsePrefix("10.20.30.40/24"),
		}},
		NonDefaultRoutes: []RouteObservation{
			{Destination: netip.MustParsePrefix("10.20.30.0/24"), Interface: "eth0", Protocol: "kernel"},
			{Destination: netip.MustParsePrefix("192.168.240.0/20"), Interface: "eth0", Protocol: "dhcp"},
			{Destination: netip.MustParsePrefix("192.168.250.1/32"), Interface: "eth0", Table: "100", Protocol: "static"},
			{Destination: netip.MustParsePrefix("0.0.0.0/0"), Interface: "eth0", Protocol: "dhcp"},
		},
	}
	tests := []struct {
		candidate string
		want      int
	}{
		{candidate: "172.20.0.0/26", want: 0},
		{candidate: "10.20.30.0/26", want: 2},
		{candidate: "192.168.240.0/26", want: 1},
		{candidate: "192.168.250.0/26", want: 2},
	}
	for _, test := range tests {
		conflicts := FindMainRouteConflicts(netip.MustParsePrefix(test.candidate), main)
		if len(conflicts) != test.want {
			t.Errorf("%s conflicts = %+v, want %d", test.candidate, conflicts, test.want)
		}
	}
}

func TestDetectMainNetworkChanges(t *testing.T) {
	before := MainNetworkSnapshot{
		Main: MainNICObservation{
			InterfaceName: "eth0",
			MAC:           "00:15:5d:01:02:03",
			IPv4Addresses: []AddressObservation{{Prefix: netip.MustParsePrefix("10.0.0.10/24")}},
			DefaultRoutes: []RouteObservation{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				Gateway:     netip.MustParseAddr("10.0.0.1"),
				Interface:   "eth0",
			}},
		},
		DNS: DNSObservation{Servers: []netip.Addr{netip.MustParseAddr("10.0.0.2")}},
	}

	after := before
	if DetectMainNetworkChanges(before, after).Changed() {
		t.Fatal("identical snapshots reported a change")
	}
	after.Main.IPv4Addresses = []AddressObservation{{Prefix: netip.MustParsePrefix("10.0.0.11/24")}}
	after.DNS.Servers = []netip.Addr{netip.MustParseAddr("10.0.0.3")}
	change := DetectMainNetworkChanges(before, after)
	if !change.IPv4Changed || !change.DNSChanged || !change.Changed() {
		t.Fatalf("missing main IP/DNS change: %+v", change)
	}
	if change.InterfaceChanged || change.MACChanged || change.DefaultRouteChanged {
		t.Fatalf("reported unrelated change: %+v", change)
	}
}

func TestVerifyMainNICPreservedRejectsManagementRouteChange(t *testing.T) {
	expected := MainNICObservation{
		InterfaceName: "eth0",
		MAC:           "00:15:5d:01:02:03",
		AddressSource: MainAddressDHCP,
		IPv4Addresses: []AddressObservation{{Prefix: netip.MustParsePrefix("10.0.0.10/24"), Dynamic: true}},
		DefaultRoutes: []RouteObservation{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Gateway:     netip.MustParseAddr("10.0.0.1"),
			Interface:   "eth0",
		}},
	}

	observed := expected
	if !VerifyMainNICPreserved(expected, observed).Valid {
		t.Fatal("identical main observation failed verification")
	}
	observed.DefaultRoutes = nil
	verification := VerifyMainNICPreserved(expected, observed)
	if verification.Valid || len(verification.Issues) != 1 || verification.Issues[0].Field != "default_route" {
		t.Fatalf("unexpected verification: %+v", verification)
	}
}

func TestVerifyMainNICNetworkdGateChecksEffectiveFile(t *testing.T) {
	expected := MainNICObservation{
		InterfaceName: "eth0",
		MAC:           "00:15:5d:01:02:03",
		AddressSource: MainAddressDHCP,
	}
	observed := expected
	observed.EffectiveNetworkFile = "/run/systemd/network/10-netplan-hyperv.network"
	verification, err := VerifyMainNICNetworkdGate(expected, observed, DNSObservation{})
	if err != nil {
		t.Fatal(err)
	}
	if verification.Valid || len(verification.Issues) != 1 || verification.Issues[0].Field != "network_file" {
		t.Fatalf("unexpected verification: %+v", verification)
	}
	unit, err := RenderMainNetworkdUnit(expected, DNSObservation{})
	if err != nil {
		t.Fatal(err)
	}
	observed.EffectiveNetworkFile = unit.Path
	verification, err = VerifyMainNICNetworkdGate(expected, observed, DNSObservation{})
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Valid {
		t.Fatalf("generated main unit did not verify: %+v", verification)
	}
}
