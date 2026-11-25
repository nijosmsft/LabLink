package appliance

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const managementAddresses = `[{"ifname":"eth0","address":"02:00:5e:20:00:01","mtu":1450,"addr_info":[{"family":"inet","local":"198.18.22.219","prefixlen":20,"scope":"global","dynamic":true}]}]`
const managementRoutes = `[
{"dst":"default","gateway":"198.18.16.1","dev":"eth0","protocol":"dhcp","metric":123},
{"dst":"198.18.16.0/20","dev":"eth0","protocol":"kernel","scope":"link","prefsrc":"198.18.22.219"},
{"dst":"198.18.16.1","dev":"eth0","protocol":"dhcp","scope":"link","prefsrc":"198.18.22.219","metric":123},
{"dst":"198.19.0.0/16","gateway":"198.18.16.1","dev":"eth0","protocol":"dhcp","metric":124,"flags":["onlink"]}
]`

const recordedScopedManagementRoutes = `[
{"dst":"default","gateway":"192.0.2.1","protocol":"dhcp","prefsrc":"192.0.3.176","metric":100,"flags":[]},
{"dst":"198.51.100.53","gateway":"192.0.2.1","protocol":"dhcp","prefsrc":"192.0.3.176","metric":100,"flags":[]},
{"dst":"203.0.113.53","gateway":"192.0.2.1","protocol":"dhcp","prefsrc":"192.0.3.176","metric":100,"flags":[]},
{"dst":"192.0.2.0/23","protocol":"kernel","scope":"link","prefsrc":"192.0.3.176","metric":100,"flags":[]},
{"dst":"192.0.2.1","protocol":"dhcp","scope":"link","prefsrc":"192.0.3.176","metric":100,"flags":[]}
]`
const recordedManagementAddresses = `[{"ifname":"eth0","address":"02:00:5e:10:00:01","mtu":1500,"addr_info":[{"family":"inet","local":"192.0.3.176","prefixlen":23,"scope":"global","dynamic":true}]}]`

func TestManagementPinObservesRecordedScopedRoutesWithoutDevice(t *testing.T) {
	if _, err := ParseMainNICObservation([]byte(recordedManagementAddresses), []byte(recordedScopedManagementRoutes), ""); err == nil {
		t.Fatal("unscoped parser must not guess an omitted interface")
	}
	routes, err := normalizeScopedManagementRoutes([]byte(recordedScopedManagementRoutes), "eth0")
	if err != nil {
		t.Fatal(err)
	}
	observation, err := observeManagementIP([]byte(recordedManagementAddresses), routes,
		"198.51.100.53 203.0.113.53", "example.test", "192.0.3.176", nil)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Main.InterfaceName != "eth0" || len(observation.Main.DefaultRoutes) != 1 ||
		len(observation.Main.NonDefaultRoutes) != 4 || len(observation.Routes) != 5 {
		t.Fatalf("recorded scoped routes were not captured completely: %+v", observation.Main)
	}
	link, err := ParseNetworkdLinkObservation("eth0", []byte(recordedManagementAddresses), routes,
		"Network File: /run/systemd/network/10-netplan-hotpluggedeth0.network")
	if err != nil || len(link.Routes) != 5 {
		t.Fatalf("networkd observation lost scoped routes: %+v, %v", link, err)
	}
	rendered, err := renderManagementIP("[Match]\nName=eth0\n[Network]\nDHCP=ipv4\nLinkLocalAddressing=ipv6\n", observation)
	if err != nil || !strings.Contains(rendered, "[Address]\nAddress=192.0.3.176/23\nRouteMetric=100\n") ||
		strings.Count(rendered, "[Route]") != 4 {
		t.Fatalf("recorded routes/connected-prefix metric were not preserved: %v\n%s", err, rendered)
	}
	if _, err := observeManagementIP([]byte(recordedManagementAddresses), routes,
		"198.51.100.53", "", "192.0.3.176", []string{"02005e100001"}); err == nil {
		t.Fatal("scoped normalization bypassed the private-NIC guard")
	}
}

func TestManagementPinScopedRoutesPreserveFieldsAndValidation(t *testing.T) {
	input := strings.Replace(recordedScopedManagementRoutes, `"metric":100`, `"metric":100,"mtu":1400`, 1)
	routes, err := normalizeScopedManagementRoutes([]byte(input), "eth0")
	if err != nil {
		t.Fatal(err)
	}
	var before, after []map[string]any
	if err := json.Unmarshal([]byte(input), &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(routes, &after); err != nil {
		t.Fatal(err)
	}
	for _, route := range before {
		route["dev"] = "eth0"
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("normalization changed route fields other than the omitted device")
	}
	if _, err := observeManagementIP([]byte(recordedManagementAddresses), routes,
		"198.51.100.53", "", "192.0.3.176", nil); err == nil ||
		!strings.Contains(err.Error(), `unsupported DHCP route setting "mtu"`) {
		t.Fatalf("normalization bypassed unsupported-route validation: %v", err)
	}
}

func TestManagementPinScopedRoutesRejectWrongDevices(t *testing.T) {
	for _, tt := range []struct {
		name, routes, iface string
	}{
		{"wrong-default", strings.Replace(recordedScopedManagementRoutes, `"dst":"default"`, `"dst":"default","dev":"eth1"`, 1), "eth0"},
		{"private-nondefault", strings.Replace(recordedScopedManagementRoutes, `"dst":"192.0.2.0/23"`, `"dst":"192.0.2.0/23","dev":"eth1"`, 1), "eth0"},
		{"no-scope", recordedScopedManagementRoutes, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := normalizeScopedManagementRoutes([]byte(tt.routes), tt.iface); err == nil {
				t.Fatal("invalid interface-scoped observation accepted")
			}
		})
	}
	if _, err := normalizeScopedManagementRoutes([]byte(managementRoutes), "eth0"); err != nil {
		t.Fatalf("matching explicit route devices should remain supported: %v", err)
	}
}

func TestManagementPinCopiesIPv6PolicyAndExactDHCPConfiguration(t *testing.T) {
	observation, err := observeManagementIP([]byte(managementAddresses), []byte(managementRoutes),
		"Link 2 (eth0): 198.18.16.1 2001:db8::53", "Link 2 (eth0): lab.example.test ~corp.example.test ~.",
		"198.18.22.219", []string{"024c4c123456"})
	if err != nil {
		t.Fatal(err)
	}
	original := "[Match]\nDriver=hv_netvsc\n\n[Network]\nDHCP=yes\nIPv6AcceptRA=yes\nLinkLocalAddressing=ipv6\nAddress=2001:db8::2/64\n\n[DHCPv4]\nUseMTU=true\n"
	rendered, err := renderManagementIP(original, observation)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"MACAddress=02:00:5e:20:00:01", "DHCP=ipv6", "IPv6AcceptRA=yes", "LinkLocalAddressing=ipv6",
		"Address=2001:db8::2/64", "Address=198.18.22.219/20", "MTUBytes=1450",
		"DNS=198.18.16.1 2001:db8::53", "Domains=lab.example.test ~corp.example.test ~.",
		"Destination=0.0.0.0/0\nMetric=123\nTable=main\nGateway=198.18.16.1",
		"Destination=198.18.16.1/32", "PreferredSource=198.18.22.219", "Scope=link",
		"Destination=198.19.0.0/16\nMetric=124", "GatewayOnLink=yes",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("missing %q:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "Driver=") || strings.Contains(rendered, "eth1") {
		t.Fatal("candidate is not restricted to the management MAC")
	}
	rendered, err = renderManagementIP(strings.Replace(original, "DHCP=yes", "DHCP=ipv4", 1), observation)
	if err != nil || !strings.Contains(rendered, "DHCP=no") {
		t.Fatalf("IPv4-only DHCP should remain IPv4-only: %v", err)
	}
}

func TestManagementPinPreservesConnectedPrefixMetric(t *testing.T) {
	const addresses = recordedManagementAddresses
	for _, tt := range []struct {
		name, metricJSON string
		wantMetric       int
	}{
		{"nonzero", `,"metric":100`, 100},
		{"explicit-zero", `,"metric":0`, 0},
		{"implicit-zero", "", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			routes := fmt.Sprintf(`[
{"dst":"default","gateway":"192.0.2.1","dev":"eth0","protocol":"dhcp","metric":100},
{"dst":"192.0.2.1/32","dev":"eth0","protocol":"kernel","scope":"link","prefsrc":"192.0.3.176","metric":75},
{"dst":"192.0.2.0/23","dev":"eth0","protocol":"kernel","scope":"link","prefsrc":"192.0.3.176"%s}
]`, tt.metricJSON)
			observation, err := observeManagementIP([]byte(addresses), []byte(routes),
				"Link 2 (eth0): 192.0.2.1", "", "192.0.3.176", nil)
			if err != nil {
				t.Fatal(err)
			}
			rendered, err := renderManagementIP("[Match]\nName=eth0\n[Network]\nDHCP=ipv4\n[DHCPv4]\nRouteMetric=777\n", observation)
			if err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf("[Address]\nAddress=192.0.3.176/23\nRouteMetric=%d\n", tt.wantMetric)
			if !strings.Contains(rendered, want) {
				t.Errorf("missing connected-prefix metric on static address %q:\n%s", want, rendered)
			}
			if strings.Count(rendered, "Address=192.0.3.176/23") != 1 ||
				strings.Contains(rendered, "Destination=192.0.2.0/23") {
				t.Errorf("connected prefix must be generated once by the address:\n%s", rendered)
			}
		})
	}
}

func TestManagementPinRejectsWrongNICStubDNSAndUnsupportedRouting(t *testing.T) {
	for _, tt := range []struct {
		name, addresses, routes, dns, expected string
		private                                []string
	}{
		{"private", managementAddresses, managementRoutes, "198.18.16.1", "198.18.22.219", []string{"02005E200001"}},
		{"wrong-endpoint", managementAddresses, managementRoutes, "198.18.16.1", "198.19.240.1", nil},
		{"stub-dns", managementAddresses, managementRoutes, "127.0.0.53", "198.18.22.219", nil},
		{"missing-dns", managementAddresses, managementRoutes, "", "198.18.22.219", nil},
		{"other-interface", managementAddresses, strings.Replace(managementRoutes, `"dev":"eth0"`, `"dev":"eth1"`, 1), "198.18.16.1", "198.18.22.219", nil},
		{"unsupported-protocol", managementAddresses, strings.ReplaceAll(managementRoutes, `"dhcp"`, `"redirect"`), "198.18.16.1", "198.18.22.219", nil},
		{"multiple-addresses", strings.Replace(managementAddresses, `"addr_info":[`, `"addr_info":[{"family":"inet","local":"198.19.240.1","prefixlen":26},`, 1), managementRoutes, "198.18.16.1", "198.18.22.219", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := observeManagementIP([]byte(tt.addresses), []byte(tt.routes), tt.dns, "", tt.expected, tt.private); err == nil {
				t.Fatal("unsafe observation accepted")
			}
		})
	}
}

func TestManagementPinRollsBackEveryFailedApplyStage(t *testing.T) {
	failed, rollbackFailed := errors.New("apply failure"), errors.New("rollback failure")
	for stage := 0; stage < 3; stage++ {
		calls := []int{}
		step := func(n int) func() error {
			return func() error {
				calls = append(calls, n)
				if n == stage {
					return failed
				}
				return nil
			}
		}
		err := applyManagementIP(step(0), step(1), step(2), func() error {
			calls = append(calls, 3)
			return rollbackFailed
		})
		if !errors.Is(err, failed) || !errors.Is(err, rollbackFailed) || len(calls) != stage+2 || calls[len(calls)-1] != 3 {
			t.Fatalf("stage %d: calls %v, error %v", stage, calls, err)
		}
	}
	rolledBack := false
	ok := func() error { return nil }
	if err := applyManagementIP(ok, ok, ok, func() error { rolledBack = true; return nil }); err != nil || rolledBack {
		t.Fatalf("successful apply rolled back: %v", err)
	}
}
