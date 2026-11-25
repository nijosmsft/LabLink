package appliance

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Sanitized native iproute2 outputs retain the omitted fields and address families.
const recordedFullManagementAddresses = `[{"ifindex":2,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"qdisc":"mq","operstate":"UP","group":"default","txqlen":1000,"link_type":"ether","address":"02:00:5e:10:00:01","broadcast":"ff:ff:ff:ff:ff:ff","addr_info":[{"family":"inet","local":"192.0.3.176","prefixlen":23,"metric":100,"broadcast":"192.0.3.255","scope":"global","dynamic":true,"label":"eth0","valid_life_time":2859,"preferred_life_time":2859},{"family":"inet6","local":"fe80::5eff:fe10:1","prefixlen":64,"scope":"link","valid_life_time":4294967295,"preferred_life_time":4294967295}]}]`
const recordedFilteredManagementAddresses = `[{"ifindex":2,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"qdisc":"mq","operstate":"UP","group":"default","txqlen":1000,"addr_info":[{"family":"inet","local":"192.0.3.176","prefixlen":23,"metric":100,"broadcast":"192.0.3.255","scope":"global","dynamic":true,"label":"eth0","valid_life_time":1970,"preferred_life_time":1970}]}]`
const recordedManagementUnit = "[Match]\nDriver=hv_netvsc\nName=eth0\n\n[Network]\nDHCP=ipv4\nLinkLocalAddressing=ipv6\n\n[DHCP]\nRouteMetric=100\nUseMTU=true\n"
const recordedManagementUnitPath = "/run/systemd/network/10-netplan-hotpluggedeth0.network"

type managementCaptureExecutorFunc func(context.Context, string, ...string) (CommandResult, error)

func (f managementCaptureExecutorFunc) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	return f(ctx, name, args...)
}

func readOnlyManagementCaptureCommands(iface string) []string {
	return []string{
		"ip -j address show dev " + iface,
		"ip -j -4 route show table main dev " + iface,
		"ip -j -4 route show default table all",
		"ip -j -4 rule show",
		"networkctl status --no-pager --full " + iface,
		"systemctl is-active --quiet NetworkManager.service",
		"resolvectl dns " + iface,
		"resolvectl domain " + iface,
	}
}

func replayManagementCapture(t *testing.T, addresses string) (managementIPCapture, func()) {
	t.Helper()
	commands := readOnlyManagementCaptureCommands("eth0")
	results := []CommandResult{
		{Stdout: addresses},
		{Stdout: recordedScopedManagementRoutes},
		{Stdout: `[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","protocol":"dhcp","prefsrc":"192.0.3.176","metric":100,"flags":[]}]`},
		{Stdout: `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`},
		{Stdout: "\u25cf 2: eth0\n Network File: " + recordedManagementUnitPath + "\n State: routable (configured)\n Online state: online\n Hardware Address: 02:00:5e:10:00:01\n MTU: 1500 (min: 68, max: 65521)\n DNS: 198.51.100.53\n      203.0.113.53\n Search Domains: example.test\n"},
		{ExitCode: 4},
		{Stdout: "Link 2 (eth0): 198.51.100.53 203.0.113.53"},
		{Stdout: "Link 2 (eth0): example.test"},
	}
	outputs := make(map[string]CommandResult, len(commands)+1)
	for i, command := range commands {
		outputs[command] = results[i]
	}
	outputs["ip -j -4 address show dev eth0 scope global"] = CommandResult{Stdout: recordedFilteredManagementAddresses}
	var calls, globs []string
	reads := 0
	capture := managementIPCapture{
		executor: managementCaptureExecutorFunc(func(_ context.Context, name string, args ...string) (CommandResult, error) {
			command := strings.Join(append([]string{name}, args...), " ")
			calls = append(calls, command)
			if result, ok := outputs[command]; ok {
				return result, nil
			}
			return CommandResult{}, fmt.Errorf("unexpected capture command %q", command)
		}),
		readFile: func(filename string) ([]byte, error) {
			if filename != recordedManagementUnitPath {
				return nil, fmt.Errorf("unexpected capture read %q", filename)
			}
			reads++
			return []byte(recordedManagementUnit), nil
		},
		glob: func(pattern string) ([]string, error) {
			globs = append(globs, pattern)
			return nil, nil
		},
	}
	return capture, func() {
		t.Helper()
		if !reflect.DeepEqual(calls, commands) || reads != 1 {
			t.Errorf("incomplete read-only capture contract: commands=%v, unit reads=%d", calls, reads)
		}
		var wantGlobs []string
		for _, root := range []string{"/etc", "/run", "/usr/lib", "/usr/local/lib"} {
			wantGlobs = append(wantGlobs, path.Join(root, "systemd/network", path.Base(recordedManagementUnitPath)+".d", "*.conf"))
		}
		if !reflect.DeepEqual(globs, wantGlobs) {
			t.Errorf("capture drop-in checks = %v, want %v", globs, wantGlobs)
		}
	}
}

func TestManagementCaptureRecordedProductionPipeline(t *testing.T) {
	for _, tt := range []struct{ name, addresses string }{
		{"native-output", recordedFullManagementAddresses},
		{"global-only-view", strings.Replace(recordedFullManagementAddresses, `"addr_info":[`, `"addr_info":[{"family":"inet","local":"169.254.1.2","prefixlen":16,"scope":"link"},{"family":"inet6","local":"2001:db8::2","prefixlen":64,"scope":"global"},`, 1)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			capture, check := replayManagementCapture(t, tt.addresses)
			observation, original, err := capture.capture(context.Background(), "eth0", "192.0.3.176", []string{"02:00:5e:10:00:02"}, false)
			if err != nil {
				t.Fatal(err)
			}
			check()
			if observation.Main.MAC != "02:00:5e:10:00:01" || observation.Main.AddressSource != MainAddressDHCP ||
				len(observation.Main.IPv4Addresses) != 1 || observation.Main.IPv4Addresses[0].Prefix.String() != "192.0.3.176/23" ||
				observation.MTU != 1500 || len(observation.Routes) != 5 ||
				!sameManagementValues(observation.DNS, []string{"198.51.100.53", "203.0.113.53"}) ||
				!sameManagementValues(observation.Domains, []string{"example.test"}) || original != recordedManagementUnit {
				t.Fatal("complete capture changed the recorded management identity or policy")
			}
			rendered, err := renderManagementIP(original, observation)
			if err != nil || !strings.Contains(rendered, "[Address]\nAddress=192.0.3.176/23\nRouteMetric=100\n") ||
				!strings.Contains(rendered, "LinkLocalAddressing=ipv6") || strings.Count(rendered, "[Route]") != 4 {
				t.Fatalf("complete capture cannot render preserved policy: %v\n%s", err, rendered)
			}
		})
	}
}

func TestManagementCaptureRejectsWrongIdentity(t *testing.T) {
	for _, tt := range []struct {
		name, addresses, expected string
		private                   []string
	}{
		{"wrong-interface", strings.Replace(recordedFullManagementAddresses, `"ifname":"eth0"`, `"ifname":"eth1"`, 1), "192.0.3.176", nil},
		{"missing-mac", recordedFilteredManagementAddresses, "192.0.3.176", nil},
		{"wrong-ipv4", recordedFullManagementAddresses, "192.0.3.177", nil},
		{"private-mac", recordedFullManagementAddresses, "192.0.3.176", []string{"02:00:5e:10:00:01"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			capture, _ := replayManagementCapture(t, tt.addresses)
			if _, _, err := capture.capture(context.Background(), "eth0", tt.expected, tt.private, false); err == nil {
				t.Fatal("capture accepted mismatched management identity")
			}
		})
	}
}

func TestManagementIPReadOnlyFixtureCapture(t *testing.T) {
	if os.Getenv("LABLINK_TEST_MANAGEMENT_CAPTURE") != "1" {
		t.Skip("explicit read-only fixture capture opt-in is required")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("read-only fixture capture requires Linux")
	}
	required := func(suffix string) string {
		t.Helper()
		value := strings.TrimSpace(os.Getenv("LABLINK_TEST_MANAGEMENT_" + suffix))
		if value == "" {
			t.Fatalf("missing fixture identity guard %s", suffix)
		}
		return value
	}
	hostname, err := os.Hostname()
	if err != nil || hostname != required("HOSTNAME") {
		t.Fatal("fixture hostname guard failed")
	}
	machineID, err := os.ReadFile("/etc/machine-id")
	if err != nil || strings.TrimSpace(string(machineID)) != required("MACHINE_ID") {
		t.Fatal("fixture machine-ID guard failed")
	}
	iface := required("INTERFACE")
	if err := validateInterfaceName(iface); err != nil || strings.HasPrefix(iface, "-") {
		t.Fatal("fixture interface guard is invalid")
	}
	expected, err := netip.ParseAddr(required("IPV4"))
	if err != nil || !expected.Is4() || expected.IsLoopback() || expected.IsUnspecified() {
		t.Fatal("fixture IPv4 guard is invalid")
	}
	mac, err := canonicalMAC(required("MAC"), false)
	if err != nil {
		t.Fatal("fixture MAC guard is invalid")
	}
	link, err := net.InterfaceByName(iface)
	if err != nil || !strings.EqualFold(link.HardwareAddr.String(), mac) {
		t.Fatal("fixture MAC guard failed")
	}
	addresses, err := link.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		found = found || err == nil && prefix.Addr() == expected
	}
	if !found {
		t.Fatal("fixture IPv4 guard failed")
	}
	privateMACs := strings.FieldsFunc(required("PRIVATE_MACS"), func(r rune) bool { return r == ',' || r == ' ' })
	if len(privateMACs) == 0 {
		t.Fatal("fixture private-MAC guards are required")
	}
	for _, value := range privateMACs {
		private, err := canonicalMAC(value, false)
		if err != nil || private == mac {
			t.Fatal("fixture private-MAC guard is invalid")
		}
	}
	commands := readOnlyManagementCaptureCommands(iface)
	var calls []string
	guarded := managementIPCapture{
		executor: managementCaptureExecutorFunc(func(ctx context.Context, name string, args ...string) (CommandResult, error) {
			command := strings.Join(append([]string{name}, args...), " ")
			allowed := false
			for _, candidate := range commands {
				allowed = allowed || command == candidate
			}
			if !allowed {
				return CommandResult{}, fmt.Errorf("non-allowlisted fixture command refused: %q", command)
			}
			calls = append(calls, command)
			return (OSCommandExecutor{}).Run(ctx, name, args...)
		}),
		readFile: os.ReadFile, glob: filepath.Glob,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	observation, original, err := guarded.capture(ctx, iface, expected.String(), privateMACs, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, commands) || observation.Main.MAC != mac || observation.Main.AddressSource != MainAddressDHCP {
		t.Fatal("fixture capture did not complete the entire expected DHCP observation")
	}
	if _, err := renderManagementIP(original, observation); err != nil {
		t.Fatalf("read-only capture policy cannot be rendered in memory: %v", err)
	}
	t.Logf("complete read-only capture passed: commands=%d routes=%d mtu=%d dns=%d", len(calls), len(observation.Routes), observation.MTU, len(observation.DNS))
}
