package appliance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

type MainAddressSource string

const (
	MainAddressDHCP   MainAddressSource = "dhcp"
	MainAddressStatic MainAddressSource = "static"
)

type AddressObservation struct {
	Prefix  netip.Prefix
	Dynamic bool
	Scope   string
}

type RouteObservation struct {
	Destination netip.Prefix
	Gateway     netip.Addr
	Interface   string
	Table       string
	Protocol    string
	Metric      int
}

type MainNICObservation struct {
	InterfaceName        string
	MAC                  string
	IPv4Addresses        []AddressObservation
	DefaultRoutes        []RouteObservation
	NonDefaultRoutes     []RouteObservation
	AddressSource        MainAddressSource
	EffectiveNetworkFile string
}

type RouteConflict struct {
	Kind      string
	Prefix    netip.Prefix
	Interface string
	Table     string
	Protocol  string
}

type MainNetworkSnapshot struct {
	Main MainNICObservation
	DNS  DNSObservation
}

type MainNetworkChange struct {
	InterfaceChanged    bool
	MACChanged          bool
	IPv4Changed         bool
	DefaultRouteChanged bool
	DNSChanged          bool
}

type MainNICVerification struct {
	Valid  bool
	Issues []VerificationIssue
}

func (c MainNetworkChange) Changed() bool {
	return c.InterfaceChanged || c.MACChanged || c.IPv4Changed || c.DefaultRouteChanged || c.DNSChanged
}

func ParseMainNICObservation(addressJSON, routeJSON []byte, effectiveNetworkFile string) (MainNICObservation, error) {
	links, err := parseIPLinks(addressJSON)
	if err != nil {
		return MainNICObservation{}, err
	}
	routes, err := ParseIPv4Routes(routeJSON)
	if err != nil {
		return MainNICObservation{}, err
	}

	defaults := make([]RouteObservation, 0)
	for _, route := range routes {
		if route.Destination.Bits() == 0 && route.Interface != "" {
			defaults = append(defaults, route)
		}
	}
	if len(defaults) == 0 {
		return MainNICObservation{}, fmt.Errorf("no IPv4 default route identifies the main interface")
	}
	sort.SliceStable(defaults, func(i, j int) bool {
		if defaults[i].Metric != defaults[j].Metric {
			return defaults[i].Metric < defaults[j].Metric
		}
		return defaults[i].Interface < defaults[j].Interface
	})
	mainInterface := defaults[0].Interface
	link, ok := links[mainInterface]
	if !ok {
		return MainNICObservation{}, fmt.Errorf("default-route interface %q is absent from address observations", mainInterface)
	}
	mac, err := canonicalMAC(link.MAC, false)
	if err != nil {
		return MainNICObservation{}, fmt.Errorf("main interface %q: %w", mainInterface, err)
	}

	mainDefaults := make([]RouteObservation, 0)
	nonDefaults := make([]RouteObservation, 0)
	for _, route := range routes {
		if route.Destination.Bits() == 0 {
			if route.Interface == mainInterface {
				mainDefaults = append(mainDefaults, route)
			}
			continue
		}
		nonDefaults = append(nonDefaults, route)
	}
	source := MainAddressStatic
	for _, address := range link.Addresses {
		if address.Dynamic {
			source = MainAddressDHCP
			break
		}
	}
	return MainNICObservation{
		InterfaceName:        mainInterface,
		MAC:                  mac,
		IPv4Addresses:        link.Addresses,
		DefaultRoutes:        mainDefaults,
		NonDefaultRoutes:     nonDefaults,
		AddressSource:        source,
		EffectiveNetworkFile: strings.TrimSpace(effectiveNetworkFile),
	}, nil
}

func ParseIPv4Routes(data []byte) ([]RouteObservation, error) {
	var raw []struct {
		Destination string          `json:"dst"`
		Gateway     string          `json:"gateway"`
		Interface   string          `json:"dev"`
		Table       json.RawMessage `json:"table"`
		Protocol    string          `json:"protocol"`
		Metric      int             `json:"metric"`
		Family      string          `json:"family"`
		Type        string          `json:"type"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse IPv4 route JSON: %w", err)
	}
	routes := make([]RouteObservation, 0, len(raw))
	for _, item := range raw {
		if item.Family != "" && item.Family != "inet" {
			continue
		}
		destination, err := parseRoutePrefix(item.Destination)
		if err != nil {
			return nil, err
		}
		var gateway netip.Addr
		if item.Gateway != "" {
			gateway, err = netip.ParseAddr(item.Gateway)
			if err != nil || !gateway.Is4() {
				return nil, fmt.Errorf("invalid IPv4 route gateway %q", item.Gateway)
			}
		}
		routes = append(routes, RouteObservation{
			Destination: destination,
			Gateway:     gateway,
			Interface:   item.Interface,
			Table:       rawJSONText(item.Table),
			Protocol:    item.Protocol,
			Metric:      item.Metric,
		})
	}
	return routes, nil
}

func FindMainRouteConflicts(candidate netip.Prefix, main MainNICObservation) []RouteConflict {
	if !candidate.IsValid() || !candidate.Addr().Is4() {
		return []RouteConflict{{Kind: "invalid_candidate", Prefix: candidate}}
	}
	candidate = candidate.Masked()
	conflicts := make([]RouteConflict, 0)
	for _, address := range main.IPv4Addresses {
		if prefixesOverlap(candidate, address.Prefix) {
			conflicts = append(conflicts, RouteConflict{
				Kind:      "main_address",
				Prefix:    address.Prefix.Masked(),
				Interface: main.InterfaceName,
			})
		}
	}
	for _, route := range main.NonDefaultRoutes {
		if route.Destination.Bits() == 0 {
			continue
		}
		if prefixesOverlap(candidate, route.Destination) {
			conflicts = append(conflicts, RouteConflict{
				Kind:      "non_default_route",
				Prefix:    route.Destination.Masked(),
				Interface: route.Interface,
				Table:     route.Table,
				Protocol:  route.Protocol,
			})
		}
	}
	sort.Slice(conflicts, func(i, j int) bool {
		if conflicts[i].Prefix.String() != conflicts[j].Prefix.String() {
			return conflicts[i].Prefix.String() < conflicts[j].Prefix.String()
		}
		return conflicts[i].Kind < conflicts[j].Kind
	})
	return conflicts
}

func DetectMainNetworkChanges(before, after MainNetworkSnapshot) MainNetworkChange {
	return MainNetworkChange{
		InterfaceChanged:    before.Main.InterfaceName != after.Main.InterfaceName,
		MACChanged:          !strings.EqualFold(before.Main.MAC, after.Main.MAC),
		IPv4Changed:         !sameStrings(addressStrings(before.Main.IPv4Addresses), addressStrings(after.Main.IPv4Addresses)),
		DefaultRouteChanged: !sameStrings(routeStrings(before.Main.DefaultRoutes), routeStrings(after.Main.DefaultRoutes)),
		DNSChanged:          !sameStrings(dnsStrings(before.DNS), dnsStrings(after.DNS)),
	}
}

func VerifyMainNICPreserved(expected, observed MainNICObservation) MainNICVerification {
	result := MainNICVerification{Valid: true}
	addIssue := func(field, message string) {
		result.Valid = false
		result.Issues = append(result.Issues, VerificationIssue{Field: field, Message: message})
	}
	if expected.InterfaceName != observed.InterfaceName {
		addIssue("interface", fmt.Sprintf("got %q, want %q", observed.InterfaceName, expected.InterfaceName))
	}
	if !strings.EqualFold(expected.MAC, observed.MAC) {
		addIssue("mac", fmt.Sprintf("got %q, want %q", observed.MAC, expected.MAC))
	}
	if expected.AddressSource != observed.AddressSource {
		addIssue("address_source", fmt.Sprintf("got %q, want %q", observed.AddressSource, expected.AddressSource))
	}
	if !sameStrings(addressStrings(expected.IPv4Addresses), addressStrings(observed.IPv4Addresses)) {
		addIssue("addresses", "main IPv4 addresses changed during networkd activation")
	}
	if !sameStrings(routeStrings(expected.DefaultRoutes), routeStrings(observed.DefaultRoutes)) {
		addIssue("default_route", "main IPv4 default route changed during networkd activation")
	}
	return result
}

func VerifyMainNICNetworkdGate(expected, observed MainNICObservation, dns DNSObservation) (MainNICVerification, error) {
	result := VerifyMainNICPreserved(expected, observed)
	unit, err := RenderMainNetworkdUnit(expected, dns)
	if err != nil {
		return MainNICVerification{}, err
	}
	if observed.EffectiveNetworkFile != unit.Path {
		result.Valid = false
		result.Issues = append(result.Issues, VerificationIssue{
			Field:   "network_file",
			Message: fmt.Sprintf("effective file %q, want %q", observed.EffectiveNetworkFile, unit.Path),
		})
	}
	return result, nil
}

type ipLinkObservation struct {
	MAC       string
	Addresses []AddressObservation
}

func parseIPLinks(data []byte) (map[string]ipLinkObservation, error) {
	var raw []struct {
		Name    string `json:"ifname"`
		Address string `json:"address"`
		Info    []struct {
			Family    string   `json:"family"`
			Local     string   `json:"local"`
			PrefixLen int      `json:"prefixlen"`
			Scope     string   `json:"scope"`
			Dynamic   bool     `json:"dynamic"`
			Flags     []string `json:"flags"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse IPv4 address JSON: %w", err)
	}
	result := make(map[string]ipLinkObservation, len(raw))
	for _, item := range raw {
		link := ipLinkObservation{MAC: item.Address}
		for _, info := range item.Info {
			if info.Family != "inet" {
				continue
			}
			address, err := netip.ParseAddr(info.Local)
			if err != nil || !address.Is4() || info.PrefixLen < 0 || info.PrefixLen > 32 {
				return nil, fmt.Errorf("invalid IPv4 address observation %q/%d on %q", info.Local, info.PrefixLen, item.Name)
			}
			dynamic := info.Dynamic
			for _, flag := range info.Flags {
				dynamic = dynamic || flag == "dynamic"
			}
			link.Addresses = append(link.Addresses, AddressObservation{
				Prefix:  netip.PrefixFrom(address, info.PrefixLen),
				Dynamic: dynamic,
				Scope:   info.Scope,
			})
		}
		result[item.Name] = link
	}
	return result, nil
}

func parseRoutePrefix(value string) (netip.Prefix, error) {
	if value == "" || value == "default" {
		return netip.MustParsePrefix("0.0.0.0/0"), nil
	}
	if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Is4() {
		return prefix.Masked(), nil
	}
	if address, err := netip.ParseAddr(value); err == nil && address.Is4() {
		return netip.PrefixFrom(address, 32), nil
	}
	return netip.Prefix{}, fmt.Errorf("invalid IPv4 route destination %q", value)
}

func rawJSONText(value json.RawMessage) string {
	value = bytes.TrimSpace(value)
	if len(value) == 0 {
		return ""
	}
	var text string
	if json.Unmarshal(value, &text) == nil {
		return text
	}
	return string(value)
}

func prefixesOverlap(left, right netip.Prefix) bool {
	if !left.IsValid() || !right.IsValid() || left.Addr().BitLen() != right.Addr().BitLen() {
		return false
	}
	left = left.Masked()
	right = right.Masked()
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}

func addressStrings(addresses []AddressObservation) []string {
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, address.Prefix.String())
	}
	sort.Strings(values)
	return values
}

func routeStrings(routes []RouteObservation) []string {
	values := make([]string, 0, len(routes))
	for _, route := range routes {
		values = append(values, fmt.Sprintf("%s|%s|%s|%s|%d", route.Destination, route.Gateway, route.Interface, route.Table, route.Metric))
	}
	sort.Strings(values)
	return values
}

func dnsStrings(observation DNSObservation) []string {
	values := make([]string, 0, len(observation.Servers)+len(observation.SearchDomains))
	for _, server := range observation.Servers {
		values = append(values, "server:"+server.String())
	}
	for _, domain := range observation.SearchDomains {
		values = append(values, "search:"+domain)
	}
	return values
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
