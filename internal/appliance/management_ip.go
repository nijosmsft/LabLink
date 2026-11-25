package appliance

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const ManagementIPCapability = "orchestrator_management_ipv4_pin_v1"

const managementUnit = "/etc/systemd/network/00-00-lablink-management-ip.network"

type managementRoute struct {
	Destination string          `json:"dst"`
	Gateway     string          `json:"gateway"`
	Device      string          `json:"dev"`
	Protocol    string          `json:"protocol"`
	Scope       string          `json:"scope"`
	Source      string          `json:"prefsrc"`
	Table       json.RawMessage `json:"table"`
	Metric      int             `json:"metric"`
	Type        string          `json:"type"`
	Flags       []string        `json:"flags"`
	Nexthops    json.RawMessage `json:"nexthops"`
}

type managementObservation struct {
	Main    MainNICObservation
	MTU     int
	Routes  []managementRoute
	DNS     []string
	Domains []string
}

func sameManagementValues(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	sort.Strings(a)
	sort.Strings(b)
	return slices.Equal(a, b)
}

// Only use for the successful "ip ... route show ... dev <iface>" query, which
// may omit dev from every row. Keep raw fields for downstream safety validation.
func normalizeScopedManagementRoutes(routes []byte, iface string) ([]byte, error) {
	if err := validateInterfaceName(iface); err != nil || strings.HasPrefix(iface, "-") {
		return nil, fmt.Errorf("unsupported management interface name %q", iface)
	}
	var scoped []map[string]json.RawMessage
	if err := json.Unmarshal(routes, &scoped); err != nil {
		return nil, err
	}
	device := json.RawMessage(strconv.Quote(iface))
	for _, route := range scoped {
		if route == nil {
			return nil, fmt.Errorf("invalid management route")
		}
		if raw, present := route["dev"]; present {
			var observed string
			if err := json.Unmarshal(raw, &observed); err != nil || observed != iface {
				return nil, fmt.Errorf("management route interface does not match scoped interface %q", iface)
			}
		} else {
			route["dev"] = device
		}
	}
	return json.Marshal(scoped)
}

func observeManagementIP(addresses, routes []byte, dns, domains, expected string, privateMACs []string) (managementObservation, error) {
	var result managementObservation
	main, err := ParseMainNICObservation(addresses, routes, "")
	if err != nil {
		return result, err
	}
	for _, mac := range privateMACs {
		if strings.EqualFold(compactManagementMAC(mac), compactManagementMAC(main.MAC)) {
			return result, fmt.Errorf("management interface matches a private NIC")
		}
	}
	if len(main.IPv4Addresses) != 1 || main.IPv4Addresses[0].Prefix.Addr().String() != expected {
		return result, fmt.Errorf("management NIC must have exactly the authenticated endpoint IPv4 %s", expected)
	}
	var links []struct {
		Name string `json:"ifname"`
		MTU  int    `json:"mtu"`
	}
	if err := json.Unmarshal(addresses, &links); err != nil {
		return result, err
	}
	for _, link := range links {
		if link.Name == main.InterfaceName {
			result.MTU = link.MTU
		}
	}
	if result.MTU < 576 || result.MTU > 65535 {
		return result, fmt.Errorf("management MTU is unavailable or unsupported")
	}
	if err := json.Unmarshal(routes, &result.Routes); err != nil {
		return result, err
	}
	var rawRoutes []map[string]json.RawMessage
	if err := json.Unmarshal(routes, &rawRoutes); err != nil {
		return result, err
	}
	gateway := false
	for i, route := range result.Routes {
		if route.Device != main.InterfaceName {
			return result, fmt.Errorf("ambiguous management route interface")
		}
		if len(route.Nexthops) != 0 || route.Type != "" && route.Type != "unicast" {
			return result, fmt.Errorf("multipath or non-unicast management routing is unsupported")
		}
		if route.Protocol != "dhcp" && route.Protocol != "kernel" && route.Protocol != "static" {
			return result, fmt.Errorf("unsupported management route protocol %q", route.Protocol)
		}
		if route.Protocol == "dhcp" {
			for key := range rawRoutes[i] {
				if !slices.Contains([]string{"dst", "gateway", "dev", "protocol", "scope", "prefsrc", "table", "metric", "type", "flags", "nexthops", "family", "expires"}, key) {
					return result, fmt.Errorf("unsupported DHCP route setting %q", key)
				}
			}
			if route.Destination != "default" {
				if _, err := parseRoutePrefix(route.Destination); err != nil {
					return result, fmt.Errorf("unsupported DHCP route destination %q", route.Destination)
				}
			}
			for _, value := range []string{route.Gateway, route.Source} {
				if value != "" {
					ip, err := netip.ParseAddr(value)
					if err != nil || !ip.Is4() {
						return result, fmt.Errorf("invalid DHCP route IPv4 %q", value)
					}
				}
			}
			if route.Scope != "" && route.Scope != "global" && route.Scope != "link" {
				return result, fmt.Errorf("unsupported DHCP route scope %q", route.Scope)
			}
			if _, err := managementRouteTable(route.Table); err != nil {
				return result, err
			}
			for _, flag := range route.Flags {
				if flag != "onlink" {
					return result, fmt.Errorf("unsupported DHCP route flag %q", flag)
				}
			}
		}
		gateway = gateway || route.Destination == "default" && route.Gateway != ""
	}
	if !gateway {
		return result, fmt.Errorf("management default gateway is unavailable")
	}
	for _, value := range resolvectlLinkValues(dns, main.InterfaceName) {
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.IsLoopback() || ip.IsUnspecified() {
			return result, fmt.Errorf("management DNS %q is not an upstream resolver", value)
		}
		result.DNS = append(result.DNS, ip.String())
	}
	if len(result.DNS) == 0 {
		return result, fmt.Errorf("management upstream DNS is unavailable")
	}
	for _, domain := range resolvectlLinkValues(domains, main.InterfaceName) {
		name := strings.TrimPrefix(domain, "~")
		if name != "." && !validDNSDomain(strings.TrimSuffix(name, ".")) {
			return result, fmt.Errorf("unsupported management DNS domain %q", domain)
		}
		result.Domains = append(result.Domains, domain)
	}
	result.Main = main
	return result, nil
}

func compactManagementMAC(mac string) string {
	return strings.ToLower(strings.NewReplacer(":", "", "-", "").Replace(mac))
}

func managementRouteTable(raw json.RawMessage) (string, error) {
	value := strings.Trim(string(raw), `"`)
	if value == "" || value == "main" || value == "254" {
		return "main", nil
	}
	if n, err := strconv.ParseUint(value, 10, 32); err == nil && n > 0 {
		return value, nil
	}
	return "", fmt.Errorf("unsupported DHCP routing table %q", value)
}

// Copy the effective unit rather than reconstructing IPv6/RA/link-local policy.
// The earlier MAC-specific unit leaves the original and every private NIC intact.
func renderManagementIP(original string, observed managementObservation) (string, error) {
	var out strings.Builder
	fmt.Fprintf(&out, "# LabLink accepted-risk IPv4 stopgap; original unit is unchanged.\n[Match]\nMACAddress=%s\n", observed.Main.MAC)
	section, dhcp := "", ""
	for _, line := range strings.Split(original, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasSuffix(trimmed, `\`) {
			return "", fmt.Errorf("continued networkd directives are unsupported")
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = trimmed
		}
		if section == "[Match]" || section == "" {
			continue
		}
		key, value, found := strings.Cut(trimmed, "=")
		if section == "[Network]" && found && strings.TrimSpace(key) == "DHCP" {
			dhcp = strings.TrimSpace(value)
		}
		out.WriteString(line + "\n")
	}
	switch dhcp {
	case "yes", "true":
		dhcp = "ipv6"
	case "ipv4":
		dhcp = "no"
	default:
		return "", fmt.Errorf("effective networkd unit does not own DHCP4")
	}
	fmt.Fprintf(&out, "\n[Link]\nMTUBytes=%d\n\n[Network]\nDHCP=%s\nDNS=%s\n",
		observed.MTU, dhcp, strings.Join(observed.DNS, " "))
	if len(observed.Domains) != 0 {
		fmt.Fprintf(&out, "Domains=%s\n", strings.Join(observed.Domains, " "))
	}
	address := observed.Main.IPv4Addresses[0].Prefix
	prefixMetric := 0
	for _, route := range observed.Routes {
		prefix, err := parseRoutePrefix(route.Destination)
		if err == nil && route.Protocol == "kernel" && route.Gateway == "" && prefix == address.Masked() {
			prefixMetric = route.Metric
			break
		}
	}
	// networkd's [Address] RouteMetric preserves the kernel-generated prefix route.
	fmt.Fprintf(&out, "\n[Address]\nAddress=%s\nRouteMetric=%d\n", address, prefixMetric)
	for _, route := range observed.Routes {
		if route.Protocol != "dhcp" {
			continue
		}
		table, err := managementRouteTable(route.Table)
		if err != nil {
			return "", err
		}
		destination := route.Destination
		prefix, err := parseRoutePrefix(destination)
		if err != nil {
			return "", err
		}
		destination = prefix.String()
		fmt.Fprintf(&out, "\n[Route]\nDestination=%s\nMetric=%d\nTable=%s\n", destination, route.Metric, table)
		if route.Gateway != "" {
			fmt.Fprintf(&out, "Gateway=%s\n", route.Gateway)
		}
		if route.Source != "" {
			fmt.Fprintf(&out, "PreferredSource=%s\n", route.Source)
		}
		if route.Scope != "" {
			fmt.Fprintf(&out, "Scope=%s\n", route.Scope)
		}
		if slices.Contains(route.Flags, "onlink") {
			out.WriteString("GatewayOnLink=yes\n")
		}
	}
	return out.String(), nil
}

func applyManagementIP(write, apply, verify, rollback func() error) error {
	for _, step := range []func() error{write, apply, verify} {
		if err := step(); err != nil {
			return errors.Join(err, rollback())
		}
	}
	return nil
}
