package appliance

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

// Keep capture dependencies read-only so the production path can be replayed.
type managementIPCapture struct {
	executor CommandExecutor
	readFile func(string) ([]byte, error)
	glob     func(string) ([]string, error)
}

func (c managementIPCapture) command(ctx context.Context, name string, args ...string) (string, error) {
	result, err := c.executor.Run(ctx, name, args...)
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		return "", commandFailure(name, result)
	}
	return result.Stdout, nil
}

// Filter addresses locally: ip's family/scope filters can omit link-layer MAC
// metadata. The complete link remains bound to the explicitly queried interface.
func globalManagementAddressJSON(data []byte, iface string) ([]byte, error) {
	var links []map[string]json.RawMessage
	if err := json.Unmarshal(data, &links); err != nil {
		return nil, err
	}
	if len(links) != 1 || links[0] == nil {
		return nil, fmt.Errorf("management address query must return exactly the scoped interface")
	}
	var name string
	if err := json.Unmarshal(links[0]["ifname"], &name); err != nil || name != iface {
		return nil, fmt.Errorf("management address interface does not match scoped interface %q", iface)
	}
	var addresses []json.RawMessage
	if err := json.Unmarshal(links[0]["addr_info"], &addresses); err != nil {
		return nil, err
	}
	global := make([]json.RawMessage, 0, len(addresses))
	for _, raw := range addresses {
		var address struct {
			Family string `json:"family"`
			Scope  string `json:"scope"`
		}
		if err := json.Unmarshal(raw, &address); err != nil {
			return nil, err
		}
		if address.Family == "inet" && address.Scope == "global" {
			global = append(global, raw)
		}
	}
	filtered, err := json.Marshal(global)
	if err != nil {
		return nil, err
	}
	links[0]["addr_info"] = filtered
	return json.Marshal(links)
}

func (c managementIPCapture) capture(ctx context.Context, iface, expected string, privateMACs []string, fullStatic bool) (managementObservation, string, error) {
	var empty managementObservation
	if err := validateInterfaceName(iface); err != nil || strings.HasPrefix(iface, "-") {
		return empty, "", fmt.Errorf("unsupported management interface name %q", iface)
	}
	addresses, err := c.command(ctx, "ip", "-j", "address", "show", "dev", iface)
	if err != nil {
		return empty, "", err
	}
	addressJSON, err := globalManagementAddressJSON([]byte(addresses), iface)
	if err != nil {
		return empty, "", err
	}
	routes, err := c.command(ctx, "ip", "-j", "-4", "route", "show", "table", "main", "dev", iface)
	if err != nil {
		return empty, "", err
	}
	routeJSON, err := normalizeScopedManagementRoutes([]byte(routes), iface)
	if err != nil {
		return empty, "", err
	}
	main, err := ParseMainNICObservation(addressJSON, routeJSON, "")
	if err != nil {
		return empty, "", err
	}
	endpointPresent := false
	for _, address := range main.IPv4Addresses {
		endpointPresent = endpointPresent || address.Prefix.Addr().String() == expected
	}
	if !endpointPresent {
		return empty, "", fmt.Errorf("management IPv4 differs from the authenticated endpoint")
	}
	for _, mac := range privateMACs {
		if compactManagementMAC(main.MAC) == compactManagementMAC(mac) {
			return empty, "", fmt.Errorf("refusing to pin a private NIC")
		}
	}
	if main.AddressSource == MainAddressStatic && !fullStatic {
		return managementObservation{Main: main}, "", nil
	}
	if len(main.IPv4Addresses) != 1 {
		return empty, "", fmt.Errorf("multiple management IPv4 addresses are unsupported; keeping DHCP")
	}
	defaults, err := c.command(ctx, "ip", "-j", "-4", "route", "show", "default", "table", "all")
	if err != nil {
		return empty, "", err
	}
	var defaultRoutes []managementRoute
	if err := json.Unmarshal([]byte(defaults), &defaultRoutes); err != nil {
		return empty, "", err
	}
	for _, route := range defaultRoutes {
		table, err := managementRouteTable(route.Table)
		if err != nil || table != "main" || route.Device != iface {
			return empty, "", fmt.Errorf("multiple management interfaces or policy routing are unsupported")
		}
	}
	rules, err := c.command(ctx, "ip", "-j", "-4", "rule", "show")
	if err != nil {
		return empty, "", err
	}
	var policy []struct {
		Table json.RawMessage `json:"table"`
	}
	if err := json.Unmarshal([]byte(rules), &policy); err != nil {
		return empty, "", err
	}
	if len(policy) != 3 || strings.Trim(string(policy[0].Table), `"`) != "local" ||
		strings.Trim(string(policy[1].Table), `"`) != "main" ||
		strings.Trim(string(policy[2].Table), `"`) != "default" {
		return empty, "", fmt.Errorf("custom IPv4 policy routing is unsupported")
	}
	status, err := c.command(ctx, "networkctl", "status", "--no-pager", "--full", iface)
	if err != nil {
		return empty, "", err
	}
	link, err := ParseNetworkdLinkObservation(iface, addressJSON, routeJSON, status)
	if err != nil {
		return empty, "", err
	}
	unit := link.EffectiveNetworkFile
	if !(strings.HasPrefix(unit, "/run/systemd/network/") || strings.HasPrefix(unit, "/etc/systemd/network/")) ||
		path.Ext(unit) != ".network" || strings.ContainsAny(unit, "\r\n") {
		return empty, "", fmt.Errorf("management NIC is not owned by a supported networkd unit")
	}
	for _, root := range []string{"/etc", "/run", "/usr/lib", "/usr/local/lib"} {
		dropins, err := c.glob(path.Join(root, "systemd/network", path.Base(unit)+".d", "*.conf"))
		if err != nil || len(dropins) != 0 {
			return empty, "", fmt.Errorf("networkd drop-ins are unsupported; keeping DHCP")
		}
	}
	active, err := c.executor.Run(ctx, "systemctl", "is-active", "--quiet", "NetworkManager.service")
	if err != nil || active.ExitCode == 0 {
		return empty, "", fmt.Errorf("NetworkManager ownership cannot be excluded")
	}
	original, err := c.readFile(unit)
	if err != nil {
		return empty, "", err
	}
	dns, err := c.command(ctx, "resolvectl", "dns", iface)
	if err != nil {
		return empty, "", err
	}
	domains, err := c.command(ctx, "resolvectl", "domain", iface)
	if err != nil {
		return empty, "", err
	}
	observation, err := observeManagementIP(addressJSON, routeJSON, dns, domains, expected, privateMACs)
	return observation, string(original), err
}
