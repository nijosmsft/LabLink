//go:build linux

package appliance

func PlanMainDNSDiscovery(interfaceName string) HostNetworkPlan {
	return HostNetworkPlan{Commands: []PlannedCommand{
		{Path: "resolvectl", Args: []string{"dns", interfaceName}, Captures: "resolvectl_dns", Optional: true},
		{Path: "resolvectl", Args: []string{"domain", interfaceName}, Captures: "resolvectl_domains", Optional: true},
		{Path: "cat", Args: []string{"/run/systemd/resolve/resolv.conf"}, Captures: "resolved_resolv_conf", Optional: true},
	}}
}
