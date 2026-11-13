//go:build linux

package appliance

func PlanMainNICDiscovery() HostNetworkPlan {
	return HostNetworkPlan{Commands: []PlannedCommand{
		{Path: "ip", Args: []string{"-j", "-4", "address", "show"}, Captures: "ipv4_addresses"},
		{Path: "ip", Args: []string{"-j", "-4", "route", "show", "table", "all"}, Captures: "ipv4_routes"},
	}}
}

func PlanMainNICNetworkdGate(main MainNICObservation, dns DNSObservation) (HostNetworkPlan, error) {
	unit, err := RenderMainNetworkdUnit(main, dns)
	if err != nil {
		return HostNetworkPlan{}, err
	}
	return HostNetworkPlan{
		Files: []PlannedFile{{
			Path:    unit.Path,
			Content: unit.Content,
			Mode:    0o644,
		}},
		Commands: []PlannedCommand{
			{Path: "networkctl", Args: []string{"reload"}},
			{Path: "networkctl", Args: []string{"reconfigure", main.InterfaceName}},
			{Path: "networkctl", Args: []string{"status", "--no-pager", "--full", main.InterfaceName}, Captures: "networkctl_status"},
			{Path: "ip", Args: []string{"-j", "-4", "address", "show", "dev", main.InterfaceName}, Captures: "ipv4_addresses"},
			{Path: "ip", Args: []string{"-j", "-4", "route", "show", "table", "all", "dev", main.InterfaceName}, Captures: "ipv4_routes"},
		},
	}, nil
}
