//go:build linux

package appliance

func PlanPrivateNICNetworkdApply(spec PrivateNICSpec) (HostNetworkPlan, error) {
	unit, err := RenderPrivateNetworkdUnit(spec)
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
			{Path: "networkctl", Args: []string{"reconfigure", spec.InterfaceName}},
			{Path: "networkctl", Args: []string{"status", "--no-pager", "--full", spec.InterfaceName}, Captures: "networkctl_status"},
			{Path: "ip", Args: []string{"-j", "-4", "address", "show", "dev", spec.InterfaceName}, Captures: "ipv4_addresses"},
			{Path: "ip", Args: []string{"-j", "-4", "route", "show", "table", "all", "dev", spec.InterfaceName}, Captures: "ipv4_routes"},
			{Path: "sysctl", Args: []string{"-n", "net.ipv4.ip_forward"}, Captures: "ipv4_forwarding"},
		},
	}, nil
}

func PlanPrivateNICNetworkdRemoval(spec PrivateNICSpec) (HostNetworkPlan, error) {
	unit, err := RenderPrivateNetworkdUnit(spec)
	if err != nil {
		return HostNetworkPlan{}, err
	}
	return HostNetworkPlan{
		Files: []PlannedFile{{Path: unit.Path, Remove: true}},
		Commands: []PlannedCommand{
			{Path: "networkctl", Args: []string{"reload"}},
		},
	}, nil
}

func PlanPrivateNICNetworkdVerification(spec PrivateNICSpec) HostNetworkPlan {
	return HostNetworkPlan{Commands: []PlannedCommand{
		{Path: "networkctl", Args: []string{"status", "--no-pager", "--full", spec.InterfaceName}, Captures: "networkctl_status"},
		{Path: "ip", Args: []string{"-j", "-4", "address", "show", "dev", spec.InterfaceName}, Captures: "ipv4_addresses"},
		{Path: "ip", Args: []string{"-j", "-4", "route", "show", "table", "all", "dev", spec.InterfaceName}, Captures: "ipv4_routes"},
	}}
}
