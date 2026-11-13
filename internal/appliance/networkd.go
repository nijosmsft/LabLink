package appliance

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type NetworkdLinkObservation struct {
	InterfaceName        string
	MAC                  string
	IPv4Addresses        []AddressObservation
	Routes               []RouteObservation
	DNSServers           []netip.Addr
	EffectiveNetworkFile string
	DHCPLease            bool
}

type ForwardingObservation struct {
	IPv4Enabled bool
}

type VerificationIssue struct {
	Field   string
	Message string
}

type PrivateNICVerification struct {
	Valid  bool
	Issues []VerificationIssue
}

func ParseNetworkdLinkObservation(interfaceName string, addressJSON, routeJSON []byte, networkctlStatus string) (NetworkdLinkObservation, error) {
	links, err := parseIPLinks(addressJSON)
	if err != nil {
		return NetworkdLinkObservation{}, err
	}
	link, ok := links[interfaceName]
	if !ok {
		return NetworkdLinkObservation{}, fmt.Errorf("interface %q is absent from address observations", interfaceName)
	}
	mac, err := canonicalMAC(link.MAC, false)
	if err != nil {
		return NetworkdLinkObservation{}, err
	}
	routes, err := ParseIPv4Routes(routeJSON)
	if err != nil {
		return NetworkdLinkObservation{}, err
	}
	observation := NetworkdLinkObservation{
		InterfaceName: interfaceName,
		MAC:           mac,
		IPv4Addresses: link.Addresses,
	}
	for _, route := range routes {
		if route.Interface == interfaceName {
			observation.Routes = append(observation.Routes, route)
		}
	}
	for _, line := range strings.Split(networkctlStatus, "\n") {
		line = strings.TrimSpace(strings.TrimLeft(line, "● "))
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "Network File":
			if value != "n/a" {
				observation.EffectiveNetworkFile = value
			}
		case "DNS":
			for _, token := range strings.Fields(value) {
				if address, parseErr := netip.ParseAddr(token); parseErr == nil && address.Is4() {
					observation.DNSServers = append(observation.DNSServers, address.Unmap())
				}
			}
		case "DHCP Server", "DHCP4 Server":
			observation.DHCPLease = value != "" && value != "n/a"
		}
	}
	for _, address := range observation.IPv4Addresses {
		observation.DHCPLease = observation.DHCPLease || address.Dynamic
	}
	return observation, nil
}

func ParseIPv4Forwarding(value string) (ForwardingObservation, error) {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || (parsed != 0 && parsed != 1) {
		return ForwardingObservation{}, fmt.Errorf("invalid net.ipv4.ip_forward value %q", strings.TrimSpace(value))
	}
	return ForwardingObservation{IPv4Enabled: parsed == 1}, nil
}

func VerifyPrivateNIC(spec PrivateNICSpec, observation NetworkdLinkObservation) (PrivateNICVerification, error) {
	unit, err := RenderPrivateNetworkdUnit(spec)
	if err != nil {
		return PrivateNICVerification{}, err
	}
	expectedMAC, _ := canonicalMAC(spec.MAC, true)
	expectedGateway, _ := PrivateGateway(spec.Subnet)
	expectedPrefix := netip.PrefixFrom(expectedGateway, 26)
	result := PrivateNICVerification{Valid: true}
	addIssue := func(field, message string) {
		result.Valid = false
		result.Issues = append(result.Issues, VerificationIssue{Field: field, Message: message})
	}
	if spec.InterfaceName != "" && observation.InterfaceName != spec.InterfaceName {
		addIssue("interface", fmt.Sprintf("got %q, want %q", observation.InterfaceName, spec.InterfaceName))
	}
	if !strings.EqualFold(observation.MAC, expectedMAC) {
		addIssue("mac", fmt.Sprintf("got %q, want %q", observation.MAC, expectedMAC))
	}
	if observation.EffectiveNetworkFile != unit.Path {
		addIssue("network_file", fmt.Sprintf("effective file %q, want %q", observation.EffectiveNetworkFile, unit.Path))
	}
	if len(observation.IPv4Addresses) != 1 || observation.IPv4Addresses[0].Prefix != expectedPrefix {
		addIssue("addresses", fmt.Sprintf("expected only %s", expectedPrefix))
	} else if observation.IPv4Addresses[0].Dynamic {
		addIssue("dhcp", "expected address is marked dynamic")
	}
	if observation.DHCPLease {
		addIssue("dhcp", "private interface has an active DHCP lease")
	}
	for _, route := range observation.Routes {
		if route.Destination.Bits() == 0 {
			addIssue("default_route", "private interface has an IPv4 default route")
		}
	}
	if len(observation.DNSServers) != 0 {
		addIssue("dns", "private interface has link-scoped DNS servers")
	}
	return result, nil
}

func VerifyPrePolicyPrivateNIC(spec PrivateNICSpec, observation NetworkdLinkObservation, forwarding ForwardingObservation) (PrivateNICVerification, error) {
	result, err := VerifyPrivateNIC(spec, observation)
	if err != nil {
		return result, err
	}
	if forwarding.IPv4Enabled {
		result.Valid = false
		result.Issues = append(result.Issues, VerificationIssue{
			Field:   "ipv4_forwarding",
			Message: "IPv4 forwarding is enabled before isolation policy activation",
		})
	}
	return result, nil
}
