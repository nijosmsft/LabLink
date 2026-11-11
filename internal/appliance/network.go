package appliance

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strings"
)

const NetworkdDirectory = "/etc/systemd/network"

var unitSlugPattern = regexp.MustCompile(`[^a-z0-9_.-]+`)

type PlannedCommand struct {
	Path     string
	Args     []string
	Captures string
	Optional bool
}

type PlannedFile struct {
	Path    string
	Content string
	Mode    uint32
	Remove  bool
}

type HostNetworkPlan struct {
	Files    []PlannedFile
	Commands []PlannedCommand
}

type PrivateNICSpec struct {
	NetworkID     string
	MAC           string
	InterfaceName string
	Subnet        netip.Prefix
}

type NetworkdUnit struct {
	Path    string
	Content string
}

func PrivateGateway(subnet netip.Prefix) (netip.Addr, error) {
	subnet = subnet.Masked()
	if !subnet.Addr().Is4() || subnet.Bits() != 26 {
		return netip.Addr{}, fmt.Errorf("private subnet %q must be an IPv4 /26", subnet)
	}
	raw := subnet.Addr().As4()
	value := binary.BigEndian.Uint32(raw[:])
	if value == ^uint32(0) {
		return netip.Addr{}, fmt.Errorf("private subnet %q has no gateway address", subnet)
	}
	value++
	binary.BigEndian.PutUint32(raw[:], value)
	return netip.AddrFrom4(raw), nil
}

func RenderPrivateNetworkdUnit(spec PrivateNICSpec) (NetworkdUnit, error) {
	if strings.TrimSpace(spec.NetworkID) == "" {
		return NetworkdUnit{}, fmt.Errorf("network ID is empty")
	}
	mac, err := canonicalMAC(spec.MAC, true)
	if err != nil {
		return NetworkdUnit{}, err
	}
	gateway, err := PrivateGateway(spec.Subnet)
	if err != nil {
		return NetworkdUnit{}, err
	}
	unitPath := path.Join(NetworkdDirectory, networkdUnitName("00-lablink-private", spec.NetworkID))
	content := fmt.Sprintf(`[Match]
MACAddress=%s

[Network]
Address=%s/26
DHCP=no
IPv6AcceptRA=no
LinkLocalAddressing=no
DNSDefaultRoute=no
`, mac, gateway)
	return NetworkdUnit{Path: unitPath, Content: content}, nil
}

func RenderMainNetworkdUnit(main MainNICObservation, dns DNSObservation) (NetworkdUnit, error) {
	mac, err := canonicalMAC(main.MAC, false)
	if err != nil {
		return NetworkdUnit{}, err
	}
	if strings.TrimSpace(main.InterfaceName) == "" {
		return NetworkdUnit{}, fmt.Errorf("main interface name is empty")
	}

	var content strings.Builder
	fmt.Fprintf(&content, "[Match]\nMACAddress=%s\n\n[Network]\n", mac)
	switch main.AddressSource {
	case MainAddressDHCP:
		content.WriteString("DHCP=yes\n")
	case MainAddressStatic:
		addresses := append([]AddressObservation(nil), main.IPv4Addresses...)
		sort.Slice(addresses, func(i, j int) bool {
			return addresses[i].Prefix.String() < addresses[j].Prefix.String()
		})
		if len(addresses) == 0 {
			return NetworkdUnit{}, fmt.Errorf("static main interface has no IPv4 addresses")
		}
		for _, address := range addresses {
			fmt.Fprintf(&content, "Address=%s\n", address.Prefix)
		}
		for _, server := range dns.Servers {
			fmt.Fprintf(&content, "DNS=%s\n", server)
		}
		for _, domain := range dns.SearchDomains {
			fmt.Fprintf(&content, "Domains=%s\n", domain)
		}
	default:
		return NetworkdUnit{}, fmt.Errorf("unsupported main address source %q", main.AddressSource)
	}

	if main.AddressSource == MainAddressStatic {
		routes := append([]RouteObservation(nil), main.DefaultRoutes...)
		sort.Slice(routes, func(i, j int) bool {
			if routes[i].Metric != routes[j].Metric {
				return routes[i].Metric < routes[j].Metric
			}
			return routes[i].Gateway.Compare(routes[j].Gateway) < 0
		})
		for _, route := range routes {
			if !route.Gateway.Is4() {
				continue
			}
			content.WriteString("\n[Route]\nDestination=0.0.0.0/0\n")
			fmt.Fprintf(&content, "Gateway=%s\n", route.Gateway)
			if route.Metric != 0 {
				fmt.Fprintf(&content, "Metric=%d\n", route.Metric)
			}
		}
	}

	unitPath := path.Join(NetworkdDirectory, networkdUnitName("00-lablink-main", mac))
	return NetworkdUnit{Path: unitPath, Content: content.String()}, nil
}

func networkdUnitName(prefix, immutableID string) string {
	lower := strings.ToLower(strings.TrimSpace(immutableID))
	slug := strings.Trim(unitSlugPattern.ReplaceAllString(lower, "-"), "-.")
	if slug == "" {
		slug = "id"
	}
	if len(slug) > 36 {
		slug = slug[:36]
	}
	sum := sha256.Sum256([]byte(immutableID))
	return fmt.Sprintf("%s-%s-%x.network", prefix, slug, sum[:6])
}

func canonicalMAC(value string, requireLocal bool) (string, error) {
	hardware, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(hardware) != 6 {
		return "", fmt.Errorf("invalid Ethernet MAC %q", value)
	}
	if hardware[0]&1 != 0 {
		return "", fmt.Errorf("MAC %q is multicast", value)
	}
	if requireLocal && hardware[0]&2 == 0 {
		return "", fmt.Errorf("private NIC MAC %q must be locally administered", value)
	}
	return strings.ToLower(hardware.String()), nil
}
