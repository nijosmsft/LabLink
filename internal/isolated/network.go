package isolated

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"strings"
)

var privateAddressPool = netip.MustParsePrefix("192.168.240.0/20")

const (
	PrivateNetworkPrefixBits   = 26
	PrivateSubnetCount         = 1 << (PrivateNetworkPrefixBits - 20)
	FirstGuestAddressOffset    = 10
	LastGuestAddressOffset     = 62
	MaxNetworksPerOrchestrator = 16
	MaxVMsPerOrchestrator      = 100
)

type RouteConflictObservation struct {
	Candidate netip.Prefix
	Route     RouteObservation
}

type RouteObservation struct {
	DestinationPrefix string `json:"destination_prefix"`
	NextHop           string `json:"next_hop"`
	InterfaceAlias    string `json:"interface_alias"`
	RouteMetric       int    `json:"route_metric"`
}

func FindPrivateRouteConflicts(
	candidate netip.Prefix,
	routes []RouteObservation,
) []RouteConflictObservation {
	if !candidate.IsValid() {
		return []RouteConflictObservation{{Candidate: candidate}}
	}

	var conflicts []RouteConflictObservation
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(route.DestinationPrefix))
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 {
			continue
		}
		if candidate.Overlaps(prefix.Masked()) {
			conflicts = append(conflicts, RouteConflictObservation{
				Candidate: candidate, Route: route,
			})
		}
	}
	return conflicts
}

func DeterministicMAC(resourceID string) (string, error) {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "" {
		return "", fmt.Errorf("resource ID is required")
	}
	sum := sha256.Sum256(
		[]byte("lablink-isolated-mac/v1\x00" + resourceID))
	return fmt.Sprintf(
		"02155D%02X%02X%02X", sum[0], sum[1], sum[2]), nil
}

func PrivateSubnet(index int) (netip.Prefix, error) {
	if index < 0 || index >= PrivateSubnetCount {
		return netip.Prefix{}, &DomainError{
			Code: "NETWORK_CAPACITY_EXHAUSTED",
			Message: fmt.Sprintf(
				"subnet index %d is outside the /20 range 0-%d",
				index, PrivateSubnetCount-1),
		}
	}
	base := privateAddressPool.Masked().Addr().As4()
	offset := index * (1 << (32 - PrivateNetworkPrefixBits))
	value := uint32(base[0])<<24 | uint32(base[1])<<16 |
		uint32(base[2])<<8 | uint32(base[3])
	value += uint32(offset)
	address := netip.AddrFrom4([4]byte{
		byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value),
	})
	return netip.PrefixFrom(address, PrivateNetworkPrefixBits), nil
}

func PrivateGateway(prefix netip.Prefix) netip.Addr {
	return prefix.Masked().Addr().Next()
}

func GuestAddress(prefix netip.Prefix, offset int) (netip.Addr, error) {
	if !prefix.IsValid() || prefix.Bits() != PrivateNetworkPrefixBits ||
		!privateAddressPool.Contains(prefix.Addr()) {
		return netip.Addr{}, &DomainError{
			Code: "INVALID_PRIVATE_SUBNET", Message: prefix.String(),
		}
	}
	if offset < FirstGuestAddressOffset || offset > LastGuestAddressOffset {
		return netip.Addr{}, &DomainError{
			Code: "INVALID_GUEST_ADDRESS",
			Message: fmt.Sprintf(
				"guest offset must be between %d and %d",
				FirstGuestAddressOffset, LastGuestAddressOffset),
		}
	}
	address := prefix.Masked().Addr()
	for i := 0; i < offset; i++ {
		address = address.Next()
	}
	return address, nil
}

func SubnetIndexFromCIDR(cidr string) (int, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || prefix.Bits() != PrivateNetworkPrefixBits {
		return 0, &DomainError{Code: "INVALID_PRIVATE_SUBNET", Message: cidr}
	}
	for index := 0; index < PrivateSubnetCount; index++ {
		candidate, _ := PrivateSubnet(index)
		if candidate == prefix.Masked() {
			return index, nil
		}
	}
	return 0, &DomainError{Code: "INVALID_PRIVATE_SUBNET", Message: cidr}
}
