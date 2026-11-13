package appliance

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

type ConntrackTuple struct {
	Source          netip.Addr
	Destination     netip.Addr
	SourcePort      uint16
	DestinationPort uint16
}

type ConntrackEntry struct {
	Protocol string
	State    string
	Original ConntrackTuple
	Reply    ConntrackTuple
	Mark     uint32
}

type ConntrackFilter struct {
	GuestIPv4        netip.Addr
	PrivateInterface string
	MainInterface    string
	ConntrackMark    uint32
}

type ConntrackParser interface {
	Parse(string) ([]ConntrackEntry, error)
}

type ConntrackInspector interface {
	Count(context.Context, ConntrackFilter) (int, error)
}

type ConntrackRetirer interface {
	RetireExact(context.Context, ConntrackFilter) error
}

func ConntrackEntryMatches(entry ConntrackEntry, filter ConntrackFilter) bool {
	if !filter.GuestIPv4.Is4() || filter.ConntrackMark == 0 ||
		entry.Mark != filter.ConntrackMark {
		return false
	}
	return entry.Original.Source.Unmap() == filter.GuestIPv4.Unmap()
}

func validateConntrackFilter(filter ConntrackFilter) error {
	if !filter.GuestIPv4.Is4() || filter.GuestIPv4.IsUnspecified() ||
		filter.GuestIPv4.IsLoopback() || filter.GuestIPv4.IsMulticast() {
		return fmt.Errorf("invalid managed guest IPv4 %q", filter.GuestIPv4)
	}
	if filter.ConntrackMark == 0 {
		return fmt.Errorf("conntrack mark must be non-zero")
	}
	if err := validateInterfaceName(
		strings.TrimSpace(filter.PrivateInterface),
	); err != nil {
		return fmt.Errorf("private interface: %w", err)
	}
	if err := validateInterfaceName(
		strings.TrimSpace(filter.MainInterface),
	); err != nil {
		return fmt.Errorf("main interface: %w", err)
	}
	if filter.PrivateInterface == filter.MainInterface {
		return fmt.Errorf("private and main interfaces must differ")
	}
	return nil
}

func validateInterfaceName(value string) error {
	if value == "" || len(value) > 15 {
		return fmt.Errorf("invalid interface name %q", value)
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '_' || character == '-' || character == '.') {
			return fmt.Errorf("invalid interface name %q", value)
		}
	}
	return nil
}
