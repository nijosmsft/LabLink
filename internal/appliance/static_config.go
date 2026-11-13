package appliance

import (
	"net/netip"
	"strings"
)

type StaticConfig struct {
	Networks []StaticNetwork
	Guests   []StaticGuest
	Relays   []StaticRelay
	NAT      []StaticNAT
}

type StaticNetwork struct {
	ID             string
	CIDR           string
	GatewayIPv4    string
	NICMAC         string
	InterfaceName  string
	DNSServersJSON string
}

type StaticGuest struct {
	ID        string
	NetworkID string
	IPv4      string
	MAC       string
}

type StaticRelay struct {
	ID         string
	VMID       string
	ListenPort int64
	TargetIPv4 string
	TargetPort int64
}

type StaticNAT struct {
	VMID          string
	ConntrackMark int64
	Enabled       bool
}

type RetiredNAT struct {
	VMID          string
	GuestIPv4     string
	ConntrackMark int64
}

func ValidateStaticConfig(config StaticConfig) error {
	networks := make(map[string]StaticNetwork, len(config.Networks))
	guests := make(map[string]StaticGuest, len(config.Guests))
	relayPorts := make(map[int64]string, len(config.Relays))
	marks := make(map[int64]string, len(config.NAT))
	for _, network := range config.Networks {
		network.ID = strings.TrimSpace(network.ID)
		if network.ID == "" {
			return storeError(CodeInvalidArgument, "network ID is required")
		}
		if _, exists := networks[network.ID]; exists {
			return storeError(CodeInvalidArgument,
				"duplicate network %q", network.ID)
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(network.CIDR))
		if err != nil || !prefix.Addr().Is4() {
			return storeError(CodeInvalidArgument,
				"network %q has invalid IPv4 CIDR", network.ID)
		}
		gateway, err := netip.ParseAddr(strings.TrimSpace(network.GatewayIPv4))
		if err != nil || !gateway.Is4() || !prefix.Contains(gateway) {
			return storeError(CodeInvalidArgument,
				"network %q has invalid gateway", network.ID)
		}
		networks[network.ID] = network
	}
	for _, guest := range config.Guests {
		if strings.TrimSpace(guest.ID) == "" {
			return storeError(CodeInvalidArgument, "guest ID is required")
		}
		if _, exists := guests[guest.ID]; exists {
			return storeError(CodeInvalidArgument,
				"duplicate guest %q", guest.ID)
		}
		if _, exists := networks[guest.NetworkID]; !exists {
			return storeError(CodeInvalidArgument,
				"guest %q references unknown network %q",
				guest.ID, guest.NetworkID)
		}
		address, err := netip.ParseAddr(strings.TrimSpace(guest.IPv4))
		if err != nil || !address.Is4() {
			return storeError(CodeInvalidArgument,
				"guest %q has invalid IPv4", guest.ID)
		}
		guests[guest.ID] = guest
	}
	for _, relay := range config.Relays {
		guest, exists := guests[relay.VMID]
		if strings.TrimSpace(relay.ID) == "" || !exists {
			return storeError(CodeInvalidArgument,
				"relay %q references unknown guest %q", relay.ID, relay.VMID)
		}
		if relay.ListenPort < RelayPortMin || relay.ListenPort > RelayPortMax {
			return storeError(CodeInvalidArgument,
				"relay %q listen port is outside the managed range", relay.ID)
		}
		if prior, exists := relayPorts[relay.ListenPort]; exists {
			return storeError(CodeInvalidArgument,
				"relays %q and %q use port %d",
				prior, relay.ID, relay.ListenPort)
		}
		if relay.TargetIPv4 != guest.IPv4 {
			return storeError(CodeInvalidArgument,
				"relay %q target does not match guest %q",
				relay.ID, relay.VMID)
		}
		relayPorts[relay.ListenPort] = relay.ID
	}
	for _, nat := range config.NAT {
		if _, exists := guests[nat.VMID]; !exists {
			return storeError(CodeInvalidArgument,
				"NAT references unknown guest %q", nat.VMID)
		}
		if nat.ConntrackMark <= 0 ||
			nat.ConntrackMark > int64(^uint32(0)) {
			return storeError(CodeInvalidArgument,
				"NAT for %q has invalid conntrack mark", nat.VMID)
		}
		if prior, exists := marks[nat.ConntrackMark]; exists {
			return storeError(CodeInvalidArgument,
				"NAT for %q and %q use conntrack mark %d",
				prior, nat.VMID, nat.ConntrackMark)
		}
		marks[nat.ConntrackMark] = nat.VMID
	}
	return nil
}
