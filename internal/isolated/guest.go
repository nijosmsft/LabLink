package isolated

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
)

const (
	BootstrapNetworkNone      = "none"
	BootstrapNetworkPreStaged = "pre_staged"
	BootstrapNetworkNAT       = "nat_enabled"
)

type ReachableService struct {
	Kind    string `json:"kind"`
	Address string `json:"address"`
	Port    int    `json:"port,omitempty"`
}

type CreateGuestRequest struct {
	OperationID                 string
	VMID                        VMID
	RelayID                     RelayID
	Network                     isolatedstate.PrivateNetwork
	Orchestrator                isolatedstate.Orchestrator
	DisplayName                 string
	GuestOS                     isolatedstate.GuestOS
	ProfileName                 string
	NATEnabled                  bool
	BootstrapNetworkRequirement string
	KnownNetworkBootstrap       bool
	DomainJoin                  bool
	ReachableServices           []ReachableService
	ExpectedParentGeneration    isolatedstate.Generation
	HostFence                   int64
	HostLeaseID                 string
	HostLeaseSecret             []byte
	HostLeaseExpiresUnix        int64
	StorageRoot                 string
	VMPath                      string
	VHDPath                     string
}

type GuestPlan struct {
	VM                          isolatedstate.IsolatedVM      `json:"vm"`
	Relay                       isolatedstate.RelayAllocation `json:"relay"`
	NAT                         isolatedstate.NATAllocation   `json:"nat"`
	Reservations                []appliance.Reservation       `json:"reservations"`
	ResultingParentGeneration   uint64                        `json:"resulting_parent_generation"`
	BootstrapNetworkRequirement string                        `json:"bootstrap_network_requirement"`
	ReachableServices           []ReachableService            `json:"reachable_services,omitempty"`
}

type GuestAllocationClient interface {
	GetApplianceState(context.Context, string) (appliance.DesiredSnapshot, error)
	ReserveResources(context.Context, string, appliance.ReserveRequest) (appliance.ReserveResult, error)
}

type GuestDomain struct {
	Appliance GuestAllocationClient
}

func ValidateBootstrapPolicy(requirement string, natEnabled, knownNetworkBootstrap, domainJoin bool, services []ReachableService) error {
	requirement = strings.ToLower(strings.TrimSpace(requirement))
	if requirement == "" {
		requirement = BootstrapNetworkNone
	}
	switch requirement {
	case BootstrapNetworkNone, BootstrapNetworkPreStaged, BootstrapNetworkNAT:
	default:
		return fmt.Errorf("BOOTSTRAP_NETWORK_REQUIREMENT_INVALID: expected none, pre_staged, or nat_enabled")
	}
	if knownNetworkBootstrap && requirement == BootstrapNetworkNone {
		return fmt.Errorf("BOOTSTRAP_NETWORK_DECLARATION_REQUIRED: known package/download/bootstrap work cannot declare none")
	}
	if requirement == BootstrapNetworkNAT && !natEnabled {
		return fmt.Errorf("BOOTSTRAP_REQUIRES_NAT: network bootstrap is not allowed while NAT is disabled")
	}
	if knownNetworkBootstrap && !natEnabled && requirement != BootstrapNetworkPreStaged {
		return fmt.Errorf("BOOTSTRAP_NETWORK_BLOCKED: internet/main-network bootstrap requires NAT or fully pre-staged artifacts")
	}
	if domainJoin {
		if len(services) == 0 {
			return fmt.Errorf("DOMAIN_SERVICES_REQUIRED: domain join requires explicit reachable_services")
		}
		hasDNS, hasDC := false, false
		for _, service := range services {
			if net.ParseIP(strings.TrimSpace(service.Address)) == nil {
				return fmt.Errorf("REACHABLE_SERVICE_INVALID: %q is not an IP address", service.Address)
			}
			switch strings.ToLower(strings.TrimSpace(service.Kind)) {
			case "dns":
				hasDNS = true
			case "domain_controller", "dc":
				hasDC = true
			default:
				return fmt.Errorf("REACHABLE_SERVICE_INVALID: unsupported service kind %q", service.Kind)
			}
		}
		if !hasDNS || !hasDC {
			return fmt.Errorf("DOMAIN_SERVICES_REQUIRED: reachable DNS and domain_controller services are required")
		}
	}
	return nil
}

func (d GuestDomain) ReserveAndPlan(ctx context.Context, request CreateGuestRequest) (GuestPlan, error) {
	if d.Appliance == nil {
		return GuestPlan{}, fmt.Errorf("isolated guest appliance client is required")
	}
	if err := request.VMID.Validate(); err != nil {
		return GuestPlan{}, err
	}
	if err := request.RelayID.Validate(); err != nil {
		return GuestPlan{}, err
	}
	if request.Network.ID == "" || request.Network.OrchestratorID != request.Orchestrator.ID {
		return GuestPlan{}, fmt.Errorf("GUEST_NETWORK_MISMATCH: exact managed network and orchestrator are required")
	}
	if request.Network.LifecycleState != isolatedstate.NetworkReady {
		return GuestPlan{}, fmt.Errorf("GUEST_NETWORK_NOT_READY: network %s is %s", request.Network.ID, request.Network.LifecycleState)
	}
	if request.GuestOS != isolatedstate.GuestWindows && request.GuestOS != isolatedstate.GuestLinux {
		return GuestPlan{}, fmt.Errorf("unsupported isolated guest OS %q", request.GuestOS)
	}
	if err := ValidateBootstrapPolicy(request.BootstrapNetworkRequirement, request.NATEnabled,
		request.KnownNetworkBootstrap, request.DomainJoin, request.ReachableServices); err != nil {
		return GuestPlan{}, err
	}
	names, err := VMNames(request.VMID)
	if err != nil {
		return GuestPlan{}, err
	}
	snapshot, err := d.Appliance.GetApplianceState(ctx, request.Orchestrator.ID)
	if err != nil {
		return GuestPlan{}, err
	}
	ip, port, mark, err := selectGuestResources(snapshot, request.Network)
	if err != nil {
		return GuestPlan{}, err
	}
	mac, err := hyperv.DeterministicIsolatedMAC(request.VMID.String())
	if err != nil {
		return GuestPlan{}, err
	}
	inputs := map[string]any{
		"vm_id": request.VMID.String(), "relay_id": request.RelayID.String(),
		"network_id": request.Network.ID, "ipv4": ip, "mac": mac,
		"listen_port": port, "conntrack_mark": mark,
		"nat_enabled": request.NATEnabled, "profile": request.ProfileName,
	}
	semantic, err := isolatedstate.SemanticHash(inputs)
	if err != nil {
		return GuestPlan{}, err
	}
	ipReservationID := isolatedstate.StableMutationID(request.OperationID, request.VMID.String(), "reserve_guest", "ip")
	macReservationID := isolatedstate.StableMutationID(request.OperationID, request.VMID.String(), "reserve_guest", "mac")
	relayReservationID := isolatedstate.StableMutationID(request.OperationID, request.RelayID.String(), "reserve_guest", "relay")
	markReservationID := isolatedstate.StableMutationID(request.OperationID, request.VMID.String(), "reserve_guest", "conntrack")
	port64, mark64 := int64(port), int64(mark)
	reservations := []appliance.Reservation{
		{ID: ipReservationID, ResourceKind: "guest_ip", ResourceID: request.VMID.String(), NetworkID: request.Network.ID, IPv4: ip, CapacityKind: "guest", CapacityUnits: 1},
		{ID: macReservationID, ResourceKind: "guest_mac", ResourceID: request.VMID.String(), NetworkID: request.Network.ID, MAC: mac},
		{ID: relayReservationID, ResourceKind: "relay", ResourceID: request.RelayID.String(), NetworkID: request.Network.ID, ListenPort: &port64, CapacityKind: "relay", CapacityUnits: 1},
		{ID: markReservationID, ResourceKind: "conntrack_mark", ResourceID: request.VMID.String(), NetworkID: request.Network.ID, ConntrackMark: &mark64},
	}
	result, err := d.Appliance.ReserveResources(ctx, request.Orchestrator.ID, appliance.ReserveRequest{
		Header: appliance.MutationHeader{
			ParentOperationID: request.OperationID,
			MutationID:        isolatedstate.StableMutationID(request.OperationID, request.VMID.String(), "reserve_guest", "reserve"),
			SemanticHash:      semantic, ResourceID: request.VMID.String(),
			ParentResourceID: request.Network.ID, ExpectedGeneration: 0, NewGeneration: 1,
			HostFence:                uint64(request.HostFence),
			ExpectedParentGeneration: uint64(request.ExpectedParentGeneration),
		},
		PhysicalHostID: request.Orchestrator.PhysicalHostID,
		HostLeaseID:    request.HostLeaseID, HostLeaseSecret: request.HostLeaseSecret,
		HostLeaseExpiresUnix: request.HostLeaseExpiresUnix,
		Reservations:         reservations,
	})
	if err != nil {
		return GuestPlan{}, err
	}
	if len(result.Reservations) != len(reservations) {
		return GuestPlan{}, fmt.Errorf("INVALID_APPLIANCE_RESPONSE: expected four guest reservations")
	}
	dns := request.Network.DNSServersJSON
	now := isolatedstate.UnixSeconds(0)
	natDesired, natObserved := isolatedstate.NATDesiredDisabled, isolatedstate.NATObservedDisabled
	if request.NATEnabled {
		natDesired, natObserved = isolatedstate.NATDesiredEnabled, isolatedstate.NATObservedEnabled
	}
	displayName := strings.TrimSpace(request.DisplayName)
	if displayName == "" {
		displayName = names.HyperVName
	}
	requirement := strings.ToLower(strings.TrimSpace(request.BootstrapNetworkRequirement))
	if requirement == "" {
		requirement = BootstrapNetworkNone
	}
	return GuestPlan{
		VM: isolatedstate.IsolatedVM{
			ID: request.VMID.String(), OrchestratorID: request.Orchestrator.ID,
			NetworkID: request.Network.ID, DisplayName: displayName,
			HyperVName: names.HyperVName, Incarnation: 1, NodeName: names.NodeName,
			GuestOS: request.GuestOS, ProfileName: request.ProfileName,
			IPv4: ip, MAC: mac, PrefixLength: PrivateNetworkPrefixBits,
			GatewayIPv4: request.Network.GatewayIPv4, DNSServersJSON: dns,
			StorageRoot: request.StorageRoot, VMPath: request.VMPath, VHDPath: request.VHDPath,
			DesiredGeneration: 1, LifecycleState: isolatedstate.VMAllocating,
			CreatedAt: now, UpdatedAt: now,
		},
		Relay: isolatedstate.RelayAllocation{
			ID: request.RelayID.String(), VMID: request.VMID.String(),
			OrchestratorID: request.Orchestrator.ID, ListenPort: port,
			TargetIPv4: ip, TargetPort: appliance.RelayTargetPort,
			DesiredGeneration: 1, LifecycleState: isolatedstate.RelayAllocated,
			CreatedAt: now, UpdatedAt: now,
		},
		NAT: isolatedstate.NATAllocation{
			VMID: request.VMID.String(), OrchestratorID: request.Orchestrator.ID,
			DesiredState: natDesired, ObservedState: natObserved, ConntrackMark: int64(mark),
			DesiredGeneration: 1, UpdatedAt: now,
		},
		Reservations: result.Reservations, ResultingParentGeneration: result.ParentGeneration,
		BootstrapNetworkRequirement: requirement, ReachableServices: append([]ReachableService(nil), request.ReachableServices...),
	}, nil
}

func selectGuestResources(snapshot appliance.DesiredSnapshot, network isolatedstate.PrivateNetwork) (string, int, int, error) {
	prefix, err := netip.ParsePrefix(network.CIDR)
	if err != nil || prefix.Bits() != PrivateNetworkPrefixBits {
		return "", 0, 0, fmt.Errorf("INVALID_PRIVATE_SUBNET: %q", network.CIDR)
	}
	usedIP, usedPort, usedMark := map[string]bool{}, map[int]bool{}, map[int]bool{}
	for _, reservation := range snapshot.Reservations {
		if reservation.RetiredAtUnix != nil {
			continue
		}
		if reservation.IPv4 != "" {
			usedIP[reservation.IPv4] = true
		}
		if reservation.ListenPort != nil {
			usedPort[int(*reservation.ListenPort)] = true
		}
		if reservation.ConntrackMark != nil {
			usedMark[int(*reservation.ConntrackMark)] = true
		}
	}
	ip := ""
	for offset := FirstGuestAddressOffset; offset <= LastGuestAddressOffset; offset++ {
		candidate, _ := GuestAddress(prefix, offset)
		if !usedIP[candidate.String()] {
			ip = candidate.String()
			break
		}
	}
	if ip == "" {
		return "", 0, 0, fmt.Errorf("CAPACITY_EXHAUSTED: no guest IPv4 address remains in %s", network.CIDR)
	}
	port := 0
	for value := appliance.RelayPortMin; value <= appliance.RelayPortMax; value++ {
		if !usedPort[value] {
			port = value
			break
		}
	}
	if port == 0 {
		return "", 0, 0, fmt.Errorf("CAPACITY_EXHAUSTED: no relay port remains")
	}
	mark := 0
	for value := 1; value <= MaxVMsPerOrchestrator; value++ {
		if !usedMark[value] {
			mark = value
			break
		}
	}
	if mark == 0 {
		return "", 0, 0, fmt.Errorf("CAPACITY_EXHAUSTED: no conntrack mark remains")
	}
	return ip, port, mark, nil
}

func ParseDNSServers(data string) ([]string, error) {
	data = strings.TrimSpace(data)
	if data == "" {
		return nil, nil
	}
	var values []string
	if strings.HasPrefix(data, "[") {
		if err := jsonUnmarshal([]byte(data), &values); err != nil {
			return nil, fmt.Errorf("invalid DNS server JSON: %w", err)
		}
	} else {
		values = strings.Split(data, ",")
	}
	for i := range values {
		values[i] = strings.TrimSpace(values[i])
		if net.ParseIP(values[i]) == nil {
			return nil, fmt.Errorf("invalid DNS server %q", values[i])
		}
	}
	sort.Strings(values)
	return values, nil
}

var jsonUnmarshal = func(data []byte, target any) error {
	return json.Unmarshal(data, target)
}

func WindowsStaticNetworkScript(ip string, prefixLength int, gateway, mac string, dns []string) (string, error) {
	if net.ParseIP(ip) == nil || net.ParseIP(gateway) == nil || prefixLength != PrivateNetworkPrefixBits {
		return "", fmt.Errorf("invalid isolated Windows static network")
	}
	normalizedMAC := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(mac, "-", ""), ":", ""))
	if len(normalizedMAC) != 12 {
		return "", fmt.Errorf("invalid isolated Windows MAC %q", mac)
	}
	dnsValues := make([]string, 0, len(dns))
	for _, value := range dns {
		if net.ParseIP(value) == nil {
			return "", fmt.Errorf("invalid DNS server %q", value)
		}
		dnsValues = append(dnsValues, "'"+strings.ReplaceAll(value, "'", "''")+"'")
	}
	return fmt.Sprintf(`$expectedMac = '%s'
$adapter = @(Get-NetAdapter | Where-Object { ($_.MacAddress -replace '[-:]','').ToUpperInvariant() -eq $expectedMac })
if ($adapter.Count -ne 1) { throw "ISOLATED_ADAPTER_IDENTITY_MISMATCH" }
$ifIndex = [int]$adapter[0].ifIndex
Set-NetIPInterface -InterfaceIndex $ifIndex -Dhcp Disabled -AddressFamily IPv4 -ErrorAction Stop
Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
Get-NetRoute -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object DestinationPrefix -eq '0.0.0.0/0' | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceIndex $ifIndex -IPAddress '%s' -PrefixLength %d -DefaultGateway '%s' -ErrorAction Stop | Out-Null
Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ServerAddresses @(%s) -ErrorAction Stop
`, normalizedMAC, ip, prefixLength, gateway, strings.Join(dnsValues, ",")), nil
}

func LinuxStaticNetworkConfig(ip string, prefixLength int, gateway, mac string, dns []string) (string, error) {
	if net.ParseIP(ip) == nil || net.ParseIP(gateway) == nil || prefixLength != PrivateNetworkPrefixBits {
		return "", fmt.Errorf("invalid isolated Linux static network")
	}
	hw := strings.ToLower(strings.ReplaceAll(mac, "-", ":"))
	parsedMAC, err := net.ParseMAC(hw)
	if err != nil {
		return "", fmt.Errorf("invalid isolated Linux MAC %q", mac)
	}
	hw = parsedMAC.String()
	var nameservers string
	if len(dns) > 0 {
		nameservers = "\n      nameservers:\n        addresses: [" + strings.Join(dns, ", ") + "]"
	}
	return "version: 2\nethernets:\n  isolated:\n    match:\n      macaddress: " + strconv.Quote(hw) +
		"\n    set-name: isolated0\n    dhcp4: false\n    dhcp6: false\n    addresses: [" + ip + "/" + strconv.Itoa(prefixLength) + "]" +
		"\n    routes:\n      - to: 0.0.0.0/0\n        via: " + gateway + nameservers, nil
}

func LinuxStaticNetworkBootstrapScript(ip string, prefixLength int, gateway, mac string, dns []string) (string, error) {
	if net.ParseIP(ip) == nil || net.ParseIP(gateway) == nil || prefixLength != PrivateNetworkPrefixBits {
		return "", fmt.Errorf("invalid isolated Linux static network")
	}
	parsedMAC, err := net.ParseMAC(strings.ToLower(strings.ReplaceAll(mac, "-", ":")))
	if err != nil {
		return "", fmt.Errorf("invalid isolated Linux MAC %q", mac)
	}
	for _, value := range dns {
		if net.ParseIP(value) == nil {
			return "", fmt.Errorf("invalid DNS server %q", value)
		}
	}
	var networkd strings.Builder
	fmt.Fprintf(&networkd, `[Match]
MACAddress=%s

[Network]
Address=%s/%d
Gateway=%s
`, parsedMAC.String(), ip, prefixLength, gateway)
	for _, value := range dns {
		fmt.Fprintf(&networkd, "DNS=%s\n", value)
	}
	return fmt.Sprintf(`#!/bin/bash
set -euo pipefail
expected_mac=%s
interface=
for address_file in /sys/class/net/*/address; do
    if [ "$(tr '[:upper:]' '[:lower:]' < "$address_file")" = "$expected_mac" ]; then
        interface="$(basename "$(dirname "$address_file")")"
        break
    fi
done
if [ -z "$interface" ]; then
    echo "ISOLATED_ADAPTER_IDENTITY_MISMATCH" >&2
    exit 1
fi
install -d -m 0755 /etc/systemd/network
cat > /etc/systemd/network/10-lablink-isolated.network <<'EOF'
%sEOF
chmod 0644 /etc/systemd/network/10-lablink-isolated.network
ip link set dev "$interface" up
ip -4 address flush dev "$interface" scope global
ip address add %s/%d dev "$interface"
ip route replace default via %s dev "$interface"
systemctl restart systemd-networkd.service
for attempt in $(seq 1 30); do
    if ip -4 -o address show dev "$interface" | grep -Fq ' %s/%d '; then
        exit 0
    fi
    sleep 1
done
echo "ISOLATED_STATIC_IPV4_VERIFY_FAILED" >&2
exit 1
`, strconv.Quote(parsedMAC.String()), networkd.String(), ip, prefixLength, gateway, ip, prefixLength), nil
}

func WindowsDNSUpdateScript(mac string, dns []string) (string, error) {
	normalizedMAC := strings.ToUpper(strings.NewReplacer("-", "", ":", "").Replace(mac))
	if len(normalizedMAC) != 12 {
		return "", fmt.Errorf("invalid isolated Windows MAC %q", mac)
	}
	values := make([]string, 0, len(dns))
	for _, value := range dns {
		if net.ParseIP(value) == nil {
			return "", fmt.Errorf("invalid DNS server %q", value)
		}
		values = append(values, "'"+strings.ReplaceAll(value, "'", "''")+"'")
	}
	if len(values) == 0 {
		return "", fmt.Errorf("at least one DNS server is required")
	}
	return fmt.Sprintf(`$expectedMac = '%s'
$adapter = @(Get-NetAdapter | Where-Object { ($_.MacAddress -replace '[-:]','').ToUpperInvariant() -eq $expectedMac })
if ($adapter.Count -ne 1) { throw "ISOLATED_ADAPTER_IDENTITY_MISMATCH" }
Set-DnsClientServerAddress -InterfaceIndex ([int]$adapter[0].ifIndex) -ServerAddresses @(%s) -ErrorAction Stop
`, normalizedMAC, strings.Join(values, ",")), nil
}

func LinuxDNSUpdateScript(mac string, dns []string) (string, error) {
	parsedMAC, err := net.ParseMAC(strings.ToLower(strings.ReplaceAll(mac, "-", ":")))
	if err != nil {
		return "", fmt.Errorf("invalid isolated Linux MAC %q", mac)
	}
	if len(dns) == 0 {
		return "", fmt.Errorf("at least one DNS server is required")
	}
	lines := make([]string, 0, len(dns))
	for _, value := range dns {
		if net.ParseIP(value) == nil {
			return "", fmt.Errorf("invalid DNS server %q", value)
		}
		lines = append(lines, "DNS="+value)
	}
	return fmt.Sprintf(`set -euo pipefail
expected_mac=%s
interface=
for address_file in /sys/class/net/*/address; do
    if [ "$(tr '[:upper:]' '[:lower:]' < "$address_file")" = "$expected_mac" ]; then
        interface="$(basename "$(dirname "$address_file")")"
        break
    fi
done
if [ -z "$interface" ]; then
    echo "ISOLATED_ADAPTER_IDENTITY_MISMATCH" >&2
    exit 1
fi
unit=/etc/systemd/network/10-lablink-isolated.network
if [ ! -f "$unit" ]; then
    echo "ISOLATED_NETWORK_UNIT_MISSING" >&2
    exit 1
fi
temp="$(mktemp)"
trap 'rm -f "$temp"' EXIT
sed '/^DNS=/d' "$unit" > "$temp"
cat >> "$temp" <<'EOF'
%s
EOF
install -m 0644 "$temp" "$unit"
networkctl reload
resolvectl dns "$interface" %s
`, strconv.Quote(parsedMAC.String()), strings.Join(lines, "\n"), strings.Join(dns, " ")), nil
}
