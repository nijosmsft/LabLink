package isolated

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
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

func ValidateBootstrapPolicy(
	requirement string,
	natEnabled, knownNetworkBootstrap, domainJoin bool,
	services []ReachableService,
) error {
	requirement = strings.ToLower(strings.TrimSpace(requirement))
	if requirement == "" {
		requirement = BootstrapNetworkNone
	}
	switch requirement {
	case BootstrapNetworkNone, BootstrapNetworkPreStaged, BootstrapNetworkNAT:
	default:
		return fmt.Errorf(
			"BOOTSTRAP_NETWORK_REQUIREMENT_INVALID: expected none, pre_staged, or nat_enabled")
	}
	if knownNetworkBootstrap && requirement == BootstrapNetworkNone {
		return fmt.Errorf(
			"BOOTSTRAP_NETWORK_DECLARATION_REQUIRED: known package/download/bootstrap work cannot declare none")
	}
	if requirement == BootstrapNetworkNAT && !natEnabled {
		return fmt.Errorf(
			"BOOTSTRAP_REQUIRES_NAT: network bootstrap is not allowed while NAT is disabled")
	}
	if knownNetworkBootstrap && !natEnabled &&
		requirement != BootstrapNetworkPreStaged {
		return fmt.Errorf(
			"BOOTSTRAP_NETWORK_BLOCKED: internet/main-network bootstrap requires NAT or fully pre-staged artifacts")
	}
	if domainJoin {
		if len(services) == 0 {
			return fmt.Errorf(
				"DOMAIN_SERVICES_REQUIRED: domain join requires explicit reachable_services")
		}
		hasDNS, hasDC := false, false
		for _, service := range services {
			if net.ParseIP(strings.TrimSpace(service.Address)) == nil {
				return fmt.Errorf(
					"REACHABLE_SERVICE_INVALID: %q is not an IP address",
					service.Address)
			}
			switch strings.ToLower(strings.TrimSpace(service.Kind)) {
			case "dns":
				hasDNS = true
			case "domain_controller", "dc":
				hasDC = true
			default:
				return fmt.Errorf(
					"REACHABLE_SERVICE_INVALID: unsupported service kind %q",
					service.Kind)
			}
		}
		if !hasDNS || !hasDC {
			return fmt.Errorf(
				"DOMAIN_SERVICES_REQUIRED: reachable DNS and domain_controller services are required")
		}
	}
	return nil
}

func ParseDNSServers(data string) ([]string, error) {
	data = strings.TrimSpace(data)
	if data == "" {
		return nil, nil
	}
	var values []string
	if strings.HasPrefix(data, "[") {
		if err := json.Unmarshal([]byte(data), &values); err != nil {
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

func WindowsStaticNetworkScript(
	ip string,
	prefixLength int,
	gateway, mac string,
	dns []string,
) (string, error) {
	if net.ParseIP(ip) == nil || net.ParseIP(gateway) == nil ||
		prefixLength != PrivateNetworkPrefixBits {
		return "", fmt.Errorf("invalid isolated Windows static network")
	}
	normalizedMAC := strings.ToUpper(
		strings.NewReplacer("-", "", ":", "").Replace(mac))
	if len(normalizedMAC) != 12 {
		return "", fmt.Errorf("invalid isolated Windows MAC %q", mac)
	}
	dnsValues := make([]string, 0, len(dns))
	for _, value := range dns {
		if net.ParseIP(value) == nil {
			return "", fmt.Errorf("invalid DNS server %q", value)
		}
		dnsValues = append(dnsValues,
			"'"+strings.ReplaceAll(value, "'", "''")+"'")
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

func LinuxStaticNetworkConfig(
	ip string,
	prefixLength int,
	gateway, mac string,
	dns []string,
) (string, error) {
	if net.ParseIP(ip) == nil || net.ParseIP(gateway) == nil ||
		prefixLength != PrivateNetworkPrefixBits {
		return "", fmt.Errorf("invalid isolated Linux static network")
	}
	parsedMAC, err := net.ParseMAC(
		strings.ToLower(strings.ReplaceAll(mac, "-", ":")))
	if err != nil {
		return "", fmt.Errorf("invalid isolated Linux MAC %q", mac)
	}
	var nameservers string
	if len(dns) > 0 {
		nameservers = "\n      nameservers:\n        addresses: [" +
			strings.Join(dns, ", ") + "]"
	}
	return "version: 2\nethernets:\n  isolated:\n    match:\n      macaddress: " +
		strconv.Quote(parsedMAC.String()) +
		"\n    set-name: isolated0\n    dhcp4: false\n    dhcp6: false\n    addresses: [" +
		ip + "/" + strconv.Itoa(prefixLength) + "]" +
		"\n    routes:\n      - to: 0.0.0.0/0\n        via: " +
		gateway + nameservers, nil
}

func LinuxStaticNetworkBootstrapScript(
	ip string,
	prefixLength int,
	gateway, mac string,
	dns []string,
) (string, error) {
	if net.ParseIP(ip) == nil || net.ParseIP(gateway) == nil ||
		prefixLength != PrivateNetworkPrefixBits {
		return "", fmt.Errorf("invalid isolated Linux static network")
	}
	parsedMAC, err := net.ParseMAC(
		strings.ToLower(strings.ReplaceAll(mac, "-", ":")))
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
`, strconv.Quote(parsedMAC.String()), networkd.String(),
		ip, prefixLength, gateway, ip, prefixLength), nil
}
