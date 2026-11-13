package appliance

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

const (
	DNSStateReady              = "ready"
	DNSStateNoUpstreamResolver = "no_upstream_resolver"
)

var dnsLabelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

type RejectedResolver struct {
	Value  string
	Reason string
}

type DNSObservation struct {
	InterfaceName string
	Servers       []netip.Addr
	SearchDomains []string
	SplitDomains  []string
	Rejected      []RejectedResolver
	Warnings      []string
	State         string
	Truncated     bool
}

type DNSUnavailableError struct {
	InterfaceName string
	Rejected      []RejectedResolver
	SplitDomains  []string
}

func (e *DNSUnavailableError) Error() string {
	message := fmt.Sprintf("main link %q has no usable upstream IPv4 resolver", e.InterfaceName)
	if len(e.Rejected) != 0 {
		message += fmt.Sprintf(" (%d unsuitable value(s) rejected)", len(e.Rejected))
	}
	message += "; split-DNS routing domains cannot be represented by guest static resolver lists"
	return message
}

func ParseResolvectlObservation(dnsOutput, domainOutput, interfaceName string, privateGateways []netip.Addr) DNSObservation {
	observation := DNSObservation{InterfaceName: interfaceName}
	serverTokens := resolvectlLinkValues(dnsOutput, interfaceName)
	observation.Servers, observation.Rejected, observation.Truncated = filterResolvers(serverTokens, privateGateways)

	domainTokens := resolvectlLinkValues(domainOutput, interfaceName)
	totalSearchLength := 0
	for _, token := range domainTokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if strings.HasPrefix(token, "~") {
			observation.SplitDomains = append(observation.SplitDomains, token)
			continue
		}
		domain := strings.TrimSuffix(token, ".")
		if !validDNSDomain(domain) {
			observation.Warnings = append(observation.Warnings, fmt.Sprintf("ignored invalid search domain %q", token))
			continue
		}
		addedLength := len(domain)
		if len(observation.SearchDomains) != 0 {
			addedLength++
		}
		if len(observation.SearchDomains) == 6 || totalSearchLength+addedLength > 256 {
			observation.Truncated = true
			continue
		}
		observation.SearchDomains = append(observation.SearchDomains, domain)
		totalSearchLength += addedLength
	}
	if len(observation.SplitDomains) != 0 {
		observation.Warnings = append(observation.Warnings,
			"split-DNS routing domains cannot be copied to guest static resolver configuration")
	}
	if observation.Truncated {
		observation.Warnings = append(observation.Warnings,
			"resolver or search-domain data was truncated to guest static configuration limits")
	}
	if len(observation.Servers) == 0 {
		observation.State = DNSStateNoUpstreamResolver
	} else {
		observation.State = DNSStateReady
	}
	return observation
}

func ParseResolvedResolvConf(content, interfaceName string, privateGateways []netip.Addr) DNSObservation {
	tokens := make([]string, 0)
	search := make([]string, 0)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			tokens = append(tokens, fields[1])
		case "search":
			search = append(search, fields[1:]...)
		}
	}
	return ParseResolvectlObservation(strings.Join(tokens, " "), strings.Join(search, " "), interfaceName, privateGateways)
}

func RequireUpstreamDNS(observation DNSObservation) error {
	if len(observation.Servers) != 0 {
		return nil
	}
	return &DNSUnavailableError{
		InterfaceName: observation.InterfaceName,
		Rejected:      append([]RejectedResolver(nil), observation.Rejected...),
		SplitDomains:  append([]string(nil), observation.SplitDomains...),
	}
}

func resolvectlLinkValues(output, interfaceName string) []string {
	var values []string
	sawLinkHeading := false
	matchedLink := false
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "Link ") {
			sawLinkHeading = true
			open := strings.Index(trimmed, "(")
			close := strings.Index(trimmed, ")")
			matchedLink = open >= 0 && close > open && trimmed[open+1:close] == interfaceName
			if !matchedLink {
				continue
			}
			if colon := strings.Index(trimmed, ":"); colon >= 0 {
				values = append(values, strings.Fields(trimmed[colon+1:])...)
			}
			continue
		}
		if matchedLink && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			values = append(values, strings.Fields(trimmed)...)
		}
	}
	if !sawLinkHeading {
		if strings.Contains(output, "Global:") {
			return nil
		}
		values = append(values, strings.Fields(output)...)
	}
	return values
}

func filterResolvers(tokens []string, privateGateways []netip.Addr) ([]netip.Addr, []RejectedResolver, bool) {
	gateways := make(map[netip.Addr]struct{}, len(privateGateways))
	for _, gateway := range privateGateways {
		if gateway.Is4() {
			gateways[gateway.Unmap()] = struct{}{}
		}
	}
	seen := make(map[netip.Addr]struct{})
	servers := make([]netip.Addr, 0, 3)
	rejected := make([]RejectedResolver, 0)
	truncated := false
	for _, token := range tokens {
		value := strings.TrimSpace(strings.TrimSuffix(token, ","))
		if percent := strings.IndexByte(value, '%'); percent >= 0 {
			value = value[:percent]
		}
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() {
			rejected = append(rejected, RejectedResolver{Value: token, Reason: "not a unicast IPv4 address"})
			continue
		}
		address = address.Unmap()
		reason := unsuitableResolverReason(address, gateways)
		if reason != "" {
			rejected = append(rejected, RejectedResolver{Value: token, Reason: reason})
			continue
		}
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		if len(servers) == 3 {
			truncated = true
			continue
		}
		servers = append(servers, address)
	}
	return servers, rejected, truncated
}

func unsuitableResolverReason(address netip.Addr, privateGateways map[netip.Addr]struct{}) string {
	if address.IsUnspecified() {
		return "unspecified address"
	}
	if address.IsLoopback() {
		return "loopback or local resolver stub"
	}
	if address.IsMulticast() {
		return "multicast address"
	}
	if address.IsLinkLocalUnicast() {
		return "link-local address"
	}
	if netip.MustParsePrefix("0.0.0.0/8").Contains(address) {
		return "reserved this-network address"
	}
	if netip.MustParsePrefix("240.0.0.0/4").Contains(address) {
		return "reserved address"
	}
	if address == netip.MustParseAddr("255.255.255.255") {
		return "broadcast address"
	}
	if _, ok := privateGateways[address]; ok {
		return "managed private-link gateway address"
	}
	return ""
}

func validDNSDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if !dnsLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}
