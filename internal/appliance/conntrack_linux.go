//go:build linux

package appliance

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type LinuxConntrackConfig struct {
	Executor CommandExecutor
	Parser   ConntrackParser
}

type LinuxConntrack struct {
	executor CommandExecutor
	parser   ConntrackParser
}

type conntrackTextParser struct{}

func NewLinuxConntrack(config LinuxConntrackConfig) (*LinuxConntrack, error) {
	executor := config.Executor
	if executor == nil {
		executor = OSCommandExecutor{}
	}
	parser := config.Parser
	if parser == nil {
		parser = conntrackTextParser{}
	}
	return &LinuxConntrack{executor: executor, parser: parser}, nil
}

func (c *LinuxConntrack) Count(
	ctx context.Context,
	filter ConntrackFilter,
) (int, error) {
	if err := validateConntrackFilter(filter); err != nil {
		return 0, err
	}
	result, err := c.executor.Run(ctx, "conntrack", "-L", "-f", "ipv4", "-o", "extended")
	if err != nil {
		return 0, err
	}
	if result.ExitCode != 0 {
		return 0, commandFailure("conntrack -L -f ipv4 -o extended", result)
	}
	entries, err := c.parser.Parse(result.Stdout)
	if err != nil {
		return 0, fmt.Errorf("appliance: parse conntrack output: %w", err)
	}
	count := 0
	for _, entry := range entries {
		if ConntrackEntryMatches(entry, filter) {
			count++
		}
	}
	return count, nil
}

func ParseConntrackOutput(output string) ([]ConntrackEntry, error) {
	return conntrackTextParser{}.Parse(output)
}

func (conntrackTextParser) Parse(output string) ([]ConntrackEntry, error) {
	var entries []ConntrackEntry
	for lineNumber, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "src=") {
			continue
		}
		entry, err := parseConntrackLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func parseConntrackLine(line string) (ConntrackEntry, error) {
	fields := strings.Fields(line)
	var entry ConntrackEntry
	for _, field := range fields {
		candidate := strings.ToLower(strings.Trim(field, "[]"))
		switch candidate {
		case "tcp", "udp", "icmp", "icmpv6", "sctp", "dccp", "gre":
			if entry.Protocol == "" {
				entry.Protocol = candidate
			}
		}
		if !strings.Contains(field, "=") && entry.State == "" &&
			field == strings.ToUpper(field) && strings.IndexFunc(field, func(r rune) bool {
			return r >= 'A' && r <= 'Z'
		}) >= 0 {
			entry.State = strings.Trim(field, "[]")
		}
	}

	tuple := 0
	sourceCount := 0
	for _, field := range fields {
		key, value, ok := strings.Cut(strings.Trim(field, "[]"), "=")
		if !ok {
			continue
		}
		switch key {
		case "src":
			if sourceCount > 0 {
				tuple = 1
			}
			sourceCount++
			address, err := netip.ParseAddr(strings.TrimSuffix(value, ","))
			if err != nil {
				return ConntrackEntry{}, fmt.Errorf("invalid source address %q", value)
			}
			if tuple == 0 {
				entry.Original.Source = address.Unmap()
			} else {
				entry.Reply.Source = address.Unmap()
			}
		case "dst":
			address, err := netip.ParseAddr(strings.TrimSuffix(value, ","))
			if err != nil {
				return ConntrackEntry{}, fmt.Errorf("invalid destination address %q", value)
			}
			if tuple == 0 {
				entry.Original.Destination = address.Unmap()
			} else {
				entry.Reply.Destination = address.Unmap()
			}
		case "sport":
			port, err := parseConntrackPort(value)
			if err != nil {
				return ConntrackEntry{}, err
			}
			if tuple == 0 {
				entry.Original.SourcePort = port
			} else {
				entry.Reply.SourcePort = port
			}
		case "dport":
			port, err := parseConntrackPort(value)
			if err != nil {
				return ConntrackEntry{}, err
			}
			if tuple == 0 {
				entry.Original.DestinationPort = port
			} else {
				entry.Reply.DestinationPort = port
			}
		case "mark":
			mark, err := strconv.ParseUint(strings.TrimSuffix(value, ","), 0, 32)
			if err != nil {
				return ConntrackEntry{}, fmt.Errorf("invalid conntrack mark %q", value)
			}
			entry.Mark = uint32(mark)
		}
	}
	if !entry.Original.Source.IsValid() || !entry.Original.Destination.IsValid() ||
		!entry.Reply.Source.IsValid() || !entry.Reply.Destination.IsValid() {
		return ConntrackEntry{}, fmt.Errorf("conntrack entry does not contain two complete address tuples")
	}
	return entry, nil
}

func parseConntrackPort(value string) (uint16, error) {
	port, err := strconv.ParseUint(strings.TrimSuffix(value, ","), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid conntrack port %q", value)
	}
	return uint16(port), nil
}
