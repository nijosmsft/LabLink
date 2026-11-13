//go:build linux

package appliance

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestParseConntrackOutputMatchesOnlyExactGuestAndMark(t *testing.T) {
	output := `tcp 6 431999 ESTABLISHED src=10.83.0.10 dst=1.1.1.1 sport=51000 dport=443 src=1.1.1.1 dst=192.0.2.10 sport=443 dport=51000 [ASSURED] mark=601 use=1
udp 17 20 src=10.83.0.11 dst=8.8.8.8 sport=53000 dport=53 src=8.8.8.8 dst=192.0.2.10 sport=53 dport=53000 mark=601 use=1
tcp 6 431999 ESTABLISHED src=10.83.0.1 dst=10.83.0.10 sport=42000 dport=9091 src=10.83.0.10 dst=10.83.0.1 sport=9091 dport=42000 [ASSURED] mark=601 use=1
tcp 6 431999 ESTABLISHED src=10.83.0.10 dst=9.9.9.9 sport=52000 dport=443 src=9.9.9.9 dst=192.0.2.10 sport=443 dport=52000 [ASSURED] mark=602 use=1`
	entries, err := ParseConntrackOutput(output)
	if err != nil {
		t.Fatalf("ParseConntrackOutput: %v", err)
	}
	filter := ConntrackFilter{
		GuestIPv4:        netip.MustParseAddr("10.83.0.10"),
		PrivateInterface: "eth1",
		MainInterface:    "eth0",
		ConntrackMark:    601,
	}
	matches := 0
	for _, entry := range entries {
		if ConntrackEntryMatches(entry, filter) {
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("matching entries = %d, want 1; entries=%+v", matches, entries)
	}
}

type fixedConntrackParser struct {
	called bool
}

func (p *fixedConntrackParser) Parse(string) ([]ConntrackEntry, error) {
	p.called = true
	return []ConntrackEntry{{
		Protocol: "udp",
		Original: ConntrackTuple{
			Source:      netip.MustParseAddr("10.83.0.10"),
			Destination: netip.MustParseAddr("8.8.8.8"),
		},
		Reply: ConntrackTuple{
			Source:      netip.MustParseAddr("8.8.8.8"),
			Destination: netip.MustParseAddr("192.0.2.10"),
		},
		Mark: 601,
	}}, nil
}

func TestLinuxConntrackUsesInjectedExecutorAndParser(t *testing.T) {
	parser := &fixedConntrackParser{}
	executor := &scriptedExecutor{
		run: func(name string, args ...string) (CommandResult, error) {
			if got := name + " " + strings.Join(args, " "); got != "conntrack -L -f ipv4 -o extended" {
				return CommandResult{}, fmt.Errorf("unexpected command %q", got)
			}

			return CommandResult{Stdout: "injected parser input"}, nil
		},
	}
	inspector, err := NewLinuxConntrack(LinuxConntrackConfig{
		Executor: executor,
		Parser:   parser,
	})
	if err != nil {
		t.Fatalf("NewLinuxConntrack: %v", err)
	}
	count, err := inspector.Count(context.Background(), ConntrackFilter{
		GuestIPv4:        netip.MustParseAddr("10.83.0.10"),
		PrivateInterface: "eth1",
		MainInterface:    "eth0",
		ConntrackMark:    601,
	})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 1 || !parser.called {
		t.Fatalf("count=%d parser.called=%v, want 1/true", count, parser.called)
	}
}

func TestLinuxConntrackRetireExactTargetsMarkAndGuestIdempotently(t *testing.T) {
	var commands []string
	deleteCalls := 0
	executor := &scriptedExecutor{
		run: func(name string, args ...string) (CommandResult, error) {
			command := name + " " + strings.Join(args, " ")
			commands = append(commands, command)
			if strings.Contains(command, " -D ") {
				deleteCalls++
				if deleteCalls == 2 {
					return CommandResult{
						ExitCode: 1,
						Stderr:   "0 flow entries have been deleted.",
					}, nil
				}
				return CommandResult{}, nil
			}
			return CommandResult{Stdout: "tcp 6 100 ESTABLISHED src=10.83.0.11 dst=8.8.8.8 sport=50001 dport=443 src=8.8.8.8 dst=192.0.2.10 sport=443 dport=50001 mark=602 use=1"}, nil
		},
	}
	conntrack, err := NewLinuxConntrack(LinuxConntrackConfig{Executor: executor})
	if err != nil {
		t.Fatal(err)
	}
	filter := ConntrackFilter{
		GuestIPv4:        netip.MustParseAddr("10.83.0.10"),
		PrivateInterface: "eth1", MainInterface: "eth0", ConntrackMark: 601,
	}
	if err := conntrack.RetireExact(context.Background(), filter); err != nil {
		t.Fatalf("RetireExact: %v", err)
	}
	if err := conntrack.RetireExact(context.Background(), filter); err != nil {
		t.Fatalf("idempotent RetireExact: %v", err)
	}
	want := "conntrack -D -f ipv4 --mark 601 -s 10.83.0.10"
	if commands[0] != want || commands[2] != want {
		t.Fatalf("delete commands = %v, want exact %q", commands, want)
	}
	for _, command := range commands {
		if strings.Contains(command, "602") || strings.Contains(command, " -F") {
			t.Fatalf("unrelated or broad conntrack command: %q", command)
		}
	}
}

func TestLinuxConntrackRetireExactSurfacesRemainingEntry(t *testing.T) {
	executor := &scriptedExecutor{
		run: func(name string, args ...string) (CommandResult, error) {
			command := name + " " + strings.Join(args, " ")
			if strings.Contains(command, " -D ") {
				return CommandResult{ExitCode: 1, Stderr: "delete failed"}, nil
			}
			return CommandResult{Stdout: "tcp 6 100 ESTABLISHED src=10.83.0.10 dst=8.8.8.8 sport=50000 dport=443 src=8.8.8.8 dst=192.0.2.10 sport=443 dport=50000 mark=601 use=1"}, nil
		},
	}
	conntrack, err := NewLinuxConntrack(LinuxConntrackConfig{Executor: executor})
	if err != nil {
		t.Fatal(err)
	}
	err = conntrack.RetireExact(context.Background(), ConntrackFilter{
		GuestIPv4:        netip.MustParseAddr("10.83.0.10"),
		PrivateInterface: "eth1", MainInterface: "eth0", ConntrackMark: 601,
	})
	if err == nil || !strings.Contains(err.Error(), "delete failed") {
		t.Fatalf("RetireExact error = %v", err)
	}
}
