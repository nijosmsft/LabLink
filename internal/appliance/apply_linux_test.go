//go:build linux

package appliance

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"testing"
)

type memoryFiles struct {
	mu    sync.Mutex
	files map[string][]byte
}

func (f *memoryFiles) ReadFile(path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), data...), nil
}

func (f *memoryFiles) WriteFileAtomic(path string, data []byte, _ fs.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.files == nil {
		f.files = make(map[string][]byte)
	}
	f.files[path] = append([]byte(nil), data...)
	return nil
}

func (f *memoryFiles) Exists(path string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.files[path]
	return ok, nil
}

type scriptedExecutor struct {
	mu       sync.Mutex
	commands []string
	run      func(string, ...string) (CommandResult, error)
}

func (e *scriptedExecutor) Run(
	_ context.Context,
	name string,
	args ...string,
) (CommandResult, error) {
	e.mu.Lock()
	e.commands = append(e.commands, name+" "+strings.Join(args, " "))
	e.mu.Unlock()
	if e.run == nil {
		return CommandResult{}, nil
	}
	return e.run(name, args...)
}

func TestEmergencyPolicyIsAtomicDropFirstAndDisablesForwarding(t *testing.T) {
	files := &memoryFiles{}
	executor := &scriptedExecutor{}
	policy, err := NewEmergencyPolicy(EmergencyPolicyConfig{
		Executor: executor,
		Files:    files,
		Path:     "/run/test-emergency.nft",
	})
	if err != nil {
		t.Fatalf("NewEmergencyPolicy: %v", err)
	}
	if err := policy.Activate(context.Background()); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	data, err := files.ReadFile("/run/test-emergency.nft")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	text := string(data)
	if !strings.HasPrefix(text, "flush ruleset") ||
		!strings.Contains(text, "chain forward") ||
		!strings.Contains(text, "policy drop") ||
		!strings.Contains(text, EmergencyRuleSignature) {
		t.Fatalf("unexpected emergency policy:\n%s", text)
	}
	want := []string{
		"nft --check -f /run/test-emergency.nft",
		"nft -f /run/test-emergency.nft",
		"sysctl -w net.ipv4.ip_forward=0",
	}
	if fmt.Sprint(executor.commands) != fmt.Sprint(want) {
		t.Fatalf("commands = %v, want %v", executor.commands, want)
	}
}

func TestFullPolicyPrivateICMPAndRelayOrdering(t *testing.T) {
	snapshot := StaticSnapshot{
		Networks: []Network{{
			ID: "network-1", GatewayIPv4: "10.80.0.1",
			InterfaceName: "eth1", State: "active",
		}},
		Guests: []Guest{{
			ID: "guest-1", NetworkID: "network-1", IPv4: "10.80.0.10",
			State: "active",
		}},
		Relays: []Relay{{
			ID: "relay-1", VMID: "guest-1", TargetIPv4: "10.80.0.10",
			TargetPort: RelayTargetPort, State: "bound",
		}},
		NAT: []NATState{{
			VMID: "guest-1", State: "enabled", ConntrackMark: 101,
		}},
	}
	ruleset, forwarding, err := compileFullRuleset(
		snapshot, "eth0", "snapshot-hash", "compiled-hash")
	if err != nil {
		t.Fatalf("compileFullRuleset: %v", err)
	}
	if !forwarding {
		t.Fatal("forwarding = false, want true")
	}
	for _, line := range strings.Split(ruleset, "\n") {
		if strings.Contains(line, ApplianceRuleSignature) && len(strings.TrimSpace(line)) > 128 {
			t.Fatalf("nftables ownership comment exceeds 128 characters: %q", line)
		}
	}
	privateAccept := strings.Index(ruleset,
		`iifname "eth1" ip daddr 10.80.0.1 icmp type`)
	privateDrop := strings.Index(ruleset,
		`iifname "eth1" ip protocol icmp drop`)
	relayReply := strings.Index(ruleset,
		`iifname "eth1" ct state established ct direction reply ip saddr 10.80.0.10 ip daddr 10.80.0.1 tcp sport 9091 accept`)
	privateTerminal := strings.Index(ruleset,
		`iifname @private_ifaces drop comment "private-terminal-drop"`)
	broadEstablished := strings.Index(ruleset,
		`ct state established,related accept`)
	mainICMP := strings.LastIndex(ruleset,
		`iifname "eth0" icmp type`)
	for name, index := range map[string]int{
		"private accept":    privateAccept,
		"private drop":      privateDrop,
		"relay reply":       relayReply,
		"private terminal":  privateTerminal,
		"broad established": broadEstablished,
		"main ICMP":         mainICMP,
	} {
		if index < 0 {
			t.Fatalf("%s rule missing:\n%s", name, ruleset)
		}
	}
	if !(privateAccept < privateDrop &&
		privateDrop < relayReply &&
		relayReply < privateTerminal &&
		privateTerminal < broadEstablished &&
		broadEstablished < mainICMP) {
		t.Fatalf("unsafe input ordering:\n%s", ruleset)
	}
}

func TestNATPolicyGatesNewAndEstablishedFlowsByExactVMState(t *testing.T) {
	base := StaticSnapshot{
		Networks: []Network{{
			ID: "network-1", GatewayIPv4: "10.80.0.1",
			InterfaceName: "eth1", State: "active",
		}, {
			ID: "network-2", GatewayIPv4: "10.81.0.1",
			InterfaceName: "eth2", State: "active",
		}},
		Guests: []Guest{{
			ID: "guest-1", NetworkID: "network-1", IPv4: "10.80.0.10",
			State: "active",
		}},
	}

	enabled := base
	enabled.NAT = []NATState{{
		VMID: "guest-1", State: "enabled", ConntrackMark: 101,
	}}
	ruleset, forwarding, err := compileFullRuleset(
		enabled, "eth0", "snapshot-hash", "compiled-hash")
	if err != nil {
		t.Fatalf("compile enabled NAT: %v", err)
	}
	if !forwarding {
		t.Fatal("enabled NAT did not enable IPv4 forwarding")
	}
	for _, want := range []string{
		`"eth1" . 10.80.0.10 : 0x65`,
		`iifname @private_ifaces oifname "eth0" ct state new ct mark set iifname . ip saddr map @enabled_guest_marks accept`,
		`iifname @private_ifaces oifname "eth0" ct state established,related ct direction original iifname . ip saddr . ct mark @active_nat_sources accept`,
		`iifname "eth0" oifname @private_ifaces ct state established,related ct direction reply oifname . ip daddr . ct mark @active_nat_sources accept`,
		`oifname "eth0" iifname . ip saddr . ct mark @nat_sources masquerade`,
	} {
		if !strings.Contains(ruleset, want) {
			t.Fatalf("enabled ruleset lacks %q:\n%s", want, ruleset)
		}
	}
	crossDrop := strings.Index(ruleset,
		`iifname @private_ifaces oifname @private_ifaces drop comment "private-cross-network-drop"`)
	established := strings.Index(ruleset,
		`ct state established,related ct direction original`)
	if crossDrop < 0 || established < 0 || crossDrop > established {
		t.Fatalf("cross-private drop is not before established-flow accepts:\n%s", ruleset)
	}
	if strings.Contains(ruleset,
		`ct state established,related ct mark @active_nat_marks accept`) {
		t.Fatalf("ruleset contains unconditional marked established accept:\n%s", ruleset)
	}

	draining := base
	draining.NAT = []NATState{{
		VMID: "guest-1", State: "draining", ConntrackMark: 101,
	}}
	ruleset, forwarding, err = compileFullRuleset(
		draining, "eth0", "snapshot-hash", "compiled-hash")
	if err != nil {
		t.Fatalf("compile draining NAT: %v", err)
	}
	if !forwarding {
		t.Fatal("draining NAT disabled forwarding before existing flows expired")
	}
	if strings.Contains(ruleset, "ct state new ct mark set") {
		t.Fatalf("draining NAT still accepts new flows:\n%s", ruleset)
	}
	for _, want := range []string{
		`ct state established,related ct direction original`,
		`ct state established,related ct direction reply`,
		`masquerade`,
	} {
		if !strings.Contains(ruleset, want) {
			t.Fatalf("draining NAT lacks existing-flow rule %q:\n%s", want, ruleset)
		}
	}

	disabled := base
	disabled.NAT = []NATState{{
		VMID: "guest-1", State: "disabled", ConntrackMark: 101,
	}}
	ruleset, forwarding, err = compileFullRuleset(
		disabled, "eth0", "snapshot-hash", "compiled-hash")
	if err != nil {
		t.Fatalf("compile disabled NAT: %v", err)
	}
	if forwarding {
		t.Fatal("disabled NAT left IPv4 forwarding enabled")
	}
	for _, forbidden := range []string{
		"ct state new ct mark set",
		"ct state established,related ct direction",
		"masquerade",
	} {
		if strings.Contains(ruleset, forbidden) {
			t.Fatalf("disabled NAT contains %q:\n%s", forbidden, ruleset)
		}
	}
}

func TestConflictScannerReportsBootstrapFailurePlanWithoutDisablingServices(t *testing.T) {
	executor := &scriptedExecutor{
		run: func(name string, args ...string) (CommandResult, error) {
			command := name + " " + strings.Join(args, " ")
			switch command {
			case "systemctl is-enabled --quiet ufw.service":
				return CommandResult{}, nil
			case "systemctl is-active --quiet docker.service":
				return CommandResult{}, nil
			case "nft list ruleset":
				return CommandResult{Stdout: "table inet foreign {\n}\n"}, nil
			default:
				if name == "systemctl" {
					return CommandResult{ExitCode: 1}, nil
				}
				return CommandResult{}, nil
			}
		},
	}
	scanner, err := NewConflictScanner(ConflictScannerConfig{
		Executor: executor,
		Files:    &memoryFiles{},
	})
	if err != nil {
		t.Fatalf("NewConflictScanner: %v", err)
	}
	plan, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if plan.Revision == "" || len(plan.Conflicts) != 3 {
		t.Fatalf("conflict plan = %+v", plan)
	}
	for _, command := range executor.commands {
		if strings.Contains(command, " disable ") ||
			strings.Contains(command, " stop ") ||
			strings.Contains(command, " mask ") {
			t.Fatalf("scanner performed mutating command %q", command)
		}
	}
}
