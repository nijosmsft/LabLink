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
	snapshot := DesiredSnapshot{
		Status:    Status{InventoryGeneration: 6},
		Authority: Authority{Fence: 4, ParentGeneration: 2, ParentState: "active"},
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

func TestConflictScannerProducesApprovalPlanWithoutDisablingServices(t *testing.T) {
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
	if !plan.ApprovalRequired || plan.Revision == "" || len(plan.Conflicts) != 3 {
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
