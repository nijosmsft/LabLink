//go:build linux

package appliance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	defaultRulesetPath   = "/run/lablink/appliance.nft"
	defaultEmergencyPath = "/run/lablink/emergency.nft"
)

type OSCommandExecutor struct{}

func (OSCommandExecutor) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	command := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	result := CommandResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if err == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}
	return result, err
}

type OSFileSystem struct{}

func (OSFileSystem) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (OSFileSystem) Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (OSFileSystem) WriteFileAtomic(path string, data []byte, mode fs.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	return directoryFile.Sync()
}

type LinuxCompiler struct {
	mainInterface string
}

type linuxPrivateNetwork struct {
	ID, Interface, Gateway string
}

func NewLinuxCompiler(config LinuxCompilerConfig) (*LinuxCompiler, error) {
	mainInterface := strings.TrimSpace(config.MainInterface)
	if err := validateInterfaceName(mainInterface); err != nil {
		return nil, fmt.Errorf("appliance: main interface: %w", err)
	}
	return &LinuxCompiler{mainInterface: mainInterface}, nil
}

func (c *LinuxCompiler) Compile(
	_ context.Context,
	snapshot DesiredSnapshot,
	intent Intent,
) (CompiledApply, error) {
	snapshotHash, err := HashDesiredSnapshot(snapshot)
	if err != nil {
		return CompiledApply{}, err
	}
	ruleset, forwarding, err := compileFullRuleset(
		snapshot, c.mainInterface, snapshotHash, compiledHashToken)
	if err != nil {
		return CompiledApply{}, err
	}
	return CompiledApply{
		Intent:           intent,
		Artifacts:        map[string][]byte{NFTablesArtifact: []byte(ruleset)},
		EnableForwarding: forwarding,
	}, nil
}

type LinuxApplyTarget struct {
	executor  CommandExecutor
	files     FileSystem
	path      string
	emergency *EmergencyPolicy
}

func NewLinuxApplyTarget(config LinuxTargetConfig) (*LinuxApplyTarget, error) {
	executor := config.Executor
	if executor == nil {
		executor = OSCommandExecutor{}
	}
	files := config.Files
	if files == nil {
		files = OSFileSystem{}
	}
	path := strings.TrimSpace(config.RulesetPath)
	if path == "" {
		path = defaultRulesetPath
	}
	emergencyPath := strings.TrimSpace(config.EmergencyPath)
	if emergencyPath == "" {
		emergencyPath = defaultEmergencyPath
	}
	emergency, err := NewEmergencyPolicy(EmergencyPolicyConfig{
		Executor: executor,
		Files:    files,
		Path:     emergencyPath,
	})
	if err != nil {
		return nil, err
	}
	return &LinuxApplyTarget{
		executor:  executor,
		files:     files,
		path:      path,
		emergency: emergency,
	}, nil
}

func (t *LinuxApplyTarget) ActivateEmergency(ctx context.Context) error {
	return t.emergency.Activate(ctx)
}

func (t *LinuxApplyTarget) Apply(ctx context.Context, compiled CompiledApply) error {
	ruleset, ok := compiled.Artifacts[NFTablesArtifact]
	if !ok || len(ruleset) == 0 {
		return fmt.Errorf("appliance: compiled nftables artifact is missing")
	}
	if !bytes.Contains(ruleset, []byte("flush ruleset")) ||
		!bytes.Contains(ruleset, []byte(ApplianceRuleSignature)) ||
		!bytes.Contains(ruleset, []byte("compiled="+compiled.CompiledHash)) {
		return fmt.Errorf("appliance: compiled nftables artifact lacks ownership metadata")
	}
	if err := t.files.WriteFileAtomic(t.path, ruleset, 0o600); err != nil {
		return fmt.Errorf("appliance: write nftables candidate: %w", err)
	}
	if err := runChecked(ctx, t.executor, "nft", "--check", "-f", t.path); err != nil {
		_ = t.ActivateEmergency(ctx)
		return fmt.Errorf("appliance: validate nftables candidate: %w", err)
	}
	if err := runChecked(ctx, t.executor, "nft", "-f", t.path); err != nil {
		_ = t.ActivateEmergency(ctx)
		return fmt.Errorf("appliance: atomically load nftables ruleset: %w", err)
	}
	forwarding := "0"
	if compiled.EnableForwarding {
		forwarding = "1"
	}
	if err := runChecked(ctx, t.executor, "sysctl", "-w",
		"net.ipv4.ip_forward="+forwarding); err != nil {
		_ = t.ActivateEmergency(ctx)
		return fmt.Errorf("appliance: set IPv4 forwarding: %w", err)
	}
	return nil
}

func (t *LinuxApplyTarget) Verify(
	ctx context.Context,
	compiled CompiledApply,
) (Verification, error) {
	rules, err := t.executor.Run(ctx, "nft", "list", "ruleset")
	if err != nil {
		return Verification{}, err
	}
	if rules.ExitCode != 0 {
		return Verification{}, commandFailure("nft list ruleset", rules)
	}
	if !strings.Contains(rules.Stdout, ApplianceRuleSignature) {
		return Verification{Detail: "nftables ownership signature is absent"}, nil
	}
	if !strings.Contains(rules.Stdout, "compiled="+compiled.CompiledHash) {
		return Verification{Detail: "nftables compiled hash does not match"}, nil
	}
	forwarding, err := t.executor.Run(ctx, "sysctl", "-n", "net.ipv4.ip_forward")
	if err != nil {
		return Verification{}, err
	}
	if forwarding.ExitCode != 0 {
		return Verification{}, commandFailure("sysctl -n net.ipv4.ip_forward", forwarding)
	}
	want := "0"
	if compiled.EnableForwarding {
		want = "1"
	}
	if strings.TrimSpace(forwarding.Stdout) != want {
		return Verification{Detail: fmt.Sprintf(
			"IPv4 forwarding is %q, want %s", strings.TrimSpace(forwarding.Stdout), want)}, nil
	}
	return Verification{Matched: true}, nil
}

func compileFullRuleset(
	snapshot DesiredSnapshot,
	mainInterface, snapshotHash, compiledHash string,
) (string, bool, error) {
	if err := validateInterfaceName(mainInterface); err != nil {
		return "", false, err
	}
	networks := make(map[string]linuxPrivateNetwork)
	var private []linuxPrivateNetwork
	for _, network := range snapshot.Networks {
		if network.RetiredAtUnix != nil || network.State == "retired" {
			continue
		}
		if err := validateInterfaceName(network.InterfaceName); err != nil {
			return "", false, fmt.Errorf("network %s interface: %w", network.ID, err)
		}
		gateway, err := netip.ParseAddr(network.GatewayIPv4)
		if err != nil || !gateway.Is4() {
			return "", false, fmt.Errorf("network %s has invalid gateway IPv4 %q",
				network.ID, network.GatewayIPv4)
		}
		item := linuxPrivateNetwork{network.ID, network.InterfaceName, gateway.String()}
		networks[network.ID] = item
		private = append(private, item)
	}
	sort.Slice(private, func(i, j int) bool { return private[i].Interface < private[j].Interface })

	guests := make(map[string]Guest)
	for _, guest := range snapshot.Guests {
		if guest.RetiredAtUnix != nil || guest.State == "retired" {
			continue
		}
		address, err := netip.ParseAddr(guest.IPv4)
		if err != nil || !address.Is4() {
			return "", false, fmt.Errorf("guest %s has invalid IPv4 %q", guest.ID, guest.IPv4)
		}
		if _, ok := networks[guest.NetworkID]; !ok {
			return "", false, fmt.Errorf("guest %s references inactive network %s",
				guest.ID, guest.NetworkID)
		}
		guest.IPv4 = address.String()
		guests[guest.ID] = guest
	}

	var activeMarks, natPairs, enabledMappings []string
	for _, state := range snapshot.NAT {
		guest, ok := guests[state.VMID]
		if !ok {
			if state.State == "disabled" {
				continue
			}
			return "", false, fmt.Errorf("NAT state references inactive guest %s", state.VMID)
		}
		if state.ConntrackMark <= 0 {
			return "", false, fmt.Errorf("NAT state for %s has invalid conntrack mark %d",
				state.VMID, state.ConntrackMark)
		}
		network := networks[guest.NetworkID]
		mark := fmt.Sprintf("0x%x", state.ConntrackMark)
		switch state.State {
		case "enabled":
			activeMarks = append(activeMarks, mark)
			natPairs = append(natPairs, guest.IPv4+" . "+mark)
			enabledMappings = append(enabledMappings,
				quoteNFT(network.Interface)+" . "+guest.IPv4+" : "+mark)
		case "draining":
			activeMarks = append(activeMarks, mark)
			natPairs = append(natPairs, guest.IPv4+" . "+mark)
		case "disabled":
		default:
			return "", false, fmt.Errorf("NAT state for %s has invalid state %q",
				state.VMID, state.State)
		}
	}
	sort.Strings(activeMarks)
	sort.Strings(natPairs)
	sort.Strings(enabledMappings)

	var relayRules []string
	for _, relay := range snapshot.Relays {
		if relay.RetiredAtUnix != nil || relay.State == "retired" ||
			relay.State == "disabled" {
			continue
		}
		guest, ok := guests[relay.VMID]
		if !ok {
			return "", false, fmt.Errorf("relay %s references inactive guest %s",
				relay.ID, relay.VMID)
		}
		if relay.TargetPort != RelayTargetPort {
			return "", false, fmt.Errorf("relay %s target port is %d, want %d",
				relay.ID, relay.TargetPort, RelayTargetPort)
		}
		target, err := netip.ParseAddr(relay.TargetIPv4)
		if err != nil || !target.Is4() || target.String() != guest.IPv4 {
			return "", false, fmt.Errorf("relay %s target %q is not guest %s IPv4 %s",
				relay.ID, relay.TargetIPv4, guest.ID, guest.IPv4)
		}
		network := networks[guest.NetworkID]
		relayRules = append(relayRules, fmt.Sprintf(
			"        iifname %s ct state established ct direction reply ip saddr %s ip daddr %s tcp sport %d accept comment %s",
			quoteNFT(network.Interface), guest.IPv4, network.Gateway,
			RelayTargetPort, quoteNFT("relay:"+relay.ID)))
	}
	sort.Strings(relayRules)

	var builder strings.Builder
	builder.WriteString("flush ruleset\n\n")
	builder.WriteString("table inet lablink {\n")
	fmt.Fprintf(&builder, "    comment %s\n", quoteNFT(
		ApplianceRuleSignature+" snapshot="+snapshotHash+" compiled="+compiledHash))
	writeSet(&builder, "private_ifaces", "ifname", privateInterfaces(private))
	writeSet(&builder, "active_nat_marks", "mark", activeMarks)
	writeMap(&builder, "enabled_guest_marks", "ifname . ipv4_addr : mark", enabledMappings)
	writeSet(&builder, "nat_sources", "ipv4_addr . mark", natPairs)

	builder.WriteString("    chain input {\n")
	builder.WriteString("        type filter hook input priority filter; policy drop;\n")
	builder.WriteString("        iifname \"lo\" accept\n")
	builder.WriteString("        ct state invalid drop\n")
	for _, network := range private {
		fmt.Fprintf(&builder,
			"        iifname %s ip daddr %s icmp type { destination-unreachable, time-exceeded, parameter-problem, echo-request, echo-reply } accept comment %s\n",
			quoteNFT(network.Interface), network.Gateway,
			quoteNFT("private-gateway-icmp:"+network.ID))
		fmt.Fprintf(&builder,
			"        iifname %s ip protocol icmp drop comment %s\n",
			quoteNFT(network.Interface), quoteNFT("private-non-gateway-icmp:"+network.ID))
	}
	for _, rule := range relayRules {
		builder.WriteString(rule)
		builder.WriteByte('\n')
	}
	if len(private) != 0 {
		builder.WriteString("        iifname @private_ifaces drop comment \"private-terminal-drop\"\n")
	}
	builder.WriteString("        ct state established,related accept\n")
	fmt.Fprintf(&builder, "        iifname %s tcp dport { %d, 20000-39999 } accept\n",
		quoteNFT(mainInterface), RelayTargetPort)
	fmt.Fprintf(&builder,
		"        iifname %s icmp type { destination-unreachable, time-exceeded, parameter-problem, echo-request, echo-reply } accept\n",
		quoteNFT(mainInterface))
	builder.WriteString("    }\n\n")

	builder.WriteString("    chain output {\n")
	builder.WriteString("        type filter hook output priority filter; policy accept;\n")
	builder.WriteString("    }\n\n")

	builder.WriteString("    chain forward {\n")
	builder.WriteString("        type filter hook forward priority filter; policy drop;\n")
	builder.WriteString("        ct state invalid drop\n")
	if len(private) != 0 {
		builder.WriteString("        iifname @private_ifaces oifname @private_ifaces drop comment \"private-cross-network-drop\"\n")
	}
	if len(activeMarks) != 0 {
		builder.WriteString("        ct state established,related ct mark @active_nat_marks accept\n")
	}
	if len(enabledMappings) != 0 {
		fmt.Fprintf(&builder,
			"        iifname @private_ifaces oifname %s ct state new ct mark set iifname . ip saddr map @enabled_guest_marks accept\n",
			quoteNFT(mainInterface))
	}
	builder.WriteString("    }\n\n")

	builder.WriteString("    chain postrouting {\n")
	builder.WriteString("        type nat hook postrouting priority srcnat; policy accept;\n")
	if len(natPairs) != 0 {
		fmt.Fprintf(&builder,
			"        oifname %s ip saddr . ct mark @nat_sources masquerade\n",
			quoteNFT(mainInterface))
	}
	builder.WriteString("    }\n")
	builder.WriteString("}\n")
	return builder.String(), len(private) != 0, nil
}

func privateInterfaces(networks []linuxPrivateNetwork) []string {
	values := make([]string, 0, len(networks))
	for _, network := range networks {
		values = append(values, quoteNFT(network.Interface))
	}
	return values
}

func writeSet(builder *strings.Builder, name, itemType string, elements []string) {
	fmt.Fprintf(builder, "    set %s {\n        type %s\n", name, itemType)
	if len(elements) != 0 {
		fmt.Fprintf(builder, "        elements = { %s }\n", strings.Join(elements, ", "))
	}
	builder.WriteString("    }\n\n")
}

func writeMap(builder *strings.Builder, name, itemType string, elements []string) {
	fmt.Fprintf(builder, "    map %s {\n        type %s\n", name, itemType)
	if len(elements) != 0 {
		fmt.Fprintf(builder, "        elements = { %s }\n", strings.Join(elements, ", "))
	}
	builder.WriteString("    }\n\n")
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

func quoteNFT(value string) string {
	return strconv.Quote(value)
}

func runChecked(
	ctx context.Context,
	executor CommandExecutor,
	name string,
	args ...string,
) error {
	result, err := executor.Run(ctx, name, args...)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return commandFailure(name+" "+strings.Join(args, " "), result)
	}
	return nil
}

func commandFailure(command string, result CommandResult) error {
	detail := strings.TrimSpace(result.Stderr)
	if detail == "" {
		detail = strings.TrimSpace(result.Stdout)
	}
	if detail == "" {
		detail = "no diagnostic output"
	}
	return fmt.Errorf("%s exited with code %d: %s", command, result.ExitCode, detail)
}
