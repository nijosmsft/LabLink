//go:build linux

package appliance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type ConflictScanner struct {
	executor CommandExecutor
	files    FileSystem
}

type conflictingService struct {
	Name   string
	Detail string
}

var conflictingServices = []conflictingService{
	{UFWServiceName, "UFW owns firewall policy"},
	{FirewalldServiceName, "firewalld owns dynamic firewall policy"},
	{"docker.service", "Docker may manage nftables or iptables NAT policy"},
	{"docker.socket", "Docker socket activation may start Docker firewall management"},
	{"podman.service", "Podman may manage nftables or iptables NAT policy"},
	{"podman.socket", "Podman socket activation may start container firewall management"},
	{"netavark-dhcp-proxy.service", "Netavark may manage container network policy"},
	{"nftables.service", "the distribution nftables service may restore another ruleset"},
	{"netfilter-persistent.service", "netfilter-persistent may restore another ruleset"},
}

func NewConflictScanner(config ConflictScannerConfig) (*ConflictScanner, error) {
	executor := config.Executor
	if executor == nil {
		executor = OSCommandExecutor{}
	}
	files := config.Files
	if files == nil {
		files = OSFileSystem{}
	}
	return &ConflictScanner{executor: executor, files: files}, nil
}

func (s *ConflictScanner) Scan(ctx context.Context) (ConflictPlan, error) {
	var conflicts []Conflict
	var actions []ConflictAction
	foundService := make(map[string]bool)
	for _, service := range conflictingServices {
		enabled, err := s.serviceState(ctx, "is-enabled", service.Name)
		if err != nil {
			return ConflictPlan{}, err
		}
		active, err := s.serviceState(ctx, "is-active", service.Name)
		if err != nil {
			return ConflictPlan{}, err
		}
		if !enabled && !active {
			continue
		}
		conflicts = append(conflicts, Conflict{
			Kind:    ConflictService,
			Name:    service.Name,
			Detail:  service.Detail,
			Enabled: enabled,
			Active:  active,
		})
		foundService[service.Name] = true
		actions = append(actions, ConflictAction{
			Service: service.Name,
			Action:  "systemctl disable --now " + service.Name,
		})
	}
	if !foundService[UFWServiceName] {
		exists, err := s.files.Exists("/etc/ufw/ufw.conf")
		if err != nil {
			return ConflictPlan{}, fmt.Errorf("appliance: inspect UFW configuration: %w", err)
		}
		if exists {
			data, err := s.files.ReadFile("/etc/ufw/ufw.conf")
			if err != nil {
				return ConflictPlan{}, fmt.Errorf("appliance: read UFW configuration: %w", err)
			}
			if ufwEnabled(string(data)) {
				conflicts = append(conflicts, Conflict{
					Kind:   ConflictConfiguration,
					Name:   "ufw",
					Detail: "UFW configuration has ENABLED=yes",
				})
				actions = append(actions, ConflictAction{
					Service: "ufw",
					Action:  "ufw disable",
				})
			}
		}
	}

	rules, err := s.executor.Run(ctx, "nft", "list", "ruleset")
	if err != nil {
		return ConflictPlan{}, fmt.Errorf("appliance: inspect nftables ruleset: %w", err)
	}

	if rules.ExitCode != 0 {
		return ConflictPlan{}, commandFailure("nft list ruleset", rules)
	}
	if unmanagedRuleset(rules.Stdout) {
		conflicts = append(conflicts, Conflict{
			Kind:   ConflictRuleset,
			Name:   "nftables",
			Detail: "a non-empty ruleset is not exclusively owned by the LabLink appliance",
		})
		actions = append(actions, ConflictAction{
			Service: "nftables",
			Action:  "replace the complete ruleset with the approved LabLink appliance policy",
		})
	}

	sort.Slice(conflicts, func(i, j int) bool {
		if conflicts[i].Kind == conflicts[j].Kind {
			return conflicts[i].Name < conflicts[j].Name
		}
		return conflicts[i].Kind < conflicts[j].Kind
	})
	sort.Slice(actions, func(i, j int) bool {
		if actions[i].Service == actions[j].Service {
			return actions[i].Action < actions[j].Action
		}
		return actions[i].Service < actions[j].Service
	})
	plan := ConflictPlan{
		Conflicts: conflicts,
		Actions:   actions,
	}
	plan.Revision = conflictRevision(plan)
	return plan, nil
}

func ufwEnabled(configuration string) bool {
	for _, line := range strings.Split(configuration, "\n") {
		line = strings.TrimSpace(line)
		if strings.EqualFold(line, "ENABLED=yes") {
			return true
		}
	}
	return false
}

func (s *ConflictScanner) serviceState(
	ctx context.Context,
	verb, service string,
) (bool, error) {
	result, err := s.executor.Run(ctx, "systemctl", verb, "--quiet", service)
	if err != nil {
		return false, fmt.Errorf("appliance: systemctl %s %s: %w", verb, service, err)
	}
	switch result.ExitCode {
	case 0:
		return true, nil
	case 1, 3, 4:
		return false, nil
	default:
		return false, commandFailure("systemctl "+verb+" --quiet "+service, result)
	}
}

func unmanagedRuleset(ruleset string) bool {
	trimmed := strings.TrimSpace(ruleset)
	if trimmed == "" {
		return false
	}
	if !strings.Contains(trimmed, ApplianceRuleSignature) &&
		!strings.Contains(trimmed, EmergencyRuleSignature) {
		return true
	}
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "table ") && line != "table inet lablink {" {
			return true
		}
	}
	return false
}

func conflictRevision(plan ConflictPlan) string {
	canonical := struct {
		Conflicts []Conflict       `json:"conflicts"`
		Actions   []ConflictAction `json:"actions"`
	}{
		Conflicts: plan.Conflicts,
		Actions:   plan.Actions,
	}
	data, _ := json.Marshal(canonical)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
