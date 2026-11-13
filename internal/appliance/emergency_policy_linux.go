//go:build linux

package appliance

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const EmergencyRuleSignature = "lablink-appliance-emergency-v1"

const emergencyRuleset = `flush ruleset

table inet lablink {
    comment "` + EmergencyRuleSignature + `"

    chain input {
        type filter hook input priority filter; policy drop;
        iifname "lo" accept
        ct state invalid drop
        ct state established,related accept
        tcp dport 9091 accept
        icmp type { destination-unreachable, time-exceeded, parameter-problem, echo-request, echo-reply } accept
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }
}
`

type EmergencyPolicy struct {
	executor CommandExecutor
	files    FileSystem
	path     string
}

func NewEmergencyPolicy(config EmergencyPolicyConfig) (*EmergencyPolicy, error) {
	executor := config.Executor
	if executor == nil {
		executor = OSCommandExecutor{}
	}
	files := config.Files
	if files == nil {
		files = OSFileSystem{}
	}
	path := strings.TrimSpace(config.Path)
	if path == "" {
		path = defaultEmergencyPath
	}
	return &EmergencyPolicy{executor: executor, files: files, path: path}, nil
}

func (p *EmergencyPolicy) Ruleset() string {
	return emergencyRuleset
}

func (p *EmergencyPolicy) Activate(ctx context.Context) error {
	if err := p.files.WriteFileAtomic(p.path, []byte(emergencyRuleset), 0o600); err != nil {
		disableErr := runChecked(ctx, p.executor, "sysctl", "-w", "net.ipv4.ip_forward=0")
		return errors.Join(fmt.Errorf("appliance: write emergency nftables policy: %w", err),
			disableErr)
	}
	checkErr := runChecked(ctx, p.executor, "nft", "--check", "-f", p.path)
	var loadErr error
	if checkErr == nil {
		loadErr = runChecked(ctx, p.executor, "nft", "-f", p.path)
	}
	disableErr := runChecked(ctx, p.executor, "sysctl", "-w", "net.ipv4.ip_forward=0")
	if checkErr != nil {
		checkErr = fmt.Errorf("appliance: validate emergency nftables policy: %w", checkErr)
	}
	if loadErr != nil {
		loadErr = fmt.Errorf("appliance: load emergency nftables policy: %w", loadErr)
	}
	if disableErr != nil {
		disableErr = fmt.Errorf("appliance: disable IPv4 forwarding: %w", disableErr)
	}
	return errors.Join(checkErr, loadErr, disableErr)
}
