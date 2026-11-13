package isolated

import (
	"fmt"
	"strings"
)

type Capability string

const (
	CapabilityApplianceV1        Capability = "isolated.appliance.v1"
	CapabilityNetworkV1          Capability = "isolated.network.v1"
	CapabilityRelayV1            Capability = "isolated.relay.v1"
	CapabilityNATV1              Capability = "isolated.nat.v1"
	CapabilityStatsV1            Capability = "isolated.stats.v1"
	CapabilityAuthorityReleaseV1 Capability = "isolated.authority-release.v1"
	CapabilityParentLifecycleV1  Capability = "isolated.parent-lifecycle.v1"

	// Isolated orchestrators have no legacy fallback: authority release and
	// frozen-parent lifecycle are mandatory protocol-v2 operations.
	MinimumProtocolVersion uint32 = 2
	MaximumProtocolVersion uint32 = 2
)

type ProtocolRange struct {
	Minimum uint32
	Maximum uint32
}

type CompatibilityRequirements struct {
	Capabilities  []Capability
	ProtocolRange ProtocolRange
	ServerVersion string
}

type AgentCompatibility struct {
	Node            string
	AgentVersion    string
	Capabilities    []string
	ProtocolVersion uint32
}

type CompatibilityError struct {
	Code                string
	Node                string
	AgentVersion        string
	ServerVersion       string
	MissingCapabilities []Capability
	ProtocolVersion     uint32
	SupportedProtocol   ProtocolRange
}

func RequiredOrchestratorCapabilities() []Capability {
	return []Capability{
		CapabilityApplianceV1,
		CapabilityNetworkV1,
		CapabilityRelayV1,
		CapabilityNATV1,
		CapabilityStatsV1,
		CapabilityAuthorityReleaseV1,
		CapabilityParentLifecycleV1,
	}
}

func OrchestratorCompatibilityRequirements(serverVersion string) CompatibilityRequirements {
	return CompatibilityRequirements{
		Capabilities: RequiredOrchestratorCapabilities(),
		ProtocolRange: ProtocolRange{
			Minimum: MinimumProtocolVersion,
			Maximum: MaximumProtocolVersion,
		},
		ServerVersion: serverVersion,
	}
}

func CheckOrchestratorCompatibility(agent AgentCompatibility, serverVersion string) error {
	return CheckAgentCompatibility(agent, OrchestratorCompatibilityRequirements(serverVersion))
}

func (r ProtocolRange) Validate() error {
	if r.Minimum == 0 || r.Maximum == 0 || r.Minimum > r.Maximum {
		return fmt.Errorf(
			"invalid protocol range %d-%d: versions must be non-zero and ordered",
			r.Minimum,
			r.Maximum,
		)
	}
	return nil
}

func (r ProtocolRange) Contains(version uint32) bool {
	return r.Validate() == nil && version >= r.Minimum && version <= r.Maximum
}

func (r CompatibilityRequirements) Validate() error {
	if err := r.ProtocolRange.Validate(); err != nil {
		return err
	}
	if len(r.Capabilities) == 0 {
		return fmt.Errorf("at least one required capability must be specified")
	}
	for _, capability := range r.Capabilities {
		if strings.TrimSpace(string(capability)) == "" {
			return fmt.Errorf("required capability must not be empty")
		}
	}
	return nil
}

func CheckAgentCompatibility(
	agent AgentCompatibility,
	requirements CompatibilityRequirements,
) error {
	if err := requirements.Validate(); err != nil {
		return err
	}
	if agent.ProtocolVersion < requirements.ProtocolRange.Minimum {
		return &CompatibilityError{
			Code:              "AGENT_UPGRADE_REQUIRED",
			Node:              agent.Node,
			AgentVersion:      agent.AgentVersion,
			ServerVersion:     requirements.ServerVersion,
			ProtocolVersion:   agent.ProtocolVersion,
			SupportedProtocol: requirements.ProtocolRange,
		}
	}
	if agent.ProtocolVersion > requirements.ProtocolRange.Maximum {
		return &CompatibilityError{
			Code:              "AGENT_PROTOCOL_UNSUPPORTED",
			Node:              agent.Node,
			AgentVersion:      agent.AgentVersion,
			ServerVersion:     requirements.ServerVersion,
			ProtocolVersion:   agent.ProtocolVersion,
			SupportedProtocol: requirements.ProtocolRange,
		}
	}

	reported := make(map[string]struct{}, len(agent.Capabilities))
	for _, capability := range agent.Capabilities {
		reported[capability] = struct{}{}
	}
	missing := make([]Capability, 0)
	seenRequired := make(map[Capability]struct{}, len(requirements.Capabilities))
	for _, capability := range requirements.Capabilities {
		if _, duplicate := seenRequired[capability]; duplicate {
			continue
		}
		seenRequired[capability] = struct{}{}
		if _, ok := reported[string(capability)]; !ok {
			missing = append(missing, capability)
		}
	}
	if len(missing) > 0 {
		return &CompatibilityError{
			Code:                "AGENT_CAPABILITY_MISSING",
			Node:                agent.Node,
			AgentVersion:        agent.AgentVersion,
			ServerVersion:       requirements.ServerVersion,
			MissingCapabilities: missing,
			ProtocolVersion:     agent.ProtocolVersion,
			SupportedProtocol:   requirements.ProtocolRange,
		}
	}
	return nil
}

func (e *CompatibilityError) Error() string {
	if e == nil {
		return ""
	}
	node := strings.TrimSpace(e.Node)
	guidanceNode := node
	if guidanceNode == "" {
		guidanceNode = "<orchestrator-node>"
	}
	agentVersion := fallbackValue(e.AgentVersion, "<unknown>")
	serverVersion := fallbackValue(e.ServerVersion, "<unknown>")

	switch e.Code {
	case "AGENT_CAPABILITY_MISSING":
		missing := make([]string, len(e.MissingCapabilities))
		for i, capability := range e.MissingCapabilities {
			missing[i] = string(capability)
		}
		return fmt.Sprintf(
			"%s: node %q agent version %q is missing required capabilities [%s]; server version %q; run update_agent(node=%s)",
			e.Code,
			node,
			agentVersion,
			strings.Join(missing, ", "),
			serverVersion,
			guidanceNode,
		)
	case "AGENT_PROTOCOL_UNSUPPORTED":
		return fmt.Sprintf(
			"%s: node %q agent version %q reports protocol version %d, supported range is %d-%d; server version %q; run update_agent(node=%s)",
			e.Code,
			node,
			agentVersion,
			e.ProtocolVersion,
			e.SupportedProtocol.Minimum,
			e.SupportedProtocol.Maximum,
			serverVersion,
			guidanceNode,
		)
	case "AGENT_UPGRADE_REQUIRED":
		return fmt.Sprintf(
			"%s: node %q agent version %q reports protocol version %d but isolated appliance protocol v%d or newer is required for authority release and frozen lifecycle; server version %q; run update_agent(node=%s)",
			e.Code,
			node,
			agentVersion,
			e.ProtocolVersion,
			e.SupportedProtocol.Minimum,
			serverVersion,
			guidanceNode,
		)
	default:
		return fallbackValue(e.Code, "AGENT_INCOMPATIBLE")
	}
}

func fallbackValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
