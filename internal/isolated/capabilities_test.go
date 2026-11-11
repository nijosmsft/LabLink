package isolated

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckAgentCompatibilityAcceptsCompleteSetAndUnknownCapabilities(t *testing.T) {
	t.Parallel()

	reported := []string{"future.unknown.v9"}
	for _, capability := range RequiredOrchestratorCapabilities() {
		reported = append(reported, string(capability))
	}
	err := CheckOrchestratorCompatibility(
		AgentCompatibility{
			Node:            "orch-1",
			AgentVersion:    "v1.2.3",
			Capabilities:    reported,
			ProtocolVersion: MinimumProtocolVersion,
		},
		"v1.2.4",
	)
	if err != nil {
		t.Fatalf("CheckAgentCompatibility(): %v", err)
	}
}

func TestMissingCapabilitiesFailClosedWithUpdateGuidance(t *testing.T) {
	t.Parallel()

	requirements := OrchestratorCompatibilityRequirements("server-v2")
	err := CheckAgentCompatibility(
		AgentCompatibility{
			Node:            "orch-abc",
			AgentVersion:    "agent-v1",
			Capabilities:    []string{string(CapabilityApplianceV1), "future.unknown.v9"},
			ProtocolVersion: MinimumProtocolVersion,
		},
		requirements,
	)
	if err == nil {
		t.Fatal("CheckAgentCompatibility() unexpectedly succeeded")
	}
	var compatibilityErr *CompatibilityError
	if !errors.As(err, &compatibilityErr) {
		t.Fatalf("error type = %T, want *CompatibilityError", err)
	}
	if compatibilityErr.Code != "AGENT_CAPABILITY_MISSING" {
		t.Fatalf("error code = %q", compatibilityErr.Code)
	}
	wantMissing := []Capability{
		CapabilityNetworkV1,
		CapabilityRelayV1,
		CapabilityNATV1,
		CapabilityStatsV1,
	}
	if len(compatibilityErr.MissingCapabilities) != len(wantMissing) {
		t.Fatalf("missing capabilities = %v, want %v", compatibilityErr.MissingCapabilities, wantMissing)
	}
	for i := range wantMissing {
		if compatibilityErr.MissingCapabilities[i] != wantMissing[i] {
			t.Fatalf("missing capabilities = %v, want %v", compatibilityErr.MissingCapabilities, wantMissing)
		}
	}
	for _, want := range []string{
		"AGENT_CAPABILITY_MISSING",
		string(CapabilityNetworkV1),
		string(CapabilityStatsV1),
		"agent-v1",
		"server-v2",
		"update_agent(node=orch-abc)",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestProtocolRangeBoundariesAndFailures(t *testing.T) {
	t.Parallel()

	requirements := CompatibilityRequirements{
		Capabilities: []Capability{CapabilityApplianceV1},
		ProtocolRange: ProtocolRange{
			Minimum: 2,
			Maximum: 4,
		},
		ServerVersion: "server-v4",
	}
	for _, version := range []uint32{2, 3, 4} {
		err := CheckAgentCompatibility(
			AgentCompatibility{
				Node:            "orch",
				AgentVersion:    "agent",
				Capabilities:    []string{string(CapabilityApplianceV1)},
				ProtocolVersion: version,
			},
			requirements,
		)
		if err != nil {
			t.Errorf("protocol version %d rejected: %v", version, err)
		}
	}
	for _, version := range []uint32{0, 1, 5} {
		err := CheckAgentCompatibility(
			AgentCompatibility{
				Node:            "orch",
				AgentVersion:    "agent",
				Capabilities:    []string{string(CapabilityApplianceV1)},
				ProtocolVersion: version,
			},
			requirements,
		)
		if err == nil {
			t.Errorf("protocol version %d unexpectedly accepted", version)
			continue
		}
		for _, want := range []string{
			"AGENT_PROTOCOL_UNSUPPORTED",
			"supported range is 2-4",
			"update_agent(node=orch)",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("protocol error %q does not contain %q", err, want)
			}
		}
	}
}

func TestCompatibilityRequirementsValidation(t *testing.T) {
	t.Parallel()

	if err := (ProtocolRange{Minimum: 0, Maximum: 1}).Validate(); err == nil {
		t.Fatal("zero minimum protocol unexpectedly accepted")
	}
	if err := (ProtocolRange{Minimum: 2, Maximum: 1}).Validate(); err == nil {
		t.Fatal("reversed protocol range unexpectedly accepted")
	}
	if err := (CompatibilityRequirements{
		ProtocolRange: ProtocolRange{Minimum: 1, Maximum: 1},
	}).Validate(); err == nil {
		t.Fatal("empty capability requirement unexpectedly accepted")
	}
	err := CheckAgentCompatibility(
		AgentCompatibility{},
		CompatibilityRequirements{
			Capabilities:  []Capability{""},
			ProtocolRange: ProtocolRange{Minimum: 1, Maximum: 1},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("empty required capability error = %v", err)
	}
}

func TestDuplicateRequirementsDoNotDuplicateDiagnostics(t *testing.T) {
	t.Parallel()

	err := CheckAgentCompatibility(
		AgentCompatibility{Node: "orch", ProtocolVersion: 1},
		CompatibilityRequirements{
			Capabilities: []Capability{CapabilityRelayV1, CapabilityRelayV1},
			ProtocolRange: ProtocolRange{
				Minimum: 1,
				Maximum: 1,
			},
		},
	)
	var compatibilityErr *CompatibilityError
	if !errors.As(err, &compatibilityErr) {
		t.Fatalf("error = %v, want compatibility error", err)
	}
	if len(compatibilityErr.MissingCapabilities) != 1 {
		t.Fatalf("missing capabilities = %v, want one entry", compatibilityErr.MissingCapabilities)
	}
	if !strings.Contains(err.Error(), "update_agent(node=orch)") {
		t.Fatalf("missing update guidance: %v", err)
	}
}

func TestMissingNodeUsesExplicitPlaceholderGuidance(t *testing.T) {
	t.Parallel()

	err := CheckAgentCompatibility(
		AgentCompatibility{ProtocolVersion: 1},
		CompatibilityRequirements{
			Capabilities:  []Capability{CapabilityRelayV1},
			ProtocolRange: ProtocolRange{Minimum: 1, Maximum: 1},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "update_agent(node=<orchestrator-node>)") {
		t.Fatalf("error = %v, want placeholder update guidance", err)
	}
}
