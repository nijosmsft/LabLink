package isolated

import (
	"strings"
	"testing"
)

func TestGeneratedImmutableIDsAreCanonicalRandomUUIDs(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{})
	for i := 0; i < 128; i++ {
		values := []struct {
			kind string
			id   string
			err  error
		}{
			newOrchestratorIDForTest(),
			newNetworkIDForTest(),
			newVMIDForTest(),
			newRelayIDForTest(),
			newOperationIDForTest(),
		}
		for _, value := range values {
			if value.err != nil {
				t.Fatalf("New%sID: %v", value.kind, value.err)
			}
			if !canonicalRandomUUID.MatchString(value.id) {
				t.Fatalf("%s ID %q is not a canonical random UUID", value.kind, value.id)
			}
			if _, duplicate := seen[value.id]; duplicate {
				t.Fatalf("duplicate generated ID %q", value.id)
			}
			seen[value.id] = struct{}{}
		}
	}
}

func TestParseImmutableIDsNormalizeCaseAndWhitespace(t *testing.T) {
	t.Parallel()

	const upper = " AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE "
	const want = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

	orchestratorID, err := ParseOrchestratorID(upper)
	if err != nil || orchestratorID.String() != want {
		t.Fatalf("ParseOrchestratorID() = %q, %v", orchestratorID, err)
	}
	networkID, err := ParseNetworkID(upper)
	if err != nil || networkID.String() != want {
		t.Fatalf("ParseNetworkID() = %q, %v", networkID, err)
	}
	vmID, err := ParseVMID(upper)
	if err != nil || vmID.String() != want {
		t.Fatalf("ParseVMID() = %q, %v", vmID, err)
	}
	relayID, err := ParseRelayID(upper)
	if err != nil || relayID.String() != want {
		t.Fatalf("ParseRelayID() = %q, %v", relayID, err)
	}
	operationID, err := ParseOperationID(upper)
	if err != nil || operationID.String() != want {
		t.Fatalf("ParseOperationID() = %q, %v", operationID, err)
	}
}

func TestImmutableIDValidationRejectsNonRandomOrNonCanonicalValues(t *testing.T) {
	t.Parallel()

	tests := []string{
		"",
		"not-a-uuid",
		"aaaaaaaa-bbbb-1ccc-8ddd-eeeeeeeeeeee",
		"aaaaaaaa-bbbb-4ccc-7ddd-eeeeeeeeeeee",
		"{aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee}",
		"AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
	}
	for _, value := range tests {
		if err := OrchestratorID(value).Validate(); err == nil {
			t.Errorf("OrchestratorID(%q).Validate() unexpectedly succeeded", value)
		}
	}
}

func TestImmutableIDShortFormIsStable(t *testing.T) {
	t.Parallel()

	id := OrchestratorID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
	if got, want := id.Short(), "aaaaaaaabbbb"; got != want {
		t.Fatalf("Short() = %q, want %q", got, want)
	}
	if len(id.Short()) != ShortIDLength || strings.Contains(id.Short(), "-") {
		t.Fatalf("short ID %q has an invalid shape", id.Short())
	}
	if got := OrchestratorID("invalid").Short(); got != "" {
		t.Fatalf("invalid short ID = %q, want empty", got)
	}
}

func newOrchestratorIDForTest() struct {
	kind string
	id   string
	err  error
} {
	id, err := NewOrchestratorID()
	return struct {
		kind string
		id   string
		err  error
	}{"Orchestrator", id.String(), err}
}

func newNetworkIDForTest() struct {
	kind string
	id   string
	err  error
} {
	id, err := NewNetworkID()
	return struct {
		kind string
		id   string
		err  error
	}{"Network", id.String(), err}
}

func newVMIDForTest() struct {
	kind string
	id   string
	err  error
} {
	id, err := NewVMID()
	return struct {
		kind string
		id   string
		err  error
	}{"VM", id.String(), err}
}

func newRelayIDForTest() struct {
	kind string
	id   string
	err  error
} {
	id, err := NewRelayID()
	return struct {
		kind string
		id   string
		err  error
	}{"Relay", id.String(), err}
}

func newOperationIDForTest() struct {
	kind string
	id   string
	err  error
} {
	id, err := NewOperationID()
	return struct {
		kind string
		id   string
		err  error
	}{"Operation", id.String(), err}
}
