package cascadeauth

import "testing"

func TestCanonicalCascadeVocabularyIsResourceScoped(t *testing.T) {
	for _, resourceType := range []string{"vm", "relay", "nat", "network"} {
		operations, err := OperationsForResource(resourceType)
		if err != nil {
			t.Fatal(err)
		}
		for _, operation := range operations {
			parsed, err := Parse(string(operation.Action))
			if err != nil {
				t.Fatal(err)
			}
			if parsed != operation.Action {
				t.Fatalf("parsed action = %q, want %q", parsed, operation.Action)
			}
			if err := ValidateScope(operation.ResourceType, operation.Action); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := Parse("delete"); err == nil {
		t.Fatal("unknown generic cascade action was accepted")
	}
	if err := ValidateScope("network", ActionGuestDeleteExact); err == nil {
		t.Fatal("guest deletion was accepted for a network resource")
	}
}
