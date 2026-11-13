package isolated

import (
	"regexp"
	"strings"
	"testing"
)

func TestNormalizeHumanPrefix(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"  My Fancy_VM.Name  ": "my-fancy-vm-name",
		"network---east":       "network-east",
		"Équipe / 東京 / 42":     "quipe-42",
		"__A__B__":             "a-b",
		"---":                  "",
	}
	for input, want := range tests {
		if got := NormalizeHumanPrefix(input); got != want {
			t.Errorf("NormalizeHumanPrefix(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestPhysicalNameIsDeterministicSafeAndLengthBounded(t *testing.T) {
	t.Parallel()

	const id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	const prefix = "A Very Long Human Prefix With Spaces / Symbols"

	first, err := PhysicalName(prefix, id, 32)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PhysicalName(prefix, id, 32)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("physical name is not deterministic: %q != %q", first, second)
	}
	if len(first) > 32 || !regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(first) {
		t.Fatalf("physical name %q is not safe and bounded", first)
	}
	if !strings.HasSuffix(first, "-aaaaaaaabbbb") {
		t.Fatalf("physical name %q does not preserve immutable short ID", first)
	}
}

func TestPhysicalNameCollisionResistanceComesFromImmutableID(t *testing.T) {
	t.Parallel()

	first, err := PhysicalName(
		"same display prefix",
		"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		MaxPhysicalNameLength,
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PhysicalName(
		"same display prefix",
		"bbbbbbbb-aaaa-4ccc-8ddd-eeeeeeeeeeee",
		MaxPhysicalNameLength,
	)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("different immutable IDs produced the same name %q", first)
	}
}

func TestTypedPhysicalNamesAreStableAndDisplayNameIndependent(t *testing.T) {
	t.Parallel()

	orchestratorID := OrchestratorID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
	networkID := NetworkID("bbbbbbbb-aaaa-4ccc-8ddd-eeeeeeeeeeee")
	vmID := VMID("cccccccc-aaaa-4ccc-8ddd-eeeeeeeeeeee")

	orchestrator, err := OrchestratorNames(orchestratorID)
	if err != nil {
		t.Fatal(err)
	}
	network, err := NetworkNames(networkID)
	if err != nil {
		t.Fatal(err)
	}
	vm, err := VMNames(vmID)
	if err != nil {
		t.Fatal(err)
	}

	values := []struct {
		name string
		max  int
	}{
		{orchestrator.HyperVName, MaxPhysicalNameLength},
		{orchestrator.NodeName, MaxPhysicalNameLength},
		{network.HyperVSwitchName, MaxPhysicalNameLength},
		{network.OrchestratorAdapterName, MaxPhysicalNameLength},
		{vm.HyperVName, MaxPhysicalNameLength},
		{vm.NodeName, MaxWindowsNodeNameLength},
		{vm.PrivateAdapterName, MaxPhysicalNameLength},
	}
	for _, value := range values {
		if err := ValidatePhysicalName(value.name, value.max); err != nil {
			t.Errorf("ValidatePhysicalName(%q): %v", value.name, err)
		}
	}
	if len(vm.NodeName) != MaxWindowsNodeNameLength {
		t.Fatalf("Windows-compatible node name length = %d, want %d", len(vm.NodeName), MaxWindowsNodeNameLength)
	}

	again, err := VMNames(vmID)
	if err != nil {
		t.Fatal(err)
	}
	if again != vm {
		t.Fatalf("physical names changed without an immutable ID change: %+v != %+v", again, vm)
	}
}

func TestPhysicalNameValidationFailures(t *testing.T) {
	t.Parallel()

	const id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	tests := []struct {
		name      string
		prefix    string
		id        string
		maxLength int
	}{
		{"empty normalized prefix", "---", id, 63},
		{"invalid ID", "vm", "not-a-uuid", 63},
		{"bound too short", "vm", id, ShortIDLength + 1},
		{"bound too long", "vm", id, MaxPhysicalNameLength + 1},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := PhysicalName(test.prefix, test.id, test.maxLength); err == nil {
				t.Fatal("PhysicalName() unexpectedly succeeded")
			}
		})
	}

	for _, value := range []string{"", "-bad", "Bad", "bad_", strings.Repeat("a", 64)} {
		if err := ValidatePhysicalName(value, MaxPhysicalNameLength); err == nil {
			t.Errorf("ValidatePhysicalName(%q) unexpectedly succeeded", value)
		}
	}
}
