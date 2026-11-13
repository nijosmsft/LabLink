package isolated

import (
	"errors"
	"strings"
	"testing"
)

func TestDerivePhysicalHostIdentityCanonicalizesFacts(t *testing.T) {
	t.Parallel()

	identity, err := DerivePhysicalHostIdentity(
		" {AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE} ",
		" 12345678-1234-5678-9ABC-DEF012345678 ",
	)
	if err != nil {
		t.Fatal(err)
	}
	if identity.MachineGUID != "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" {
		t.Fatalf("MachineGUID = %q", identity.MachineGUID)
	}
	if identity.SMBIOSUUID != "12345678-1234-5678-9abc-def012345678" {
		t.Fatalf("SMBIOSUUID = %q", identity.SMBIOSUUID)
	}
	const want = "a0edbbc586f6eae6165c76ec3a6e28c7df32d9d62cddb4642239174ee65d3960"
	if identity.ID.String() != want {
		t.Fatalf("physical host ID = %q, want %q", identity.ID, want)
	}

	again, err := DerivePhysicalHostIdentity(identity.MachineGUID, identity.SMBIOSUUID)
	if err != nil {
		t.Fatal(err)
	}
	if identity != again {
		t.Fatalf("canonical derivation is not deterministic: %+v != %+v", identity, again)
	}
}

func TestDerivePhysicalHostIdentityRejectsMissingAndPlaceholderFacts(t *testing.T) {
	t.Parallel()

	valid := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	tests := []struct {
		name    string
		machine string
		smbios  string
	}{
		{"missing machine", "", valid},
		{"missing smbios", valid, ""},
		{"zero machine", "00000000-0000-0000-0000-000000000000", valid},
		{"all f smbios", valid, "ffffffff-ffff-ffff-ffff-ffffffffffff"},
		{"known placeholder", valid, "03000200-0400-0500-0006-000700080009"},
		{"text placeholder", "To Be Filled By O.E.M.", valid},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DerivePhysicalHostIdentity(test.machine, test.smbios); err == nil {
				t.Fatal("DerivePhysicalHostIdentity() unexpectedly succeeded")
			}
		})
	}
}

func TestPhysicalHostIDParsingNormalizesCase(t *testing.T) {
	t.Parallel()

	upper := strings.Repeat("AB", 32)
	id, err := ParsePhysicalHostID(" " + upper + " ")
	if err != nil {
		t.Fatal(err)
	}
	if id.String() != strings.ToLower(upper) {
		t.Fatalf("ParsePhysicalHostID() = %q", id)
	}
	for _, value := range []string{"", "abc", strings.Repeat("g", 64), strings.Repeat("a", 63)} {
		if _, err := ParsePhysicalHostID(value); err == nil {
			t.Errorf("ParsePhysicalHostID(%q) unexpectedly succeeded", value)
		}
	}
}

func TestHostReferencesUseCanonicalIdentityRatherThanAlias(t *testing.T) {
	t.Parallel()

	identity, err := DerivePhysicalHostIdentity(
		"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		"12345678-1234-5678-9abc-def012345678",
	)
	if err != nil {
		t.Fatal(err)
	}
	byName, err := NewHostReference(" HOST01.Example.COM. ", identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	byAddress, err := NewHostReference("[2001:0DB8::1]", identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	if byName.Alias != "host01.example.com" {
		t.Fatalf("normalized DNS alias = %q", byName.Alias)
	}
	if byAddress.Alias != "2001:db8::1" {
		t.Fatalf("normalized address alias = %q", byAddress.Alias)
	}
	if !byName.SamePhysicalHost(byAddress) {
		t.Fatal("aliases for the same physical ID were treated as different hosts")
	}
	if byName.CanonicalKey() != byAddress.CanonicalKey() ||
		byName.CanonicalKey() != identity.ID.String() {
		t.Fatalf("canonical keys differ: %q, %q", byName.CanonicalKey(), byAddress.CanonicalKey())
	}
}

func TestHostReferenceCannotRelyOnAliasAlone(t *testing.T) {
	t.Parallel()

	if _, err := NewHostReference("host01", ""); err == nil {
		t.Fatal("alias-only host reference unexpectedly succeeded")
	}
	if got := (HostReference{Alias: "host01"}).CanonicalKey(); got != "" {
		t.Fatalf("alias-only canonical key = %q, want empty", got)
	}
}

func TestHostIdentityChangeFailsClosed(t *testing.T) {
	t.Parallel()

	expected := PhysicalHostID(strings.Repeat("a", 64))
	observed := PhysicalHostID(strings.Repeat("b", 64))
	reference, err := NewHostReference("host01", expected)
	if err != nil {
		t.Fatal(err)
	}
	err = reference.VerifyObserved(observed)
	if err == nil {
		t.Fatal("VerifyObserved() unexpectedly succeeded")
	}
	var changed *HostIdentityChangedError
	if !errors.As(err, &changed) {
		t.Fatalf("error type = %T, want *HostIdentityChangedError", err)
	}
	for _, want := range []string{
		"HOST_IDENTITY_CHANGED",
		"host01",
		expected.String(),
		observed.String(),
		"explicit operator reconciliation",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	if err := reference.VerifyObserved(expected); err != nil {
		t.Fatalf("matching physical ID rejected: %v", err)
	}
}

func TestPhysicalHostTupleIsOrderedAndVersioned(t *testing.T) {
	t.Parallel()

	first, err := DerivePhysicalHostIdentity(
		"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		"12345678-1234-5678-9abc-def012345678",
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DerivePhysicalHostIdentity(
		"12345678-1234-5678-9abc-def012345678",
		"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
	)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID {
		t.Fatal("swapping canonical tuple fields did not change physical host ID")
	}
	if !strings.Contains(PhysicalHostIdentityVersion, "/v1") {
		t.Fatalf("identity version %q is not explicitly versioned", PhysicalHostIdentityVersion)
	}
}
