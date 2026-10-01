package secretstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreRoundTripAndNoPlaintextAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.json")
	store := Open(path)
	const value = "MSRC-secret-value"
	if err := store.Set("archive", value); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get("archive")
	if err != nil || got != value {
		t.Fatalf("Get = %q, %v", got, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), value) {
		t.Fatal("secret persisted in plaintext")
	}
	if err := store.Set("archive", "replacement"); err != nil {
		t.Fatalf("replace secret: %v", err)
	}
	if got, err := store.Get("archive"); err != nil || got != "replacement" {
		t.Fatalf("replacement Get = %q, %v", got, err)
	}
	names, err := store.List()
	if err != nil || len(names) != 1 || names[0] != "archive" {
		t.Fatalf("List = %v, %v", names, err)
	}
	if err := store.Delete("archive"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("archive"); err == nil {
		t.Fatal("deleted secret still resolves")
	}
}

func TestStoreRejectsInvalidNames(t *testing.T) {
	store := Open(filepath.Join(t.TempDir(), "secrets.json"))
	if err := store.Set("bad name", "value"); err == nil {
		t.Fatal("expected invalid-name error")
	}
}
