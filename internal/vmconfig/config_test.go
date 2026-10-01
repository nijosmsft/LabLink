package vmconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveDefaultAndNamedProfiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vm-defaults.json")
	if err := os.WriteFile(path, []byte(`{
  "default_profile": "lab",
  "profiles": {
    "lab": {"target":"node1","base_vhd":"E:\\base.vhdx","vm_root":"E:\\VM"},
    "small": {"memory_mb":4096,"cpu_count":2}
  }
}`), 0600); err != nil {
		t.Fatal(err)
	}
	store := Load(path)

	profile, name, err := store.Resolve("")
	if err != nil || name != "lab" || profile.Target != "node1" {
		t.Fatalf("default profile = %+v, %q, %v", profile, name, err)
	}
	profile, name, err = store.Resolve("small")
	if err != nil || name != "small" || profile.MemoryMB != 4096 {
		t.Fatalf("named profile = %+v, %q, %v", profile, name, err)
	}
}

func TestMissingFileIsEmptyStore(t *testing.T) {
	store := Load(filepath.Join(t.TempDir(), "missing.json"))
	profile, name, err := store.Resolve("")
	if err != nil || name != "" || profile != (Profile{}) {
		t.Fatalf("empty store = %+v, %q, %v", profile, name, err)
	}
}

func TestMalformedConfigIsSurfaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vm-defaults.json")
	if err := os.WriteFile(path, []byte(`{nope`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path).Resolve(""); err == nil {
		t.Fatal("expected malformed config error")
	}
}
