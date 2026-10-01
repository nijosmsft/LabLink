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
  "target_defaults": {"node2": "small"},
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
	profile, name, err = store.ResolveForTarget("", "NODE2")
	if err != nil || name != "small" || profile.CPUCount != 2 {
		t.Fatalf("target profile = %+v, %q, %v", profile, name, err)
	}
}

func TestSetListDeleteTargetTemplate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vm-defaults.json")
	store := Load(path)
	profile := Profile{Target: "node30", VMRoot: `E:\VM`, CPUCount: 4}
	if err := store.Set("rr30", profile, true); err != nil {
		t.Fatal(err)
	}
	resolved, name, err := store.ResolveForTarget("", "NODE30")
	if err != nil || name != "rr30" || resolved.VMRoot != `E:\VM` {
		t.Fatalf("resolved = %+v, %q, %v", resolved, name, err)
	}
	config, err := store.List()
	if err != nil || len(config.Names()) != 1 || config.TargetDefaults["node30"] != "rr30" {
		t.Fatalf("list = %+v, %v", config, err)
	}
	if err := store.Delete("rr30"); err != nil {
		t.Fatal(err)
	}
	config, err = store.List()
	if err != nil || len(config.Profiles) != 0 || len(config.TargetDefaults) != 0 {
		t.Fatalf("after delete = %+v, %v", config, err)
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
