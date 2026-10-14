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
	profile, name, err = store.ResolveWindowsForTarget("", "NODE2")
	if err != nil || name != "small" || profile.CPUCount != 2 {
		t.Fatalf("Windows target profile = %+v, %q, %v", profile, name, err)
	}
}

func TestResolveLinuxProfilesWithoutChangingWindowsDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vm-defaults.json")
	if err := os.WriteFile(path, []byte(`{
  "default_profile": "windows",
  "target_defaults": {"node1": "windows-small"},
  "default_linux_profile": "ubuntu",
  "linux_target_defaults": {"node1": "ubuntu-large"},
  "profiles": {
    "windows": {"target":"node0","base_vhd":"E:\\base.vhdx"},
    "windows-small": {"target":"node1","memory_mb":4096},
    "ubuntu": {
      "guest_os":"linux",
      "distribution":"ubuntu",
      "release":"24.04",
      "architecture":"amd64",
      "image_cache_root":"E:\\LabLinkImages",
      "linux_username":"lab",
      "ssh_public_key_file":"C:\\keys\\lab.pub",
      "linux_password_credential":"linux-lab",
      "allow_ssh_password_auth":true,
      "network_config":"version: 2",
      "disk_size_gb":64,
      "image_builder_profile":"builder",
      "builder_vm_name":"ubuntu-builder",
      "delete_builder_after_prepare":true
    },
    "ubuntu-large": {"guest_os":"linux","target":"node1","memory_mb":8192},
    "builder": {
      "guest_os":"windows",
      "target":"node1",
      "dynamic_memory":false,
      "expose_virtualization_extensions":true,
      "virtualization_based_security_opt_out":true
    }
  }
}`), 0600); err != nil {
		t.Fatal(err)
	}
	store := Load(path)

	windows, name, err := store.ResolveWindowsForTarget("", "NODE1")
	if err != nil || name != "windows-small" || windows.MemoryMB != 4096 {
		t.Fatalf("Windows resolution changed: %+v, %q, %v", windows, name, err)
	}
	linux, name, err := store.ResolveLinux("")
	if err != nil || name != "ubuntu" || linux.ImageCacheRoot != `E:\LabLinkImages` || linux.DiskSizeGB != 64 {
		t.Fatalf("Linux default = %+v, %q, %v", linux, name, err)
	}
	if linux.LinuxPasswordCredential != "linux-lab" || linux.AllowSSHPasswordAuth == nil ||
		!*linux.AllowSSHPasswordAuth || linux.NetworkConfig != "version: 2" ||
		linux.ImageBuilderProfile != "builder" || linux.BuilderVMName != "ubuntu-builder" ||
		linux.DeleteBuilderAfterPrepare == nil || !*linux.DeleteBuilderAfterPrepare {
		t.Fatalf("Linux access settings not preserved: %+v", linux)
	}
	builder, builderName, err := store.ResolveWindows("builder")
	if err != nil || builderName != "builder" || builder.ExposeVirtualizationExtensions == nil ||
		!*builder.ExposeVirtualizationExtensions || builder.VirtualizationBasedSecurityOptOut == nil ||
		!*builder.VirtualizationBasedSecurityOptOut {
		t.Fatalf("builder isolation settings not preserved: %+v, %q, %v", builder, builderName, err)
	}
	linux, name, err = store.ResolveLinuxForTarget("", "NODE1")
	if err != nil || name != "ubuntu-large" || linux.MemoryMB != 8192 {
		t.Fatalf("Linux target = %+v, %q, %v", linux, name, err)
	}
	if _, _, err := store.ResolveLinux("windows"); err == nil {
		t.Fatal("expected Linux resolution to reject a Windows profile")
	}
	if _, _, err := store.ResolveWindows("ubuntu"); err == nil {
		t.Fatal("expected Windows resolution to reject a Linux profile")
	}
}

func TestEmptyGuestOSIsWindows(t *testing.T) {
	guestOS, err := (Profile{}).EffectiveGuestOS()
	if err != nil || guestOS != GuestOSWindows {
		t.Fatalf("empty guest_os = %q, %v", guestOS, err)
	}
	if _, err := (Profile{GuestOS: "freebsd"}).EffectiveGuestOS(); err == nil {
		t.Fatal("expected unsupported guest_os error")
	}
}

func TestSetListDeleteTargetTemplate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vm-defaults.json")
	store := Load(path)
	enabled := true
	profile := Profile{
		Target: "node30", VMRoot: `E:\VM`, CPUCount: 4,
		VirtualizationBasedSecurityOptOut: &enabled,
	}
	if err := store.Set("rr30", profile, true); err != nil {
		t.Fatal(err)
	}
	resolved, name, err := store.ResolveForTarget("", "NODE30")
	if err != nil || name != "rr30" || resolved.VMRoot != `E:\VM` ||
		resolved.VirtualizationBasedSecurityOptOut == nil || !*resolved.VirtualizationBasedSecurityOptOut {
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

func TestSetDeleteLinuxTargetTemplate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vm-defaults.json")
	store := Load(path)
	profile := Profile{Target: "node30", GuestOS: GuestOSLinux, ImageCacheRoot: `E:\Images`}
	if err := store.Set("ubuntu", profile, true); err != nil {
		t.Fatal(err)
	}
	config, err := store.List()
	if err != nil || config.LinuxTargetDefaults["node30"] != "ubuntu" || len(config.TargetDefaults) != 0 {
		t.Fatalf("Linux defaults = %+v, %v", config, err)
	}
	if err := store.Delete("ubuntu"); err != nil {
		t.Fatal(err)
	}
	config, err = store.List()
	if err != nil || len(config.LinuxTargetDefaults) != 0 {
		t.Fatalf("after Linux delete = %+v, %v", config, err)
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
