package vmconfig

import (
	"os"
	"path/filepath"
	"strings"
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
      "profile_usage":"linux_image_builder",
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
	if usage, err := builder.EffectiveProfileUsage(); err != nil || usage != ProfileUsageLinuxImageBuilder {
		t.Fatalf("builder usage = %q, %v", usage, err)
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

func TestProfileUsageDefaultsValidatesAndGuardsPublicWindowsResolution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vm-defaults.json")
	if err := os.WriteFile(path, []byte(`{
  "default_profile": "ordinary",
  "target_defaults": {"node1": "ordinary"},
  "profiles": {
    "ordinary": {"target":"node1","guest_os":"windows"},
    "builder": {"target":"node1","guest_os":"windows","profile_usage":"linux_image_builder"},
    "legacy-builder": {"target":"node1","guest_os":"windows"},
    "ubuntu": {"target":"node1","guest_os":"linux","image_builder_profile":"legacy-builder"}
  }
}`), 0600); err != nil {
		t.Fatal(err)
	}
	store := Load(path)

	ordinary, name, err := store.ResolveOrdinaryWindowsForTarget("", "node1")
	if err != nil || name != "ordinary" {
		t.Fatalf("ordinary default = %+v, %q, %v", ordinary, name, err)
	}
	if usage, err := ordinary.EffectiveProfileUsage(); err != nil || usage != ProfileUsageOrdinary {
		t.Fatalf("empty profile_usage = %q, %v", usage, err)
	}
	if _, name, err := store.ResolveWindowsForTarget("builder", "node1"); err != nil || name != "builder" {
		t.Fatalf("internal builder resolution failed: %q, %v", name, err)
	}
	if _, _, err := store.ResolveOrdinaryWindowsForTarget("builder", "node1"); err == nil ||
		!strings.Contains(err.Error(), `ordinary profile "ordinary"`) ||
		!strings.Contains(err.Error(), "target default") {
		t.Fatalf("unexpected public builder rejection: %v", err)
	}
	if builderOnly, err := store.IsLinuxImageBuilderProfile("legacy-builder"); err != nil || !builderOnly {
		t.Fatalf("legacy referenced builder was not inferred: %v, %v", builderOnly, err)
	}
	if _, _, err := store.ResolveOrdinaryWindowsForTarget("legacy-builder", "node1"); err == nil ||
		!strings.Contains(err.Error(), "referenced by a Linux image_builder_profile") {
		t.Fatalf("unexpected inferred builder rejection: %v", err)
	}
}

func TestUnknownProfileUsageFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vm-defaults.json")
	if err := os.WriteFile(path, []byte(`{
  "default_profile": "bad",
  "profiles": {"bad": {"profile_usage":"future_mode"}}
}`), 0600); err != nil {
		t.Fatal(err)
	}
	store := Load(path)
	if _, _, err := store.ResolveWindows(""); err == nil || !strings.Contains(err.Error(), "unsupported profile_usage") {
		t.Fatalf("unknown profile usage did not fail closed: %v", err)
	}
	if _, err := store.List(); err == nil {
		t.Fatal("list must not silently return an unknown profile_usage")
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

func TestSetListBuilderUsageRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vm-defaults.json")
	store := Load(path)
	profile := Profile{
		Target: "node30", GuestOS: GuestOSWindows,
		ProfileUsage: ProfileUsageLinuxImageBuilder,
	}
	if err := store.Set("builder", profile, false); err != nil {
		t.Fatal(err)
	}
	config, err := store.List()
	if err != nil || config.Profiles["builder"].ProfileUsage != ProfileUsageLinuxImageBuilder {
		t.Fatalf("profile_usage did not round trip: %+v, %v", config.Profiles["builder"], err)
	}
	if err := store.Set("bad-default", profile, true); err == nil ||
		!strings.Contains(err.Error(), "set_as_target_default=false") {
		t.Fatalf("builder profile became an ordinary target default: %v", err)
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

func TestWindowsDomainJoinProfileRoundTripAndDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vm-defaults.json")
	if err := os.WriteFile(path, []byte(`{
  "default_profile":"domain",
  "profiles":{"domain":{
    "guest_os":"windows",
    "target":"node1",
    "domain_join":{
      "domain":"cfdev.nttest.microsoft.com",
      "username":"cfdev\\netcdev",
      "password_secret":"cfdev-domain-password",
      "ou_path":"OU=Lab,DC=cfdev,DC=nttest,DC=microsoft,DC=com"
    }
  }}
}`), 0600); err != nil {
		t.Fatal(err)
	}
	profile, _, err := Load(path).ResolveWindows("")
	if err != nil {
		t.Fatal(err)
	}
	if profile.DomainJoin == nil ||
		profile.DomainJoin.Domain != "cfdev.nttest.microsoft.com" ||
		profile.DomainJoin.Username != `cfdev\netcdev` ||
		!profile.DomainJoin.EffectiveReboot() ||
		!profile.DomainJoin.EffectiveVerifySecureChannel() {
		t.Fatalf("domain join profile = %+v", profile.DomainJoin)
	}
}

func TestDomainJoinRejectedForLinuxProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vm-defaults.json")
	if err := os.WriteFile(path, []byte(`{
  "default_linux_profile":"ubuntu",
  "profiles":{"ubuntu":{
    "guest_os":"linux",
    "domain_join":{
      "domain":"cfdev.nttest.microsoft.com",
      "username":"cfdev\\netcdev",
      "password_secret":"cfdev-domain-password"
    }
  }}
}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path).List(); err == nil || !strings.Contains(err.Error(), "supported only for Windows") {
		t.Fatalf("Linux domain join validation = %v", err)
	}
}

func TestDomainJoinVerificationRequiresReboot(t *testing.T) {
	disabled := false
	config := WindowsDomainJoin{
		Domain: "cfdev.nttest.microsoft.com", Username: `cfdev\netcdev`,
		PasswordSecret: "cfdev-domain-password", Reboot: &disabled,
	}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "requires domain_join.reboot=true") {
		t.Fatalf("domain join reboot validation = %v", err)
	}
}
