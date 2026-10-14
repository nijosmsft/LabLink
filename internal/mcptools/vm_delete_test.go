package mcptools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/security"
	"github.com/nijosmsft/lablink/internal/vmconfig"
)

func TestResolveVMDeleteIdentityWindowsAndLinux(t *testing.T) {
	defaultsPath := filepath.Join(t.TempDir(), "vm-defaults.json")
	if err := os.WriteFile(defaultsPath, []byte(`{
  "default_profile":"windows",
  "profiles":{"windows":{"target":"host","vm_root":"E:\\WindowsVM"}}
}`), 0600); err != nil {
		t.Fatal(err)
	}
	defaults := vmconfig.Load(defaultsPath)
	target := Target{Name: "host"}

	windows, err := resolveVMDeleteIdentity(reqNoToken(map[string]any{"name": "Win VM"}), target, defaults, nil)
	if err != nil {
		t.Fatal(err)
	}
	if windows.GuestOS != vmconfig.GuestOSWindows || windows.ManagedRoot != `E:\WindowsVM` || windows.NodeName != "WINVM" {
		t.Fatalf("Windows identity = %+v", windows)
	}

	metadata := &hyperv.LinuxVMMetadata{
		SchemaVersion: hyperv.LinuxVMMetadataSchema, GuestOS: vmconfig.GuestOSLinux,
		VMName: "Ubuntu VM", NodeName: "ubuntu-node", ManagedRoot: `F:\LinuxVM`,
		ParentVHDX: `F:\Images\ubuntu.vhdx`, ChildVHDX: `F:\LinuxVM\Ubuntu VM\Ubuntu VM.vhdx`,
		ExpectedCIDATAISO: `F:\LinuxVM\Ubuntu VM\cidata.iso`, CleanupPhase: hyperv.LinuxVMCleanupComplete,
	}
	linux, err := resolveVMDeleteIdentity(reqNoToken(map[string]any{"name": "ubuntu vm"}), target, defaults, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if linux.GuestOS != vmconfig.GuestOSLinux || linux.ManagedRoot != metadata.ManagedRoot ||
		linux.NodeName != metadata.NodeName || linux.ExpectedParentVHDX != metadata.ParentVHDX {
		t.Fatalf("Linux identity = %+v", linux)
	}
}

func TestResolveVMDeleteIdentityRejectsLinuxMetadataOverrides(t *testing.T) {
	metadata := &hyperv.LinuxVMMetadata{
		SchemaVersion: hyperv.LinuxVMMetadataSchema, GuestOS: "linux", VMName: "vm",
		NodeName: "node", ManagedRoot: `E:\VM`, ParentVHDX: `E:\Images\base.vhdx`,
	}

	_, err := resolveVMDeleteIdentity(reqNoToken(map[string]any{
		"name": "vm", "managed_root": `F:\Other`,
	}), Target{Name: "host"}, vmconfig.Load(filepath.Join(t.TempDir(), "missing.json")), metadata)
	if err == nil {
		t.Fatal("expected persisted managed root to reject override")
	}
}

func TestResolveVMDeleteIdentityAcceptsLegacyLinuxMetadataForCleanup(t *testing.T) {
	metadata := &hyperv.LinuxVMMetadata{
		SchemaVersion: 1, GuestOS: vmconfig.GuestOSLinux, VMName: "old-linux-vm",
		NodeName: "old-linux-node", ManagedRoot: `E:\VM`,
		ParentVHDX: `E:\Images\old-base.vhdx`, ChildVHDX: `E:\VM\old-linux-vm\old-linux-vm.vhdx`,
		ExpectedCIDATAISO: `E:\VM\old-linux-vm\cidata.iso`, CleanupPhase: hyperv.LinuxVMCleanupAttached,
	}
	identity, err := resolveVMDeleteIdentity(
		reqNoToken(map[string]any{"name": "old-linux-vm"}),
		Target{Name: "host"},
		vmconfig.Load(filepath.Join(t.TempDir(), "missing.json")),
		metadata,
	)
	if err != nil {
		t.Fatal(err)
	}
	if identity.GuestOS != vmconfig.GuestOSLinux || identity.NodeName != metadata.NodeName ||
		identity.ManagedRoot != metadata.ManagedRoot || identity.ExpectedParentVHDX != metadata.ParentVHDX {
		t.Fatalf("legacy Linux identity = %+v", identity)
	}
}

func TestRegistryRemovalUsesStoredCase(t *testing.T) {
	reg := registry.Load(filepath.Join(t.TempDir(), "nodes.json"))
	if err := reg.SetNode(&registry.Node{Name: "Ubuntu-Node"}); err != nil {
		t.Fatal(err)
	}
	if got := caseCorrectRegistryNodeName(reg, "ubuntu-node"); got != "Ubuntu-Node" {
		t.Fatalf("case-correct name = %q", got)
	}
}

func TestDeleteVMLocksBeforeMetadataInspectionAndReleasesAfterDelete(t *testing.T) {
	agent := &linuxImageMockAgent{responses: []string{
		`{"status":"lock_acquired","acquired":true}`,
		`{"exists":false}`,
		`{"status":"dry_run"}`,
		`{"status":"lock_released","released":true}`,
	}}
	addr := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"host": addr})
	pool := agentclient.NewPool("", security.ClientTransportConfig{Mode: security.TransportModeInsecure})
	defer pool.Close()
	defaults := linuxDefaultsStore(t, `{
  "default_profile":"windows",
  "profiles":{"windows":{"target":"host","vm_root":"E:\\WindowsVM"}}
}`)
	handler := deleteVMHandler(reg, pool, defaults, audit.NewLog(t.TempDir()), VMEnrollmentConfig{})
	result, err := handler(context.Background(), reqNoToken(map[string]any{
		"target": "host", "name": "Win VM", "dry_run": true,
	}))
	if err != nil || result == nil || result.IsError {
		t.Fatalf("delete dry run: result=%#v err=%v", result, err)
	}
	scripts := agent.Scripts()
	if len(scripts) != 4 {
		t.Fatalf("executed %d scripts, want lock/inspect/delete/release: %#v", len(scripts), scripts)
	}
	if !strings.Contains(scripts[0], `LabLink\vm-locks`) ||
		!strings.Contains(scripts[1], "expected_iso_exists") ||
		!strings.Contains(scripts[2], "Remove-VM") ||
		!strings.Contains(scripts[3], "lock_released") {
		t.Fatalf("delete lifecycle lock ordering is unsafe: %#v", scripts)
	}
}

func TestDeleteVMLockContentionStopsBeforeMetadataInspection(t *testing.T) {
	agent := &linuxImageMockAgent{responses: []string{
		`{"status":"lock_busy","acquired":false}`,
	}}
	addr := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"host": addr})
	pool := agentclient.NewPool("", security.ClientTransportConfig{Mode: security.TransportModeInsecure})
	defer pool.Close()
	defaults := linuxDefaultsStore(t, `{
  "default_profile":"windows",
  "profiles":{"windows":{"target":"host","vm_root":"E:\\WindowsVM"}}
}`)
	handler := deleteVMHandler(reg, pool, defaults, audit.NewLog(t.TempDir()), VMEnrollmentConfig{})
	result, err := handler(context.Background(), reqNoToken(map[string]any{
		"target": "host", "name": "Win VM",
	}))
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("contended delete: result=%#v err=%v", result, err)
	}
	scripts := agent.Scripts()
	if len(scripts) != 1 || !strings.Contains(scripts[0], `LabLink\vm-locks`) {
		t.Fatalf("contended delete inspected or mutated the VM before acquiring the lock: %#v", scripts)
	}
}
