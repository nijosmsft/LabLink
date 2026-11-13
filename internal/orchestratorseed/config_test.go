package orchestratorseed

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/nijosmsft/lablink/internal/appliance"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	config.OrchestratorID = "orch-1234"
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	if config.MaxNetworks != 16 || config.MaxVMs != 100 ||
		config.RelayPortMin != 20000 || config.RelayPortMax != 39999 ||
		config.SubnetPool != "192.168.240.0/20" || config.SubnetPrefix != 26 {
		t.Fatalf("unexpected defaults: %+v", config)
	}
}

func TestRenderCustomizationFiles(t *testing.T) {
	files, err := Files(Config{
		ApplianceVersion: "v1.2.3",
		OrchestratorID:   "orch-1234",
		PackageSource:    PackageSourceOnline,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"orchestrator/customization-manifest.json",
		"orchestrator/dependency-manifest.json",
		"orchestrator/install-orchestrator.sh",
		"orchestrator/emergency.nft",
		"orchestrator/lablink-disable-conflicting-firewalls.service",
		"orchestrator/lablink-appliance-firewall.service",
		"orchestrator/lablink-appliance-watchdog.service",
		"orchestrator/lablink-agent-appliance.conf",
	} {
		if len(files[name]) == 0 {
			t.Errorf("missing rendered file %s", name)
		}
		if bytes.Contains(files[name], []byte{'\r'}) {
			t.Errorf("Linux seed asset %s contains a carriage return", name)
		}
	}
	var manifest customizationManifest
	if err := json.Unmarshal(files["orchestrator/customization-manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(files["orchestrator/dependency-manifest.json"])
	if manifest.Mode != "isolated_orchestrator" || !manifest.PreserveMainDHCP ||
		manifest.DependencySHA256 != hex.EncodeToString(sum[:]) ||
		manifest.PackageSource != PackageSourceOnline ||
		manifest.ConflictPolicy != "auto_disable_known_firewall_managers" ||
		len(manifest.ServiceOrder) == 0 ||
		manifest.ServiceOrder[0] != "lablink-disable-conflicting-firewalls.service" {
		t.Fatalf("unexpected customization manifest: %+v", manifest)
	}
	script := string(files["orchestrator/install-orchestrator.sh"])
	if strings.Contains(script, "%!") {
		t.Fatalf("installer template formatting failed:\n%s", script)
	}
	for _, want := range []string{
		"nftables=1.0.9-1ubuntu0.1",
		"conntrack=1:1.4.8-1ubuntu1",
		"systemd-networkd",
		"LABLINK_APPLIANCE_MODE=true",
		"lablink-disable-conflicting-firewalls.service",
		"lablink-appliance-firewall.service",
		"version-manifest.json",
		"existing main DHCP policy",
		"lablink-agent-appliance-transition.log",
		"rm -f /etc/systemd/system/lablink-agent.service.d/20-appliance.conf",
		"systemctl stop \"$service\"",
		"systemctl disable \"$service\"",
		"systemctl mask \"$service\"",
		"systemctl is-active --quiet \"$service\"",
		"systemctl is-enabled \"$service\"",
		"test \"$load_state\" = \"not-found\"",
		"expected masked",
		"ufw --force disable",
	} {
		if !strings.Contains(script+string(files["orchestrator/lablink-agent-appliance.conf"]), want) {
			t.Errorf("rendered customization missing %q", want)
		}
	}

	for _, service := range appliance.AutomaticallyNeutralizedFirewallManagerServices() {
		if !strings.Contains(script, shellQuote(service)) {
			t.Errorf("rendered customization missing shared conflict service %q", service)
		}
	}
	firewallUnit := string(files["orchestrator/lablink-appliance-firewall.service"])
	agentUnit := string(files["orchestrator/lablink-agent-appliance.conf"])
	neutralizerUnit := string(files["orchestrator/lablink-disable-conflicting-firewalls.service"])
	for name, unit := range map[string]string{
		"firewall": firewallUnit,
		"agent":    agentUnit,
	} {
		if !strings.Contains(unit, "Requires=lablink-disable-conflicting-firewalls.service") ||
			!strings.Contains(unit, "After=lablink-disable-conflicting-firewalls.service") {
			t.Errorf("%s unit does not require conflict neutralization first:\n%s", name, unit)
		}
	}
	if !strings.Contains(neutralizerUnit, "Type=oneshot") ||
		!strings.Contains(neutralizerUnit, "WantedBy=network-pre.target") ||
		strings.Contains(neutralizerUnit, "RemainAfterExit=yes") {
		t.Errorf("neutralizer must rerun as an inactive oneshot dependency:\n%s", neutralizerUnit)
	}

	for _, forbidden := range []string{"rm /etc/netplan"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("seed customization performs runtime conflict action %q", forbidden)
		}
	}
}

func TestDependencyManifestUsesOneSnapshotCompatiblePackageSet(t *testing.T) {
	files, err := Files(Config{OrchestratorID: "orch-dependencies", PackageSource: PackageSourceOnline})
	if err != nil {
		t.Fatal(err)
	}
	var manifest dependencyManifest
	if err := json.Unmarshal(files["orchestrator/dependency-manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Snapshot.Identity != "ubuntu-noble-2026-11-01" ||
		manifest.Snapshot.BaseURL != "https://snapshot.ubuntu.com/ubuntu/20261101T000000Z" {
		t.Fatalf("unexpected dependency snapshot: %+v", manifest.Snapshot)
	}
	versions := make(map[string]string, len(manifest.Packages))
	for _, pkg := range manifest.Packages {
		versions[pkg.Name] = pkg.Version
	}
	expected := map[string]string{
		"nftables":         "1.0.9-1ubuntu0.1",
		"conntrack":        "1:1.4.8-1ubuntu1",
		"iproute2":         "6.1.0-1ubuntu6.4",
		"systemd":          "255.4-1ubuntu8.18",
		"systemd-resolved": "255.4-1ubuntu8.18",
		"ca-certificates":  "20260816ubuntu0.24.04.1",
	}
	for name, version := range expected {
		if versions[name] != version {
			t.Errorf("%s=%q want %q", name, versions[name], version)
		}
	}
	if versions["systemd"] != versions["systemd-resolved"] {
		t.Fatalf("systemd package cohort is mixed: systemd=%s systemd-resolved=%s",
			versions["systemd"], versions["systemd-resolved"])
	}
}

func TestOfflineBundlePolicyValidationAndRender(t *testing.T) {
	digest := strings.Repeat("a", 64)
	config := Config{
		OrchestratorID: "orch-offline",
		PackageSource:  PackageSourceOffline,
		OfflineBundle: &OfflineBundle{
			Path:           "orchestrator/offline-bundle",
			ManifestSHA256: digest,
		},
	}
	files, err := Files(config)
	if err != nil {
		t.Fatal(err)
	}
	script := string(files["orchestrator/install-orchestrator.sh"])
	if !strings.Contains(script, digest+"  $manifest") ||
		!strings.Contains(script, "complete_dependency_closure") ||
		!strings.Contains(script, "dpkg --install") {
		t.Fatalf("offline verification missing:\n%s", script)
	}
	config.OfflineBundle.Path = "../escape"
	if _, err := Files(config); err == nil {
		t.Fatal("expected offline bundle traversal rejection")
	}
	config.OfflineBundle.Path = `bundle/$(touch-pwned)`
	if _, err := Files(config); err == nil {
		t.Fatal("expected offline bundle shell metacharacter rejection")
	}
	config.OfflineBundle.Path = "bundle"
	config.OfflineBundle.ManifestSHA256 = "bad"
	if _, err := Files(config); err == nil {
		t.Fatal("expected offline manifest checksum rejection")
	}
}

func TestPackagedAssetsAreComplete(t *testing.T) {
	assets, err := AssetFiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"dependency-manifest.json",
		"emergency.nft",
		"lablink-disable-conflicting-firewalls.service",
		"lablink-appliance-firewall.service",
		"lablink-appliance-watchdog.service",
		"lablink-agent-appliance.conf",
		"offline-bundle-manifest.example.json",
	} {
		if len(assets[name]) == 0 {
			t.Errorf("missing packaged asset %s", name)
		}
	}
}

func TestRenderedInstallerShellSyntax(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash.exe may be the WSL launcher without an installed distribution")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	files, err := Files(Config{OrchestratorID: "orch-syntax", PackageSource: PackageSourceOnline})
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(bash, "-n")
	command.Stdin = bytes.NewReader(files["orchestrator/install-orchestrator.sh"])
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, output)
	}
}
