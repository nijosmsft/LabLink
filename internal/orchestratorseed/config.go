package orchestratorseed

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/nijosmsft/lablink/internal/appliance"
)

const (
	ManifestSchemaVersion = 1

	PackageSourceOnline        = "online"
	PackageSourceOffline       = "offline"
	PackageSourcePreferOffline = "prefer_offline"

	DefaultMaxNetworks  = 16
	DefaultMaxVMs       = 100
	DefaultRelayPortMin = 20000
	DefaultRelayPortMax = 39999
	DefaultSubnetPool   = "192.168.240.0/20"
	DefaultSubnetPrefix = 26
)

var (
	//go:embed assets/*
	assetFS embed.FS

	sha256Pattern   = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	idPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	seedPathPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
)

type OfflineBundle struct {
	Path           string `json:"path"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

type Config struct {
	ApplianceVersion string         `json:"appliance_version"`
	OrchestratorID   string         `json:"orchestrator_id"`
	PackageSource    string         `json:"package_source"`
	OfflineBundle    *OfflineBundle `json:"offline_bundle,omitempty"`
	MaxNetworks      int            `json:"max_networks"`
	MaxVMs           int            `json:"max_vms"`
	RelayPortMin     int            `json:"relay_port_min"`
	RelayPortMax     int            `json:"relay_port_max"`
	SubnetPool       string         `json:"subnet_pool"`
	SubnetPrefix     int            `json:"subnet_prefix"`
}

type dependencyManifest struct {
	SchemaVersion int    `json:"schema_version"`
	Distribution  string `json:"distribution"`
	Release       string `json:"release"`
	Architecture  string `json:"architecture"`
	Snapshot      struct {
		Identity   string   `json:"identity"`
		BaseURL    string   `json:"base_url"`
		Suites     []string `json:"suites"`
		Components []string `json:"components"`
	} `json:"snapshot"`
	Packages []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"packages"`
}

type customizationManifest struct {
	SchemaVersion    int            `json:"schema_version"`
	Mode             string         `json:"mode"`
	ApplianceVersion string         `json:"appliance_version"`
	OrchestratorID   string         `json:"orchestrator_id"`
	Distribution     string         `json:"distribution"`
	Release          string         `json:"release"`
	Architecture     string         `json:"architecture"`
	PackageSource    string         `json:"package_source"`
	OfflineBundle    *OfflineBundle `json:"offline_bundle,omitempty"`
	DependencySHA256 string         `json:"dependency_manifest_sha256"`
	PreserveMainDHCP bool           `json:"preserve_main_dhcp"`
	NetworkManager   string         `json:"private_network_manager"`
	ConflictPolicy   string         `json:"conflicting_manager_policy"`
	MaxNetworks      int            `json:"max_networks"`
	MaxVMs           int            `json:"max_vms"`
	RelayPortMin     int            `json:"relay_port_min"`
	RelayPortMax     int            `json:"relay_port_max"`
	SubnetPool       string         `json:"subnet_pool"`
	SubnetPrefix     int            `json:"subnet_prefix"`
	ServiceOrder     []string       `json:"service_order"`
}

func DefaultConfig() Config {
	return Config{
		ApplianceVersion: "dev",
		PackageSource:    PackageSourceOnline,
		MaxNetworks:      DefaultMaxNetworks,
		MaxVMs:           DefaultMaxVMs,
		RelayPortMin:     DefaultRelayPortMin,
		RelayPortMax:     DefaultRelayPortMax,
		SubnetPool:       DefaultSubnetPool,
		SubnetPrefix:     DefaultSubnetPrefix,
	}
}

func (c Config) withDefaults() Config {
	defaults := DefaultConfig()
	if strings.TrimSpace(c.ApplianceVersion) == "" {
		c.ApplianceVersion = defaults.ApplianceVersion
	}
	if strings.TrimSpace(c.PackageSource) == "" {
		c.PackageSource = defaults.PackageSource
	}
	if c.MaxNetworks == 0 {
		c.MaxNetworks = defaults.MaxNetworks
	}
	if c.MaxVMs == 0 {
		c.MaxVMs = defaults.MaxVMs
	}
	if c.RelayPortMin == 0 {
		c.RelayPortMin = defaults.RelayPortMin
	}
	if c.RelayPortMax == 0 {
		c.RelayPortMax = defaults.RelayPortMax
	}
	if strings.TrimSpace(c.SubnetPool) == "" {
		c.SubnetPool = defaults.SubnetPool
	}
	if c.SubnetPrefix == 0 {
		c.SubnetPrefix = defaults.SubnetPrefix
	}
	return c
}

func (c Config) Validate() error {
	c = c.withDefaults()
	if !idPattern.MatchString(c.ApplianceVersion) {
		return fmt.Errorf("invalid appliance version %q", c.ApplianceVersion)
	}
	if !idPattern.MatchString(c.OrchestratorID) {
		return fmt.Errorf("invalid orchestrator ID %q", c.OrchestratorID)
	}
	switch c.PackageSource {
	case PackageSourceOnline:
		if c.OfflineBundle != nil {
			return fmt.Errorf("offline_bundle is not used when package_source is %q", PackageSourceOnline)
		}
	case PackageSourceOffline:
		if c.OfflineBundle == nil {
			return fmt.Errorf("offline_bundle is required when package_source is %q", PackageSourceOffline)
		}
	case PackageSourcePreferOffline:
	default:
		return fmt.Errorf("unsupported package_source %q", c.PackageSource)
	}
	if c.OfflineBundle != nil {
		bundlePath := strings.TrimSpace(c.OfflineBundle.Path)
		if err := ValidateOfflineBundlePath(bundlePath); err != nil {
			return err
		}
		if !sha256Pattern.MatchString(c.OfflineBundle.ManifestSHA256) {
			return fmt.Errorf("offline_bundle.manifest_sha256 must be a SHA-256 hex digest")
		}
	}
	if c.MaxNetworks < 1 || c.MaxNetworks > DefaultMaxNetworks {
		return fmt.Errorf("max_networks must be between 1 and %d", DefaultMaxNetworks)
	}
	if c.MaxVMs < 1 || c.MaxVMs > DefaultMaxVMs {
		return fmt.Errorf("max_vms must be between 1 and %d", DefaultMaxVMs)
	}
	if c.RelayPortMin < 1 || c.RelayPortMax > 65535 || c.RelayPortMin > c.RelayPortMax {
		return fmt.Errorf("relay port range must be within 1-65535 and ordered")
	}
	if c.RelayPortMax-c.RelayPortMin+1 < c.MaxVMs {
		return fmt.Errorf("relay port range must contain at least max_vms ports")
	}
	pool, err := netip.ParsePrefix(c.SubnetPool)
	if err != nil || !pool.Addr().Is4() || pool != pool.Masked() {
		return fmt.Errorf("subnet_pool must be a canonical IPv4 prefix")
	}
	if c.SubnetPrefix < pool.Bits() || c.SubnetPrefix > 30 {
		return fmt.Errorf("subnet_prefix must be between pool prefix /%d and /30", pool.Bits())
	}
	if 1<<(c.SubnetPrefix-pool.Bits()) < c.MaxNetworks {
		return fmt.Errorf("subnet_pool does not contain max_networks subnets")
	}
	return nil
}

func ValidateOfflineBundlePath(value string) error {
	if value == "" || path.IsAbs(value) || path.Clean(value) != value ||
		!seedPathPattern.MatchString(value) {
		return fmt.Errorf("offline_bundle.path must be a safe relative seed path without traversal")
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("offline_bundle.path must be a safe relative seed path without traversal")
		}
	}
	return nil
}

func Files(config Config) (map[string][]byte, error) {
	config = config.withDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	dependencyData, err := assetFS.ReadFile("assets/dependency-manifest.json")
	if err != nil {
		return nil, err
	}
	dependencyData = normalizeLinuxTextAsset(dependencyData)
	var dependencies dependencyManifest
	if err := json.Unmarshal(dependencyData, &dependencies); err != nil {
		return nil, fmt.Errorf("parse embedded dependency manifest: %w", err)
	}
	if dependencies.SchemaVersion != ManifestSchemaVersion ||
		dependencies.Distribution != "ubuntu" || dependencies.Release != "24.04" ||
		dependencies.Architecture != "amd64" || len(dependencies.Packages) == 0 {
		return nil, fmt.Errorf("embedded dependency manifest is not the supported Ubuntu 24.04 amd64 manifest")
	}
	for _, pkg := range dependencies.Packages {
		if strings.TrimSpace(pkg.Name) == "" || strings.TrimSpace(pkg.Version) == "" {
			return nil, fmt.Errorf("embedded dependency manifest contains an unpinned package")
		}
	}
	dependencySum := sha256.Sum256(dependencyData)
	manifest := customizationManifest{
		SchemaVersion:    ManifestSchemaVersion,
		Mode:             "isolated_orchestrator",
		ApplianceVersion: config.ApplianceVersion,
		OrchestratorID:   config.OrchestratorID,
		Distribution:     dependencies.Distribution,
		Release:          dependencies.Release,
		Architecture:     dependencies.Architecture,
		PackageSource:    config.PackageSource,
		OfflineBundle:    config.OfflineBundle,
		DependencySHA256: hex.EncodeToString(dependencySum[:]),
		PreserveMainDHCP: true,
		NetworkManager:   "systemd-networkd",
		ConflictPolicy:   "auto_disable_known_firewall_managers",
		MaxNetworks:      config.MaxNetworks,
		MaxVMs:           config.MaxVMs,
		RelayPortMin:     config.RelayPortMin,
		RelayPortMax:     config.RelayPortMax,
		SubnetPool:       config.SubnetPool,
		SubnetPrefix:     config.SubnetPrefix,
		ServiceOrder: []string{
			"lablink-disable-conflicting-firewalls.service",
			"lablink-appliance-firewall.service",
			"systemd-networkd.service",
			"network-online.target",
			"lablink-agent.service",
			"lablink-appliance-watchdog.service",
		},
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	manifestData = append(manifestData, '\n')

	files := map[string][]byte{
		"orchestrator/customization-manifest.json": manifestData,
		"orchestrator/dependency-manifest.json":    append([]byte(nil), dependencyData...),
	}
	for _, name := range []string{
		"emergency.nft",
		"lablink-disable-conflicting-firewalls.service",
		"lablink-appliance-firewall.service",
		"lablink-appliance-watchdog.service",
		"lablink-agent-appliance.conf",
	} {
		data, err := assetFS.ReadFile("assets/" + name)
		if err != nil {
			return nil, err
		}
		files["orchestrator/"+name] = normalizeLinuxTextAsset(data)
	}
	files["orchestrator/install-orchestrator.sh"] = renderInstaller(config, dependencies)
	return files, nil
}

func AssetFiles() (map[string][]byte, error) {
	entries, err := assetFS.ReadDir("assets")
	if err != nil {
		return nil, err
	}
	files := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := assetFS.ReadFile("assets/" + entry.Name())
		if err != nil {
			return nil, err
		}
		files[entry.Name()] = normalizeLinuxTextAsset(data)
	}
	return files, nil
}

func normalizeLinuxTextAsset(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
}

func renderInstaller(config Config, dependencies dependencyManifest) []byte {
	specs := make([]string, 0, len(dependencies.Packages))
	checks := make([]string, 0, len(dependencies.Packages))
	for _, pkg := range dependencies.Packages {
		specs = append(specs, shellQuote(pkg.Name+"="+pkg.Version))
		checks = append(checks, fmt.Sprintf(
			"test \"$(dpkg-query -W -f='${Version}' %s)\" = %s",
			shellQuote(pkg.Name), shellQuote(pkg.Version)))
	}
	sort.Strings(specs)
	sort.Strings(checks)
	managerServices := appliance.AutomaticallyNeutralizedFirewallManagerServices()
	managerServiceArgs := make([]string, 0, len(managerServices))
	for _, service := range managerServices {
		managerServiceArgs = append(managerServiceArgs, shellQuote(service))
	}

	bundlePath := ""
	bundleManifestSHA := ""
	if config.OfflineBundle != nil {
		bundlePath = config.OfflineBundle.Path
		bundleManifestSHA = strings.ToLower(config.OfflineBundle.ManifestSHA256)
	}
	script := fmt.Sprintf(`#!/bin/bash
set -Eeuo pipefail
umask 077

src="$(cd "$(dirname "$0")" && pwd)"
status=/var/log/lablink-orchestrator-install.status
fail() {
  rc=$?
  printf 'failed rc=%%s line=%%s\n' "$rc" "${BASH_LINENO[0]:-unknown}" > "$status"
  logger -t lablink-orchestrator-install "customization failed rc=$rc"
  exit "$rc"
}
trap fail ERR

test -s "$src/customization-manifest.json"
test -s "$src/dependency-manifest.json"
main_iface="$(ip -4 route show default | awk 'NR==1 {print $5}')"
test -n "$main_iface"

install_online() {
  apt_root=/var/lib/lablink-agent/appliance/apt
  install -d -m 0755 "$apt_root"
  cat > "$apt_root/sources.list" <<'EOF'
deb %s noble main universe
deb %s noble-updates main universe
deb %s noble-security main universe
EOF
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o Acquire::Check-Valid-Until=false -o Dir::Etc::sourcelist="$apt_root/sources.list" -o Dir::Etc::sourceparts="-" update
  apt-get -o Acquire::Check-Valid-Until=false -o Dir::Etc::sourcelist="$apt_root/sources.list" -o Dir::Etc::sourceparts="-" \
    install -y --no-install-recommends %s
}

verify_offline_bundle() {
  bundle="$src/%s"
  manifest="$bundle/bundle-manifest.json"
  test -s "$manifest"
  echo "%s  $manifest" | sha256sum --check --status
  python3 - "$bundle" "$manifest" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1]).resolve()
manifest = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
if manifest.get("schema_version") != 1:
    raise SystemExit("unsupported offline bundle schema")
if (manifest.get("distribution"), manifest.get("release"), manifest.get("architecture")) != ("ubuntu", "24.04", "amd64"):
    raise SystemExit("offline bundle target mismatch")
if manifest.get("complete_dependency_closure") is not True:
    raise SystemExit("offline bundle is not a complete dependency closure")
packages = manifest.get("packages") or []
if not packages:
    raise SystemExit("offline bundle contains no packages")
for package in packages:
    if package.get("architecture") not in ("amd64", "all"):
        raise SystemExit("offline bundle contains an incompatible architecture")
    candidate = (root / package["file"]).resolve()
    if root not in candidate.parents or not candidate.is_file():
        raise SystemExit("offline bundle path escapes bundle root or is missing")
    digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
    if digest.lower() != package["sha256"].lower():
        raise SystemExit("offline bundle package checksum mismatch")
PY
  mapfile -t debs < <(find "$bundle" -type f -name '*.deb' -print | sort)
  test "${#debs[@]}" -gt 0
  dpkg --install "${debs[@]}"
}

case %s in
  online)
    install_online
    ;;
  offline)
    verify_offline_bundle
    ;;
  prefer_offline)
    if test -n %s && test -s "$src/%s/bundle-manifest.json"; then
      verify_offline_bundle
    else
      install_online
    fi
    ;;
esac

%s
command -v nft >/dev/null
command -v conntrack >/dev/null
command -v ip >/dev/null
command -v networkctl >/dev/null
systemctl cat systemd-networkd.service >/dev/null
test -e /proc/sys/net/ipv4/ip_forward
for module in nf_tables nf_conntrack nf_conntrack_netlink nf_nat nft_chain_nat hv_netvsc hv_utils; do
  grep -qw "$module" /proc/modules || modprobe -n "$module" >/dev/null
done

install -d -m 0755 /opt/lablink/orchestrator /etc/systemd/system/lablink-agent.service.d
install -d -o root -g root -m 0700 /var/lib/lablink-agent/appliance
install -m 0644 "$src/emergency.nft" /opt/lablink/orchestrator/emergency.nft
install -m 0644 "$src/dependency-manifest.json" /opt/lablink/orchestrator/dependency-manifest.json
install -m 0644 "$src/customization-manifest.json" /var/lib/lablink-agent/appliance/version-manifest.json
install -m 0644 "$src/lablink-disable-conflicting-firewalls.service" /etc/systemd/system/lablink-disable-conflicting-firewalls.service
install -m 0644 "$src/lablink-appliance-firewall.service" /etc/systemd/system/lablink-appliance-firewall.service
install -m 0644 "$src/lablink-appliance-watchdog.service" /etc/systemd/system/lablink-appliance-watchdog.service
install -m 0644 "$src/lablink-agent-appliance.conf" /etc/systemd/system/lablink-agent.service.d/20-appliance.conf

cat > /opt/lablink/orchestrator/load-emergency-policy.sh <<'EOF'
#!/bin/bash
set -Eeuo pipefail
printf '0\n' > /proc/sys/net/ipv4/ip_forward
exec /usr/sbin/nft -f /opt/lablink/orchestrator/emergency.nft
EOF
cat > /opt/lablink/orchestrator/disable-conflicting-firewalls.sh <<'EOF'
#!/bin/bash
set -Eeuo pipefail

if command -v ufw >/dev/null && test -f /etc/ufw/ufw.conf; then
  ufw --force disable
  if grep -Eiq '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*yes[[:space:]]*$' /etc/ufw/ufw.conf; then
    echo "UFW configuration remains enabled after disable" >&2
    exit 1
  fi
fi

services=(%s)
for service in "${services[@]}"; do
  load_state="$(systemctl show --property=LoadState --value "$service" 2>/dev/null || true)"
  if test -z "$load_state" || test "$load_state" = "not-found"; then
    continue
  fi
  systemctl stop "$service"
  enabled_state="$(systemctl is-enabled "$service" 2>/dev/null || true)"
  if test "$enabled_state" != "masked"; then
    systemctl disable "$service"
    systemctl mask "$service"
  fi
  if systemctl is-active --quiet "$service"; then
    echo "$service remains active after neutralization" >&2
    exit 1
  fi
  enabled_state="$(systemctl is-enabled "$service" 2>/dev/null || true)"
  if test "$enabled_state" != "masked"; then
    echo "$service enablement state is $enabled_state, expected masked" >&2
    exit 1
  fi
done
EOF
cat > /opt/lablink/orchestrator/verify-appliance-policy.sh <<'EOF'
#!/bin/bash
set -Eeuo pipefail
test -s /var/lib/lablink-agent/appliance/version-manifest.json
/usr/sbin/nft list table inet lablink | grep -q 'policy drop'
EOF
chmod 0755 /opt/lablink/orchestrator/disable-conflicting-firewalls.sh /opt/lablink/orchestrator/load-emergency-policy.sh /opt/lablink/orchestrator/verify-appliance-policy.sh

# Seed customization neutralizes known firewall managers before LabLink takes
# ownership. Runtime conflict scanning fails readiness if any manager or
# unmanaged rules remain. The existing main DHCP policy and all /etc/netplan
# files remain untouched.
systemctl daemon-reload
systemctl enable lablink-disable-conflicting-firewalls.service
systemctl enable --now lablink-appliance-firewall.service
systemctl enable lablink-appliance-watchdog.service
transition_ok=false
if systemctl restart lablink-agent.service; then
  for _ in $(seq 1 15); do
    if systemctl is-active --quiet lablink-agent.service &&
       timeout 1 bash -c '</dev/tcp/127.0.0.1/9091' 2>/dev/null; then
      transition_ok=true
      break
    fi
    sleep 1
  done
fi
if ! $transition_ok; then
  journalctl --no-pager -u lablink-appliance-firewall.service -u lablink-agent.service -n 200 \
    > /var/log/lablink-agent-appliance-transition.log 2>&1 || true
  rm -f /etc/systemd/system/lablink-agent.service.d/20-appliance.conf
  systemctl daemon-reload
  systemctl restart lablink-agent.service
  false
fi
systemctl is-active --quiet lablink-appliance-firewall.service
systemctl is-active --quiet lablink-agent.service
ip -4 route show default | grep -q "dev $main_iface"
printf 'ok version=%s mode=isolated_orchestrator\n' > "$status"
logger -t lablink-orchestrator-install "customization complete"
`,
		dependencies.Snapshot.BaseURL, dependencies.Snapshot.BaseURL, dependencies.Snapshot.BaseURL,
		strings.Join(specs, " "),
		bundlePath, bundleManifestSHA,
		shellQuote(config.PackageSource),
		shellQuote(bundlePath), bundlePath,
		strings.Join(checks, "\n"),
		strings.Join(managerServiceArgs, " "),
		config.ApplianceVersion,
	)
	return []byte(script)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
