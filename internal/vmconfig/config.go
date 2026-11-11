package vmconfig

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/nijosmsft/lablink/internal/flock"
	"github.com/nijosmsft/lablink/internal/orchestratorseed"
)

const (
	GuestOSWindows = "windows"
	GuestOSLinux   = "linux"

	ProfileUsageOrdinary          = "ordinary"
	ProfileUsageLinuxImageBuilder = "linux_image_builder"
)

// Profile contains non-secret defaults for creating a Hyper-V VM.
// AdminCredential is a credential-store profile name, never a password.
// GuestOS is backward-compatible: empty means Windows.
type Profile struct {
	Target                            string             `json:"target,omitempty"`
	GuestOS                           string             `json:"guest_os,omitempty"`
	ProfileUsage                      string             `json:"profile_usage,omitempty"`
	BaseVHD                           string             `json:"base_vhd,omitempty"`
	VMRoot                            string             `json:"vm_root,omitempty"`
	VSwitch                           string             `json:"vswitch,omitempty"`
	AdminCredential                   string             `json:"admin_password_credential,omitempty"`
	MemoryMB                          float64            `json:"memory_mb,omitempty"`
	CPUCount                          float64            `json:"cpu_count,omitempty"`
	DynamicMemory                     bool               `json:"dynamic_memory,omitempty"`
	DynamicMinMB                      float64            `json:"dynamic_min_mb,omitempty"`
	DynamicMaxMB                      float64            `json:"dynamic_max_mb,omitempty"`
	DynamicBufferPct                  float64            `json:"dynamic_buffer_pct,omitempty"`
	SecureBoot                        *bool              `json:"secure_boot,omitempty"`
	Locale                            string             `json:"locale,omitempty"`
	TimeZone                          string             `json:"timezone,omitempty"`
	AutoLogon                         bool               `json:"auto_logon,omitempty"`
	ObfuscatePassword                 bool               `json:"obfuscate_password,omitempty"`
	RegisterLabLink                   *bool              `json:"register_with_lablink,omitempty"`
	LabLinkRole                       string             `json:"lablink_role,omitempty"`
	LabLinkPort                       int                `json:"lablink_port,omitempty"`
	MinHostReservePct                 float64            `json:"min_host_reserve_pct,omitempty"`
	ExposeVirtualizationExtensions    *bool              `json:"expose_virtualization_extensions,omitempty"`
	VirtualizationBasedSecurityOptOut *bool              `json:"virtualization_based_security_opt_out,omitempty"`
	Distribution                      string             `json:"distribution,omitempty"`
	Release                           string             `json:"release,omitempty"`
	Architecture                      string             `json:"architecture,omitempty"`
	ImageCacheRoot                    string             `json:"image_cache_root,omitempty"`
	LinuxUsername                     string             `json:"linux_username,omitempty"`
	SSHPublicKey                      string             `json:"ssh_public_key,omitempty"`
	SSHPublicKeyFile                  string             `json:"ssh_public_key_file,omitempty"`
	LinuxPasswordCredential           string             `json:"linux_password_credential,omitempty"`
	AllowSSHPasswordAuth              *bool              `json:"allow_ssh_password_auth,omitempty"`
	NetworkConfig                     string             `json:"network_config,omitempty"`
	DiskSizeGB                        float64            `json:"disk_size_gb,omitempty"`
	ImageBuilderProfile               string             `json:"image_builder_profile,omitempty"`
	BuilderVMName                     string             `json:"builder_vm_name,omitempty"`
	DeleteBuilderAfterPrepare         *bool              `json:"delete_builder_after_prepare,omitempty"`
	DomainJoin                        *WindowsDomainJoin `json:"domain_join,omitempty"`
}

// IsolatedOrchestratorProfile references an ordinary Linux VM profile and
// adds the bounded appliance policy used to customize it after the existing
// create_linux_vm bootstrap completes.
type IsolatedOrchestratorProfile struct {
	LinuxProfile                string  `json:"linux_profile"`
	MainVSwitch                 string  `json:"main_vswitch,omitempty"`
	CPUCount                    float64 `json:"cpu_count,omitempty"`
	MemoryMB                    float64 `json:"memory_mb,omitempty"`
	DynamicMemory               *bool   `json:"dynamic_memory,omitempty"`
	MaxNetworks                 int     `json:"max_networks,omitempty"`
	MaxVMs                      int     `json:"max_vms,omitempty"`
	RelayPortMin                int     `json:"relay_port_min,omitempty"`
	RelayPortMax                int     `json:"relay_port_max,omitempty"`
	SubnetPool                  string  `json:"subnet_pool,omitempty"`
	SubnetPrefix                int     `json:"subnet_prefix,omitempty"`
	PackageSource               string  `json:"package_source,omitempty"`
	OfflineBundlePath           string  `json:"offline_bundle_path,omitempty"`
	OfflineBundleManifestSHA256 string  `json:"offline_bundle_manifest_sha256,omitempty"`
}

// ResolvedIsolatedOrchestratorProfile contains an effective appliance policy
// and the ordinary Linux VM profile that remains the bootstrap source.
type ResolvedIsolatedOrchestratorProfile struct {
	Profile          IsolatedOrchestratorProfile
	LinuxProfileName string
	LinuxVM          Profile
}

// SeedConfig converts the resolved profile policy to the customization input
// consumed by the ordinary Linux NoCloud seed path.
func (r ResolvedIsolatedOrchestratorProfile) SeedConfig(applianceVersion, orchestratorID string) orchestratorseed.Config {
	config := orchestratorseed.Config{
		ApplianceVersion: applianceVersion,
		OrchestratorID:   orchestratorID,
		PackageSource:    r.Profile.PackageSource,
		MaxNetworks:      r.Profile.MaxNetworks,
		MaxVMs:           r.Profile.MaxVMs,
		RelayPortMin:     r.Profile.RelayPortMin,
		RelayPortMax:     r.Profile.RelayPortMax,
		SubnetPool:       r.Profile.SubnetPool,
		SubnetPrefix:     r.Profile.SubnetPrefix,
	}
	if r.Profile.OfflineBundlePath != "" {
		config.OfflineBundle = &orchestratorseed.OfflineBundle{
			Path:           r.Profile.OfflineBundlePath,
			ManifestSHA256: r.Profile.OfflineBundleManifestSHA256,
		}
	}
	return config
}

// WindowsDomainJoin contains non-secret defaults for joining a Windows guest
// after LabLink enrollment. PasswordSecret is a secret-store name, never a
// password value.
type WindowsDomainJoin struct {
	Domain              string `json:"domain"`
	Username            string `json:"username"`
	PasswordSecret      string `json:"password_secret"`
	OUPath              string `json:"ou_path,omitempty"`
	Reboot              *bool  `json:"reboot,omitempty"`
	VerifySecureChannel *bool  `json:"verify_secure_channel,omitempty"`
}

func (c WindowsDomainJoin) EffectiveReboot() bool {
	return c.Reboot == nil || *c.Reboot
}

func (c WindowsDomainJoin) EffectiveVerifySecureChannel() bool {
	return c.VerifySecureChannel == nil || *c.VerifySecureChannel
}

func (c WindowsDomainJoin) Validate() error {
	c.Domain = strings.TrimSpace(c.Domain)
	c.Username = strings.TrimSpace(c.Username)
	c.PasswordSecret = strings.TrimSpace(c.PasswordSecret)
	c.OUPath = strings.TrimSpace(c.OUPath)
	if c.Domain == "" {
		return fmt.Errorf("domain_join.domain is required")
	}
	if len(c.Domain) > 253 {
		return fmt.Errorf("domain_join.domain is too long")
	}
	for _, label := range strings.Split(c.Domain, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("domain_join.domain %q is not a valid DNS domain", c.Domain)
		}
		for _, r := range label {
			if !(r == '-' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
				return fmt.Errorf("domain_join.domain %q is not a valid DNS domain", c.Domain)
			}
		}
	}
	if c.Username == "" {
		return fmt.Errorf("domain_join.username is required")
	}
	if strings.ContainsAny(c.Username, "\r\n\x00") {
		return fmt.Errorf("domain_join.username contains invalid control characters")
	}
	if c.PasswordSecret == "" {
		return fmt.Errorf("domain_join.password_secret is required")
	}
	for _, r := range c.PasswordSecret {
		if !(r == '-' || r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return fmt.Errorf("domain_join.password_secret %q contains invalid character %q", c.PasswordSecret, r)
		}
	}
	if strings.ContainsAny(c.OUPath, "\r\n\x00") {
		return fmt.Errorf("domain_join.ou_path contains invalid control characters")
	}
	if c.EffectiveVerifySecureChannel() && !c.EffectiveReboot() {
		return fmt.Errorf("domain_join.verify_secure_channel requires domain_join.reboot=true")
	}
	return nil
}

// Config is loaded from ~/.lablink/vm-defaults.json by default.
type Config struct {
	DefaultProfile                     string                                 `json:"default_profile,omitempty"`
	TargetDefaults                     map[string]string                      `json:"target_defaults,omitempty"`
	DefaultLinuxProfile                string                                 `json:"default_linux_profile,omitempty"`
	LinuxTargetDefaults                map[string]string                      `json:"linux_target_defaults,omitempty"`
	DefaultIsolatedOrchestratorProfile string                                 `json:"default_isolated_orchestrator_profile,omitempty"`
	IsolatedOrchestratorProfiles       map[string]IsolatedOrchestratorProfile `json:"isolated_orchestrator_profiles,omitempty"`
	Profiles                           map[string]Profile                     `json:"profiles,omitempty"`
}

// Store is an immutable loaded defaults file.
type Store struct {
	mu   sync.Mutex
	path string
}

// Load reads VM defaults. A missing file is valid and yields an empty store;
// malformed content is retained as an error so callers do not silently ignore
// a broken autonomous-creation policy.
func Load(path string) *Store {
	return &Store{path: path}
}

func emptyConfig() Config {
	return Config{
		Profiles:                     map[string]Profile{},
		TargetDefaults:               map[string]string{},
		LinuxTargetDefaults:          map[string]string{},
		IsolatedOrchestratorProfiles: map[string]IsolatedOrchestratorProfile{},
	}
}

func (s *Store) load() (Config, error) {
	config := emptyConfig()
	if s == nil {
		return config, nil
	}
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return config, nil
	}
	if err != nil {
		return config, fmt.Errorf("read VM defaults %s: %w", s.path, err)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("parse VM defaults %s: %w", s.path, err)
	}
	if config.Profiles == nil {
		config.Profiles = map[string]Profile{}
	}
	if config.TargetDefaults == nil {
		config.TargetDefaults = map[string]string{}
	}
	if config.LinuxTargetDefaults == nil {
		config.LinuxTargetDefaults = map[string]string{}
	}
	if config.IsolatedOrchestratorProfiles == nil {
		config.IsolatedOrchestratorProfiles = map[string]IsolatedOrchestratorProfile{}
	}
	for name, profile := range config.Profiles {
		guestOS, err := profile.EffectiveGuestOS()
		if err != nil {
			return config, fmt.Errorf("VM defaults profile %q: %w", name, err)
		}
		if _, err := profile.EffectiveProfileUsage(); err != nil {
			return config, fmt.Errorf("VM defaults profile %q: %w", name, err)
		}
		if profile.DomainJoin != nil {
			if guestOS != GuestOSWindows {
				return config, fmt.Errorf("VM defaults profile %q: domain_join is supported only for Windows profiles", name)
			}
			if err := profile.DomainJoin.Validate(); err != nil {
				return config, fmt.Errorf("VM defaults profile %q: %w", name, err)
			}
		}
	}
	for name := range config.IsolatedOrchestratorProfiles {
		if _, err := config.resolveIsolatedOrchestratorProfile(name); err != nil {
			return config, fmt.Errorf("isolated orchestrator profile %q: %w", name, err)
		}
	}
	if selected := strings.TrimSpace(config.DefaultIsolatedOrchestratorProfile); selected != "" {
		if _, ok := config.IsolatedOrchestratorProfiles[selected]; !ok {
			return config, fmt.Errorf("default_isolated_orchestrator_profile %q not found", selected)
		}
	}
	return config, nil
}

func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Resolve returns the requested profile, or the configured default when name
// is empty. The returned name is the actual selected profile.
func (s *Store) Resolve(name string) (Profile, string, error) {
	return s.ResolveForTarget(name, "")
}

// ResolveForTarget selects an explicit profile, then a target-specific
// default, then the global default.
func (s *Store) ResolveForTarget(name, target string) (Profile, string, error) {
	return s.resolveForTarget(name, target, false, false)
}

// ResolveWindows returns a Windows profile using the legacy default_profile
// and target_defaults selectors. Profiles with an empty guest_os are Windows.
func (s *Store) ResolveWindows(name string) (Profile, string, error) {
	return s.ResolveWindowsForTarget(name, "")
}

// ResolveWindowsForTarget selects an explicit Windows profile, then the
// legacy target-specific default, then the legacy global default.
func (s *Store) ResolveWindowsForTarget(name, target string) (Profile, string, error) {
	return s.resolveForTarget(name, target, false, true)
}

// ResolveOrdinaryWindowsForTarget resolves the profile used by the public
// create_windows_vm tool and rejects builder-only profiles. Internal Linux
// image preparation intentionally uses ResolveWindowsForTarget instead.
func (s *Store) ResolveOrdinaryWindowsForTarget(name, target string) (Profile, string, error) {
	profile, selected, err := s.ResolveWindowsForTarget(name, target)
	if err != nil {
		return Profile{}, "", err
	}
	builderOnly, err := s.IsLinuxImageBuilderProfile(selected)
	if err != nil {
		return Profile{}, "", err
	}
	if !builderOnly {
		return profile, selected, nil
	}
	suggestionTarget := target
	if strings.TrimSpace(suggestionTarget) == "" {
		suggestionTarget = profile.Target
	}
	suggestion := s.ordinaryWindowsDefaultSuggestion(suggestionTarget, selected)
	return Profile{}, "", fmt.Errorf(
		"VM defaults profile %q is reserved for internal Linux image preparation (profile_usage %q or referenced by a Linux image_builder_profile); %s",
		selected, ProfileUsageLinuxImageBuilder, suggestion,
	)
}

// IsLinuxImageBuilderProfile reports whether a Windows profile is explicitly
// classified as a Linux image builder or is referenced by any Linux profile.
// Reference inference preserves existing configurations created before
// profile_usage was introduced.
func (s *Store) IsLinuxImageBuilderProfile(name string) (bool, error) {
	if s == nil || strings.TrimSpace(name) == "" {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	config, err := s.load()
	if err != nil {
		return false, err
	}
	return config.isLinuxImageBuilderProfile(name)
}

func (c Config) isLinuxImageBuilderProfile(name string) (bool, error) {
	profile, ok := c.Profiles[name]
	if !ok {
		return false, fmt.Errorf("VM defaults profile %q not found", name)
	}
	usage, err := profile.EffectiveProfileUsage()
	if err != nil {
		return false, fmt.Errorf("VM defaults profile %q: %w", name, err)
	}
	if usage == ProfileUsageLinuxImageBuilder {
		return true, nil
	}
	for linuxName, candidate := range c.Profiles {
		guestOS, err := candidate.EffectiveGuestOS()
		if err != nil {
			return false, fmt.Errorf("VM defaults profile %q: %w", linuxName, err)
		}
		if guestOS == GuestOSLinux &&
			strings.EqualFold(strings.TrimSpace(candidate.ImageBuilderProfile), strings.TrimSpace(name)) {
			return true, nil
		}
	}
	return false, nil
}

// ResolveLinux returns a Linux profile using default_linux_profile and
// linux_target_defaults.
func (s *Store) ResolveLinux(name string) (Profile, string, error) {
	return s.ResolveLinuxForTarget(name, "")
}

// ResolveLinuxForTarget selects an explicit Linux profile, then the
// Linux-specific target default, then the Linux-specific global default.
func (s *Store) ResolveLinuxForTarget(name, target string) (Profile, string, error) {
	return s.resolveForTarget(name, target, true, true)
}

// ResolveIsolatedOrchestrator selects an explicit profile or the configured
// isolated-orchestrator default without changing ordinary Linux resolution.
func (s *Store) ResolveIsolatedOrchestrator(name string) (ResolvedIsolatedOrchestratorProfile, string, error) {
	if s == nil {
		return ResolvedIsolatedOrchestratorProfile{}, "", nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	config, err := s.load()
	if err != nil {
		return ResolvedIsolatedOrchestratorProfile{}, "", err
	}
	selected := strings.TrimSpace(name)
	if selected == "" {
		selected = strings.TrimSpace(config.DefaultIsolatedOrchestratorProfile)
	}
	if selected == "" {
		return ResolvedIsolatedOrchestratorProfile{}, "", nil
	}
	resolved, err := config.resolveIsolatedOrchestratorProfile(selected)
	if err != nil {
		return ResolvedIsolatedOrchestratorProfile{}, "", fmt.Errorf("isolated orchestrator profile %q: %w", selected, err)
	}
	return resolved, selected, nil
}

func (c Config) resolveIsolatedOrchestratorProfile(name string) (ResolvedIsolatedOrchestratorProfile, error) {
	profile, ok := c.IsolatedOrchestratorProfiles[name]
	if !ok {
		return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf("not found")
	}
	profile = profile.withDefaults()
	linuxName := strings.TrimSpace(profile.LinuxProfile)
	if linuxName == "" {
		return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf("linux_profile is required")
	}
	linuxProfile, ok := c.Profiles[linuxName]
	if !ok {
		return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf("linux_profile %q not found", linuxName)
	}
	guestOS, err := linuxProfile.EffectiveGuestOS()
	if err != nil {
		return ResolvedIsolatedOrchestratorProfile{}, err
	}
	if guestOS != GuestOSLinux {
		return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf("linux_profile %q is for guest_os %q", linuxName, guestOS)
	}
	usage, err := linuxProfile.EffectiveProfileUsage()
	if err != nil {
		return ResolvedIsolatedOrchestratorProfile{}, err
	}
	if usage != ProfileUsageOrdinary {
		return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf("linux_profile %q must be an ordinary Linux profile", linuxName)
	}
	if !strings.EqualFold(strings.TrimSpace(linuxProfile.Distribution), "ubuntu") ||
		strings.TrimSpace(linuxProfile.Release) != "24.04" ||
		!strings.EqualFold(strings.TrimSpace(linuxProfile.Architecture), "amd64") {
		return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf(
			"linux_profile %q must use Ubuntu 24.04 amd64", linuxName)
	}
	mainVSwitch := strings.TrimSpace(profile.MainVSwitch)
	if mainVSwitch == "" {
		mainVSwitch = strings.TrimSpace(linuxProfile.VSwitch)
	}
	if mainVSwitch == "" {
		return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf("main_vswitch or linux_profile.vswitch is required")
	}
	profile.MainVSwitch = mainVSwitch
	if profile.CPUCount <= 0 || profile.CPUCount != float64(int(profile.CPUCount)) {
		return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf("cpu_count must be a positive whole number")
	}
	if profile.MemoryMB <= 0 || profile.MemoryMB != float64(int(profile.MemoryMB)) {
		return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf("memory_mb must be a positive whole number")
	}
	if profile.DynamicMemory != nil && *profile.DynamicMemory {
		return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf("dynamic_memory must be false for an isolated orchestrator")
	}
	if profile.MaxNetworks < 1 || profile.MaxNetworks > orchestratorseed.DefaultMaxNetworks {
		return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf(
			"max_networks must be between 1 and %d", orchestratorseed.DefaultMaxNetworks)
	}
	if profile.MaxVMs < 1 || profile.MaxVMs > orchestratorseed.DefaultMaxVMs {
		return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf(
			"max_vms must be between 1 and %d", orchestratorseed.DefaultMaxVMs)
	}
	if profile.RelayPortMin < 1 || profile.RelayPortMax > 65535 ||
		profile.RelayPortMin > profile.RelayPortMax ||
		profile.RelayPortMax-profile.RelayPortMin+1 < profile.MaxVMs {
		return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf(
			"relay port range must be ordered, within 1-65535, and contain at least max_vms ports")
	}
	pool, err := netip.ParsePrefix(profile.SubnetPool)
	if err != nil || !pool.Addr().Is4() || pool != pool.Masked() {
		return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf("subnet_pool must be a canonical IPv4 prefix")
	}
	if profile.SubnetPrefix < pool.Bits() || profile.SubnetPrefix > 30 {
		return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf(
			"subnet_prefix must be between pool prefix /%d and /30", pool.Bits())
	}
	availableSubnets := 1 << (profile.SubnetPrefix - pool.Bits())
	if availableSubnets < profile.MaxNetworks {
		return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf(
			"subnet_pool provides %d subnets, fewer than max_networks %d", availableSubnets, profile.MaxNetworks)
	}
	switch profile.PackageSource {
	case orchestratorseed.PackageSourceOnline:
		if profile.OfflineBundlePath != "" || profile.OfflineBundleManifestSHA256 != "" {
			return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf(
				"offline bundle fields are not used when package_source is %q", profile.PackageSource)
		}
	case orchestratorseed.PackageSourceOffline:
		if strings.TrimSpace(profile.OfflineBundlePath) == "" ||
			!isSHA256(profile.OfflineBundleManifestSHA256) {
			return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf(
				"offline package source requires offline_bundle_path and offline_bundle_manifest_sha256")
		}
	case orchestratorseed.PackageSourcePreferOffline:
		if (profile.OfflineBundlePath == "") != (profile.OfflineBundleManifestSHA256 == "") ||
			profile.OfflineBundleManifestSHA256 != "" && !isSHA256(profile.OfflineBundleManifestSHA256) {
			return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf(
				"prefer_offline bundle path and SHA-256 must be provided together")
		}
	default:
		return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf("unsupported package_source %q", profile.PackageSource)
	}
	if profile.OfflineBundlePath != "" {
		if err := orchestratorseed.ValidateOfflineBundlePath(profile.OfflineBundlePath); err != nil {
			return ResolvedIsolatedOrchestratorProfile{}, fmt.Errorf("%s", strings.NewReplacer(
				"offline_bundle.path", "offline_bundle_path").Replace(err.Error()))
		}
	}

	linuxProfile.VSwitch = profile.MainVSwitch
	linuxProfile.CPUCount = profile.CPUCount
	linuxProfile.MemoryMB = profile.MemoryMB
	linuxProfile.DynamicMemory = false
	register := true
	linuxProfile.RegisterLabLink = &register
	linuxProfile.LabLinkPort = 9091
	if strings.TrimSpace(linuxProfile.LabLinkRole) == "" || linuxProfile.LabLinkRole == "vm" {
		linuxProfile.LabLinkRole = "isolated-orchestrator"
	}
	return ResolvedIsolatedOrchestratorProfile{
		Profile:          profile,
		LinuxProfileName: linuxName,
		LinuxVM:          linuxProfile,
	}, nil
}

func (p IsolatedOrchestratorProfile) withDefaults() IsolatedOrchestratorProfile {
	static := false
	if p.CPUCount == 0 {
		p.CPUCount = 4
	}
	if p.MemoryMB == 0 {
		p.MemoryMB = 8192
	}
	if p.DynamicMemory == nil {
		p.DynamicMemory = &static
	}
	if p.MaxNetworks == 0 {
		p.MaxNetworks = orchestratorseed.DefaultMaxNetworks
	}
	if p.MaxVMs == 0 {
		p.MaxVMs = orchestratorseed.DefaultMaxVMs
	}
	if p.RelayPortMin == 0 {
		p.RelayPortMin = orchestratorseed.DefaultRelayPortMin
	}
	if p.RelayPortMax == 0 {
		p.RelayPortMax = orchestratorseed.DefaultRelayPortMax
	}
	if strings.TrimSpace(p.SubnetPool) == "" {
		p.SubnetPool = orchestratorseed.DefaultSubnetPool
	}
	if p.SubnetPrefix == 0 {
		p.SubnetPrefix = orchestratorseed.DefaultSubnetPrefix
	}
	if strings.TrimSpace(p.PackageSource) == "" {
		p.PackageSource = orchestratorseed.PackageSourceOnline
	}
	return p
}

func isSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func (s *Store) resolveForTarget(name, target string, linux, validateOS bool) (Profile, string, error) {
	if s == nil {
		return Profile{}, "", nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	config, err := s.load()
	if err != nil {
		return Profile{}, "", err
	}
	selected := strings.TrimSpace(name)
	if selected == "" && strings.TrimSpace(target) != "" {
		defaults := config.TargetDefaults
		if linux {
			defaults = config.LinuxTargetDefaults
		}
		for configuredTarget, profileName := range defaults {
			if strings.EqualFold(strings.TrimSpace(configuredTarget), strings.TrimSpace(target)) {
				selected = strings.TrimSpace(profileName)
				break
			}
		}
	}
	if selected == "" {
		if linux {
			selected = strings.TrimSpace(config.DefaultLinuxProfile)
		} else {
			selected = strings.TrimSpace(config.DefaultProfile)
		}
	}
	if selected == "" {
		return Profile{}, "", nil
	}
	profile, ok := config.Profiles[selected]
	if !ok {
		return Profile{}, "", fmt.Errorf("VM defaults profile %q not found in %s", selected, s.path)
	}
	if _, err := profile.EffectiveProfileUsage(); err != nil {
		return Profile{}, "", fmt.Errorf("VM defaults profile %q: %w", selected, err)
	}
	if validateOS {
		guestOS, err := profile.EffectiveGuestOS()
		if err != nil {
			return Profile{}, "", fmt.Errorf("VM defaults profile %q: %w", selected, err)
		}
		expected := GuestOSWindows
		if linux {
			expected = GuestOSLinux
		}
		if guestOS != expected {
			return Profile{}, "", fmt.Errorf("VM defaults profile %q is for guest_os %q, not %q", selected, guestOS, expected)
		}
	}
	return profile, selected, nil
}

func (s *Store) ordinaryWindowsDefaultSuggestion(target, rejected string) string {
	if s == nil {
		return "choose an ordinary Windows profile"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	config, err := s.load()
	if err != nil {
		return "choose an ordinary Windows profile"
	}
	candidates := make([]struct {
		name   string
		source string
	}, 0, 2)
	if strings.TrimSpace(target) != "" {
		for configuredTarget, profileName := range config.TargetDefaults {
			if strings.EqualFold(strings.TrimSpace(configuredTarget), strings.TrimSpace(target)) {
				candidates = append(candidates, struct {
					name   string
					source string
				}{strings.TrimSpace(profileName), fmt.Sprintf("target default for %q", target)})
				break
			}
		}
	}
	candidates = append(candidates, struct {
		name   string
		source string
	}{strings.TrimSpace(config.DefaultProfile), "default_profile"})
	for _, candidate := range candidates {
		if candidate.name == "" || candidate.name == rejected {
			continue
		}
		profile, ok := config.Profiles[candidate.name]
		if !ok {
			continue
		}
		guestOS, guestErr := profile.EffectiveGuestOS()
		builderOnly, builderErr := config.isLinuxImageBuilderProfile(candidate.name)
		if guestErr == nil && builderErr == nil && guestOS == GuestOSWindows && !builderOnly {
			return fmt.Sprintf("use ordinary profile %q configured as the %s", candidate.name, candidate.source)
		}
	}
	return "choose an ordinary Windows profile or configure default_profile/target_defaults to one"
}

func (s *Store) Set(name string, profile Profile, targetDefault bool) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("template name is required")
	}
	if s == nil || s.path == "" {
		return fmt.Errorf("VM template store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := flock.Lock(s.path + ".lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	config, err := s.load()
	if err != nil {
		return err
	}
	guestOS, err := profile.EffectiveGuestOS()
	if err != nil {
		return err
	}
	usage, err := profile.EffectiveProfileUsage()
	if err != nil {
		return err
	}
	if profile.DomainJoin != nil {
		if guestOS != GuestOSWindows {
			return fmt.Errorf("domain_join is supported only for Windows profiles")
		}
		if err := profile.DomainJoin.Validate(); err != nil {
			return err
		}
	}
	if targetDefault && usage == ProfileUsageLinuxImageBuilder {
		return fmt.Errorf("profile_usage %q cannot be an ordinary target default; save it with set_as_target_default=false", usage)
	}
	config.Profiles[name] = profile
	if targetDefault {
		if strings.TrimSpace(profile.Target) == "" {
			return fmt.Errorf("target is required when setting a target default")
		}
		if guestOS == GuestOSLinux {
			config.LinuxTargetDefaults[profile.Target] = name
		} else {
			config.TargetDefaults[profile.Target] = name
		}
	}
	for orchestratorName := range config.IsolatedOrchestratorProfiles {
		if _, err := config.resolveIsolatedOrchestratorProfile(orchestratorName); err != nil {
			return fmt.Errorf("isolated orchestrator profile %q: %w", orchestratorName, err)
		}
	}
	return s.save(config)
}

func (s *Store) Delete(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("template name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := flock.Lock(s.path + ".lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	config, err := s.load()
	if err != nil {
		return err
	}
	if _, ok := config.Profiles[name]; !ok {
		return fmt.Errorf("VM template %q not found", name)
	}
	for orchestratorName, orchestrator := range config.IsolatedOrchestratorProfiles {
		if strings.TrimSpace(orchestrator.LinuxProfile) == name {
			return fmt.Errorf("VM template %q is referenced by isolated orchestrator profile %q", name, orchestratorName)
		}
	}
	delete(config.Profiles, name)
	for target, selected := range config.TargetDefaults {
		if selected == name {
			delete(config.TargetDefaults, target)
		}
	}
	for target, selected := range config.LinuxTargetDefaults {
		if selected == name {
			delete(config.LinuxTargetDefaults, target)
		}
	}
	if config.DefaultProfile == name {
		config.DefaultProfile = ""
	}
	if config.DefaultLinuxProfile == name {
		config.DefaultLinuxProfile = ""
	}
	return s.save(config)
}

func (s *Store) List() (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

func (s *Store) save(config Config) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, s.path)
}

func (c Config) Names() []string {
	names := make([]string, 0, len(c.Profiles))
	for name := range c.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// EffectiveGuestOS normalizes guest_os. Empty is Windows for compatibility.
func (p Profile) EffectiveGuestOS() (string, error) {
	switch strings.ToLower(strings.TrimSpace(p.GuestOS)) {
	case "", GuestOSWindows:
		return GuestOSWindows, nil
	case GuestOSLinux:
		return GuestOSLinux, nil
	default:
		return "", fmt.Errorf("unsupported guest_os %q (expected windows or linux)", p.GuestOS)
	}
}

// EffectiveProfileUsage normalizes profile_usage. Empty remains ordinary for
// compatibility with profiles created before usage classification existed.
func (p Profile) EffectiveProfileUsage() (string, error) {
	switch strings.ToLower(strings.TrimSpace(p.ProfileUsage)) {
	case "", ProfileUsageOrdinary:
		return ProfileUsageOrdinary, nil
	case ProfileUsageLinuxImageBuilder:
		return ProfileUsageLinuxImageBuilder, nil
	default:
		return "", fmt.Errorf(
			"unsupported profile_usage %q (expected %s or %s)",
			p.ProfileUsage, ProfileUsageOrdinary, ProfileUsageLinuxImageBuilder,
		)
	}
}
