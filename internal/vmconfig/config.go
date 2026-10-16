package vmconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/nijosmsft/lablink/internal/flock"
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
	Target                            string  `json:"target,omitempty"`
	GuestOS                           string  `json:"guest_os,omitempty"`
	ProfileUsage                      string  `json:"profile_usage,omitempty"`
	BaseVHD                           string  `json:"base_vhd,omitempty"`
	VMRoot                            string  `json:"vm_root,omitempty"`
	VSwitch                           string  `json:"vswitch,omitempty"`
	AdminCredential                   string  `json:"admin_password_credential,omitempty"`
	MemoryMB                          float64 `json:"memory_mb,omitempty"`
	CPUCount                          float64 `json:"cpu_count,omitempty"`
	DynamicMemory                     bool    `json:"dynamic_memory,omitempty"`
	DynamicMinMB                      float64 `json:"dynamic_min_mb,omitempty"`
	DynamicMaxMB                      float64 `json:"dynamic_max_mb,omitempty"`
	DynamicBufferPct                  float64 `json:"dynamic_buffer_pct,omitempty"`
	SecureBoot                        *bool   `json:"secure_boot,omitempty"`
	Locale                            string  `json:"locale,omitempty"`
	TimeZone                          string  `json:"timezone,omitempty"`
	AutoLogon                         bool    `json:"auto_logon,omitempty"`
	ObfuscatePassword                 bool    `json:"obfuscate_password,omitempty"`
	RegisterLabLink                   *bool   `json:"register_with_lablink,omitempty"`
	LabLinkRole                       string  `json:"lablink_role,omitempty"`
	LabLinkPort                       int     `json:"lablink_port,omitempty"`
	MinHostReservePct                 float64 `json:"min_host_reserve_pct,omitempty"`
	ExposeVirtualizationExtensions    *bool   `json:"expose_virtualization_extensions,omitempty"`
	VirtualizationBasedSecurityOptOut *bool   `json:"virtualization_based_security_opt_out,omitempty"`
	Distribution                      string  `json:"distribution,omitempty"`
	Release                           string  `json:"release,omitempty"`
	Architecture                      string  `json:"architecture,omitempty"`
	ImageCacheRoot                    string  `json:"image_cache_root,omitempty"`
	LinuxUsername                     string  `json:"linux_username,omitempty"`
	SSHPublicKey                      string  `json:"ssh_public_key,omitempty"`
	SSHPublicKeyFile                  string  `json:"ssh_public_key_file,omitempty"`
	LinuxPasswordCredential           string  `json:"linux_password_credential,omitempty"`
	AllowSSHPasswordAuth              *bool   `json:"allow_ssh_password_auth,omitempty"`
	NetworkConfig                     string  `json:"network_config,omitempty"`
	DiskSizeGB                        float64 `json:"disk_size_gb,omitempty"`
	ImageBuilderProfile               string  `json:"image_builder_profile,omitempty"`
	BuilderVMName                     string  `json:"builder_vm_name,omitempty"`
	DeleteBuilderAfterPrepare         *bool   `json:"delete_builder_after_prepare,omitempty"`
}

// Config is loaded from ~/.lablink/vm-defaults.json by default.
type Config struct {
	DefaultProfile      string             `json:"default_profile,omitempty"`
	TargetDefaults      map[string]string  `json:"target_defaults,omitempty"`
	DefaultLinuxProfile string             `json:"default_linux_profile,omitempty"`
	LinuxTargetDefaults map[string]string  `json:"linux_target_defaults,omitempty"`
	Profiles            map[string]Profile `json:"profiles,omitempty"`
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
		Profiles:            map[string]Profile{},
		TargetDefaults:      map[string]string{},
		LinuxTargetDefaults: map[string]string{},
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
	for name, profile := range config.Profiles {
		if _, err := profile.EffectiveGuestOS(); err != nil {
			return config, fmt.Errorf("VM defaults profile %q: %w", name, err)
		}
		if _, err := profile.EffectiveProfileUsage(); err != nil {
			return config, fmt.Errorf("VM defaults profile %q: %w", name, err)
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
