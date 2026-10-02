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

// Profile contains non-secret defaults for creating a Windows Hyper-V VM.
// AdminCredential is a credential-store profile name, never a password.
type Profile struct {
	Target            string  `json:"target,omitempty"`
	BaseVHD           string  `json:"base_vhd,omitempty"`
	VMRoot            string  `json:"vm_root,omitempty"`
	VSwitch           string  `json:"vswitch,omitempty"`
	AdminCredential   string  `json:"admin_password_credential,omitempty"`
	MemoryMB          float64 `json:"memory_mb,omitempty"`
	CPUCount          float64 `json:"cpu_count,omitempty"`
	DynamicMemory     bool    `json:"dynamic_memory,omitempty"`
	DynamicMinMB      float64 `json:"dynamic_min_mb,omitempty"`
	DynamicMaxMB      float64 `json:"dynamic_max_mb,omitempty"`
	DynamicBufferPct  float64 `json:"dynamic_buffer_pct,omitempty"`
	SecureBoot        *bool   `json:"secure_boot,omitempty"`
	Locale            string  `json:"locale,omitempty"`
	TimeZone          string  `json:"timezone,omitempty"`
	AutoLogon         bool    `json:"auto_logon,omitempty"`
	ObfuscatePassword bool    `json:"obfuscate_password,omitempty"`
	RegisterLabLink   bool    `json:"register_with_lablink,omitempty"`
	LabLinkRole       string  `json:"lablink_role,omitempty"`
	LabLinkPort       int     `json:"lablink_port,omitempty"`
	MinHostReservePct float64 `json:"min_host_reserve_pct,omitempty"`
}

// Config is loaded from ~/.lablink/vm-defaults.json by default.
type Config struct {
	DefaultProfile string             `json:"default_profile,omitempty"`
	TargetDefaults map[string]string  `json:"target_defaults,omitempty"`
	Profiles       map[string]Profile `json:"profiles,omitempty"`
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
		Profiles:       map[string]Profile{},
		TargetDefaults: map[string]string{},
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
		for configuredTarget, profileName := range config.TargetDefaults {
			if strings.EqualFold(strings.TrimSpace(configuredTarget), strings.TrimSpace(target)) {
				selected = strings.TrimSpace(profileName)
				break
			}
		}
	}
	if selected == "" {
		selected = strings.TrimSpace(config.DefaultProfile)
	}
	if selected == "" {
		return Profile{}, "", nil
	}
	profile, ok := config.Profiles[selected]
	if !ok {
		return Profile{}, "", fmt.Errorf("VM defaults profile %q not found in %s", selected, s.path)
	}
	return profile, selected, nil
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
	config.Profiles[name] = profile
	if targetDefault {
		if strings.TrimSpace(profile.Target) == "" {
			return fmt.Errorf("target is required when setting a target default")
		}
		config.TargetDefaults[profile.Target] = name
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
	if config.DefaultProfile == name {
		config.DefaultProfile = ""
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
