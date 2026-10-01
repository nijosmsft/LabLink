package vmconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
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
}

// Config is loaded from ~/.lablink/vm-defaults.json by default.
type Config struct {
	DefaultProfile string             `json:"default_profile,omitempty"`
	Profiles       map[string]Profile `json:"profiles,omitempty"`
}

// Store is an immutable loaded defaults file.
type Store struct {
	path   string
	config Config
	err    error
}

// Load reads VM defaults. A missing file is valid and yields an empty store;
// malformed content is retained as an error so callers do not silently ignore
// a broken autonomous-creation policy.
func Load(path string) *Store {
	store := &Store{path: path, config: Config{Profiles: map[string]Profile{}}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return store
	}
	if err != nil {
		store.err = fmt.Errorf("read VM defaults %s: %w", path, err)
		return store
	}
	if err := json.Unmarshal(data, &store.config); err != nil {
		store.err = fmt.Errorf("parse VM defaults %s: %w", path, err)
		return store
	}
	if store.config.Profiles == nil {
		store.config.Profiles = map[string]Profile{}
	}
	return store
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
	if s == nil {
		return Profile{}, "", nil
	}
	if s.err != nil {
		return Profile{}, "", s.err
	}
	selected := strings.TrimSpace(name)
	if selected == "" {
		selected = strings.TrimSpace(s.config.DefaultProfile)
	}
	if selected == "" {
		return Profile{}, "", nil
	}
	profile, ok := s.config.Profiles[selected]
	if !ok {
		return Profile{}, "", fmt.Errorf("VM defaults profile %q not found in %s", selected, s.path)
	}
	return profile, selected, nil
}
