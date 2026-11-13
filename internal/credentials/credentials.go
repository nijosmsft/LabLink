package credentials

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode"

	"github.com/nijosmsft/lablink/internal/secretstore"
)

const currentStoreVersion = 2

var ErrLegacyPlaintext = errors.New("legacy plaintext credential requires re-save")

// Profile stores credential metadata. Password is populated only on Get and is
// never serialized to credentials.json.
type Profile struct {
	Name           string `json:"name"`
	Username       string `json:"username"`
	Password       string `json:"-"`
	PasswordSecret string `json:"password_secret,omitempty"`
	RequiresResave bool   `json:"requires_resave,omitempty"`
}

type diskProfile struct {
	Name           string `json:"name"`
	Username       string `json:"username"`
	Password       string `json:"password,omitempty"`
	PasswordSecret string `json:"password_secret,omitempty"`
	RequiresResave bool   `json:"requires_resave,omitempty"`
}

type storeData struct {
	Version  int                     `json:"version"`
	Profiles map[string]*diskProfile `json:"profiles"`
}

// Store manages credential metadata and an encrypted password store.
type Store struct {
	mu       sync.RWMutex
	profiles map[string]*Profile
	filePath string
	secrets  *secretstore.Store
	loadErr  error
}

// LoadStore reads credential metadata from disk. Passwords are stored in a
// separate encrypted store beside credentials.json.
func LoadStore(filePath string, encrypted ...*secretstore.Store) *Store {
	secretPath := filepath.Join(filepath.Dir(filePath), "credential-secrets.json")
	secretStore := secretstore.Open(secretPath)
	if len(encrypted) > 0 && encrypted[0] != nil {
		secretStore = encrypted[0]
	}
	s := &Store{
		profiles: make(map[string]*Profile),
		filePath: filePath,
		secrets:  secretStore,
	}
	s.loadErr = s.load()
	return s
}

func ValidateName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("credential name is required")
	}
	if len(name) > 128 {
		return "", fmt.Errorf("credential name cannot exceed 128 characters")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("credential name contains a control character")
		}
	}
	return name, nil
}

func ValidateUsername(username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", fmt.Errorf("credential username is required")
	}
	if len(username) > 256 {
		return "", fmt.Errorf("credential username cannot exceed 256 characters")
	}
	for _, r := range username {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("credential username contains a control character")
		}
	}
	return username, nil
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.filePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read credential metadata: %w", err)
	}
	var stored storeData
	if err := json.Unmarshal(data, &stored); err != nil {
		return fmt.Errorf("parse credential metadata: %w", err)
	}
	for key, raw := range stored.Profiles {
		if raw == nil {
			continue
		}
		name := strings.TrimSpace(raw.Name)
		if name == "" {
			name = strings.TrimSpace(key)
		}
		if name == "" {
			continue
		}
		s.profiles[name] = &Profile{
			Name:           name,
			Username:       raw.Username,
			PasswordSecret: raw.PasswordSecret,
			RequiresResave: raw.RequiresResave ||
				(raw.Password != "" && raw.PasswordSecret == "") ||
				raw.PasswordSecret == "",
		}
	}
	return nil
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0700); err != nil {
		return err
	}
	profiles := make(map[string]*diskProfile, len(s.profiles))
	for name, profile := range s.profiles {
		profiles[name] = &diskProfile{
			Name:           profile.Name,
			Username:       profile.Username,
			PasswordSecret: profile.PasswordSecret,
			RequiresResave: profile.RequiresResave,
		}
	}
	data, err := json.MarshalIndent(storeData{
		Version: currentStoreVersion, Profiles: profiles,
	}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Remove(s.filePath); err != nil && !os.IsNotExist(err) {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, s.filePath)
}

// NewPasswordSecretName returns a unique opaque encrypted-store key.
func NewPasswordSecretName(profileName string) (string, error) {
	name, err := ValidateName(profileName)
	if err != nil {
		return "", err
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate credential secret identity: %w", err)
	}
	sum := sha256.Sum256([]byte(name))
	return "credential-password." + hex.EncodeToString(sum[:8]) + "." +
		hex.EncodeToString(random), nil
}

// SecretStorePath returns the encrypted password-store path.
func (s *Store) SecretStorePath() string {
	if s == nil || s.secrets == nil {
		return ""
	}
	return s.secrets.Path()
}

// ReloadSecrets refreshes encrypted passwords written by the prompt helper.
func (s *Store) ReloadSecrets() error {
	if s == nil || s.secrets == nil {
		return fmt.Errorf("credential password store is unavailable")
	}
	return s.secrets.Reload()
}

// Err reports a credential metadata load failure.
func (s *Store) Err() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadErr
}

// Set encrypts a password and adds or updates a credential profile.
func (s *Store) Set(p *Profile) error {
	if p == nil {
		return fmt.Errorf("credential profile is required")
	}
	name, err := ValidateName(p.Name)
	if err != nil {
		return err
	}
	if p.Password == "" {
		return fmt.Errorf("credential password cannot be empty")
	}
	secretName, err := NewPasswordSecretName(name)
	if err != nil {
		return err
	}
	if err := s.secrets.Set(secretName, p.Password); err != nil {
		return fmt.Errorf("encrypt credential password: %w", err)
	}
	if err := s.SetReference(name, p.Username, secretName); err != nil {
		_ = s.secrets.Delete(secretName)
		return err
	}
	return nil
}

// SetReference commits metadata for a password already written by the local
// prompt helper. The referenced encrypted value must exist.
func (s *Store) SetReference(name, username, secretName string) error {
	name, err := ValidateName(name)
	if err != nil {
		return err
	}
	secretName, err = secretstore.ValidateName(secretName)
	if err != nil {
		return err
	}
	if _, err := s.secrets.Get(secretName); err != nil {
		return fmt.Errorf("resolve encrypted credential password: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return s.loadErr
	}
	old := s.profiles[name]
	next := &Profile{
		Name: name, Username: strings.TrimSpace(username),
		PasswordSecret: secretName,
	}
	s.profiles[name] = next
	if err := s.saveLocked(); err != nil {
		if old == nil {
			delete(s.profiles, name)
		} else {
			s.profiles[name] = old
		}
		return err
	}
	if old != nil && old.PasswordSecret != "" && old.PasswordSecret != secretName {
		_ = s.secrets.Delete(old.PasswordSecret)
	}
	return nil
}

// Get returns a credential profile with its password decrypted in memory.
func (s *Store) Get(name string) (*Profile, error) {
	name, err := ValidateName(name)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	if s.loadErr != nil {
		err := s.loadErr
		s.mu.RUnlock()
		return nil, err
	}
	p, ok := s.profiles[name]
	if !ok {
		s.mu.RUnlock()
		return nil, fmt.Errorf("credential profile %q not found", name)
	}
	copy := *p
	s.mu.RUnlock()
	if copy.RequiresResave || copy.PasswordSecret == "" {
		return nil, fmt.Errorf("%w: credential profile %q is disabled; run save_credential with its name and username",
			ErrLegacyPlaintext, name)
	}
	password, err := s.secrets.Get(copy.PasswordSecret)
	if err != nil {
		return nil, fmt.Errorf("decrypt credential profile %q: %w", name, err)
	}
	copy.Password = password
	return &copy, nil
}

// Delete removes a credential profile and its encrypted password.
func (s *Store) Delete(name string) error {
	name, err := ValidateName(name)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return s.loadErr
	}
	profile, ok := s.profiles[name]
	if !ok {
		return fmt.Errorf("credential profile %q not found", name)
	}
	delete(s.profiles, name)
	if err := s.saveLocked(); err != nil {
		s.profiles[name] = profile
		return err
	}
	if profile.PasswordSecret != "" {
		_ = s.secrets.Delete(profile.PasswordSecret)
	}
	return nil
}

// List returns all profile names.
func (s *Store) List() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.profiles))
	for name := range s.profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ListProfiles returns credential metadata without passwords.
func (s *Store) ListProfiles() []*Profile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	profiles := make([]*Profile, 0, len(s.profiles))
	for _, profile := range s.profiles {
		copy := *profile
		copy.Password = ""
		profiles = append(profiles, &copy)
	}
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Name < profiles[j].Name
	})
	return profiles
}
