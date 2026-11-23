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
	"unicode"

	"github.com/nijosmsft/lablink/internal/flock"
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
	profiles   map[string]*Profile
	filePath   string
	secretPath string
	transient  bool
}

// NewTransient returns a read-only, request-scoped credential store. Passwords
// received on an authenticated VM-management channel never reach disk.
func NewTransient(profiles []*Profile) (*Store, error) {
	s := &Store{profiles: make(map[string]*Profile), transient: true}
	for _, profile := range profiles {
		if profile == nil {
			return nil, fmt.Errorf("credential profile is required")
		}
		name, err := ValidateName(profile.Name)
		if err != nil {
			return nil, err
		}
		if profile.Password == "" {
			return nil, fmt.Errorf("credential %q has an empty password", name)
		}
		if profile.Username != "" {
			if _, err := ValidateUsername(profile.Username); err != nil {
				return nil, err
			}
		}
		if _, exists := s.profiles[name]; exists {
			return nil, fmt.Errorf("duplicate credential %q", name)
		}
		s.profiles[name] = &Profile{Name: name, Username: profile.Username, Password: profile.Password}
	}
	return s, nil
}

// LoadStore opens a disk-backed store without caching credentials. Each
// operation reads the metadata and any requested password directly from disk.
func LoadStore(filePath string, encrypted ...*secretstore.Store) *Store {
	secretPath := filepath.Join(filepath.Dir(filePath), "credential-secrets.json")
	if len(encrypted) > 0 && encrypted[0] != nil {
		secretPath = encrypted[0].Path()
	}
	return &Store{
		filePath:   filePath,
		secretPath: secretPath,
	}
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

func (s *Store) lock() (*flock.Locker, error) {
	if s.transient {
		return nil, nil
	}
	if s.filePath == "" {
		return nil, fmt.Errorf("credential metadata path is required")
	}
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0700); err != nil {
		return nil, err
	}
	return flock.Lock(s.filePath + ".lock")
}

func (s *Store) load() (map[string]*Profile, error) {
	if s.transient {
		return s.profiles, nil
	}
	profiles := make(map[string]*Profile)
	data, err := os.ReadFile(s.filePath)
	if os.IsNotExist(err) {
		return profiles, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read credential metadata: %w", err)
	}
	var stored storeData
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("parse credential metadata: %w", err)
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
		profiles[name] = &Profile{
			Name:           name,
			Username:       raw.Username,
			PasswordSecret: raw.PasswordSecret,
			RequiresResave: raw.RequiresResave ||
				(raw.Password != "" && raw.PasswordSecret == "") ||
				raw.PasswordSecret == "",
		}
	}
	return profiles, nil
}

func (s *Store) saveLocked(values map[string]*Profile) error {
	profiles := make(map[string]*diskProfile, len(values))
	for name, profile := range values {
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
	defer os.Remove(tmp)
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
	if s == nil {
		return ""
	}
	return s.secretPath
}

// ReloadSecrets validates the encrypted password store. Reads never use a cache.
func (s *Store) ReloadSecrets() error {
	if s == nil || s.secretPath == "" {
		return fmt.Errorf("credential password store is unavailable")
	}
	return secretstore.Open(s.secretPath).Reload()
}

// Err reports a current credential metadata read failure.
func (s *Store) Err() error {
	lock, err := s.lock()
	if err != nil {
		return err
	}
	defer lock.Close()
	_, err = s.load()
	return err
}

// Set encrypts a password and adds or updates a credential profile.
func (s *Store) Set(p *Profile) error {
	if s.transient {
		return fmt.Errorf("request-scoped credential store is read-only")
	}
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
	secrets := secretstore.Open(s.secretPath)
	if err := secrets.Set(secretName, p.Password); err != nil {
		return fmt.Errorf("encrypt credential password: %w", err)
	}
	if err := s.SetReference(name, p.Username, secretName); err != nil {
		_ = secrets.Delete(secretName)
		return err
	}
	return nil
}

// SetReference commits metadata for a password already written by the local
// prompt helper. The referenced encrypted value must exist.
func (s *Store) SetReference(name, username, secretName string) error {
	if s.transient {
		return fmt.Errorf("request-scoped credential store is read-only")
	}
	name, err := ValidateName(name)
	if err != nil {
		return err
	}
	secretName, err = secretstore.ValidateName(secretName)
	if err != nil {
		return err
	}
	lock, err := s.lock()
	if err != nil {
		return err
	}
	defer lock.Close()
	profiles, err := s.load()
	if err != nil {
		return err
	}
	secrets := secretstore.Open(s.secretPath)
	if _, err := secrets.Get(secretName); err != nil {
		return fmt.Errorf("resolve encrypted credential password: %w", err)
	}

	old := profiles[name]
	next := &Profile{
		Name: name, Username: strings.TrimSpace(username),
		PasswordSecret: secretName,
	}
	profiles[name] = next
	if err := s.saveLocked(profiles); err != nil {
		return err
	}
	if old != nil && old.PasswordSecret != "" && old.PasswordSecret != secretName {
		_ = secrets.Delete(old.PasswordSecret)
	}
	return nil
}

// Get returns a credential profile with its password decrypted in memory.
func (s *Store) Get(name string) (*Profile, error) {
	name, err := ValidateName(name)
	if err != nil {
		return nil, err
	}
	lock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	profiles, err := s.load()
	if err != nil {
		return nil, err
	}
	p, ok := profiles[name]
	if !ok {
		return nil, fmt.Errorf("credential profile %q not found", name)
	}
	copy := *p
	if s.transient {
		return &copy, nil
	}
	if copy.RequiresResave || copy.PasswordSecret == "" {
		return nil, fmt.Errorf("%w: credential profile %q is disabled; run save_credential with its name and username",
			ErrLegacyPlaintext, name)
	}
	password, err := secretstore.Open(s.secretPath).Get(copy.PasswordSecret)
	if err != nil {
		return nil, fmt.Errorf("decrypt credential profile %q: %w", name, err)
	}
	copy.Password = password
	return &copy, nil
}

// Delete removes a credential profile and its encrypted password.
func (s *Store) Delete(name string) error {
	if s.transient {
		return fmt.Errorf("request-scoped credential store is read-only")
	}
	name, err := ValidateName(name)
	if err != nil {
		return err
	}
	lock, err := s.lock()
	if err != nil {
		return err
	}
	defer lock.Close()
	profiles, err := s.load()
	if err != nil {
		return err
	}
	profile, ok := profiles[name]
	if !ok {
		return fmt.Errorf("credential profile %q not found", name)
	}
	delete(profiles, name)
	if err := s.saveLocked(profiles); err != nil {
		return err
	}
	if profile.PasswordSecret != "" {
		_ = secretstore.Open(s.secretPath).Delete(profile.PasswordSecret)
	}
	return nil
}

// List returns all profile names.
func (s *Store) List() ([]string, error) {
	profiles, err := s.ListProfiles()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		name := profile.Name
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// ListProfiles returns credential metadata without passwords.
func (s *Store) ListProfiles() ([]*Profile, error) {
	lock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	values, err := s.load()
	if err != nil {
		return nil, err
	}
	profiles := make([]*Profile, 0, len(values))
	for _, profile := range values {
		copy := *profile
		copy.Password = ""
		profiles = append(profiles, &copy)
	}
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Name < profiles[j].Name
	})
	return profiles, nil
}
