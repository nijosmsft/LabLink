package secretstore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nijosmsft/lablink/internal/flock"
)

type protector interface {
	Protect([]byte) ([]byte, error)
	Unprotect([]byte) ([]byte, error)
}

type storeData struct {
	Version int               `json:"version"`
	Secrets map[string]string `json:"secrets"`
}

// Store persists arbitrary named secrets encrypted at rest.
type Store struct {
	filePath string
}

func Open(filePath string) *Store {
	return &Store{filePath: filePath}
}

// Path returns the encrypted store file used by this Store.
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.filePath
}

func ValidateName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("secret name is required")
	}
	for _, r := range name {
		if !(r == '-' || r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return "", fmt.Errorf("secret name %q contains invalid character %q", name, r)
		}
	}
	return name, nil
}

// Reload validates the current disk contents. Every operation already reads
// directly from disk; neither encrypted nor decrypted values are cached.
func (s *Store) Reload() error {
	_, err := s.List()
	return err
}

func (s *Store) Set(name, value string) error {
	name, err := ValidateName(name)
	if err != nil {
		return err
	}
	if value == "" {
		return fmt.Errorf("secret value cannot be empty")
	}
	lock, err := s.lock()
	if err != nil {
		return err
	}
	defer lock.Close()
	values, err := s.load()
	if err != nil {
		return err
	}
	p, err := newProtector(filepath.Dir(s.filePath))
	if err != nil {
		return err
	}
	encrypted, err := p.Protect([]byte(value))
	if err != nil {
		return fmt.Errorf("encrypt secret %q: %w", name, err)
	}
	values[name] = base64.StdEncoding.EncodeToString(encrypted)
	return s.saveLocked(values)
}

func (s *Store) Get(name string) (string, error) {
	name, err := ValidateName(name)
	if err != nil {
		return "", err
	}
	lock, err := s.lock()
	if err != nil {
		return "", err
	}
	defer lock.Close()
	values, err := s.load()
	if err != nil {
		return "", err
	}
	encoded, ok := values[name]
	if !ok {
		return "", fmt.Errorf("secret %q not found", name)
	}
	encrypted, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode secret %q: %w", name, err)
	}
	p, err := newProtector(filepath.Dir(s.filePath))
	if err != nil {
		return "", err
	}
	plain, err := p.Unprotect(encrypted)
	if err != nil {
		return "", fmt.Errorf("decrypt secret %q: %w", name, err)
	}
	defer clear(plain)
	return string(plain), nil
}

func (s *Store) Delete(name string) error {
	name, err := ValidateName(name)
	if err != nil {
		return err
	}
	lock, err := s.lock()
	if err != nil {
		return err
	}
	defer lock.Close()
	values, err := s.load()
	if err != nil {
		return err
	}
	if _, ok := values[name]; !ok {
		return fmt.Errorf("secret %q not found", name)
	}
	delete(values, name)
	return s.saveLocked(values)
}

func (s *Store) List() ([]string, error) {
	lock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	values, err := s.load()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (s *Store) lock() (*flock.Locker, error) {
	if s.filePath == "" {
		return nil, fmt.Errorf("secret store path is required")
	}
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0700); err != nil {
		return nil, err
	}
	return flock.Lock(s.filePath + ".lock")
}

func (s *Store) load() (map[string]string, error) {
	data, err := os.ReadFile(s.filePath)
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read secret store: %w", err)
	}
	var stored storeData
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("parse secret store: %w", err)
	}
	if stored.Secrets == nil {
		stored.Secrets = map[string]string{}
	}
	return stored.Secrets, nil
}

func (s *Store) saveLocked(values map[string]string) error {
	data, err := json.MarshalIndent(storeData{Version: 1, Secrets: values}, "", "  ")
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
