package secretstore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
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
	mu           sync.RWMutex
	filePath     string
	protector    protector
	protectorErr error
	secrets      map[string]string
	loadErr      error
}

func Open(filePath string) *Store {
	p, err := newProtector(filepath.Dir(filePath))
	s := &Store{
		filePath:     filePath,
		protector:    p,
		protectorErr: err,
		secrets:      map[string]string{},
		loadErr:      err,
	}
	if err != nil {
		return s
	}
	s.loadErr = s.reloadLocked()
	return s
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

// Reload refreshes the in-memory view after another process updates the store.
func (s *Store) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadErr = s.reloadLocked()
	return s.loadErr
}

func (s *Store) Set(name, value string) error {
	name, err := ValidateName(name)
	if err != nil {
		return err
	}
	if value == "" {
		return fmt.Errorf("secret value cannot be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return s.loadErr
	}
	encrypted, err := s.protector.Protect([]byte(value))
	if err != nil {
		return fmt.Errorf("encrypt secret %q: %w", name, err)
	}
	s.secrets[name] = base64.StdEncoding.EncodeToString(encrypted)
	return s.saveLocked()
}

func (s *Store) Get(name string) (string, error) {
	name, err := ValidateName(name)
	if err != nil {
		return "", err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.loadErr != nil {
		return "", s.loadErr
	}
	encoded, ok := s.secrets[name]
	if !ok {
		return "", fmt.Errorf("secret %q not found", name)
	}
	encrypted, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode secret %q: %w", name, err)
	}
	plain, err := s.protector.Unprotect(encrypted)
	if err != nil {
		return "", fmt.Errorf("decrypt secret %q: %w", name, err)
	}
	return string(plain), nil
}

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
	if _, ok := s.secrets[name]; !ok {
		return fmt.Errorf("secret %q not found", name)
	}
	delete(s.secrets, name)
	return s.saveLocked()
}

func (s *Store) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	names := make([]string, 0, len(s.secrets))
	for name := range s.secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (s *Store) reloadLocked() error {
	if s.protectorErr != nil {
		return s.protectorErr
	}
	data, err := os.ReadFile(s.filePath)
	if os.IsNotExist(err) {
		s.secrets = map[string]string{}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read secret store: %w", err)
	}
	var stored storeData
	if err := json.Unmarshal(data, &stored); err != nil {
		return fmt.Errorf("parse secret store: %w", err)
	}
	s.secrets = stored.Secrets
	if s.secrets == nil {
		s.secrets = map[string]string{}
	}
	return nil
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(storeData{Version: 1, Secrets: s.secrets}, "", "  ")
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
