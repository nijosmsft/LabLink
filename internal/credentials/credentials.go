package credentials

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Profile stores a named credential.
type Profile struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Store manages named credential profiles with JSON persistence.
type Store struct {
	mu       sync.RWMutex
	profiles map[string]*Profile
	filePath string
}

type storeData struct {
	Profiles map[string]*Profile `json:"profiles"`
}

// LoadStore reads the credential store from disk.
func LoadStore(filePath string) *Store {
	s := &Store{
		profiles: make(map[string]*Profile),
		filePath: filePath,
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return s
	}
	var d storeData
	if err := json.Unmarshal(data, &d); err != nil {
		return s
	}
	if d.Profiles != nil {
		s.profiles = d.Profiles
	}
	return s
}

func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0700); err != nil {
		return err
	}
	d := storeData{Profiles: s.profiles}
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.filePath, data, 0600)
}

// Set adds or updates a credential profile.
func (s *Store) Set(p *Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.profiles[p.Name] = p
	return s.save()
}

// Get returns a credential profile by name.
func (s *Store) Get(name string) (*Profile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.profiles[name]
	if !ok {
		return nil, fmt.Errorf("credential profile %q not found", name)
	}
	return p, nil
}

// Delete removes a credential profile.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.profiles, name)
	return s.save()
}

// List returns all profile names.
func (s *Store) List() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.profiles))
	for n := range s.profiles {
		names = append(names, n)
	}
	return names
}
