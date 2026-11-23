package credentials

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestStoresObserveExternalCredentialChangesWithoutReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	reader, writer := LoadStore(path), LoadStore(path)
	if err := writer.Set(&Profile{Name: "first", Username: "old-user", Password: "old-password"}); err != nil {
		t.Fatal(err)
	}
	names, err := reader.List()
	if err != nil || len(names) != 1 || names[0] != "first" {
		t.Fatalf("new external profile was not listed: %v, %v", names, err)
	}
	if err := writer.Set(&Profile{Name: "first", Username: "new-user", Password: "new-password"}); err != nil {
		t.Fatal(err)
	}
	profile, err := reader.Get("first")
	if err != nil || profile.Username != "new-user" || profile.Password != "new-password" {
		t.Fatal("external credential replacement was not read")
	}
	if err := reader.Set(&Profile{Name: "second", Password: "second-password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Get("second"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Delete("first"); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Get("first"); err == nil {
		t.Fatal("externally deleted credential was cached")
	}
	names, err = reader.List()
	if err != nil || len(names) != 1 || names[0] != "second" {
		t.Fatalf("stale credential names survived: %v, %v", names, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Get("second"); err == nil {
		t.Fatal("deleted metadata file was cached")
	}
}

func TestCredentialReadErrorsDoNotReturnCachedProfilesOrPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store := LoadStore(path)
	if err := store.Set(&Profile{Name: "first", Password: "test-password"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListProfiles(); err == nil {
		t.Fatal("metadata corruption was hidden by a cached list")
	}
	if _, err := store.Get("first"); err == nil {
		t.Fatal("metadata corruption was hidden by a cached credential")
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("first"); err != nil {
		t.Fatalf("repaired metadata requires a restart: %v", err)
	}
}

func TestConcurrentCredentialStoresPreserveEveryWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	const count = 8
	stores := make([]*Store, count)
	for i := range stores {
		stores[i] = LoadStore(path)
	}
	start := make(chan struct{})
	failures := make(chan error, count)
	var workers sync.WaitGroup
	for i, store := range stores {
		workers.Add(1)
		go func(i int, store *Store) {
			defer workers.Done()
			<-start
			failures <- store.Set(&Profile{Name: fmt.Sprintf("profile-%d", i), Password: fmt.Sprintf("test-password-%d", i)})
		}(i, store)
	}
	close(start)
	workers.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := range stores {
		profile, err := stores[0].Get(fmt.Sprintf("profile-%d", i))
		if err != nil || profile.Password != fmt.Sprintf("test-password-%d", i) {
			t.Fatalf("concurrent writer %d was lost: %v", i, err)
		}
	}
}
