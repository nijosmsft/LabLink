package secretstore

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestStoresReadCurrentSecretsAndPreserveUnrelatedWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.json")
	first, second := Open(path), Open(path)
	if err := first.Set("first", "initial"); err != nil {
		t.Fatal(err)
	}
	if err := second.Set("second", "other"); err != nil {
		t.Fatal(err)
	}
	if value, err := first.Get("second"); err != nil || value != "other" {
		t.Fatal("external secret addition was not read")
	}
	if err := second.Set("first", "replacement"); err != nil {
		t.Fatal(err)
	}
	if value, err := first.Get("first"); err != nil || value != "replacement" {
		t.Fatal("external replacement was not read")
	}
	if err := second.Delete("first"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Get("first"); err == nil {
		t.Fatal("deleted secret was cached")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Get("second"); err == nil {
		t.Fatal("corrupt store returned a cached secret")
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if value, err := first.Get("second"); err != nil || value != "other" {
		t.Fatalf("restored store requires reload: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Get("second"); err == nil {
		t.Fatal("deleted secret file was cached")
	}
}

func TestConcurrentStoresShareEncryptionKeyAcrossFiles(t *testing.T) {
	root := t.TempDir()
	const count = 8
	stores := make([]*Store, count)
	for i := range stores {
		stores[i] = Open(filepath.Join(root, fmt.Sprintf("secrets-%d.json", i)))
	}
	start := make(chan struct{})
	failures := make(chan error, count)
	var workers sync.WaitGroup
	for i, store := range stores {
		workers.Add(1)
		go func(i int, store *Store) {
			defer workers.Done()
			<-start
			failures <- store.Set("test", fmt.Sprintf("test-value-%d", i))
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
	for i, store := range stores {
		if value, err := Open(store.Path()).Get("test"); err != nil || value != fmt.Sprintf("test-value-%d", i) {
			t.Fatalf("concurrent encryption key creation lost writer %d: %v", i, err)
		}
	}
}
