package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestReloadIfStaleAfterExternalWrite verifies that a SetNode call observes
// changes another process made to nodes.json, instead of clobbering them with
// a stale in-memory snapshot. Simulates the sibling process by writing the
// file directly with a doctored mtime.
func TestReloadIfStaleAfterExternalWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nodes.json")

	r := Load(path)
	if err := r.SetNode(&Node{Name: "alpha", Address: "10.0.0.1:9091"}); err != nil {
		t.Fatalf("SetNode alpha: %v", err)
	}

	// Simulate a sibling LabLinkServer process writing a different node.
	external := registryData{
		Nodes: map[string]*Node{
			"alpha": {Name: "alpha", Address: "10.0.0.1:9091"},
			"beta":  {Name: "beta", Address: "10.0.0.2:9091"},
		},
	}
	data, err := json.MarshalIndent(external, "", "  ")
	if err != nil {
		t.Fatalf("marshal external: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("external write: %v", err)
	}
	// Push mtime forward so reload-if-stale fires regardless of filesystem
	// timestamp granularity.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// Now add a third node through r. If reload-if-stale works, beta survives.
	if err := r.SetNode(&Node{Name: "gamma", Address: "10.0.0.3:9091"}); err != nil {
		t.Fatalf("SetNode gamma: %v", err)
	}

	final := Load(path)
	for _, name := range []string{"alpha", "beta", "gamma"} {
		if _, ok := final.GetNode(name); !ok {
			t.Errorf("expected node %q to survive, got missing", name)
		}
	}
}

// TestConcurrentSetNodeFromSameProcess just exercises the in-process mutex
// under contention; ensures the new lock plumbing didn't deadlock.
func TestConcurrentSetNodeFromSameProcess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nodes.json")
	r := Load(path)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			n := &Node{Name: "n" + string(rune('a'+i)), Address: "10.0.0.1:9091"}
			if err := r.SetNode(n); err != nil {
				t.Errorf("SetNode: %v", err)
			}
		}(i)
	}
	wg.Wait()

	if got := len(r.AllNodes()); got != 20 {
		t.Errorf("expected 20 nodes after concurrent SetNode, got %d", got)
	}
}
