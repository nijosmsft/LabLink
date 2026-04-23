package mcptools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nijosmsft/lablink/internal/healthmon"
	"github.com/nijosmsft/lablink/internal/registry"
)

func TestNodeCallContextAllowsUnknownNodes(t *testing.T) {
	old := hmon
	t.Cleanup(func() { hmon = old })

	reg := registry.Load(filepath.Join(t.TempDir(), "nodes.json"))
	hmon = healthmon.New(reg, nil)

	ctx, cancel := nodeCallContext(context.Background(), "fresh-node")
	defer cancel()

	select {
	case <-ctx.Done():
		t.Fatal("expected unknown node to get a live context")
	default:
	}
}

func TestValidateTopologyRolesRejectsUnknownNodes(t *testing.T) {
	reg := registry.Load(filepath.Join(t.TempDir(), "nodes.json"))
	if err := reg.SetNode(&registry.Node{Name: "server", Address: "127.0.0.1:9091"}); err != nil {
		t.Fatalf("SetNode failed: %v", err)
	}

	if err := validateTopologyRoles(reg, map[string][]string{"server": {"server"}}); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	err := validateTopologyRoles(reg, map[string][]string{"client": {"missing"}})
	if err == nil {
		t.Fatal("expected topology validation to fail")
	}
	if !strings.Contains(err.Error(), `node "missing"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTruncateOutputDoesNotClaimSpillFileOnWriteFailure(t *testing.T) {
	badTemp := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(badTemp, []byte("x"), 0644); err != nil {
		t.Fatalf("failed to create temp-file blocker: %v", err)
	}

	t.Setenv("DEVICE_INTERACTION_OUTPUT_LIMIT", "4")
	t.Setenv("TMP", badTemp)
	t.Setenv("TEMP", badTemp)
	t.Setenv("TMPDIR", badTemp)

	truncated, output, spillPath := truncateOutput("abcdef")
	if !truncated {
		t.Fatal("expected output to be truncated")
	}
	if spillPath != "" {
		t.Fatalf("expected no spill path on write failure, got %q", spillPath)
	}
	if !strings.Contains(output, "could not be saved") {
		t.Fatalf("expected write failure note, got %q", output)
	}
}
