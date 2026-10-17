//go:build windows

package mcptools

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadSecretPromptStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	if err := os.WriteFile(path, []byte(`{"ok":false,"error":"prompt canceled"}`), 0600); err != nil {
		t.Fatal(err)
	}
	status, err := readSecretPromptStatus(path)
	if err != nil {
		t.Fatal(err)
	}
	if status.OK || status.Error != "prompt canceled" {
		t.Fatalf("status = %#v", status)
	}
}
