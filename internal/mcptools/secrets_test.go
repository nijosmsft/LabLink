package mcptools

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nijosmsft/lablink/internal/secretstore"
)

func TestSaveSecretLaunchesMaskedPromptAndReloadsStore(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "secrets.json")
	absoluteStorePath, err := filepath.Abs(storePath)
	if err != nil {
		t.Fatal(err)
	}
	store := secretstore.Open(storePath)
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"name": "archive"}
	helperPath := `C:\LabLink\bin\lablink-secret.exe`
	launched := false
	launcher := func(_ context.Context, helper, path, name string) error {
		launched = true
		if helper != helperPath || path != absoluteStorePath || name != "archive" {
			t.Fatalf("launch args = %q, %q, %q", helper, path, name)
		}
		return secretstore.Open(path).Set(name, "sensitive-value")
	}
	result, err := saveSecretHandler(store, helperPath, launcher)(context.Background(), req)
	if err != nil || result == nil || result.IsError {
		t.Fatalf("handler = %#v, %v", result, err)
	}
	if !launched {
		t.Fatal("secret prompt was not launched")
	}
	value, err := store.Get("archive")
	if err != nil || value != "sensitive-value" {
		t.Fatalf("reloaded secret = %q, %v", value, err)
	}
}

func TestSaveSecretReturnsPromptFailure(t *testing.T) {
	store := secretstore.Open(filepath.Join(t.TempDir(), "secrets.json"))
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"name": "archive"}
	result, err := saveSecretHandler(store, "lablink-secret", func(context.Context, string, string, string) error {
		return context.Canceled
	})(context.Background(), req)
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("prompt failure result = %#v, %v", result, err)
	}
}

func TestSaveSecretRejectsInvalidName(t *testing.T) {
	store := secretstore.Open(filepath.Join(t.TempDir(), "secrets.json"))
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"name": "bad name"}
	result, err := saveSecretHandler(store, "lablink-secret", nil)(context.Background(), req)
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("invalid name result = %#v, %v", result, err)
	}
}
