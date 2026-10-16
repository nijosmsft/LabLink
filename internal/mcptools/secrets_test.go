package mcptools

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nijosmsft/lablink/internal/secretstore"
)

func TestSaveSecretReturnsLocalInstructionsWithoutSaving(t *testing.T) {
	storePath := filepath.Join(".testdata", t.Name(), "secrets.json")
	absoluteStorePath, err := filepath.Abs(storePath)
	if err != nil {
		t.Fatal(err)
	}
	store := secretstore.Open(storePath)
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"name": "archive"}
	result, err := saveSecretInstructionsHandler(store, `C:\LabLink\bin\lablink-secret.exe`)(context.Background(), req)
	if err != nil || result == nil || result.IsError {
		t.Fatalf("handler = %#v, %v", result, err)
	}
	text := toolResultText(result)
	for _, want := range []string{
		"was not requested or saved through MCP",
		"lablink-secret.exe",
		"--store",
		absoluteStorePath,
		"masked terminal",
		"`secret_env`",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("instructions missing %q:\n%s", want, text)
		}
	}
	if names, err := store.List(); err != nil || len(names) != 0 {
		t.Fatalf("save instructions mutated store: %v, %v", names, err)
	}
}

func TestFormatSecretCommandQuotesShellMetacharacters(t *testing.T) {
	shell, command := formatSecretCommand(`C:\Program Files\Lab'Link\lablink-secret.exe`, `C:\Users\Test User\secret's.json`, "archive", "windows")
	if shell != "powershell" || command != `& 'C:\Program Files\Lab''Link\lablink-secret.exe' set --store 'C:\Users\Test User\secret''s.json' 'archive'` {
		t.Fatalf("PowerShell command = %q, %q", shell, command)
	}

	shell, command = formatSecretCommand("/opt/lab'link/lablink-secret", "/home/test user/secret's.json", "archive", "linux")
	if shell != "sh" || command != `'/opt/lab'"'"'link/lablink-secret' set --store '/home/test user/secret'"'"'s.json' 'archive'` {
		t.Fatalf("POSIX command = %q, %q", shell, command)
	}
}

func TestSaveSecretRejectsInvalidName(t *testing.T) {
	store := secretstore.Open(filepath.Join(t.TempDir(), "secrets.json"))
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"name": "bad name"}
	result, err := saveSecretInstructionsHandler(store, "lablink-secret")(context.Background(), req)
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("invalid name result = %#v, %v", result, err)
	}
}
