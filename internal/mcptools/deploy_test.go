package mcptools

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/secretstore"
)

func TestSaveCredentialSchemaDoesNotAcceptPassword(t *testing.T) {
	s := server.NewMCPServer("test", "1.0")
	RegisterDeploy(
		s, nil, nil,
		credentials.LoadStore(filepath.Join(t.TempDir(), "credentials.json")),
		"token", "helper",
	)
	tool := s.ListTools()["save_credential"]
	if tool == nil {
		t.Fatal("save_credential was not registered")
	}
	properties := tool.Tool.InputSchema.Properties
	if _, ok := properties["password"]; ok {
		t.Fatal("save_credential must not expose a password MCP argument")
	}
	for _, field := range []string{"name", "username"} {
		if _, ok := properties[field]; !ok {
			t.Errorf("save_credential missing %s", field)
		}
	}
}

func TestSaveCredentialUsesMaskedPromptAndEncryptedStore(t *testing.T) {
	store := credentials.LoadStore(filepath.Join(t.TempDir(), "credentials.json"))
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{
		"name": "winrm-admin", "username": `CONTOSO\admin`,
	}
	helperPath := `C:\LabLink\bin\lablink-secret.exe`
	launched := false
	launcher := func(
		_ context.Context,
		helper, path, secretName, credentialName string,
	) error {
		launched = true
		if helper != helperPath || path != store.SecretStorePath() ||
			credentialName != "winrm-admin" ||
			!strings.HasPrefix(secretName, "credential-password.") {
			t.Fatalf("launch args = %q, %q, %q, %q",
				helper, path, secretName, credentialName)
		}
		return secretstore.Open(path).Set(secretName, "prompted-password")
	}
	result, err := saveCredentialHandler(
		store, helperPath, launcher,
	)(context.Background(), req)
	if err != nil || result == nil || result.IsError {
		t.Fatalf("handler = %#v, %v", result, err)
	}
	if !launched {
		t.Fatal("credential prompt was not launched")
	}
	profile, err := store.Get("winrm-admin")
	if err != nil || profile.Username != `CONTOSO\admin` ||
		profile.Password != "prompted-password" {
		t.Fatalf("saved profile = %#v, %v", profile, err)
	}
	if strings.Contains(toolResultText(result), "prompted-password") {
		t.Fatal("password appeared in MCP result")
	}
}

func TestSaveCredentialRejectsPasswordArgument(t *testing.T) {
	store := credentials.LoadStore(filepath.Join(t.TempDir(), "credentials.json"))
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{
		"name": "admin", "username": "admin", "password": "do-not-accept",
	}
	launched := false
	result, err := saveCredentialHandler(
		store, "helper", func(context.Context, string, string, string, string) error {
			launched = true
			return nil
		},
	)(context.Background(), req)
	if err != nil || result == nil || !result.IsError || launched {
		t.Fatalf("handler = %#v, %v, launched=%t", result, err, launched)
	}
	if strings.Contains(toolResultText(result), "do-not-accept") {
		t.Fatal("rejected password appeared in MCP result")
	}
}

func TestPowerShellDeploymentScriptUsesStdinNotCommandLine(t *testing.T) {
	const secret = "command-line-secret"
	cmd := powerShellStdinCommand(context.Background(), "write-output '"+secret+"'")
	if strings.Contains(strings.Join(cmd.Args, " "), secret) {
		t.Fatalf("password appeared in command line: %v", cmd.Args)
	}
	data, err := io.ReadAll(cmd.Stdin)
	if err != nil || !strings.Contains(string(data), secret) {
		t.Fatalf("stdin script = %q, %v", data, err)
	}
}
