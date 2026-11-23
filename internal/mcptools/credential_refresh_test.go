package mcptools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nijosmsft/lablink/internal/credentials"
)

func TestCredentialListingObservesAnotherSessionWithoutRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	handler := listCredentialsHandler(credentials.LoadStore(path))
	request := mcp.CallToolRequest{}
	result, err := handler(context.Background(), request)
	if err != nil || result.IsError || !strings.Contains(toolResultText(result), "No credential profiles") {
		t.Fatal("fresh store was not empty")
	}
	writer := credentials.LoadStore(path)
	if err := writer.Set(&credentials.Profile{Name: "other-session", Username: "operator", Password: "never-return-this-password"}); err != nil {
		t.Fatal(err)
	}
	result, err = handler(context.Background(), request)
	if err != nil || result.IsError || !strings.Contains(toolResultText(result), "other-session") ||
		strings.Contains(toolResultText(result), "never-return-this-password") {
		t.Fatal("running handler did not safely list the externally created profile")
	}
	if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err = handler(context.Background(), request)
	if err != nil || !result.IsError || !strings.Contains(toolResultText(result), "load credential metadata") {
		t.Fatal("metadata read failure was reported as an empty credential list")
	}
}
