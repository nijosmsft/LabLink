package mcptools

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/secretstore"
)

// RegisterSecrets exposes secret metadata and safe local-ingestion guidance.
// Secret values never appear in MCP requests, results, ops, or audit logs.
func RegisterSecrets(s *server.MCPServer, store *secretstore.Store, helperPath string) {
	s.AddTool(
		mcp.NewTool("save_secret",
			mcp.WithDescription("Open a local masked terminal prompt to save or replace an encrypted arbitrary secret. Secret values never pass through MCP."),
			mcp.WithString("name", mcp.Required(), mcp.Description("Secret name used by secret_env references")),
		),
		saveSecretHandler(store, helperPath, launchSecretPrompt),
	)

	s.AddTool(
		mcp.NewTool("list_secrets",
			mcp.WithDescription("List saved arbitrary secret names. Values are never returned."),
		),
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			names, err := store.List()
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if len(names) == 0 {
				return mcp.NewToolResultText("No arbitrary secrets are saved."), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "**Saved secrets** (%d)\n\n", len(names))
			for _, name := range names {
				fmt.Fprintf(&b, "- `%s`\n", name)
			}
			return mcp.NewToolResultText(b.String()), nil
		},
	)

	s.AddTool(
		mcp.NewTool("delete_secret",
			mcp.WithDescription("Delete a saved arbitrary secret."),
			mcp.WithString("name", mcp.Required(), mcp.Description("Secret name")),
		),
		func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			name := req.GetString("name", "")
			if err := store.Delete(name); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return mcp.NewToolResultText(fmt.Sprintf("Secret `%s` deleted.", name)), nil
		},
	)
}

type secretPromptLauncher func(context.Context, string, string, string) error

func saveSecretHandler(store *secretstore.Store, helperPath string, launch secretPromptLauncher) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name, err := secretstore.ValidateName(req.GetString("name", ""))
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		storePath, err := filepath.Abs(store.Path())
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("resolve secret store path: %v", err)), nil
		}
		if err := launch(ctx, helperPath, storePath, name); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("secret prompt failed: %v", err)), nil
		}
		if err := store.Reload(); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("reload secret store after prompt: %v", err)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf(
			"Secret `%s` saved securely through a local masked terminal. The value did not pass through MCP.",
			name,
		)), nil
	}
}
