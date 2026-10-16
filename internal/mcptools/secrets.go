package mcptools

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
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
			mcp.WithDescription("Return the local masked-input command for saving or replacing an encrypted arbitrary secret. Secret values are never requested through MCP."),
			mcp.WithString("name", mcp.Required(), mcp.Description("Secret name used by secret_env references")),
		),
		saveSecretInstructionsHandler(store, helperPath),
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

func saveSecretInstructionsHandler(store *secretstore.Store, helperPath string) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name, err := secretstore.ValidateName(req.GetString("name", ""))
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		storePath, err := filepath.Abs(store.Path())
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("resolve secret store path: %v", err)), nil
		}
		shell, command := formatSecretCommand(helperPath, storePath, name, runtime.GOOS)
		return mcp.NewToolResultText(fmt.Sprintf(
			"**Secret `%s` was not requested or saved through MCP.**\n\n"+
				"MCP form elicitation must not collect sensitive values. Run this command locally as the same OS account that runs LabLink; it reads and confirms the value through a masked terminal:\n\n```%s\n%s\n```\n\n"+
				"After it succeeds, use the secret name through `secret_env`.",
			name, shell, command,
		)), nil
	}
}

func formatSecretCommand(helperPath, storePath, name, goos string) (string, string) {
	if goos == "windows" {
		return "powershell", fmt.Sprintf("& %s set --store %s %s",
			quotePowerShell(helperPath), quotePowerShell(storePath), quotePowerShell(name))
	}
	return "sh", fmt.Sprintf("%s set --store %s %s",
		quotePOSIXShell(helperPath), quotePOSIXShell(storePath), quotePOSIXShell(name))
}

func quotePowerShell(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func quotePOSIXShell(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
