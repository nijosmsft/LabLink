package mcptools

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/secretstore"
)

// RegisterSecrets exposes secret metadata and an elicitation-only write path.
// Secret values never appear in tool arguments, results, ops, or audit logs.
func RegisterSecrets(s *server.MCPServer, store *secretstore.Store) {
	s.AddTool(
		mcp.NewTool("save_secret",
			mcp.WithDescription("Save or replace an encrypted arbitrary secret. The value is requested through MCP elicitation and is never accepted as a tool argument or returned."),
			mcp.WithString("name", mcp.Required(), mcp.Description("Secret name used by secret_env references")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			name := strings.TrimSpace(req.GetString("name", ""))
			result, err := s.RequestElicitation(ctx, mcp.ElicitationRequest{
				Params: mcp.ElicitationParams{
					Message: fmt.Sprintf("Enter the value for LabLink secret %q. It will be encrypted locally and never returned.", name),
					RequestedSchema: map[string]any{
						"type": "object",
						"properties": map[string]any{
							"value": map[string]any{
								"type":        "string",
								"title":       "Secret value",
								"description": "Sensitive value; do not include it in any other field.",
								"format":      "password",
							},
						},
						"required":             []string{"value"},
						"additionalProperties": false,
					},
				},
			})
			if err != nil {
				if errors.Is(err, server.ErrElicitationNotSupported) {
					return mcp.NewToolResultError("the MCP client does not support secure secret elicitation"), nil
				}
				return mcp.NewToolResultError(fmt.Sprintf("secret elicitation failed: %v", err)), nil
			}
			if result.Action != mcp.ElicitationResponseActionAccept {
				return mcp.NewToolResultError("secret save cancelled or declined"), nil
			}
			content, ok := result.Content.(map[string]any)
			if !ok {
				return mcp.NewToolResultError("secret elicitation returned invalid content"), nil
			}
			value, _ := content["value"].(string)
			if err := store.Set(name, value); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return mcp.NewToolResultText(fmt.Sprintf("Secret `%s` saved securely.", name)), nil
		},
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
