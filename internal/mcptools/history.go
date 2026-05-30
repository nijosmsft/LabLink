package mcptools

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/audit"
)

func RegisterHistory(s *server.MCPServer, auditLog *audit.Log) {
	addTool(s, 
		mcp.NewTool("get_history",
			mcp.WithDescription("Query the command audit log. Useful to recall what was previously executed."),
			mcp.WithString("node", mcp.Description("Filter by node name")),
			mcp.WithString("command_filter", mcp.Description("Filter by command substring")),
			mcp.WithNumber("last_n", mcp.Description("Return only the last N entries (default 20)")),
		),
		getHistoryHandler(auditLog),
	)
}

func getHistoryHandler(auditLog *audit.Log) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		node := request.GetString("node", "")
		commandFilter := request.GetString("command_filter", "")
		lastN := request.GetInt("last_n", 20)

		entries, err := auditLog.Query(node, commandFilter, lastN)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("query history: %v", err)), nil
		}

		if len(entries) == 0 {
			return mcp.NewToolResultText("No history entries found."), nil
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("**Command history** (%d entries)\n\n", len(entries)))
		sb.WriteString("| Time | Node | Tool | Command | Exit | Duration | Size |\n")
		sb.WriteString("|------|------|------|---------|------|----------|------|\n")
		for _, e := range entries {
			cmd := e.Command
			if len(cmd) > 60 {
				cmd = cmd[:57] + "..."
			}
			truncMark := ""
			if e.Truncated {
				truncMark = " (T)"
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %d | %dms | %s%s |\n",
				e.Timestamp.Format("15:04:05"),
				e.Node, e.Tool, cmd, e.ExitCode, e.DurationMs,
				formatBytes(int64(e.OutputBytes)), truncMark))
		}
		return mcp.NewToolResultText(sb.String()), nil
	}
}
