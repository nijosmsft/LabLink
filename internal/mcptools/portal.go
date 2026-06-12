package mcptools

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// portalURL is set once at startup by cmd/lablink-server when the local portal binds.
// Stored as an atomic so the tool handler can read it without a lock and so
// future code can swap it (e.g., portal restart) without races. An empty value
// means the portal is disabled or failed to start.
var portalURL atomic.Value

// SetPortalURL records the bookmarkable portal URL for get_portal_url to
// return. Pass "" to indicate the portal is unavailable.
func SetPortalURL(u string) {
	portalURL.Store(u)
}

func currentPortalURL() string {
	v := portalURL.Load()
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// RegisterPortal exposes get_portal_url so the AI client can hand the operator
// a clickable link to the local operations portal without grepping logs.
func RegisterPortal(s *server.MCPServer) {
	addTool(s, 
		mcp.NewTool("get_portal_url",
			mcp.WithDescription("Return the local LabLink portal URL; empty if portal is disabled."),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			u := currentPortalURL()
			if u == "" {
				return mcp.NewToolResultText("LabLink portal is not running in this process. Set LABLINK_PORTAL=enabled (or unset it) and restart the MCP server. To pin the port, set LABLINK_PORTAL_ADDR=127.0.0.1:9092."), nil
			}
			return mcp.NewToolResultText(fmt.Sprintf("LabLink portal: %s", u)), nil
		},
	)
}
