package mcptools

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/registry"
	"gopkg.in/yaml.v3"
)

// yamlNode is the YAML-friendly representation of a node.
type yamlNode struct {
	Address string            `yaml:"address"`
	Role    string            `yaml:"role,omitempty"`
	Labels  map[string]string `yaml:"labels,omitempty"`
}

// yamlContext is the YAML-friendly representation of node context.
type yamlContext struct {
	WorkingDir string            `yaml:"working_dir,omitempty"`
	Env        map[string]string `yaml:"env,omitempty"`
}

// yamlTopology is the YAML-friendly representation of a topology.
type yamlTopology struct {
	Roles map[string][]string `yaml:"roles"`
}

// yamlFile is the top-level YAML structure.
type yamlFile struct {
	Nodes      map[string]yamlNode     `yaml:"nodes"`
	Topologies map[string]yamlTopology `yaml:"topologies,omitempty"`
	Contexts   map[string]yamlContext  `yaml:"contexts,omitempty"`
}

func RegisterImportExport(s *server.MCPServer, reg *registry.Registry) {
	addTool(s, 
		mcp.NewTool("export_nodes",
			mcp.WithDescription("Export all nodes, topologies, and contexts to a YAML file."),
			mcp.WithString("file", mcp.Required(), mcp.Description("Output YAML file path")),
		),
		exportNodesHandler(reg),
	)

	addTool(s, 
		mcp.NewTool("import_nodes",
			mcp.WithDescription("Import nodes, topologies, and contexts from a YAML file, overwriting existing entries."),
			mcp.WithString("file", mcp.Required(), mcp.Description("Input YAML file path")),
		),
		importNodesHandler(reg),
	)
}

func exportNodesHandler(reg *registry.Registry) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		filePath := request.GetString("file", "")

		nodes := reg.AllNodes()
		if len(nodes) == 0 {
			return mcp.NewToolResultError("no nodes to export"), nil
		}

		yf := yamlFile{
			Nodes:      make(map[string]yamlNode),
			Topologies: make(map[string]yamlTopology),
			Contexts:   make(map[string]yamlContext),
		}

		for _, n := range nodes {
			yf.Nodes[n.Name] = yamlNode{
				Address: n.Address,
				Role:    n.Role,
				Labels:  n.Labels,
			}

			// Export context if set.
			if nctx, ok := reg.GetNodeContext(n.Name); ok {
				if nctx.WorkingDir != "" || len(nctx.Env) > 0 {
					yf.Contexts[n.Name] = yamlContext{
						WorkingDir: nctx.WorkingDir,
						Env:        nctx.Env,
					}
				}
			}
		}

		// Export topologies.
		for _, name := range reg.AllTopologyNames() {
			if t, ok := reg.GetTopology(name); ok {
				yf.Topologies[name] = yamlTopology{Roles: t.Roles}
			}
		}

		// Remove empty sections.
		if len(yf.Topologies) == 0 {
			yf.Topologies = nil
		}
		if len(yf.Contexts) == 0 {
			yf.Contexts = nil
		}

		data, err := yaml.Marshal(yf)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("marshal: %v", err)), nil
		}

		if err := os.WriteFile(filePath, data, 0644); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("write %s: %v", filePath, err)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("Exported **%d nodes**, **%d topologies**, **%d contexts** to `%s`",
			len(yf.Nodes), len(yf.Topologies), len(yf.Contexts), filePath)), nil
	}
}

func importNodesHandler(reg *registry.Registry) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		filePath := request.GetString("file", "")

		data, err := os.ReadFile(filePath)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("read %s: %v", filePath, err)), nil
		}

		var yf yamlFile
		if err := yaml.Unmarshal(data, &yf); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("parse YAML: %v", err)), nil
		}

		if len(yf.Nodes) == 0 {
			return mcp.NewToolResultError("YAML file contains no nodes"), nil
		}

		var imported, skipped int
		var details strings.Builder

		for name, yn := range yf.Nodes {
			node := &registry.Node{
				Name:    name,
				Address: yn.Address,
				Role:    yn.Role,
				Labels:  yn.Labels,
			}
			if err := reg.SetNode(node); err != nil {
				details.WriteString(fmt.Sprintf("- **%s**: failed (%v)\n", name, err))
				skipped++
				continue
			}
			details.WriteString(fmt.Sprintf("- **%s** (%s, role=%s)\n", name, yn.Address, yn.Role))
			imported++
		}

		// Import contexts.
		ctxCount := 0
		for name, yc := range yf.Contexts {
			if _, ok := reg.GetNode(name); !ok {
				continue
			}
			nctx := &registry.NodeContext{
				WorkingDir: yc.WorkingDir,
				Env:        yc.Env,
			}
			if err := reg.SetNodeContext(name, nctx); err != nil {
				details.WriteString(fmt.Sprintf("- context for **%s**: failed (%v)\n", name, err))
				continue
			}
			ctxCount++
		}

		// Import topologies.
		topoCount := 0
		for name, yt := range yf.Topologies {
			if err := validateTopologyRoles(reg, yt.Roles); err != nil {
				details.WriteString(fmt.Sprintf("- topology **%s**: failed (%v)\n", name, err))
				continue
			}
			t := &registry.Topology{
				Name:  name,
				Roles: yt.Roles,
			}
			if err := reg.SetTopology(t); err != nil {
				details.WriteString(fmt.Sprintf("- topology **%s**: failed (%v)\n", name, err))
				continue
			}
			topoCount++
		}

		result := fmt.Sprintf("Imported **%d nodes**, **%d topologies**, **%d contexts** from `%s`\n\n%s",
			imported, topoCount, ctxCount, filePath, details.String())
		if skipped > 0 {
			result += fmt.Sprintf("\n%d nodes skipped due to errors", skipped)
		}
		return mcp.NewToolResultText(result), nil
	}
}
