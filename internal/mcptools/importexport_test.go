package mcptools

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nijosmsft/lablink/internal/registry"
)

func callImportExportHandler(t *testing.T, handler func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error), filePath string) {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"file": filePath}
	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("handler returned failure: %#v", result)
	}
}

func TestImportExportPreservesTLSServerName(t *testing.T) {
	dir := t.TempDir()
	source := registry.Load(filepath.Join(dir, "source.json"))
	nodes := []*registry.Node{
		{
			Name:          "direct-node",
			Address:       "10.0.0.10:9091",
			Role:          "server",
			Labels:        map[string]string{"site": "west"},
			TLSServerName: "direct-node.lablink",
		},
		{
			Name:          "isolated-guest",
			Address:       "10.0.0.20:23456",
			Role:          "isolated-vm",
			Labels:        map[string]string{"lablink.kind": "isolated-vm", "lablink.relay_id": "relay-1"},
			TLSServerName: "isolated-guest",
		},
	}
	for _, node := range nodes {
		if err := source.SetNode(node); err != nil {
			t.Fatalf("SetNode(%s): %v", node.Name, err)
		}
	}

	exportPath := filepath.Join(dir, "nodes.yaml")
	callImportExportHandler(t, exportNodesHandler(source), exportPath)

	target := registry.Load(filepath.Join(dir, "target.json"))
	callImportExportHandler(t, importNodesHandler(target), exportPath)

	for _, want := range nodes {
		got, ok := target.GetNode(want.Name)
		if !ok {
			t.Fatalf("missing imported node %q", want.Name)
		}
		if got.Address != want.Address {
			t.Errorf("%s address = %q, want %q", want.Name, got.Address, want.Address)
		}
		if got.TLSServerName != want.TLSServerName {
			t.Errorf("%s TLS server name = %q, want %q", want.Name, got.TLSServerName, want.TLSServerName)
		}
		if got.Role != want.Role {
			t.Errorf("%s role = %q, want %q", want.Name, got.Role, want.Role)
		}
		if len(got.Labels) != len(want.Labels) {
			t.Errorf("%s labels = %#v, want %#v", want.Name, got.Labels, want.Labels)
		}
		for key, value := range want.Labels {
			if got.Labels[key] != value {
				t.Errorf("%s label %q = %q, want %q", want.Name, key, got.Labels[key], value)
			}
		}
	}
}

func TestImportLegacyYAMLOmitsTLSServerName(t *testing.T) {
	dir := t.TempDir()
	importPath := filepath.Join(dir, "legacy.yaml")
	legacy := []byte(`nodes:
  legacy-node:
    address: 192.0.2.10:9091
    role: Client
    labels:
      generation: legacy
topologies:
  lab:
    roles:
      client:
        - legacy-node
contexts:
  legacy-node:
    working_dir: C:\work
    env:
      MODE: legacy
`)
	if err := os.WriteFile(importPath, legacy, 0o600); err != nil {
		t.Fatalf("write legacy YAML: %v", err)
	}

	reg := registry.Load(filepath.Join(dir, "nodes.json"))
	callImportExportHandler(t, importNodesHandler(reg), importPath)

	node, ok := reg.GetNode("legacy-node")
	if !ok {
		t.Fatal("legacy node was not imported")
	}
	if node.TLSServerName != "" {
		t.Errorf("legacy TLS server name = %q, want empty", node.TLSServerName)
	}
	if node.Address != "192.0.2.10:9091" || node.Role != "client" || node.Labels["generation"] != "legacy" {
		t.Errorf("legacy node fields changed: %#v", node)
	}
	nodeContext, ok := reg.GetNodeContext("legacy-node")
	if !ok || nodeContext.WorkingDir != `C:\work` || nodeContext.Env["MODE"] != "legacy" {
		t.Errorf("legacy context changed: %#v, present=%v", nodeContext, ok)
	}
	topology, ok := reg.GetTopology("lab")
	if !ok || len(topology.Roles["client"]) != 1 || topology.Roles["client"][0] != "legacy-node" {
		t.Errorf("legacy topology changed: %#v, present=%v", topology, ok)
	}
}

func TestExportOmitsEmptyOptionalNodeFields(t *testing.T) {
	dir := t.TempDir()
	reg := registry.Load(filepath.Join(dir, "nodes.json"))
	if err := reg.SetNode(&registry.Node{Name: "minimal", Address: "192.0.2.20:9091"}); err != nil {
		t.Fatalf("SetNode: %v", err)
	}

	exportPath := filepath.Join(dir, "minimal.yaml")
	callImportExportHandler(t, exportNodesHandler(reg), exportPath)
	data, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	if string(data) != "nodes:\n    minimal:\n        address: 192.0.2.20:9091\n" {
		t.Fatalf("minimal export contains optional fields:\n%s", data)
	}
}
