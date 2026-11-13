package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRemoveNodePrunesTopologies(t *testing.T) {
	reg := &Registry{
		nodes: map[string]*Node{
			"server": {Name: "server"},
			"client": {Name: "client"},
		},
		topologies: map[string]*Topology{
			"lab": {
				Name: "lab",
				Roles: map[string][]string{
					"server": {"server"},
					"client": {"client"},
				},
			},
		},
		nodeContexts: map[string]*NodeContext{},
		filePath:     t.TempDir() + `\nodes.json`,
	}

	if err := reg.RemoveNode("server"); err != nil {
		t.Fatalf("RemoveNode failed: %v", err)
	}

	topology, ok := reg.GetTopology("lab")
	if !ok {
		t.Fatal("expected topology to remain for other roles")
	}
	if _, ok := topology.Roles["server"]; ok {
		t.Fatalf("expected removed node role to be pruned, got %+v", topology.Roles["server"])
	}
	if got := topology.Roles["client"]; len(got) != 1 || got[0] != "client" {
		t.Fatalf("unexpected remaining client role contents: %+v", got)
	}
}

func TestNodeJSONPersistencePreservesFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.json")
	reg := Load(path)
	lastSeen := time.Date(2026, 11, 11, 22, 30, 0, 0, time.UTC)
	want := &Node{
		Name:          "isolated-guest",
		Address:       "192.0.2.40:23456",
		Role:          "isolated-vm",
		Labels:        map[string]string{"lablink.kind": "isolated-vm", "custom": "preserved"},
		OS:            "windows",
		Arch:          "amd64",
		CPUCount:      8,
		Memory:        16 << 30,
		LastSeen:      lastSeen,
		TransportMode: "mtls",
		TLSServerName: "isolated-guest",
	}
	if err := reg.SetNode(want); err != nil {
		t.Fatalf("SetNode: %v", err)
	}

	reloaded := Load(path)
	got, ok := reloaded.GetNode(want.Name)
	if !ok {
		t.Fatal("persisted node is missing")
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("persisted node = %#v, want %#v", got, want)
	}
}

func TestNodeJSONOmitsEmptyOptionalFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.json")
	reg := Load(path)
	if err := reg.SetNode(&Node{Name: "minimal", Address: "192.0.2.50:9091"}); err != nil {
		t.Fatalf("SetNode: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read nodes.json: %v", err)
	}
	var persisted registryData
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatalf("unmarshal nodes.json: %v", err)
	}
	if persisted.Nodes["minimal"].TLSServerName != "" || persisted.Nodes["minimal"].Labels != nil {
		t.Fatalf("empty optional fields changed after JSON round-trip: %#v", persisted.Nodes["minimal"])
	}
	if strings.Contains(string(data), "tls_server_name") || strings.Contains(string(data), `"labels"`) {
		t.Fatalf("empty optional fields were serialized:\n%s", data)
	}
}

func TestSetNodePreservesLabelsWhenUpdateOmitsThem(t *testing.T) {
	reg := Load(filepath.Join(t.TempDir(), "nodes.json"))
	if err := reg.SetNode(&Node{
		Name: "orchestrator", Address: "192.0.2.10:9091",
		Labels: map[string]string{"lablink.orchestrator_id": "orch-id"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := reg.SetNode(&Node{Name: "orchestrator", Address: "192.0.2.11:9091"}); err != nil {
		t.Fatal(err)
	}
	node, ok := reg.GetNode("orchestrator")
	if !ok || node.Address != "192.0.2.11:9091" ||
		node.Labels["lablink.orchestrator_id"] != "orch-id" {
		t.Fatalf("updated node lost labels: %+v", node)
	}
}

func TestGetNodeReturnsIndependentRoleAndLabels(t *testing.T) {
	reg := Load(filepath.Join(t.TempDir(), "nodes.json"))
	if err := reg.SetNode(&Node{
		Name: "orchestrator", Role: "isolated-orchestrator",
		Labels: map[string]string{"lablink.kind": "isolated-orchestrator"},
	}); err != nil {
		t.Fatal(err)
	}
	node, ok := reg.GetNode("orchestrator")
	if !ok {
		t.Fatal("node missing")
	}
	node.Role = "mutated"
	node.Labels["lablink.kind"] = "mutated"
	persisted, ok := reg.GetNode("orchestrator")
	if !ok || persisted.Role != "isolated-orchestrator" ||
		persisted.Labels["lablink.kind"] != "isolated-orchestrator" {
		t.Fatalf("caller mutated registry-owned node: %+v", persisted)
	}
}
