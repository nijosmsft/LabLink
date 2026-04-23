package registry

import "testing"

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
