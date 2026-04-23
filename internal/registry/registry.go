package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// normalizeRole returns a canonical (lowercase, trimmed) role name. Roles are
// always compared case-insensitively so that "Client", "client", and "CLIENT"
// all resolve to the same bucket.
func normalizeRole(role string) string {
	return strings.ToLower(strings.TrimSpace(role))
}

// Node represents a registered test machine.
type Node struct {
	Name          string            `json:"name"`
	Address       string            `json:"address"`
	Role          string            `json:"role,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	OS            string            `json:"os,omitempty"`
	Arch          string            `json:"arch,omitempty"`
	CPUCount      int               `json:"cpu_count,omitempty"`
	Memory        int64             `json:"memory_bytes,omitempty"`
	LastSeen      time.Time         `json:"last_seen,omitempty"`
	TransportMode string            `json:"transport_mode,omitempty"`
	TLSServerName string            `json:"tls_server_name,omitempty"`
}

// NodeContext stores persistent per-node defaults.
type NodeContext struct {
	WorkingDir string            `json:"working_dir,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
}

// Topology is a named group of nodes with role assignments.
type Topology struct {
	Name  string              `json:"name"`
	Roles map[string][]string `json:"roles"` // role -> list of node names
}

// registryData is the JSON-serialized form.
type registryData struct {
	Nodes        map[string]*Node        `json:"nodes"`
	Topologies   map[string]*Topology    `json:"topologies,omitempty"`
	NodeContexts map[string]*NodeContext `json:"node_contexts,omitempty"`
}

// Registry manages nodes, topologies, and contexts with JSON persistence.
type Registry struct {
	mu           sync.RWMutex
	nodes        map[string]*Node
	topologies   map[string]*Topology
	nodeContexts map[string]*NodeContext
	filePath     string
}

// Load reads the registry from a JSON file, or creates an empty one.
func Load(filePath string) *Registry {
	r := &Registry{
		nodes:        make(map[string]*Node),
		topologies:   make(map[string]*Topology),
		nodeContexts: make(map[string]*NodeContext),
		filePath:     filePath,
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return r
	}

	var d registryData
	if err := json.Unmarshal(data, &d); err != nil {
		return r
	}

	if d.Nodes != nil {
		for _, n := range d.Nodes {
			n.Role = normalizeRole(n.Role)
		}
		r.nodes = d.Nodes
	}
	if d.Topologies != nil {
		for _, t := range d.Topologies {
			if t.Roles == nil {
				continue
			}
			normalized := make(map[string][]string, len(t.Roles))
			for role, names := range t.Roles {
				normalized[normalizeRole(role)] = names
			}
			t.Roles = normalized
		}
		r.topologies = d.Topologies
	}
	if d.NodeContexts != nil {
		r.nodeContexts = d.NodeContexts
	}
	return r
}

// Save persists the registry to disk.
func (r *Registry) Save() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.saveLocked()
}

func (r *Registry) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(r.filePath), 0755); err != nil {
		return err
	}
	d := registryData{
		Nodes:        r.nodes,
		Topologies:   r.topologies,
		NodeContexts: r.nodeContexts,
	}
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.filePath, data, 0644)
}

// SetNode adds or updates a node.
func (r *Registry) SetNode(n *Node) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n.Role = normalizeRole(n.Role)
	r.nodes[n.Name] = n
	return r.saveLocked()
}

// GetNode returns a node by name.
func (r *Registry) GetNode(name string) (*Node, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n, ok := r.nodes[name]
	return n, ok
}

// RenameNode renames a node, updating all references in contexts and topologies.
func (r *Registry) RenameNode(oldName, newName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	node, ok := r.nodes[oldName]
	if !ok {
		return fmt.Errorf("node %q not found", oldName)
	}

	// Update node.
	node.Name = newName
	r.nodes[newName] = node
	delete(r.nodes, oldName)

	// Update context.
	if ctx, ok := r.nodeContexts[oldName]; ok {
		r.nodeContexts[newName] = ctx
		delete(r.nodeContexts, oldName)
	}

	// Update topology references.
	for _, t := range r.topologies {
		for role, names := range t.Roles {
			for i, n := range names {
				if n == oldName {
					t.Roles[role][i] = newName
				}
			}
		}
	}

	return r.saveLocked()
}

// RemoveNode deletes a node by name.
func (r *Registry) RemoveNode(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.nodes, name)
	delete(r.nodeContexts, name)

	for topologyName, topology := range r.topologies {
		for role, names := range topology.Roles {
			filtered := names[:0]
			for _, nodeName := range names {
				if nodeName != name {
					filtered = append(filtered, nodeName)
				}
			}
			if len(filtered) == 0 {
				delete(topology.Roles, role)
				continue
			}
			topology.Roles[role] = filtered
		}
		if len(topology.Roles) == 0 {
			delete(r.topologies, topologyName)
		}
	}

	return r.saveLocked()
}

// AllNodes returns a copy of all nodes.
func (r *Registry) AllNodes() []*Node {
	r.mu.RLock()
	defer r.mu.RUnlock()
	nodes := make([]*Node, 0, len(r.nodes))
	for _, n := range r.nodes {
		nodes = append(nodes, n)
	}
	return nodes
}

// NodesByRole returns all nodes with the given role. Comparison is case-insensitive.
func (r *Registry) NodesByRole(role string) []*Node {
	r.mu.RLock()
	defer r.mu.RUnlock()
	target := normalizeRole(role)
	var nodes []*Node
	for _, n := range r.nodes {
		if n.Role == target {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

// AllTopologyNames returns the names of all topologies.
func (r *Registry) AllTopologyNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.topologies))
	for n := range r.topologies {
		names = append(names, n)
	}
	return names
}

// SetTopology adds or updates a topology.
func (r *Registry) SetTopology(t *Topology) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t.Roles != nil {
		normalized := make(map[string][]string, len(t.Roles))
		for role, names := range t.Roles {
			normalized[normalizeRole(role)] = names
		}
		t.Roles = normalized
	}
	r.topologies[t.Name] = t
	return r.saveLocked()
}

// GetTopology returns a topology by name.
func (r *Registry) GetTopology(name string) (*Topology, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.topologies[name]
	return t, ok
}

// NodesForTopologyRole returns nodes for a specific role in a topology. Role comparison is case-insensitive.
func (r *Registry) NodesForTopologyRole(topologyName, role string) []*Node {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.topologies[topologyName]
	if !ok {
		return nil
	}
	names, ok := t.Roles[normalizeRole(role)]
	if !ok {
		return nil
	}
	var nodes []*Node
	for _, name := range names {
		if n, ok := r.nodes[name]; ok {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

// SetNodeContext sets persistent defaults for a node.
func (r *Registry) SetNodeContext(name string, ctx *NodeContext) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nodeContexts[name] = ctx
	return r.saveLocked()
}

// GetNodeContext returns the persistent context for a node.
func (r *Registry) GetNodeContext(name string) (*NodeContext, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ctx, ok := r.nodeContexts[name]
	return ctx, ok
}
