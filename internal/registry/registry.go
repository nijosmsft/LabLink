package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nijosmsft/lablink/internal/flock"
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
//
// Multiple LabLinkServer processes may share the same nodes.json (one per AI
// client session). To prevent silent last-writer-wins clobber, every
// read-modify-write cycle is serialised through an OS-level advisory lock on
// a sidecar "<filePath>.lock" file, and in-memory state is reloaded from disk
// whenever the on-disk mtime has moved ahead of what we last loaded.
type Registry struct {
	mu           sync.RWMutex
	nodes        map[string]*Node
	topologies   map[string]*Topology
	nodeContexts map[string]*NodeContext
	filePath     string
	loadedMtime  time.Time
}

// Load reads the registry from a JSON file, or creates an empty one.
func Load(filePath string) *Registry {
	r := &Registry{
		nodes:        make(map[string]*Node),
		topologies:   make(map[string]*Topology),
		nodeContexts: make(map[string]*NodeContext),
		filePath:     filePath,
	}
	r.reloadFromDiskLocked()
	return r
}

// reloadFromDiskLocked replaces in-memory state with whatever is on disk and
// records the file mtime that produced it. Safe to call with no file present
// (yields empty maps and a zero mtime). Callers must hold r.mu for write.
func (r *Registry) reloadFromDiskLocked() {
	r.nodes = make(map[string]*Node)
	r.topologies = make(map[string]*Topology)
	r.nodeContexts = make(map[string]*NodeContext)
	r.loadedMtime = time.Time{}

	info, err := os.Stat(r.filePath)
	if err != nil {
		return
	}
	data, err := os.ReadFile(r.filePath)
	if err != nil {
		return
	}
	var d registryData
	if err := json.Unmarshal(data, &d); err != nil {
		return
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
	r.loadedMtime = info.ModTime()
}

// reloadIfStaleLocked refreshes in-memory state when another process has
// written to nodes.json since we last loaded. Caller must hold r.mu for write.
func (r *Registry) reloadIfStaleLocked() {
	info, err := os.Stat(r.filePath)
	if err != nil {
		// File gone: only reset if we previously had loaded something.
		if !r.loadedMtime.IsZero() {
			r.reloadFromDiskLocked()
		}
		return
	}
	if info.ModTime().After(r.loadedMtime) {
		r.reloadFromDiskLocked()
	}
}

// withWriteLock serialises a read-modify-write across processes. It acquires
// an OS-level advisory lock on <filePath>.lock, reloads in-memory state if
// the on-disk file has moved on, runs fn (which mutates the maps), then
// writes the merged state back atomically. r.mu is held for write across the
// entire critical section so concurrent in-process readers see a consistent
// view.
func (r *Registry) withWriteLock(fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(r.filePath), 0755); err != nil {
		return err
	}
	lk, err := flock.Lock(r.filePath + ".lock")
	if err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}
	defer lk.Close()

	r.mu.Lock()
	defer r.mu.Unlock()

	r.reloadIfStaleLocked()

	if err := fn(); err != nil {
		return err
	}
	return r.saveAtomicLocked()
}

// withReadLock guarantees the caller observes the freshest on-disk state by
// briefly acquiring the cross-process lock and reloading if stale. fn runs
// with r.mu held for read.
func (r *Registry) withReadLock(fn func()) {
	lk, err := flock.Lock(r.filePath + ".lock")
	if err == nil {
		// Best effort: if the lock can't be taken (e.g. read-only fs), we
		// still serve in-memory state. Disk reads racing with another
		// process's atomic rename are safe — they'll just see one or the
		// other consistent file.
		r.mu.Lock()
		r.reloadIfStaleLocked()
		r.mu.Unlock()
		lk.Close()
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn()
}

// saveAtomicLocked writes the in-memory state to "<filePath>.tmp" and then
// renames over <filePath>. On Windows, os.Rename uses MoveFileEx with
// MOVEFILE_REPLACE_EXISTING so the swap is atomic enough that readers always
// see one full version or the other.
func (r *Registry) saveAtomicLocked() error {
	d := registryData{
		Nodes:        r.nodes,
		Topologies:   r.topologies,
		NodeContexts: r.nodeContexts,
	}
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, r.filePath); err != nil {
		os.Remove(tmp)
		return err
	}
	if info, err := os.Stat(r.filePath); err == nil {
		r.loadedMtime = info.ModTime()
	}
	return nil
}

// Save persists the registry to disk. Equivalent to a no-op write under the
// cross-process lock, useful when the caller has mutated state through a path
// that didn't already save.
func (r *Registry) Save() error {
	return r.withWriteLock(func() error { return nil })
}

// SetNode adds or updates a node.
func (r *Registry) SetNode(n *Node) error {
	return r.withWriteLock(func() error {
		n.Role = normalizeRole(n.Role)
		r.nodes[n.Name] = n
		return nil
	})
}

// GetNode returns a node by name.
func (r *Registry) GetNode(name string) (*Node, bool) {
	var (
		node *Node
		ok   bool
	)
	r.withReadLock(func() {
		node, ok = r.nodes[name]
	})
	return node, ok
}

// RenameNode renames a node, updating all references in contexts and topologies.
func (r *Registry) RenameNode(oldName, newName string) error {
	return r.withWriteLock(func() error {
		node, ok := r.nodes[oldName]
		if !ok {
			return fmt.Errorf("node %q not found", oldName)
		}
		node.Name = newName
		r.nodes[newName] = node
		delete(r.nodes, oldName)

		if ctx, ok := r.nodeContexts[oldName]; ok {
			r.nodeContexts[newName] = ctx
			delete(r.nodeContexts, oldName)
		}

		for _, t := range r.topologies {
			for role, names := range t.Roles {
				for i, n := range names {
					if n == oldName {
						t.Roles[role][i] = newName
					}
				}
			}
		}
		return nil
	})
}

// RemoveNode deletes a node by name.
func (r *Registry) RemoveNode(name string) error {
	return r.withWriteLock(func() error {
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
		return nil
	})
}

// AllNodes returns a copy of all nodes.
func (r *Registry) AllNodes() []*Node {
	var nodes []*Node
	r.withReadLock(func() {
		nodes = make([]*Node, 0, len(r.nodes))
		for _, n := range r.nodes {
			nodes = append(nodes, n)
		}
	})
	return nodes
}

// NodesByRole returns all nodes with the given role. Comparison is case-insensitive.
func (r *Registry) NodesByRole(role string) []*Node {
	var nodes []*Node
	target := normalizeRole(role)
	r.withReadLock(func() {
		for _, n := range r.nodes {
			if n.Role == target {
				nodes = append(nodes, n)
			}
		}
	})
	return nodes
}

// AllTopologyNames returns the names of all topologies.
func (r *Registry) AllTopologyNames() []string {
	var names []string
	r.withReadLock(func() {
		names = make([]string, 0, len(r.topologies))
		for n := range r.topologies {
			names = append(names, n)
		}
	})
	return names
}

// SetTopology adds or updates a topology.
func (r *Registry) SetTopology(t *Topology) error {
	return r.withWriteLock(func() error {
		if t.Roles != nil {
			normalized := make(map[string][]string, len(t.Roles))
			for role, names := range t.Roles {
				normalized[normalizeRole(role)] = names
			}
			t.Roles = normalized
		}
		r.topologies[t.Name] = t
		return nil
	})
}

// GetTopology returns a topology by name.
func (r *Registry) GetTopology(name string) (*Topology, bool) {
	var (
		t  *Topology
		ok bool
	)
	r.withReadLock(func() {
		t, ok = r.topologies[name]
	})
	return t, ok
}

// NodesForTopologyRole returns nodes for a specific role in a topology. Role comparison is case-insensitive.
func (r *Registry) NodesForTopologyRole(topologyName, role string) []*Node {
	var nodes []*Node
	target := normalizeRole(role)
	r.withReadLock(func() {
		t, ok := r.topologies[topologyName]
		if !ok {
			return
		}
		names, ok := t.Roles[target]
		if !ok {
			return
		}
		for _, name := range names {
			if n, ok := r.nodes[name]; ok {
				nodes = append(nodes, n)
			}
		}
	})
	return nodes
}

// SetNodeContext sets persistent defaults for a node.
func (r *Registry) SetNodeContext(name string, ctx *NodeContext) error {
	return r.withWriteLock(func() error {
		r.nodeContexts[name] = ctx
		return nil
	})
}

// GetNodeContext returns the persistent context for a node.
func (r *Registry) GetNodeContext(name string) (*NodeContext, bool) {
	var (
		ctx *NodeContext
		ok  bool
	)
	r.withReadLock(func() {
		ctx, ok = r.nodeContexts[name]
	})
	return ctx, ok
}
