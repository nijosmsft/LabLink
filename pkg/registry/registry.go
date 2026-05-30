// Package registry is the public re-export of lablink's node registry.
//
// External callers (for example github.com/nijosmsft/gokd/cmd/gokd-mcp) can
// load the same nodes.json that LabLinkServer uses and look up node addresses
// and TLS server names.
package registry

import (
	internal "github.com/nijosmsft/lablink/internal/registry"
)

// Node is a re-export of the internal node descriptor.
type Node = internal.Node

// Registry is a re-export of the internal in-memory + on-disk node registry.
type Registry = internal.Registry

// Load reads the registry from a JSON file, or creates an empty one when the
// file does not exist.
func Load(filePath string) *Registry {
	return internal.Load(filePath)
}
