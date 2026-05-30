package agentclient

import (
	internal "github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/pkg/security"
)

// Pool is a re-export of the internal connection pool. Type alias keeps
// internal and public types interoperable.
type Pool = internal.Pool

// NewPool creates a new agent connection pool with the given shared auth
// token and TLS configuration.
func NewPool(token string, transport security.ClientTransportConfig) *Pool {
	return internal.NewPool(token, transport)
}
