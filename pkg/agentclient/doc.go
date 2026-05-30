// Package agentclient is the public re-export of lablink's gRPC node-agent
// client pool.
//
// External callers (for example github.com/nijosmsft/gokd/cmd/gokd-mcp) cannot
// import the internal package directly. This shim exposes the same Pool type
// (via type alias) and a handful of constructors so consumers can dial node
// agents using the same connection pool, mTLS configuration and auth token as
// LabLinkServer itself.
package agentclient
