// Package security is the public re-export of lablink's TLS and shared-secret
// helpers, so external callers (for example github.com/nijosmsft/gokd) can
// resolve the same transport configuration and auth token as LabLinkServer.
package security

import (
	internal "github.com/nijosmsft/lablink/internal/security"
)

// TransportMode re-exports the internal TransportMode enum (mtls / insecure).
type TransportMode = internal.TransportMode

// ClientTransportConfig re-exports the internal client TLS configuration.
type ClientTransportConfig = internal.ClientTransportConfig

const (
	// TransportModeMTLS denotes mTLS gRPC transport.
	TransportModeMTLS = internal.TransportModeMTLS
	// TransportModeInsecure denotes the legacy plaintext transport.
	TransportModeInsecure = internal.TransportModeInsecure
)

// FirstPresentEnv returns the value of the first environment variable in
// names that is set and non-empty, or "" if none are.
func FirstPresentEnv(names ...string) string {
	return internal.FirstPresentEnv(names...)
}

// FirstNonEmpty returns the first non-empty string from values.
func FirstNonEmpty(values ...string) string {
	return internal.FirstNonEmpty(values...)
}

// ResolveToken resolves the shared agent auth token from explicit values,
// explicit files, environment variables, or environment-pointed files.
//
// envValueNames lists env vars that may hold the literal token value.
// envFileNames  lists env vars that may hold a path to a file containing the
// token. Returns the token plus a human-readable description of where it came
// from.
func ResolveToken(explicitValue, explicitFile string, envValueNames, envFileNames []string) (string, string, error) {
	return internal.ResolveToken(explicitValue, explicitFile, envValueNames, envFileNames)
}

// AllowInsecure returns whether the legacy plaintext gRPC transport is
// permitted, given an explicit flag value and the LABLINK_ALLOW_INSECURE env
// var.
func AllowInsecure(flagValue bool) (bool, error) {
	return internal.AllowInsecure(flagValue)
}

// ResolveClientTransport resolves the client TLS configuration from
// command-line / env inputs, mirroring how LabLinkServer initializes its pool.
func ResolveClientTransport(modeValue string, allowInsecure bool, caCertPath, certPath, keyPath, serverName string) (ClientTransportConfig, error) {
	return internal.ResolveClientTransport(modeValue, allowInsecure, caCertPath, certPath, keyPath, serverName)
}
