package security

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type TransportMode string

const (
	TransportModeMTLS     TransportMode = "mtls"
	TransportModeInsecure TransportMode = "insecure"

	allowInsecureEnv       = "LABLINK_ALLOW_INSECURE"
	legacyAllowInsecureEnv = "DEVICE_INTERACTION_ALLOW_INSECURE"
	transportEnv           = "LABLINK_TRANSPORT"
)

type ClientTransportConfig struct {
	Mode       TransportMode
	CACertPath string
	CertPath   string
	KeyPath    string
	ServerName string
}

type ServerTransportConfig struct {
	Mode       TransportMode
	CACertPath string
	CertPath   string
	KeyPath    string
}

// AllowInsecure returns true when the caller has explicitly opted into the
// current plaintext gRPC transport via flag or environment variable.
func AllowInsecure(flagValue bool) (bool, error) {
	if flagValue {
		return true, nil
	}
	return boolFromEnv(allowInsecureEnv, legacyAllowInsecureEnv)
}

func ResolveClientTransport(modeValue string, allowInsecure bool, caCertPath, certPath, keyPath, serverName string) (ClientTransportConfig, error) {
	mode, err := resolveMode(modeValue, allowInsecure)
	if err != nil {
		return ClientTransportConfig{}, err
	}

	cfg := ClientTransportConfig{
		Mode:       mode,
		CACertPath: strings.TrimSpace(caCertPath),
		CertPath:   strings.TrimSpace(certPath),
		KeyPath:    strings.TrimSpace(keyPath),
		ServerName: strings.TrimSpace(serverName),
	}

	if cfg.Mode == TransportModeMTLS {
		if err := requireTLSPaths(map[string]string{
			"CA cert":     cfg.CACertPath,
			"client cert": cfg.CertPath,
			"client key":  cfg.KeyPath,
		}); err != nil {
			return ClientTransportConfig{}, err
		}
	}

	return cfg, nil
}

func ResolveServerTransport(modeValue string, allowInsecure bool, caCertPath, certPath, keyPath string) (ServerTransportConfig, error) {
	mode, err := resolveMode(modeValue, allowInsecure)
	if err != nil {
		return ServerTransportConfig{}, err
	}

	cfg := ServerTransportConfig{
		Mode:       mode,
		CACertPath: strings.TrimSpace(caCertPath),
		CertPath:   strings.TrimSpace(certPath),
		KeyPath:    strings.TrimSpace(keyPath),
	}

	if cfg.Mode == TransportModeMTLS {
		if err := requireTLSPaths(map[string]string{
			"CA cert":     cfg.CACertPath,
			"server cert": cfg.CertPath,
			"server key":  cfg.KeyPath,
		}); err != nil {
			return ServerTransportConfig{}, err
		}
	}

	return cfg, nil
}

func ResolveServerName(address, override, defaultServerName string) string {
	if value := strings.TrimSpace(override); value != "" {
		return value
	}
	if value := strings.TrimSpace(defaultServerName); value != "" {
		return value
	}

	host := strings.TrimSpace(address)
	if parsedHost, _, err := net.SplitHostPort(address); err == nil {
		host = parsedHost
	}
	return strings.Trim(host, "[]")
}

func NewClientCredentials(cfg ClientTransportConfig, serverName string) (credentials.TransportCredentials, error) {
	if cfg.Mode == TransportModeInsecure {
		return insecure.NewCredentials(), nil
	}

	resolvedServerName := ResolveServerName("", serverName, cfg.ServerName)
	cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}

	rootCAs, err := loadCertPool(cfg.CACertPath)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCAs,
		ServerName:   resolvedServerName,
	}
	return credentials.NewTLS(tlsCfg), nil
}

func NewServerCredentials(cfg ServerTransportConfig) (credentials.TransportCredentials, error) {
	if cfg.Mode != TransportModeMTLS {
		return nil, fmt.Errorf("server TLS credentials requested for transport mode %q", cfg.Mode)
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}

	clientCAs, err := loadCertPool(cfg.CACertPath)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	return credentials.NewTLS(tlsCfg), nil
}

func boolFromEnv(names ...string) (bool, error) {
	for _, name := range names {
		value, ok := os.LookupEnv(name)
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}

		parsed, err := strconv.ParseBool(strings.TrimSpace(value))
		if err != nil {
			return false, fmt.Errorf("invalid %s value %q: %w", name, value, err)
		}
		return parsed, nil
	}

	return false, nil
}

func resolveMode(modeValue string, allowInsecure bool) (TransportMode, error) {
	switch strings.ToLower(strings.TrimSpace(modeValue)) {
	case "":
		if allowInsecure {
			return TransportModeInsecure, nil
		}
		return TransportModeMTLS, nil
	case string(TransportModeMTLS):
		return TransportModeMTLS, nil
	case string(TransportModeInsecure):
		return TransportModeInsecure, nil
	default:
		return "", fmt.Errorf("invalid %s value %q (expected mtls or insecure)", transportEnv, modeValue)
	}
}

func requireTLSPaths(paths map[string]string) error {
	for name, value := range paths {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s path is required for mTLS transport", name)
		}
	}
	return nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate bundle %s: %w", path, err)
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(pemBytes); !ok {
		return nil, fmt.Errorf("parse CA certificate bundle %s", path)
	}
	return pool, nil
}

// InsecureTransportOptInError explains how to explicitly keep using the legacy
// plaintext gRPC transport until mTLS support is configured.
func InsecureTransportOptInError(includeFlag bool) error {
	flagHint := ""
	if includeFlag {
		flagHint = " pass --transport insecure, --allow-insecure, or"
	}

	return fmt.Errorf(
		"LabLink's insecure gRPC transport is disabled by default;%s set %s=insecure (or %s=true / %s=true during migration) to opt in",
		flagHint,
		transportEnv,
		allowInsecureEnv,
		legacyAllowInsecureEnv,
	)
}
