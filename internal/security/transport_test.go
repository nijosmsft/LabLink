package security

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/nijosmsft/lablink/internal/pki"
)

func TestAllowInsecureDefaultsFalse(t *testing.T) {
	t.Setenv(allowInsecureEnv, "")
	t.Setenv(legacyAllowInsecureEnv, "")

	allowed, err := AllowInsecure(false)
	if err != nil {
		t.Fatalf("AllowInsecure(false) returned error: %v", err)
	}
	if allowed {
		t.Fatalf("AllowInsecure(false) = true, want false")
	}
}

func TestAllowInsecureUsesFlag(t *testing.T) {
	allowed, err := AllowInsecure(true)
	if err != nil {
		t.Fatalf("AllowInsecure(true) returned error: %v", err)
	}
	if !allowed {
		t.Fatalf("AllowInsecure(true) = false, want true")
	}
}

func TestAllowInsecureReadsPrimaryEnv(t *testing.T) {
	t.Setenv(allowInsecureEnv, "true")

	allowed, err := AllowInsecure(false)
	if err != nil {
		t.Fatalf("AllowInsecure(false) returned error: %v", err)
	}
	if !allowed {
		t.Fatalf("AllowInsecure(false) = false, want true")
	}
}

func TestAllowInsecureReadsLegacyEnv(t *testing.T) {
	t.Setenv(legacyAllowInsecureEnv, "1")

	allowed, err := AllowInsecure(false)
	if err != nil {
		t.Fatalf("AllowInsecure(false) returned error: %v", err)
	}
	if !allowed {
		t.Fatalf("AllowInsecure(false) = false, want true")
	}
}

func TestAllowInsecureRejectsInvalidEnv(t *testing.T) {
	t.Setenv(allowInsecureEnv, "maybe")

	_, err := AllowInsecure(false)
	if err == nil {
		t.Fatal("AllowInsecure(false) error = nil, want invalid env error")
	}
}

func TestResolveClientTransportDefaultsToMTLS(t *testing.T) {
	_, err := ResolveClientTransport("", false, "", "", "", "")
	if err == nil {
		t.Fatal("ResolveClientTransport() error = nil, want missing mTLS path error")
	}
}

func TestResolveClientTransportAllowsExplicitInsecureMode(t *testing.T) {
	cfg, err := ResolveClientTransport("insecure", false, "", "", "", "")
	if err != nil {
		t.Fatalf("ResolveClientTransport() error = %v", err)
	}
	if cfg.Mode != TransportModeInsecure {
		t.Fatalf("ResolveClientTransport() mode = %q, want %q", cfg.Mode, TransportModeInsecure)
	}
}

func TestNewTransportCredentialsForMTLS(t *testing.T) {
	caPath, clientCertPath, clientKeyPath, serverCertPath, serverKeyPath := writeTestCerts(t)

	clientCfg, err := ResolveClientTransport("mtls", false, caPath, clientCertPath, clientKeyPath, "server-25.lablink")
	if err != nil {
		t.Fatalf("ResolveClientTransport() error = %v", err)
	}
	if _, err := NewClientCredentials(clientCfg, ""); err != nil {
		t.Fatalf("NewClientCredentials() error = %v", err)
	}

	serverCfg, err := ResolveServerTransport("mtls", false, caPath, serverCertPath, serverKeyPath)
	if err != nil {
		t.Fatalf("ResolveServerTransport() error = %v", err)
	}
	if _, err := NewServerCredentials(serverCfg); err != nil {
		t.Fatalf("NewServerCredentials() error = %v", err)
	}
}

func writeTestCerts(t *testing.T) (string, string, string, string, string) {
	t.Helper()

	now := time.Now()
	rootPEM, rootKey, rootCert, err := pki.CreateRootCA("LabLink Root", 365*24*time.Hour, now)
	if err != nil {
		t.Fatalf("CreateRootCA() error = %v", err)
	}
	issuingPEM, issuingKey, issuingCert, err := pki.CreateIntermediateCA("LabLink Issuing", 180*24*time.Hour, now, rootCert, rootKey)
	if err != nil {
		t.Fatalf("CreateIntermediateCA() error = %v", err)
	}

	clientCertPEM, clientKeyPEM, _, err := pki.IssueClientCertificate("copilot-cli", 90*24*time.Hour, now, issuingCert, issuingKey, issuingPEM)
	if err != nil {
		t.Fatalf("IssueClientCertificate() error = %v", err)
	}
	serverKeyPEM, csrPEM, csr, err := pki.CreateServerCSR("server-25", "server-25.lablink")
	if err != nil {
		t.Fatalf("CreateServerCSR() error = %v", err)
	}
	serverCertPEM, _, err := pki.SignServerCSR(csr, 30*24*time.Hour, now, issuingCert, issuingKey, issuingPEM)
	if err != nil {
		t.Fatalf("SignServerCSR() error = %v", err)
	}

	tempDir := t.TempDir()
	caPath := filepath.Join(tempDir, "ca.crt")
	clientCertPath := filepath.Join(tempDir, "client.crt")
	clientKeyPath := filepath.Join(tempDir, "client.key")
	serverKeyPath := filepath.Join(tempDir, "server.key")
	serverCertPath := filepath.Join(tempDir, "server.crt")

	if err := pki.WritePEMFile(caPath, rootPEM, 0644); err != nil {
		t.Fatalf("WritePEMFile(ca) error = %v", err)
	}
	if err := pki.WritePEMFile(clientCertPath, clientCertPEM, 0644); err != nil {
		t.Fatalf("WritePEMFile(client cert) error = %v", err)
	}
	if err := pki.WritePEMFile(clientKeyPath, clientKeyPEM, 0600); err != nil {
		t.Fatalf("WritePEMFile(client key) error = %v", err)
	}
	if err := pki.WritePEMFile(filepath.Join(tempDir, "server.csr"), csrPEM, 0644); err != nil {
		t.Fatalf("WritePEMFile(server csr) error = %v", err)
	}
	if err := pki.WritePEMFile(serverKeyPath, serverKeyPEM, 0600); err != nil {
		t.Fatalf("WritePEMFile(server key) error = %v", err)
	}
	if err := pki.WritePEMFile(serverCertPath, serverCertPEM, 0644); err != nil {
		t.Fatalf("WritePEMFile(server cert) error = %v", err)
	}

	return caPath, clientCertPath, clientKeyPath, serverCertPath, serverKeyPath
}
