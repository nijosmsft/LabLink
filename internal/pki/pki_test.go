package pki

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestCreateAndSignServerCSR(t *testing.T) {
	now := time.Now()
	rootPEM, rootKey, rootCert, err := CreateRootCA("LabLink Root", 365*24*time.Hour, now)
	if err != nil {
		t.Fatalf("CreateRootCA() error = %v", err)
	}

	issuingPEM, issuingKey, issuingCert, err := CreateIntermediateCA("LabLink Issuing", 180*24*time.Hour, now, rootCert, rootKey)
	if err != nil {
		t.Fatalf("CreateIntermediateCA() error = %v", err)
	}
	if len(rootPEM) == 0 || len(issuingPEM) == 0 {
		t.Fatal("expected non-empty CA PEM output")
	}

	_, csrPEM, csr, err := CreateServerCSR("server-25", "server-25.lablink")
	if err != nil {
		t.Fatalf("CreateServerCSR() error = %v", err)
	}
	if len(csrPEM) == 0 {
		t.Fatal("expected non-empty CSR PEM output")
	}

	serverPEM, serverCert, err := SignServerCSR(csr, 30*24*time.Hour, now, issuingCert, issuingKey, issuingPEM)
	if err != nil {
		t.Fatalf("SignServerCSR() error = %v", err)
	}
	if len(serverPEM) == 0 {
		t.Fatal("expected non-empty server certificate PEM output")
	}
	if got := len(serverCert.DNSNames); got != 1 || serverCert.DNSNames[0] != "server-25.lablink" {
		t.Fatalf("server certificate DNS SANs = %v, want [server-25.lablink]", serverCert.DNSNames)
	}
	if len(serverCert.ExtKeyUsage) != 1 || serverCert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("server certificate EKU = %v, want only serverAuth", serverCert.ExtKeyUsage)
	}
}

func TestIssueClientCertificate(t *testing.T) {
	now := time.Now()
	_, rootKey, rootCert, err := CreateRootCA("LabLink Root", 365*24*time.Hour, now)
	if err != nil {
		t.Fatalf("CreateRootCA() error = %v", err)
	}

	issuingPEM, issuingKey, issuingCert, err := CreateIntermediateCA("LabLink Issuing", 180*24*time.Hour, now, rootCert, rootKey)
	if err != nil {
		t.Fatalf("CreateIntermediateCA() error = %v", err)
	}

	clientPEM, clientKeyPEM, clientCert, err := IssueClientCertificate("copilot-cli", 90*24*time.Hour, now, issuingCert, issuingKey, issuingPEM)
	if err != nil {
		t.Fatalf("IssueClientCertificate() error = %v", err)
	}
	if len(clientPEM) == 0 || len(clientKeyPEM) == 0 {
		t.Fatal("expected non-empty client cert and key output")
	}
	if len(clientCert.ExtKeyUsage) != 1 || clientCert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("client certificate EKU = %v, want only clientAuth", clientCert.ExtKeyUsage)
	}
}
