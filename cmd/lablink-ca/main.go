package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nijosmsft/lablink/internal/pki"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "init":
		err = runInit(os.Args[2:])
	case "issue-client":
		err = runIssueClient(os.Args[2:])
	case "sign-server-csr":
		err = runSignServerCSR(os.Args[2:])
	case "show-cert":
		err = runShowCert(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`Usage:
  lablink-ca init [flags]
  lablink-ca issue-client [flags]
  lablink-ca sign-server-csr [flags]
  lablink-ca show-cert --cert <path>

Commands:
  init             Initialize a self-managed LabLink root and issuing CA
  issue-client     Issue an mTLS client certificate for the MCP/operator side
  sign-server-csr  Sign a LabLink agent server CSR
  show-cert        Print a readable summary of a PEM certificate`)
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	pkiDir := fs.String("pki-dir", defaultPKIDir(), "directory to store the LabLink PKI")
	outDir := fs.String("out", "", "alias for -pki-dir")
	rootCN := fs.String("root-cn", "LabLink Root CA", "root CA common name")
	issuingCN := fs.String("issuing-cn", "LabLink Issuing CA", "issuing CA common name")
	rootDays := fs.Int("root-days", 365*5, "root CA validity in days")
	issuingDays := fs.Int("issuing-days", 365, "issuing CA validity in days")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*outDir) != "" {
		*pkiDir = strings.TrimSpace(*outDir)
	}

	now := time.Now()
	rootCertPEM, rootKey, rootCert, err := pki.CreateRootCA(*rootCN, time.Duration(*rootDays)*24*time.Hour, now)
	if err != nil {
		return fmt.Errorf("create root CA: %w", err)
	}
	rootKeyPEM, err := pki.MarshalECDSAPrivateKeyPEM(rootKey)
	if err != nil {
		return fmt.Errorf("marshal root key: %w", err)
	}

	issuingCertPEM, issuingKey, _, err := pki.CreateIntermediateCA(*issuingCN, time.Duration(*issuingDays)*24*time.Hour, now, rootCert, rootKey)
	if err != nil {
		return fmt.Errorf("create issuing CA: %w", err)
	}
	issuingKeyPEM, err := pki.MarshalECDSAPrivateKeyPEM(issuingKey)
	if err != nil {
		return fmt.Errorf("marshal issuing key: %w", err)
	}

	if err := pki.WritePEMFile(filepath.Join(*pkiDir, "root", "root.crt"), rootCertPEM, 0644); err != nil {
		return err
	}
	if err := pki.WritePEMFile(filepath.Join(*pkiDir, "root", "root.key"), rootKeyPEM, 0600); err != nil {
		return err
	}
	if err := pki.WritePEMFile(filepath.Join(*pkiDir, "issuing", "issuing.crt"), issuingCertPEM, 0644); err != nil {
		return err
	}
	if err := pki.WritePEMFile(filepath.Join(*pkiDir, "issuing", "issuing.key"), issuingKeyPEM, 0600); err != nil {
		return err
	}
	if err := pki.WritePEMFile(filepath.Join(*pkiDir, "ca-bundle", "ca.crt"), rootCertPEM, 0644); err != nil {
		return err
	}

	fmt.Printf("Initialized LabLink PKI at %s\n", *pkiDir)
	fmt.Printf("- Root CA: %s\n", filepath.Join(*pkiDir, "root", "root.crt"))
	fmt.Printf("- Issuing CA: %s\n", filepath.Join(*pkiDir, "issuing", "issuing.crt"))
	fmt.Printf("- CA bundle: %s\n", filepath.Join(*pkiDir, "ca-bundle", "ca.crt"))
	return nil
}

func runIssueClient(args []string) error {
	fs := flag.NewFlagSet("issue-client", flag.ContinueOnError)
	pkiDir := fs.String("pki-dir", defaultPKIDir(), "directory containing the LabLink PKI")
	caDir := fs.String("ca-dir", "", "alias for -pki-dir")
	name := fs.String("name", "default", "client profile name")
	commonName := fs.String("common-name", "", "alias for -name")
	validDays := fs.Int("days", 90, "client certificate validity in days")
	certOut := fs.String("cert-out", "", "path to write the client certificate chain PEM")
	keyOut := fs.String("key-out", "", "path to write the client private key PEM")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*caDir) != "" {
		*pkiDir = strings.TrimSpace(*caDir)
	}
	if strings.TrimSpace(*commonName) != "" {
		*name = strings.TrimSpace(*commonName)
	}

	issuingCert, issuingKey, issuingCertPEM, err := loadIssuingCA(*pkiDir)
	if err != nil {
		return err
	}

	clientCertPEM, clientKeyPEM, cert, err := pki.IssueClientCertificate(*name, time.Duration(*validDays)*24*time.Hour, time.Now(), issuingCert, issuingKey, issuingCertPEM)
	if err != nil {
		return fmt.Errorf("issue client certificate: %w", err)
	}

	if *certOut == "" {
		*certOut = filepath.Join(*pkiDir, "clients", *name, "client.crt")
	}
	if *keyOut == "" {
		*keyOut = filepath.Join(*pkiDir, "clients", *name, "client.key")
	}

	if err := pki.WritePEMFile(*certOut, clientCertPEM, 0644); err != nil {
		return err
	}
	if err := pki.WritePEMFile(*keyOut, clientKeyPEM, 0600); err != nil {
		return err
	}

	fmt.Printf("Issued client certificate for %s\n", *name)
	fmt.Printf("- Cert: %s\n", *certOut)
	fmt.Printf("- Key:  %s\n", *keyOut)
	fmt.Printf("- Expires: %s\n", cert.NotAfter.Format(time.RFC3339))
	return nil
}

func runSignServerCSR(args []string) error {
	fs := flag.NewFlagSet("sign-server-csr", flag.ContinueOnError)
	pkiDir := fs.String("pki-dir", defaultPKIDir(), "directory containing the LabLink PKI")
	caDir := fs.String("ca-dir", "", "alias for -pki-dir")
	csrPath := fs.String("csr", "", "path to the server CSR PEM")
	certOut := fs.String("cert-out", "", "path to write the signed server certificate chain PEM")
	validDays := fs.Int("days", 30, "server certificate validity in days")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*caDir) != "" {
		*pkiDir = strings.TrimSpace(*caDir)
	}
	if strings.TrimSpace(*csrPath) == "" {
		return fmt.Errorf("--csr is required")
	}

	issuingCert, issuingKey, issuingCertPEM, err := loadIssuingCA(*pkiDir)
	if err != nil {
		return err
	}

	csr, err := pki.ReadCertificateRequest(*csrPath)
	if err != nil {
		return fmt.Errorf("read CSR: %w", err)
	}

	serverCertPEM, cert, err := pki.SignServerCSR(csr, time.Duration(*validDays)*24*time.Hour, time.Now(), issuingCert, issuingKey, issuingCertPEM)
	if err != nil {
		return fmt.Errorf("sign server CSR: %w", err)
	}

	if *certOut == "" {
		*certOut = strings.TrimSuffix(*csrPath, filepath.Ext(*csrPath)) + ".crt"
	}
	if err := pki.WritePEMFile(*certOut, serverCertPEM, 0644); err != nil {
		return err
	}

	fmt.Printf("Signed server CSR %s\n", *csrPath)
	fmt.Printf("- Cert: %s\n", *certOut)
	fmt.Printf("- DNS SANs: %s\n", strings.Join(cert.DNSNames, ", "))
	fmt.Printf("- Expires: %s\n", cert.NotAfter.Format(time.RFC3339))
	return nil
}

func runShowCert(args []string) error {
	fs := flag.NewFlagSet("show-cert", flag.ContinueOnError)
	certPath := fs.String("cert", "", "path to the certificate PEM")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*certPath) == "" {
		return fmt.Errorf("--cert is required")
	}

	cert, err := pki.ReadCertificate(*certPath)
	if err != nil {
		return fmt.Errorf("read certificate: %w", err)
	}

	fmt.Printf("Subject: %s\n", cert.Subject.String())
	fmt.Printf("Issuer: %s\n", cert.Issuer.String())
	fmt.Printf("Serial: %s\n", cert.SerialNumber.String())
	fmt.Printf("Not Before: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("Not After: %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("Is CA: %t\n", cert.IsCA)
	if len(cert.DNSNames) > 0 {
		fmt.Printf("DNS SANs: %s\n", strings.Join(cert.DNSNames, ", "))
	}
	if len(cert.IPAddresses) > 0 {
		var ips []string
		for _, ip := range cert.IPAddresses {
			ips = append(ips, ip.String())
		}
		fmt.Printf("IP SANs: %s\n", strings.Join(ips, ", "))
	}
	fmt.Printf("Ext Key Usage: %v\n", cert.ExtKeyUsage)
	return nil
}

func loadIssuingCA(pkiDir string) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	issuingCertPath := filepath.Join(pkiDir, "issuing", "issuing.crt")
	issuingKeyPath := filepath.Join(pkiDir, "issuing", "issuing.key")

	issuingCert, err := pki.ReadCertificate(issuingCertPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read issuing certificate: %w", err)
	}
	issuingKey, err := pki.ReadECDSAPrivateKey(issuingKeyPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read issuing private key: %w", err)
	}
	issuingCertPEM, err := os.ReadFile(issuingCertPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read issuing certificate PEM: %w", err)
	}

	return issuingCert, issuingKey, issuingCertPEM, nil
}

func defaultPKIDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".lablink", "pki")
	}
	return filepath.Join(home, ".lablink", "pki")
}
