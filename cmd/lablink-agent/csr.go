package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/nijosmsft/lablink/internal/pki"
)

func generateServerCSRAction() error {
	serverName := resolveTLSServerName()
	if serverName == "" {
		return fmt.Errorf("a TLS server name is required (use --tls-server-name or LABLINK_TLS_SERVER_NAME)")
	}

	keyPath := firstNonEmpty(*tlsKeyPath, *keyOut)
	if strings.TrimSpace(keyPath) == "" {
		return fmt.Errorf("a key output path is required (use --tls-key or --key-out)")
	}
	if strings.TrimSpace(*csrOut) == "" {
		return fmt.Errorf("--csr-out is required")
	}

	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing private key at %s", keyPath)
	}
	if _, err := os.Stat(*csrOut); err == nil {
		return fmt.Errorf("refusing to overwrite existing CSR at %s", *csrOut)
	}

	hostname, _ := os.Hostname()
	keyPEM, csrPEM, _, err := pki.CreateServerCSR(hostname, serverName)
	if err != nil {
		return err
	}

	if err := pki.WritePEMFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}
	if err := pki.WritePEMFile(*csrOut, csrPEM, 0644); err != nil {
		return err
	}

	fmt.Printf("Generated server key and CSR for %s\n", serverName)
	fmt.Printf("- Key: %s\n", keyPath)
	fmt.Printf("- CSR: %s\n", *csrOut)
	return nil
}
