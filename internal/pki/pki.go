package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func GenerateECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func MarshalECDSAPrivateKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func ParseECDSAPrivateKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no private key PEM block found")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is %T, want ECDSA", parsed)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported private key PEM type %q", block.Type)
	}
}

func ReadECDSAPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseECDSAPrivateKeyPEM(data)
}

func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		return x509.ParseCertificate(block.Bytes)
	}
	return nil, fmt.Errorf("no certificate PEM block found")
}

func ReadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCertificatePEM(data)
}

func ParseCertificateRequestPEM(data []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no certificate request PEM block found")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("unexpected PEM type %q", block.Type)
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func ReadCertificateRequest(path string) (*x509.CertificateRequest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCertificateRequestPEM(data)
}

func WritePEMFile(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, data, perm)
}

func CreateRootCA(commonName string, validFor time.Duration, now time.Time) ([]byte, *ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := GenerateECDSAKey()
	if err != nil {
		return nil, nil, nil, err
	}

	serial, err := serialNumber()
	if err != nil {
		return nil, nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key, cert, nil
}

func CreateIntermediateCA(commonName string, validFor time.Duration, now time.Time, parent *x509.Certificate, parentKey crypto.Signer) ([]byte, *ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := GenerateECDSAKey()
	if err != nil {
		return nil, nil, nil, err
	}

	serial, err := serialNumber()
	if err != nil {
		return nil, nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key, cert, nil
}

func IssueClientCertificate(commonName string, validFor time.Duration, now time.Time, issuer *x509.Certificate, issuerKey crypto.Signer, chainPEMs ...[]byte) ([]byte, []byte, *x509.Certificate, error) {
	key, err := GenerateECDSAKey()
	if err != nil {
		return nil, nil, nil, err
	}

	serial, err := serialNumber()
	if err != nil {
		return nil, nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}

	keyPEM, err := MarshalECDSAPrivateKeyPEM(key)
	if err != nil {
		return nil, nil, nil, err
	}

	certPEM := ConcatPEMs(append([][]byte{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, chainPEMs...)...)
	return certPEM, keyPEM, cert, nil
}

func CreateServerCSR(commonName, serverName string) ([]byte, []byte, *x509.CertificateRequest, error) {
	key, err := GenerateECDSAKey()
	if err != nil {
		return nil, nil, nil, err
	}

	keyPEM, err := MarshalECDSAPrivateKeyPEM(key)
	if err != nil {
		return nil, nil, nil, err
	}

	csrPEM, csr, err := CreateServerCSRWithKey(commonName, serverName, key)
	if err != nil {
		return nil, nil, nil, err
	}

	return keyPEM, csrPEM, csr, nil
}

func CreateServerCSRWithKey(commonName, serverName string, key *ecdsa.PrivateKey) ([]byte, *x509.CertificateRequest, error) {
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		return nil, nil, fmt.Errorf("server name is required for CSR generation")
	}

	cn := strings.TrimSpace(commonName)
	if cn == "" {
		cn = serverName
	}

	dnsNames, ipAddresses := subjectAltNames(serverName)
	template := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: cn},
		DNSNames:           dnsNames,
		IPAddresses:        ipAddresses,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, nil, err
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), csr, nil
}

func SignServerCSR(csr *x509.CertificateRequest, validFor time.Duration, now time.Time, issuer *x509.Certificate, issuerKey crypto.Signer, chainPEMs ...[]byte) ([]byte, *x509.Certificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("invalid CSR signature: %w", err)
	}

	if len(csr.DNSNames) == 0 && len(csr.IPAddresses) == 0 {
		return nil, nil, fmt.Errorf("CSR must include at least one DNS or IP subjectAltName")
	}

	serial, err := serialNumber()
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer, csr.PublicKey, issuerKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}

	certPEM := ConcatPEMs(append([][]byte{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, chainPEMs...)...)
	return certPEM, cert, nil
}

func LoadKeyPair(certPath, keyPath string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certPath, keyPath)
}

func ConcatPEMs(pems ...[]byte) []byte {
	return bytes.Join(pems, nil)
}

func subjectAltNames(serverName string) ([]string, []net.IP) {
	if ip := net.ParseIP(serverName); ip != nil {
		return nil, []net.IP{ip}
	}
	return []string{serverName}, nil
}

func serialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
