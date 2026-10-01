//go:build !windows

package secretstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

type aesProtector struct {
	aead cipher.AEAD
}

func newProtector(configDir string) (protector, error) {
	keyPath := filepath.Join(configDir, "secrets.key")
	key, err := os.ReadFile(keyPath)
	if os.IsNotExist(err) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(configDir, 0700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, key, 0600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid secret-store key length %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesProtector{aead: aead}, nil
}

func (p aesProtector) Protect(data []byte) ([]byte, error) {
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return p.aead.Seal(nonce, nonce, data, nil), nil
}

func (p aesProtector) Unprotect(data []byte) ([]byte, error) {
	if len(data) < p.aead.NonceSize() {
		return nil, fmt.Errorf("encrypted secret is truncated")
	}
	nonce := data[:p.aead.NonceSize()]
	return p.aead.Open(nil, nonce, data[p.aead.NonceSize():], nil)
}
