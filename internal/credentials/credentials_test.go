package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nijosmsft/lablink/internal/secretstore"
)

func TestStoreEncryptsPasswordsAndKeepsMetadataNonSecret(t *testing.T) {
	root := t.TempDir()
	metadataPath := filepath.Join(root, "credentials.json")
	store := LoadStore(metadataPath)
	const password = "Never-Write-This-Plaintext!"
	if err := store.Set(&Profile{
		Name: "admin", Username: `CONTOSO\admin`, Password: password,
	}); err != nil {
		t.Fatal(err)
	}

	profile, err := store.Get("admin")
	if err != nil || profile.Password != password ||
		profile.Username != `CONTOSO\admin` {
		t.Fatalf("Get = %#v, %v", profile, err)
	}
	for _, path := range []string{metadataPath, store.SecretStorePath()} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), password) {
			t.Fatalf("plaintext password found in %s", path)
		}
	}
	metadata, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(metadata), `"password"`) ||
		!strings.Contains(string(metadata), `"password_secret"`) {
		t.Fatalf("credential metadata = %s", metadata)
	}
}

func TestLegacyPlaintextCredentialIsRejectedUntilResaved(t *testing.T) {
	root := t.TempDir()
	metadataPath := filepath.Join(root, "credentials.json")
	legacy := `{"profiles":{"legacy":{"name":"legacy","username":"admin","password":"old-secret"}}}`
	if err := os.WriteFile(metadataPath, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	store := LoadStore(metadataPath)
	if _, err := store.Get("legacy"); !errors.Is(err, ErrLegacyPlaintext) {
		t.Fatalf("legacy Get error = %v", err)
	}
	profiles := store.ListProfiles()
	if len(profiles) != 1 || !profiles[0].RequiresResave {
		t.Fatalf("legacy profiles = %#v", profiles)
	}
	if err := store.Set(&Profile{
		Name: "legacy", Username: "admin", Password: "replacement",
	}); err != nil {
		t.Fatal(err)
	}
	profile, err := store.Get("legacy")
	if err != nil || profile.Password != "replacement" {
		t.Fatalf("resaved profile = %#v, %v", profile, err)
	}
	metadata, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(metadata), "old-secret") ||
		strings.Contains(string(metadata), `"password"`) {
		t.Fatalf("legacy plaintext survived re-save: %s", metadata)
	}
}

func TestSetReferenceUsesExternallyPromptedEncryptedValue(t *testing.T) {
	root := t.TempDir()
	metadataPath := filepath.Join(root, "credentials.json")
	encrypted := secretstore.Open(filepath.Join(root, "credential-secrets.json"))
	store := LoadStore(metadataPath, encrypted)
	secretName, err := NewPasswordSecretName("prompted")
	if err != nil {
		t.Fatal(err)
	}
	if err := secretstore.Open(encrypted.Path()).Set(secretName, "prompt-value"); err != nil {
		t.Fatal(err)
	}
	if err := store.ReloadSecrets(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetReference("prompted", "operator", secretName); err != nil {
		t.Fatal(err)
	}
	profile, err := store.Get("prompted")
	if err != nil || profile.Password != "prompt-value" {
		t.Fatalf("prompted profile = %#v, %v", profile, err)
	}
}
