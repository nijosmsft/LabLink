package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFirstPresentEnvReturnsTrimmedValue(t *testing.T) {
	t.Setenv("LABLINK_TEST_EMPTY", "   ")
	t.Setenv("LABLINK_TEST_VALUE", " value ")

	got := FirstPresentEnv("LABLINK_TEST_EMPTY", "LABLINK_TEST_VALUE")
	if got != "value" {
		t.Fatalf("FirstPresentEnv() = %q, want %q", got, "value")
	}
}

func TestReadSecretFileTrimsWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(path, []byte("secret-value\r\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	got, err := ReadSecretFile(path)
	if err != nil {
		t.Fatalf("ReadSecretFile() error = %v", err)
	}
	if got != "secret-value" {
		t.Fatalf("ReadSecretFile() = %q, want %q", got, "secret-value")
	}
}

func TestResolveTokenUsesTokenFileEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.txt")
	if err := os.WriteFile(path, []byte("token-from-file\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Setenv("LABLINK_AGENT_TOKEN_FILE", path)

	got, source, err := ResolveToken("", "", []string{"LABLINK_AGENT_TOKEN"}, []string{"LABLINK_AGENT_TOKEN_FILE"})
	if err != nil {
		t.Fatalf("ResolveToken() error = %v", err)
	}
	if got != "token-from-file" {
		t.Fatalf("ResolveToken() token = %q, want %q", got, "token-from-file")
	}
	if source == "none" {
		t.Fatalf("ResolveToken() source = %q, want file source", source)
	}
}
