package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nijosmsft/lablink/internal/secretstore"
)

func TestSetStoresConfirmedSecretWithoutPrintingValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.json")
	values := [][]byte{[]byte("sensitive-value"), []byte("sensitive-value")}
	reader := func(string) ([]byte, error) {
		value := append([]byte(nil), values[0]...)
		values = values[1:]
		return value, nil
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"set", "--store", path, "archive"}, &stdout, &stderr, reader); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "sensitive-value") || strings.Contains(stderr.String(), "sensitive-value") {
		t.Fatal("secret value was printed")
	}
	value, err := secretstore.Open(path).Get("archive")
	if err != nil || value != "sensitive-value" {
		t.Fatalf("stored secret = %q, %v", value, err)
	}
}

func TestSetRejectsMismatchWithoutCreatingSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.json")
	values := [][]byte{[]byte("first"), []byte("second")}
	reader := func(string) ([]byte, error) {
		value := append([]byte(nil), values[0]...)
		values = values[1:]
		return value, nil
	}
	if err := run([]string{"set", "--store", path, "archive"}, &bytes.Buffer{}, &bytes.Buffer{}, reader); err == nil ||
		!strings.Contains(err.Error(), "do not match") {
		t.Fatalf("mismatch error = %v", err)
	}
	if _, err := secretstore.Open(path).Get("archive"); err == nil {
		t.Fatal("mismatched secret was stored")
	}
}

func TestListDeleteAndVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.json")
	if err := secretstore.Open(path).Set("archive", "value"); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := run([]string{"list", "--store", path}, &stdout, &bytes.Buffer{}, nil); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(stdout.String()) != "archive" {
		t.Fatalf("list output = %q", stdout.String())
	}
	if err := run([]string{"delete", "--store", path, "archive"}, &bytes.Buffer{}, &bytes.Buffer{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := secretstore.Open(path).Get("archive"); err == nil {
		t.Fatal("secret was not deleted")
	}
	stdout.Reset()
	if err := run([]string{"--version"}, &stdout, &bytes.Buffer{}, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), secretVersion) {
		t.Fatalf("version output = %q", stdout.String())
	}
}

func TestWriteSecretStatusContainsOnlyOutcome(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	t.Setenv(secretStatusFileEnv, path)
	writeSecretStatus(errors.New("prompt canceled"))

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var status secretStatus
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	if status.OK || status.Error != "prompt canceled" {
		t.Fatalf("status = %#v", status)
	}
}

func TestReadSecretWithFeedbackMasksCharactersAndHandlesBackspace(t *testing.T) {
	var output bytes.Buffer
	value, err := readSecretWithFeedback(strings.NewReader("ab\bcd\r"), &output)
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "acd" {
		t.Fatalf("value = %q", value)
	}
	if output.String() != "**\b \b**" {
		t.Fatalf("feedback = %q", output.String())
	}
	if strings.Contains(output.String(), string(value)) {
		t.Fatal("secret value appeared in feedback")
	}
}

func TestReadSecretWithFeedbackUsesOneMarkerPerUnicodeCharacter(t *testing.T) {
	var output bytes.Buffer
	value, err := readSecretWithFeedback(strings.NewReader("päss\r"), &output)
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "päss" || output.String() != "****" {
		t.Fatalf("value = %q, feedback = %q", value, output.String())
	}
}

func TestReadSecretWithFeedbackHandlesCancelAndIgnoresControls(t *testing.T) {
	var output bytes.Buffer
	_, err := readSecretWithFeedback(strings.NewReader("\tA\x03"), &output)
	if !errors.Is(err, errSecretInputCanceled) {
		t.Fatalf("cancel error = %v", err)
	}
	if output.String() != "*" {
		t.Fatalf("feedback = %q", output.String())
	}
}
