package credentials

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCredentialChangesFromAnotherProcessNeedNoReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	reader := LoadStore(path)
	runWriter := func(action string) {
		t.Helper()
		command := exec.Command(os.Args[0], "-test.run=^TestCredentialWriterProcess$")
		command.Env = append(os.Environ(), "LABLINK_CREDENTIAL_TEST_PATH="+path, "LABLINK_CREDENTIAL_TEST_ACTION="+action)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("credential writer %s: %v\n%s", action, err, output)
		}
	}
	runWriter("create")
	names, err := reader.List()
	if err != nil || len(names) != 1 || names[0] != "other-process" {
		t.Fatalf("external profile not listed: %v, %v", names, err)
	}
	runWriter("replace")
	profile, err := reader.Get("other-process")
	if err != nil || profile.Password != "replacement-test-password" {
		t.Fatalf("external replacement was not read: %v", err)
	}
	runWriter("delete")
	if _, err := reader.Get("other-process"); err == nil {
		t.Fatal("external deletion returned a cached credential")
	}
}

func TestCredentialWriterProcess(t *testing.T) {
	path := os.Getenv("LABLINK_CREDENTIAL_TEST_PATH")
	if path == "" {
		t.Skip("subprocess helper")
	}
	store := LoadStore(path)
	var err error
	switch os.Getenv("LABLINK_CREDENTIAL_TEST_ACTION") {
	case "create":
		err = store.Set(&Profile{Name: "other-process", Username: "operator", Password: "initial-test-password"})
	case "replace":
		err = store.Set(&Profile{Name: "other-process", Username: "operator", Password: "replacement-test-password"})
	case "delete":
		err = store.Delete("other-process")
	default:
		t.Fatal("unknown credential writer action")
	}
	if err != nil {
		t.Fatal(err)
	}
}
