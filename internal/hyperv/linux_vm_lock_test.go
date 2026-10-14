package hyperv

import (
	"strings"
	"testing"
)

func TestLinuxVMLockIsPerNameAndOwnerChecked(t *testing.T) {
	acquire, err := BuildLinuxVMAcquireLockScript(LinuxVMLockParams{Key: "abc", Owner: "owner-1"})
	if err != nil {
		t.Fatal(err)
	}
	release, err := BuildLinuxVMReleaseLockScript(LinuxVMLockParams{Key: "abc", Owner: "owner-1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"New-Item -ItemType Directory -Path $lockPath -ErrorAction Stop", "Move-Item -LiteralPath $lockPath", "recovered_stale", "'abc' + '.lock'"} {
		if !strings.Contains(acquire, want) {
			t.Errorf("acquire lock missing %q", want)
		}
	}
	if !strings.Contains(release, "[string]$existing.token -ceq $ownerToken") {
		t.Fatal("release does not enforce random owner token")
	}
}
