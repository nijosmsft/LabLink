package hyperv

import (
	"strings"
	"testing"
)

func TestResourceSafetyScriptChecksMemoryStorageAndOverride(t *testing.T) {
	script, err := ResourceSafetyScript(ResourceSafetyParams{
		MemoryMB: 8192, StoragePath: `E:\VM\vm1\vm1.vhdx`,
		ReserveVHDPath: `E:\base.vhdx`, MinHostReservePct: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"HOST_MEMORY_RESERVE",
		"HOST_STORAGE_RESERVE",
		"allow_host_resource_pressure=true",
		"FreePhysicalMemory",
		"Get-VHD -Path $resourceReserveVhd",
		"minimum_free_pct",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("resource script missing %q", want)
		}
	}
}

func TestResourceSafetyScriptValidatesThreshold(t *testing.T) {
	if _, err := ResourceSafetyScript(ResourceSafetyParams{
		MemoryMB: 1, StoragePath: `E:\x`, MinHostReservePct: 100,
	}); err == nil {
		t.Fatal("expected invalid threshold error")
	}
}
