package main

import (
	"os"
	"testing"

	"github.com/nijosmsft/lablink/internal/security"
)

func TestLeaseEnforcementEnabledTokens(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "unset empty", in: "", want: false},
		{name: "whitespace empty", in: " \t\r\n", want: false},
		{name: "zero disabled", in: "0", want: false},
		{name: "false disabled", in: "false", want: false},
		{name: "no disabled", in: "no", want: false},
		{name: "off disabled", in: "off", want: false},
		{name: "disabled disabled", in: "disabled", want: false},
		{name: "garbage disabled", in: "garbage", want: false},
		{name: "one enabled", in: "1", want: true},
		{name: "true enabled", in: "true", want: true},
		{name: "yes enabled", in: "yes", want: true},
		{name: "on enabled", in: "on", want: true},
		{name: "enabled enabled", in: "enabled", want: true},
		{name: "case insensitive", in: "TrUe", want: true},
		{name: "trimmed", in: "  enabled\t", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := leaseEnforcementEnabled(tt.in); got != tt.want {
				t.Fatalf("leaseEnforcementEnabled(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestLeaseEnforcementDefaultEnvIsDisabled(t *testing.T) {
	old, hadOld := os.LookupEnv("LABLINK_LEASE_REQUIRED")
	t.Cleanup(func() {
		if hadOld {
			_ = os.Setenv("LABLINK_LEASE_REQUIRED", old)
		} else {
			_ = os.Unsetenv("LABLINK_LEASE_REQUIRED")
		}
	})

	_ = os.Unsetenv("LABLINK_LEASE_REQUIRED")
	if leaseEnforcementEnabled(security.FirstPresentEnv("LABLINK_LEASE_REQUIRED")) {
		t.Fatal("unset LABLINK_LEASE_REQUIRED should leave lease enforcement disabled")
	}

	_ = os.Setenv("LABLINK_LEASE_REQUIRED", "")
	if leaseEnforcementEnabled(security.FirstPresentEnv("LABLINK_LEASE_REQUIRED")) {
		t.Fatal("empty LABLINK_LEASE_REQUIRED should leave lease enforcement disabled")
	}
}
