package mcptools

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/isolated"
)

func TestSimpleIsolatedToolSurfaceMatchesNormalLifecycle(t *testing.T) {
	s := server.NewMCPServer("test", "1.0")
	RegisterIsolatedLifecycleTools(s, &isolatedLifecycleDeps{})
	tools := s.ListTools()
	expected := []string{
		"create_isolated_orchestrator", "list_isolated_orchestrators",
		"get_isolated_orchestrator", "delete_isolated_orchestrator",
		"add_isolated_network", "remove_isolated_network",
		"create_isolated_vm", "delete_isolated_vm",
		"list_isolated_vms", "get_isolated_vm",
		"rename_isolated_display_name",
		"enable_isolated_vm_nat", "disable_isolated_vm_nat",
		"get_isolated_vm_nat", "list_isolated_vm_nat",
		"list_isolated_relays", "get_isolated_relay_stats",
		"validate_isolated_relay", "rebind_isolated_relays",
	}
	if len(tools) != len(expected) {
		t.Fatalf("registered %d tools, want %d", len(tools), len(expected))
	}
	for _, name := range expected {
		registered := tools[name]
		if registered == nil {
			t.Fatalf("tool %q was not registered", name)
		}
		for _, removed := range []string{
			"expected_generation", "operation_id", "resume_exact",
			"approved_plan_revision",
		} {
			if _, ok := registered.Tool.InputSchema.Properties[removed]; ok {
				t.Errorf("%s exposes removed field %s", name, removed)
			}
		}
	}
	if _, ok := tools["create_isolated_vm"].Tool.InputSchema.Properties["name"]; !ok {
		t.Fatal("create_isolated_vm must use the normal VM name")
	}
	for _, removed := range []string{
		"repair_isolated_vm", "reconcile_isolated_orchestrator",
		"reconcile_isolated_vm_nat", "create_isolated_relay",
		"adopt_isolated_relay", "remove_isolated_relay",
	} {
		if tools[removed] != nil {
			t.Errorf("removed HA-style tool %q is still registered", removed)
		}
	}
}

func TestConfigureStaticAfterPrivateNICReadyRetriesHotPlugRace(t *testing.T) {
	attempts := 0
	snapshot, err := configureStaticAfterPrivateNICReady(
		context.Background(), time.Second, time.Millisecond,
		func() (isolated.ApplianceSnapshot, error) {
			attempts++
			if attempts < 3 {
				return isolated.ApplianceSnapshot{},
					errors.New("no interface has MAC 02155d7dfe8e")
			}
			return isolated.ApplianceSnapshot{Ready: true}, nil
		},
	)
	if err != nil {
		t.Fatalf("configure after hot-plug: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
	if !snapshot.Ready {
		t.Fatal("successful snapshot was not returned")
	}
}

func TestConfigureStaticAfterPrivateNICReadyDoesNotRetryPermanentError(t *testing.T) {
	attempts := 0
	_, err := configureStaticAfterPrivateNICReady(
		context.Background(), time.Second, time.Millisecond,
		func() (isolated.ApplianceSnapshot, error) {
			attempts++
			return isolated.ApplianceSnapshot{}, errors.New("invalid CIDR")
		},
	)
	if err == nil {
		t.Fatal("expected permanent error")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}
