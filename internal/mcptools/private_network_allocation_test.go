package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nijosmsft/lablink/internal/isolated"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
)

func TestPrivateNetworkAllocationDoesNotRequireHostRoutes(t *testing.T) {
	all := make([]int, isolated.PrivateSubnetCount)
	for i := range all {
		all[i] = i
	}
	for _, test := range []struct {
		name        string
		active      []int
		deleted     []int
		other       []int
		wantCIDR    string
		wantFailure bool
	}{
		{name: "first-without-host-discovery", wantCIDR: "192.168.240.0/26"},
		{name: "skip-active-subnets", active: []int{0, 2}, wantCIDR: "192.168.240.64/26"},
		{name: "reuse-retired-subnet", deleted: []int{0}, wantCIDR: "192.168.240.0/26"},
		{name: "separate-orchestrator-can-reuse-addresses", other: []int{0}, wantCIDR: "192.168.240.0/26"},
		{name: "actual-pool-exhaustion", active: all, wantFailure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			store, err := isolatedstate.Open(filepath.Join(t.TempDir(), "isolated.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			for _, id := range []string{"orch-private", "orch-other"} {
				if err := store.PutOrchestrator(ctx, isolatedstate.Orchestrator{
					ID: id, DisplayName: id, PhysicalHostID: "host1", HostNode: "node1",
					HyperVName: id, NodeName: id, ProfileName: "ubuntu", MainVSwitch: "main",
					AgentPort: 9091, ApplianceSchema: 3, LifecycleState: isolatedstate.OrchestratorReady,
					HealthState: "ready", CreatedAt: 1, UpdatedAt: 1,
				}); err != nil {
					t.Fatal(err)
				}
			}
			addNetwork := func(orchestrator string, index int, state isolatedstate.NetworkLifecycleState) {
				t.Helper()
				prefix, err := isolated.PrivateSubnet(index)
				if err != nil {
					t.Fatal(err)
				}
				name := fmt.Sprintf("%s-%d", orchestrator, index)
				if err := store.PutNetwork(ctx, isolatedstate.PrivateNetwork{
					ID: name, OrchestratorID: orchestrator, DisplayName: name,
					HyperVSwitchName: name, SubnetIndex: index, CIDR: prefix.String(),
					GatewayIPv4:     isolated.PrivateGateway(prefix).String(),
					OrchestratorMAC: fmt.Sprintf("02155D%06X", index+1),
					DNSServersJSON:  "[]", LifecycleState: state, CreatedAt: 1, UpdatedAt: 1,
				}); err != nil {
					t.Fatal(err)
				}
			}
			for _, index := range test.active {
				addNetwork("orch-private", index, isolatedstate.NetworkReady)
			}
			for _, index := range test.deleted {
				addNetwork("orch-private", index, isolatedstate.NetworkDeleted)
			}
			for _, index := range test.other {
				addNetwork("orch-other", index, isolatedstate.NetworkReady)
			}

			// No host client or discovery dependency: host/VPN routes cannot gate allocation.
			deps := &isolatedLifecycleDeps{
				state: store, registry: newRebootTestRegistry(t, map[string]string{"node1": "127.0.0.1:1"}),
			}
			result, err := addSimpleIsolatedNetworkHandler(deps)(ctx, reqNoMeta("add_isolated_network",
				map[string]any{"orchestrator_id": "orch-private", "dry_run": true}))
			if err != nil || result == nil || result.IsError != test.wantFailure {
				t.Fatalf("private allocation failed: %+v, %v", result, err)
			}
			if test.wantFailure {
				if !strings.Contains(toolResultText(result), "no unused private /26 subnet remains for this orchestrator") {
					t.Fatalf("wrong exhaustion diagnostic: %s", toolResultText(result))
				}
			} else {
				var plan struct {
					CIDR string `json:"cidr"`
				}
				if err := json.Unmarshal([]byte(jsonExtract(toolResultText(result))), &plan); err != nil {
					t.Fatal(err)
				}
				if plan.CIDR != test.wantCIDR {
					t.Fatalf("allocated %s, want %s", plan.CIDR, test.wantCIDR)
				}
			}
			networks, err := store.ListNetworks(ctx, "orch-private")
			if err != nil || len(networks) != len(test.active)+len(test.deleted) {
				t.Fatalf("dry run changed existing allocations: %v", err)
			}
		})
	}
}
