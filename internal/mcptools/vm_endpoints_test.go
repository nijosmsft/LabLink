package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"
	"google.golang.org/grpc"
)

func endpointTestReconciler(t *testing.T) *VMEndpointReconciler {
	t.Helper()
	dir := t.TempDir()
	state, err := isolatedstate.Open(filepath.Join(dir, "isolated.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	pool := agentclient.NewPool("", security.ClientTransportConfig{Mode: security.TransportModeInsecure})
	t.Cleanup(pool.Close)
	return NewVMEndpointReconciler(registry.Load(filepath.Join(dir, "nodes.json")), pool, state)
}

func endpointTestNode(name, ip, vmID string) *registry.Node {
	return &registry.Node{
		Name: name, Address: net.JoinHostPort(ip, "9091"),
		TLSServerName: name, TransportMode: "mtls",
		Labels: map[string]string{
			vmHostLabel: "host", vmIDLabel: vmID, vmMACLabel: "02155D000001",
		},
	}
}

func TestVMEndpointRefreshRejectsUnverifiedAndWrongNICCandidates(t *testing.T) {
	for _, test := range []struct {
		name        string
		observation vmEndpointObservation
		probeErr    error
		wantErr     bool
		wantIP      string
	}{
		{"authenticated", vmEndpointObservation{VMID: "vm-1", MAC: "02:15:5d:00:00:01", State: "Running", Addresses: []string{"192.0.2.20"}}, nil, false, "192.0.2.20"},
		{"wrong-certificate", vmEndpointObservation{VMID: "vm-1", MAC: "02155D000001", State: "Running", Addresses: []string{"192.0.2.20"}}, errors.New("certificate identity mismatch"), true, "192.0.2.10"},
		{"wrong-VM", vmEndpointObservation{VMID: "vm-2", MAC: "02155D000001", State: "Running", Addresses: []string{"192.0.2.20"}}, nil, true, "192.0.2.10"},
		{"wrong-NIC", vmEndpointObservation{VMID: "vm-1", MAC: "02155D000002", State: "Running", Addresses: []string{"192.0.2.20"}}, nil, true, "192.0.2.10"},
		{"stopped", vmEndpointObservation{VMID: "vm-1", MAC: "02155D000001", State: "Off", Addresses: []string{"192.0.2.20"}}, nil, false, "192.0.2.10"},
		{"waiting-DHCP", vmEndpointObservation{VMID: "vm-1", MAC: "02155D000001", State: "Running", Addresses: []string{"169.254.1.1", "::1", "127.0.0.1"}}, nil, true, "192.0.2.10"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := endpointTestReconciler(t)
			node := endpointTestNode("guest", "192.0.2.10", "vm-1")
			if err := r.reg.SetNode(node); err != nil {
				t.Fatal(err)
			}
			r.discover = func(_ context.Context, host string, bindings []vmEndpointBinding) ([]vmEndpointObservation, error) {
				if host != "host" || len(bindings) != 1 || bindings[0].VMID != "vm-1" {
					t.Fatalf("unexpected discovery binding: %s %+v", host, bindings)
				}
				observation := test.observation
				observation.NodeName = node.Name
				return []vmEndpointObservation{observation}, nil
			}
			probes := 0
			r.probe = func(_ context.Context, expected *registry.Node, address string) error {
				probes++
				if expected.TLSServerName != "guest" || address != "192.0.2.20:9091" {
					t.Fatalf("identity changed with address: %+v %s", expected, address)
				}
				return test.probeErr
			}
			err := r.Reconcile(context.Background())
			if (err != nil) != test.wantErr {
				t.Fatalf("Reconcile error = %v", err)
			}
			got, _ := r.reg.GetNode(node.Name)
			if got.Address != net.JoinHostPort(test.wantIP, "9091") || got.TLSServerName != node.TLSServerName || !reflect.DeepEqual(got.Labels, node.Labels) {
				t.Fatalf("incorrect refreshed node: %+v", got)
			}
			if test.observation.State == "Off" && probes != 0 {
				t.Fatal("attempted to reach or start a stopped VM")
			}
		})
	}
}

func TestOrchestratorEndpointRefreshCascadesToOfflineChildrenAndRetriesPartialPersistence(t *testing.T) {
	r := endpointTestReconciler(t)
	ctx := context.Background()
	parent := endpointTestNode("orchestrator", "192.0.2.10", "orchestrator-vm")
	parent.Role = "isolated-orchestrator"
	parent.Labels["lablink.orchestrator_id"] = "orch-1"
	if err := r.reg.SetNode(parent); err != nil {
		t.Fatal(err)
	}
	record := isolatedstate.Orchestrator{
		ID: "orch-1", NodeName: parent.Name, HostNode: "host", PhysicalHostID: "host-1",
		HyperVVMID: optionalTrimmed("orchestrator-vm"), MainMAC: optionalTrimmed("02155D000001"),
		MainIP: optionalTrimmed("192.0.2.10"), MainVSwitch: "Default Switch",
		LifecycleState: isolatedstate.OrchestratorReady, AgentPort: 9091, MaxNetworks: 16, MaxVMs: 100,
	}
	if err := r.state.PutOrchestrator(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := r.state.PutNetwork(ctx, isolatedstate.PrivateNetwork{
		ID: "network", OrchestratorID: record.ID, SubnetIndex: 0,
		CIDR: "192.168.240.0/26", GatewayIPv4: "192.168.240.1",
		OrchestratorMAC: "02155D000010", LifecycleState: isolatedstate.NetworkReady,
	}); err != nil {
		t.Fatal(err)
	}
	var children []isolatedstate.IsolatedVM
	for i := 0; i < 2; i++ {
		id := fmt.Sprintf("guest-%d", i)
		vm := isolatedstate.IsolatedVM{
			ID: id, NodeName: id, OrchestratorID: record.ID, NetworkID: "network",
			HyperVName: id, IPv4: fmt.Sprintf("192.168.240.%d", 10+i),
			MAC: fmt.Sprintf("02155D00002%d", i), GuestOS: isolatedstate.GuestLinux,
			LifecycleState: isolatedstate.VMReady,
		}
		if err := r.state.PutVM(ctx, vm); err != nil {
			t.Fatal(err)
		}
		children = append(children, vm)
		if err := r.state.PutRelay(ctx, isolatedstate.RelayAllocation{
			ID: "relay-" + id, VMID: id, OrchestratorID: record.ID,
			ListenPort: 20000 + i, TargetIPv4: vm.IPv4, TargetPort: 9091,
			LifecycleState: isolatedstate.RelayReady,
		}); err != nil {
			t.Fatal(err)
		}
		if err := r.state.PutNAT(ctx, isolatedstate.NATAllocation{
			VMID: id, OrchestratorID: record.ID, State: isolatedstate.NATDisabled, ConntrackMark: int64(i + 1),
		}); err != nil {
			t.Fatal(err)
		}
		if err := r.reg.SetNode(&registry.Node{
			Name: id, Address: fmt.Sprintf("192.0.2.10:%d", 20000+i),
			TLSServerName: id, TransportMode: "mtls",
			Labels: map[string]string{"lablink.orchestrator_id": record.ID, "lablink.kind": "isolated-vm"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	r.discover = func(context.Context, string, []vmEndpointBinding) ([]vmEndpointObservation, error) {
		return []vmEndpointObservation{{
			NodeName: parent.Name, VMID: "orchestrator-vm", MAC: "02155D000001",
			State: "Running", Addresses: []string{"192.0.2.20"},
		}}, nil
	}
	attempt := 0
	r.probe = func(_ context.Context, node *registry.Node, _ string) error {
		if node.Name != parent.Name {
			t.Fatal("offline children must not be probed to refresh their relay endpoints")
		}
		attempt++
		if attempt == 1 {
			// A concurrent registry edit must prevent a partially committed subtree.
			node, _ := r.reg.GetNode("guest-1")
			node.Labels["user-context"] = "preserve"
			return r.reg.SetNode(node)
		}
		return nil
	}
	if err := r.Reconcile(ctx); err == nil {
		t.Fatal("concurrent registry change was not detected")
	}
	for _, name := range []string{parent.Name, "guest-0", "guest-1"} {
		node, _ := r.reg.GetNode(name)
		if nodeHost(node.Address) != "192.0.2.10" {
			t.Fatal("subtree was only partially refreshed")
		}
	}
	// MainIP was persisted before the failed registry write; retry must still
	// refresh all descendants instead of treating the matching MainIP as done.
	for i := 0; i < 2; i++ {
		if err := r.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for i, child := range children {
		node, _ := r.reg.GetNode(child.NodeName)
		if node.Address != fmt.Sprintf("192.0.2.20:%d", 20000+i) || node.TLSServerName != child.NodeName {
			t.Fatalf("child endpoint was not refreshed: %+v", node)
		}
		vm, err := r.state.GetVM(ctx, child.ID)
		if err != nil || !reflect.DeepEqual(vm, child) {
			t.Fatalf("private VM configuration changed: %+v %v", vm, err)
		}
		nat, err := r.state.GetNAT(ctx, child.ID)
		if err != nil || nat.State != isolatedstate.NATDisabled || nat.ConntrackMark != int64(i+1) {
			t.Fatalf("NAT setting changed: %+v %v", nat, err)
		}
	}
	got, err := r.state.GetOrchestrator(ctx, record.ID)
	if err != nil || valueOrEmpty(got.MainIP) != "192.0.2.20" || got.HyperVVMID == nil || *got.HyperVVMID != "orchestrator-vm" {
		t.Fatalf("orchestrator endpoint was not persisted: %+v %v", got, err)
	}
}

func TestVMEndpointProbeRetainsExpectedMTLSIdentityWithoutProtocolGate(t *testing.T) {
	address, transport := startEnrollmentMTLSAgent(t, "expected-guest")
	pool := agentclient.NewPool("", transport)
	defer pool.Close()
	r := &VMEndpointReconciler{pool: pool}
	node := &registry.Node{Name: "guest", TLSServerName: "expected-guest", TransportMode: "mtls"}
	if err := r.probeEndpoint(context.Background(), node, address); err != nil {
		t.Fatalf("ordinary mTLS agent rejected: %v", err)
	}
	node.TLSServerName = "another-guest"
	if err := r.probeEndpoint(context.Background(), node, address); err == nil {
		t.Fatal("IP reuse by another TLS identity was accepted")
	}
}

type endpointMirrorAgent struct {
	pb.UnimplementedNodeAgentServer
	nodes []*registry.Node
	t     *testing.T
}

func (a *endpointMirrorAgent) ManageVM(req *pb.ManageVMRequest, stream grpc.ServerStreamingServer[pb.ManageVMResponse]) error {
	if req.ToolName != "list_isolated_orchestrators" || string(req.ArgumentsJson) != `{"target":"localhost"}` {
		a.t.Errorf("refresh did not reuse the existing read-only operation: %+v", req)
	}
	nodes, _ := json.Marshal(a.nodes)
	result, _ := json.Marshal(mcp.NewToolResultText("[]"))
	return stream.Send(&pb.ManageVMResponse{NodesJson: nodes, ResultJson: result})
}

func TestRestrictedVMEndpointRefreshUpdatesOperatorMirror(t *testing.T) {
	r := endpointTestReconciler(t)
	guest := endpointTestNode("guest", "192.0.2.10", "vm-1")
	unreported := endpointTestNode("unreported", "192.0.2.11", "vm-2")
	if err := syncLocalVMNodes(r.reg, "hyperv", []*registry.Node{guest, unreported}); err != nil {
		t.Fatal(err)
	}
	fresh := *guest
	fresh.Address = "192.0.2.20:9091"
	address, transport := startEnrollmentMTLSAgentServer(t, "hyperv", &endpointMirrorAgent{nodes: []*registry.Node{&fresh}, t: t})
	r.pool.Close()
	r.pool = agentclient.NewPool("", transport)
	t.Cleanup(r.pool.Close)
	if err := r.reg.SetNode(&registry.Node{
		Name: "hyperv", Address: address, TLSServerName: "hyperv", Labels: map[string]string{"lablink.local_hyperv": "true"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := r.reg.GetNode(guest.Name)
	if got.Address != fresh.Address || got.Labels[localVMSourceLabel] != "hyperv" || got.TLSServerName != guest.TLSServerName {
		t.Fatalf("operator mirror retained a stale endpoint: %+v", got)
	}
	if _, found := r.reg.GetNode(unreported.Name); !found {
		t.Fatal("read-only endpoint refresh deleted a node missing from its snapshot")
	}
}

func TestRestrictedEndpointRefreshDoesNotQueueBehindVMCreation(t *testing.T) {
	host := &LocalVMHost{}
	host.mu.Lock()
	defer host.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := make(chan error, 1)
	go func() {
		_, _, err := host.Call(ctx, &pb.ManageVMRequest{ToolName: "list_isolated_orchestrators"})
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("busy host did not bound refresh: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("endpoint refresh queued behind a VM operation")
	}
}
