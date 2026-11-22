package healthmon

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"
	"google.golang.org/grpc"
)

type recoveryProbeAgent struct {
	pb.UnimplementedNodeAgentServer
}

func (*recoveryProbeAgent) GetInfo(context.Context, *pb.GetInfoRequest) (*pb.GetInfoResponse, error) {
	return &pb.GetInfoResponse{Hostname: "recovered"}, nil
}

func TestRecoveryKeepsTheSuccessfullyProbedConnectionUsable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	pb.RegisterNodeAgentServer(server, &recoveryProbeAgent{})
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	pool := agentclient.NewPool("", security.ClientTransportConfig{Mode: security.TransportModeInsecure})
	defer pool.Close()
	monitor := New(registry.Load(filepath.Join(t.TempDir(), "nodes.json")), pool)
	monitor.deadThreshold = 1
	node := &registry.Node{Name: "recovering", Address: listener.Addr().String()}
	monitor.recordFailure(node)
	client, err := pool.GetClient(node.Address)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.GetInfo(ctx, &pb.GetInfoRequest{}); err != nil {
		t.Fatal(err)
	}
	monitor.RecordAuthenticatedProbeSuccess(node)
	if _, err := client.GetInfo(ctx, &pb.GetInfoRequest{}); err != nil {
		t.Fatalf("health recovery discarded a proven-live connection: %v", err)
	}
}

func TestRecordAuthenticatedProbeSuccessRevivesOfflineNode(t *testing.T) {
	reg := registry.Load(filepath.Join(t.TempDir(), "nodes.json"))
	pool := agentclient.NewPool("", security.ClientTransportConfig{Mode: security.TransportModeInsecure})
	defer pool.Close()

	monitor := New(reg, pool)
	monitor.deadThreshold = 1
	node := &registry.Node{
		Name:          "builder",
		Address:       "127.0.0.1:9091",
		TLSServerName: "builder",
	}

	staleCtx := monitor.NodeContext(node.Name)
	monitor.recordFailure(node)
	select {
	case <-staleCtx.Done():
	default:
		t.Fatal("offline node context was not cancelled")
	}

	before := time.Now()
	monitor.RecordAuthenticatedProbeSuccess(node)

	state := monitor.GetStatus(node.Name)
	if state.Status != "online" || state.ConsecutiveFails != 0 || state.LastSeen.Before(before) {
		t.Fatalf("unexpected recovered state: %+v", state)
	}
	freshCtx := monitor.NodeContext(node.Name)
	if freshCtx == staleCtx {
		t.Fatal("offline node context was not replaced")
	}
	select {
	case <-freshCtx.Done():
		t.Fatal("recovered node context is still cancelled")
	default:
	}
}

func TestVersionMismatchWarnsOnceAndNeverMarksNodeUnhealthy(t *testing.T) {
	reg := registry.Load(filepath.Join(t.TempDir(), "nodes.json"))
	pool := agentclient.NewPool("", security.ClientTransportConfig{Mode: security.TransportModeInsecure})
	defer pool.Close()
	monitor := New(reg, pool, "v2.0.0")
	node := &registry.Node{Name: "node1", Address: "127.0.0.1:9091"}

	monitor.RecordAuthenticatedProbeSuccess(node, "v1.0.0")
	monitor.RecordAuthenticatedProbeSuccess(node, "v1.0.0")

	state := monitor.GetStatus(node.Name)
	if state.Status != "online" || state.AgentVersion != "v1.0.0" ||
		!state.UpgradeRecommended || state.VersionWarning == "" {
		t.Fatalf("mismatch state = %+v", state)
	}
	if len(monitor.warnedVersionTuples) != 1 {
		t.Fatalf("warning tuple count = %d, want 1", len(monitor.warnedVersionTuples))
	}
	select {
	case <-monitor.NodeContext(node.Name).Done():
		t.Fatal("version mismatch cancelled the node context")
	default:
	}
}

func TestVersionMatchChangeAndEmptyValues(t *testing.T) {
	reg := registry.Load(filepath.Join(t.TempDir(), "nodes.json"))
	pool := agentclient.NewPool("", security.ClientTransportConfig{Mode: security.TransportModeInsecure})
	defer pool.Close()
	node := &registry.Node{Name: "node1", Address: "127.0.0.1:9091"}

	monitor := New(reg, pool, "v2.0.0")
	monitor.RecordAuthenticatedProbeSuccess(node, "v2.0.0")
	state := monitor.GetStatus(node.Name)
	if state.UpgradeRecommended || state.VersionWarning != "" || len(monitor.warnedVersionTuples) != 0 {
		t.Fatalf("matching versions warned: %+v", state)
	}

	monitor.RecordAuthenticatedProbeSuccess(node, "v1.0.0")
	monitor.RecordAuthenticatedProbeSuccess(node, "v1.1.0")
	state = monitor.GetStatus(node.Name)
	if state.AgentVersion != "v1.1.0" || !state.UpgradeRecommended ||
		len(monitor.warnedVersionTuples) != 2 {
		t.Fatalf("new version did not produce a new warning: %+v tuples=%d", state, len(monitor.warnedVersionTuples))
	}

	monitor.RecordAuthenticatedProbeSuccess(node, "")
	state = monitor.GetStatus(node.Name)
	if state.AgentVersion != "" || state.UpgradeRecommended || state.VersionWarning != "" {
		t.Fatalf("empty agent version should be informational only: %+v", state)
	}

	devMonitor := New(reg, pool, "dev")
	devMonitor.RecordAuthenticatedProbeSuccess(node, "dev")
	if state := devMonitor.GetStatus(node.Name); state.UpgradeRecommended || len(devMonitor.warnedVersionTuples) != 0 {
		t.Fatalf("matching dev versions warned: %+v", state)
	}
	emptyServerMonitor := New(reg, pool, "")
	emptyServerMonitor.RecordAuthenticatedProbeSuccess(node, "v1.0.0")
	if state := emptyServerMonitor.GetStatus(node.Name); state.UpgradeRecommended || len(emptyServerMonitor.warnedVersionTuples) != 0 {
		t.Fatalf("empty server version warned: %+v", state)
	}
}
