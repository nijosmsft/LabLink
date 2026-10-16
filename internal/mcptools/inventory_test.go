package mcptools

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/healthmon"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

type versionInfoAgent struct {
	pb.UnimplementedNodeAgentServer
	version string
}

func (a *versionInfoAgent) GetInfo(context.Context, *pb.GetInfoRequest) (*pb.GetInfoResponse, error) {
	return &pb.GetInfoResponse{
		Hostname: "node1", Os: "windows", Arch: "amd64", CpuCount: 8,
		MemoryBytes: 16 << 30, AgentVersion: a.version,
	}, nil
}

func TestListNodesExposesNonBlockingVersionWarning(t *testing.T) {
	agent := &versionInfoAgent{version: "v1.0.0"}
	address := startNodeAgent(t, agent)
	reg := registry.Load(filepath.Join(t.TempDir(), "nodes.json"))
	node := &registry.Node{
		Name: "node1", Address: address, OS: "windows", Arch: "amd64",
		TransportMode: string(security.TransportModeInsecure),
	}
	if err := reg.SetNode(node); err != nil {
		t.Fatal(err)
	}
	pool := agentclient.NewPool("", security.ClientTransportConfig{Mode: security.TransportModeInsecure})
	defer pool.Close()
	monitor := healthmon.New(reg, pool, "v2.0.0")
	previous := hmon
	SetHealthMonitor(monitor)
	t.Cleanup(func() { SetHealthMonitor(previous) })

	result, err := listNodesHandler(reg, pool)(context.Background(), reqNoToken(nil))
	if err != nil || result == nil || result.IsError {
		t.Fatalf("list nodes: result=%#v err=%v", result, err)
	}
	text := toolResultText(result)
	for _, want := range []string{
		"Agent Version", "Upgrade Recommended", "Version Warning",
		"v1.0.0", "true", "agent upgrade recommended",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("list_nodes missing %q:\n%s", want, text)
		}
	}
	if state := monitor.GetStatus("node1"); state.Status != "online" || !state.UpgradeRecommended {
		t.Fatalf("version mismatch affected node state: %+v", state)
	}
}
