package isolated

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/registry"
	pb "github.com/nijosmsft/lablink/proto/agent"
	"google.golang.org/grpc"
)

type pinRegistry struct{ node *registry.Node }

func (r pinRegistry) GetNode(name string) (*registry.Node, bool) { return r.node, name == r.node.Name }
func (r pinRegistry) NodesByRole(role string) []*registry.Node {
	if role == r.node.Role {
		return []*registry.Node{r.node}
	}
	return nil
}

type pinAgent struct {
	pb.NodeAgentClient
	info           *pb.GetInfoResponse
	calls          []*pb.PinOrchestratorIPv4Request
	alreadyStatic  bool
	beginError     bool
	reconnectError bool
	probes         int
}

func (a *pinAgent) GetInfo(context.Context, *pb.GetInfoRequest, ...grpc.CallOption) (*pb.GetInfoResponse, error) {
	a.probes++
	if a.reconnectError && a.probes > 1 {
		return nil, errors.New("connection lost")
	}
	return a.info, nil
}

func (a *pinAgent) PinOrchestratorIPv4(_ context.Context, req *pb.PinOrchestratorIPv4Request, _ ...grpc.CallOption) (*pb.PinOrchestratorIPv4Response, error) {
	a.calls = append(a.calls, req)
	if a.beginError {
		return nil, errors.New("apply failed")
	}
	if a.alreadyStatic || req.ConfirmToken != "" {
		return &pb.PinOrchestratorIPv4Response{Message: "unchanged or confirmed"}, nil
	}
	return &pb.PinOrchestratorIPv4Response{ConfirmToken: "pending"}, nil
}

type pinPool struct {
	agent  *pinAgent
	resets int
}

func (p *pinPool) GetEndpointClient(agentclient.Endpoint) (pb.NodeAgentClient, error) {
	return p.agent, nil
}
func (p *pinPool) ResetEndpoint(agentclient.Endpoint) { p.resets++ }

func TestManagementPinUsesFreshVerifiedConnectionAndNeverReplaysApply(t *testing.T) {
	for _, tt := range []struct {
		name                                                        string
		static, legacy, beginError, reconnectError, nonOrchestrator bool
		wantCalls, wantResets                                       int
		wantError                                                   string
	}{
		{"new-or-reconnected", false, false, false, false, false, 2, 1, ""},
		{"already-static", true, false, false, false, false, 1, 0, ""},
		{"legacy-agent", false, true, false, false, false, 0, 0, "does not support"},
		{"failed-apply", false, false, true, false, false, 1, 0, "pin failed"},
		{"failed-reconnect", false, false, false, true, false, 1, 1, "awaiting DHCP rollback"},
		{"ordinary-guest", false, false, false, false, true, 0, 0, "no registered isolated orchestrator"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			node := &registry.Node{
				Name: "orchestrator-test", Address: "172.22.22.219:9091",
				Role: isolatedOrchestratorRole, TransportMode: "mtls", TLSServerName: "orchestrator-test",
				Labels: map[string]string{orchestratorIDLabel: "test-id"},
			}
			if tt.nonOrchestrator {
				node.Role = "guest"
			}
			info := &pb.GetInfoResponse{ApplianceReady: true, ProtocolVersion: MaximumProtocolVersion}
			for _, cap := range RequiredOrchestratorCapabilities() {
				info.Capabilities = append(info.Capabilities, string(cap))
			}
			if !tt.legacy {
				info.Capabilities = append(info.Capabilities, appliance.ManagementIPCapability)
			}
			agent := &pinAgent{info: info, alreadyStatic: tt.static, beginError: tt.beginError, reconnectError: tt.reconnectError}
			pool := &pinPool{agent: agent}
			client := NewApplianceRPCClient(pinRegistry{node}, pool, "")
			_, err := client.PinManagementIPv4(context.Background(), "test-id")
			if tt.wantError == "" && err != nil || tt.wantError != "" && (err == nil || !strings.Contains(err.Error(), tt.wantError)) {
				t.Fatalf("error = %v, want %q", err, tt.wantError)
			}
			if len(agent.calls) != tt.wantCalls || pool.resets != tt.wantResets {
				t.Fatalf("RPC calls %d, resets %d", len(agent.calls), pool.resets)
			}
			for i, call := range agent.calls {
				if call.ExpectedIpv4 != "172.22.22.219" || i == 0 && call.ConfirmToken != "" || i == 1 && call.ConfirmToken != "pending" {
					t.Fatalf("incorrect management pin request: %+v", call)
				}
			}
		})
	}
}
