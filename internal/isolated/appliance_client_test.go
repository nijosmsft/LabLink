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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeApplianceRegistry struct {
	nodes map[string]*registry.Node
}

func (f *fakeApplianceRegistry) GetNode(name string) (*registry.Node, bool) {
	node, ok := f.nodes[name]
	return node, ok
}

func (f *fakeApplianceRegistry) NodesByRole(role string) []*registry.Node {
	var result []*registry.Node
	for _, node := range f.nodes {
		if strings.EqualFold(node.Role, role) {
			result = append(result, node)
		}
	}
	return result
}

type fakeAppliancePool struct {
	clients   map[string]pb.NodeAgentClient
	endpoints []agentclient.Endpoint
	resets    []agentclient.Endpoint
}

func (f *fakeAppliancePool) GetEndpointClient(endpoint agentclient.Endpoint) (pb.NodeAgentClient, error) {
	f.endpoints = append(f.endpoints, endpoint)
	client := f.clients[endpoint.Address]
	if client == nil {
		return nil, errors.New("missing fake client")
	}
	return client, nil
}

func (f *fakeAppliancePool) ResetEndpoint(endpoint agentclient.Endpoint) {
	f.resets = append(f.resets, endpoint)
}

type fakeAppliancePBClient struct {
	pb.NodeAgentClient
	infoFn     func(context.Context) (*pb.GetInfoResponse, error)
	stateFn    func(context.Context, *pb.GetApplianceStateRequest) (*pb.GetApplianceStateResponse, error)
	reserveFn  func(context.Context, *pb.ReserveResourcesRequest) (*pb.ReserveResourcesResponse, error)
	applyNetFn func(context.Context, *pb.ApplyPrivateNetworkRequest) (*pb.ApplyPrivateNetworkResponse, error)
	rebindFn   func(context.Context, *pb.RebindRelaysRequest) (*pb.RebindRelaysResponse, error)
}

func (f *fakeAppliancePBClient) GetInfo(
	ctx context.Context,
	_ *pb.GetInfoRequest,
	_ ...grpc.CallOption,
) (*pb.GetInfoResponse, error) {
	return f.infoFn(ctx)
}

func (f *fakeAppliancePBClient) GetApplianceState(
	ctx context.Context,
	req *pb.GetApplianceStateRequest,
	_ ...grpc.CallOption,
) (*pb.GetApplianceStateResponse, error) {
	return f.stateFn(ctx, req)
}

func (f *fakeAppliancePBClient) ReserveResources(
	ctx context.Context,
	req *pb.ReserveResourcesRequest,
	_ ...grpc.CallOption,
) (*pb.ReserveResourcesResponse, error) {
	return f.reserveFn(ctx, req)
}

func (f *fakeAppliancePBClient) ApplyPrivateNetwork(
	ctx context.Context,
	req *pb.ApplyPrivateNetworkRequest,
	_ ...grpc.CallOption,
) (*pb.ApplyPrivateNetworkResponse, error) {
	return f.applyNetFn(ctx, req)
}

func (f *fakeAppliancePBClient) RebindRelays(
	ctx context.Context,
	req *pb.RebindRelaysRequest,
	_ ...grpc.CallOption,
) (*pb.RebindRelaysResponse, error) {
	return f.rebindFn(ctx, req)
}

func compatibleInfo() *pb.GetInfoResponse {
	capabilities := RequiredOrchestratorCapabilities()
	values := make([]string, len(capabilities))
	for i, capability := range capabilities {
		values[i] = string(capability)
	}
	return &pb.GetInfoResponse{
		AgentVersion: "v2", Capabilities: values, ProtocolVersion: 1,
		ApplianceReady: true, ApplianceGeneration: 9,
	}
}

func newApplianceClientTest(
	client pb.NodeAgentClient,
) (*ApplianceRPCClient, *fakeApplianceRegistry, *fakeAppliancePool) {
	node := &registry.Node{
		Name: "orch-node", Address: "10.0.0.1:9091", Role: isolatedOrchestratorRole,
		TransportMode: "mtls", TLSServerName: "orch-node",
		Labels: map[string]string{orchestratorIDLabel: orchAID},
	}
	reg := &fakeApplianceRegistry{nodes: map[string]*registry.Node{node.Name: node}}
	pool := &fakeAppliancePool{clients: map[string]pb.NodeAgentClient{node.Address: client}}
	return NewApplianceRPCClient(reg, pool, "server-v2"), reg, pool
}

func TestApplianceClientConvertsPagedStateAndPendingMutation(t *testing.T) {
	fake := &fakeAppliancePBClient{}
	fake.infoFn = func(context.Context) (*pb.GetInfoResponse, error) {
		return compatibleInfo(), nil
	}
	fake.stateFn = func(_ context.Context, req *pb.GetApplianceStateRequest) (*pb.GetApplianceStateResponse, error) {
		state := &pb.ApplianceState{
			SchemaVersion: 1, ProtocolVersion: 1, Ready: true,
			ApplianceGeneration: 8, InventoryGeneration: 7,
			Fence: &pb.FenceState{
				PhysicalHostId: testHostID, HostFence: 4, HostLeaseId: "lease",
				ParentResourceId: orchAID, ParentGeneration: 3,
			},
			MainIpv4: "10.0.0.1", PolicyVerified: true, Ipv4ForwardingEnabled: true,
		}
		if req.GetPageToken() == "" {
			subnet := uint32(2)
			return &pb.GetApplianceStateResponse{
				Appliance: state, NextPageToken: "next",
				Reservations: []*pb.Reservation{{
					Id: "reservation", ResourceKind: "network", ResourceId: networkAID,
					SubnetIndex: &subnet, ParentGeneration: 3,
				}},
				Networks: []*pb.PrivateNetwork{{
					Id: networkAID, Cidr: "192.168.240.128/26", GatewayIpv4: "192.168.240.129",
					NicMac: "00155D010203", DnsServers: []string{"1.1.1.1"},
					Generation: &pb.GenerationState{
						DesiredGeneration: 2, AppliedGeneration: 2,
						ObservedGeneration: 2, ParentGeneration: 3,
					},
					State: "active",
				}},
			}, nil
		}
		return &pb.GetApplianceStateResponse{
			Appliance: state,
			Guests: []*pb.IsolatedGuest{{
				Id: "guest", NetworkId: networkAID, Ipv4: "192.168.240.140",
				Generation: &pb.GenerationState{DesiredGeneration: 1},
			}},
			ApplyIntents: []*pb.ApplyIntent{{
				MutationId: "mutation", ResourceKind: "guest", ResourceId: "guest",
				SemanticHash: "hash", Phase: "staged",
			}},
		}, nil
	}
	fake.applyNetFn = func(_ context.Context, req *pb.ApplyPrivateNetworkRequest) (*pb.ApplyPrivateNetworkResponse, error) {
		if req.GetHeader().GetSemanticHash() != "semantic" || req.GetHeader().GetHostFence() != 4 {
			t.Fatalf("wire header = %+v", req.GetHeader())
		}
		return &pb.ApplyPrivateNetworkResponse{
			Network: &pb.PrivateNetwork{
				Id: networkAID, State: "pending",
				Generation: &pb.GenerationState{DesiredGeneration: 2, AppliedGeneration: 1, ObservedGeneration: 1},
			},
			Mutation: &pb.MutationResult{
				MutationId: "mutation", SemanticHash: "semantic",
				Generation:          &pb.GenerationState{DesiredGeneration: 2, AppliedGeneration: 1, ObservedGeneration: 1},
				ApplianceGeneration: 10,
			},
		}, nil
	}
	client, _, _ := newApplianceClientTest(fake)

	snapshot, err := client.InspectApplianceState(context.Background(), orchAID)
	if err != nil {
		t.Fatalf("InspectApplianceState: %v", err)
	}
	if snapshot.Fence.HostFence != 4 || snapshot.Desired.Authority.ParentGeneration != 3 ||
		len(snapshot.Desired.Networks) != 1 || snapshot.Desired.Networks[0].DNSServersJSON != `["1.1.1.1"]` ||
		len(snapshot.Desired.Guests) != 1 || len(snapshot.ApplyIntents) != 1 {
		t.Fatalf("snapshot conversion = %+v", snapshot)
	}
	result, err := client.ApplyPrivateNetwork(context.Background(), orchAID, ApplyPrivateNetworkInput{
		Header: MutationEnvelope{Header: appliance.MutationHeader{
			MutationID: "mutation", SemanticHash: "semantic", ResourceID: networkAID,
			ExpectedGeneration: 1, NewGeneration: 2, HostFence: 4,
		}},
	})
	if err != nil {
		t.Fatalf("ApplyPrivateNetwork: %v", err)
	}
	if !result.Pending || !result.Mutation.Pending || result.Mutation.ApplianceGeneration != 10 {
		t.Fatalf("pending mutation = %+v", result)
	}
}

func TestApplianceClientPreservesStaleGenerationAndCollisionDetails(t *testing.T) {
	tests := []struct {
		name      string
		detail    *pb.ApplianceConflict
		grpcCode  codes.Code
		wantCode  string
		collision bool
	}{
		{
			name: "stale generation", grpcCode: codes.Aborted, wantCode: string(appliance.CodeGenerationConflict),
			detail: &pb.ApplianceConflict{
				Code:       pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_GENERATION_CONFLICT,
				ResourceId: networkAID,
				Generation: &pb.GenerationState{DesiredGeneration: 4, AppliedGeneration: 3},
				Fence:      &pb.FenceState{HostFence: 8},
			},
		},
		{
			name: "port collision", grpcCode: codes.AlreadyExists, wantCode: string(appliance.CodePortInUse),
			collision: true,
			detail: &pb.ApplianceConflict{
				Code:       pb.ApplianceErrorCode_APPLIANCE_ERROR_CODE_PORT_IN_USE,
				ResourceId: networkAID, InventoryGeneration: 12,
				Inventory: &pb.InventorySummary{MaxGuests: 100, LiveGuests: 2, FreeRelayPortCount: 98},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeAppliancePBClient{}
			fake.infoFn = func(context.Context) (*pb.GetInfoResponse, error) {
				return compatibleInfo(), nil
			}
			fake.reserveFn = func(context.Context, *pb.ReserveResourcesRequest) (*pb.ReserveResourcesResponse, error) {
				st, err := status.New(test.grpcCode, test.wantCode).WithDetails(test.detail)
				if err != nil {
					t.Fatal(err)
				}
				return nil, st.Err()
			}
			client, _, _ := newApplianceClientTest(fake)
			_, err := client.ReserveResources(context.Background(), orchAID, appliance.ReserveRequest{
				Header:       appliance.MutationHeader{MutationID: "m"},
				Reservations: []appliance.Reservation{{ResourceKind: "relay", ResourceID: networkAID}},
			})
			if ErrorCode(err) != test.wantCode || status.Code(err) != test.grpcCode {
				t.Fatalf("error = %v, code = %s, grpc = %s", err, ErrorCode(err), status.Code(err))
			}
			var rpcErr *ApplianceStatusError
			if !errors.As(err, &rpcErr) || rpcErr.ResourceID != networkAID {
				t.Fatalf("status details not preserved: %#v", err)
			}
			var collision *appliance.CollisionError
			if errors.As(err, &collision) != test.collision {
				t.Fatalf("collision match = %v, want %v", collision != nil, test.collision)
			}
		})
	}
}

func TestApplianceClientFailsClosedForReadinessCapabilityAndIdentity(t *testing.T) {
	t.Run("readiness", func(t *testing.T) {
		fake := &fakeAppliancePBClient{}
		fake.infoFn = func(context.Context) (*pb.GetInfoResponse, error) {
			info := compatibleInfo()
			info.ApplianceReady = false
			info.ApplianceError = "policy restore failed"
			return info, nil
		}
		client, _, _ := newApplianceClientTest(fake)
		_, err := client.CheckReadiness(context.Background(), orchAID)
		if ErrorCode(err) != string(appliance.CodeNotReady) {
			t.Fatalf("readiness error = %v", err)
		}
	})
	t.Run("missing capability", func(t *testing.T) {
		fake := &fakeAppliancePBClient{}
		fake.infoFn = func(context.Context) (*pb.GetInfoResponse, error) {
			info := compatibleInfo()
			info.Capabilities = info.Capabilities[:1]
			return info, nil
		}
		client, _, _ := newApplianceClientTest(fake)
		_, err := client.CheckReadiness(context.Background(), orchAID)
		if ErrorCode(err) != "AGENT_CAPABILITY_MISSING" ||
			!strings.Contains(err.Error(), "update_agent(node=orch-node)") {
			t.Fatalf("capability error = %v", err)
		}
	})
	t.Run("strict identity", func(t *testing.T) {
		fake := &fakeAppliancePBClient{infoFn: func(context.Context) (*pb.GetInfoResponse, error) {
			return compatibleInfo(), nil
		}}
		client, reg, pool := newApplianceClientTest(fake)
		reg.nodes["orch-node"].TLSServerName = ""
		_, err := client.CheckReadiness(context.Background(), orchAID)
		if ErrorCode(err) != "ORCHESTRATOR_TLS_IDENTITY_REQUIRED" || len(pool.endpoints) != 0 {
			t.Fatalf("identity error = %v, endpoints = %v", err, pool.endpoints)
		}
	})
}

func TestApplianceClientCancellationAndAddressChangeReset(t *testing.T) {
	blocking := &fakeAppliancePBClient{}
	blocking.infoFn = func(ctx context.Context) (*pb.GetInfoResponse, error) {
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	client, _, _ := newApplianceClientTest(blocking)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.CheckReadiness(ctx, orchAID)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}

	ready := &fakeAppliancePBClient{infoFn: func(context.Context) (*pb.GetInfoResponse, error) {
		return compatibleInfo(), nil
	}}
	client, reg, pool := newApplianceClientTest(ready)
	if _, err := client.CheckReadiness(context.Background(), orchAID); err != nil {
		t.Fatal(err)
	}
	old := agentclient.Endpoint{Address: "10.0.0.1:9091", TLSServerName: "orch-node"}
	reg.nodes["orch-node"].Address = "10.0.0.2:9091"
	pool.clients["10.0.0.2:9091"] = ready
	if _, err := client.CheckReadiness(context.Background(), orchAID); err != nil {
		t.Fatal(err)
	}
	if len(pool.resets) != 1 || pool.resets[0] != old {
		t.Fatalf("resets = %v, want old endpoint", pool.resets)
	}
}

func TestApplianceClientRebindAlwaysResetsEndpoint(t *testing.T) {
	fake := &fakeAppliancePBClient{}
	fake.infoFn = func(context.Context) (*pb.GetInfoResponse, error) {
		return compatibleInfo(), nil
	}
	fake.rebindFn = func(context.Context, *pb.RebindRelaysRequest) (*pb.RebindRelaysResponse, error) {
		return &pb.RebindRelaysResponse{
			Mutation: &pb.MutationResult{MutationId: "rebind", SemanticHash: "hash"},
		}, nil
	}
	client, _, pool := newApplianceClientTest(fake)
	_, mutation, err := client.RebindRelays(context.Background(), orchAID, MutationEnvelope{
		Header: appliance.MutationHeader{MutationID: "rebind", SemanticHash: "hash"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if mutation.MutationID != "rebind" || len(pool.resets) != 1 {
		t.Fatalf("mutation = %+v, resets = %v", mutation, pool.resets)
	}
}
