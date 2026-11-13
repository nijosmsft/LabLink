package agent

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestGetInfoWireCompatibility(t *testing.T) {
	var legacy []byte
	legacy = protowire.AppendTag(legacy, 1, protowire.BytesType)
	legacy = protowire.AppendString(legacy, "node-1")
	legacy = protowire.AppendTag(legacy, 2, protowire.BytesType)
	legacy = protowire.AppendString(legacy, "linux")
	legacy = protowire.AppendTag(legacy, 3, protowire.BytesType)
	legacy = protowire.AppendString(legacy, "amd64")
	legacy = protowire.AppendTag(legacy, 4, protowire.VarintType)
	legacy = protowire.AppendVarint(legacy, 8)
	legacy = protowire.AppendTag(legacy, 5, protowire.VarintType)
	legacy = protowire.AppendVarint(legacy, 16<<30)
	legacy = protowire.AppendTag(legacy, 6, protowire.BytesType)
	legacy = protowire.AppendString(legacy, "v1.0.0")

	var got GetInfoResponse
	if err := proto.Unmarshal(legacy, &got); err != nil {
		t.Fatalf("unmarshal legacy GetInfoResponse: %v", err)
	}
	if got.Hostname != "node-1" || got.Os != "linux" || got.Arch != "amd64" ||
		got.CpuCount != 8 || got.MemoryBytes != 16<<30 || got.AgentVersion != "v1.0.0" {
		t.Fatalf("legacy fields changed during unmarshal: hostname=%q os=%q arch=%q cpu_count=%d memory_bytes=%d agent_version=%q",
			got.GetHostname(), got.GetOs(), got.GetArch(), got.GetCpuCount(), got.GetMemoryBytes(), got.GetAgentVersion())
	}
	if len(got.Capabilities) != 0 || got.ProtocolVersion != 0 || got.ApplianceReady ||
		got.ApplianceGeneration != 0 || got.ApplianceError != "" {
		t.Fatalf("new fields did not retain proto3 defaults: capabilities=%q protocol_version=%d appliance_ready=%t appliance_generation=%d appliance_error=%q",
			got.GetCapabilities(), got.GetProtocolVersion(), got.GetApplianceReady(), got.GetApplianceGeneration(), got.GetApplianceError())
	}
}

func TestGetInfoAdditiveFieldNumbers(t *testing.T) {
	fields := (&GetInfoResponse{}).ProtoReflect().Descriptor().Fields()
	want := map[protoreflect.Name]protoreflect.FieldNumber{
		"hostname":             1,
		"os":                   2,
		"arch":                 3,
		"cpu_count":            4,
		"memory_bytes":         5,
		"agent_version":        6,
		"capabilities":         7,
		"protocol_version":     8,
		"appliance_ready":      9,
		"appliance_generation": 10,
		"appliance_error":      11,
	}
	if fields.Len() != len(want) {
		t.Fatalf("GetInfoResponse has %d fields, want %d", fields.Len(), len(want))
	}
	for name, number := range want {
		field := fields.ByName(name)
		if field == nil {
			t.Fatalf("GetInfoResponse missing field %q", name)
		}
		if field.Number() != number {
			t.Fatalf("GetInfoResponse.%s field number = %d, want %d", name, field.Number(), number)
		}
	}
}

func TestMutationHeaderContract(t *testing.T) {
	fields := (&MutationHeader{}).ProtoReflect().Descriptor().Fields()
	want := []protoreflect.Name{
		"parent_operation_id",
		"mutation_id",
		"semantic_hash",
		"resource_id",
		"expected_generation",
		"new_generation",
		"physical_host_id",
		"host_fence",
		"parent_resource_id",
		"expected_parent_generation",
		"host_lease_id",
		"host_lease_secret",
		"cascade_operation_id",
		"cascade_plan_revision",
		"cascade_plan_hash",
		"cascade_item_id",
		"host_lease_expires_unix",
		"cascade_resource_kind",
		"cascade_action",
	}

	t.Run("cascade authority item", func(t *testing.T) {
		requestFields := (&SetApplianceParentLifecycleRequest{}).
			ProtoReflect().Descriptor().Fields()
		if field := requestFields.ByName("cascade_items"); field == nil ||
			field.Number() != 4 || !field.IsList() ||
			field.Message().FullName() != "agent.CascadeAuthorityItem" {
			t.Fatalf("SetApplianceParentLifecycleRequest.cascade_items = %+v", field)
		}
		fields := (&CascadeAuthorityItem{}).ProtoReflect().Descriptor().Fields()
		want := []protoreflect.Name{
			"item_id", "resource_kind", "resource_id", "action",
			"expected_generation",
		}
		for index, name := range want {
			field := fields.ByName(name)
			if field == nil || field.Number() != protoreflect.FieldNumber(index+1) {
				t.Fatalf("CascadeAuthorityItem.%s = %+v", name, field)
			}
		}
	})
	if fields.Len() != len(want) {
		t.Fatalf("MutationHeader has %d fields, want %d", fields.Len(), len(want))
	}
	for i, name := range want {
		field := fields.ByName(name)
		if field == nil {
			t.Fatalf("MutationHeader missing field %q", name)
		}
		if field.Number() != protoreflect.FieldNumber(i+1) {
			t.Fatalf("MutationHeader.%s field number = %d, want %d", name, field.Number(), i+1)
		}
	}
}

func TestApplianceRPCContract(t *testing.T) {
	service := File_proto_agent_agent_proto.Services().ByName("NodeAgent")
	if service == nil {
		t.Fatal("NodeAgent service missing")
	}
	want := map[protoreflect.Name][2]protoreflect.FullName{
		"GetApplianceState":           {"agent.GetApplianceStateRequest", "agent.GetApplianceStateResponse"},
		"ReserveResources":            {"agent.ReserveResourcesRequest", "agent.ReserveResourcesResponse"},
		"ReleaseResources":            {"agent.ReleaseResourcesRequest", "agent.ReleaseResourcesResponse"},
		"ReleaseApplianceAuthority":   {"agent.MutationHeader", "agent.FenceState"},
		"SetApplianceParentLifecycle": {"agent.SetApplianceParentLifecycleRequest", "agent.FenceState"},
		"ApplyPrivateNetwork":         {"agent.ApplyPrivateNetworkRequest", "agent.ApplyPrivateNetworkResponse"},
		"RemovePrivateNetwork":        {"agent.RemovePrivateNetworkRequest", "agent.RemovePrivateNetworkResponse"},
		"RegisterIsolatedGuest":       {"agent.RegisterIsolatedGuestRequest", "agent.RegisterIsolatedGuestResponse"},
		"RemoveIsolatedGuest":         {"agent.RemoveIsolatedGuestRequest", "agent.RemoveIsolatedGuestResponse"},
		"ApplyRelay":                  {"agent.ApplyRelayRequest", "agent.Relay"},
		"RemoveRelay":                 {"agent.RemoveRelayRequest", "agent.Relay"},
		"ListRelays":                  {"agent.ListRelaysRequest", "agent.ListRelaysResponse"},
		"GetRelayStats":               {"agent.GetRelayStatsRequest", "agent.GetRelayStatsResponse"},
		"RebindRelays":                {"agent.RebindRelaysRequest", "agent.RebindRelaysResponse"},
		"ValidateRelay":               {"agent.ValidateRelayRequest", "agent.ValidateRelayResponse"},
		"AdoptRelay":                  {"agent.AdoptRelayRequest", "agent.Relay"},
		"SetNatState":                 {"agent.SetNatStateRequest", "agent.NatState"},
		"ListNatState":                {"agent.ListNatStateRequest", "agent.ListNatStateResponse"},
		"ReconcileNat":                {"agent.ReconcileNatRequest", "agent.ReconcileNatResponse"},
	}
	for name, types := range want {
		method := service.Methods().ByName(name)
		if method == nil {
			t.Fatalf("NodeAgent missing RPC %q", name)
		}
		if method.Input().FullName() != types[0] || method.Output().FullName() != types[1] {
			t.Fatalf("%s types = (%s, %s), want (%s, %s)",
				name, method.Input().FullName(), method.Output().FullName(), types[0], types[1])
		}
	}
}

func TestEveryMutationCarriesHeader(t *testing.T) {
	mutations := []proto.Message{
		&ReserveResourcesRequest{},
		&ReleaseResourcesRequest{},
		&ApplyPrivateNetworkRequest{},
		&RemovePrivateNetworkRequest{},
		&RegisterIsolatedGuestRequest{},
		&RemoveIsolatedGuestRequest{},
		&ApplyRelayRequest{},
		&RemoveRelayRequest{},
		&RebindRelaysRequest{},
		&AdoptRelayRequest{},
		&SetNatStateRequest{},
		&ReconcileNatRequest{},
	}
	headerName := protoreflect.FullName("agent.MutationHeader")
	for _, mutation := range mutations {
		descriptor := mutation.ProtoReflect().Descriptor()
		field := descriptor.Fields().ByName("header")
		if field == nil {
			t.Errorf("%s missing mutation header", descriptor.FullName())
			continue
		}
		if field.Number() != 1 || field.Message() == nil || field.Message().FullName() != headerName {
			t.Errorf("%s.header = field %d type %v, want field 1 agent.MutationHeader",
				descriptor.FullName(), field.Number(), field.Message())
		}
	}

	fields := (&ApplyRelayRequest{}).ProtoReflect().Descriptor().Fields()
	if fields.ByName("target_port") != nil {
		t.Fatal("ApplyRelayRequest must not expose target_port")
	}
}
