package agent

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestSimpleApplianceRPCContract(t *testing.T) {
	service := File_proto_agent_agent_proto.Services().ByName("NodeAgent")
	if service == nil {
		t.Fatal("NodeAgent service missing")
	}
	want := map[protoreflect.Name][2]protoreflect.FullName{
		"GetApplianceState": {
			"agent.GetApplianceStateRequest",
			"agent.GetApplianceStateResponse",
		},
		"ConfigureIsolatedAppliance": {
			"agent.ConfigureIsolatedApplianceRequest",
			"agent.ConfigureIsolatedApplianceResponse",
		},
		"GetRelayStats": {
			"agent.GetRelayStatsRequest",
			"agent.GetRelayStatsResponse",
		},
		"ValidateRelay": {
			"agent.ValidateRelayRequest",
			"agent.ValidateRelayResponse",
		},
	}
	for name, types := range want {
		method := service.Methods().ByName(name)
		if method == nil {
			t.Fatalf("NodeAgent missing RPC %q", name)
		}
		if method.Input().FullName() != types[0] ||
			method.Output().FullName() != types[1] {
			t.Fatalf("%s types = (%s, %s), want (%s, %s)",
				name, method.Input().FullName(), method.Output().FullName(),
				types[0], types[1])
		}
	}
	for _, removed := range []protoreflect.Name{
		"ReserveResources", "ReleaseResources",
		"ReleaseApplianceAuthority", "SetApplianceParentLifecycle",
		"ApplyPrivateNetwork", "RemovePrivateNetwork",
		"RegisterIsolatedGuest", "RemoveIsolatedGuest",
		"ApplyRelay", "RemoveRelay", "ListRelays",
		"RebindRelays", "AdoptRelay",
		"SetNatState", "ListNatState", "ReconcileNat",
	} {
		if service.Methods().ByName(removed) != nil {
			t.Errorf("removed RPC %q remains exposed", removed)
		}
	}
}

func TestGetInfoHasNoApplianceGeneration(t *testing.T) {
	fields := (&GetInfoResponse{}).ProtoReflect().Descriptor().Fields()
	if fields.ByName("appliance_generation") != nil {
		t.Fatal("GetInfoResponse still exposes appliance_generation")
	}
}
