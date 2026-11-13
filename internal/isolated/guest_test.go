package isolated

import (
	"context"
	"strings"
	"testing"

	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
)

type guestAllocationFake struct {
	snapshot appliance.DesiredSnapshot
	request  appliance.ReserveRequest
}

func (f *guestAllocationFake) GetApplianceState(context.Context, string) (appliance.DesiredSnapshot, error) {
	return f.snapshot, nil
}

func (f *guestAllocationFake) ReserveResources(_ context.Context, _ string, request appliance.ReserveRequest) (appliance.ReserveResult, error) {
	f.request = request
	return appliance.ReserveResult{Reservations: request.Reservations, ParentGeneration: 7}, nil
}

func TestGuestPlanAllocatesImmutableApplianceResources(t *testing.T) {
	client := &guestAllocationFake{}
	orchestrator := isolatedstate.Orchestrator{
		ID:                "11111111-1111-4111-8111-111111111111",
		DesiredGeneration: 6,
	}
	network := isolatedstate.PrivateNetwork{
		ID:             "22222222-2222-4222-8222-222222222222",
		OrchestratorID: orchestrator.ID, CIDR: "192.168.240.0/26",
		GatewayIPv4: "192.168.240.1", DNSServersJSON: `["10.0.0.53"]`,
		LifecycleState: isolatedstate.NetworkReady,
	}
	plan, err := (GuestDomain{Appliance: client}).ReserveAndPlan(context.Background(), CreateGuestRequest{
		OperationID: "33333333-3333-4333-8333-333333333333",
		VMID:        "44444444-4444-4444-8444-444444444444",
		RelayID:     "55555555-5555-4555-8555-555555555555",
		Network:     network, Orchestrator: orchestrator, DisplayName: "mutable",
		GuestOS: isolatedstate.GuestWindows, ProfileName: "windows", HostFence: 9,
		ExpectedParentGeneration: 6,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.VM.IPv4 != "192.168.240.10" || plan.VM.PrefixLength != 26 ||
		plan.VM.GatewayIPv4 != "192.168.240.1" || plan.Relay.ListenPort != appliance.RelayPortMin ||
		plan.NAT.ConntrackMark != 1 || plan.ResultingParentGeneration != 7 {
		t.Fatalf("unexpected guest plan: %+v", plan)
	}
	if plan.VM.HyperVName == plan.VM.DisplayName || plan.VM.NodeName == plan.VM.DisplayName {
		t.Fatal("mutable display name leaked into immutable infrastructure identity")
	}
	if len(client.request.Reservations) != 4 {
		t.Fatalf("reservations = %d, want IP/MAC/relay/conntrack", len(client.request.Reservations))
	}
}

func TestStaticGuestNetworkRendering(t *testing.T) {
	windows, err := WindowsStaticNetworkScript("192.168.240.10", 26, "192.168.240.1", "02155D010203", []string{"10.0.0.53"})
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{"Dhcp Disabled", "PrefixLength 26", "192.168.240.1", "Set-DnsClientServerAddress", "expectedMac"} {
		if !strings.Contains(windows, wanted) {
			t.Errorf("Windows static script missing %q", wanted)
		}
	}
	linux, err := LinuxStaticNetworkConfig("192.168.240.11", 26, "192.168.240.1", "02155D010204", []string{"10.0.0.53"})
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{"dhcp4: false", "192.168.240.11/26", "via: 192.168.240.1", "macaddress:", "10.0.0.53"} {
		if !strings.Contains(linux, wanted) {
			t.Errorf("Linux static network config missing %q", wanted)
		}
	}
	if !strings.Contains(linux, `macaddress: "02:15:5d:01:02:04"`) ||
		strings.Contains(linux, `macaddress: "02155d010204"`) {
		t.Fatalf("Linux static network config did not canonicalize the MAC:\n%s", linux)
	}
	if strings.Contains(linux, "dhcp4: true") {
		t.Fatal("isolated Linux config must not use DHCP")
	}
	bootstrap, err := LinuxStaticNetworkBootstrapScript(
		"192.168.240.11", 26, "192.168.240.1", "02155D010204", []string{"10.0.0.53"})
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{
		"MACAddress=02:15:5d:01:02:04", "Address=192.168.240.11/26",
		"Gateway=192.168.240.1", "DNS=10.0.0.53",
		"ip address add 192.168.240.11/26", "ISOLATED_STATIC_IPV4_VERIFY_FAILED",
	} {
		if !strings.Contains(bootstrap, wanted) {
			t.Errorf("Linux static network bootstrap missing %q", wanted)
		}
	}
	windowsDNS, err := WindowsDNSUpdateScript("02155D010203", []string{"10.0.0.53", "10.0.0.54"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(windowsDNS, "Set-DnsClientServerAddress") ||
		!strings.Contains(windowsDNS, "'10.0.0.53','10.0.0.54'") {
		t.Fatalf("Windows DNS update script is incomplete:\n%s", windowsDNS)
	}
	linuxDNS, err := LinuxDNSUpdateScript("02155D010204", []string{"10.0.0.53", "10.0.0.54"})
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{
		"expected_mac=\"02:15:5d:01:02:04\"", "DNS=10.0.0.53",
		"DNS=10.0.0.54", `resolvectl dns "$interface" 10.0.0.53 10.0.0.54`,
	} {
		if !strings.Contains(linuxDNS, wanted) {
			t.Errorf("Linux DNS update script missing %q", wanted)
		}
	}
}

func TestBootstrapAndDomainPolicy(t *testing.T) {
	if err := ValidateBootstrapPolicy(BootstrapNetworkNone, false, true, false, nil); err == nil {
		t.Fatal("NAT-off known download/bootstrap was accepted")
	}
	if err := ValidateBootstrapPolicy(BootstrapNetworkNAT, true, true, false, nil); err != nil {
		t.Fatalf("NAT-enabled bootstrap rejected: %v", err)
	}
	services := []ReachableService{
		{Kind: "dns", Address: "10.0.0.53"},
		{Kind: "domain_controller", Address: "10.0.0.54"},
	}
	if err := ValidateBootstrapPolicy(BootstrapNetworkNAT, true, true, true, services); err != nil {
		t.Fatalf("declared reachable domain services rejected: %v", err)
	}
	if err := ValidateBootstrapPolicy(BootstrapNetworkNAT, true, true, true, services[:1]); err == nil {
		t.Fatal("domain join without a declared domain controller was accepted")
	}
}

func TestRepairDecisionIncrementsOnlyOnRecreate(t *testing.T) {
	vm := isolatedstate.IsolatedVM{Incarnation: 4}
	healthy := GuestRepairObservation{
		HostIdentityValid: true, NICValid: true, TimeSyncEnabled: true,
		RelayValid: true, GuestReachable: true, StaticNetworkValid: true,
		NATValid: true, RegistryValid: true,
	}
	if decision := DecideGuestRepair(vm, healthy, nil); decision.Recreate || decision.NextIncarnation != 4 {
		t.Fatalf("healthy repair decision = %+v", decision)
	}
	healthy.RelayValid = false
	if decision := DecideGuestRepair(vm, healthy, nil); !decision.Recreate || decision.NextIncarnation != 5 {
		t.Fatalf("recreate decision = %+v", decision)
	}
}
