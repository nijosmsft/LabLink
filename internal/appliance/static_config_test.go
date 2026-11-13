package appliance

import (
	"context"
	"path/filepath"
	"testing"
)

func TestReplaceStaticConfigIsIdentityBasedAndIdempotent(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "appliance.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	config := StaticConfig{
		Networks: []StaticNetwork{{
			ID: "network-1", CIDR: "192.168.240.0/26",
			GatewayIPv4: "192.168.240.1", NICMAC: "02155D000001",
			InterfaceName: "eth1", DNSServersJSON: `["10.0.0.53"]`,
		}},
		Guests: []StaticGuest{{
			ID: "vm-1", NetworkID: "network-1",
			IPv4: "192.168.240.10", MAC: "02155D000002",
		}},
		Relays: []StaticRelay{{
			ID: "relay-1", VMID: "vm-1", ListenPort: 20000,
			TargetIPv4: "192.168.240.10", TargetPort: RelayTargetPort,
		}},
		NAT: []StaticNAT{{
			VMID: "vm-1", ConntrackMark: 1, Enabled: true,
		}},
	}
	for i := 0; i < 2; i++ {
		if err := store.ReplaceStaticConfig(context.Background(), config); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Networks) != 1 || len(snapshot.Guests) != 1 ||
		len(snapshot.Relays) != 1 || len(snapshot.NAT) != 1 {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	if snapshot.Relays[0].ListenPort != 20000 ||
		snapshot.NAT[0].ConntrackMark != 1 ||
		snapshot.NAT[0].State != "enabled" {
		t.Fatalf("unexpected relay/NAT: %+v %+v", snapshot.Relays[0], snapshot.NAT[0])
	}

	if err := store.ReplaceStaticConfig(context.Background(), StaticConfig{}); err != nil {
		t.Fatal(err)
	}
	empty, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.Networks)+len(empty.Guests)+len(empty.Relays)+len(empty.NAT) != 0 {
		t.Fatalf("static configuration was not removed: %+v", empty)
	}
}

func TestValidateStaticConfigRejectsCrossResourceCollisions(t *testing.T) {
	err := ValidateStaticConfig(StaticConfig{
		Networks: []StaticNetwork{{
			ID: "network-1", CIDR: "192.168.240.0/26",
			GatewayIPv4: "192.168.240.1",
		}},
		Guests: []StaticGuest{
			{ID: "vm-1", NetworkID: "network-1", IPv4: "192.168.240.10"},
			{ID: "vm-2", NetworkID: "network-1", IPv4: "192.168.240.11"},
		},
		NAT: []StaticNAT{
			{VMID: "vm-1", ConntrackMark: 1},
			{VMID: "vm-2", ConntrackMark: 1},
		},
	})
	if err == nil {
		t.Fatal("duplicate conntrack mark was accepted")
	}
}
