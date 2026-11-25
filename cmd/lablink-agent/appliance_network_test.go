package main

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/nijosmsft/lablink/internal/appliance"
)

type networkTestCompiler struct {
	snapshots []appliance.StaticSnapshot
}

func (c *networkTestCompiler) Compile(_ context.Context, snapshot appliance.StaticSnapshot) (appliance.CompiledApply, error) {
	c.snapshots = append(c.snapshots, snapshot)
	return appliance.CompiledApply{CompiledHash: "network-test"}, nil
}

type networkTestTarget struct {
	applies   int
	verifyErr bool
}

type networkTestListener struct {
	net.Listener
	once    sync.Once
	release func()
}

func (l *networkTestListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(l.release)
	return err
}

func (t *networkTestTarget) ActivateEmergency(context.Context) error { return nil }
func (t *networkTestTarget) Apply(context.Context, appliance.CompiledApply) error {
	t.applies++
	return nil
}
func (t *networkTestTarget) Verify(context.Context, appliance.CompiledApply) (appliance.Verification, error) {
	return appliance.Verification{Matched: !t.verifyErr, Detail: "injected policy mismatch"}, nil
}

func TestManagementIPChangeRebindsRelaysAndVerifiesPolicyWithoutChangingPrivateConfiguration(t *testing.T) {
	for _, failure := range []string{"none", "relay", "policy", "relay-address-reverted", "policy-address-reverted"} {
		t.Run(failure, func(t *testing.T) {
			ctx := context.Background()
			store, err := appliance.Open(filepath.Join(t.TempDir(), "appliance.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			config := appliance.StaticConfig{
				Networks: []appliance.StaticNetwork{{
					ID: "net-1", CIDR: "192.168.240.0/26", GatewayIPv4: "192.168.240.1",
					NICMAC: "02155D000001", InterfaceName: "eth1",
				}},
				Guests: []appliance.StaticGuest{
					{ID: "guest-1", NetworkID: "net-1", IPv4: "192.168.240.10", MAC: "02155D000010"},
					{ID: "guest-2", NetworkID: "net-1", IPv4: "192.168.240.11", MAC: "02155D000011"},
				},
				Relays: []appliance.StaticRelay{
					{ID: "relay-1", VMID: "guest-1", ListenPort: 20000, TargetIPv4: "192.168.240.10", TargetPort: 9091},
					{ID: "relay-2", VMID: "guest-2", ListenPort: 20001, TargetIPv4: "192.168.240.11", TargetPort: 9091},
				},
				NAT: []appliance.StaticNAT{
					{VMID: "guest-1", ConntrackMark: 101, Enabled: true},
					{VMID: "guest-2", ConntrackMark: 102, Enabled: false},
				},
			}
			if err := store.ReplaceStaticConfig(ctx, config); err != nil {
				t.Fatal(err)
			}
			var listens []string
			failRelay := false
			var listenerMu sync.Mutex
			boundAddresses := make(map[string]bool)
			relay, err := appliance.NewRelayManager(store, appliance.RelayManagerOptions{
				CurrentMainIPv4: func(context.Context) (string, error) { return "192.0.2.10", nil },
				Listen: func(_ context.Context, _, address string) (net.Listener, error) {
					state, err := store.Status(ctx)
					if err != nil || state.Ready {
						t.Errorf("appliance was ready while changing listeners: %+v %v", state, err)
					}
					listens = append(listens, address)
					if failRelay && strings.HasSuffix(address, ":20001") {
						return nil, errors.New("injected listener failure")
					}
					listenerMu.Lock()
					defer listenerMu.Unlock()
					if boundAddresses[address] {
						return nil, errors.New("address already in use")
					}
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						return nil, err
					}
					boundAddresses[address] = true
					return &networkTestListener{Listener: listener, release: func() {
						listenerMu.Lock()
						delete(boundAddresses, address)
						listenerMu.Unlock()
					}}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = relay.Shutdown(ctx) })
			if err := relay.Start(ctx); err != nil {
				t.Fatal(err)
			}
			compiler := &networkTestCompiler{}
			target := &networkTestTarget{}
			manager, err := appliance.NewApplyManager(appliance.ApplyManagerOptions{Store: store, Compiler: compiler, Target: target})
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.ApplyStaticConfig(ctx); err != nil {
				t.Fatal(err)
			}
			before, err := store.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			service := &applianceRPC{enabled: true, store: store, relay: relay, apply: manager, networkIP: "192.0.2.10"}
			failRelay = strings.HasPrefix(failure, "relay")
			target.verifyErr = strings.HasPrefix(failure, "policy")
			desiredIP := "192.0.2.20"
			err = service.reconcileManagementIPv4(ctx, "192.0.2.20")
			if failure != "none" {
				state, stateErr := store.Status(ctx)
				if err == nil || stateErr != nil || state.Ready || service.networkIP != "192.0.2.10" {
					t.Fatalf("failed repair was declared complete: %v %+v %v", err, state, stateErr)
				}
				failRelay, target.verifyErr = false, false
				if strings.HasSuffix(failure, "address-reverted") {
					desiredIP = "192.0.2.10"
				}
				err = service.reconcileManagementIPv4(ctx, desiredIP)
			}
			if err != nil {
				t.Fatal(err)
			}
			after, err := store.Snapshot(ctx)
			if err != nil || !after.Status.Ready {
				t.Fatalf("repair not verified: %+v %v", after.Status, err)
			}
			if !reflect.DeepEqual(before.Networks, after.Networks) ||
				!reflect.DeepEqual(before.Guests, after.Guests) || !reflect.DeepEqual(before.NAT, after.NAT) {
				t.Fatal("management IP repair altered private networking or NAT policy")
			}
			for _, bound := range after.Relays {
				if bound.BoundMainIP != desiredIP || bound.LastBindError != "" {
					t.Fatalf("relay retained the old endpoint: %+v", bound)
				}
			}
			applies, binds := target.applies, len(listens)
			if applies < 2 {
				t.Fatal("IP change did not reapply and verify the persisted policy")
			}
			if err := service.reconcileManagementIPv4(ctx, desiredIP); err != nil ||
				target.applies != applies || len(listens) != binds {
				t.Fatal("unchanged management IP caused unnecessary re-plumbing")
			}
		})
	}
}
