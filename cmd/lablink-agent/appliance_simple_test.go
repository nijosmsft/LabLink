package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nijosmsft/lablink/internal/appliance"
	pb "github.com/nijosmsft/lablink/proto/agent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNormalAgentDoesNotReportApplianceState(t *testing.T) {
	server := &agentServer{}
	info, err := server.GetInfo(context.Background(), &pb.GetInfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if info.ApplianceReady || info.ApplianceError != "" ||
		info.ProtocolVersion != 0 || len(info.Capabilities) != 0 {
		t.Fatalf("ordinary agent reported appliance state: %+v", info)
	}
	_, err = server.GetApplianceState(
		context.Background(), &pb.GetApplianceStateRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("GetApplianceState error = %v", err)
	}
}

func TestApplianceStateUsesStaticConfiguration(t *testing.T) {
	store, err := appliance.Open(
		filepath.Join(t.TempDir(), "appliance.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.ReplaceStaticConfig(
		context.Background(), appliance.StaticConfig{
			Networks: []appliance.StaticNetwork{{
				ID: "network-1", CIDR: "192.168.240.0/26",
				GatewayIPv4: "192.168.240.1",
				NICMAC:      "02155D000001", InterfaceName: "eth1",
			}},
		}); err != nil {
		t.Fatal(err)
	}
	server := &agentServer{appliance: &applianceRPC{
		enabled: true, store: store, mainInterface: "eth0",
	}}
	state, err := server.GetApplianceState(
		context.Background(), &pb.GetApplianceStateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.GetNetworks()) != 1 ||
		state.GetNetworks()[0].GetId() != "network-1" {
		t.Fatalf("unexpected state: %+v", state)
	}
}

func TestCompactMACAcceptsInventoryAndLinuxFormats(t *testing.T) {
	for _, value := range []string{
		"02155D7DFE8E",
		"02:15:5d:7d:fe:8e",
		"02-15-5D-7D-FE-8E",
	} {
		if got := compactMAC(value); got != "02155d7dfe8e" {
			t.Fatalf("compactMAC(%q) = %q", value, got)
		}
	}
}

func TestShutdownRelayForStaticReplaceBoundsPersistentConnections(t *testing.T) {
	started := time.Now()
	err := shutdownRelayForStaticReplace(
		context.Background(), 10*time.Millisecond,
		func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	)
	if err != nil {
		t.Fatalf("bounded shutdown: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded shutdown took %s", elapsed)
	}
}

func TestShutdownRelayForStaticReplacePreservesCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := shutdownRelayForStaticReplace(
		ctx, time.Second,
		func(ctx context.Context) error {
			return ctx.Err()
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown error = %v, want context cancellation", err)
	}
}
