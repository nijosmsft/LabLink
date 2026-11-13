package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/isolated"
	pb "github.com/nijosmsft/lablink/proto/agent"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	gproto "google.golang.org/protobuf/proto"
)

func TestNormalAgentCompatibility(t *testing.T) {
	server := &agentServer{}
	info, err := server.GetInfo(context.Background(), &pb.GetInfoRequest{})
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if len(info.Capabilities) != 0 || info.ProtocolVersion != 0 ||
		info.ApplianceReady || info.ApplianceGeneration != 0 ||
		info.ApplianceError != "" {
		t.Fatalf("ordinary agent unexpectedly reports appliance state: %+v", info)
	}
	_, err = server.GetApplianceState(context.Background(), &pb.GetApplianceStateRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("GetApplianceState error = %v, want FailedPrecondition", err)
	}
}

func TestApplianceStartupReadinessAndCapabilities(t *testing.T) {
	path := filepath.Join(t.TempDir(), "appliance.db")
	service := openApplianceRPC(applianceConfig{Enabled: true, DBPath: path}, "linux")
	t.Cleanup(func() { _ = service.Close() })
	if service.startupErr != nil {
		t.Fatalf("openApplianceRPC: %v", service.startupErr)
	}

	server := &agentServer{appliance: service}
	info, err := server.GetInfo(context.Background(), &pb.GetInfoRequest{})
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if info.ApplianceReady {
		t.Fatal("appliance skeleton reported ready without an external apply engine")
	}
	if info.ProtocolVersion != isolated.MaximumProtocolVersion {
		t.Fatalf("protocol version = %d, want %d",
			info.ProtocolVersion, isolated.MaximumProtocolVersion)
	}
	if len(info.Capabilities) != len(isolated.RequiredOrchestratorCapabilities()) {
		t.Fatalf("capabilities = %v", info.Capabilities)
	}
	for _, capability := range isolated.RequiredOrchestratorCapabilities() {
		found := false
		for _, reported := range info.Capabilities {
			found = found || reported == string(capability)
		}
		if !found {
			t.Errorf("missing capability %q", capability)
		}
	}
	if !strings.Contains(info.ApplianceError, "external apply engine") {
		t.Fatalf("appliance error = %q, want external apply readiness explanation",
			info.ApplianceError)
	}

	state, err := server.GetApplianceState(context.Background(), &pb.GetApplianceStateRequest{})
	if err != nil {
		t.Fatalf("GetApplianceState: %v", err)
	}
	if state.Appliance.Ready ||
		!strings.Contains(state.Appliance.Error, "external apply engine") {
		t.Fatalf("unexpected appliance state: %+v", state.Appliance)
	}
}

func TestApplianceConfigAndCorruptStateFailClosed(t *testing.T) {
	getenv := func(key string) string {
		switch key {
		case applianceModeEnv:
			return "definitely"
		case applianceDBEnv:
			return "ignored.db"
		default:
			return ""
		}
	}
	cfg, err := resolveApplianceConfig(false, "", getenv)
	if err == nil || !cfg.Enabled {
		t.Fatalf("invalid appliance mode resolved as cfg=%+v err=%v", cfg, err)
	}

	path := filepath.Join(t.TempDir(), "corrupt.db")
	if err := os.WriteFile(path, []byte("not sqlite"), 0o600); err != nil {
		t.Fatalf("write corrupt state: %v", err)
	}
	service := openApplianceRPC(applianceConfig{Enabled: true, DBPath: path}, "linux")
	t.Cleanup(func() { _ = service.Close() })
	if service.startupErr == nil {
		t.Fatal("corrupt appliance state unexpectedly opened")
	}
	info, err := (&agentServer{appliance: service}).GetInfo(
		context.Background(), &pb.GetInfoRequest{})
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if info.ApplianceReady || info.ApplianceError == "" {
		t.Fatalf("corrupt state did not fail closed: %+v", info)
	}
}

func TestApplianceRPCReplayConflictCollisionAndPendingApply(t *testing.T) {
	store, err := appliance.Open(filepath.Join(t.TempDir(), "appliance.db"))
	if err != nil {
		t.Fatalf("appliance.Open: %v", err)
	}

	t.Cleanup(func() { _ = store.Close() })
	if err := store.InstallAuthority(context.Background(), appliance.Authority{
		PhysicalHostID:       "host-1",
		HostLeaseID:          "lease-1",
		HostLeaseSecretHash:  testLeaseSecretHash(),
		HostLeaseExpiresUnix: time.Now().Add(time.Hour).Unix(),
		Fence:                7,
		ParentGeneration:     3,
		ParentState:          "active",
	}); err != nil {
		t.Fatalf("InstallAuthority: %v", err)
	}
	if err := store.SetReadiness(context.Background(), false, externalApplyPending); err != nil {
		t.Fatalf("SetReadiness: %v", err)
	}
	server := &agentServer{appliance: &applianceRPC{enabled: true, store: store}}
	ctx := context.Background()

	subnet := uint32(4)
	reserveHeader := rpcHeader("reserve-network", "reserve-hash", "", 0, 0, 7, 3)
	reserve, err := server.ReserveResources(ctx, &pb.ReserveResourcesRequest{
		Header: reserveHeader,
		Candidates: []*pb.ReservationCandidate{{
			ResourceKind: "network",
			ResourceId:   "network-1",
			SubnetIndex:  &subnet,
			Mac:          "02:00:00:00:10:01",
		}},
	})
	if err != nil {
		t.Fatalf("ReserveResources: %v", err)
	}
	if reserve.ReservationId == "" || len(reserve.Reservations) != 1 {
		t.Fatalf("unexpected reservation response: %+v", reserve)
	}
	replayedReserve, err := server.ReserveResources(ctx, &pb.ReserveResourcesRequest{
		Header: reserveHeader,
		Candidates: []*pb.ReservationCandidate{{
			ResourceKind: "network",
			ResourceId:   "network-1",
			SubnetIndex:  &subnet,
			Mac:          "02:00:00:00:10:01",
		}},
	})
	if err != nil {
		t.Fatalf("ReserveResources replay: %v", err)
	}
	if !replayedReserve.Mutation.Replayed {
		t.Fatal("reservation replay was not reported")
	}
	conflictingHeader := rpcHeader("reserve-network", "different-hash", "", 0, 0, 7, 3)
	_, err = server.ReserveResources(ctx, &pb.ReserveResourcesRequest{
		Header: conflictingHeader,
		Candidates: []*pb.ReservationCandidate{{
			ResourceKind: "network",
			ResourceId:   "network-1",
			SubnetIndex:  &subnet,
			Mac:          "02:00:00:00:10:01",
		}},
	})
	if status.Code(err) != codes.Aborted {
		t.Fatalf("hash conflict error = %v, want Aborted", err)
	}

	collisionHeader := rpcHeader("reserve-collision", "collision-hash", "", 0, 0, 7, 3)
	_, err = server.ReserveResources(ctx, &pb.ReserveResourcesRequest{
		Header: collisionHeader,
		Candidates: []*pb.ReservationCandidate{{
			ResourceKind: "network",
			ResourceId:   "network-2",
			SubnetIndex:  &subnet,
			Mac:          "02:00:00:00:10:02",
		}},
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("reservation collision error = %v, want AlreadyExists", err)
	}
	if len(status.Convert(err).Details()) != 1 {
		t.Fatalf("collision details = %v, want one ApplianceConflict",
			status.Convert(err).Details())
	}

	applyHeader := rpcHeader("apply-network", "apply-hash", "network-1", 0, 1, 7, 3)
	applied, err := server.ApplyPrivateNetwork(ctx, &pb.ApplyPrivateNetworkRequest{
		Header:        applyHeader,
		ReservationId: reserve.ReservationId,
		Cidr:          "10.80.1.0/26",
		GatewayIpv4:   "10.80.1.1",
		NicMac:        "02:00:00:00:10:01",
		InterfaceName: "isolated0",
		DnsServers:    []string{"10.0.0.1"},
	})
	if err != nil {
		t.Fatalf("ApplyPrivateNetwork: %v", err)
	}
	if applied.Network.State != "pending" ||
		applied.Network.Generation.DesiredGeneration != 1 ||
		applied.Network.Generation.AppliedGeneration != 0 ||
		applied.Network.Generation.ObservedGeneration != 0 {
		t.Fatalf("external apply was incorrectly reported as complete: %+v", applied.Network)
	}
	replayedApply, err := server.ApplyPrivateNetwork(ctx, &pb.ApplyPrivateNetworkRequest{
		Header:        applyHeader,
		ReservationId: reserve.ReservationId,
		Cidr:          "10.80.1.0/26",
		GatewayIpv4:   "10.80.1.1",
		NicMac:        "02:00:00:00:10:01",
		InterfaceName: "isolated0",
		DnsServers:    []string{"10.0.0.1"},
	})
	if err != nil {
		t.Fatalf("ApplyPrivateNetwork replay: %v", err)
	}
	if !replayedApply.Mutation.Replayed {
		t.Fatal("pending apply replay was not reported")
	}
	staleHeader := rpcHeader("apply-network-stale", "stale-hash", "network-1", 0, 1, 7, 3)
	_, err = server.ApplyPrivateNetwork(ctx, &pb.ApplyPrivateNetworkRequest{
		Header:        staleHeader,
		ReservationId: reserve.ReservationId,
		Cidr:          "10.80.1.0/26",
		GatewayIpv4:   "10.80.1.1",
		NicMac:        "02:00:00:00:10:01",
	})
	if status.Code(err) != codes.Aborted {
		t.Fatalf("generation conflict error = %v, want Aborted", err)
	}

	state, err := server.GetApplianceState(ctx, &pb.GetApplianceStateRequest{})
	if err != nil {
		t.Fatalf("GetApplianceState: %v", err)
	}
	if len(state.ApplyIntents) != 1 || state.ApplyIntents[0].Phase != "pending" {
		t.Fatalf("pending intent not reported: %+v", state.ApplyIntents)
	}
	if state.Appliance.Ready {
		t.Fatal("appliance became ready with pending external apply")
	}
}

func TestApplianceAuthorityRejectsUnauthenticatedEqualFenceAndReleasedLease(t *testing.T) {
	store, err := appliance.Open(filepath.Join(t.TempDir(), "appliance.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	expires := time.Now().Add(time.Hour).Unix()
	secret := []byte("current-secret")
	sum := sha256.Sum256(secret)
	current := appliance.Authority{
		PhysicalHostID: "host-1", HostLeaseID: "lease-1",
		HostLeaseSecretHash:  hex.EncodeToString(sum[:]),
		HostLeaseExpiresUnix: expires, Fence: 7,
		ParentGeneration: 3, ParentState: "active",
	}
	if err := store.InstallAuthority(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	unauthenticated := &pb.MutationHeader{
		HostFence: 7, ParentResourceId: "orchestrator-1",
		ExpectedParentGeneration: 3,
	}
	if err := ensureInitialApplianceAuthority(
		context.Background(), store, unauthenticated); status.Code(err) != codes.Aborted {
		t.Fatalf("unauthenticated equal fence error = %v", err)
	}
	authenticated := &pb.MutationHeader{
		PhysicalHostId: "host-1", HostLeaseId: "lease-1",
		HostLeaseSecret: secret, HostLeaseExpiresUnix: expires,
		HostFence: 7, ParentResourceId: "orchestrator-1",
		ExpectedParentGeneration: 3,
	}
	if err := ensureInitialApplianceAuthority(
		context.Background(), store, authenticated); err != nil {
		t.Fatalf("authenticated equal fence: %v", err)
	}
	if _, err := store.ReleaseAuthority(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if err := ensureInitialApplianceAuthority(
		context.Background(), store, authenticated); status.Code(err) != codes.Aborted {
		t.Fatalf("released authority error = %v", err)
	}
	next := gproto.Clone(authenticated).(*pb.MutationHeader)
	next.HostFence = 8
	next.HostLeaseId = "lease-2"
	next.HostLeaseSecret = []byte("next-secret")
	next.HostLeaseExpiresUnix = time.Now().Add(2 * time.Hour).Unix()
	if err := ensureInitialApplianceAuthority(
		context.Background(), store, next); err != nil {
		t.Fatalf("higher-fence handoff after release: %v", err)
	}
}

func TestApplianceAuthorityHandoffPreservesFrozenCascade(t *testing.T) {
	store, err := appliance.Open(filepath.Join(t.TempDir(), "appliance.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	currentSecret := []byte("current-secret")
	currentSecretHash := sha256.Sum256(currentSecret)
	current := appliance.Authority{
		PhysicalHostID:       "host-1",
		HostLeaseID:          "lease-1",
		HostLeaseSecretHash:  hex.EncodeToString(currentSecretHash[:]),
		HostLeaseExpiresUnix: time.Now().Add(time.Hour).Unix(),
		Fence:                7,
		ParentGeneration:     3,
		ParentState:          "active",
	}
	if err := store.InstallAuthority(ctx, current); err != nil {
		t.Fatal(err)
	}

	const (
		cascadeOperationID  = "11111111-1111-4111-8111-111111111111"
		cascadePlanRevision = "r1-approved"
		cascadePlanHash     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	frozen, err := store.SetParentLifecycle(
		ctx, current, 3, 4, "frozen",
		cascadeOperationID, cascadePlanRevision, cascadePlanHash,
		[]appliance.CascadeAuthorityItem{{
			ItemID:       "22222222-2222-4222-8222-222222222222",
			ResourceKind: "network",
			ResourceID:   "33333333-3333-4333-8333-333333333333",
			Action:       "delete_private_switch", ExpectedGeneration: 1,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReleaseAuthority(ctx, frozen); err != nil {
		t.Fatal(err)
	}

	nextSecret := []byte("next-secret")
	nextExpiry := time.Now().Add(2 * time.Hour).Unix()
	nextHeader := &pb.MutationHeader{
		PhysicalHostId:           "host-1",
		HostLeaseId:              "lease-2",
		HostLeaseSecret:          nextSecret,
		HostLeaseExpiresUnix:     nextExpiry,
		HostFence:                8,
		ParentResourceId:         "orchestrator-1",
		ExpectedParentGeneration: 3,
		CascadeOperationId:       cascadeOperationID,
		CascadePlanRevision:      cascadePlanRevision,
		CascadePlanHash:          cascadePlanHash,
	}
	if err := ensureInitialApplianceAuthority(ctx, store, nextHeader); err != nil {
		t.Fatalf("higher-fence frozen handoff: %v", err)
	}

	installed, err := store.Authority(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nextSecretHash := sha256.Sum256(nextSecret)
	if installed.PhysicalHostID != "host-1" ||
		installed.HostLeaseID != "lease-2" ||
		installed.HostLeaseSecretHash != hex.EncodeToString(nextSecretHash[:]) ||
		installed.HostLeaseExpiresUnix != nextExpiry ||
		installed.Fence != 8 ||
		installed.ParentGeneration != 4 ||
		installed.ParentState != "frozen" ||
		installed.CascadeOperationID != cascadeOperationID ||
		installed.CascadePlanRevision != cascadePlanRevision ||
		installed.CascadePlanHash != cascadePlanHash ||
		installed.HandoffPending {
		t.Fatalf("installed authority lost handoff state: %+v", installed)
	}

	server := &agentServer{appliance: &applianceRPC{enabled: true, store: store}}
	state, err := server.SetApplianceParentLifecycle(
		ctx, &pb.SetApplianceParentLifecycleRequest{
			Header: nextHeader, State: "frozen", NewParentGeneration: 4,
			CascadeItems: []*pb.CascadeAuthorityItem{{
				ItemId:       "22222222-2222-4222-8222-222222222222",
				ResourceKind: "network",
				ResourceId:   "33333333-3333-4333-8333-333333333333",
				Action:       "delete_private_switch", ExpectedGeneration: 1,
			}},
		})
	if err != nil {
		t.Fatalf("idempotent frozen lifecycle after handoff: %v", err)
	}
	if !state.GetFrozen() || state.GetHostFence() != 8 ||
		state.GetParentGeneration() != 4 {
		t.Fatalf("idempotent lifecycle state = %+v", state)
	}
}

func rpcHeader(
	mutationID, semanticHash, resourceID string,
	expected, next, fence, parentGeneration uint64,
) *pb.MutationHeader {
	return &pb.MutationHeader{
		ParentOperationId:        "operation-" + mutationID,
		MutationId:               mutationID,
		SemanticHash:             semanticHash,
		ResourceId:               resourceID,
		ExpectedGeneration:       expected,
		NewGeneration:            next,
		HostFence:                fence,
		ExpectedParentGeneration: parentGeneration,
		PhysicalHostId:           "host-1",
		HostLeaseId:              "lease-1",
		HostLeaseSecret:          []byte("test-lease-secret"),
		HostLeaseExpiresUnix:     time.Now().Add(time.Hour).Unix(),
	}
}

func testLeaseSecretHash() string {
	sum := sha256.Sum256([]byte("test-lease-secret"))
	return hex.EncodeToString(sum[:])
}
