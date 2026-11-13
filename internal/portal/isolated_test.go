package portal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nijosmsft/lablink/internal/appliance"
	"github.com/nijosmsft/lablink/internal/isolated"
	"github.com/nijosmsft/lablink/internal/isolatedstate"
	"github.com/nijosmsft/lablink/internal/ops"
	"github.com/nijosmsft/lablink/internal/registry"
)

type fakeIsolatedAppliance struct {
	readiness map[string]isolated.ApplianceReadiness
	snapshots map[string]isolated.ApplianceSnapshot
	stats     map[string]appliance.RelayStats
	err       error
}

func (f *fakeIsolatedAppliance) CheckReadiness(
	_ context.Context,
	id string,
) (isolated.ApplianceReadiness, error) {
	return f.readiness[id], f.err
}

func (f *fakeIsolatedAppliance) InspectApplianceState(
	_ context.Context,
	id string,
) (isolated.ApplianceSnapshot, error) {
	return f.snapshots[id], f.err
}

func (f *fakeIsolatedAppliance) GetRelayStats(
	_ context.Context,
	_, relayID string,
) (appliance.RelayStats, error) {
	return f.stats[relayID], f.err
}

type legacyIsolatedState struct {
	err error
}

func (s legacyIsolatedState) ListOrchestrators(context.Context, string) ([]isolatedstate.Orchestrator, error) {
	return nil, s.err
}

func (s legacyIsolatedState) ListNetworks(context.Context, string) ([]isolatedstate.PrivateNetwork, error) {
	return nil, s.err
}

func (s legacyIsolatedState) ListVMs(context.Context, string, string) ([]isolatedstate.IsolatedVM, error) {
	return nil, s.err
}

func (s legacyIsolatedState) ListRelays(context.Context, string, string) ([]isolatedstate.RelayAllocation, error) {
	return nil, s.err
}

func (s legacyIsolatedState) QueryContext(context.Context, string, ...any) (*sql.Rows, error) {
	return nil, s.err
}

func TestIsolatedAPIAndRendering(t *testing.T) {
	ctx := context.Background()
	dir := portalTestDir(t)
	store, err := isolatedstate.Open(filepath.Join(dir, "isolated.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	mainIP := "10.40.0.2"
	orchVMID := "orch-guid"
	switchGUID := "switch-guid"
	adapterID := "adapter-guid"
	vmGUID := "vm-guid"
	vmAdapterID := "vm-adapter-guid"
	now := isolatedstate.UnixSeconds(100)
	if err := store.PutOrchestrator(ctx, isolatedstate.Orchestrator{
		ID: "orch-a", DisplayName: `<script>alert("orch")</script>`,
		PhysicalHostID: "host-a", HostNode: "hyperv-a", HyperVName: "LL-ORCH-A",
		HyperVVMID: &orchVMID, NodeName: "orch-node", ProfileName: "default",
		MainVSwitch: "External", MainIP: &mainIP, AgentPort: 9091,
		DesiredGeneration: 3, AppliedGeneration: 2, ObservedGeneration: 2,
		LifecycleState: isolatedstate.OrchestratorReady, HealthState: "healthy",
		MaxNetworks: 16, MaxVMs: 100, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("PutOrchestrator: %v", err)
	}
	if err := store.PutNetwork(ctx, isolatedstate.PrivateNetwork{
		ID: "network-a", OrchestratorID: "orch-a", DisplayName: "private-a",
		HyperVSwitchName: "LL-SW-A", HyperVSwitchGUID: &switchGUID,
		OrchestratorAdapterID: &adapterID, SubnetIndex: 2, CIDR: "10.60.0.0/26",
		GatewayIPv4: "10.60.0.1", OrchestratorMAC: "02-00-00-00-00-01",
		DNSServersJSON: `["10.60.0.2"]`, DesiredGeneration: 2,
		AppliedGeneration: 2, ObservedGeneration: 1,
		LifecycleState: isolatedstate.NetworkReady, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("PutNetwork: %v", err)
	}
	if _, err := store.ExecContext(ctx, `
		INSERT INTO isolated_vms (
			id, orchestrator_id, network_id, display_name, hyperv_name,
			hyperv_vm_id, hyperv_adapter_id, incarnation, node_name, guest_os,
			profile_name, ipv4, mac, prefix_length, gateway_ipv4,
			dns_servers_json, storage_root, vm_path, vhd_path,
			desired_generation, applied_generation, observed_generation,
			lifecycle_state, created_at_unix, updated_at_unix
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"vm-a", "orch-a", "network-a", "guest-a", "LL-VM-A", vmGUID,
		vmAdapterID, 4, "guest-node", "windows", "win-default", "10.60.0.10",
		"02-00-00-00-00-10", 26, "10.60.0.1", `["10.60.0.3"]`,
		`C:\secret-storage-root`, `C:\secret-vm-path`, `C:\secret-vhd-path`,
		5, 4, 4, "ready", now, now,
	); err != nil {
		t.Fatalf("insert VM: %v", err)
	}
	if err := store.PutRelay(ctx, isolatedstate.RelayAllocation{
		ID: "relay-a", VMID: "vm-a", OrchestratorID: "orch-a",
		ListenPort: 20010, TargetIPv4: "10.60.0.10", TargetPort: 9091,
		DesiredGeneration: 5, AppliedGeneration: 4, ObservedGeneration: 4,
		LifecycleState: isolatedstate.RelayReady, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("PutRelay: %v", err)
	}
	if _, err := store.ExecContext(ctx, `
		INSERT INTO nat_allocations (
			vm_id, orchestrator_id, desired_state, observed_state,
			conntrack_mark, desired_generation, applied_generation,
			observed_generation, updated_at_unix
		) VALUES (?,?,?,?,?,?,?,?,?)`,
		"vm-a", "orch-a", "enabled", "enabled", 101, 3, 3, 2, now,
	); err != nil {
		t.Fatalf("insert NAT: %v", err)
	}
	if _, err := store.ExecContext(ctx, `
		INSERT INTO guest_pending_updates (
			vm_id, update_kind, desired_generation, payload_json,
			created_at_unix, last_error
		) VALUES (?,?,?,?,?,?)`,
		"vm-a", "refresh_dns", 5, `{"private_key":"DO_NOT_EXPOSE"}`,
		now, "guest DNS retry pending",
	); err != nil {
		t.Fatalf("insert pending update: %v", err)
	}

	begin, err := store.BeginOperation(ctx, isolatedstate.BeginOperationRequest{
		ID: "operation-a", Kind: "create_vm", ResourceType: "vm",
		ResourceID: "vm-a", CanonicalInputs: map[string]any{
			"payload": "SECRET_PAYLOAD", "private_key": "SECRET_PRIVATE_KEY",
		},
		CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("BeginOperation: %v", err)
	}
	phase, err := store.StartOperationPhase(ctx, isolatedstate.PhaseStart{
		OperationID: begin.Operation.ID, PhaseIndex: 0,
		PhaseName: "allocate", StartedAt: now + 1,
	})
	if err != nil {
		t.Fatalf("StartOperationPhase: %v", err)
	}
	phaseErr := "allocation failed safely"
	if err := store.FinishOperationPhase(ctx, isolatedstate.PhaseFinish{
		OperationID: begin.Operation.ID, PhaseIndex: 0, Attempt: phase.Attempt,
		Status:    isolatedstate.PhaseFailed,
		Detail:    map[string]any{"secret": "SECRET_PHASE_DETAIL"},
		ErrorText: &phaseErr, FinishedAt: now + 2,
	}); err != nil {
		t.Fatalf("FinishOperationPhase: %v", err)
	}
	errorCode := "ALLOCATE_FAILED"
	if _, err := store.UpdateOperation(ctx, isolatedstate.OperationUpdate{
		OperationID: begin.Operation.ID, Status: isolatedstate.OperationFailed,
		CurrentPhase: "allocate", ErrorCode: &errorCode, ErrorText: &phaseErr,
		UpdatedAt: now + 2,
	}); err != nil {
		t.Fatalf("UpdateOperation: %v", err)
	}

	reg := registry.Load(filepath.Join(dir, "nodes.json"))
	if err := reg.SetNode(&registry.Node{
		Name: "orch-node", Address: "10.40.0.2:9091",
		Role: "isolated-orchestrator", TransportMode: "mtls",
		TLSServerName: "orch-node",
	}); err != nil {
		t.Fatalf("SetNode orchestrator: %v", err)
	}
	if err := reg.SetNode(&registry.Node{
		Name: "guest-node", Address: "10.60.0.10:9091",
		TransportMode: "mtls", TLSServerName: "guest-node",
	}); err != nil {
		t.Fatalf("SetNode guest: %v", err)
	}
	client := &fakeIsolatedAppliance{
		readiness: map[string]isolated.ApplianceReadiness{
			"orch-a": {
				Node: "orch-node", AgentVersion: "v1.2.3",
				Capabilities: []string{
					string(isolated.CapabilityStatsV1),
					string(isolated.CapabilityApplianceV1),
				},
				ProtocolVersion: isolated.MaximumProtocolVersion, Ready: true, ApplianceGeneration: 9,
			},
		},
		snapshots: map[string]isolated.ApplianceSnapshot{
			"orch-a": {
				SchemaVersion: isolated.MaximumApplianceSchema, ProtocolVersion: isolated.MaximumProtocolVersion, Ready: true,
				ApplianceGeneration: 9, InventoryGeneration: 8,
				MainIPv4: "10.40.0.2", PolicyVerified: true, IPv4Forwarding: true,
				Desired: appliance.DesiredSnapshot{
					Networks: []appliance.Network{{
						ID: "network-a", DNSServersJSON: `["10.60.0.9"]`,
						State: "ready", DesiredGeneration: 2,
						AppliedGeneration: 2, ObservedGeneration: 2,
					}},
					Guests: []appliance.Guest{{
						ID: "vm-a", NetworkID: "network-a", IPv4: "10.60.0.10",
						MAC: "02-00-00-00-00-10", State: "ready",
					}},
					Relays: []appliance.Relay{{
						ID: "relay-a", VMID: "vm-a", ListenPort: 20010,
						TargetIPv4: "10.60.0.10", TargetPort: 9091,
						State: "ready", BoundMainIP: "10.40.0.2",
					}},
					NAT: []appliance.NATState{{
						VMID: "vm-a", State: "enabled", ConntrackMark: 101,
					}},
				},
			},
		},
		stats: map[string]appliance.RelayStats{
			"relay-a": {
				RelayID: "relay-a", ListenerState: "ready",
				BindAddress: "10.40.0.2:20010", ActiveConnections: 2,
				TotalAcceptedConnections: 7, BytesGuestToMain: 100,
				BytesMainToGuest: 200, RelayGeneration: 5,
				ApplianceGeneration: 9,
			},
		},
	}

	server := newPortalTestServer(t, reg, store, client)
	stateBody := getPortalBody(t, server, "/api/isolated?stats_limit=1")
	if strings.Contains(stateBody, `<script>`) {
		t.Fatalf("JSON did not HTML-escape display name: %s", stateBody)
	}
	for _, secret := range []string{
		"DO_NOT_EXPOSE", "SECRET_PAYLOAD", "SECRET_PRIVATE_KEY",
		"SECRET_PHASE_DETAIL", `C:\secret-storage-root`,
	} {
		if strings.Contains(stateBody, secret) {
			t.Fatalf("isolated API exposed %q: %s", secret, stateBody)
		}
	}
	var snapshot isolatedSnapshotJSON
	if err := json.Unmarshal([]byte(stateBody), &snapshot); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if len(snapshot.Orchestrators) != 1 || !snapshot.Orchestrators[0].Readiness.Ready {
		t.Fatalf("orchestrators = %+v", snapshot.Orchestrators)
	}
	if got := snapshot.Orchestrators[0].Endpoint.TLSName; got != "orch-node" {
		t.Fatalf("orchestrator TLS name = %q", got)
	}
	if len(snapshot.Networks) != 1 || !snapshot.Networks[0].DNSDrift {
		t.Fatalf("networks = %+v", snapshot.Networks)
	}
	if len(snapshot.VMs) != 1 || snapshot.VMs[0].Incarnation != 4 ||
		!snapshot.VMs[0].TLS.IdentityOK || snapshot.VMs[0].NAT == nil ||
		!snapshot.VMs[0].DNSUpdatePending {
		t.Fatalf("VMs = %+v", snapshot.VMs)
	}
	if len(snapshot.Relays) != 1 || snapshot.Relays[0].Stats == nil ||
		snapshot.Relays[0].Stats.TotalAcceptedConnections != 7 {
		t.Fatalf("relays = %+v", snapshot.Relays)
	}

	operationsBody := getPortalBody(t, server, "/api/isolated/operations?limit=1&phase_limit=10")
	for _, secret := range []string{"SECRET_PAYLOAD", "SECRET_PRIVATE_KEY", "SECRET_PHASE_DETAIL"} {
		if strings.Contains(operationsBody, secret) {
			t.Fatalf("operations API exposed %q: %s", secret, operationsBody)
		}
	}
	var operations isolatedOperationsJSON
	if err := json.Unmarshal([]byte(operationsBody), &operations); err != nil {
		t.Fatalf("decode operations: %v", err)
	}
	if len(operations.Operations) != 1 ||
		operations.Operations[0].ResumeID != "operation-a" ||
		len(operations.Operations[0].Phases) != 1 ||
		operations.Operations[0].Phases[0].ErrorText == nil {
		t.Fatalf("operations = %+v", operations.Operations)
	}

	indexBody := getPortalBody(t, server, "/")
	for _, expected := range []string{
		`id="tab-isolated"`, `id="pane-isolated"`,
		"Durable operations", "item.textContent = String(line)",
	} {
		if !strings.Contains(indexBody, expected) {
			t.Fatalf("index missing %q", expected)
		}
	}
}

func TestIsolatedAuthorizationAndReadOnlyMethods(t *testing.T) {
	store, err := isolatedstate.Open(filepath.Join(portalTestDir(t), "isolated.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()
	server := newPortalTestServer(t, nil, store, nil)

	resp, err := http.Get("http://" + server.Addr() + "/api/isolated")
	if err != nil {
		t.Fatalf("GET without key: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET without key status = %d, want 401", resp.StatusCode)
	}

	request, err := http.NewRequest(http.MethodPost, portalTestURL(server, "/api/isolated"), nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("POST isolated: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", resp.StatusCode)
	}
}

func TestIsolatedEmptyAndLegacyState(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		store, err := isolatedstate.Open(filepath.Join(portalTestDir(t), "isolated.db"))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer store.Close()
		server := newPortalTestServer(t, nil, store, nil)
		var snapshot isolatedSnapshotJSON
		if err := json.Unmarshal([]byte(getPortalBody(t, server, "/api/isolated")), &snapshot); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(snapshot.Orchestrators) != 0 || len(snapshot.Errors) != 0 {
			t.Fatalf("empty snapshot = %+v", snapshot)
		}
	})

	t.Run("legacy missing tables", func(t *testing.T) {
		server := newPortalTestServer(t, nil, legacyIsolatedState{
			err: errors.New("no such table: orchestrators"),
		}, nil)
		resp, err := http.Get(portalTestURL(server, "/api/isolated"))
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "no such table") {
			t.Fatalf("legacy error missing: %s", body)
		}
	})

	t.Run("appliance unavailable", func(t *testing.T) {
		ctx := context.Background()
		store, err := isolatedstate.Open(filepath.Join(portalTestDir(t), "isolated.db"))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer store.Close()
		if err := store.PutOrchestrator(ctx, isolatedstate.Orchestrator{
			ID: "orch-offline", DisplayName: "offline",
			PhysicalHostID: "host-a", HostNode: "hyperv-a",
			HyperVName: "LL-ORCH-OFFLINE", NodeName: "orch-offline-node",
			ProfileName: "default", MainVSwitch: "External", AgentPort: 9091,
			LifecycleState: isolatedstate.OrchestratorDegraded,
			HealthState:    "unreachable", CreatedAt: 1, UpdatedAt: 1,
		}); err != nil {
			t.Fatalf("PutOrchestrator: %v", err)
		}
		server := newPortalTestServer(t, nil, store, &fakeIsolatedAppliance{
			readiness: map[string]isolated.ApplianceReadiness{},
			snapshots: map[string]isolated.ApplianceSnapshot{},
			stats:     map[string]appliance.RelayStats{},
			err:       errors.New("appliance unavailable"),
		})
		var snapshot isolatedSnapshotJSON
		if err := json.Unmarshal([]byte(getPortalBody(t, server, "/api/isolated")), &snapshot); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(snapshot.Orchestrators) != 1 ||
			!strings.Contains(snapshot.Orchestrators[0].Readiness.Error, "unavailable") {
			t.Fatalf("offline orchestrator = %+v", snapshot.Orchestrators)
		}
	})
}

func TestIsolatedReadsCrossProcessUpdates(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(portalTestDir(t), "isolated.db")
	readerStore, err := isolatedstate.Open(path)
	if err != nil {
		t.Fatalf("Open reader: %v", err)
	}
	defer readerStore.Close()
	writerStore, err := isolatedstate.Open(path)
	if err != nil {
		t.Fatalf("Open writer: %v", err)
	}
	defer writerStore.Close()

	server := newPortalTestServer(t, nil, readerStore, nil)
	var before isolatedSnapshotJSON
	if err := json.Unmarshal([]byte(getPortalBody(t, server, "/api/isolated")), &before); err != nil {
		t.Fatalf("decode before: %v", err)
	}
	if len(before.Orchestrators) != 0 {
		t.Fatalf("before orchestrators = %+v", before.Orchestrators)
	}
	if err := writerStore.PutOrchestrator(ctx, isolatedstate.Orchestrator{
		ID: "orch-cross-process", DisplayName: "cross-process",
		PhysicalHostID: "host-a", HostNode: "hyperv-a",
		HyperVName: "LL-ORCH-CROSS", NodeName: "orch-cross-node",
		ProfileName: "default", MainVSwitch: "External", AgentPort: 9091,
		LifecycleState: isolatedstate.OrchestratorPlanned,
		HealthState:    "unknown", CreatedAt: 1, UpdatedAt: 1,
	}); err != nil {
		t.Fatalf("writer PutOrchestrator: %v", err)
	}
	var after isolatedSnapshotJSON
	if err := json.Unmarshal([]byte(getPortalBody(t, server, "/api/isolated")), &after); err != nil {
		t.Fatalf("decode after: %v", err)
	}
	if len(after.Orchestrators) != 1 || after.Orchestrators[0].ID != "orch-cross-process" {
		t.Fatalf("cross-process update not visible: %+v", after.Orchestrators)
	}
}

func newPortalTestServer(
	t *testing.T,
	reg *registry.Registry,
	state isolatedStateReader,
	client isolatedApplianceReader,
) *Server {
	t.Helper()
	server, err := New(ops.NewRegistry(10), reg, nil, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	server.isolated.mu.Lock()
	server.isolated.state = state
	server.isolated.appliance = client
	server.isolated.reg = reg
	server.isolated.mu.Unlock()
	t.Cleanup(func() {
		_ = server.Shutdown(context.Background())
	})
	return server
}

func getPortalBody(t *testing.T, server *Server, path string) string {
	t.Helper()
	resp, err := http.Get(portalTestURL(server, path))
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, body = %s", path, resp.StatusCode, body)
	}
	return string(body)
}

func portalTestURL(server *Server, path string) string {
	root, _ := url.Parse(server.URL())
	target, _ := url.Parse("http://" + server.Addr() + path)
	query := target.Query()
	query.Set("k", root.Query().Get("k"))
	target.RawQuery = query.Encode()
	return target.String()
}

func portalTestDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", ".portal-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
