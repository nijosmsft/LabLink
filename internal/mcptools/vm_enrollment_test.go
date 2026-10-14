package mcptools

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/healthmon"
	"github.com/nijosmsft/lablink/internal/pki"
	"github.com/nijosmsft/lablink/internal/registry"
	internalsec "github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"
	"google.golang.org/grpc"
)

type enrollmentInfoAgent struct {
	pb.UnimplementedNodeAgentServer
}

func (*enrollmentInfoAgent) GetInfo(context.Context, *pb.GetInfoRequest) (*pb.GetInfoResponse, error) {
	return &pb.GetInfoResponse{
		Os:          "windows",
		Arch:        "amd64",
		CpuCount:    4,
		MemoryBytes: 8 << 30,
	}, nil
}

func TestVerifyEnrolledVMRevivesOfflineHealthContext(t *testing.T) {
	for _, register := range []bool{false, true} {
		t.Run("register="+strconv.FormatBool(register), func(t *testing.T) {
			address := startNodeAgent(t, &enrollmentInfoAgent{})
			host, port := splitEnrollmentAddress(t, address)
			reg, pool, monitor := offlineEnrollmentMonitor(t, "builder")

			oldMonitor := hmon
			hmon = monitor
			t.Cleanup(func() { hmon = oldMonitor })

			err := verifyEnrolledVMWithOptions(context.Background(), windowsVMPlan{
				LabLinkNodeName: "builder",
				LabLinkRole:     "linux-image-builder",
				LabLinkPort:     port,
			}, startedVMInfo{IPAddress: host}, reg, pool, register, enrollmentWaitOptions{
				Timeout: time.Second,
			})
			if err != nil {
				t.Fatalf("verifyEnrolledVMWithOptions() error = %v", err)
			}

			state := monitor.GetStatus("builder")
			if state.Status != "online" || state.ConsecutiveFails != 0 {
				t.Fatalf("health state was not revived immediately: %+v", state)
			}
			select {
			case <-monitor.NodeContext("builder").Done():
				t.Fatal("verified node still has a cancelled health context")
			default:
			}

			node, ok := reg.GetNode("builder")
			if !ok {
				t.Fatal("builder disappeared from registry")
			}
			if register {
				if node.Address != address || node.TLSServerName != "builder" || node.TransportMode != "mtls" {
					t.Fatalf("registry did not receive verified identity: %+v", node)
				}
			} else if node.Address != "127.0.0.1:1" {
				t.Fatalf("register=false changed registry address to %q", node.Address)
			}
		})
	}
}

func TestVerifyEnrolledVMFailedProbeDoesNotReviveOfflineHealthContext(t *testing.T) {
	reg, pool, monitor := offlineEnrollmentMonitor(t, "builder")
	oldMonitor := hmon
	hmon = monitor
	t.Cleanup(func() { hmon = oldMonitor })

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	err := verifyEnrolledVMWithOptions(ctx, windowsVMPlan{
		LabLinkNodeName: "builder",
		LabLinkPort:     1,
	}, startedVMInfo{IPAddress: "127.0.0.1"}, reg, pool, false, enrollmentWaitOptions{
		Timeout: time.Second,
	})
	if err == nil {
		t.Fatal("expected failed probe")
	}
	assertEnrollmentMonitorOffline(t, monitor, "builder")
}

func TestVerifyEnrolledVMTLSMismatchDoesNotReviveOfflineHealthContext(t *testing.T) {
	address, transport := startEnrollmentMTLSAgent(t, "different-node")
	host, port := splitEnrollmentAddress(t, address)
	reg := newRebootTestRegistry(t, map[string]string{
		"builder": "127.0.0.1:1",
	})
	pool := agentclient.NewPool("", transport)
	t.Cleanup(pool.Close)
	monitor := offlineEnrollmentMonitorWithPool(t, reg, pool, "builder")

	oldMonitor := hmon
	hmon = monitor
	t.Cleanup(func() { hmon = oldMonitor })

	err := verifyEnrolledVMWithOptions(context.Background(), windowsVMPlan{
		LabLinkNodeName: "builder",
		LabLinkPort:     port,
	}, startedVMInfo{IPAddress: host}, reg, pool, false, enrollmentWaitOptions{
		Timeout: time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "wrong TLS identity") {
		t.Fatalf("expected permanent TLS identity error, got %v", err)
	}
	assertEnrollmentMonitorOffline(t, monitor, "builder")
}

func offlineEnrollmentMonitor(t *testing.T, nodeName string) (*registry.Registry, *agentclient.Pool, *healthmon.Monitor) {
	t.Helper()
	reg := newRebootTestRegistry(t, map[string]string{
		nodeName: "127.0.0.1:1",
	})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	t.Cleanup(pool.Close)
	return reg, pool, offlineEnrollmentMonitorWithPool(t, reg, pool, nodeName)
}

func offlineEnrollmentMonitorWithPool(t *testing.T, reg *registry.Registry, pool *agentclient.Pool, nodeName string) *healthmon.Monitor {
	t.Helper()
	t.Setenv("DEAD_THRESHOLD", "1")
	t.Setenv("HEALTH_CHECK_INTERVAL", "1h")
	t.Setenv("HEALTH_CHECK_TIMEOUT", "20ms")
	monitor := healthmon.New(reg, pool)
	monitor.Start()

	deadline := time.Now().Add(2 * time.Second)
	for monitor.GetStatus(nodeName).Status != "offline" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	monitor.Stop()
	assertEnrollmentMonitorOffline(t, monitor, nodeName)
	return monitor
}

func assertEnrollmentMonitorOffline(t *testing.T, monitor *healthmon.Monitor, nodeName string) {
	t.Helper()
	if state := monitor.GetStatus(nodeName); state.Status != "offline" {
		t.Fatalf("health state = %+v, want offline", state)
	}
	select {
	case <-monitor.NodeContext(nodeName).Done():
	default:
		t.Fatal("offline node context is live")
	}
}

func splitEnrollmentAddress(t *testing.T, address string) (string, int) {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func startEnrollmentMTLSAgent(t *testing.T, serverName string) (string, internalsec.ClientTransportConfig) {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	rootPEM, rootKey, rootCert, err := pki.CreateRootCA("Test Root", 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	issuingPEM, issuingKey, issuingCert, err := pki.CreateIntermediateCA("Test Issuing", 24*time.Hour, now, rootCert, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, clientKey, _, err := pki.IssueClientCertificate("test-client", 24*time.Hour, now, issuingCert, issuingKey, issuingPEM)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, _, csr, err := pki.CreateServerCSR(serverName, serverName)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, _, err := pki.SignServerCSR(csr, 24*time.Hour, now, issuingCert, issuingKey, issuingPEM)
	if err != nil {
		t.Fatal(err)
	}

	caPath := filepath.Join(dir, "ca.crt")
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	serverCertPath := filepath.Join(dir, "server.crt")
	serverKeyPath := filepath.Join(dir, "server.key")
	for path, data := range map[string][]byte{
		caPath:         rootPEM,
		clientCertPath: clientCert,
		clientKeyPath:  clientKey,
		serverCertPath: serverCert,
		serverKeyPath:  serverKey,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	serverCreds, err := internalsec.NewServerCredentials(internalsec.ServerTransportConfig{
		Mode:       internalsec.TransportModeMTLS,
		CACertPath: caPath,
		CertPath:   serverCertPath,
		KeyPath:    serverKeyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(serverCreds))
	pb.RegisterNodeAgentServer(server, &enrollmentInfoAgent{})
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() {
		server.Stop()
		_ = ln.Close()
	})

	return ln.Addr().String(), internalsec.ClientTransportConfig{
		Mode:       internalsec.TransportModeMTLS,
		CACertPath: caPath,
		CertPath:   clientCertPath,
		KeyPath:    clientKeyPath,
	}
}
