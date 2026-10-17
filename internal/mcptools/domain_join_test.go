package mcptools

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/secretstore"
	internalsec "github.com/nijosmsft/lablink/internal/security"
	"github.com/nijosmsft/lablink/internal/vmconfig"
	pb "github.com/nijosmsft/lablink/proto/agent"
	"google.golang.org/grpc"
)

type domainJoinMockAgent struct {
	pb.UnimplementedNodeAgentServer
	mu        sync.Mutex
	responses []string
	exitCodes []int32
	requests  []*pb.ExecuteRequest
}

func (a *domainJoinMockAgent) Execute(req *pb.ExecuteRequest, stream grpc.ServerStreamingServer[pb.ExecuteResponse]) error {
	a.mu.Lock()
	index := len(a.requests)
	a.requests = append(a.requests, req)
	response := `{"computer_name":"NODE1","domain":"cfdev.nttest.microsoft.com","changed":true}`
	if index < len(a.responses) {
		response = a.responses[index]
	}
	var exit int32
	if index < len(a.exitCodes) {
		exit = a.exitCodes[index]
	}
	a.mu.Unlock()
	return stream.Send(&pb.ExecuteResponse{Pid: 1, Data: []byte(response), Done: true, ExitCode: exit})
}

func (a *domainJoinMockAgent) snapshot() []*pb.ExecuteRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]*pb.ExecuteRequest(nil), a.requests...)
}

func TestWindowsDomainJoinInjectsSecretWithoutExposingIt(t *testing.T) {
	const password = "domain-password-value"
	agent := &domainJoinMockAgent{}
	address := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": address})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	secrets := secretstore.Open(filepath.Join(t.TempDir(), "secrets.json"))
	if err := secrets.Set("domain-password", password); err != nil {
		t.Fatal(err)
	}
	disabled := false
	result, err := executeWindowsDomainJoin(
		context.Background(),
		"node1",
		vmconfig.WindowsDomainJoin{
			Domain: "cfdev.nttest.microsoft.com", Username: `cfdev\netcdev`,
			PasswordSecret: "domain-password", Reboot: &disabled, VerifySecureChannel: &disabled,
		},
		5,
		reg,
		pool,
		secrets,
		audit.NewLog(t.TempDir()),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Rebooted || result.SecureChannelVerified {
		t.Fatalf("domain join result = %+v", result)
	}
	requests := agent.snapshot()
	if len(requests) != 1 || requests[0].Env[domainJoinPasswordEnv] != password {
		t.Fatalf("domain join environment = %#v", requests)
	}
	if strings.Contains(requests[0].Command, password) {
		t.Fatal("domain password was embedded in the command")
	}
}

func TestWindowsDomainJoinAlreadyJoinedVerifiesWithoutReboot(t *testing.T) {
	agent := &domainJoinMockAgent{responses: []string{
		`{"computer_name":"NODE1","domain":"CFDEV.NTTEST.MICROSOFT.COM","changed":false}`,
		`{"computer_name":"NODE1","domain":"CFDEV.NTTEST.MICROSOFT.COM","part_of_domain":true,"domain_controller":"CFDEV-DC-01"}`,
	}}
	address := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": address})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	secrets := secretstore.Open(filepath.Join(t.TempDir(), "secrets.json"))
	if err := secrets.Set("domain-password", "value"); err != nil {
		t.Fatal(err)
	}
	result, err := executeWindowsDomainJoin(
		context.Background(), "node1",
		vmconfig.WindowsDomainJoin{
			Domain: "cfdev.nttest.microsoft.com", Username: `cfdev\netcdev`,
			PasswordSecret: "domain-password",
		},
		5, reg, pool, secrets, audit.NewLog(t.TempDir()),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || result.Rebooted || !result.SecureChannelVerified ||
		result.DomainController != "CFDEV-DC-01" {
		t.Fatalf("idempotent domain join result = %+v", result)
	}
	if requests := agent.snapshot(); len(requests) != 2 {
		t.Fatalf("domain join requests = %d", len(requests))
	}
}

func TestWindowsDomainJoinRedactsSecretOnFailure(t *testing.T) {
	const password = "do-not-leak-domain-password"
	agent := &domainJoinMockAgent{
		responses: []string{"join failed: " + password},
		exitCodes: []int32{1},
	}
	address := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": address})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	secrets := secretstore.Open(filepath.Join(t.TempDir(), "secrets.json"))
	if err := secrets.Set("domain-password", password); err != nil {
		t.Fatal(err)
	}
	disabled := false
	_, err := executeWindowsDomainJoin(
		context.Background(), "node1",
		vmconfig.WindowsDomainJoin{
			Domain: "cfdev.nttest.microsoft.com", Username: `cfdev\netcdev`,
			PasswordSecret: "domain-password", Reboot: &disabled, VerifySecureChannel: &disabled,
		},
		5, reg, pool, secrets, audit.NewLog(t.TempDir()),
	)
	if err == nil || strings.Contains(err.Error(), password) || !strings.Contains(err.Error(), passwordMask) {
		t.Fatalf("redacted domain join error = %v", err)
	}
}

func TestWindowsDomainJoinRejectsNonWindowsNode(t *testing.T) {
	reg := newRebootTestRegistry(t, map[string]string{"node1": "127.0.0.1:1"})
	setRebootNodeOS(t, reg, "node1", "linux")
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	secrets := secretstore.Open(filepath.Join(t.TempDir(), "secrets.json"))
	if err := secrets.Set("domain-password", "value"); err != nil {
		t.Fatal(err)
	}
	_, err := executeWindowsDomainJoin(
		context.Background(), "node1",
		vmconfig.WindowsDomainJoin{
			Domain: "cfdev.nttest.microsoft.com", Username: `cfdev\netcdev`,
			PasswordSecret: "domain-password",
		},
		5, reg, pool, secrets, audit.NewLog(t.TempDir()),
	)
	if err == nil || !strings.Contains(err.Error(), "only Windows nodes") {
		t.Fatalf("non-Windows domain join error = %v", err)
	}
}

func TestWindowsDomainJoinScriptUsesEnvironmentAndEscapesInputs(t *testing.T) {
	script := buildWindowsDomainJoinScript(vmconfig.WindowsDomainJoin{
		Domain: "corp.example.com", Username: `CORP\o'brien`,
		PasswordSecret: "domain-password", OUPath: `OU=Lab's,DC=corp,DC=example,DC=com`,
	})
	for _, want := range []string{
		`$env:LABLINK_DOMAIN_JOIN_PASSWORD`,
		`'CORP\o''brien'`,
		`'OU=Lab''s,DC=corp,DC=example,DC=com'`,
		"Resolve-DnsName",
		"nltest.exe /dsgetdc",
		"Add-Computer",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("domain join script missing %q:\n%s", want, script)
		}
	}
}

func TestJoinWindowsDomainToolHandlerReturnsFencedResult(t *testing.T) {
	agent := &domainJoinMockAgent{}
	address := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": address})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	secrets := secretstore.Open(filepath.Join(t.TempDir(), "secrets.json"))
	if err := secrets.Set("domain-password", "value"); err != nil {
		t.Fatal(err)
	}
	result, err := joinWindowsDomainHandler(reg, pool, secrets, audit.NewLog(t.TempDir()))(
		context.Background(),
		reqNoToken(map[string]any{
			"node": "node1", "domain": "cfdev.nttest.microsoft.com",
			"username": `cfdev\netcdev`, "password_secret": "domain-password",
			"reboot": false, "verify_secure_channel": false,
		}),
	)
	if err != nil || result == nil || result.IsError {
		t.Fatalf("domain join handler = %#v, %v", result, err)
	}
	text := toolResultText(result)
	if !strings.Contains(text, "```json") || !strings.Contains(text, `"changed": true`) {
		t.Fatalf("domain join result = %s", text)
	}
}

func TestParseWindowsDomainJoinRejectsUnknownField(t *testing.T) {
	_, err := parseWindowsDomainJoinArgument(map[string]any{
		"domain": "corp.example.com", "username": `CORP\user`,
		"password_secret": "domain-password", "future_option": true,
	})
	if err == nil || !strings.Contains(err.Error(), `unsupported field "future_option"`) {
		t.Fatalf("unknown domain join field error = %v", err)
	}
}
