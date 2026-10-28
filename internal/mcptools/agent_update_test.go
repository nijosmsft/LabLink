package mcptools

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nijosmsft/lablink/internal/agentclient"
	internalsec "github.com/nijosmsft/lablink/internal/security"
	pb "github.com/nijosmsft/lablink/proto/agent"
	"google.golang.org/grpc"
)

type updateAgentFake struct {
	pb.UnimplementedNodeAgentServer
	mu              sync.Mutex
	version         string
	expectedVersion string
	pushed          map[string][]byte
	scripts         []string
}

func (a *updateAgentFake) GetInfo(context.Context, *pb.GetInfoRequest) (*pb.GetInfoResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return &pb.GetInfoResponse{
		Os: "windows", Arch: "amd64", AgentVersion: a.version,
	}, nil
}

func (a *updateAgentFake) ExecuteScript(req *pb.ExecuteScriptRequest, stream grpc.ServerStreamingServer[pb.ExecuteResponse]) error {
	a.mu.Lock()
	a.scripts = append(a.scripts, req.ScriptBody)
	if strings.Contains(req.ScriptBody, "detached Windows agent update scheduled") {
		a.version = a.expectedVersion
	}
	a.mu.Unlock()
	return stream.Send(&pb.ExecuteResponse{Done: true, ExitCode: 0})
}

func (a *updateAgentFake) PushFile(stream grpc.ClientStreamingServer[pb.PushFileRequest, pb.PushFileResponse]) error {
	var remote string
	var data []byte
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if msg.RemotePath != "" {
			remote = msg.RemotePath
		}
		data = append(data, msg.Chunk...)
		if msg.IsLast {
			break
		}
	}
	a.mu.Lock()
	if a.pushed == nil {
		a.pushed = map[string][]byte{}
	}
	a.pushed[remote] = append([]byte(nil), data...)
	a.mu.Unlock()
	return stream.SendAndClose(&pb.PushFileResponse{RemotePath: remote, BytesWritten: int64(len(data))})
}

func TestValidateBundledAgentRequiresServerVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lablink-agent")
	if err := os.WriteFile(path, []byte("binary-data-v1.2.3-more-data"), 0600); err != nil {
		t.Fatal(err)
	}
	hash, size, err := validateBundledAgent(path, "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 64 || size != int64(len("binary-data-v1.2.3-more-data")) {
		t.Fatalf("unexpected payload metadata: hash=%q size=%d", hash, size)
	}
	if _, _, err := validateBundledAgent(path, "v9.9.9"); err == nil {
		t.Fatal("accepted bundled agent without the running server version")
	}
}

func TestUpdatePlanSelectsBundledPayloadByOS(t *testing.T) {
	config := AgentUpdateConfig{
		ServerVersion:      "v1.2.3",
		WindowsAgentBinary: `C:\LabLink\current\bin\lablink-agent.exe`,
		LinuxAgentBinary:   `/opt/lablink/current/bin/linux-amd64/lablink-agent`,
	}
	windows, remoteBinary, remoteScript, launcher, shell, err := updatePlan(
		&pb.GetInfoResponse{Os: "windows", Arch: "amd64"},
		config,
	)
	if err != nil {
		t.Fatal(err)
	}
	if windows != config.WindowsAgentBinary || remoteBinary != windowsUpdateBinary ||
		remoteScript != windowsUpdateScript || shell != "powershell" ||
		!strings.Contains(launcher, "New-ScheduledTaskAction") {
		t.Fatalf("unexpected Windows plan: %q %q %q %q", windows, remoteBinary, remoteScript, shell)
	}

	linux, remoteBinary, remoteScript, launcher, shell, err := updatePlan(
		&pb.GetInfoResponse{Os: "linux", Arch: "amd64"},
		config,
	)
	if err != nil {
		t.Fatal(err)
	}
	if linux != config.LinuxAgentBinary || remoteBinary != linuxUpdateBinary ||
		remoteScript != linuxUpdateScript || shell != "bash" ||
		!strings.Contains(launcher, "systemd-run") {
		t.Fatalf("unexpected Linux plan: %q %q %q %q", linux, remoteBinary, remoteScript, shell)
	}
	if _, _, _, _, _, err := updatePlan(
		&pb.GetInfoResponse{Os: "linux", Arch: "arm64"},
		config,
	); err == nil {
		t.Fatal("accepted unsupported architecture")
	}
}

func TestDetachedUpdateScriptsVerifyAndRollback(t *testing.T) {
	windows := windowsAgentUpdateScript("v1.2.3", strings.Repeat("a", 64))
	for _, want := range []string{
		"Get-FileHash", "SHA256 mismatch", "Stop-Service", "Move-Item",
		"lablink-agent.previous.exe", "Start-Service", "expectedVersion",
	} {
		if !strings.Contains(windows, want) {
			t.Errorf("Windows updater missing %q", want)
		}
	}
	for _, forbidden := range []string{"Invoke-WebRequest", "github.com", "$env:TEMP"} {
		if strings.Contains(windows, forbidden) {
			t.Errorf("Windows updater must not use %q", forbidden)
		}
	}

	linux := linuxAgentUpdateScript("v1.2.3", strings.Repeat("b", 64))
	for _, want := range []string{
		"sha256sum", "systemctl stop lablink-agent.service", "systemctl start lablink-agent.service",
		"lablink-agent.previous", "trap rollback ERR", "expected_version",
	} {
		if !strings.Contains(linux, want) {
			t.Errorf("Linux updater missing %q", want)
		}
	}
	for _, forbidden := range []string{"curl ", "wget ", "github.com", "/tmp/"} {
		if strings.Contains(linux, forbidden) {
			t.Errorf("Linux updater must not use %q", forbidden)
		}
	}
}

func TestWindowsDetachedUpdateScriptParses(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows PowerShell parser is only available on Windows")
	}
	script := windowsAgentUpdateScript("v1.2.3", strings.Repeat("a", 64))
	parser := `$inputScript = [Console]::In.ReadToEnd()
$tokens = $null
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseInput($inputScript, [ref]$tokens, [ref]$errors)
if ($errors.Count) {
    $errors | ForEach-Object { [Console]::Error.WriteLine($_.Message) }
    exit 1
}`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", parser)
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated Windows updater does not parse: %v\n%s", err, output)
	}
}

func TestAgentUpdateDefaults(t *testing.T) {
	if defaultAgentUpdateTimeout != 180 {
		t.Fatalf("default timeout = %d", defaultAgentUpdateTimeout)
	}
	config := AgentUpdateConfig{PollInterval: time.Millisecond}
	if config.PollInterval <= 0 {
		t.Fatal("test poll interval not applied")
	}
}

func TestUpdateAgentHandlerPushesDetachedUpdateAndVerifiesVersion(t *testing.T) {
	const expected = "v1.2.3"
	payload := filepath.Join(t.TempDir(), "lablink-agent.exe")
	if err := os.WriteFile(payload, []byte("test-binary-"+expected), 0600); err != nil {
		t.Fatal(err)
	}
	agent := &updateAgentFake{version: "v1.0.0", expectedVersion: expected}
	address := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": address})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()

	previousMonitor := hmon
	hmon = nil
	t.Cleanup(func() { hmon = previousMonitor })

	handler := updateAgentHandler(reg, pool, AgentUpdateConfig{
		ServerVersion:      expected,
		WindowsAgentBinary: payload,
		PollInterval:       time.Millisecond,
	})
	result, err := handler(context.Background(), reqNoToken(map[string]any{
		"node": "node1", "timeout_seconds": 30,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("update failed: %s", toolResultText(result))
	}
	agent.mu.Lock()
	defer agent.mu.Unlock()
	if agent.version != expected {
		t.Fatalf("agent version = %q, want %q", agent.version, expected)
	}
	if len(agent.pushed[windowsUpdateBinary]) == 0 {
		t.Fatal("bundled Windows agent was not pushed")
	}
	if !strings.Contains(string(agent.pushed[windowsUpdateScript]), "Get-FileHash") {
		t.Fatal("detached Windows updater script was not pushed")
	}
	if len(agent.scripts) < 2 {
		t.Fatalf("expected staging preparation and detached launcher, got %d scripts", len(agent.scripts))
	}
}
