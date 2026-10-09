package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/pki"
	"github.com/nijosmsft/lablink/internal/registry"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

type VMEnrollmentConfig struct {
	ConfigDir   string
	PKIDir      string
	AgentBinary string
	AuthToken   string
}

type enrollmentPayload struct {
	RemoteDir string
	Cleanup   func()
}

func prepareEnrollmentPayload(
	ctx context.Context,
	plan windowsVMPlan,
	config VMEnrollmentConfig,
	reg *registry.Registry,
	pool *agentclient.Pool,
) (enrollmentPayload, error) {
	if !plan.RegisterWithLabLink {
		return enrollmentPayload{}, nil
	}
	if config.AuthToken == "" {
		return enrollmentPayload{}, fmt.Errorf("LabLink enrollment requires a configured agent auth token")
	}
	if _, err := os.Stat(config.AgentBinary); err != nil {
		return enrollmentPayload{}, fmt.Errorf("LabLink enrollment agent binary: %w", err)
	}

	certPEM, keyPEM, err := ensureGuestServerIdentity(config.PKIDir, plan.LabLinkNodeName)
	if err != nil {
		return enrollmentPayload{}, err
	}
	caPEM, err := os.ReadFile(filepath.Join(config.PKIDir, "ca-bundle", "ca.crt"))
	if err != nil {
		return enrollmentPayload{}, fmt.Errorf("read LabLink CA bundle: %w", err)
	}

	localDir, err := os.MkdirTemp("", "lablink-vm-enroll-*")
	if err != nil {
		return enrollmentPayload{}, err
	}
	cleanupLocal := func() { _ = os.RemoveAll(localDir) }
	files := map[string][]byte{
		"ca.crt":              caPEM,
		"server.crt":          certPEM,
		"server.key":          keyPEM,
		"agent.token":         []byte(config.AuthToken),
		"Install-LabLink.ps1": []byte(guestEnrollmentScript(plan)),
	}
	agentData, err := os.ReadFile(config.AgentBinary)
	if err != nil {
		cleanupLocal()
		return enrollmentPayload{}, err
	}
	files["lablink-agent.exe"] = agentData

	target, err := resolvePlanTarget(plan.Target, reg)
	if err != nil {
		cleanupLocal()
		return enrollmentPayload{}, err
	}
	stageID, err := newRemoteStageID()
	if err != nil {
		cleanupLocal()
		return enrollmentPayload{}, err
	}
	remoteDir := `C:\Windows\Temp\lablink-enroll-` + stageID
	cleanupRemote := func() {
		script := fmt.Sprintf(`Remove-Item -LiteralPath %s -Recurse -Force -ErrorAction SilentlyContinue`, hyperv.PSLit(remoteDir))
		_, _, _ = runPS(context.Background(), reg, pool, target, script, vmDefaultTimeoutSec)
	}
	for name, data := range files {
		localPath := filepath.Join(localDir, name)
		perm := os.FileMode(0644)
		if name == "server.key" || name == "agent.token" {
			perm = 0600
		}
		if err := os.WriteFile(localPath, data, perm); err != nil {
			cleanupRemote()
			cleanupLocal()
			return enrollmentPayload{}, err
		}
		if err := pushToTarget(ctx, reg, pool, target, localPath, remoteDir+`\`+name); err != nil {
			cleanupRemote()
			cleanupLocal()
			return enrollmentPayload{}, fmt.Errorf("stage enrollment payload %s: %w", name, err)
		}
	}
	return enrollmentPayload{
		RemoteDir: remoteDir,
		Cleanup: func() {
			cleanupRemote()
			cleanupLocal()
		},
	}, nil
}

func ensureGuestServerIdentity(pkiDir, nodeName string) ([]byte, []byte, error) {
	if err := validateVMPathName(nodeName); err != nil {
		return nil, nil, fmt.Errorf("invalid LabLink node name: %w", err)
	}
	serverDir := filepath.Join(pkiDir, "issued", "servers", nodeName)
	certPath := filepath.Join(serverDir, "server.crt")
	keyPath := filepath.Join(serverDir, "server.key")
	if certPEM, certErr := os.ReadFile(certPath); certErr == nil {
		if keyPEM, keyErr := os.ReadFile(keyPath); keyErr == nil {
			return certPEM, keyPEM, nil
		}
	}

	issuingCert, err := pki.ReadCertificate(filepath.Join(pkiDir, "issuing", "issuing.crt"))
	if err != nil {
		return nil, nil, fmt.Errorf("read issuing certificate: %w", err)
	}
	issuingKey, err := pki.ReadECDSAPrivateKey(filepath.Join(pkiDir, "issuing", "issuing.key"))
	if err != nil {
		return nil, nil, fmt.Errorf("read issuing key: %w", err)
	}
	issuingPEM, err := os.ReadFile(filepath.Join(pkiDir, "issuing", "issuing.crt"))
	if err != nil {
		return nil, nil, err
	}
	keyPEM, csrPEM, csr, err := pki.CreateServerCSR(nodeName, nodeName)
	if err != nil {
		return nil, nil, err
	}
	certPEM, _, err := pki.SignServerCSR(csr, 5*365*24*time.Hour, time.Now(), issuingCert, issuingKey, issuingPEM)
	if err != nil {
		return nil, nil, err
	}
	if err := pki.WritePEMFile(filepath.Join(serverDir, "server.csr"), csrPEM, 0644); err != nil {
		return nil, nil, err
	}
	if err := pki.WritePEMFile(certPath, certPEM, 0644); err != nil {
		return nil, nil, err
	}
	if err := pki.WritePEMFile(keyPath, keyPEM, 0600); err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

func guestEnrollmentScript(plan windowsVMPlan) string {
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$payload = $PSScriptRoot
$dest = 'C:\LabLink'
$tls = Join-Path $dest 'tls'
New-Item -ItemType Directory -Force -Path $dest,$tls | Out-Null
Copy-Item (Join-Path $payload 'lablink-agent.exe') (Join-Path $dest 'lablink-agent.exe') -Force
Copy-Item (Join-Path $payload 'agent.token') (Join-Path $dest 'agent.token') -Force
Copy-Item (Join-Path $payload 'ca.crt') (Join-Path $tls 'ca.crt') -Force
Copy-Item (Join-Path $payload 'server.crt') (Join-Path $tls 'server.crt') -Force
Copy-Item (Join-Path $payload 'server.key') (Join-Path $tls 'server.key') -Force
icacls (Join-Path $dest 'agent.token') /inheritance:r /grant:r 'SYSTEM:F' 'Administrators:F' | Out-Null
icacls (Join-Path $tls 'server.key') /inheritance:r /grant:r 'SYSTEM:F' 'Administrators:F' | Out-Null
Remove-Item (Join-Path $payload 'agent.token') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $payload 'server.key') -Force -ErrorAction SilentlyContinue
$exe = Join-Path $dest 'lablink-agent.exe'
$installArgs = @('--install','--listen',':%d','--transport','mtls','--auth-token-file',(Join-Path $dest 'agent.token'),'--tls-ca',(Join-Path $tls 'ca.crt'),'--tls-cert',(Join-Path $tls 'server.crt'),'--tls-key',(Join-Path $tls 'server.key'))
$install = Start-Process -FilePath $exe -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
if ($install.ExitCode -ne 0) { throw "lablink-agent install failed: $($install.ExitCode)" }
if (-not (Get-NetFirewallRule -DisplayName 'LabLink Agent' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'LabLink Agent' -Direction Inbound -Protocol TCP -LocalPort %d -Program $exe -Action Allow -Profile Any | Out-Null
}
Start-Service -Name 'LabLink Agent'
Set-Location $env:TEMP
Remove-Item -LiteralPath $payload -Recurse -Force -ErrorAction SilentlyContinue
`, plan.LabLinkPort, plan.LabLinkPort)
}

func enrollmentFirstBootScript(userScript string) string {
	var b strings.Builder
	b.WriteString(`& 'C:\Windows\Setup\Scripts\LabLinkPayload\Install-LabLink.ps1'`)
	b.WriteString("\r\n")
	if strings.TrimSpace(userScript) != "" {
		b.WriteString(userScript)
		b.WriteString("\r\n")
	}
	return b.String()
}

type startedVMInfo struct {
	IPAddress string `json:"ip_address"`
	State     string `json:"state"`
}

func startVMAndDiscoverIP(ctx context.Context, plan windowsVMPlan, reg *registry.Registry, pool *agentclient.Pool) (startedVMInfo, error) {
	target, err := resolvePlanTarget(plan.Target, reg)
	if err != nil {
		return startedVMInfo{}, err
	}
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$name = %s
$deadline = (Get-Date).AddMinutes(15)
$vm = Get-VM -Name $name -ErrorAction Stop
if ($vm.State -ne 'Running') {
    try {
        Start-VM -Name $name -ErrorAction Stop | Out-Null
    } catch {
        throw "VM_START_FAILED: VM '$name' could not start: $($_.Exception.Message)"
    }
}
do {
    $ip = Get-VMNetworkAdapter -VMName $name -ErrorAction SilentlyContinue |
        ForEach-Object IPAddresses |
        Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -notmatch '^169\.254\.' -and $_ -ne '127.0.0.1' } |
        Select-Object -First 1
    if ($ip) { break }
    Start-Sleep -Seconds 5
} while ((Get-Date) -lt $deadline)
if (-not $ip) { throw "VM_IP_TIMEOUT: VM '$name' did not report an IPv4 address within 15 minutes" }
[pscustomobject]@{ ip_address=$ip; state=[string](Get-VM -Name $name).State } | ConvertTo-Json -Compress
`, hyperv.PSLit(plan.Name))
	out, _, err := runPS(ctx, reg, pool, target, script, 1000)
	if err != nil {
		return startedVMInfo{}, err
	}
	var result startedVMInfo
	if err := json.Unmarshal([]byte(jsonExtract(out)), &result); err != nil {
		return startedVMInfo{}, fmt.Errorf("parse started VM address: %w", err)
	}
	return result, nil
}

func registerEnrolledVM(ctx context.Context, plan windowsVMPlan, info startedVMInfo, reg *registry.Registry, pool *agentclient.Pool) error {
	address := fmt.Sprintf("%s:%d", info.IPAddress, plan.LabLinkPort)
	deadline := time.Now().Add(5 * time.Minute)
	var lastErr error
	for time.Now().Before(deadline) {
		client, err := pool.GetClient(address, plan.LabLinkNodeName)
		if err == nil {
			probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			live, probeErr := client.GetInfo(probeCtx, &pb.GetInfoRequest{})
			cancel()
			if probeErr == nil {
				return reg.SetNode(&registry.Node{
					Name: plan.LabLinkNodeName, Address: address, Role: plan.LabLinkRole,
					OS: live.Os, Arch: live.Arch, CPUCount: int(live.CpuCount),
					Memory: live.MemoryBytes, LastSeen: time.Now(),
					TransportMode: "mtls", TLSServerName: plan.LabLinkNodeName,
				})
			}
			if isPermanentTLSIdentityError(probeErr) {
				return fmt.Errorf("LabLink guest agent at %s presented the wrong TLS identity for %q: %w", address, plan.LabLinkNodeName, probeErr)
			}
			lastErr = probeErr
		} else {
			lastErr = err
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("LabLink guest agent did not become ready at %s: %w", address, lastErr)
}

func isPermanentTLSIdentityError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "failed to verify certificate") &&
		(strings.Contains(message, "certificate is valid for") ||
			strings.Contains(message, "certificate is not valid for any names"))
}
