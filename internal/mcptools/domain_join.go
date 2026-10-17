package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/secretstore"
	"github.com/nijosmsft/lablink/internal/vmconfig"
)

const domainJoinPasswordEnv = "LABLINK_DOMAIN_JOIN_PASSWORD"

type windowsDomainJoinResult struct {
	Node                  string `json:"node"`
	ComputerName          string `json:"computer_name"`
	Domain                string `json:"domain"`
	Username              string `json:"username"`
	Changed               bool   `json:"changed"`
	Rebooted              bool   `json:"rebooted"`
	SecureChannelVerified bool   `json:"secure_channel_verified"`
	DomainController      string `json:"domain_controller,omitempty"`
}

type domainJoinApplyResult struct {
	ComputerName string `json:"computer_name"`
	Domain       string `json:"domain"`
	Changed      bool   `json:"changed"`
}

type domainJoinVerifyResult struct {
	ComputerName     string `json:"computer_name"`
	Domain           string `json:"domain"`
	PartOfDomain     bool   `json:"part_of_domain"`
	DomainController string `json:"domain_controller"`
}

func registerWindowsDomainJoinTool(
	s *server.MCPServer,
	reg *registry.Registry,
	pool *agentclient.Pool,
	secrets *secretstore.Store,
	auditLog *audit.Log,
	leaseCfg LeaseGateConfig,
) {
	s.AddTool(
		mcp.NewTool("join_windows_domain",
			mcp.WithDescription("Join an existing Windows LabLink node to Active Directory using a saved password secret, reboot once, and verify the Netlogon secure channel."),
			mcp.WithString("node", mcp.Required(), mcp.Description("Existing Windows node name")),
			mcp.WithString("domain", mcp.Required(), mcp.Description("Active Directory DNS domain")),
			mcp.WithString("username", mcp.Required(), mcp.Description("Domain account in DOMAIN\\user or user@domain form")),
			mcp.WithString("password_secret", mcp.Required(), mcp.Description("Saved secret name containing the domain account password")),
			mcp.WithString("ou_path", mcp.Description("Optional computer-account OU distinguished name")),
			mcp.WithBoolean("reboot", mcp.Description("Reboot after a new join (default true)")),
			mcp.WithBoolean("verify_secure_channel", mcp.Description("Verify domain membership and Netlogon secure channel after reboot (default true)")),
			mcp.WithNumber("wait_seconds", mcp.Description("Maximum reboot recovery time in seconds (default 180)")),
		),
		LeaseGate(leaseCfg, extractSingleNode("node"), joinWindowsDomainHandler(reg, pool, secrets, auditLog)),
	)
}

func joinWindowsDomainHandler(
	reg *registry.Registry,
	pool *agentclient.Pool,
	secrets *secretstore.Store,
	auditLog *audit.Log,
) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		waitSeconds := req.GetInt("wait_seconds", 180)
		stopHeartbeat := StartMCPHeartbeat(ctx, req, defaultHeartbeatInterval, func() (int64, int64) {
			return int64(time.Since(start).Seconds()), int64(waitSeconds + 120)
		})
		defer stopHeartbeat()

		reboot := req.GetBool("reboot", true)
		verify := req.GetBool("verify_secure_channel", true)
		config := vmconfig.WindowsDomainJoin{
			Domain:              req.GetString("domain", ""),
			Username:            req.GetString("username", ""),
			PasswordSecret:      req.GetString("password_secret", ""),
			OUPath:              req.GetString("ou_path", ""),
			Reboot:              &reboot,
			VerifySecureChannel: &verify,
		}
		result, err := executeWindowsDomainJoin(
			ctx,
			req.GetString("node", ""),
			config,
			waitSeconds,
			reg,
			pool,
			secrets,
			auditLog,
		)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return vmResult(
			fmt.Sprintf("**Windows node `%s` joined to `%s`**", result.Node, result.Domain),
			marshalPlan(result),
		), nil
	}
}

func executeWindowsDomainJoin(
	ctx context.Context,
	nodeName string,
	config vmconfig.WindowsDomainJoin,
	waitSeconds int,
	reg *registry.Registry,
	pool *agentclient.Pool,
	secrets *secretstore.Store,
	auditLog *audit.Log,
) (windowsDomainJoinResult, error) {
	nodeName = strings.TrimSpace(nodeName)
	if nodeName == "" {
		return windowsDomainJoinResult{}, fmt.Errorf("node is required")
	}
	if err := config.Validate(); err != nil {
		return windowsDomainJoinResult{}, err
	}
	if waitSeconds <= 0 {
		waitSeconds = 180
	}
	node, ok := reg.GetNode(nodeName)
	if !ok {
		return windowsDomainJoinResult{}, fmt.Errorf("node %q not found", nodeName)
	}
	if !strings.EqualFold(strings.TrimSpace(node.OS), "windows") {
		return windowsDomainJoinResult{}, fmt.Errorf("join_windows_domain supports only Windows nodes; node %q reports OS %q", nodeName, node.OS)
	}
	if secrets == nil {
		return windowsDomainJoinResult{}, fmt.Errorf("secret store is not configured")
	}
	password, err := secrets.Get(config.PasswordSecret)
	if err != nil {
		return windowsDomainJoinResult{}, fmt.Errorf("resolve domain password secret %q: %w", config.PasswordSecret, err)
	}

	client, err := pool.GetClient(node.Address, node.TLSServerName)
	if err != nil {
		return windowsDomainJoinResult{}, fmt.Errorf("connect to %s: %w", nodeName, err)
	}
	callCtx, cancel := nodeCallContext(ctx, nodeName)
	defer cancel()

	start := time.Now()
	output, exitCode, _, err := executeAndCollect(
		callCtx,
		client,
		buildWindowsDomainJoinScript(config),
		"powershell",
		"",
		map[string]string{domainJoinPasswordEnv: password},
		120,
	)
	output = redactSecrets(output, []string{password})
	if auditLog != nil {
		auditLog.Append(audit.Entry{
			Timestamp: start, Node: nodeName, Tool: "join_windows_domain",
			Command: "(join Windows domain)", Shell: "powershell",
			ExitCode: exitCode, DurationMs: time.Since(start).Milliseconds(),
			OutputBytes: len(output),
		})
	}
	if err != nil {
		return windowsDomainJoinResult{}, fmt.Errorf("execute domain join on %s: %w", nodeName, err)
	}
	if exitCode != 0 {
		return windowsDomainJoinResult{}, fmt.Errorf("domain join on %s exited %d: %s", nodeName, exitCode, strings.TrimSpace(output))
	}
	var applied domainJoinApplyResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &applied); err != nil {
		return windowsDomainJoinResult{}, fmt.Errorf("parse domain join result from %s: %w; output: %s", nodeName, err, strings.TrimSpace(output))
	}

	result := windowsDomainJoinResult{
		Node: nodeName, ComputerName: applied.ComputerName,
		Domain: config.Domain, Username: config.Username, Changed: applied.Changed,
	}
	if applied.Changed && config.EffectiveReboot() {
		rebootReq := mcp.CallToolRequest{}
		rebootReq.Params.Arguments = map[string]any{"node": nodeName, "wait_seconds": waitSeconds}
		rebootResult, rebootErr := rebootNodeHandler(reg, pool, auditLog)(ctx, rebootReq)
		if rebootErr != nil {
			return windowsDomainJoinResult{}, fmt.Errorf("domain joined but reboot failed: %w", rebootErr)
		}
		if rebootResult == nil || rebootResult.IsError {
			return windowsDomainJoinResult{}, fmt.Errorf("domain joined but reboot verification failed: %s", toolResultText(rebootResult))
		}
		result.Rebooted = true
	}
	if config.EffectiveVerifySecureChannel() {
		verified, err := verifyWindowsDomainJoin(ctx, node, config.Domain, pool, auditLog)
		if err != nil {
			return windowsDomainJoinResult{}, err
		}
		result.ComputerName = verified.ComputerName
		result.Domain = verified.Domain
		result.SecureChannelVerified = true
		result.DomainController = verified.DomainController
	}
	return result, nil
}

func verifyWindowsDomainJoin(
	ctx context.Context,
	node *registry.Node,
	domain string,
	pool *agentclient.Pool,
	auditLog *audit.Log,
) (domainJoinVerifyResult, error) {
	client, err := pool.GetClient(node.Address, node.TLSServerName)
	if err != nil {
		return domainJoinVerifyResult{}, fmt.Errorf("reconnect to %s for domain verification: %w", node.Name, err)
	}
	callCtx, cancel := nodeCallContext(ctx, node.Name)
	defer cancel()
	start := time.Now()
	output, exitCode, _, err := executeAndCollect(
		callCtx, client, buildWindowsDomainVerifyScript(domain), "powershell", "", nil, 60,
	)
	if auditLog != nil {
		auditLog.Append(audit.Entry{
			Timestamp: start, Node: node.Name, Tool: "join_windows_domain",
			Command: "(verify Windows domain secure channel)", Shell: "powershell",
			ExitCode: exitCode, DurationMs: time.Since(start).Milliseconds(),
			OutputBytes: len(output),
		})
	}
	if err != nil {
		return domainJoinVerifyResult{}, fmt.Errorf("verify domain join on %s: %w", node.Name, err)
	}
	if exitCode != 0 {
		return domainJoinVerifyResult{}, fmt.Errorf("verify domain join on %s exited %d: %s", node.Name, exitCode, strings.TrimSpace(output))
	}
	var result domainJoinVerifyResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &result); err != nil {
		return domainJoinVerifyResult{}, fmt.Errorf("parse domain verification result from %s: %w; output: %s", node.Name, err, strings.TrimSpace(output))
	}
	return result, nil
}

func buildWindowsDomainJoinScript(config vmconfig.WindowsDomainJoin) string {
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$domain = %s
$username = %s
$ouPath = %s
$system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
if ($system.PartOfDomain) {
    if ($system.Domain -ine $domain) {
        throw "ALREADY_JOINED_TO_DIFFERENT_DOMAIN: '$($system.Domain)'"
    }
    [pscustomobject]@{ computer_name=$env:COMPUTERNAME; domain=$system.Domain; changed=$false } | ConvertTo-Json -Compress
    exit 0
}
$null = Resolve-DnsName -Name $domain -Type A -ErrorAction Stop
$dc = & nltest.exe /dsgetdc:$domain 2>&1
if ($LASTEXITCODE -ne 0) { throw "DOMAIN_CONTROLLER_DISCOVERY_FAILED: $($dc -join ' | ')" }
$password = $env:%s
if ([string]::IsNullOrEmpty($password)) { throw 'DOMAIN_PASSWORD_SECRET_EMPTY' }
$secure = ConvertTo-SecureString $password -AsPlainText -Force
$credential = [pscredential]::new($username, $secure)
try {
    $parameters = @{
        DomainName=$domain; Credential=$credential; Force=$true; PassThru=$true
        ErrorAction='Stop'; WarningAction='SilentlyContinue'
    }
    if (-not [string]::IsNullOrWhiteSpace($ouPath)) { $parameters['OUPath'] = $ouPath }
    $joined = Add-Computer @parameters
    if (-not $joined.HasSucceeded) { throw 'ADD_COMPUTER_REPORTED_FAILURE' }
    [pscustomobject]@{ computer_name=$env:COMPUTERNAME; domain=$domain; changed=$true } | ConvertTo-Json -Compress
} finally {
    Remove-Item Env:%s -ErrorAction SilentlyContinue
    $credential = $null
    $secure = $null
    $password = $null
}
`, hyperv.PSLit(strings.TrimSpace(config.Domain)), hyperv.PSLit(strings.TrimSpace(config.Username)),
		hyperv.PSLit(strings.TrimSpace(config.OUPath)), domainJoinPasswordEnv, domainJoinPasswordEnv)
}

func buildWindowsDomainVerifyScript(domain string) string {
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$expectedDomain = %s
$system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
if (-not $system.PartOfDomain) { throw 'COMPUTER_NOT_JOINED_TO_DOMAIN' }
if ($system.Domain -ine $expectedDomain) { throw "DOMAIN_MISMATCH: '$($system.Domain)'" }
$channel = & nltest.exe /sc_verify:$expectedDomain 2>&1
if ($LASTEXITCODE -ne 0) { throw "SECURE_CHANNEL_VERIFICATION_FAILED: $($channel -join ' | ')" }
$dcLine = $channel | Where-Object { $_ -match 'Trusted DC Name' } | Select-Object -First 1
$dc = if ($dcLine -match '\\\\([^\s]+)') { $Matches[1] } else { '' }
[pscustomobject]@{
    computer_name=$env:COMPUTERNAME; domain=$system.Domain; part_of_domain=$true
    domain_controller=$dc
} | ConvertTo-Json -Compress
`, hyperv.PSLit(strings.TrimSpace(domain)))
}

func windowsDomainJoinSchema(name, description string) mcp.ToolOption {
	return mcp.WithObject(name,
		mcp.Description(description),
		mcp.Properties(map[string]any{
			"domain": map[string]any{
				"type": "string", "description": "Active Directory DNS domain",
			},
			"username": map[string]any{
				"type": "string", "description": "Domain account in DOMAIN\\user or user@domain form",
			},
			"password_secret": map[string]any{
				"type": "string", "description": "Saved secret name containing the domain account password",
			},
			"ou_path": map[string]any{
				"type": "string", "description": "Optional computer-account OU distinguished name",
			},
			"reboot": map[string]any{
				"type": "boolean", "description": "Reboot after a new join (default true)",
			},
			"verify_secure_channel": map[string]any{
				"type": "boolean", "description": "Verify Netlogon secure channel after reboot (default true)",
			},
		}),
		func(schema map[string]any) {
			schema["required"] = []string{"domain", "username", "password_secret"}
		},
		mcp.AdditionalProperties(false),
	)
}

func parseWindowsDomainJoinArgument(value any) (*vmconfig.WindowsDomainJoin, error) {
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("domain_join must be an object")
	}
	allowed := map[string]struct{}{
		"domain": {}, "username": {}, "password_secret": {}, "ou_path": {},
		"reboot": {}, "verify_secure_channel": {},
	}
	for name := range object {
		if _, ok := allowed[name]; !ok {
			return nil, fmt.Errorf("domain_join contains unsupported field %q", name)
		}
	}
	config := &vmconfig.WindowsDomainJoin{}
	if value, exists := object["domain"]; exists {
		typed, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("domain_join.domain must be a string")
		}
		config.Domain = typed
	}
	if value, exists := object["username"]; exists {
		typed, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("domain_join.username must be a string")
		}
		config.Username = typed
	}
	if value, exists := object["password_secret"]; exists {
		typed, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("domain_join.password_secret must be a string")
		}
		config.PasswordSecret = typed
	}
	if value, exists := object["ou_path"]; exists {
		typed, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("domain_join.ou_path must be a string")
		}
		config.OUPath = typed
	}
	if value, exists := object["reboot"]; exists {
		typed, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("domain_join.reboot must be a boolean")
		}
		config.Reboot = &typed
	}
	if value, exists := object["verify_secure_channel"]; exists {
		typed, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("domain_join.verify_secure_channel must be a boolean")
		}
		config.VerifySecureChannel = &typed
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return config, nil
}
