package mcptools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/linuximage"
	internalsec "github.com/nijosmsft/lablink/internal/security"
	"github.com/nijosmsft/lablink/internal/vmconfig"
	pb "github.com/nijosmsft/lablink/proto/agent"
	"google.golang.org/grpc"
)

type linuxImageMockAgent struct {
	pb.UnimplementedNodeAgentServer
	mu        sync.Mutex
	responses []string
	scripts   []string
	envs      []map[string]string
	failAt    int
	failure   string
}

func (a *linuxImageMockAgent) ExecuteScript(req *pb.ExecuteScriptRequest, stream grpc.ServerStreamingServer[pb.ExecuteResponse]) error {
	a.mu.Lock()
	a.scripts = append(a.scripts, req.ScriptBody)
	a.envs = append(a.envs, cloneStringMap(req.Env))
	call := len(a.scripts)
	response := `{"status":"ready"}`
	if len(a.responses) > 0 {
		response = a.responses[0]
		a.responses = a.responses[1:]
	}
	fail := a.failAt > 0 && call == a.failAt
	failure := a.failure
	a.mu.Unlock()
	if err := stream.Send(&pb.ExecuteResponse{Pid: 1, Data: []byte(response)}); err != nil {
		return err
	}
	if fail {
		if failure == "" {
			failure = "injected transport failure"
		}
		if err := stream.Send(&pb.ExecuteResponse{Data: []byte(failure)}); err != nil {
			return err
		}
		return stream.Send(&pb.ExecuteResponse{Done: true, ExitCode: 1})
	}
	return stream.Send(&pb.ExecuteResponse{Done: true, ExitCode: 0})
}

func (a *linuxImageMockAgent) Scripts() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.scripts...)
}

func (a *linuxImageMockAgent) Envs() []map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	result := make([]map[string]string, len(a.envs))
	for i, env := range a.envs {
		result[i] = cloneStringMap(env)
	}
	return result
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func TestResolveLinuxImagePlanRequiresValidWindowsBuilderBeforeMutation(t *testing.T) {
	tests := map[string]string{
		"missing builder": `{
  "default_linux_profile":"ubuntu",
  "profiles":{"ubuntu":{"guest_os":"linux","target":"localhost","image_cache_root":"E:\\Images"}}
}`,
		"builder is Linux": `{
  "default_linux_profile":"ubuntu",
  "profiles":{
    "ubuntu":{"guest_os":"linux","target":"localhost","image_cache_root":"E:\\Images","image_builder_profile":"wrong"},
    "wrong":{"guest_os":"linux","target":"localhost"}
  }
}`,
		"builder incomplete": `{
  "default_linux_profile":"ubuntu",
  "profiles":{
    "ubuntu":{"guest_os":"linux","target":"localhost","image_cache_root":"E:\\Images","image_builder_profile":"builder"},
    "builder":{"guest_os":"windows","target":"localhost","base_vhd":"E:\\base.vhdx"}
  }
}`,
		"builder credential unavailable": `{
  "default_linux_profile":"ubuntu",
  "profiles":{
    "ubuntu":{"guest_os":"linux","target":"localhost","image_cache_root":"E:\\Images","image_builder_profile":"builder"},
    "builder":{
      "guest_os":"windows","target":"localhost","base_vhd":"E:\\base.vhdx","vm_root":"E:\\VM",
      "vswitch":"ext","admin_password_credential":"missing"
    }
  }
}`,
		"builder targets another host": `{
  "default_linux_profile":"ubuntu",
  "profiles":{
    "ubuntu":{"guest_os":"linux","target":"localhost","image_cache_root":"E:\\Images","image_builder_profile":"builder"},
    "builder":{
      "guest_os":"windows","target":"other-host","base_vhd":"E:\\base.vhdx","vm_root":"E:\\VM",
      "vswitch":"ext","admin_password_credential":"builder-admin"
    }
  }
}`,
		"builder missing VBS opt-out": `{
  "default_linux_profile":"ubuntu",
  "profiles":{
    "ubuntu":{"guest_os":"linux","target":"localhost","image_cache_root":"E:\\Images","image_builder_profile":"builder"},
    "builder":{
      "guest_os":"windows","target":"localhost","base_vhd":"E:\\base.vhdx","vm_root":"E:\\VM",
      "vswitch":"ext","admin_password_credential":"builder-admin",
      "dynamic_memory":false,"expose_virtualization_extensions":true
    }
  }
}`,
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			store, creds := linuxBuilderStores(t, data)
			agent := &linuxImageMockAgent{}
			addr := startNodeAgent(t, agent)
			reg := newRebootTestRegistry(t, map[string]string{"unused": addr})
			handler := prepareLinuxImageHandler(reg, nil, store, creds, nil, VMEnrollmentConfig{}, LeaseGateConfig{})
			result, err := handler(context.Background(), reqNoToken(map[string]any{}))
			if err != nil || result == nil || !result.IsError {
				t.Fatalf("expected builder validation error: result=%#v err=%v", result, err)
			}
			if len(agent.Scripts()) != 0 {
				t.Fatal("invalid builder profile reached host mutation")
			}
		})
	}
}

func TestResolveLinuxImagePlanRejectsBuilderWithoutVBSOptOut(t *testing.T) {
	store, creds := linuxBuilderStores(t, strings.Replace(
		validBuilderConfig(false),
		`,"expose_virtualization_extensions":true,
      "virtualization_based_security_opt_out":true`,
		`,"expose_virtualization_extensions":true`,
		1,
	))
	_, _, err := resolveLinuxImagePlan(reqNoToken(map[string]any{}), newRebootTestRegistry(t, nil), store, creds)
	if err == nil || !strings.Contains(err.Error(), "virtualization_based_security_opt_out=true") {
		t.Fatalf("expected explicit VBS opt-out validation error, got %v", err)
	}
}

func TestResolveLinuxImagePlanRequiresCompleteBuilderCredential(t *testing.T) {
	store, creds := linuxBuilderStores(t, validBuilderConfig(false))
	if err := creds.Set(&credentials.Profile{Name: "builder-admin", Password: "secret"}); err != nil {
		t.Fatal(err)
	}
	_, _, err := resolveLinuxImagePlan(reqNoToken(map[string]any{}), newRebootTestRegistry(t, nil), store, creds)
	if err == nil || !strings.Contains(err.Error(), "must contain username and password") {
		t.Fatalf("expected complete builder credential validation, got %v", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("builder credential validation leaked the password")
	}
}

func TestResolveLinuxImagePlanBuildsNestedWindowsBuilder(t *testing.T) {
	store, creds := linuxBuilderStores(t, validBuilderConfig(false))
	plan, target, err := resolveLinuxImagePlan(reqNoToken(map[string]any{}), newRebootTestRegistry(t, nil), store, creds)
	if err != nil {
		t.Fatal(err)
	}
	if !target.IsLocal || plan.ImageBuilderProfile != "builder" || plan.BuilderVMName != "LL-LNXBLD-LOCAL" {
		t.Fatalf("unexpected plan: %+v target=%+v", plan, target)
	}
	if !plan.Builder.ExposeVirtualizationExtensions || !plan.Builder.VirtualizationBasedSecurityOptOut ||
		plan.Builder.DynamicMemory || !plan.Builder.RegisterWithLabLink ||
		plan.Builder.LabLinkRole != "linux-image-builder" ||
		plan.Builder.LabLinkNodeName == "" || plan.Builder.ManagedMetadata == "" {
		t.Fatalf("builder plan lacks nested virtualization/enrollment ownership: %+v", plan.Builder)
	}
	if plan.DeleteBuilderAfterPrepare {
		t.Fatal("builder should be retained stopped by default")
	}
}

func TestResolveLinuxImagePlanDeleteBuilderOverride(t *testing.T) {
	store, creds := linuxBuilderStores(t, validBuilderConfig(false))
	plan, _, err := resolveLinuxImagePlan(reqNoToken(map[string]any{
		"builder_vm_name": "Custom-Builder", "delete_builder_after_prepare": true,
	}), newRebootTestRegistry(t, nil), store, creds)
	if err != nil {
		t.Fatal(err)
	}
	if plan.BuilderVMName != "Custom-Builder" || !plan.DeleteBuilderAfterPrepare {
		t.Fatalf("override not applied: %+v", plan)
	}
}

func TestPrepareLinuxImageDryRunDoesNotExecute(t *testing.T) {
	store, creds := linuxBuilderStores(t, validBuilderConfig(false))
	handler := prepareLinuxImageHandler(newRebootTestRegistry(t, nil), nil, store, creds, nil, VMEnrollmentConfig{}, LeaseGateConfig{})
	result, err := handler(context.Background(), reqNoToken(map[string]any{"dry_run": true}))
	if err != nil || result == nil || result.IsError {
		t.Fatalf("dry run: result=%#v err=%v", result, err)
	}
	text := toolResultText(result)
	for _, want := range []string{
		linuximage.ImageURL, linuximage.TransformSchema, `"image_builder_profile": "builder"`,
		`"expose_virtualization_extensions": true`, `"lablink_role": "linux-image-builder"`,
		`"virtualization_based_security_opt_out": true`, `"dynamic_memory": false`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("dry-run output missing %q:\n%s", want, text)
		}
	}
}

func TestPrepareLinuxImageReturnsActiveBITSBeforeBuilderMutation(t *testing.T) {
	store, creds := linuxBuilderStores(t, strings.ReplaceAll(validBuilderConfig(false), `"target":"localhost"`, `"target":"node1"`))
	agent := &linuxImageMockAgent{responses: []string{
		`{"status":"builder_source_ready","source_preconditions_valid":true}`,
		`{"status":"ready","filesystem_mutation":false}`,
		`{"status":"image_preparing","all_complete":false,"state":{"phase":"downloading","jobs":[{"kind":"azure_vhd_archive","state":"Transferring"}]}}`,
	}}
	addr := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	handler := prepareLinuxImageHandler(reg, pool, store, creds, nil, VMEnrollmentConfig{}, LeaseGateConfig{})
	result, err := handler(context.Background(), reqNoToken(map[string]any{}))
	if err != nil || result == nil || result.IsError {
		t.Fatalf("prepare: result=%#v err=%v", result, err)
	}
	if text := toolResultText(result); !strings.Contains(text, "BITS is active") {
		t.Fatalf("unexpected result:\n%s", text)
	}
	scripts := agent.Scripts()
	if len(scripts) != 3 || strings.Contains(strings.ToLower(strings.Join(scripts, "\n")), "wsl.exe") ||
		strings.Contains(strings.Join(scripts, "\n"), "New-VM") {
		t.Fatalf("download progress reached builder/WSL mutation: %d scripts", len(scripts))
	}
}

func TestLinuxImageBuilderUserScriptsSendCredentialOnlyInEnvAndRedact(t *testing.T) {
	const secret = "builder-password-never-print"
	store, creds := linuxBuilderStores(t, validBuilderConfig(false))
	if err := creds.Set(&credentials.Profile{
		Name: "builder-admin", Username: "BuilderAdmin", Password: secret,
	}); err != nil {
		t.Fatal(err)
	}
	plan, _, err := resolveLinuxImagePlan(reqNoToken(map[string]any{}), newRebootTestRegistry(t, nil), store, creds)
	if err != nil {
		t.Fatal(err)
	}
	agent := &linuxImageMockAgent{responses: []string{
		`{"status":"builder_ready"}`,
		`{"status":"filesystem_updated","safe_to_detach":true}`,
		"LABLINK_ERROR: transport echoed " + secret,
	}, failAt: 3, failure: secret}
	addr := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"builder": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	builder, err := resolvePlanTarget("builder", reg)
	if err != nil {
		t.Fatal(err)
	}
	payloads := []string{
		"Write-Output 'setup payload'",
		"Write-Output 'transform payload'",
	}
	for _, payload := range payloads {
		wrapper, wrapErr := hyperv.BuildLinuxImageBuilderUserTaskScript(payload, 60)
		if wrapErr != nil {
			t.Fatal(wrapErr)
		}
		if _, _, runErr := runLinuxImageBuilderUserScript(
			context.Background(), plan, reg, pool, builder, creds, wrapper, 30,
		); runErr != nil {
			t.Fatalf("builder user script: %v", runErr)
		}
	}
	failing, _ := hyperv.BuildLinuxImageBuilderUserTaskScript("throw 'failure'", 60)
	output, _, runErr := runLinuxImageBuilderUserScript(
		context.Background(), plan, reg, pool, builder, creds, failing, 30,
	)
	if runErr == nil {
		t.Fatal("expected injected builder user script failure")
	}
	if strings.Contains(output, secret) || strings.Contains(runErr.Error(), secret) ||
		!strings.Contains(output, passwordMask) {
		t.Fatalf("builder password was not redacted: output=%q error=%v", output, runErr)
	}
	scripts := agent.Scripts()
	envs := agent.Envs()
	if len(scripts) != 3 || len(envs) != 3 {
		t.Fatalf("recorded calls: scripts=%d envs=%d", len(scripts), len(envs))
	}
	for i := range scripts {
		if strings.Contains(scripts[i], secret) {
			t.Fatalf("password leaked into builder wrapper %d", i)
		}
		if envs[i]["LABLINK_BUILDER_USERNAME"] != "BuilderAdmin" ||
			envs[i]["LABLINK_BUILDER_PASSWORD"] != secret {
			t.Fatalf("builder call %d env = %#v", i, envs[i])
		}
	}
}

func TestBuilderOrchestratorDoesNotRunWSLDirectlyAsLocalSystem(t *testing.T) {
	source, err := os.ReadFile("linux_image.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if strings.Contains(text, "runPS(ctx, reg, pool, builderTarget, setup") ||
		strings.Contains(text, "runPS(ctx, reg, pool, builderTarget, transform") {
		t.Fatal("setup or transform still runs directly under the LabLink Agent LocalSystem context")
	}
	if strings.Count(text, "runLinuxImageBuilderUserScript(") < 4 {
		t.Fatal("setup, resume, and transform are not all routed through the builder user task")
	}
}

func TestBuilderDiskCleanupRetainsUntilVerifiedTransformAndUnmount(t *testing.T) {
	tests := []struct {
		name   string
		status string
		safe   bool
		want   bool
	}{
		{name: "transport failure before result", want: true},
		{name: "malformed JSON before acceptance", want: true},
		{name: "transform failure after unmount", status: "diagnostic_retained", safe: true, want: true},
		{name: "transform success without explicit safe flag", status: "filesystem_updated", want: true},
		{name: "verified transform and unmount", status: "filesystem_updated", safe: true, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := newLinuxImageBuilderDiskCleanup()
			if tt.status != "" {
				cleanup.acceptVerifiedTransform(tt.status, tt.safe, "diagnostic")
			}
			if cleanup.retain != tt.want {
				t.Fatalf("retain=%t, want %t for status=%q safe=%t", cleanup.retain, tt.want, tt.status, tt.safe)
			}
		})
	}
	cleanup := newLinuxImageBuilderDiskCleanup()
	if !cleanup.acceptVerifiedTransform("filesystem_updated", true, "") || cleanup.retain {
		t.Fatal("verified transform did not authorize detach")
	}
	cleanup.retainForFailure("detach response lost")
	if !cleanup.retain || !strings.Contains(cleanup.reason, "response lost") {
		t.Fatal("detach transport failure did not restore diagnostic retention")
	}
}

func TestBuilderIdentityLockKeysSerializeOnlySameBuilder(t *testing.T) {
	if builderIdentityLockKey("HOST", "Builder") != builderIdentityLockKey("host", "builder") {
		t.Fatal("same Hyper-V builder identity produced different lock keys")
	}
	if builderIdentityLockKey("host", "builder-a") == builderIdentityLockKey("host", "builder-b") {
		t.Fatal("unrelated builders on one host share a lock key")
	}
	if builderIdentityLockKey("host-a", "builder") == builderIdentityLockKey("host-b", "builder") {
		t.Fatal("same builder name on unrelated hosts shares a lock key")
	}
}

func TestDefaultLinuxImageBuilderNameIsStablePerTarget(t *testing.T) {
	if got := defaultLinuxImageBuilderName("localhost"); got != "LL-LNXBLD-LOCAL" {
		t.Fatalf("localhost name = %q", got)
	}
	if a, b := defaultLinuxImageBuilderName("RR1N4406-30"), defaultLinuxImageBuilderName("RR1N4406-30"); a != b {
		t.Fatalf("builder name is not stable: %q != %q", a, b)
	}
	nodeA := linuxImageBuilderNodeName("RR1N4406-30", "builder")
	nodeB := linuxImageBuilderNodeName("RR1N4406-31", "builder")
	if len(nodeA) > 15 || nodeA == nodeB {
		t.Fatalf("builder node identities are unsafe: %q, %q", nodeA, nodeB)
	}
}

func validBuilderConfig(deleteBuilder bool) string {
	deleteValue := "false"
	if deleteBuilder {
		deleteValue = "true"
	}
	return `{
  "default_linux_profile":"ubuntu",
  "profiles":{
    "ubuntu":{
      "guest_os":"linux","target":"localhost","distribution":"ubuntu","release":"24.04",
      "architecture":"amd64","image_cache_root":"E:\\Images","image_builder_profile":"builder",
      "delete_builder_after_prepare":` + deleteValue + `
    },
    "builder":{
      "guest_os":"windows","target":"localhost","base_vhd":"E:\\Windows\\base.vhdx",
      "vm_root":"E:\\VM","vswitch":"extswitch","admin_password_credential":"builder-admin",
      "memory_mb":8192,"cpu_count":4,"register_with_lablink":true,
      "dynamic_memory":false,"expose_virtualization_extensions":true,
      "virtualization_based_security_opt_out":true
    }
  }
}`
}

func linuxBuilderStores(t *testing.T, data string) (*vmconfig.Store, *credentials.Store) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "vm-defaults.json")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	creds := credentials.LoadStore(filepath.Join(root, "credentials.json"))
	if err := creds.Set(&credentials.Profile{Name: "builder-admin", Username: "BuilderAdmin", Password: "secret"}); err != nil {
		t.Fatal(err)
	}
	return vmconfig.Load(path), creds
}

func linuxDefaultsStore(t *testing.T, data string) *vmconfig.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vm-defaults.json")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return vmconfig.Load(path)
}

func TestBuilderRebootUsesFastPollingWithoutChangingFleetRebootPolicy(t *testing.T) {
	source, err := os.ReadFile("linux_image.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "const builderRebootPollInterval = time.Second") ||
		!strings.Contains(text, "time.After(builderRebootPollInterval)") {
		t.Fatal("builder reboot does not use its dedicated fast polling interval")
	}
	if strings.Contains(text, "rebootNodesPollInterval = time.Second") {
		t.Fatal("builder reboot changed the shared fleet reboot polling policy")
	}
}
