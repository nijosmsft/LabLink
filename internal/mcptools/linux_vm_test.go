package mcptools

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/hyperv"
	internalsec "github.com/nijosmsft/lablink/internal/security"
	"github.com/nijosmsft/lablink/internal/vmconfig"
)

func linuxTestKey() string {
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")) + " lab"
}

func TestResolveLinuxVMPlanFromProfile(t *testing.T) {
	store := linuxDefaultsStore(t, `{
  "default_linux_profile":"ubuntu",
  "profiles":{"ubuntu":{
    "guest_os":"linux","target":"localhost","distribution":"ubuntu","release":"24.04","architecture":"amd64",
    "image_cache_root":"E:\\Images","vm_root":"E:\\VM","vswitch":"ext",
    "linux_username":"lab","ssh_public_key":"`+linuxTestKey()+`","memory_mb":8192,"cpu_count":4,"disk_size_gb":80
  }}
}`)
	plan, target, err := resolveLinuxVMPlan(reqNoToken(map[string]any{"name": "Ubuntu Test"}), newRebootTestRegistry(t, nil), store, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Profile != "ubuntu" || plan.Hostname != "ubuntu-test" || plan.VHDPath != `E:\VM\Ubuntu Test\Ubuntu Test.vhdx` ||
		plan.MemoryMB != 8192 || plan.CPUCount != 4 || plan.DiskSizeGB != 80 || !target.IsLocal {
		t.Fatalf("plan=%+v target=%+v", plan, target)
	}
}

func TestCreateLinuxVMDryRunNoMutation(t *testing.T) {
	store := linuxDefaultsStore(t, `{
  "default_linux_profile":"ubuntu",
  "profiles":{"ubuntu":{
    "guest_os":"linux","image_cache_root":"E:\\Images",
    "vm_root":"E:\\VM","vswitch":"ext","linux_username":"lab","ssh_public_key":"`+linuxTestKey()+`"
  }}
}`)
	handler := createLinuxVMHandler(newRebootTestRegistry(t, nil), nil, store, nil, nil, VMEnrollmentConfig{}, LeaseGateConfig{})
	result, err := handler(context.Background(), reqNoToken(map[string]any{"name": "ubuntu-vm", "dry_run": true}))
	if err != nil || result == nil || result.IsError {
		t.Fatalf("dry run: result=%#v err=%v", result, err)
	}
	text := toolResultText(result)
	for _, want := range []string{`"hostname": "ubuntu-vm"`, `"register_with_lablink": true`, `"disk_size_gb": 64`} {
		if !strings.Contains(text, want) {
			t.Errorf("dry run missing %q:\n%s", want, text)
		}
	}
}

func TestCreateLinuxVMImageNotReadyCreatesNoVM(t *testing.T) {
	agent := &linuxImageMockAgent{responses: []string{
		`{"exists":false}`,
		`{"status":"not_started"}`,
		`{"status":"builder_source_ready","source_preconditions_valid":true}`,
		`{"status":"lock_acquired","acquired":true}`,
		`{"exists":false}`,
		`{"status":"reconciled","vm_exists":false}`,
		`{"status":"not_started"}`,
		`{"status":"builder_source_ready","source_preconditions_valid":true}`,
		`{"status":"ready"}`,
		`{"status":"image_preparing","all_complete":false}`,
		`{"status":"downloading","state":{"phase":"downloading"}}`,
	}}
	addr := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	store := linuxDefaultsStore(t, `{
  "default_linux_profile":"ubuntu",
  "profiles":{
  "ubuntu":{
    "guest_os":"linux","target":"node1","image_cache_root":"E:\\Images",
    "vm_root":"E:\\VM","vswitch":"ext","linux_username":"lab","ssh_public_key":"`+linuxTestKey()+`",
    "image_builder_profile":"builder"
  },
  "builder":{
    "guest_os":"windows","profile_usage":"linux_image_builder","target":"node1","base_vhd":"E:\\Windows\\base.vhdx",
    "vm_root":"E:\\VM","vswitch":"ext","admin_password_credential":"builder-admin",
    "dynamic_memory":false,"expose_virtualization_extensions":true,
    "virtualization_based_security_opt_out":true
  }}
}`)
	creds := credentials.LoadStore(filepath.Join(t.TempDir(), "credentials.json"))
	if err := creds.Set(&credentials.Profile{Name: "builder-admin", Username: "BuilderAdmin", Password: "secret"}); err != nil {
		t.Fatal(err)
	}
	handler := createLinuxVMHandler(reg, pool, store, creds, nil, VMEnrollmentConfig{}, LeaseGateConfig{})
	result, err := handler(context.Background(), reqNoToken(map[string]any{"name": "ubuntu-vm"}))
	if err != nil || result == nil || result.IsError {
		t.Fatalf("create: result=%#v err=%v", result, err)
	}
	text := toolResultText(result)
	if !strings.Contains(text, `"status":"image_preparing"`) || !strings.Contains(text, `"vm_created":false`) {
		t.Fatalf("unexpected result:\n%s", text)
	}
	for _, script := range agent.Scripts() {
		if strings.Contains(script, "New-VM") || strings.Contains(script, "New-VHD") {
			t.Fatal("image-not-ready flow attempted VM mutation")
		}
	}
}

func TestCreateLinuxVMCacheMissValidatesBuilderBeforeLifecycleLock(t *testing.T) {
	agent := &linuxImageMockAgent{responses: []string{
		`{"exists":false}`,
		`{"status":"not_started"}`,
	}}
	addr := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	store := linuxDefaultsStore(t, `{
  "default_linux_profile":"ubuntu",
  "profiles":{"ubuntu":{
    "guest_os":"linux","target":"node1","image_cache_root":"E:\\Images",
    "vm_root":"E:\\VM","vswitch":"ext","linux_username":"lab","ssh_public_key":"`+linuxTestKey()+`"
  }}
}`)
	handler := createLinuxVMHandler(reg, pool, store, nil, nil, VMEnrollmentConfig{}, LeaseGateConfig{})
	result, err := handler(context.Background(), reqNoToken(map[string]any{"name": "ubuntu-vm"}))
	if err != nil || result == nil || !result.IsError ||
		!strings.Contains(toolResultText(result), "image_builder_profile is required") {
		t.Fatalf("expected early builder validation failure: result=%#v err=%v", result, err)
	}
	joined := strings.Join(agent.Scripts(), "\n")
	for _, forbidden := range []string{"vm-locks", "status='reconciled'", "New-Item -ItemType Directory -Force -Path $vmLocation"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("builder validation failure occurred after lifecycle mutation %q:\n%s", forbidden, joined)
		}
	}
}

func TestCreateLinuxVMBuilderSourceFailurePrecedesLifecycleLock(t *testing.T) {
	agent := &linuxImageMockAgent{
		responses: []string{
			`{"exists":false}`,
			`{"status":"not_started"}`,
			`{"status":"builder_source_ready"}`,
		},
		failAt: 3, failure: "BUILDER_BASE_VHD_NOT_FOUND",
	}
	addr := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	store, creds := linuxBuilderStores(t, strings.ReplaceAll(validBuilderConfig(false), `"target":"localhost"`, `"target":"node1"`))
	handler := createLinuxVMHandler(reg, pool, store, creds, nil, VMEnrollmentConfig{}, LeaseGateConfig{})
	result, err := handler(context.Background(), reqNoToken(map[string]any{
		"name": "ubuntu-vm", "vm_root": `E:\VM`, "vswitch": "ext",
		"linux_username": "lab", "ssh_public_key": linuxTestKey(),
	}))
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("expected builder source failure: result=%#v err=%v", result, err)
	}
	joined := strings.Join(agent.Scripts(), "\n")
	if strings.Contains(joined, "vm-locks") || strings.Contains(joined, "status='reconciled'") {
		t.Fatalf("source failure occurred after lifecycle lock or reconciliation:\n%s", joined)
	}
}

func TestLinuxVMValidationBeforeMutation(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "id.pub")
	if err := os.WriteFile(keyFile, []byte(linuxTestKey()), 0600); err != nil {
		t.Fatal(err)
	}

	store := vmconfig.Load(filepath.Join(t.TempDir(), "missing.json"))
	base := map[string]any{
		"target": "localhost", "name": "vm", "hostname": "good", "linux_username": "lab",
		"ssh_public_key_file": keyFile, "image_cache_root": `E:\Images`,
		"vm_root": `E:\VM`, "vswitch": "ext",
	}
	for name, mutate := range map[string]func(map[string]any){
		"hostname": func(v map[string]any) { v["hostname"] = "Bad_Name" },
		"username": func(v map[string]any) { v["linux_username"] = "root" },
		"key":      func(v map[string]any) { v["ssh_public_key_file"] = filepath.Join(t.TempDir(), "missing.pub") },
		"path":     func(v map[string]any) { v["vm_root"] = `E:\VM\..\bad` },
	} {
		t.Run(name, func(t *testing.T) {
			args := cloneArguments(base)
			mutate(args)
			if _, _, err := resolveLinuxVMPlan(reqNoToken(args), newRebootTestRegistry(t, nil), store, nil); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLinuxVMRemotePathsUseWindowsSemantics(t *testing.T) {
	store := linuxDefaultsStore(t, `{
  "default_linux_profile":"ubuntu",
  "profiles":{"ubuntu":{
    "guest_os":"linux","image_cache_root":"\\\\host\\images",
    "vm_root":"\\\\host\\vms","vswitch":"ext","linux_username":"lab","ssh_public_key":"`+linuxTestKey()+`"
  }}
}`)
	plan, _, err := resolveLinuxVMPlan(reqNoToken(map[string]any{"name": "vm"}), newRebootTestRegistry(t, nil), store, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.VMLocation != `\\host\vms\vm` || plan.VHDPath != `\\host\vms\vm\vm.vhdx` {
		t.Fatalf("remote Windows paths were joined with server OS semantics: %+v", plan)
	}
}

func TestLinuxVMAccessModesAndCredentialRedaction(t *testing.T) {
	const secret = "Never-Print-This-Password!"
	creds := credentials.LoadStore(filepath.Join(t.TempDir(), "credentials.json"))
	if err := creds.Set(&credentials.Profile{Name: "linux-lab", Username: "lab", Password: secret}); err != nil {
		t.Fatal(err)
	}
	store := vmconfig.Load(filepath.Join(t.TempDir(), "missing.json"))
	base := map[string]any{
		"target": "localhost", "name": "vm", "linux_username": "lab",
		"image_cache_root": `E:\Images`, "vm_root": `E:\VM`, "vswitch": "ext",
	}
	tests := []struct {
		name         string
		args         map[string]any
		wantKey      bool
		wantPassword bool
	}{
		{name: "key-only", args: map[string]any{"ssh_public_key": linuxTestKey()}, wantKey: true},
		{name: "password-only", args: map[string]any{"linux_password_credential": "linux-lab"}, wantPassword: true},
		{name: "both", args: map[string]any{"ssh_public_key": linuxTestKey(), "linux_password_credential": "linux-lab"}, wantKey: true, wantPassword: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := cloneArguments(base)
			for key, value := range tt.args {
				args[key] = value
			}
			plan, _, err := resolveLinuxVMPlan(reqNoToken(args), newRebootTestRegistry(t, nil), store, creds)
			if err != nil {
				t.Fatal(err)
			}
			if (plan.SSHPublicKey != "") != tt.wantKey || (plan.PasswordHash != "") != tt.wantPassword ||
				plan.AllowSSHPasswordAuth != tt.wantPassword {
				t.Fatalf("access plan = %+v", plan)
			}
			serialized := marshalPlan(plan)
			if strings.Contains(serialized, secret) || strings.Contains(serialized, plan.PasswordHash) && plan.PasswordHash != "" {
				t.Fatalf("credential material leaked into plan: %s", serialized)
			}
		})
	}

	for name, args := range map[string]map[string]any{
		"missing-access": {},
		"password-disabled": {
			"linux_password_credential": "linux-lab",
			"allow_ssh_password_auth":   false,
		},
		"password-enabled-without-credential": {
			"ssh_public_key":          linuxTestKey(),
			"allow_ssh_password_auth": true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := cloneArguments(base)
			for key, value := range args {
				request[key] = value
			}
			if _, _, err := resolveLinuxVMPlan(reqNoToken(request), newRebootTestRegistry(t, nil), store, creds); err == nil {
				t.Fatal("expected access validation error")
			} else if strings.Contains(err.Error(), secret) {
				t.Fatal("credential plaintext leaked into error")
			}
		})
	}

	handler := createLinuxVMHandler(newRebootTestRegistry(t, nil), nil, store, creds, nil, VMEnrollmentConfig{}, LeaseGateConfig{})
	dryRunArgs := cloneArguments(base)
	dryRunArgs["linux_password_credential"] = "linux-lab"
	dryRunArgs["dry_run"] = true
	result, err := handler(context.Background(), reqNoToken(dryRunArgs))
	if err != nil || result == nil || result.IsError {
		t.Fatalf("dry run: result=%#v err=%v", result, err)
	}
	if text := toolResultText(result); strings.Contains(text, secret) || strings.Contains(text, "$6$") {
		t.Fatalf("credential material leaked into dry-run output:\n%s", text)
	}
}

func TestManagedLinuxVMResumeDoesNotResolveOriginalAccess(t *testing.T) {
	missingKey := filepath.Join(t.TempDir(), "removed.pub")
	agent := &linuxImageMockAgent{responses: []string{
		`{"exists":true,"state":"Off","metadata":{"schema_version":2,"guest_os":"linux","vm_name":"vm","node_name":"vm","managed_root":"E:\\VM","parent_vhdx":"F:\\RetiredCache\\base.vhdx","child_vhdx":"E:\\VM\\vm\\vm.vhdx","expected_cidata_iso":"E:\\VM\\vm\\cidata.iso","cleanup_phase":"complete","registered":true},"attached_isos":[],"expected_iso_exists":false,"ownership_exists":false}`,
		`{"status":"lock_acquired","acquired":true}`,
		`{"exists":true,"state":"Off","metadata":{"schema_version":2,"guest_os":"linux","vm_name":"vm","node_name":"vm","managed_root":"E:\\VM","parent_vhdx":"F:\\RetiredCache\\base.vhdx","child_vhdx":"E:\\VM\\vm\\vm.vhdx","expected_cidata_iso":"E:\\VM\\vm\\cidata.iso","cleanup_phase":"complete","registered":true},"attached_isos":[],"expected_iso_exists":false,"ownership_exists":false}`,
		`{"status":"storage_validated","configuration_changed":false}`,
		`{"status":"reconciled","vm_exists":true}`,
		`[1]`,
	}}
	addr := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	store := linuxDefaultsStore(t, `{
  "default_linux_profile":"ubuntu",
  "profiles":{"ubuntu":{
    "guest_os":"linux","target":"node1","vm_root":"E:\\VM","vswitch":"ext","linux_username":"lab",
    "ssh_public_key_file":"`+strings.ReplaceAll(missingKey, `\`, `\\`)+`",
    "linux_password_credential":"removed-credential"
  }}
}`)
	handler := createLinuxVMHandler(reg, pool, store, nil, nil, VMEnrollmentConfig{}, LeaseGateConfig{})
	result, err := handler(context.Background(), reqNoToken(map[string]any{"name": "vm"}))
	if err != nil || result == nil || result.IsError {
		t.Fatalf("resume: result=%#v err=%v", result, err)
	}
	text := toolResultText(result)
	if strings.Contains(text, "read ssh_public_key_file") || strings.Contains(text, "credential store unavailable") {
		t.Fatalf("managed resume resolved retired access inputs:\n%s", text)
	}
}

func TestNewLinuxVMRequiresAccessBeforeMutation(t *testing.T) {
	agent := &linuxImageMockAgent{responses: []string{`{"exists":false}`}}
	addr := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	store := linuxDefaultsStore(t, `{
  "default_linux_profile":"ubuntu",
  "profiles":{"ubuntu":{
    "guest_os":"linux","target":"node1","image_cache_root":"E:\\Images",
    "vm_root":"E:\\VM","vswitch":"ext","linux_username":"lab"
  }}
}`)
	handler := createLinuxVMHandler(reg, pool, store, nil, nil, VMEnrollmentConfig{}, LeaseGateConfig{})
	result, err := handler(context.Background(), reqNoToken(map[string]any{"name": "vm"}))
	if err != nil || result == nil || !result.IsError ||
		!strings.Contains(toolResultText(result), "provide at least one") {
		t.Fatalf("expected access preflight failure: result=%#v err=%v", result, err)
	}
	scripts := agent.Scripts()
	if len(scripts) != 1 {
		t.Fatalf("new VM access failure ran %d scripts, want only non-mutating inspection", len(scripts))
	}
	for _, forbidden := range []string{"vm-locks", "New-Item", "Remove-Item", "status='reconciled'", "New-VM", "New-VHD"} {
		if strings.Contains(scripts[0], forbidden) {
			t.Fatalf("access failure mutated host via %q:\n%s", forbidden, scripts[0])
		}
	}
}

func TestUnsafeManagedLinuxVMStateFailsBeforeLock(t *testing.T) {
	agent := &linuxImageMockAgent{responses: []string{
		`{"exists":true,"state":"Off","metadata":null,"attached_isos":[],"expected_iso_exists":false,"ownership_exists":true}`,
	}}
	addr := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	store := linuxDefaultsStore(t, `{
  "default_linux_profile":"ubuntu",
  "profiles":{"ubuntu":{
    "guest_os":"linux","target":"node1","vm_root":"E:\\VM","vswitch":"ext","linux_username":"lab",
    "ssh_public_key_file":"C:\\removed.pub"
  }}
}`)
	handler := createLinuxVMHandler(reg, pool, store, nil, nil, VMEnrollmentConfig{}, LeaseGateConfig{})
	result, err := handler(context.Background(), reqNoToken(map[string]any{"name": "vm"}))
	if err != nil || result == nil || !result.IsError ||
		!strings.Contains(toolResultText(result), "VM_REUSE_UNSAFE") {
		t.Fatalf("expected fail-closed unsafe resume: result=%#v err=%v", result, err)
	}
	if scripts := agent.Scripts(); len(scripts) != 1 || strings.Contains(scripts[0], "vm-locks") {
		t.Fatalf("unsafe state reached lifecycle mutation: %#v", scripts)
	}
}

func TestManagedLinuxVMIncompleteOwnershipFailsClosed(t *testing.T) {
	ownershipExists := false
	state := managedLinuxVMState{
		Exists: true, State: "Off", ExpectedISOExists: true, OwnershipExists: &ownershipExists,
		Metadata: &hyperv.LinuxVMMetadata{
			SchemaVersion: hyperv.LinuxVMMetadataSchema, GuestOS: "linux",
			VMName: "vm", NodeName: "vm", ManagedRoot: `E:\VM`,
			ParentVHDX: `E:\Images\base.vhdx`, ChildVHDX: `E:\VM\vm\vm.vhdx`,
			ExpectedCIDATAISO: `E:\VM\vm\cidata.iso`, CleanupPhase: hyperv.LinuxVMCleanupAttached,
		},
	}
	plan := linuxVMPlan{Name: "vm", LabLinkNodeName: "vm", VMRoot: `E:\VM`, VHDPath: `E:\VM\vm\vm.vhdx`}
	if err := validateManagedLinuxVMState(plan, state); err == nil ||
		!strings.Contains(err.Error(), "missing persisted CIDATA ownership") {
		t.Fatalf("incomplete persisted state was accepted: %v", err)
	}
}

func TestConcurrentLinuxStagingIDsUnique(t *testing.T) {
	const count = 128
	ids := make(chan string, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := newRemoteStageID()
			if err != nil {
				errs <- err
				return
			}

			ids <- id
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for id := range ids {
		if seen[id] {
			t.Fatalf("duplicate stage ID %s", id)
		}
		seen[id] = true
	}
	if len(seen) != count {
		t.Fatalf("got %d unique IDs, want %d", len(seen), count)
	}
}

func TestPreVMLinuxSeedCleanupFailureRetainsOwnership(t *testing.T) {
	reconcileCalls := 0
	cleanup := preVMLinuxSeedCleanup{
		cleanupStage: func(context.Context) error { return os.ErrPermission },
		reconcile: func(context.Context) error {
			reconcileCalls++
			return nil
		},
	}
	err := cleanup.cleanupAfterISO(context.Background())
	if err == nil || !strings.Contains(err.Error(), "persisted ownership was retained") {
		t.Fatalf("cleanup failure not reported safely: %v", err)
	}
	if err := cleanup.cleanupBeforeVM(context.Background()); err != nil {
		t.Fatalf("retained cleanup defer returned error: %v", err)
	}
	if !cleanup.retain || reconcileCalls != 0 {
		t.Fatalf("cleanup failure removed ownership: retain=%t reconcile_calls=%d", cleanup.retain, reconcileCalls)
	}
}

func TestPreVMLinuxSeedCleanupSuccessReconciles(t *testing.T) {
	stageCleanupCalls := 0
	reconcileCalls := 0
	cleanup := preVMLinuxSeedCleanup{
		cleanupStage: func(context.Context) error {
			stageCleanupCalls++
			return nil
		},
		reconcile: func(context.Context) error {
			reconcileCalls++
			return nil
		},
	}
	if err := cleanup.cleanupAfterISO(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := cleanup.cleanupBeforeVM(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stageCleanupCalls != 2 || reconcileCalls != 1 || !cleanup.done {
		t.Fatalf("cleanup calls stage=%d reconcile=%d done=%t", stageCleanupCalls, reconcileCalls, cleanup.done)
	}
}

func TestLinuxVMLockKeysSerializeOnlySameName(t *testing.T) {
	if linuxVMLockKey("Ubuntu") != linuxVMLockKey("ubuntu") {
		t.Fatal("Hyper-V VM names are case-insensitive but lock keys differ")
	}
	if linuxVMLockKey("ubuntu-a") == linuxVMLockKey("ubuntu-b") {
		t.Fatal("distinct VM names share a lock key")
	}
	owners := map[string]bool{}
	for range 32 {
		owner, err := newRemoteStageID()
		if err != nil {
			t.Fatal(err)
		}
		if owners[owner] {
			t.Fatal("duplicate random lock owner token")
		}
		owners[owner] = true
	}
}

func TestChildOwnershipPreflightIsExact(t *testing.T) {
	agent := &linuxImageMockAgent{responses: []string{`{"status":"absent"}`}}
	addr := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	target, err := resolvePlanTarget("node1", reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureLinuxVMChildAbsent(context.Background(), `E:\VM\one\one.vhdx`, target, reg, pool); err != nil {
		t.Fatal(err)
	}
	scripts := agent.Scripts()
	if len(scripts) != 1 || !strings.Contains(scripts[0], `E:\VM\one\one.vhdx`) ||
		!strings.Contains(scripts[0], "refusing to claim or delete") {
		t.Fatalf("ownership preflight was not exact: %#v", scripts)
	}
}

func TestManagedLinuxVMResumeAcceptsDetachedCleanupAndRegistration(t *testing.T) {
	plan := linuxVMPlan{
		Name: "vm", LabLinkNodeName: "node", VMRoot: `E:\VM`,
		VHDPath: `E:\VM\vm\vm.vhdx`, PreparedVHDX: `Z:\NewCache\changed-base.vhdx`,
	}
	state := managedLinuxVMState{
		Exists: true,
		Metadata: &hyperv.LinuxVMMetadata{
			SchemaVersion: hyperv.LinuxVMMetadataSchema, GuestOS: "linux",
			VMName: "vm", NodeName: "node", ManagedRoot: `E:\VM`,
			ChildVHDX: `E:\VM\vm\vm.vhdx`, ParentVHDX: `E:\Images\base.vhdx`,
			ExpectedCIDATAISO: `E:\VM\vm\cidata.iso`,
			CleanupPhase:      hyperv.LinuxVMCleanupDetached, Registered: true,
		},
		ExpectedISOExists: true,
	}
	if err := validateManagedLinuxVMState(plan, state); err != nil {
		t.Fatalf("detached retry rejected: %v", err)
	}
	if !state.Metadata.Registered {
		t.Fatal("registered state was not preserved")
	}
}

func TestManagedLinuxVMResumeRejectsRetiredProvisioningSchema(t *testing.T) {
	plan := linuxVMPlan{
		Name: "vm", LabLinkNodeName: "node", VMRoot: `E:\VM`,
		VHDPath: `E:\VM\vm\vm.vhdx`,
	}
	state := managedLinuxVMState{
		Exists: true,
		Metadata: &hyperv.LinuxVMMetadata{
			SchemaVersion: 1, GuestOS: "linux", VMName: "vm", NodeName: "node",
			ManagedRoot: `E:\VM`, ChildVHDX: `E:\VM\vm\vm.vhdx`,
			ParentVHDX:        `E:\Images\old-base.vhdx`,
			ExpectedCIDATAISO: `E:\VM\vm\cidata.iso`,
			CleanupPhase:      hyperv.LinuxVMCleanupAttached,
		},
		ExpectedISOExists: true,
	}
	if err := validateManagedLinuxVMState(plan, state); err == nil ||
		!strings.Contains(err.Error(), "VM_REUSE_UNSAFE") {
		t.Fatalf("retired provisioning schema was accepted: %v", err)
	}
}

func TestManagedLinuxVMResumeCIDATAAttachmentStates(t *testing.T) {
	plan := linuxVMPlan{
		Name: "vm", LabLinkNodeName: "node", VMRoot: `E:\VM`,
		VHDPath: `E:\VM\vm\vm.vhdx`,
	}
	base := managedLinuxVMState{
		Exists: true,
		State:  "Off",
		Metadata: &hyperv.LinuxVMMetadata{
			SchemaVersion: hyperv.LinuxVMMetadataSchema, GuestOS: "linux",
			VMName: "vm", NodeName: "node", ManagedRoot: `E:\VM`,
			ChildVHDX: `E:\VM\vm\vm.vhdx`, ParentVHDX: `E:\Images\base.vhdx`,
			ExpectedCIDATAISO: `E:\VM\vm\cidata.iso`,
			CleanupPhase:      hyperv.LinuxVMCleanupAttached,
		},
		ExpectedISOExists: true,
	}

	t.Run("ISO present but unattached", func(t *testing.T) {
		state := base
		if err := validateManagedLinuxVMState(plan, state); err != nil {
			t.Fatalf("resumable pre-attachment state rejected: %v", err)
		}
	})

	t.Run("expected ISO already attached", func(t *testing.T) {
		state := base
		state.AttachedISOs = []string{state.Metadata.ExpectedCIDATAISO}
		if err := validateManagedLinuxVMState(plan, state); err != nil {
			t.Fatalf("idempotent already-attached state rejected: %v", err)
		}
	})

	t.Run("running with expected ISO attached", func(t *testing.T) {
		state := base
		state.State = "Running"
		state.AttachedISOs = []string{state.Metadata.ExpectedCIDATAISO}
		if err := validateManagedLinuxVMState(plan, state); err != nil {
			t.Fatalf("running post-boot resume rejected: %v", err)
		}
	})

	t.Run("running without expected ISO rejected", func(t *testing.T) {
		state := base
		state.State = "Running"
		if err := validateManagedLinuxVMState(plan, state); err == nil ||
			!strings.Contains(err.Error(), "VM_RESUME_RUNNING_CIDATA_MISSING") {
			t.Fatalf("unsafe running VM accepted: %v", err)
		}
	})

	t.Run("mismatched ISO rejected", func(t *testing.T) {
		state := base
		state.AttachedISOs = []string{`E:\VM\vm\wrong.iso`}
		if err := validateManagedLinuxVMState(plan, state); err == nil ||
			!strings.Contains(err.Error(), "VM_RESUME_CIDATA_MISMATCH") {
			t.Fatalf("mismatched ISO accepted: %v", err)
		}
	})

	t.Run("expected ISO missing", func(t *testing.T) {
		state := base
		state.ExpectedISOExists = false
		if err := validateManagedLinuxVMState(plan, state); err == nil ||
			!strings.Contains(err.Error(), "VM_RESUME_CIDATA_MISSING") {
			t.Fatalf("missing expected ISO accepted: %v", err)
		}
	})
}

func TestManagedLinuxVMRunningResumeValidatesThenContinuesDiscovery(t *testing.T) {
	agent := &linuxImageMockAgent{responses: []string{
		`{"exists":true,"state":"Running","metadata":{"schema_version":2,"guest_os":"linux","vm_name":"vm","node_name":"vm","managed_root":"E:\\VM","parent_vhdx":"F:\\RetiredCache\\persisted-base.vhdx","child_vhdx":"E:\\VM\\vm\\vm.vhdx","expected_cidata_iso":"E:\\VM\\vm\\cidata.iso","cleanup_phase":"cidata_attached","registered":false},"attached_isos":["E:\\VM\\vm\\cidata.iso"],"expected_iso_exists":true}`,
		`{"status":"lock_acquired","acquired":true}`,
		`{"exists":true,"state":"Running","metadata":{"schema_version":2,"guest_os":"linux","vm_name":"vm","node_name":"vm","managed_root":"E:\\VM","parent_vhdx":"F:\\RetiredCache\\persisted-base.vhdx","child_vhdx":"E:\\VM\\vm\\vm.vhdx","expected_cidata_iso":"E:\\VM\\vm\\cidata.iso","cleanup_phase":"cidata_attached","registered":false},"attached_isos":["E:\\VM\\vm\\cidata.iso"],"expected_iso_exists":true}`,
		`{"status":"storage_validated","configuration_changed":false}`,
		`{"status":"reconciled","vm_exists":true}`,
		`{"status":"validated_running","state":"Running","cidata_attached":true}`,
		`[1]`,
	}}
	addr := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	store := linuxDefaultsStore(t, `{
  "default_linux_profile":"ubuntu",
  "profiles":{"ubuntu":{
    "guest_os":"linux","target":"node1",
    "vm_root":"E:\\VM","vswitch":"ext","linux_username":"lab","ssh_public_key":"`+linuxTestKey()+`"
  }}
}`)
	handler := createLinuxVMHandler(reg, pool, store, nil, nil, VMEnrollmentConfig{}, LeaseGateConfig{})
	result, err := handler(context.Background(), reqNoToken(map[string]any{"name": "vm"}))
	if err != nil || result == nil || result.IsError {
		t.Fatalf("resume: result=%#v err=%v", result, err)
	}
	scripts := agent.Scripts()
	var validateIndex, bootIndex = -1, -1
	for i, script := range scripts {
		if strings.Contains(script, "status='validated_running'") {
			validateIndex = i
		}
		if strings.Contains(script, "VM_KVP_IP_TIMEOUT") {
			bootIndex = i
		}
	}
	if validateIndex < 0 || bootIndex < 0 || validateIndex >= bootIndex {
		t.Fatalf("running VM was not validated before post-boot discovery: validate=%d boot=%d", validateIndex, bootIndex)
	}
}

func TestManagedLinuxVMResumeConfiguresUnattachedCIDATABeforeBoot(t *testing.T) {
	agent := &linuxImageMockAgent{responses: []string{
		`{"exists":true,"metadata":{"schema_version":2,"guest_os":"linux","vm_name":"vm","node_name":"vm","managed_root":"E:\\VM","parent_vhdx":"F:\\RetiredCache\\persisted-base.vhdx","child_vhdx":"E:\\VM\\vm\\vm.vhdx","expected_cidata_iso":"E:\\VM\\vm\\cidata.iso","cleanup_phase":"cidata_attached","registered":false},"attached_isos":[],"expected_iso_exists":true}`,
		`{"status":"lock_acquired","acquired":true}`,
		`{"exists":true,"metadata":{"schema_version":2,"guest_os":"linux","vm_name":"vm","node_name":"vm","managed_root":"E:\\VM","parent_vhdx":"F:\\RetiredCache\\persisted-base.vhdx","child_vhdx":"E:\\VM\\vm\\vm.vhdx","expected_cidata_iso":"E:\\VM\\vm\\cidata.iso","cleanup_phase":"cidata_attached","registered":false},"attached_isos":[],"expected_iso_exists":true}`,
		`{"status":"storage_validated","configuration_changed":false}`,
		`{"status":"reconciled","vm_exists":true}`,
		`{"status":"configured","cidata_attached":true}`,
		`[1]`,
	}}
	addr := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	store := linuxDefaultsStore(t, `{
  "default_linux_profile":"ubuntu",
  "profiles":{"ubuntu":{
    "guest_os":"linux","target":"node1","image_cache_root":"Z:\\Missing-New-Cache",
    "vm_root":"E:\\VM","vswitch":"ext","linux_username":"lab","ssh_public_key":"`+linuxTestKey()+`"
  }}
}`)
	handler := createLinuxVMHandler(reg, pool, store, nil, nil, VMEnrollmentConfig{}, LeaseGateConfig{})
	result, err := handler(context.Background(), reqNoToken(map[string]any{"name": "vm"}))
	if err != nil || result == nil || result.IsError {
		t.Fatalf("resume: result=%#v err=%v", result, err)
	}
	if text := toolResultText(result); !strings.Contains(text, "retained for diagnosis") {
		t.Fatalf("expected resume to reach boot after configuration, got:\n%s", text)
	}
	scripts := agent.Scripts()
	var configureIndex, bootIndex = -1, -1
	for i, script := range scripts {
		if strings.Contains(script, "New-VM") || strings.Contains(script, "New-VHD") {
			t.Fatal("managed VM resume attempted duplicate VM or VHD creation")
		}
		if strings.Contains(script, "VM_RESUME_CIDATA_MISMATCH") {
			configureIndex = i
		}
		if strings.Contains(script, "VM_KVP_IP_TIMEOUT") {
			bootIndex = i
		}
	}
	if configureIndex < 0 || bootIndex < 0 || configureIndex >= bootIndex {
		t.Fatalf("existing VM configuration did not run before boot: configure=%d boot=%d", configureIndex, bootIndex)
	}
}

func TestManagedLinuxVMResumePrecedesAndDoesNotRequireCurrentImageCache(t *testing.T) {
	agent := &linuxImageMockAgent{responses: []string{
		`{"exists":true,"metadata":{"schema_version":2,"guest_os":"linux","vm_name":"vm","node_name":"vm","managed_root":"E:\\VM","parent_vhdx":"F:\\RetiredCache\\persisted-base.vhdx","child_vhdx":"E:\\VM\\vm\\vm.vhdx","expected_cidata_iso":"E:\\VM\\vm\\cidata.iso","cleanup_phase":"complete","registered":true},"attached_isos":[],"expected_iso_exists":false}`,
		`{"status":"lock_acquired","acquired":true}`,
		`{"exists":true,"metadata":{"schema_version":2,"guest_os":"linux","vm_name":"vm","node_name":"vm","managed_root":"E:\\VM","parent_vhdx":"F:\\RetiredCache\\persisted-base.vhdx","child_vhdx":"E:\\VM\\vm\\vm.vhdx","expected_cidata_iso":"E:\\VM\\vm\\cidata.iso","cleanup_phase":"complete","registered":true},"attached_isos":[],"expected_iso_exists":false}`,
		`{"status":"storage_validated","configuration_changed":false}`,
		`{"status":"reconciled","vm_exists":true}`,
		`[1]`,
	}}
	addr := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	store := linuxDefaultsStore(t, `{
  "default_linux_profile":"ubuntu",
  "profiles":{"ubuntu":{
    "guest_os":"linux","target":"node1","image_cache_root":"Z:\\Missing-New-Cache",
    "vm_root":"E:\\VM","vswitch":"ext","linux_username":"lab","ssh_public_key":"`+linuxTestKey()+`"
  }}
}`)
	handler := createLinuxVMHandler(reg, pool, store, nil, nil, VMEnrollmentConfig{}, LeaseGateConfig{})
	result, err := handler(context.Background(), reqNoToken(map[string]any{"name": "vm"}))
	if err != nil || result == nil || result.IsError {
		t.Fatalf("resume: result=%#v err=%v", result, err)
	}
	if text := toolResultText(result); !strings.Contains(text, "retained for diagnosis") {
		t.Fatalf("expected resume to reach persisted VM boot path, got:\n%s", text)
	}
	scripts := agent.Scripts()
	joined := strings.Join(scripts, "\n---\n")
	if strings.Contains(joined, "status='not_started'") ||
		strings.Contains(joined, "BUILDER_BASE_VHD_NOT_FOUND") {
		t.Fatalf("resume consulted the current image cache before using persisted metadata:\n%s", joined)
	}
	if !strings.Contains(joined, `cidata.iso`) {
		t.Fatalf("resume did not use persisted ISO identity:\n%s", joined)
	}
	var storageIndex, bootIndex = -1, -1
	for i, script := range scripts {
		if strings.Contains(script, "status='storage_validated'") {
			storageIndex = i
		}
		if strings.Contains(script, "VM_KVP_IP_TIMEOUT") {
			bootIndex = i
		}
	}
	if storageIndex < 0 || bootIndex < 0 || storageIndex >= bootIndex {
		t.Fatalf("complete-phase resume did not validate storage before boot: storage=%d boot=%d", storageIndex, bootIndex)
	}
}

func TestManagedLinuxVMDetachedResumeValidatesStorageBeforeBoot(t *testing.T) {
	metadata := `{"schema_version":2,"guest_os":"linux","vm_name":"vm","node_name":"vm","managed_root":"E:\\VM","parent_vhdx":"F:\\RetiredCache\\persisted-base.vhdx","child_vhdx":"E:\\VM\\vm\\vm.vhdx","expected_cidata_iso":"E:\\VM\\vm\\cidata.iso","cleanup_phase":"cidata_detached","registered":true}`
	agent := &linuxImageMockAgent{responses: []string{
		`{"exists":true,"state":"Off","metadata":` + metadata + `,"attached_isos":[],"expected_iso_exists":true}`,
		`{"status":"lock_acquired","acquired":true}`,
		`{"exists":true,"state":"Off","metadata":` + metadata + `,"attached_isos":[],"expected_iso_exists":true}`,
		`{"status":"storage_validated","configuration_changed":false}`,
		`{"status":"reconciled","vm_exists":true}`,
		`[1]`,
	}}
	addr := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	store := linuxDefaultsStore(t, `{
  "default_linux_profile":"ubuntu",
  "profiles":{"ubuntu":{
    "guest_os":"linux","target":"node1","image_cache_root":"Z:\\Missing-New-Cache",
    "vm_root":"E:\\VM","vswitch":"ext","linux_username":"lab","ssh_public_key":"`+linuxTestKey()+`"
  }}
}`)
	handler := createLinuxVMHandler(reg, pool, store, nil, nil, VMEnrollmentConfig{}, LeaseGateConfig{})
	result, err := handler(context.Background(), reqNoToken(map[string]any{"name": "vm"}))
	if err != nil || result == nil || result.IsError {
		t.Fatalf("resume: result=%#v err=%v", result, err)
	}
	scripts := agent.Scripts()
	var storageIndex, bootIndex = -1, -1
	for i, script := range scripts {
		if strings.Contains(script, "status='storage_validated'") {
			storageIndex = i
		}
		if strings.Contains(script, "VM_KVP_IP_TIMEOUT") {
			bootIndex = i
		}
	}
	if storageIndex < 0 || bootIndex < 0 || storageIndex >= bootIndex {
		t.Fatalf("detached-phase resume did not validate storage before boot: storage=%d boot=%d", storageIndex, bootIndex)
	}
	for _, script := range scripts {
		if strings.Contains(script, "Add-VMDvdDrive") {
			t.Fatal("cidata_detached resume reconfigured CIDATA")
		}
	}
}

func TestManagedLinuxVMStorageMismatchStopsBeforeBootAndMTLS(t *testing.T) {
	metadata := `{"schema_version":2,"guest_os":"linux","vm_name":"vm","node_name":"vm","managed_root":"E:\\VM","parent_vhdx":"F:\\Cache\\expected.vhdx","child_vhdx":"E:\\VM\\vm\\vm.vhdx","expected_cidata_iso":"E:\\VM\\vm\\cidata.iso","cleanup_phase":"complete","registered":true}`
	agent := &linuxImageMockAgent{
		responses: []string{
			`{"exists":true,"state":"Off","metadata":` + metadata + `,"attached_isos":[],"expected_iso_exists":false}`,
			`{"status":"lock_acquired","acquired":true}`,
			`{"exists":true,"state":"Off","metadata":` + metadata + `,"attached_isos":[],"expected_iso_exists":false}`,
			`VM_PARENT_VHD_MISMATCH`,
		},
		failAt: 4, failure: "VM_PARENT_VHD_MISMATCH",
	}
	addr := startNodeAgent(t, agent)
	reg := newRebootTestRegistry(t, map[string]string{"node1": addr})
	pool := agentclient.NewPool("", internalsec.ClientTransportConfig{Mode: internalsec.TransportModeInsecure})
	defer pool.Close()
	store := linuxDefaultsStore(t, `{
	  "default_linux_profile":"ubuntu",
	  "profiles":{"ubuntu":{
	    "guest_os":"linux","target":"node1","image_cache_root":"Z:\\Missing",
	    "vm_root":"E:\\VM","vswitch":"ext","linux_username":"lab","ssh_public_key":"`+linuxTestKey()+`"
	  }}
	}`)
	handler := createLinuxVMHandler(reg, pool, store, nil, nil, VMEnrollmentConfig{}, LeaseGateConfig{})
	result, err := handler(context.Background(), reqNoToken(map[string]any{"name": "vm"}))
	if err != nil || result == nil || result.IsError {
		t.Fatalf("expected retained diagnostic result: result=%#v err=%v", result, err)
	}
	if !strings.Contains(toolResultText(result), "VM_PARENT_VHD_MISMATCH") {
		t.Fatalf("storage mismatch not reported:\n%s", toolResultText(result))
	}
	for _, script := range agent.Scripts() {
		if strings.Contains(script, "VM_KVP_IP_TIMEOUT") || strings.Contains(script, "metadata_updated") ||
			strings.Contains(script, "status='reconciled'") {
			t.Fatal("storage mismatch reached reconciliation, boot, or registration")
		}
	}
}
