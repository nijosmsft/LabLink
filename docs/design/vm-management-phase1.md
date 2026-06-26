# Design Spec — LabLink VM Management, Phase 1 (Windows VM on Hyper-V)

**Status:** **Approved with required changes — Phase-1 primitives implemented.** Two reviews
(network-design + Heimdall fleet-consistency) approved the design *with required changes*;
those are now locked in §0 below and reflected in the tool/param tables. Implementation of the
five primitives has landed on `feat/vm-management`.
**Author:** Sam (lablink Dev, mcp-servers Squad)
**Date:** 2026-06-26
**Requested by:** Nithin Jose
**Branch / worktree:** `feat/vm-management` @ `C:\git\.worktrees\lablink\vm-mgmt`
**Umbrella issue:** nijosmsft/mcp-servers#28
**Reviews:** `netdesign-lablink-vm-phase1-review.md` (SOUND WITH CHANGES),
`heimdall-lablink-vm-design-phase1-fleet-consistency.md` (APPROVE WITH NOTES)

---

## 0. Review Resolutions (locked decisions)

The two reviews approved the design **with required changes**. These are **decisions, not
options**, and are implemented in `internal/hyperv`, `internal/hyperv/unattend`, and
`internal/mcptools/{target.go,vm.go}`.

### 0.1 Critical safety — external vSwitch can sever the agent connection

- **Management-NIC detection (`list_physical_nics`).** Each NIC is flagged
  `is_management_nic` / `management_risk` by resolving, on the target, the interface that owns
  the IP the LabLink server uses to reach the host (`Get-NetIPAddress -IPAddress <mgmtIP>`),
  falling back to the lowest-metric default-route interface. `recommended_for_external` is only
  true for an Up, unbound, non-management NIC.
- **`create_vswitch` safeguard.** On a **remote** target, creating an **external** switch on the
  management NIC is **BLOCKED** (`MGMT_NIC_BLOCKED`) unless the caller passes
  `allow_management_nic_disruption=true`. `allow_management_os` defaults to **true**; setting it
  `false` on a remote external switch is also blocked (`MGMT_OS_BLOCKED`) without the same
  override. `New-VMSwitch ... -AllowManagementOS:$true` is the default.
- **Disruptive remote NIC ops** should use an async/detached job + reconnect/poll pattern rather
  than one blocking gRPC call that can die mid-reconfig. **Status: the safeguard/override and the
  detached-job guidance are shipped; the automated detached-job + reconnect executor is DEFERRED**
  (documented in §10.2) — until then the override is the conscious, audited escape hatch.

### 0.2 Hyper-V completeness (`create_vm`)

Gen2 secure boot uses `Set-VMFirmware -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows`;
the install DVD is selected **deterministically by ISO path** (not "the DVD drive") before being
set as `FirstBootDevice`; dynamic memory wires **min/max/buffer**; the script **validates paths +
free space**, refuses to clobber an existing VM (`VM_EXISTS`), checks the VHD is **not in use**,
and validates the vSwitch exists. `if_exists=reuse` for `create_vswitch` validates **type, bound
adapter, and AllowManagementOS** before reusing (`VSWITCH_MISMATCH`).

### 0.3 unattend

- **Method A (default).** Never inject into a shared golden/base VHD — when `base_vhd` is given a
  **differencing child** is created at `vhd_path` and only the child is mutated. The Windows volume
  is located **by content** (`Windows\System32\Config\SYSTEM`), not by drive letter (temp letters
  are assigned when missing and removed afterward). The tool **dismounts only the VHD it mounted**
  (tracked `$mountedByUs`, `try/finally`).
- **Method B (clean install).** A correct clean-install answer file needs a full **windowsPE** pass
  (UEFI/GPT partitioning, image selection, install target) + a vetted ISO writer. This is **not**
  fully implemented in P1, so it is an explicit **DEFERRED stub** (`METHOD_B_DEFERRED`) — we do not
  ship a half clean-install path.
- **Password.** First-boot **scrub** of `C:\Windows\Panther`, `Panther\UnattendGC`, the staged
  first-boot script, and the AutoLogon registry values (`AutoAdminLogon`, `DefaultPassword`,
  `DefaultDomainName`) is baked into `FirstLogonCommands`. **`AutoLogonCount=1`** is used whenever
  AutoLogon is enabled. The password is **redacted** (`***`) in ops args, audit `Command`, and the
  tool return; staged cleartext copies are scrubbed on the host. Optional base64 obfuscation is
  supported but **documented as NOT encryption**.

### 0.4 Fleet / consistency

- **Windows PowerShell, not pwsh.** The localhost path now uses `powershell.exe` on Windows
  (`localPowershellExe()`), matching the remote agent + Hyper-V cmdlet behavior. `runPS` treats a
  **nonzero exit as a tool failure**, and `executeLocalPowershell` was fixed so `timeoutSec<=0`
  means **no timeout** (not an immediate deadline) and a launch failure returns a real Go error.
- **Flat params + ops labeling.** All tools use **flat scalar params** (no nested object params in
  P1). Handlers call `beginOp(...)` with the **resolved target** as the node label so portal/ops
  rows are not blank (the `target`-vs-`node` mismatch Heimdall flagged). Tools return **markdown +
  a single fenced JSON block** (the chainable-tool convention), last in the response, never
  containing secrets.
- **Primitives-first.** Only the five primitives ship. The `create_windows_vm` orchestrator is
  **DEFERRED** to a follow-on until it can be a thin, tested composition over validated primitives
  with per-step resumable output.

### 0.5 Resolved open questions

| OQ | Resolution |
|----|------------|
| OQ-1 | Remote read-only discovery is **not lease-gated by default** (configurable). |
| OQ-2 | Prefer `oscdimg` when present, else a vetted bundled ISO writer (no arbitrary runtime snippets). Method B itself is deferred. |
| OQ-3 | `powershell.exe` on Windows for the localhost path. |
| OQ-4 | Password **scrub + AutoLogonCount=1 + redaction** required; obfuscation ≠ encryption. |
| OQ-5 | **Primitives-first**; orchestrator deferred. |
| OQ-6 | Require explicit VM/VHD paths on remote/shared hosts; Hyper-V defaults only via `use_host_defaults=true`; return resolved paths + free-space. |

---

## 1. Goal & scope

Add MCP tools to LabLink so an AI client (or operator) can, end-to-end, stand up a
Windows VM on Hyper-V:

1. **Create a Hyper-V vSwitch** — external (bound to a chosen physical NIC), internal, or
   private; OR reuse an existing vSwitch.
2. **Create a Gen2 Windows VM** — choosing VM location/folder, VHD path (existing or new),
   memory, vCPU, vSwitch, and boot ISO.
3. **Provision via `unattend.xml`** — generate from a template + parameters and inject for
   first-boot (hostname, admin password, locale, first-boot script).

Every operation is **caller-selectable** and works uniformly against
`target = localhost | <node>`, reusing LabLink's existing remote-node execution mechanism.
**Discovery tools** (`list_physical_nics`, `list_vswitches`) surface the option values so a
caller can prompt the user before committing.

### Non-goals (Phase 1)

- Linux guests, cloud-init, generation 1 VMs.
- VM lifecycle beyond create (start/stop/checkpoint/delete are a thin **follow-on**, see §6).
- Clustering / SCVMM / Failover Cluster / SET teams.
- Live migration, replica, shared VHDX.
- Domain join in unattend (deferred; local admin + first-boot script only in Phase 1).

---

## 2. How this grounds in the existing codebase

This section records the concrete patterns the design must reuse (verified by reading the
worktree), so implementation stays idiomatic.

### 2.1 MCP tool registration

Tools are declared with `mcp.NewTool(name, mcp.WithDescription(...), mcp.WithString/WithNumber/WithBoolean(...))`
and handled by a `server.ToolHandlerFunc`. Each feature area has a `Register<Area>(s *server.MCPServer, ...)`
function in `internal/mcptools/`, called from `cmd/lablink-server/main.go`
(see `main.go:206-225`). Handlers are wrapped two ways:

- `addTool(s, tool, handler)` — auto-tracks the call in the ops registry/portal
  (`ops_hook.go:37`). Uses the request's `node` arg as the row label.
- `LeaseGate(leaseCfg, extractor, handler)` — gates the call on an active lease for the
  touched node(s) when `LABLINK_LEASE_REQUIRED` is set (`leasecheck.go:55`).

Mutating tools use `addTool` + `LeaseGate`. Example skeleton (from `execute.go:37`):

```go
s.AddTool(
    mcp.NewTool("execute_command",
        mcp.WithString("node", mcp.Required(), mcp.Description("Node name from registry")),
        mcp.WithString("command", mcp.Required(), ...),
    ),
    LeaseGate(leaseCfg, extractSingleNode("node"), executeCommandHandler(reg, pool, auditLog)),
)
```

### 2.2 Remote vs local execution (the mechanism the VM tools must reuse)

**Remote (a registered node):**
`reg.GetNode(name)` → `pool.GetClient(node.Address, node.TLSServerName)` →
`client.Execute(...)` / `client.ExecuteScript(...)` (gRPC server-streaming) →
`collectStreamOutput(stream)` returns `(output, exitCode, pid, jobID, err)`.
Convenience wrappers already exist: `executeAndCollect(ctx, client, cmd, shell, wd, env, timeout)`
(`helpers.go:85`) and `executeScriptOnNode(...)` (`multinode.go:202`).

The remote **agent** (`cmd/lablink-agent/executor.go`) runs PowerShell via
`powershell.exe -NoProfile -NonInteractive -Command <cmd>` (Windows PowerShell 5.1), and
`ExecuteScript` writes the body to a temp `.ps1` and runs it. **This is exactly the surface
Hyper-V needs** — the `Hyper-V` PowerShell module ships in-box on Windows Server / Win10+.

**Local (the lablink-server host itself):**
`executeLocalPowershell(ctx, script, timeoutSec)` (`helpers.go:126`) runs
`pwsh -NoProfile -Command <script>` locally and returns `(output, exitCode, pid, err)`.
It is defined but currently unused — Phase 1 will be its first consumer. (See Open Question
OQ-3 re: `pwsh` vs `powershell.exe` parity.)

> **Design consequence:** All Hyper-V work is expressed as **PowerShell that runs on the
> target**. We never call WMI/Go-native Hyper-V APIs. This keeps one code path, identical
> local and remote, and rides the agent's existing stream/timeout/heartbeat machinery.

### 2.3 Node model, leasing, file transfer

- `registry.Node{ Name, Address, Role, OS, Arch, TLSServerName, ... }` (`registry.go:23`).
- Lease gating resolves **node names**; extractors live in `leasecheck.go`
  (`extractSingleNode`, `extractMultiNodes`, custom extractors).
- File push/pull: `push_file`/`pull_file` (`transfer.go`), helper `pushFileToNode(...)`
  (`helpers.go:101`). Used to ship a generated `unattend.xml` / AutoUnattend ISO to a
  remote target.
- Credentials: `internal/credentials` store + `save_credential`/`list_credentials`
  (`deploy.go`). Phase 1 reuses this to avoid passing admin passwords inline.

---

## 3. Target routing: `target = localhost | <node>` (the unifying abstraction)

LabLink today has **two** execution code paths (local helper vs gRPC node). To make every VM
tool uniform, Phase 1 introduces one small internal abstraction (no proto change):

```go
// internal/mcptools/target.go  (NEW)
type Target struct {
    Name    string            // "localhost" or a registry node name
    IsLocal bool
}

// resolveTarget reads the "target" arg (default "localhost").
func resolveTarget(req mcp.CallToolRequest, reg *registry.Registry) (Target, error)

// runPS executes a PowerShell script on the target, local or remote, and
// returns (stdout+stderr, exitCode, err). Internally:
//   - IsLocal  -> executeLocalPowershell(ctx, script, timeout)
//   - else     -> reg.GetNode + pool.GetClient + executeScriptOnNode (shell="powershell")
func runPS(ctx context.Context, reg *registry.Registry, pool *agentclient.Pool,
           t Target, script string, timeoutSec int) (string, int, error)

// pushToTarget copies a local file to the target (no-op/local-copy for localhost,
// pushFileToNode for remote).
func pushToTarget(ctx context.Context, reg *registry.Registry, pool *agentclient.Pool,
                  t Target, localPath, remotePath string) error
```

### 3.1 `target` semantics

| `target` value        | Behaviour |
|-----------------------|-----------|
| omitted / `localhost` / `local` | Run on the lablink-server host via `executeLocalPowershell`. |
| `<registry node name>` | Resolve node, run via the agent gRPC `ExecuteScript` path. |

### 3.2 Lease-gating the `target`

A new extractor `extractTarget("target")` returns:
- `nil` when target is local (**no lease required** — you own your own host), so `LeaseGate`
  passes through;
- `["<node>"]` when target is remote, so the caller must hold a lease on that node — exactly
  like every other node-touching tool.

```go
func extractTarget(arg string) NodeExtractor {
    return func(req mcp.CallToolRequest, _ *registry.Registry) []string {
        v := strings.TrimSpace(req.GetString(arg, "localhost"))
        if v == "" || strings.EqualFold(v, "localhost") || strings.EqualFold(v, "local") {
            return nil
        }
        return []string{v}
    }
}
```

This is the **entire** local-vs-remote story: tools take `target`, the handler calls `runPS`,
and `LeaseGate(leaseCfg, extractTarget("target"), handler)` enforces ownership only for remote
targets. No new transport, no proto change.

---

## 4. Tool surface (proposed)

All tools live in a new `internal/mcptools/vm.go` (`RegisterVM(...)`), wired in `main.go`.
Common conventions:

- Every tool takes `target` (string, default `"localhost"`).
- Read-only discovery tools use `addTool` only (no lease gate — they don't mutate).
  > Note: a remote discovery call still *touches* a node; we gate **mutating** VM tools and
  > leave discovery ungated for ergonomics (it only runs `Get-*` cmdlets). See OQ-5.
- Mutating tools use `addTool` + `LeaseGate(..., extractTarget("target"), ...)`.
- Return shape: human-readable markdown **plus** a fenced ```json block carrying the
  structured result, so the AI client can both render and parse. (Matches the repo's
  "markdown result text" convention while remaining machine-readable.)

### 4.1 `list_physical_nics` (discovery, read-only)

| Param | Type | Req | Description |
|-------|------|-----|-------------|
| `target` | string | no | `localhost` (default) or node name |
| `include_virtual` | bool | no | Include vEthernet/virtual adapters (default false) |

PowerShell: `Get-NetAdapter -Physical | Where-Object Status -in 'Up','Disconnected'`
joined with `Get-VMSwitch` to flag NICs already bound to an external switch.

Returns:
```json
{
  "target": "localhost",
  "nics": [
    { "name": "Ethernet 2", "interface_description": "Intel(R) X710",
      "mac": "00-15-5D-01-02-03", "status": "Up", "link_speed": "10 Gbps",
      "bound_vswitch": null, "recommended_for_external": true }
  ]
}
```

### 4.2 `list_vswitches` (discovery, read-only)

| Param | Type | Req | Description |
|-------|------|-----|-------------|
| `target` | string | no | `localhost` or node name |

PowerShell: `Get-VMSwitch | Select Name, SwitchType, NetAdapterInterfaceDescription, AllowManagementOS`.

Returns:
```json
{
  "target": "localhost",
  "vswitches": [
    { "name": "ExternalSwitch", "type": "External", "net_adapter": "Intel(R) X710",
      "allow_management_os": true }
  ]
}
```

### 4.3 `create_vswitch` (mutating, lease-gated)

| Param | Type | Req | Description |
|-------|------|-----|-------------|
| `target` | string | no | `localhost` or node name |
| `name` | string | **yes** | vSwitch name |
| `type` | string | **yes** | `external` \| `internal` \| `private` |
| `net_adapter` | string | cond. | Physical NIC name (required when `type=external`) |
| `allow_management_os` | bool | no | Keep host connectivity on an external switch (default true) |
| `allow_management_nic_disruption` | bool | no | Override the management-NIC severance safeguard on a **remote** target (default false). Required to bind an external switch to the management NIC, or to set `allow_management_os=false` remotely. |
| `if_exists` | string | no | `reuse` (default) \| `fail` \| `replace` — idempotency control. `reuse` validates type/adapter/AllowManagementOS match (`VSWITCH_MISMATCH`). |

PowerShell sequence (external):
```powershell
$sw = Get-VMSwitch -Name $name -ErrorAction SilentlyContinue
if ($sw) {
    if ($ifExists -eq 'fail')    { throw "vSwitch '$name' already exists" }
    if ($ifExists -eq 'reuse')   { <emit existing, exit 0> }
    if ($ifExists -eq 'replace') { Remove-VMSwitch -Name $name -Force }
}
if (-not $sw -or $ifExists -eq 'replace') {
    New-VMSwitch -Name $name -NetAdapterName $netAdapter `
        -AllowManagementOS:$allowMgmtOS
}
```
Internal/private substitute `New-VMSwitch -Name $name -SwitchType Internal|Private`.

Returns the created/reused switch object (same shape as `list_vswitches` rows) plus
`"action": "created" | "reused" | "replaced"`.

### 4.4 `create_vm` (mutating, lease-gated)

| Param | Type | Req | Description |
|-------|------|-----|-------------|
| `target` | string | no | `localhost` or node name |
| `name` | string | **yes** | VM name |
| `vm_location` | string | cond. | Folder for VM config (`-Path`); **required unless `use_host_defaults=true`** (OQ-6) |
| `use_host_defaults` | bool | no | Permit the Hyper-V host default VM location (default false) |
| `vhd_path` | string | cond. | Path to an **existing** VHDX to attach (`-VHDPath`) |
| `new_vhd_path` | string | cond. | Path for a **new** VHDX (`-NewVHDPath`) |
| `new_vhd_size_gb` | number | cond. | Size for the new VHDX (`-NewVHDSizeBytes`) |
| `memory_mb` | number | no | Startup memory (default 4096) |
| `dynamic_memory` | bool | no | Enable dynamic memory (default false) |
| `dynamic_min_mb` | number | no | Dynamic memory minimum (when `dynamic_memory`) |
| `dynamic_max_mb` | number | no | Dynamic memory maximum (when `dynamic_memory`) |
| `dynamic_buffer_pct` | number | no | Dynamic memory buffer percentage (when `dynamic_memory`) |
| `cpu_count` | number | no | vCPU count (default 2) |
| `vswitch` | string | no | vSwitch to attach the primary NIC to (validated to exist) |
| `iso_path` | string | no | Windows install ISO; attached as DVD, set as first boot device **by matching the ISO path** |
| `secure_boot` | bool | no | Gen2 Secure Boot, `MicrosoftWindows` template (default true) |
| `required_free_gb` | number | no | Extra free-space requirement (GB) on the new VHD volume |

Exactly one of (`vhd_path`) or (`new_vhd_path` + `new_vhd_size_gb`) must be provided.

PowerShell sequence (new VHD + boot ISO):
```powershell
$exists = Get-VM -Name $name -ErrorAction SilentlyContinue
if ($exists) { throw "VM '$name' already exists" }   # idempotency: explicit fail

$args = @{ Name = $name; Generation = 2;
           MemoryStartupBytes = $memoryMB*1MB }
if ($vmLocation)  { $args.Path = $vmLocation }
if ($vhdPath)     { $args.VHDPath = $vhdPath }
else              { $args.NewVHDPath = $newVhdPath; $args.NewVHDSizeBytes = $sizeGB*1GB }
if ($vswitch)     { $args.SwitchName = $vswitch }
New-VM @args

Set-VMProcessor -VMName $name -Count $cpuCount
if ($dynamicMemory) { Set-VMMemory -VMName $name -DynamicMemoryEnabled $true }
if ($iso) {
    Add-VMDvdDrive -VMName $name -Path $iso
    $dvd = Get-VMDvdDrive -VMName $name
    Set-VMFirmware  -VMName $name -FirstBootDevice $dvd
}
if (-not $secureBoot) { Set-VMFirmware -VMName $name -EnableSecureBoot Off }
```

Returns:
```json
{ "target":"localhost","name":"win-test-01","generation":2,"state":"Off",
  "memory_mb":4096,"cpu_count":2,"vswitch":"ExternalSwitch",
  "vhd_path":"D:\\VMs\\win-test-01\\win-test-01.vhdx","action":"created" }
```

### 4.5 `provision_unattend` (mutating, lease-gated)

Generates an `unattend.xml` / `AutoUnattend.xml` from a template + params and **injects** it
into the VM's media (see §5). Idempotent: re-running regenerates and re-injects.

| Param | Type | Req | Description |
|-------|------|-----|-------------|
| `target` | string | no | `localhost` or node name |
| `vm_name` | string | **yes** | VM to provision |
| `hostname` | string | no | Guest computer name (default = `vm_name`) |
| `admin_password` | string | cond. | Local Administrator password (**see §5.3**) |
| `admin_password_credential` | string | cond. | Name of a saved credential profile to source the password from (preferred) |
| `locale` | string | no | e.g. `en-US` (UI/input/system locale, default `en-US`) |
| `timezone` | string | no | e.g. `Pacific Standard Time` |
| `product_key` | string | no | KMS/retail key (optional) |
| `first_boot_script` | string | no | Inline PowerShell run once at first logon (staged to `\Windows\Setup\Scripts\FirstBoot.ps1`) |
| `auto_logon` | bool | no | Enable one-time AutoLogon (`AutoLogonCount=1`, then scrubbed) (default false) |
| `obfuscate_password` | bool | no | Windows base64 answer-file obfuscation — **NOT encryption** (default false) |
| `injection_method` | string | no | `mount-vhd` (default) \| `autounattend-iso` (**deferred** — returns `METHOD_B_DEFERRED`) |
| `vhd_path` | string | **yes** | The OS VHDX to inject into (or the differencing-child path when `base_vhd` is set) |
| `base_vhd` | string | cond. | Shared sysprepped base VHDX; a **differencing child** is created at `vhd_path` and the base is never mutated |

Returns the path of the generated unattend, the injection method used, and a **masked**
echo of params (password never returned).

### 4.6 `create_windows_vm` (orchestrator) — **DEFERRED (primitives-first, OQ-5)**

> **Status: not shipped in Phase 1.** Per both reviews (OQ-5), only the validated primitives ship
> first. When added, the orchestrator must be a **thin composition** over the primitives, use
> **flat scalar params** (no nested object params — Heimdall §1), and emit **per-step resumable**
> output. The flattened param surface (`create_vswitch_name`, `create_vswitch_type`,
> `create_vswitch_net_adapter`, …) is reserved for that follow-on.

High-level convenience that would chain §4.3–§4.5 in one call, for the common "make me a VM" path.
It is **strictly a composition** of the primitives (so the primitives remain independently
usable/testable).

| Param | Type | Req | Description |
|-------|------|-----|-------------|
| `target` | string | no | `localhost` or node name |
| `name` | string | **yes** | VM name (also default hostname) |
| `vswitch` | string | cond. | Existing vSwitch to attach |
| `create_vswitch` | object | cond. | If `vswitch` absent: `{ name, type, net_adapter }` to create one first |
| `vm_location` | string | no | VM config folder |
| `base_vhd` | string | cond. | Path to a **sysprepped/generalized** base VHDX to copy/differencing-clone |
| `new_vhd_path` / `new_vhd_size_gb` | — | cond. | Or create a blank VHD + install from `iso_path` |
| `iso_path` | string | cond. | Windows install ISO (when not using a base VHD) |
| `memory_mb`, `cpu_count`, `dynamic_memory` | — | no | As in `create_vm` |
| `hostname`, `admin_password[_credential]`, `locale`, `timezone`, `first_boot_script` | — | no | As in `provision_unattend` |
| `start` | bool | no | Power on the VM after provisioning (default false) |

Behaviour (orchestrated, with per-step status in the result):
1. Resolve/`create_vswitch` if needed.
2. `create_vm`.
3. `provision_unattend` (inject AutoUnattend/unattend).
4. Optional `Start-VM` if `start=true`.

Returns a step-by-step JSON array plus a final summary, so partial failures are legible and
the operation is **resumable** (each primitive is idempotent/​explicit per §3, §4).

### 4.7 Summary of proposed tools

| Tool | Kind | Lease-gated | Core cmdlets |
|------|------|-------------|--------------|
| `list_physical_nics` | discovery | no | `Get-NetAdapter`, `Get-VMSwitch` |
| `list_vswitches` | discovery | no | `Get-VMSwitch` |
| `create_vswitch` | mutating | yes (remote) | `New-VMSwitch` |
| `create_vm` | mutating | yes (remote) | `New-VM`, `Set-VMProcessor`, `Set-VMMemory`, `Add-VMDvdDrive`, `Set-VMFirmware` |
| `provision_unattend` | mutating | yes (remote) | `New-VHD -Differencing`, `Mount-VHD`/`Dismount-VHD` + copy |
| `create_windows_vm` | orchestrator | — | **DEFERRED** (primitives-first, §4.6) |

---

## 5. unattend.xml strategy

### 5.1 Generation (template + params)

A Go `text/template` (or `html/template` with XML-safe escaping) renders an
`Autounattend.xml`/`unattend.xml` from typed params. Template lives at
`internal/hyperv/unattend/autounattend.xml.tmpl`; rendering in
`internal/hyperv/unattend/unattend.go`.

Params struct (illustrative):
```go
type UnattendParams struct {
    Hostname        string
    AdminPassword   string // sourced at call time, never persisted in the template file
    Locale          string // default en-US
    TimeZone        string
    ProductKey      string
    FirstBootScript string // emitted as a <FirstLogonCommands>/SetupComplete.cmd step
    Architecture    string // amd64 -> "amd64"
}
```

The template covers the `specialize` (ComputerName, locale, timezone), `oobeSystem`
(`<OOBE>` skip EULA/network, AutoLogon optional, `<UserAccounts><AdministratorPassword>`),
and optional `<FirstLogonCommands>` passes. XML special characters in all params are escaped.

### 5.2 Injection (two supported methods)

LabLink builds the XML **on the lablink-server host**, then puts it where Windows Setup/​Sysprep
will find it on the **target**:

**Method A — `mount-vhd` (default; for a sysprepped/generalized base VHDX):**
1. Render `unattend.xml` locally.
2. `pushToTarget` the file to the target (no-op when local).
3. On the target, run PowerShell:
   ```powershell
   $mount = Mount-VHD -Path $vhdPath -Passthrough | Get-Disk | Get-Partition |
            Where-Object { $_.DriveLetter } 
   # locate the Windows volume, then:
   New-Item -ItemType Directory -Force "$drive:\Windows\Panther" | Out-Null
   Copy-Item $unattendOnTarget "$drive:\Windows\Panther\unattend.xml" -Force
   Dismount-VHD -Path $vhdPath
   ```
   On first boot the specialize pass consumes `\Windows\Panther\unattend.xml`.
   (For a first-boot script we also drop `\Windows\Setup\Scripts\SetupComplete.cmd`.)

**Method B — `autounattend-iso` (for clean install from a Windows ISO):**
1. Render `Autounattend.xml` locally.
2. Build a tiny ISO with `Autounattend.xml` at its root (via `New-IsoFile` helper PowerShell,
   or `oscdimg` if present — see OQ-2), push to target.
3. `Add-VMDvdDrive -VMName $vm -Path <autounattend.iso>` as a **second** DVD. Windows Setup
   scans removable media roots for `Autounattend.xml` automatically.

Phase 1 ships **Method A as default** (fastest, deterministic, base-image workflow) and
Method B for the install-from-ISO path. `provision_unattend.injection_method` selects.

### 5.3 Admin-password security handling (RAI/credential)

**Hard rules:**
- **Never hardcode** a password in the template, repo, or generated artifact committed to disk
  longer than necessary.
- **Prefer `admin_password_credential`** → resolve from the existing `internal/credentials`
  store at call time; the plaintext password lives only in memory during rendering.
- If `admin_password` is supplied inline, accept it but **mask** it everywhere:
  - Ops registry / portal args: store `admin_password` as `***` (the `beginOp` args map must
    receive a redacted value — never the raw secret).
  - Audit log (`internal/audit`): the VM tools must **not** put the password in
    `Entry.Command` or args; log only `admin_password=<set>`.
  - Tool return value: echo params with the password replaced by `***`.
- The rendered `unattend.xml` contains the password in cleartext (Windows requirement). The
  injector must **delete the staged copy** on the lablink-server host after push, and the
  on-VHD `Panther\unattend.xml` is consumed+removed by Windows during specialize. Document
  this residual-risk clearly (OQ-4).
- Optionally support unattend `<AdministratorPassword><PlainText>false` with a base64 of
  `<password>AdministratorPassword` (Windows' obfuscation) — not real encryption, but avoids
  trivially-grep'able plaintext. Flagged as low-value; default plaintext-with-cleanup.

---

## 6. Hyper-V interaction details

### 6.1 Prerequisites & preflight (every tool runs this first)

A shared `Test-LabLinkHyperV` preamble (emitted by `internal/hyperv/preflight.go`) checks and
returns a structured error if unmet:

```powershell
# Hyper-V management module present?
if (-not (Get-Command New-VM -ErrorAction SilentlyContinue)) {
    throw 'HYPERV_NOT_AVAILABLE: Hyper-V PowerShell module/role not installed'
}
# Admin / elevation (Hyper-V cmdlets require admin; the agent service usually runs as
# LocalSystem which satisfies this, but verify)
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $admin) { throw 'NOT_ELEVATED: Hyper-V operations require Administrator' }
```

Enabling the Hyper-V **role** itself (`Enable-WindowsOptionalFeature -Online -FeatureName
Microsoft-Hyper-V -All`) requires a reboot and is **out of scope for Phase 1** — we detect and
return a clear remediation message (caller can use existing `reboot_node`/`install_package`
flows). Documented as a precondition.

### 6.2 Error handling

- All VM PowerShell runs with `$ErrorActionPreference = 'Stop'` wrapped in `try/catch`, and the
  catch emits a single-line tagged error (`HYPERV_NOT_AVAILABLE`, `NIC_NOT_FOUND`,
  `VSWITCH_EXISTS`, `VM_EXISTS`, `VHD_NOT_FOUND`, `MOUNT_FAILED`, ...) plus the exception
  message. The Go handler maps non-zero exit / tagged stderr to `mcp.NewToolResultError`.
- The Go layer also validates obvious arg combinations before running PowerShell (e.g. exactly
  one of `vhd_path`/`new_vhd_path`, `type=external` ⇒ `net_adapter` required).

### 6.3 Idempotency

| Operation | Strategy |
|-----------|----------|
| `create_vswitch` | `Get-VMSwitch` precheck + `if_exists = reuse\|fail\|replace` |
| `create_vm` | `Get-VM` precheck; existing VM ⇒ explicit `VM_EXISTS` error (no silent clobber) |
| `provision_unattend` | Regenerate + overwrite (`Copy-Item -Force`); safe to re-run |
| Mount/Dismount | Always `Dismount-VHD` in a `finally` block to avoid leaking a mounted VHD on error |

### 6.4 Why PowerShell, not WMI/Go

The agent already executes PowerShell with streaming, timeouts, and heartbeats; the Hyper-V
module is the supported, stable surface; and it gives **one identical code path** for local and
remote. WMI (`root\virtualization\v2`) would mean a second, OS-version-sensitive code path with
no upside for Phase 1.

### 6.5 Lifecycle follow-on (noted, not in Phase 1)

`start_vm` / `stop_vm` / `delete_vm` / `list_vms` are trivial wrappers (`Start-VM`, `Stop-VM`,
`Remove-VM`, `Get-VM`) and a natural Phase 1.5; called out so the package layout reserves room.

---

## 7. Local vs remote execution — exact mapping

| Concern | localhost | remote node |
|---------|-----------|-------------|
| Resolve | `target` is empty/`localhost`/`local` | `reg.GetNode(target)` |
| Run PS | `executeLocalPowershell(ctx, script, timeout)` (`pwsh`) | `executeScriptOnNode` → agent `ExecuteScript` (`powershell.exe`) |
| File staging | local file already present / `Copy-Item` | `pushFileToNode` (`push_file` machinery) |
| Lease gate | `extractTarget` returns `nil` ⇒ pass-through | returns `["<node>"]` ⇒ requires lease |
| Ops/portal | `beginOp` with `node="localhost"` | `beginOp` with `node="<node>"` |
| Health-aware ctx | n/a | `nodeCallContext` cancels if node dies |

The handler body is identical except for the one `runPS` branch; `Target` carries the choice.
No new RPC, no proto change, no new transport — this is the key design simplification.

---

## 8. Discovery-to-prompt flow

Intended caller/agent interaction so option values are **discovered, then chosen**:

```
1. list_vswitches(target)            -> existing switches
   list_physical_nics(target)        -> NICs + which are free / recommended_for_external
        │
        ▼  (agent presents choices to the user / picks a default)
2a. reuse:  create_vm(..., vswitch="ExternalSwitch")
2b. create: create_vswitch(name="LabExt", type="external",
                           net_adapter="<chosen NIC>")  then create_vm(..., vswitch="LabExt")
        │
        ▼
3. provision_unattend(vm_name, hostname, admin_password_credential=..., ...)
        │
        ▼
4. (optional) start_vm  / or use create_windows_vm to do 2-4 in one shot
```

To make this ergonomic for an AI client:
- Discovery results include `recommended_*` hints and `bound_vswitch`/`free` flags so the agent
  can pick sane defaults without a round-trip to the human when unattended.
- `create_vswitch`/`create_vm` return the canonical names so the next call can chain them.
- The orchestrator `create_windows_vm` accepts an inline `create_vswitch` object so the entire
  flow is one tool call when the caller already knows the NIC.

---

## 9. Proposed file / package layout

```
internal/
  hyperv/                         (NEW — pure builders + templates, no MCP deps; unit-testable)
    preflight.go                  Test-LabLinkHyperV preamble emitter
    vswitch.go                    BuildCreateVSwitchScript / parse Get-VMSwitch JSON
    vm.go                         BuildCreateVMScript, BuildListNicsScript
    nics.go                       parse Get-NetAdapter JSON
    unattend/
      unattend.go                 UnattendParams + Render()
      autounattend.xml.tmpl       the template
      inject.go                   BuildMountInjectScript / BuildIsoInjectScript
  mcptools/
    vm.go                         (NEW) RegisterVM(...) + the 6 tool handlers
    target.go                     (NEW) Target, resolveTarget, runPS, pushToTarget
    vm_test.go                    (NEW) handler tests (mock agent like execute_test.go)
cmd/lablink-server/
    main.go                       +1 line: mcptools.RegisterVM(s, reg, pool, creds, auditLog, leaseCfg)
docs/design/
    vm-management-phase1.md       (this doc)
```

Rationale: keep all **string/PowerShell/XML construction** in `internal/hyperv` (no MCP or gRPC
imports) so it is cheaply unit-tested in isolation; keep MCP wiring + target routing + lease
gating in `internal/mcptools`, matching the existing one-file-per-area convention.

`RegisterVM` signature mirrors siblings:
```go
func RegisterVM(s *server.MCPServer, reg *registry.Registry, pool *agentclient.Pool,
                creds *credentials.Store, auditLog *audit.Log, leaseCfg LeaseGateConfig)
```

---

## 10. Phasing & risks

### 10.1 In Phase 1 (implemented)
- `list_physical_nics` (mgmt-NIC flag), `list_vswitches`, `create_vswitch` (mgmt-NIC safeguard +
  override), `create_vm` (Gen2 completeness), `provision_unattend` (Method A differencing +
  content volume detection + password scrub).
- Local + remote target via `runPS` (Windows PowerShell, nonzero-exit = failure).
- unattend **Method A** (mount-VHD, default) with first-boot scrub + `AutoLogonCount=1`.
- Credential-sourced admin password + redaction everywhere.

### 10.2 Deferred
- **`create_windows_vm` orchestrator** (primitives-first, OQ-5).
- **unattend Method B** (AutoUnattend clean-install ISO) — needs windowsPE partitioning/image
  selection + a vetted `oscdimg`/bundled ISO writer (`METHOD_B_DEFERRED` stub).
- **Async/detached job + reconnect** executor for disruptive remote NIC ops (override is the
  current audited escape hatch).
- VM lifecycle (start/stop/checkpoint/delete/list) — Phase 1.5 (wrappers only).
- Enabling the Hyper-V role / reboot orchestration.
- Domain join, static IP in unattend, multiple NICs.
- Linux guests, cloud-init, Gen1.

### 10.3 Risks
- **Elevation:** Hyper-V cmdlets need admin. The agent typically runs as LocalSystem (OK), but
  a non-elevated agent will fail — preflight surfaces this clearly.
- **`pwsh` vs `powershell.exe` parity (local path):** `executeLocalPowershell` uses `pwsh`
  (PowerShell 7). The Hyper-V module loads in pwsh on most hosts but some cmdlets behave subtly
  differently; remote path uses Windows PowerShell 5.1. See OQ-3.
- **VHD mount races / leaked mounts:** mitigated with `finally { Dismount-VHD }`.
- **Plaintext password in unattend on disk** during first boot — residual risk, documented; we
  delete staged copies and rely on Windows consuming the on-VHD copy. See OQ-4.
- **ISO tooling availability** on arbitrary targets (OQ-2).
- **Long-running installs** (clean install from ISO can exceed default timeouts) — rely on the
  existing heartbeat/job (`detach`) machinery; provisioning that waits for OOBE may need a
  follow-up poll tool (out of Phase 1; `provision_unattend` only injects, doesn't wait).

### 10.4 Open questions for Heimdall / Nithin
- **OQ-1:** Should discovery tools (`list_*`) on a **remote** target require a lease? (Proposed:
  no — read-only, ergonomic. Heimdall to confirm policy consistency.)
- **OQ-2:** ISO build mechanism for Method B — depend on `oscdimg` (ADK) if present, else a
  bundled pure-PowerShell `New-IsoFile`? Or restrict Method B to hosts with ADK?
- **OQ-3:** For `target=localhost`, switch `executeLocalPowershell` to `powershell.exe` for
  parity with the remote agent, or keep `pwsh`? (Leaning: prefer `powershell.exe` on Windows for
  Hyper-V parity; make it configurable.)
- **OQ-4:** Acceptable handling of the plaintext admin password in the on-disk unattend during
  first boot — is delete-after-consume + masking sufficient, or do we want the base64
  obfuscation and/or a post-provision scrub step?
- **OQ-5:** Is `create_windows_vm` desired in Phase 1, or do we ship only the primitives first
  and add the orchestrator after the primitives are validated by Bucky?
- **OQ-6:** Default VM/VHD locations when `vm_location` omitted — use the Hyper-V host default,
  or require explicit paths to avoid surprising disk placement on shared lab hosts?

---

## 11. Testability notes (for Bucky)

- `internal/hyperv` builders are pure string/XML → table-driven unit tests (no Hyper-V needed):
  assert generated cmdlet text and rendered XML for representative param sets, including
  escaping and the password-masking redaction.
- MCP handlers tested with the existing **mock agent** pattern (`execute_test.go`,
  `diagnostics_test.go` spin up an in-process gRPC `NodeAgent`); the mock returns canned
  `Get-VMSwitch`/`Get-NetAdapter` JSON so handler parsing + result shaping is verified without a
  hypervisor.
- An optional **integration** lane (gated by an env flag / a node labeled `hyperv`) exercises
  real `create_vswitch`/`create_vm` against a lab host; off by default in CI.
