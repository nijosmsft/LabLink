# LabLink

[![Latest release](https://img.shields.io/github/v/release/nijosmsft/LabLink)](https://github.com/nijosmsft/LabLink/releases/latest)

**Give your AI assistant secure remote-hands on a fleet of Windows lab machines.**

LabLink is an [MCP](https://modelcontextprotocol.io) server plus a lightweight node agent. Once installed, an MCP-aware AI client (Claude Desktop, Copilot CLI, Cursor, etc.) can run commands, move files, inspect processes, and orchestrate work across many lab machines — over mutually-authenticated TLS, with a shared auth token.

```
┌──────────────────┐       MCP / stdio       ┌──────────────────┐    mTLS + token    ┌──────────────────┐
│   AI client      │ ──────────────────────▶ │  LabLinkServer   │ ─────────────────▶ │  LabLinkAgent    │
│ (Claude, etc.)   │                         │   (operator)     │                    │  (each node)     │
└──────────────────┘                         └──────────────────┘                    └──────────────────┘
```

Typical things an AI client can ask LabLink to do:

- "Run `ipconfig /all` on `lab-node-3` and summarize the output."
- "Push this build artifact to all nodes in the `clients` role and start the test."
- "Tail the last 200 lines of `C:\logs\app.log` on the server node."
- "List every node where `echo_server.exe` is currently running and kill it."

## Why LabLink?

- **One config in your AI client** → access to many remote machines.
- **mTLS by default**, with a shared bearer token for application-level auth.
- **No SSH, no RDP, no opening WinRM to your AI** — only a single gRPC port (default `9091`) per node.
- **Bootstrap scripts** generate the PKI, the token, and the MCP config snippet for you.
- **Pure Go**, no external runtimes on the nodes.

## Get started in ~5 minutes

You'll need:

- A Windows operator machine.
- One or more Windows lab nodes. WinRM isn't mandatory, but having it enabled lets the bootstrap script deploy in a single command — the [No WinRM?](#no-winrm-build-a-hand-carry-install-package) flow below covers nodes where it's blocked.
- PowerShell 5+ on both sides.

### 1. Download the latest release

Grab `lablink-vX.Y.Z-windows-amd64.zip` from the [Releases page](https://github.com/nijosmsft/LabLink/releases/latest), verify it against `SHA256SUMS.txt`, and extract:

```powershell
# Always pull the latest tag from GitHub (no manual bump needed).
$ver = (Invoke-RestMethod 'https://api.github.com/repos/nijosmsft/LabLink/releases/latest').tag_name
Invoke-WebRequest "https://github.com/nijosmsft/LabLink/releases/download/$ver/lablink-$ver-windows-amd64.zip" -OutFile lablink.zip
Invoke-WebRequest "https://github.com/nijosmsft/LabLink/releases/download/$ver/SHA256SUMS.txt"               -OutFile SHA256SUMS.txt
# Select-String.ToString() prepends "<path>:<line>:"; use .Line to get just the matched text.
$expected = ((Select-String -Path SHA256SUMS.txt -Pattern "lablink-$ver-windows-amd64.zip").Line -split '\s+')[0]
$actual   = (Get-FileHash lablink.zip -Algorithm SHA256).Hash.ToLower()
if ($expected -ne $actual) { throw "checksum mismatch: expected=$expected actual=$actual" }
# Per-version directory keeps old installs around (cheap rollback) and avoids
# Expand-Archive collisions on upgrade. Re-running the same version is idempotent
# via -Force.
$dest = "C:\LabLink\$ver"
Expand-Archive lablink.zip -DestinationPath $dest -Force
Remove-Item lablink.zip, SHA256SUMS.txt
cd $dest
```

After this you have `C:\LabLink\$ver\bin\lablink-server.exe` (and friends). To always run the latest, point a junction at it:

```powershell
$current = 'C:\LabLink\current'
if (Test-Path $current) { (Get-Item $current).Delete() }  # delete the junction, not the target
New-Item -ItemType Junction -Path $current -Target $dest | Out-Null
```

Then anything referencing `C:\LabLink\current\bin\lablink-server.exe` stays valid across upgrades.

The archive contains:

| Path | Where it runs | Purpose |
|------|---------------|---------|
| `bin\lablink-server.exe` | Operator | The MCP server your AI client launches over stdio. |
| `bin\lablink-agent.exe`  | Each node | gRPC agent that executes the work. |
| `bin\lablink-probe.exe`  | Operator | Smoke-test a node from the command line. |
| `bin\lablink-ca.exe`    | Operator | Local certificate authority used by the bootstrap scripts. |
| `scripts\*.ps1`         | Operator | Bootstrap and deployment scripts. |
| `configs\mcp.example.json` | Operator | Template for your AI client's `.mcp.json`. |

> **Building from source instead?** See [Build from source](#build-from-source) at the bottom.

### 2. Bootstrap your operator machine (one time)

```powershell
.\scripts\bootstrap-operator.ps1
```

This creates a local PKI, an operator client certificate, an auth token, and a ready-to-paste MCP snippet under `~\.lablink\`.

### 3. Bootstrap each Windows node

```powershell
.\scripts\bootstrap-windows-node.ps1 -Machine lab-node-3 -Role server
```

You can also pass several machines at once. They share the same WinRM credential and run sequentially; one failure does not stop the rest:

```powershell
.\scripts\bootstrap-windows-node.ps1 -Machine lab-node-3,lab-node-4,lab-node-5 -Role server
```

If a machine name resolves over DNS the IPv4 address is auto-detected; otherwise pass them positionally with `-IPv4Address 10.0.0.23,10.0.0.24,10.0.0.25`.

The script issues a node-specific server certificate, deploys `lablink-agent.exe` over WinRM, installs the **LabLink Agent** Windows service, opens the firewall port, verifies the node with `lablink-probe.exe`, and registers it in `~\.lablink\nodes.json`.

You'll be prompted for the node's WinRM credentials if you don't pass `-Credential`.

#### No WinRM? Build a hand-carry install package

If WinRM is disabled, blocked, or you'd rather not give the operator a credential on the node, run the same bootstrap with `-Manual`:

```powershell
.\scripts\bootstrap-windows-node.ps1 -Manual -Machine lab-node-3,lab-node-4 -Role client
```

This delegates to `scripts\build-manual-package.ps1`, which (per machine):

- issues a server certificate signed by your local LabLink CA,
- assembles `~\.lablink\manual\<node>\` with `lablink-agent.exe`, `install.ps1`, the CA bundle, the server cert + key, the auth token, and a `metadata.json` describing the node,
- zips it to `~\.lablink\manual\lablink-<node>.zip`, and
- pre-registers the node in `~\.lablink\nodes.json` so the MCP server recognizes it as soon as the agent comes up.

Hand the zip to the owner of the remote machine. They extract it and, from an elevated PowerShell:

```powershell
.\install.ps1
```

That's the entire node-side procedure. `install.ps1` mirrors the bundled files into `C:\LabLink`, locks down the token + private key, installs the **LabLink Agent** Windows service, opens the firewall, starts it, and (by default) deletes the bundled token + key copies. Override `-AgentDir` or `-Port` if needed.

You can also call the package builder directly without going through `bootstrap-windows-node.ps1`:

```powershell
.\scripts\build-manual-package.ps1 -Machine lab-node-3 -Role server -OutDir C:\handoff
```

Once the remote owner reports success, verify from the operator:

```powershell
$env:LABLINK_TRANSPORT        = 'mtls'
$env:LABLINK_AGENT_TOKEN_FILE = "$HOME\.lablink\agent.token"
$env:LABLINK_TLS_CA           = "$HOME\.lablink\pki\ca-bundle\ca.crt"
$env:LABLINK_TLS_CERT         = "$HOME\.lablink\pki\clients\default\client.crt"
$env:LABLINK_TLS_KEY          = "$HOME\.lablink\pki\clients\default\client.key"
$env:LABLINK_TLS_SERVER_NAME  = 'lab-node-3'

.\bin\lablink-probe.exe 10.0.0.23:9091
```

A successful probe ends with `Probe OK`. The `nodes.json` entry is already in place; your AI client will see the node the next time the LabLink MCP server starts.

### 4. Wire LabLink into your AI client

Open `~\.lablink\mcp.example.json` (generated in step 2) and merge it into your AI client's MCP config — for example, `~\.cursor\mcp.json` or `claude_desktop_config.json`. The snippet looks like this:

```json
{
  "mcpServers": {
    "lablink": {
      "command": "C:\\path\\to\\lablink-server.exe",
      "args": [],
      "env": {
        "LABLINK_TRANSPORT": "mtls",
        "LABLINK_AGENT_TOKEN_FILE": "C:\\Users\\you\\.lablink\\agent.token",
        "LABLINK_TLS_CA":   "C:\\Users\\you\\.lablink\\pki\\ca-bundle\\ca.crt",
        "LABLINK_TLS_CERT": "C:\\Users\\you\\.lablink\\pki\\clients\\default\\client.crt",
        "LABLINK_TLS_KEY":  "C:\\Users\\you\\.lablink\\pki\\clients\\default\\client.key"
      }
    }
  }
}
```

That's it. Restart your AI client and ask it to `list_nodes`.

## The local operations portal

When `lablink-server.exe` starts it also serves a tiny web UI on a random `127.0.0.1` port that lists every long-running operation (`execute_command`, `execute_script`, `push_file`, `pull_file`) and lets you cancel any of them. The bookmarkable URL — including a per-process access key — looks like:

```
http://127.0.0.1:49869/?k=3c76da1b807c58bd390d7cf028307d06
```

When the server runs as an MCP child of an AI client, its stderr is usually swallowed, so just ask the AI client — e.g. *"what is the portal url?"* — and it will call the `get_portal_url` tool to hand it back. (When you launch `lablink-server.exe` directly, the same URL is logged on startup.)

Open it in any browser on the operator machine. Updates stream live over Server-Sent Events. The portal binds **only** to loopback and rejects requests without the access key.

The portal has two tabs:

- **Operations** — in-flight tool calls with a Cancel button.
- **Jobs** — background (detached) commands. Any `execute_command` or `schedule_command` with `detach:true` is tracked as a *job* with a stable `job_id`, captured stdout/stderr, exit code, and lifecycle status (`running` / `exited` / `canceled` / `orphaned`). From the UI you can view captured output (stdout / stderr / both, last 500 lines by default), cancel a running job, or delete a finished one. Updates stream live via `WatchJobs` gRPC into a single `/api/jobs/stream` SSE feed. The same primitives are exposed to AI clients as `list_jobs`, `get_job_status`, `get_job_output`, `cancel_job`, and `delete_job`.

Jobs are stored on each node under `%ProgramData%\LabLink\agent\jobs\<job_id>\` (Windows) or `/var/lib/lablink-agent/jobs/<job_id>/` (Linux). Terminal jobs are auto-pruned after 7 days; override with `LABLINK_JOB_RETENTION=Nd` (or any Go duration) on the **agent** side.

Each AI client spawns its own `lablink-server.exe`, so each gets its own portal.

To turn it off, set `LABLINK_PORTAL=disabled`. To pin it to a fixed port for bookmarking, set `LABLINK_PORTAL_ADDR=127.0.0.1:9092`.

## What the AI client can do

LabLink exposes the following MCP tools. Names are stable; argument schemas are described in the tool's own `description` field that AI clients see at startup.

### Inventory and topology
| Tool | What it does |
|------|--------------|
| `register_node` | Register a node in the inventory. Probes the agent for OS, CPU, and memory. |
| `list_nodes` | List registered nodes with status, agent version, and any non-blocking upgrade recommendation. |
| `remove_node` | Remove a node from the registry. |
| `rename_node` | Rename a node, preserving context and topology references. |
| `register_topology` | Define a named group of nodes with role assignments (e.g. `server`, `client`). |
| `set_node_context` | Persist a default working directory and environment for a node. |
| `import_nodes` / `export_nodes` | Round-trip the registry to a YAML file. |

Authenticated health probes compare nonempty server and agent version strings.
An exact mismatch logs `agent upgrade recommended` once per node/version tuple
for the lifetime of the server process and is surfaced by `list_nodes`.
Version skew alone never marks a node unhealthy, cancels its context, or blocks
an operation; unsupported/missing RPCs still fail naturally when invoked.
Agent upgrades occur only through an explicit deployment/update request.

### Execution
| Tool | What it does |
|------|--------------|
| `execute_command` | Run a shell command on a node. Set `detach:true` to fire-and-forget — returns a `job_id` you can tail/cancel later. Supports foreground-only `secret_env` references. |
| `execute_script` | Push an inline script and execute it atomically. Supports `secret_env` references. |
| `execute_on_role` | Run the same command on every node with a given role, in parallel. |
| `run_script_on_role` | Run the same inline script on every node with a given role, in parallel. |
| `schedule_command` | Run a command after a delay (useful for synchronized starts). Returns a `job_id`. |
| `list_processes` / `kill_process` | Inspect or terminate remote processes. |
| `list_jobs` / `get_job_status` / `get_job_output` | Inspect background (detached) jobs on a node. |
| `cancel_job` / `delete_job` | Cancel a running job or delete a terminal job's captured output. |

### Secrets

| Tool | What it does |
|------|--------------|
| `save_secret` | Open a local masked terminal prompt for saving or replacing an arbitrary secret. The value never passes through MCP. |
| `list_secrets` | List secret names only. |
| `delete_secret` | Delete a saved secret. |

On Windows, `save_secret` opens the packaged helper in a new local console,
waits for masked entry and confirmation, then reloads the encrypted store so
the secret is immediately available through `secret_env`. The helper runs as
the same OS account as the LabLink server because DPAPI encryption is
user-scoped.

The packaged `lablink-secret` CLI remains available for direct local
administration. It requires an interactive terminal, displays `*` feedback for
each typed character, supports visible backspace correction, and refuses
redirected input.

Reference saved secrets by environment variable name:

```json
{
  "node": "lab-node-3",
  "script_body": "Expand-ArchiveWithPassword $env:MSRC_ARCHIVE_PASSWORD",
  "secret_env": {
    "MSRC_ARCHIVE_PASSWORD": "msrc-archive-password"
  }
}
```

LabLink resolves the value inside the MCP server and sends it through the
mTLS-protected agent environment map. It never places the value in the command
line, audit record, operation metadata, or returned output; literal occurrences
in stdout/stderr are replaced with `***` before returning or spilling output.
`secret_env` is rejected for detached commands because persistent job output
cannot yet guarantee equivalent redaction.

On Windows, arbitrary secrets are encrypted at rest with user-scoped DPAPI in
`~\.lablink\secrets.json`. On non-Windows operator hosts, LabLink uses an
AES-GCM key stored with restrictive permissions in `~/.lablink/secrets.key`.

### Hyper-V Windows VMs

| Tool | What it does |
|------|--------------|
| `list_physical_nics` / `list_vswitches` | Discover Hyper-V networking. |
| `create_vswitch` | Create or safely reuse an external, internal, or private switch. |
| `create_vm` | Low-level Gen2 VM primitive. |
| `provision_unattend` | Create/inject a differencing Windows OS disk using a saved administrator credential profile. |
| `create_windows_vm` | High-level safe composition of provisioning plus VM creation. |
| `join_windows_domain` | Join an existing Windows node with a saved password secret, reboot, and verify its Netlogon secure channel. |
| `save_vm_template` / `list_vm_templates` / `delete_vm_template` | Manage persistent, non-secret VM defaults and per-host template selection. |
| `delete_vm` | Dry-run-first VM deletion with optional safe child-storage, registry, and issued-identity cleanup. |

`create_windows_vm` resolves settings in this order:

1. Explicit tool arguments.
2. A named profile, or `default_profile`, from
   `~\.lablink\vm-defaults.json`.
3. An MCP form prompt for only the unresolved values.

Example autonomous default:

```json
{
  "default_profile": "windows-lab",
  "profiles": {
    "windows-lab": {
      "target": "lab-node-3",
      "base_vhd": "E:\\Images\\server-base.vhdx",
      "vm_root": "E:\\VM",
      "vswitch": "extswitch",
      "admin_password_credential": "labadmin",
      "memory_mb": 8192,
      "cpu_count": 4,
      "secure_boot": true,
      "locale": "en-US",
      "timezone": "Pacific Standard Time",
      "obfuscate_password": true
    }
  }
}
```

The defaults file contains no secret values—only the credential profile name.
Set `LABLINK_VM_DEFAULTS_FILE` to use a different path. A complete explicit
request or complete profile runs without prompting; a partial request overrides
the profile and prompts only for what remains missing. Use `dry_run:true` to
inspect the resolved plan without modifying the host.

Profiles accept `profile_usage:"ordinary"` (the default, including an omitted
field) or `profile_usage:"linux_image_builder"`. Builder-only profiles are
accepted only by the internal Linux image-preparation flow. Public
`create_windows_vm` requests, including dry runs, reject them before any host
probe or mutation and point to an ordinary target/global default when one is
configured. For backward compatibility, a Windows profile referenced by any
Linux profile's `image_builder_profile` is also inferred to be builder-only
when the explicit usage field is absent. Unknown usage values fail closed.
Save builder profiles with `set_as_target_default:false`.

`save_vm_template(..., set_as_target_default:true)` records the template under
`target_defaults`, so a request such as “create a VM on RR1N4406-30” selects
that host's template automatically.

Before any VM/VHD mutation, LabLink projects:

- host available physical memory minus the VM startup allocation, and
- target-volume free space minus worst-case VHD growth.

Both projected values must leave at least `min_host_reserve_pct` of total host
RAM/volume capacity free (default `10`). Templates can raise or lower the
threshold. They cannot disable it: bypass requires an explicit
`allow_host_resource_pressure:true` on the individual creation request.
`dry_run:true` performs the same live check and returns the measured totals,
projected values, thresholds, and safe/unsafe flags.

Failed Windows VM creation preserves evidence by default. The exact
provisioned child VHD remains in place, and LabLink performs a read-only,
exact-name VM probe and returns structured partial-VM identity, state, status,
disk, and configuration-path diagnostics together with the original error.
Set `cleanup_on_failure:true` only when rollback is desired. Opt-in cleanup
uses a per-request opaque ownership marker and removes only the exact same-name
VM, requested OS VHD, and VM location below the managed root. Missing or
mismatched identity fails cleanup closed and retains the artifacts.

When `register_with_lablink:true`, `create_windows_vm` also:

1. Issues a unique guest mTLS server certificate.
2. Injects the LabLink agent, token, certificate, and private key into the
   differencing disk.
3. Completes OOBE with a one-time Administrator logon, installs the agent from
   token/key files, configures the firewall, starts the service, and removes
   staged secret copies.
4. Starts the VM, discovers its IPv4 address, verifies the agent over mTLS, and
   registers the guest in `nodes.json`.

Windows profiles may include an optional `domain_join` object:

```json
{
  "register_with_lablink": true,
  "domain_join": {
    "domain": "corp.example.com",
    "username": "CORP\\vmjoin",
    "password_secret": "corp-domain-join",
    "ou_path": "OU=Lab,DC=corp,DC=example,DC=com",
    "reboot": true,
    "verify_secure_channel": true
  }
}
```

Save the password first with `save_secret`; profiles store only its name.
Domain join is Windows-only and requires LabLink enrollment. The VM is created,
started, and authenticated over mTLS before LabLink resolves the password
server-side, discovers a domain controller, calls `Add-Computer`, reboots once,
and verifies both domain membership and `nltest /sc_verify`. Use
`skip_domain_join:true` to bypass an inherited profile setting for one
creation.

The LabLink agent remains LocalSystem after joining. A domain password is
injected only for the join operation and is never written into unattend,
first-boot scripts, command lines, audit entries, or tool output. Domain-join
failure retains the created VM for diagnosis. VM deletion does not remove the
Active Directory computer object; directory cleanup is a separate explicit
administrative action.

The tool emits MCP progress notifications during long provisioning and
enrollment waits. If Hyper-V cannot start the guest—for example because the
host lacks available memory—the operation returns the `Start-VM` error
immediately instead of waiting for the guest IP timeout.

Explicit `hostname` values must be valid Windows computer names: 1–15 ASCII
letters, digits, or hyphens; no leading/trailing hyphen; and not all digits.
When `hostname` is omitted, LabLink derives and truncates a safe value from the
VM name.

Parallel VM creation remains supported. Each request uses independent,
cryptographically random remote staging paths so answer files and enrollment
certificates cannot overwrite another request's payload.

Windows profiles and both `create_vm` / `create_windows_vm` accept
`expose_virtualization_extensions`. When true, LabLink configures the VM
processor immediately after `New-VM` and before any guest start. The default is
false, preserving existing Windows VM behavior.

They also accept `virtualization_based_security_opt_out`. When true, LabLink
requires the new VM to remain Off, runs
`Set-VMSecurity -VirtualizationBasedSecurityOptOut $true` immediately after
`New-VM`, and verifies the value with `Get-VMSecurity` before continuing.
The default is false for backward compatibility. Dry-run plans and creation
results expose the resolved value.

`delete_vm` defaults to a dry run. Actual deletion requires `dry_run:false`;
stopping a running VM additionally requires `force_stop:true`, and file removal
requires `delete_storage:true`. Storage deletion is limited to
`<managed_root>\<vm-name>` and never follows or deletes a differencing parent
VHD. If the VM is still a registered LabLink node, deletion first runs
`ipconfig /release` as a best effort—the resulting disconnect/error is expected
and ignored—then removes the registry entry after successful VM deletion.
For managed Linux VMs, persisted identity and every attached disk path are
validated before a running guest is stopped. The OS/checkpoint VHD parent chain
must terminate at the persisted base; unrelated data-disk parents do not define
OS identity, but each data disk must still be within the managed VM directory.
Create/resume and delete use the same case-insensitive per-VM lifecycle lock,
held from metadata inspection through all requested VM, storage, registry, and
identity cleanup.

### Ubuntu 24.04 Hyper-V VMs

| Tool | What it does |
|------|--------------|
| `prepare_linux_image` | Verify Canonical's fixed Ubuntu 24.04 Azure VHD archive and prepare it through a required nested-virtualization Windows builder VM. |
| `get_linux_image_status` | Return persisted phase state plus any active BITS job IDs and byte progress. |
| `create_linux_vm` | Prepare-on-demand, create a Gen2 differencing VM, provision through standard NoCloud CIDATA, verify mTLS, and optionally register it. |

The physical host needs Hyper-V, BITS, in-box `tar.exe`, and the Hyper-V
`Convert-VHD`/`Resize-VHD` cmdlets. It verifies Canonical's signed manifest,
validates and safely extracts the exact Azure VHD archive, converts it to a
dynamic 1 MiB-block VHDX, and never installs WSL, enables WSL features, mounts
the Linux filesystem, or reboots for image preparation.

Linux profiles use `guest_os:"linux"` plus the independent
`default_linux_profile` / `linux_target_defaults` selectors. Empty `guest_os`
continues to mean Windows, and existing `default_profile` / `target_defaults`
behavior is unchanged. Linux image preparation additionally requires
`image_builder_profile`, which must name a complete Windows profile for the
same target. Builder profiles must explicitly expose virtualization
extensions, use static memory, opt out of virtualization-based security, and
set `profile_usage:"linux_image_builder"`; validation rejects an unsafe,
ordinary, or incomplete builder before host mutation. Public
`create_windows_vm` cannot use that profile.
Example:

```json
{
  "default_linux_profile": "ubuntu-lab",
  "linux_target_defaults": {
    "hyperv-host-1": "ubuntu-lab"
  },
  "profiles": {
    "linux-image-builder": {
      "guest_os": "windows",
      "profile_usage": "linux_image_builder",
      "target": "hyperv-host-1",
      "base_vhd": "E:\\Images\\windows-base.vhdx",
      "vm_root": "E:\\VM",
      "vswitch": "extswitch",
      "admin_password_credential": "lab-admin",
      "memory_mb": 8192,
      "cpu_count": 4,
      "dynamic_memory": false,
      "register_with_lablink": true,
      "expose_virtualization_extensions": true,
      "virtualization_based_security_opt_out": true
    },
    "ubuntu-lab": {
      "guest_os": "linux",
      "target": "hyperv-host-1",
      "distribution": "ubuntu",
      "release": "24.04",
      "architecture": "amd64",
      "image_cache_root": "E:\\LabLinkImages",
      "image_builder_profile": "linux-image-builder",
      "builder_vm_name": "LabLink-Ubuntu-Builder",
      "delete_builder_after_prepare": false,
      "vm_root": "E:\\VM",
      "vswitch": "extswitch",
      "linux_username": "lab",
      "ssh_public_key_file": "C:\\Users\\operator\\.ssh\\id_ed25519.pub",
      "linux_password_credential": "linux-lab",
      "allow_ssh_password_auth": true,
      "memory_mb": 4096,
      "cpu_count": 2,
      "disk_size_gb": 64,
      "register_with_lablink": true,
      "lablink_role": "vm"
    }
  }
}
```

Downloads use resumable asynchronous BITS jobs. If a transfer is active,
`prepare_linux_image` returns `image_preparing` immediately with job identity
and progress instead of blocking for the full image download. State is stored
under the configured cache root and reused by later calls. An existing file is
reused only when the persisted state records the exact fixed URL and
destination as completed. Error/Cancelled jobs are removed and recreated, and
a digest mismatch quarantines only the exact owned file/blob so the next call
redownloads it.

Security is fail-closed: the MVP accepts no arbitrary image URL. It downloads
the stable amd64 Azure VHD archive from
`https://cloud-images.ubuntu.com/releases/noble/release`, pulls
`SHA256SUMS`/`SHA256SUMS.gpg` back to the LabLink server over the authenticated
agent channel, verifies the detached signature using an embedded Canonical key
whose fingerprint is pinned to
`D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`, then checks the exact image hash
on the target. Prepared bases are content-addressed, hashed after the builder
transform, and published read-only.

The builder is created through the existing Windows VM orchestrator and
enrolled separately with role `linux-image-builder`. Nested virtualization is
configured before first start. Only the builder enables WSL features, reboots,
detects and rejects the in-box-only `wsl.exe` stub, downloads the fixed WSL
3.0.3 x64 MSI with resumable BITS, verifies its exact SHA-256 and Microsoft
Authenticode signer, and then installs Ubuntu 24.04 with
`--web-download --no-launch`. WSL setup/resume and transformation run as the
builder profile's saved normal administrator through a random, ephemeral,
highest-run-level Scheduled Task because WSL rejects LocalSystem and keeps
distribution registration per-user. The password travels only in the agent
request environment, is cleared immediately after task registration, is
redacted from transport failures/output, and never enters scripts, command
lines, task names, paths, state, plans, or audit. Exact task/job cleanup is
fail-closed. MSI execution uses bounded verbose logs and one retry only when
an unexpected exit leaves WSL absent. The pinned MSI is
`https://github.com/microsoft/WSL/releases/download/3.0.3/wsl.3.0.3.0.x64.msi`
with SHA-256
`ae977286974255bd26bf925f00f40f5692c6b2084155cbc0563c09aea091f211`.
Only after Ubuntu is verified as the default WSL2 distribution does it
inventory disks and mount the exact operation-owned staging disk, snapshots
WSL block devices before the mount, identifies exactly one newly added WSL
disk, and inspects only partitions whose `PKNAME` names that disk. The WSL
distro root is never scanned or remounted. A builder-identity lock spans all
cache/disk-size variants using the same builder while unrelated builders remain
parallel. It is retained stopped by default for reuse;
`delete_builder_after_prepare:true` deletes only the owned VM/child/identity,
never its shared Windows parent or profile assets.
Builder start additionally retries once only for the current VM/start's exact
Hyper-V Worker Admin 18590 pre-OS fatal signature (`ErrorCode0=0x10`);
ordinary 15-minute DHCP failures are not retried.
After data-disk attachment, cleanup retains the exact disk unless a completed,
verified transform returns explicit `safe_to_detach:true` after WSL unmount.
Transport, agent, JSON, transform, and cleanup failures stop the builder when
reachable and retain or restore that exact attachment for diagnosis. See
[docs/linux-vm.md](docs/linux-vm.md).

`create_linux_vm` uses a per-VM ISO9660/Joliet ISO labeled `CIDATA` with
root-level `meta-data`, `user-data`, optional `network-config`, and separate
LabLink payload files. The generic Ubuntu image consumes the standard NoCloud
seed directly. The VM uses its normal Hyper-V firmware identity.

At least one SSH key or saved `linux_password_credential` is required. Saved
passwords are converted in memory to salted SHA-512 crypt hashes; plaintext is
never written to seed data, profiles, metadata, audit, or output.
Direct root login remains disabled. The ISO carries the version-matched agent,
CA, guest certificate/key, token, and idempotent installer as separate files.
The root agent service keeps `NoNewPrivileges` and `PrivateTmp`, but deliberately
does not apply a read-only-system or finite writable-path sandbox because
remote administrative operations must be able to write requested locations
such as `/etc`, `/usr`, and `/opt`.
It is detached and deleted only after the expected guest mTLS identity is
verified. Its ownership is atomically persisted before creation, and both the
staging directory and ISO use verified, inheritance-disabled Windows ACLs
limited to SYSTEM, Administrators, and the exact Hyper-V VM identity required
for attachment. Same-name retries reconcile only those persisted exact paths;
they never glob-delete outside the managed VM directory.
After ISO creation, exact stage removal and absence are verified before
`New-VM`; cleanup failure retains ownership and stage identity for resume
reconciliation rather than continuing with secret files on disk.

Linux creation waits up to 15 minutes for DHCP IPv4 through Hyper-V KVP and up
to 10 additional minutes for the mTLS agent. MCP progress heartbeats identify
the current phase and wait status; permanent TLS certificate-name errors fail
immediately. Windows registration retains its existing five-minute default.

Retries inspect persisted VM metadata before consulting the current image
cache. Existing managed guests then acquire the per-VM lock and resume with their
persisted parent/ISO identity even if the cache was removed or the stable image
selection changed. Resume also does not resolve retired SSH key files or saved
password credentials; those inputs are required only after inspection proves
a new VM/seed is needed. The cache is required only for a new VM. An Off partial VM
receives idempotent remaining configuration. A Running VM in
`cidata_attached` must already have the exact persisted child/parent disk and
CIDATA attachment; after validation it continues address discovery, enrollment,
and success cleanup without being stopped. `cidata_detached` and `complete`
resumes also validate the exact Hyper-V child path and `Get-VHD` parent path
before boot/mTLS, without reconfiguring CIDATA. On a new-VM cache miss, builder
profile/target/credential and non-mutating builder source preconditions are
validated before the lifecycle lock or artifact reconciliation. Unsafe
mismatches are rejected. Post-boot failures retain the managed VM and ISO for
diagnosis. See
[docs/linux-vm.md](docs/linux-vm.md) and
[`configs/vm-defaults.example.json`](configs/vm-defaults.example.json).

### Files and packaging
| Tool | What it does |
|------|--------------|
| `push_file` / `pull_file` | Transfer files in either direction. |
| `copy_between_nodes` | Copy directly between two nodes (no operator-side staging). |
| `tail_file` | Read the last N lines of a remote file. |
| `install_package` | Push a directory or zip to a node and extract it on the other side. |

### Diagnostics and debugging
| Tool | What it does |
|------|--------------|
| `get_node_info` | Live system info: OS build, hostname, uptime, NICs, installed driver state. |
| `wait_for_node` | Poll until a node's agent responds (e.g., after a reboot). |
| `ping_nodes` | Quick online/offline sweep across all registered nodes. |
| `sync_time` | Force `w32tm /resync` across all nodes or a topology. |
| `collect_etw_trace` | Start WPR on a node, wait, stop, and pull the `.etl` back. |
| `get_crash_dumps` | List and optionally pull crash dumps from `Minidump` and `MEMORY.DMP`. |
| `enable_kd` / `disable_kd` / `get_kd_status` | Configure network kernel debugging on a remote VM. |
| `get_history` | Query the local audit log of past commands. |
| `get_portal_url` | Return the bookmarkable URL of the local operations portal (loopback + per-process key). |

### Patching and lifecycle
| Tool | What it does |
|------|--------------|
| `patch_binary` | Replace a protected Windows system binary using a Windows engineering replace-utility you supply (path passed via `SFPCOPY_SOURCE`). Backs up the original first. |
| `restore_binary` | Roll back a previously patched binary. |
| `ensure_test_signing` | Enable `bcdedit /set testsigning on` and report whether a reboot is needed. |
| `reboot_node` | Reboot a single node and wait until the agent is first observed offline, then back online. For 2+ nodes use `reboot_nodes` instead — calling `reboot_node` in a loop blocks for the full `wait_seconds` per node. |
| `reboot_nodes` | Reboot a list of nodes in parallel and wait once for everyone to be observed offline, then back online. Wall-clock scales with the slowest single reboot, not the node count. |

### Onboarding (operator-side)
| Tool | What it does |
|------|--------------|
| `deploy_agent` | Deploy the agent to a new Windows node via PS Remoting. |
| `save_credential` / `list_credentials` | Manage named WinRM credential profiles for `deploy_agent`. |

For day-to-day onboarding, the bootstrap scripts are recommended over `deploy_agent` because they don't require persisting WinRM credentials on the operator machine.

## Leasing and mutating tools

LabLink includes lease tools (`lease`, `extend_lease`, `release_lease`,
`wait_for_release`) for coordinating shared lab nodes. Lease enforcement for
mutating tools is **disabled by default**: commands such as `execute_command`,
`push_file`, `reboot_node`, and `patch_binary` run without first requiring an
active lease.

To re-enable one-terminal-at-a-time protection, set `LABLINK_LEASE_REQUIRED=1`
on `lablink-server.exe` before startup. The accepted opt-in values are `1`,
`true`, `yes`, `on`, and `enabled` (case-insensitive, surrounding whitespace
ignored). Any other value, including an unset or empty variable, leaves
enforcement disabled.

With enforcement enabled, a caller must hold an active lease for every touched
node before a mutating tool runs. The safety tradeoff of the new default is that
LabLink will not automatically prevent concurrent terminals from operating on
the same node unless this setting is enabled.

## Security model at a glance

- **Transport:** mTLS by default. The agent only accepts client certificates signed by your local LabLink CA.
- **Auth:** every gRPC call carries a shared bearer token. Empty token = request denied (fail-closed).
- **Secrets at rest:** the token file and private keys are written with restricted ACLs (your user + Administrators + SYSTEM).
- **Insecure mode:** plaintext gRPC still exists for migration testing but is disabled unless you explicitly set both `LABLINK_TRANSPORT=insecure` and `LABLINK_ALLOW_INSECURE=true`. Don't use it for anything other than a private bench.

See [SECURITY.md](SECURITY.md) for the full posture and threat model.

## Going further

To update LabLink binaries on the operator machine or on a lab node, run:

```powershell
.\scripts\Update-LabLink.ps1
```

The script resolves the current install directory from your MCP config (or the per-user default), downloads the latest release zip, verifies the SHA256, stops any running `lablink-*` processes (prompting unless `-Force`), swaps the binaries atomically with rollback on failure, and confirms the new version. On lab nodes where the agent runs as a Windows service, the service is stopped before the swap and restarted after. The absence of the service is auto-detected; `-SkipServiceStop` is an optional flag for operator workstations where the service is known not to exist. `Update-LabLink.ps1` ships in both the release zip (`scripts\Update-LabLink.ps1`) and at `C:\LabLink\Update-LabLink.ps1` on every agent install.

- [Fleet update pattern](docs/fleet-update.md) — composing `execute_script` + `wait_for_node` to update every node from the operator workstation.
- [`docs/quickstart.md`](docs/quickstart.md) — manual mTLS setup without the bootstrap scripts.
- [`docs/Project.md`](docs/Project.md) — architecture and design notes.
- [`docs/mtls-self-managed-cert-plan.md`](docs/mtls-self-managed-cert-plan.md) — PKI design and rationale.
- [File transfers](docs/file-transfers.md) — throughput envelope and timeout tuning for push_file / pull_file.
- All long-running MCP tools (`reboot_nodes`, `reboot_node`, `wait_for_node`, `wait_for_release`, `execute_command`, `execute_script`, `execute_on_role`, `run_script_on_role`, `collect_etw_trace`) emit `notifications/progress` every ~5 s when the client supplies `_meta.progressToken`, preventing MCP transport idle timeouts on slow operations.

`lablink-ca.exe` exposes the underlying CA primitives if you'd rather drive PKI by hand:

```powershell
.\bin\lablink-ca.exe init           -pki-dir C:\lablink-pki
.\bin\lablink-ca.exe issue-client   -pki-dir C:\lablink-pki -name operator
.\bin\lablink-ca.exe sign-server-csr -pki-dir C:\lablink-pki -csr <path>
```

## Running multiple LabLink instances

Everything `lablink-server.exe` reads or writes — `nodes.json`, `history.jsonl`, `credentials.json`, `cache/`, `pki/` — lives under a single config directory. By default that's `~/.lablink`, but you can point any installation at a different one with `LABLINK_HOME`. This lets one operator machine run several isolated LabLink "worlds" side by side: separate PKI roots, separate node inventories, separate audit logs, separate AI-client sessions.

Two common reasons to do this:

- **Isolating environments.** Keep `prod` and `lab` nodes in different homes so a bad command in one can't reach the other.
- **Per-session scratch.** Spin up a throwaway home for an experiment without touching your main inventory.

The bootstrap scripts already accept a `-HomeDir` parameter — pass the same alternate path everywhere:

```powershell
# 1. Initialise the alternate operator home (creates PKI + the operator client cert).
.\bootstrap-operator.ps1 -HomeDir C:\Users\nijos\.lablink-prod

# 2. Onboard a node into THAT home (its TLS material is signed by that home's CA
#    and its entry lands in C:\Users\nijos\.lablink-prod\nodes.json).
.\bootstrap-windows-node.ps1 `
    -HomeDir C:\Users\nijos\.lablink-prod `
    -Machine 10.0.0.10 -Node prod-server-01 -Role server

# 3. Manual install package, same idea — the package the operator hands to the
#    remote installer is also tied to that home's CA.
.\bootstrap-windows-node.ps1 -Manual `
    -HomeDir C:\Users\nijos\.lablink-prod `
    -Machine 10.0.0.11 -Node prod-server-02 -Role server
```

Then add a matching MCP server entry that points `LABLINK_HOME` at the same directory:

```jsonc
"lablink-prod": {
  "command": "C:\\Users\\nijos\\MCP\\lablink\\bin\\lablink-server.exe",
  "env": {
    "LABLINK_HOME":            "C:\\Users\\nijos\\.lablink-prod",
    "LABLINK_TRANSPORT":       "mtls",
    "LABLINK_TLS_CA":          "C:\\Users\\nijos\\.lablink-prod\\pki\\ca-bundle\\ca.crt",
    "LABLINK_TLS_CERT":        "C:\\Users\\nijos\\.lablink-prod\\pki\\clients\\default\\client.crt",
    "LABLINK_TLS_KEY":         "C:\\Users\\nijos\\.lablink-prod\\pki\\clients\\default\\client.key",
    "LABLINK_AGENT_TOKEN_FILE":"C:\\Users\\nijos\\.lablink-prod\\agent.token"
  }
}
```

You can register as many `lablink-*` entries as you want; each gets its own portal, its own audit log, and its own slice of the agent fleet.

**Sharing one home across processes.** If two AI clients both use the *same* `LABLINK_HOME` (the default setup), that's fine too — `nodes.json` and `history.jsonl` are protected by an OS-level advisory lock and atomic rename, so concurrent `register_node` / context updates / audit writes from sibling `lablink-server.exe` instances stay consistent.

## Configuration reference

| Variable | Purpose |
|----------|---------|
| `LABLINK_AGENT_TOKEN` | Shared token value (use the file form in production). |
| `LABLINK_AGENT_TOKEN_FILE` | Path to a file containing the shared token. |
| `LABLINK_TRANSPORT` | `mtls` (default) or `insecure`. |
| `LABLINK_TLS_CA` | CA bundle PEM (verifies the peer). |
| `LABLINK_TLS_CERT` | Client cert PEM (server/probe) or server cert PEM (agent). |
| `LABLINK_TLS_KEY` | Matching private key for `LABLINK_TLS_CERT`. |
| `LABLINK_TLS_SERVER_NAME` | Optional override for TLS SNI / server-name verification. |
| `LABLINK_NODES` | Path to the node registry JSON file. |
| `LABLINK_HOME` | Base config directory (default `~/.lablink`). |
| `LABLINK_LEASE_REQUIRED` | Opt in to mutating-tool lease enforcement with `1`, `true`, `yes`, `on`, or `enabled`; unset/empty/anything else leaves enforcement disabled (default). |
| `LABLINK_PORTAL` | `disabled` to suppress the local web portal. |
| `LABLINK_PORTAL_ADDR` | Override the portal bind address (loopback only, e.g. `127.0.0.1:9092`). |

## Build from source

If you don't want to use the published release zips:

```powershell
git clone https://github.com/nijosmsft/LabLink
cd LabLink
make build-all
```

This produces the same four binaries under `.\bin\`. From that point on, every step in [Get started](#get-started-in-5-minutes) works exactly the same way.

See [RELEASING.md](RELEASING.md) for how to build a release zip locally.

## License

[MIT](LICENSE).
