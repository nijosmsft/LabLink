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
Expand-Archive lablink.zip -DestinationPath C:\LabLink
cd C:\LabLink
```

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
| `list_nodes` | List registered nodes with status and metadata. |
| `remove_node` | Remove a node from the registry. |
| `rename_node` | Rename a node, preserving context and topology references. |
| `register_topology` | Define a named group of nodes with role assignments (e.g. `server`, `client`). |
| `set_node_context` | Persist a default working directory and environment for a node. |
| `import_nodes` / `export_nodes` | Round-trip the registry to a YAML file. |

### Execution
| Tool | What it does |
|------|--------------|
| `execute_command` | Run a shell command on a node. Set `detach:true` to fire-and-forget — returns a `job_id` you can tail/cancel later. |
| `execute_script` | Push an inline script and execute it atomically. |
| `execute_on_role` | Run the same command on every node with a given role, in parallel. |
| `run_script_on_role` | Run the same inline script on every node with a given role, in parallel. |
| `schedule_command` | Run a command after a delay (useful for synchronized starts). Returns a `job_id`. |
| `list_processes` / `kill_process` | Inspect or terminate remote processes. |
| `list_jobs` / `get_job_status` / `get_job_output` | Inspect background (detached) jobs on a node. |
| `cancel_job` / `delete_job` | Cancel a running job or delete a terminal job's captured output. |

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
| `reboot_node` | Reboot a single node and wait for the agent to come back. For 2+ nodes use `reboot_nodes` instead — calling `reboot_node` in a loop blocks for the full `wait_seconds` per node. |
| `reboot_nodes` | Reboot a list of nodes in parallel and wait once for everyone to come back. Wall-clock scales with the slowest single reboot, not the node count. |

### Onboarding (operator-side)
| Tool | What it does |
|------|--------------|
| `deploy_agent` | Deploy the agent to a new Windows node via PS Remoting. |
| `save_credential` / `list_credentials` | Manage named WinRM credential profiles for `deploy_agent`. |

For day-to-day onboarding, the bootstrap scripts are recommended over `deploy_agent` because they don't require persisting WinRM credentials on the operator machine.

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
