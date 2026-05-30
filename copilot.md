# Copilot guide for LabLink

This file is the project-specific brief for AI coding agents (Copilot CLI, Claude,
Cursor, etc.) working in this repository. Keep it short and current — when you
change something foundational (layout, build commands, security posture, MCP-tool
registration pattern), update this file in the same change.

For end-user docs, start at `README.md`, then `docs/Project.md` (architecture),
`docs/quickstart.md` (manual mTLS bring-up) and `SECURITY.md` (posture and
threat model).

## TL;DR

LabLink = local MCP server (`cmd/server`) + remote gRPC node agent (`cmd/agent`)
that lets AI clients drive a fleet of Windows (and Linux) lab machines over
mTLS-authenticated gRPC with a shared bearer token.

```
AI client ──MCP/stdio──▶ LabLinkServer ──mTLS+token, gRPC──▶ LabLinkAgent
                              │
                              ├── internal/registry  (nodes.json, topology)
                              ├── internal/audit     (history.jsonl)
                              ├── internal/ops       (in-flight tool tracking)
                              └── internal/portal    (loopback web UI for ops/jobs)
```

Everything stateful lives under `LABLINK_HOME` (default `~/.lablink`).

## Repo layout

| Path | What lives here |
|------|-----------------|
| `cmd/server/`        | MCP server entrypoint (`LabLinkServer.exe`). Wires registry, auth, transport, audit, portal, and every `mcptools.Register*` call. |
| `cmd/agent/`         | gRPC node agent (`LabLinkAgent.exe`). Executor, file transfer, jobs, processes, Windows service plumbing. |
| `cmd/probe/`         | `LabLinkProbe.exe` — CLI smoke test against a single node. |
| `cmd/lablink-ca/`    | Local CA used by the bootstrap scripts. |
| `cmd/pulltest/`      | Internal harness, not shipped. |
| `proto/agent/`       | gRPC contract (`agent.proto`) + generated `*.pb.go` / `*_grpc.pb.go`. Single source of truth for the wire protocol. |
| `internal/agentclient/` | Cached gRPC client pool the server uses to talk to agents. |
| `internal/mcptools/` | One file per tool family (`execute.go`, `transfer.go`, `topology.go`, …). All MCP tools are defined and registered here. |
| `internal/registry/` | Persistent node + topology + per-node context store (`nodes.json`). |
| `internal/audit/`    | Append-only command history (`history.jsonl`). |
| `internal/credentials/` | Encrypted WinRM credential profiles for `deploy_agent`. |
| `internal/ops/`      | Process-local tracking of long-running tool invocations (feeds the portal). |
| `internal/portal/`   | Loopback-only HTTP/SSE UI for operations + jobs. Keyed per-process. |
| `internal/healthmon/` | Background keepalive that marks nodes online/offline and cancels in-flight RPCs to dead nodes. |
| `internal/security/` | Token resolution, mTLS transport plumbing, insecure-mode opt-in, env aliases. |
| `internal/pki/`      | Primitives behind `lablink-ca.exe`. |
| `internal/flock/`    | Cross-process advisory locks used by the registry/audit log. |
| `scripts/`           | PowerShell bootstrap + manual-package + release-builder scripts. |
| `configs/`           | Example `.mcp.json` and `nodes.json`. |
| `docs/`              | Project, quickstart, and mTLS design docs. |
| `release/`           | Output of `scripts/build-release.ps1`. Gitignored. |
| `bin/`               | Output of `make build`. Gitignored. |

## Build, test, lint

Go 1.25.6 (pinned via `go.mod`). No external runtimes required.

```powershell
make build           # build server, Windows agent, ca, probe into .\bin
make build-all       # also builds the Linux agent
make tidy            # go mod tidy
make proto           # regenerate proto/agent/*.pb.go from agent.proto (needs protoc + plugins)
make clean           # rm -rf .\bin
```

What CI runs (`.github/workflows/ci.yml`, on `ubuntu-latest` and `windows-latest`):

```bash
gofmt -l .           # must be empty (Ubuntu job only)
go vet ./...
go build ./...
go test ./... -timeout 5m
```

Reproduce locally before pushing. New code must be `gofmt`-clean and `go vet`-clean.

Releases are built by `.github/workflows/release.yml` on tag push (`v*.*.*`),
which runs `scripts/build-release.ps1 -Version <tag>` on `windows-latest` and
uploads the resulting `lablink-<ver>-{windows,linux}-amd64.zip` + `SHA256SUMS.txt`.

## Conventions

### Go style

- Standard `gofmt`. Tabs in source, no goimports reordering surprises.
- Module path: `github.com/nijosmsft/lablink`. Use that prefix in imports.
- Import the generated proto as `pb "github.com/nijosmsft/lablink/proto/agent"`.
- Errors are wrapped with `fmt.Errorf("...: %w", err)` — keep that pattern.
- Long-lived state types (registries, pools, monitors) carry their own
  `sync.Mutex`; copy that pattern rather than reaching for `sync.Map`.
- Tests live next to the code (`*_test.go`). Cross-platform tests exist for
  shutdown-error matching and registry concurrency — keep them green on both
  GOOSes.

### Cross-platform files

Windows is the primary target; Linux agent is supported. Split OS-specific code
with build-tag filename suffixes already used in this repo:

- `_windows.go` / `_other.go` (see `cmd/server/shutdown_errors_*.go`)
- `_windows.go` / `_unix.go` (see `cmd/agent/executor_*.go`, `cmd/agent/jobs_*.go`)

Do not put `//go:build windows` inside a file without the matching `_windows.go`
suffix — keep the discoverability consistent with the rest of the tree.

### Naming / branding

The project was renamed from **device-interaction** to **LabLink**. New code
should use the LabLink names (`LABLINK_*` env vars, `~/.lablink`, `lablink`
import path). The legacy `DEVICE_*` / `DEVICE_INTERACTION_*` names are still
accepted for backwards compatibility via `security.FirstPresentEnv(...)` —
preserve those fallbacks when touching env-var lookups; don't add new legacy
aliases.

## Adding or changing an MCP tool

All tools live in `internal/mcptools` and are wired in
`cmd/server/main.go` via a `mcptools.RegisterX(s, ...)` call.

To add a new tool:

1. Put the handler in the file for its family (e.g. file ops → `transfer.go`,
   diagnostics → `diagnostics.go`). Create a new family file only if none fits.
2. Declare the tool with `mcp.NewTool("snake_case_name", mcp.WithDescription(...),
   mcp.WithString(...), …)` following the pattern in `execute.go`. Tool names
   are part of the public surface — choose carefully and don't rename without
   reason.
3. For per-node calls, get a client via `pool.GetClient(node.Address,
   node.TLSServerName)` and wrap the context with `nodeCallContext(ctx,
   node.Name)` so health-monitor cancellation works.
4. For long-running tools, bracket the work with the `ops` registry so it shows
   up in the portal and can be cancelled. Existing examples: `execute_command`,
   `push_file`, `pull_file`, `execute_script`.
5. Write to the audit log (`auditLog.Append(...)`) for anything that mutates
   remote state.
6. Add a `mcptools.RegisterYourTool(s, …)` call in `cmd/server/main.go` next to
   the other registrations. Also extend the `WithInstructions(...)` blurb if the
   tool is meant for AI-client discovery.
7. Add tests under `internal/mcptools/*_test.go`. Don't talk to real nodes —
   the existing tests stub `pb.NodeAgentClient`.

## Changing the gRPC contract

`proto/agent/agent.proto` is the contract between server and agent.

1. Edit `agent.proto`.
2. Run `make proto` (needs `protoc` + `protoc-gen-go` + `protoc-gen-go-grpc`).
3. Commit the regenerated `agent.pb.go` and `agent_grpc.pb.go` alongside
   the `.proto` change — CI does not regenerate them.
4. Update both `cmd/agent` (server side of the RPC) and the caller in
   `internal/mcptools` / `internal/agentclient` in the same change. The agent
   and server are versioned together; mismatched fleets will fail RPCs.

## Security must-knows

- mTLS is the default and the only supported public posture. Plaintext gRPC
  requires *both* `LABLINK_TRANSPORT=insecure` and `LABLINK_ALLOW_INSECURE=true`
  — don't loosen that gate.
- Auth tokens are required; empty token = request denied (fail-closed). Token
  resolution flows through `security.ResolveToken` — keep new entrypoints
  using it instead of reading env vars directly.
- **Never commit** anything under `~/.lablink/`, generated PKI material,
  `agent.token`, `nodes.json`, `history.jsonl`, `credentials.json`, or any
  `*.key` / `*.crt`. `.gitignore` already covers the common cases at the repo
  root — extend it if you add new state directories.
- Token files and private keys must be written with restricted ACLs
  (`security.WriteSecretFile` / the helpers in `internal/security`); do not
  `os.WriteFile` secrets directly.
- The portal binds **only to loopback** and requires a per-process access key.
  Do not add non-loopback listen paths.

## Running locally during development

Quickest dev loop on Windows:

```powershell
make build
.\scripts\bootstrap-operator.ps1                                          # one time, creates ~/.lablink + PKI
.\scripts\bootstrap-windows-node.ps1 -Machine <node> -Role server         # onboard a node
.\bin\LabLinkProbe.exe <node-ip>:9091                                     # sanity check
```

To debug the MCP server outside an AI client, run `.\bin\LabLinkServer.exe`
directly — it logs the portal URL on startup and speaks MCP over stdio
(you can pipe a hand-crafted JSON-RPC frame in if needed).

For multiple isolated environments on one operator machine, set `LABLINK_HOME`
to a different directory per instance; everything (PKI, registry, audit log,
portal) is scoped to that home.

## Things not to do

- Don't add new top-level packages outside the `cmd/` and `internal/` layout
  without a strong reason. Public reusable libraries are *not* a goal of this
  repo.
- Don't add new third-party dependencies casually — keep `go.mod` lean. Prefer
  stdlib + `gopsutil` + `mcp-go` + `grpc` + `protobuf` + `yaml.v3`.
- Don't change MCP tool names or argument shapes without coordinating — AI
  clients depend on them.
- Don't bypass the `agentclient.Pool`; create new gRPC connections through it
  so transport, auth, and pooling stay consistent.
- Don't write secrets to logs. The codebase has a `redact` helper in
  `internal/audit` — use it when surfacing args that may contain tokens, env
  values, or paths to key material.
