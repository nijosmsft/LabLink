# Changelog

All notable changes to LabLink are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1] - 2026-06-16

### Fixed
- `reboot_node` / `reboot_nodes` no longer report a node back online until
  it has actually gone offline and returned. The reboot wait now uses
  two-phase down->up verification; previously, a node that had not yet shut
  down could be falsely reported back immediately because its agent port was
  still reachable.
- Added `rebootNodesDownConfirmations` debounce so transient TCP dial blips
  do not count as an observed reboot/down transition.

## [0.5.0] - 2026-06-16

### Changed
- **Behavior change:** lease enforcement is now opt-in and disabled by default.
  Mutating tools no longer require an active lease unless
  `LABLINK_LEASE_REQUIRED` is set to `1`, `true`, `yes`, `on`, or `enabled`.
  This differs from <=0.4.x, where enforcement was on by default. The tradeoff
  is that LabLink no longer provides automatic one-terminal-at-a-time protection
  unless operators explicitly enable it.

## [0.4.5] - 2026-06-15

### Changed
- Lease-conflict error messages now show a one-line, human-readable breakdown
  of who holds a contested node. When the holder is your own lablink-server
  from another terminal (same cookie + same hostname), the message says so
  explicitly. When the holder is a different user on the same host, or a
  process on a different host entirely, that is also called out. The raw
  agent_id is preserved on a follow-up line (`raw: agent_id=... lease_id=...`)
  for `lease()`-path errors, and embedded in the table cell for
  `LeaseGate`-path errors, so scripts that grep the old text still work.
  No behavior change -- pure error-text upgrade.
- Adds `leasing.DescribeAgentID` / `leasing.AgentDescription` helper that
  decodes the default `<cookie>-<hostname>-<pid>-<suffix>` agent_id shape
  relative to the calling process's own identity, returning `SameHost` /
  `SameUser` booleans. Falls back to `Decoded=false` for any agent_id that
  does not match the shape (e.g., a custom `LABLINK_AGENT_ID` override), so
  the old raw-id display is never broken.

## [0.4.4] - 2026-06-12

### Performance
- Trimmed MCP tool descriptions and per-arg descriptions across all 19 files in `internal/mcptools/`. The Copilot CLI's per-session token cost for the LabLink `tools/list` payload drops by approximately 1500 tokens (from ~7700 to ~6200). No tool was renamed, no arg was renamed, no arg was removed, no handler behavior changed -- pure metadata edits. Per-file char savings range from -23% (execute.go) to -61% (patch.go); total 12694 -> 7055 chars (-44%).

### Acknowledgments
- Thank you to the network-design-reviewer agent for spotting that the trim had dropped two load-bearing semantic hints (enable_kd port uniqueness, get_job_output 8 MiB cap) that were restored before merge.

## [0.4.3] - 2026-06-12

### Added
- `Update-LabLink.ps1 -Detach`: registers a Windows one-shot scheduled task as SYSTEM running 30 seconds in the future via `schtasks.exe`, then exits 0. Use this when invoking the updater via `lablink execute_script` on a lab node -- without it, the agent's executor (per `cmd/lablink-agent/executor.go:195-196`) kills the child PowerShell when the agent's context is cancelled on `Stop-Service`, leaving the swap incomplete. With `-Detach`, the operator's `execute_script` call returns cleanly and the scheduled task runs detached from the agent's process tree.
- 2 new test cases in `scripts/tests/Update-LabLink.Tests.ps1` covering the `-Detach` branch (schtasks arg coverage; forwarded args coverage including `-Detach` exclusion).

### Notes
- On operator workstations where `lablink-server.exe` is not a Windows service, `-Detach` is NOT needed -- the standard `Update-LabLink.ps1` invocation works as before.
- Companion docs PR is open at #15 (docs/fleet-update.md) and will land alongside v0.4.3.

## [0.4.2] - 2026-06-12

### Added
- `scripts/Update-LabLink.ps1` now ships in the release zip (`scripts/` directory). Operators no longer need to git-clone the repo to update -- unzip the release and run the script.
- `Update-LabLink.ps1` is also deployed to lab nodes during agent install (via `deploy-agent.ps1` and `build-manual-package.ps1`). Operators with access to a node can update the agent in-place by invoking the script there.
- 6-case standalone PowerShell test suite at `scripts/tests/Update-LabLink.Tests.ps1` covers the destination-resolution branches (co-located, sibling-bin, service-ImagePath quoted + unquoted, default fallback, and CIM service-name filter assertion).

### Changed
- `Update-LabLink.ps1` now stops the `LabLink Agent` Windows service before swapping binaries on lab nodes, restarts it after, with a try/finally guarantee that the service is never left stopped. The previous version used `Stop-Process` only, which raced with SCM auto-restart on lab nodes.
- Binary swap split into Install / Commit / Rollback phases: `.old` backups are now only deleted after `Start-Service` and `lablink-server.exe --version` both succeed, so a service-start failure can roll back to the previous binaries. Per-file `HadPrior` tracking ensures rollback also removes any binary that did not exist in the prior install (e.g., new binary added in a target version).
- `Update-LabLink.ps1` Resolve-DestinationDir now tries (in order): explicit `-DestinationDir`, script-co-located install dir, sibling `bin/`, the `LabLink Agent` service's ImagePath, the lablink entry in `~/.copilot/mcp-config.json`, and finally `%LOCALAPPDATA%\lablink\bin\`. This fixes a regression where running the script on a lab node defaulted to `%LOCALAPPDATA%\lablink\bin\` instead of the actual `C:\LabLink` install location.
- `-SkipServiceStop` flag added for operator workstations where the service is known not to exist. (Optional -- the script auto-detects an absent service and treats it as a no-op.)

### Acknowledgments
- Thank you to the network-design-reviewer agent for catching multiple load-bearing issues across two review rounds (wrong default destination on nodes, deferred-commit on Start-Service failure, try/finally service restart, service-name match, ImagePath unquoted parsing, rollback completeness).

## [0.4.1] - 2026-06-11

### Added
- MCP progress notifications (`notifications/progress`) on every long-running tool when the client supplies `_meta.progressToken`. Prevents Copilot CLI's MCP transport from firing `-32001 Request timed out` on tool calls that exceed its ~60s idle timeout. Tools covered: `push_file`, `pull_file`, `reboot_node`, `reboot_nodes`, `wait_for_node`, `wait_for_release`, `execute_command`, `execute_script`, `execute_on_role`, `run_script_on_role`, `collect_etw_trace` (both capture and pull stages). Per-tool progress denominators are sensible (bytes for file ops, node-counts for multi-node ops, elapsed-vs-timeout for time-bound ops).
- `timeout_seconds` MCP argument on `push_file` and `pull_file` (default 600). Negative values are rejected at the handler level. `0` disables the LabLink-side deadline. (#11)
- `docs/file-transfers.md` operations guide: throughput envelope, `timeout_seconds` tuning per file size and link speed, workaround for very-large transfers (split + push/pull chunks + reassemble + hash-verify), and a forward-looking note about resumable chunked transfer (in design). (#12)
- Reusable `StartMCPHeartbeat` + `ProgressTokenFromRequest` helpers in `internal/mcptools/heartbeat.go`, designed so future long-running tools can wire MCP progress notifications in one line. (#13)

### Fixed
- `execute_command` / `execute_script` no longer leak the heartbeat ticker goroutine on early errors. (#13 fix-up)
- `collect_etw_trace` Stage 2 (ETL pull) now heartbeats; previously it used the no-notifier `pullRemoteFileToPath` and large ETL transfers could still time out the MCP transport. (#13 fix-up)

### Internal
- `internal/ops/registry.go`: `Handle.Progress(int64, int64)` + `Operation.BytesDone/BytesTotal/ProgressAt` + new `"progress"` event kind. Portal SSE consumers see the progress stream unchanged. (#11)

### Acknowledgments
- Thank you to the network-design-reviewer agent for surfacing the load-bearing flaw in the original heartbeat implementation (initially only fed the local portal, not the MCP transport) and several smaller corrections in the docs and the broader retrofit.

## [0.3.0] - 2026-06-04

### Changed (breaking)
- Renamed `cmd/server`, `cmd/agent`, `cmd/probe`, and `cmd/pulltest` packages
  to a `lablink-*` prefix.
- Shipped binaries are now kebab-case: `lablink-server.exe`,
  `lablink-agent.exe`, `lablink-probe.exe`, `lablink-ca.exe` (previously
  `LabLinkServer.exe`, `LabLinkAgent.exe`, `LabLinkProbe.exe`,
  `LabLinkCA.exe`).
- Dropped the `LabLinkAgent.exe` back-compat lookup. Existing installs must
  reinstall the agent service so it points at `lablink-agent.exe`.

### Added
- `--version` flag on every shipped binary; prints `<name> vX.Y.Z`.
- `scripts/Update-LabLink.ps1` for one-command upgrades — downloads the
  latest release zip, verifies the checksum, and replaces the local install.

## [0.2.0] - 2026-06-04

### Added
- `reboot_nodes` bulk MCP tool. Kicks every node in parallel and waits ONCE
  for the fleet to recover, so total wall-clock time is bounded by the
  slowest single reboot rather than scaling with the node count. Use this
  for any multi-node reboot — calling `reboot_node` in a loop blocks for
  the full `wait_seconds` per node.
- Background jobs: `execute_command` / `schedule_command` with
  `detach:true` are tracked as jobs with stable `job_id`, captured
  stdout/stderr, exit code, and lifecycle status. New MCP tools:
  `list_jobs`, `get_job_status`, `get_job_output`, `cancel_job`,
  `delete_job`. The local operations portal grew a Jobs tab.
- TCP forwarding: `forward_port`, `list_forwards`, `stop_forward` open a
  local listener that tunnels bytes to a target address on a remote node
  via the existing mTLS channel.
- `get_portal_url` MCP tool returns the bookmarkable loopback URL of the
  local operations portal (per-process access key included).
- `scripts/build-manual-package.ps1` and `bootstrap-windows-node.ps1
  -Manual` build a hand-carry install package for nodes where WinRM is
  disabled or blocked.

### Changed
- `pkg/agentclient`, `pkg/registry`, and `pkg/security` are now public
  packages and can be imported by external Go consumers.
- README clarifies portal URL discovery and that WinRM is optional.

## [0.1.4] - 2026-04-22

Initial public release of LabLink: an MCP server plus a lightweight node
agent that gives an MCP-aware AI client secure remote-hands on a fleet of
Windows lab machines over mutually-authenticated TLS with a shared
bearer token.

## Backwards compatibility

- Long-form environment variable aliases (`LABLINK_TLS_CA_CERT`,
  `LABLINK_TLS_CLIENT_CERT`, ...) and the legacy `DEVICE_*` names are
  still accepted by `lablink-server.exe`, `lablink-agent.exe`, and
  `lablink-probe.exe`. Prefer the short `LABLINK_TLS_CA` /
  `LABLINK_TLS_CERT` / `LABLINK_TLS_KEY` names documented in the
  README — the aliases exist only so older `mcp.json` snippets keep
  working across upgrades.
