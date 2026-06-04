# Changelog

All notable changes to LabLink are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
