# Changelog

All notable changes to LabLink are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Backward-compatible `profile_usage` classification for VM profiles.
  `ordinary` remains the default; `linux_image_builder` profiles are accepted
  only by internal Linux image preparation and are rejected by public
  `create_windows_vm` resolution before host mutation. Existing Windows
  profiles referenced by a Linux `image_builder_profile` are inferred as
  builder-only even when the new field is omitted.
- `cleanup_on_failure` for `create_windows_vm`, defaulting to false. Create or
  post-create configuration failures now return exact-name partial VM
  diagnostics and retain the provisioned child VHD by default. Explicit
  cleanup uses per-request ownership markers and fails closed on any identity
  or path mismatch.
- Non-blocking server/agent version-skew reporting. Authenticated probes warn
  once per node/version tuple, keep nodes online, and expose the observed agent
  version and upgrade recommendation through `list_nodes`.

## [0.7.0-beta.1] - 2026-10-14

### Added

- Backward-compatible Linux VM profile fields with independent
  `default_linux_profile` and `linux_target_defaults` selection. Empty
  `guest_os` remains Windows and existing Windows defaults are unchanged.
- Fixed-source Canonical Ubuntu 24.04 amd64 Azure VHD archive metadata, exact
  SHA256SUMS verification, content-addressed cache paths, resumable preparation
  state, and pinned OpenPGP verification of Canonical's documented cloud-image
  key.
- Dedicated reusable Windows image-builder VM support. Builders use the
  existing Windows profile/orchestrator and mTLS enrollment, expose nested
  virtualization and explicitly opt out of virtualization-based security
  while Off before first start, carry role `linux-image-builder`, install
  WSL2/Ubuntu only inside the guest, and are retained stopped by default or
  optionally deleted after successful preparation. Builder profiles must also
  use static memory.
- Service-safe builder bootstrap for the pinned Microsoft WSL 3.0.3 x64 MSI.
  It distinguishes the in-box `wsl.exe` stub from a real runtime, downloads
  through resumable BITS, verifies the exact SHA-256 plus Microsoft
  Authenticode signer, installs with quiet/no-restart MSI flags, resumes
  feature/MSI/distro reboots, quarantines invalid files, and verifies Ubuntu
  24.04 is the default WSL2 distribution without an elevation or UI path.
- Builder WSL setup, every reboot resume, and image transformation now execute
  as the builder profile's saved normal administrator through a random
  ephemeral password-logon/highest-run-level Scheduled Task. Credential
  values travel only in the agent request environment, are redacted and
  cleared immediately after registration, and exact task/job cleanup is
  fail-closed.
- Builder user resolution now treats the saved username as preferred rather
  than authoritative. When Windows unattend applied the password to the
  built-in Administrator instead, LabLink accepts only one enabled,
  Administrators-member local RID-500 account, persists its exact name/SID,
  and requires that SID on every setup resume and transform.
- Backward-compatible `virtualization_based_security_opt_out` support for
  Windows profiles, `create_vm`, `create_windows_vm`, and `save_vm_template`.
  The default remains false; requested opt-out is applied immediately after
  `New-VM`, verified with `Get-VMSecurity`, and surfaced in dry-run and result
  JSON.
- Safe host extraction and in-box `Convert-VHD` conversion of the authenticated
  Azure VHD, followed by exact operation-owned SCSI attachment, pre-attach disk
  inventory, WSL ext4 root discovery by content, atomic NoCloud datasource
  configuration, detach, hash, and read-only publication.
- A builder-identity lock shared by every cache key and disk-size variant using
  the same target/builder VM. It covers builder setup through detach and
  optional deletion, uses exact owner-token release and atomic stale recovery,
  and leaves unrelated builders parallel.
- `prepare_linux_image`, `get_linux_image_status`, and `create_linux_vm`.
  Active BITS transfers return immediately with resumable job progress; an
  empty cache returns `image_preparing` without creating a VM.
- Standard NoCloud seed generation on an ISO9660/Joliet `CIDATA` ISO with
  root-level `meta-data`, `user-data`, optional `network-config`, and separate
  LabLink payloads; plus idempotent Linux agent/systemd/SSH/KVP installation,
  Gen2 Linux secure boot, VHD-first boot ordering, DHCP/KVP discovery, mTLS
  verification, registration, and success-only ISO cleanup.
- Linux guests enable cloud-init manual cache-clean mode during first-boot
  installation so the cached NoCloud datasource remains authoritative after
  the secret CIDATA ISO is removed; later boots no longer degrade to
  `DataSourceNone`.
- Key-only, password-only, and combined Linux access modes. Saved password
  credentials are transformed in memory into salted SHA-512 crypt hashes;
  `allow_ssh_password_auth` controls SSH policy while root login remains
  disabled.
- Windows release archives now include the version-matched linux-amd64 agent
  at `bin/linux-amd64/lablink-agent`; Linux archive layout is unchanged.

### Security

- Linux image publication verifies `SHA256SUMS.gpg` using the embedded
  Canonical UEC Image Automatic Signing Key and requires exact fingerprint
  `D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81` before parsing the image hash.
- `image_builder_profile` is required and fully validated before any download,
  VM creation, feature enablement, or host mutation. Same-name unrelated
  builders and disks are never adopted.
- Linux VM cloud-init user-data contains no enrollment secrets. Guest
  registration occurs only after the expected per-guest mTLS identity is
  proven; failures after boot retain the expected CIDATA ISO for diagnosis.
  Password plaintext is excluded from plans, metadata, audit, seed files, and
  tool output.
- Linux image transform schema
  `lablink-linux-nocloud-azure-vhd-wsl-builder-v1` prevents every prior Linux
  image cache generation from being adopted.
- WSL feature enablement and reboot are builder-only. Disk identification uses
  persisted unique ID/serial/path/location inventory plus expected virtual
  size and SCSI target identity, never disk number alone. Ambiguous roots,
  identity mismatches, and unmount failures retain explicit safe diagnostic
  state.
- WSL block devices are inventoried immediately before the staging mount.
  Exactly one newly added disk is accepted, and only partitions with a
  validated parent relationship to that disk are inspected; the WSL
  distribution root is never scanned or remounted.
- After builder disk attachment, cleanup is retain-by-default. Only a completed,
  verified transform with explicit `safe_to_detach:true` after WSL unmount can
  authorize detach. Transport, agent, JSON, transform, and detach-response
  failures stop the builder when reachable and retain or restore the exact
  operation disk.
- CIDATA ownership is atomically persisted before ISO creation. Windows ACLs
  on the managed staging directory, secret staging tree, and ISO are verified
  fail-closed; ISO attachment grants read access only to the exact Hyper-V VM
  identity in addition to SYSTEM and Administrators.
- The Linux root agent service retains compatible hardening (`NoNewPrivileges`
  and `PrivateTmp`) without `ProtectSystem=strict` or a finite
  `ReadWritePaths` allowlist, so requested administrative execute/push/install
  operations can write `/etc`, `/usr`, `/opt`, and other explicit paths.
- Image-cache lock ownership is published by same-directory atomic rename.
  Missing or malformed owner records age from the lock-directory timestamp;
  stale locks are atomically renamed before exact-path removal rather than
  deleting the live lock name in place.

### Fixed

- Parallel Linux VM creation now serializes only the host IMAPI2FS CIDATA
  authoring section with a bounded, crash-safe exclusive file handle at
  `%ProgramData%\LabLink\locks\cidata-imapi.lock`. The lock covers COM image
  creation through the completed ISO stream write, never deletes the persistent
  lock file, and fails explicitly with `CIDATA_IMAPI_LOCK_TIMEOUT` after two
  minutes instead of retrying COM activation.
- Pinned WSL MSI installation now writes bounded verbose logs for every
  attempt, uses `Start-Process -Wait -PassThru`, accepts `0`/`3010`, re-detects
  WSL after unexpected exits, and retries at most once when it is still
  absent.
- Reusable builder startup detects only the current VM/start's Hyper-V Worker
  Admin event 18590 with fatal pre-OS `ErrorCode0=0x10`, turns off only that
  managed VM, and retries once. Ordinary DHCP timeouts are unchanged.
- Linux readiness uses a bounded 15-minute KVP address wait plus a 10-minute
  mTLS registration wait with progress heartbeats. Permanent TLS identity
  failures remain immediate, and the Windows registration timeout remains
  five minutes.
- Same-name create/resume reconciles exact persisted CIDATA staging, ISO, and
  pre-VM child-disk artifacts under the per-VM lock, covering crashes before
  ISO creation, after ISO creation, and during VM creation without globbing
  outside the managed VM directory.
- Managed Linux resume inspects persisted VM metadata before image-cache
  resolution and uses the persisted parent/ISO identity. A current cache is
  needed only for new VM creation.
- Existing managed Linux resume validates persisted metadata/ownership before
  resolving SSH key files or password credentials. Missing retired access
  inputs no longer block resume; new VM/seed paths still require valid access
  before any lifecycle lock, cache preparation, or artifact mutation.
- Restricted CIDATA staging cleanup now validates exact persisted ownership,
  removes the exact stage directory, and verifies absence. Failure aborts
  before VM creation and retains the ownership record, ISO, and stage identity
  for safe same-name reconciliation.
- New-VM cache misses resolve and validate the required Windows builder
  profile, target, credential, fixed source, base VHD, VM root, vSwitch, and
  required host commands before the per-VM lifecycle lock or artifact
  reconciliation. Existing managed resumes do not require the current builder
  or cache.
- Every managed Linux resume phase, including `cidata_detached` and `complete`,
  non-mutatingly verifies the exact Hyper-V child OS-disk path and exact
  `Get-VHD` parent path before boot or mTLS. CIDATA reconfiguration remains
  exclusive to `cidata_attached`.
- Managed Linux resume now treats an owned, present but not-yet-attached CIDATA
  ISO as a safe `cidata_attached` crash state. It idempotently reapplies the
  remaining OFF-VM CPU/memory, Secure Boot, ACL, boot-order, ISO, and KVP
  configuration while rejecting unmanaged identity or any unexpected ISO.
- A running managed VM left in `cidata_attached` is now validated against its
  persisted metadata, child/parent disk chain, ownership record, and exact
  attached ISO, then resumes KVP discovery, enrollment verification, and
  success cleanup without requiring the guest to be stopped.
- Managed Linux deletion validates VM identity and all storage before stopping
  a running guest, walks OS/checkpoint parent chains to the persisted base, and
  validates unrelated data-disk storage without treating its parent as OS
  identity.
- `delete_vm` now acquires the same case-insensitive per-VM lifecycle lock as
  create/resume before metadata inspection and holds it through Hyper-V,
  storage, registry, and issued-identity cleanup. Existing Windows deletion
  behavior remains unchanged apart from serialization.
- BITS recovery no longer trusts a destination merely because a file exists.
  Exact persisted source/destination completion records are required; terminal
  Error/Cancelled jobs are removed and recreated. Image digest failures
  quarantine only the exact owned download/blob while holding the content
  cache lock, allowing a later call to redownload it.

## [0.6.3] - 2026-10-08

### Fixed

- VM enrollment and unattend staging now use cryptographically random remote
  paths instead of timestamp-only names, preventing parallel requests from
  overwriting another guest's certificate, key, or answer file.
- Guest TLS certificate-name mismatches are reported immediately instead of
  being retried until the registration or MCP request timeout.
- Explicit Windows hostnames are validated before mutation; names longer than
  15 characters or otherwise invalid for `ComputerName` are rejected with a
  Windows-safe suggestion.

## [0.6.2] - 2026-10-07

### Added

- VM creation now enforces a configurable host resource reserve before any
  VM/VHD mutation. Projected free physical memory and target-volume capacity
  must each remain at or above 10% by default, including worst-case dynamic or
  differencing VHD growth.
- `min_host_reserve_pct` can be stored in VM templates or supplied per request.
  Only the explicit per-request `allow_host_resource_pressure=true` flag can
  bypass a failed reserve check. Dry runs return the full measured projection.

### Fixed

- `create_windows_vm` now reports Hyper-V startup failures immediately instead
  of continuing to poll for an IP address after `Start-VM` failed.
- Long-running VM creation emits MCP progress notifications while provisioning,
  starting, and registering the guest, preventing healthy operations from
  appearing idle to clients with request timeouts.

## [0.6.1] - 2026-10-01

### Added

- `create_windows_vm` high-level orchestration with explicit argument,
  per-host template, and MCP-elicitation precedence.
- Persistent VM template management through `save_vm_template`,
  `list_vm_templates`, and `delete_vm_template`, including target-specific
  defaults.
- Optional automatic guest enrollment: unique mTLS identity, offline payload
  injection, unattended OOBE completion, agent installation, IPv4 discovery,
  mTLS verification, and node registration.
- `delete_vm` with dry-run inventory, explicit running-VM/storage controls,
  managed-root enforcement, differencing-parent protection, best-effort DHCP
  release, and optional node/identity cleanup.
- Encrypted arbitrary secrets through `save_secret`, `list_secrets`, and
  `delete_secret`. Foreground `execute_command` and `execute_script` accept
  `secret_env` references and redact literal secret values from output.

### Fixed

- Corrected `Mount-VHD` to use the valid `-PassThru` parameter.
- Generated unattend files now avoid duplicate specialize components, provide
  locale settings during OOBE, and use the correct Windows AutoLogon password
  obfuscation suffix.
- Detached execution rejects `secret_env` until persistent job output can
  guarantee equivalent redaction.

## [0.6.0] - 2026-06-26

### Added
- **VM-management primitives - Phase 1 (Windows/Hyper-V)** - five new MCP tools for Hyper-V VM lifecycle management on any lablink-managed node. Closes nijosmsft/mcp-servers#28.
  - `list_physical_nics` - enumerate physical NICs on the target; flags the management NIC and marks only Up, unbound, non-management NICs as `recommended_for_external`.
  - `list_vswitches` - read-only discovery of existing Hyper-V virtual switches (name, type, bound adapter, AllowManagementOS, connected VMs).
  - `create_vswitch` - create an external or internal Hyper-V virtual switch; blocks binding an external switch to the management NIC on a remote target unless `allow_management_nic_disruption=true`; `if_exists=reuse` validates type/adapter before reuse; `if_exists=replace` guarded by the same management-NIC safety check.
  - `create_vm` - create a Generation 2 Windows VM with SecureBoot (MicrosoftWindows template), deterministic DVD ordering by ISO path, dynamic-memory min/max/startup/buffer, free-space pre-flight, VM-exists and VHD-in-use conflict guards.
  - `provision_unattend` - generate and inject an `unattend.xml` for first-boot provisioning (hostname, admin credentials, locale, time zone, product key); Method A uses a differencing VHD (never mutates a shared base), scrubs staged cleartext password on every exit path (success, failure, post-commit push error).
- `internal/hyperv` + `internal/hyperv/unattend` pure Go/PowerShell builders; argument-safe single-quoted literals; unit-tested.
- `internal/mcptools/target.go` - Target abstraction with resolveTarget/runPS/pushToTarget for transparent local-vs-remote dispatch.

### Notes
- Method B (clean-install ISO with full windowsPE pass) is a documented stub; deferred to Phase 2.
- Async/reconnect executor for disruptive remote NIC operations and durable cleartext-scrub retry for unreachable targets are deferred to Phase 2.


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
