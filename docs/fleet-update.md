# Fleet update -- updating every node from the operator workstation

## Background

After v0.4.2, every LabLink install -- operator workstation AND every lab node --
ships with `scripts/Update-LabLink.ps1` (or `C:\LabLink\Update-LabLink.ps1` on a
node). For a single machine the operator just runs the script directly. For a fleet
of nodes there is no built-in `update_nodes` MCP tool yet (tracked separately), but
you can compose the existing primitives to achieve the same result.

## The pattern

```powershell
# Operator workstation, with the LabLink MCP server loaded into your shell
# or via Copilot CLI.
$nodes = lablink list_nodes   # JSON or text -- adapt parsing to your wrapper

foreach ($n in $nodes) {
    Write-Host "Updating $n ..."
    lablink execute_script $n 'C:\LabLink\Update-LabLink.ps1 -Force -Detach'
    lablink wait_for_node $n -timeout 120
    $ver = lablink execute_script $n 'C:\LabLink\lablink-agent.exe --version'
    Write-Host "  $n -> $ver"
}
```

## Why -Detach is required

The lablink-agent executor (`cmd/lablink-agent/executor.go:195-196`) calls
`cmd.Process.Kill()` on the child PowerShell when the agent's own context is
cancelled. That cancellation happens the moment `Update-LabLink.ps1` calls
`Stop-Service "LabLink Agent"` to quiesce the process before the binary swap.
The sequence is:

1. `execute_script` launches `powershell.exe Update-LabLink.ps1 -Force` as a child.
2. The script calls `Stop-Service "LabLink Agent"`.
3. The agent service exits, cancelling its context.
4. The executor fires `cmd.Process.Kill()` on the still-running child PowerShell.
5. The child is killed before it copies the new binary or calls `Start-Service`.
6. The node is left with the service stopped and possibly mixed-version files.

The `-Detach` flag breaks this cycle. When passed, the script validates its
arguments, then calls `schtasks.exe /Create /Sc Once /Ru SYSTEM /Z` to register
a one-shot Windows scheduled task named `LabLinkSelfUpdate` that fires approximately
30 seconds in the future. The script then exits 0 immediately -- before any
`Stop-Service` call. The `execute_script` RPC completes cleanly. Roughly 30 s
later, the scheduled task runs as SYSTEM in a process tree that has no connection
to the agent, performs the full binary swap and service restart, and the task
deletes itself (`/Z`).

## Verification

After the loop, run a quick health check across the fleet:

```powershell
lablink ping_nodes
```

Every node should report alive. For per-node version confirmation:

```powershell
foreach ($n in (lablink list_nodes)) {
    $v = lablink execute_script $n 'C:\LabLink\lablink-agent.exe --version'
    Write-Host "$n -> $v"
}
```

## Single-machine update

On an operator workstation (no Windows service running), `-Detach` is not needed.
The script runs inline; there is no agent process to kill the child PowerShell.
Use the simpler form:

```powershell
.\Update-LabLink.ps1 -Force
```

Or, if updating via `execute_script` to a node from another node, use `-Detach`
as above.

## When to use this vs a single-node update

**Single node (service):** call `execute_script` with `-Force -Detach`, then
`wait_for_node`. No loop.

**Fleet (two or more nodes):** use the loop above. Sequential execution is usually
fine -- the dominant time per node is the `wait_for_node` poll (typically 5-20 s for
the service to restart), so a 10-node fleet takes about two minutes end-to-end.
Parallel execution is possible but adds error-handling complexity with little
practical benefit unless your fleet is large.

## Prerequisites

- v0.4.2 or later must already be installed on every node. The script
  `C:\LabLink\Update-LabLink.ps1` was first deployed to nodes by `deploy-agent.ps1`
  in v0.4.2. Nodes on an earlier version will not have the script in place; update
  those manually first (`push_file` the script, then invoke it).

- The `-Detach` flag requires the script change introduced in PR #16
  (branch `detach-flag`). Nodes running v0.4.2 do not have the flag; update
  those with the inline pattern once, then all future updates can use `-Detach`.

- The operator workstation must have a working LabLink MCP session (all nodes
  reachable, auth token valid).

## Future: built-in update_nodes MCP tool

A built-in `update_nodes` tool that handles the loop, the expected service-down
window, polling, and a per-node result table is tracked as a follow-up. Until it
lands, the pattern above is the recommended approach.

## See also

- `scripts/Update-LabLink.ps1` -- the per-machine update script (binary swap,
  Windows service stop/start, atomic rollback on failure).
- [`docs/file-transfers.md`](file-transfers.md) -- file transfer mechanics for
  `push_file` / `pull_file`, useful when bootstrapping nodes that do not yet have
  the script in place.
