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
    try {
        lablink execute_script $n 'C:\LabLink\Update-LabLink.ps1 -Force' | Out-Null
    } catch {
        # Expected: the script stops the LabLink Agent service mid-execution, which
        # tears down the gRPC stream serving execute_script. The binary swap continues
        # in the detached PowerShell child. Suppress and move on.
    }
    lablink wait_for_node $n -timeout 120
    $ver = lablink execute_script $n 'C:\LabLink\lablink-agent.exe --version'
    Write-Host "  $n -> $ver"
}
```

## Why the execute_script call appears to fail

`Update-LabLink.ps1` calls `Stop-Service "LabLink Agent"` partway through the binary
swap. The agent process exits, which closes the gRPC stream that is serving your
`execute_script` call. From the operator side this surfaces as a "stream closed" or
connection-lost error.

That is expected behaviour, not a bug. The binary swap continues in the detached
PowerShell child that the agent spawned before it exited. Once the new binary is in
place, `Start-Service` brings it online and the agent is reachable again. The
`try { ... } catch { }` block in the pattern above is the canonical way to handle
this.

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

## When to use this vs a single-node update

**Single node:** run `execute_script` with `Update-LabLink.ps1 -Force` once, catch
the expected stream-drop, then call `wait_for_node`. No loop.

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

- The operator workstation must have a working LabLink MCP session (all nodes
  reachable, auth token valid).

## Future: built-in update_nodes MCP tool

A built-in `update_nodes` tool that handles the loop, the expected stream-drop,
polling, and a per-node result table is tracked as a follow-up. Until it lands, the
pattern above is the recommended approach.

## See also

- `scripts/Update-LabLink.ps1` -- the per-machine update script (binary swap,
  Windows service stop/start, atomic rollback on failure).
- [`docs/file-transfers.md`](file-transfers.md) -- file transfer mechanics for
  `push_file` / `pull_file`, useful when bootstrapping nodes that do not yet have
  the script in place.
