# Restricted local Hyper-V host

This opt-in Windows installation adds local VM management to the same operator
MCP server used for remote machines. It does **not** make the entire MCP server
VM-only. Remote full agents and enrolled guest agents retain their normal tools.

## Installation

Enable Hyper-V and install its PowerShell module first. Run the operator
installer from an elevated PowerShell prompt with local support enabled:

```powershell
.\install.ps1 -LocalHyperV `
    -LocalWindowsBaseVHD 'D:\Images\windows-base.vhdx' `
    -LocalVSwitch 'Default Switch' `
    -LocalVMCredential 'local-vm-admin'
```

For an existing operator installation, run the packaged script elevated:

```powershell
& 'C:\LabLink\current\scripts\Install-LocalHyperV.ps1' `
    -WindowsBaseVHD 'D:\Images\windows-base.vhdx' `
    -VSwitch 'Default Switch' `
    -VMCredential 'local-vm-admin'
```

The Windows base must be a suitable sysprepped image, as with ordinary Windows
VM creation, and must be a standalone VHD/VHDX, not a differencing chain.
An already-used shared parent is supported: elevated setup makes a verified,
protected snapshot under the image root, leaving the source unchanged. Only
new differencing children of that snapshot are modified. The Windows base is also used to bootstrap the normal
Linux image-builder VM if a prepared Ubuntu cache is unavailable.

Setup creates `local-windows`, `local-linux-builder`, and `local-ubuntu`
profiles without replacing existing remote profiles/defaults. Save the named
VM credential through the normal masked `save_credential` prompt if it does
not already exist. These are **guest** credentials, not the service's identity.
Reload/restart the operator MCP server after installation.

Use `profile:"local-windows"` or `profile:"local-ubuntu"` for ordinary VM
creation. The same Ubuntu profile works with `create_isolated_orchestrator`.
VM tools targeting `localhost` use the registered `local-hyperv` service;
explicit remote targets keep using their ordinary full agents.

## Process and transport model

- The operator MCP server continues to run as the interactive user.
- The service runs as `NT SERVICE\LabLinkHyperV`. Startup rejects SYSTEM,
  interactive identities, and enabled Administrators membership.
- The service listens only on a numeric loopback address, by default
  `127.0.0.1:19091`, with mandatory mTLS and the normal LabLink auth token.
- The service accepts health discovery and structured `ManageVM` operations.
  Generic execution/scripts, file transfer, forwarding, process control,
  background jobs, and all other RPCs are denied by service-side interceptors.
  Changing the address used to reach it does not change this policy.
- High-level VM operations reuse the existing ordinary and isolated handlers
  and script builders. Scripts generated internally from validated VM
  parameters are not a public script-execution API.
- Newly enrolled guests are synchronized into the operator registry, where
  their normal full agents support commands, file transfer, debugging, etc.

## Privileges: non-SYSTEM is not an unprivileged sandbox

Elevated installation is required to create the service, protect its files,
and grant its explicit rights:

| Grant | Reason |
|---|---|
| Hyper-V Administrators (`S-1-5-32-578`) | VM, switch, and virtual-disk management |
| Log on as a service (`SeServiceLogonRight`) | Dedicated virtual service account |
| Perform volume maintenance (`SeManageVolumePrivilege`) | Attach/detach managed child VHDs |
| Back up files/directories (`SeBackupPrivilege`) | Backup-mode guest-filesystem access |
| Restore files/directories (`SeRestorePrivilege`) | Inject into protected Windows guest folders |
| ACLs on approved storage and service keys | VM/cache/staging access and authentication |

These are machine-wide privileges and broad Hyper-V rights. They are **not**
OS-enforced per-VM permissions. Treat the service as privileged software;
the application policy and restricted API are important security boundaries.
No local Administrators membership, LocalSystem account, or blanket Defender
exclusion for PowerShell is used for this service.

Setup protects the service directories, then adds and verifies Microsoft
Defender **antivirus** path exclusions for its code, state, VM, and image roots,
plus a process exclusion for the protected `lablink-agent.exe`. This happens
before copying or executing service binaries. A policy that prevents the
requested exclusions causes setup to stop before modifying service binaries.
ASR rules and their policy are not changed.

Real-account probes established that assigning partition drive letters through
the storage provider is still denied. Restricted Windows provisioning instead
uses a temporary DOS-device alias in the service logon session and backup-mode
copies. It checks guest destination paths for reparse points, does not alter
guest ACLs to grant the service permanent access, and removes the alias and
dismounts its child disk when finished.

## Installed policy and data

By default:

- Code and `hyperv-policy.json`: `%ProgramFiles%\LabLinkHyperV`, writable only
  by Administrators/SYSTEM; service read/execute.
- Service state/keys: `%ProgramData%\LabLinkHyperV`.
- Managed child storage: `%ProgramData%\LabLinkHyperV\VMs`.
- Ubuntu image cache: `%ProgramData%\LabLinkHyperV\Images`.

The protected code directory contains only the Windows agent, the Linux guest
agent payload, and required appliance assets. Setup uses `lablink-server.exe`
and `lablink-ca.exe` from the existing operator package rather than installing
second copies in the service directory. Client certificates are issued directly
into the protected state directory.

Installer scratch files (including temporary native-helper compilation) use
`StateRoot\Temp` after exclusions are verified. The running service also sets
`TEMP` and `TMP` beneath that excluded state root. These guarantees cover
LabLink-owned host files; shared operator registry/templates remain in the
operator home, guest filesystem writes occur inside their VHDs, and Windows
continues to manage its own service configuration and event logs.

The elevated script accepts separate `-VMRoot`, `-ImageRoot`, `-InstallRoot`,
and `-StateRoot` paths. Writes outside the installed VM root, traversal,
reparse points, physical-device paths, unapproved parent images, and arbitrary
service-side file reads are rejected. Only installation-approved existing
switches and `LabLink-`-prefixed private/internal switch creation are allowed.

The service needs its own protected TLS client/server identities and issuing
material for guest enrollment; setup copies the operator's issuing CA and CA
bundle, not the root CA private key. VM passwords are resolved by the
unprivileged operator, sent only over the authenticated management channel,
and held in a request-scoped in-memory credential store. The service does not
try to decrypt the interactive user's DPAPI credential files.

Provide SSH public keys inline; the operator resolves `ssh_public_key_file`
before invoking the privileged service. Domain joining is performed through
the created VM's full agent using `join_windows_domain`, not through the
restricted host.

Linux cold preparation still requires outbound access to the normal fixed,
verified dependencies. Network/proxy access must work for the service and its
builder VM. The restricted service uses Windows' inbox HTTPS `curl.exe` with
resumable transfers rather than BITS jobs requiring an interactive logon.
Signature/digest verification and the ordinary builder workflow are unchanged.
A prepared cache is reused as in the ordinary Linux workflow.

## Upgrade and uninstall

Re-run `Install-LocalHyperV.ps1` elevated to upgrade the service. Existing
server keys, managed VM data, inventory, and guest profile customizations are
retained. A colliding profile belonging to another target is rejected, not
overwritten. The ordinary full `LabLink Agent` service is separate and is not
modified; remove any separately installed full host agent if this machine
must expose no generic host execution endpoint.

The main `install.ps1` also updates an already installed local Hyper-V service;
`-LocalHyperV` is required only to opt in on a new installation.
`Update-LabLink.ps1` detects the protected service separately from the operator,
requires elevation to update it, and invokes its dedicated installer using the
new package. `-SkipLocalHyperV` explicitly selects an operator-only update.
When updating as a different Windows account, pass the original `-OperatorHome`
to `Update-LabLink.ps1`, or `-LocalOperatorHome` to the main installer. New
installations record the original operator home in protected `installation.json`
and reuse it on subsequent upgrades. Existing CA/token identity mismatches are
rejected before changing the service. Certificates are issued in protected
staging and prior authentication files are included in upgrade rollback.
Process stopping for operator updates is restricted to
that operator directory; it does not kill the protected agent by executable name.
An unsuccessful protected-service upgrade restores its prior runtime files and
restarts it if it was previously running. Existing Defender exclusions are
retained on uninstall because VM/state files are retained.
An installed protected service is synchronized even when the operator version
already matches, so exclusion preparation cannot be skipped by version probing.

```powershell
& 'C:\LabLink\current\scripts\Install-LocalHyperV.ps1' -Uninstall
```

Uninstall removes the restricted service, its group membership and assigned
account rights, but preserves VM data/state for explicit recovery or cleanup.
It does not delete guests, remove shared base images, or stop unrelated agents.
