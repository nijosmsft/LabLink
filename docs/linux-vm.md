# Ubuntu 24.04 Hyper-V VMs

LabLink creates Ubuntu 24.04 amd64 Generation 2 Hyper-V VMs from a prepared,
read-only parent VHDX. Image preparation uses a dedicated Windows builder VM
with nested virtualization. The physical Hyper-V host downloads, verifies,
extracts, and converts the source image, but never installs WSL, enables WSL
features, mounts the Linux filesystem, or reboots for image preparation.

## Required profiles

Every Linux profile used for image preparation must name an
`image_builder_profile`. The referenced profile must be a complete Windows VM
profile for the same Hyper-V target. Resolution fails before downloads, VM
creation, or any other host mutation when the profile is missing, unknown,
non-Windows, incomplete, or references an unavailable credential.

The Windows builder profile must set all three host-side requirements:

```json
{
  "profile_usage": "linux_image_builder",
  "dynamic_memory": false,
  "expose_virtualization_extensions": true,
  "virtualization_based_security_opt_out": true
}
```

Dynamic memory is rejected and both boolean opt-ins must be explicit. New
builder profiles should set the usage marker. For compatibility, a Windows
profile referenced by a Linux profile's `image_builder_profile` is inferred to
be builder-only even when its older configuration omits `profile_usage`.
Public `create_windows_vm`, including dry runs, rejects explicit and inferred
builder-only profiles before host mutation; only the internal
image-preparation path resolves them. Save a builder template with
`set_as_target_default:false`.

The builder is created through the normal Windows VM orchestrator, enrolled
with role `linux-image-builder`, and given a unique managed identity in Hyper-V
Notes. While the new VM is still Off, LabLink applies and verifies
`VirtualizationBasedSecurityOptOut`, then configures
`ExposeVirtualizationExtensions`, all before its first start.
An existing VM is reused only when its exact managed identity, target, profile,
VM name, and node name match. LabLink never adopts a same-name unrelated VM.

The builder name defaults deterministically per target and can be overridden
with `builder_vm_name`. It is retained stopped by default for later image
preparations. Set `delete_builder_after_prepare:true` to delete only the
operation-owned builder VM, child disk, registry entry, and issued identity
after successful publication. Shared Windows parent/profile assets are never
deleted.

## Fixed source and trust

The only accepted image source is:

```text
https://cloud-images.ubuntu.com/releases/noble/release/
ubuntu-24.04-server-cloudimg-amd64-azure.vhd.tar.gz
```

The archive's pinned VHD member is `livecd.ubuntu-cpc.azure.vhd`.

LabLink also downloads `SHA256SUMS` and `SHA256SUMS.gpg` from the same stable
Canonical release directory. The server verifies the detached signature using
an embedded Canonical key and requires fingerprint:

```text
D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81
```

There is no arbitrary source URL or external conversion-tool download. The
authenticated manifest supplies the archive digest, which the Hyper-V host
checks before extraction. Digest failures quarantine only the exact
operation-owned download/blob.

## Preparation and durable resume

`prepare_linux_image` stores variant state at:

```text
<cache>\sources\ubuntu-24.04-amd64-generic\variants\disk-<GB>\state.json
```

The transform schema is
`lablink-linux-nocloud-azure-vhd-wsl-builder-v1`; all earlier cache generations
are stale. A per-cache-key atomic lock serializes identical transformations.
An independent builder-identity lock serializes every cache key and disk-size
variant that uses the same target/builder VM while allowing unrelated builders
to run in parallel. The builder lock covers creation/reuse, WSL setup, disk
inventory, attach, transform, detach, and optional builder deletion; stale
recovery uses atomic rename and release requires the exact owner token.
BITS jobs are asynchronous and resumable. Active downloads return
`image_preparing` with job identity and byte progress.

Preparation is idempotent across:

1. signed download verification;
2. archive extraction and host `Convert-VHD`;
3. builder creation or exact-identity reuse;
4. WSL feature enablement and builder-only reboot;
5. pinned WSL 3.0.3 runtime and Ubuntu 24.04 distribution installation;
6. pre-attach disk inventory;
7. exact staging VHDX attachment;
8. WSL mount, filesystem discovery, write, verification, and unmount;
9. exact disk detach;
10. hashing and read-only publication.

The host lists the archive and accepts exactly one expected Azure VHD member.
It extracts to a random operation staging directory, uses in-box `Convert-VHD`
to produce a dynamic VHDX with a 1 MiB block size, and grows it with
`Resize-VHD` to the requested virtual size.

## Builder WSL lifecycle

Only the enrolled builder runs these operations:

- enable `Microsoft-Windows-Subsystem-Linux` and `VirtualMachinePlatform`
  with `-NoRestart`;
- persist `features_enabled_reboot_required`;
- reboot and wait for the same mTLS node to return;
- distinguish the in-box `wsl.exe` stub from a real runtime by using
  `wsl --version` and the installed Microsoft WSL product;
- download the fixed WSL 3.0.3 x64 MSI with resumable BITS to
  `C:\ProgramData\LabLink\wsl`, requiring SHA-256
  `ae977286974255bd26bf925f00f40f5692c6b2084155cbc0563c09aea091f211`
  and a valid Microsoft Authenticode signer before silent execution;
- install only
  `https://github.com/microsoft/WSL/releases/download/3.0.3/wsl.3.0.3.0.x64.msi`
  with a hidden `Start-Process -Wait -PassThru` invocation of
  `msiexec.exe /i ... /qn /norestart /L*v`. Every attempt has a bounded
  verbose log under `C:\ProgramData\LabLink\wsl`; exit `0` and `3010` are
  accepted, the runtime is re-detected after an unexpected exit, and at most
  one retry is made when WSL is still absent;
- run
  `wsl --install -d Ubuntu-24.04 --web-download --no-launch`;
- make Ubuntu 24.04 the default WSL version 2 distribution and verify it with
  nonterminating list probes.

The MSI URL, version, filename, digest, BITS display name, and distribution are
compiled-in metadata and copied into the builder's atomically replaced state
file. They are not caller inputs. Error/cancelled BITS jobs are removed and
recreated, suspended/transient jobs are resumed, and any MSI that fails hash or
signature validation is moved to an operation-owned quarantine directory
before another download can start.

The LabLink Agent remains LocalSystem for inventory and orchestration, but it
does **not** call WSL directly. WSL distribution registration is per-user, and
WSL rejects LocalSystem. Setup, every post-reboot resume, and the filesystem
transform therefore run under the builder profile's saved normal local
administrator. The SYSTEM-side script receives that credential only through
the agent request environment, creates a random 128-bit directory under
`C:\ProgramData\LabLink\builder-user-jobs`, and registers one password-logon,
highest-run-level Scheduled Task whose action references only a non-secret
runner file. It clears the password environment and variable immediately
after registration, polls with a bound, relays the payload result, then stops
and unregisters the exact task and deletes the exact job directory in
`finally`. Missing/invalid results, timeout, nonzero payload exit, and any
cleanup failure fail closed. Passwords never enter scripts, task names, paths,
arguments, state, plans, audit, logs, errors, or output.

The saved credential username is preferred, but Windows unattend may have set
that password on the built-in Administrator account instead of creating the
configured name. If the configured local name is unmapped, LabLink falls back
only to the single enabled local account whose SID ends in RID `-500`, and
requires direct local Administrators membership. Zero, multiple, disabled, or
non-administrator matches fail closed. The task runs as
`COMPUTERNAME\actual-name`; its exact name and SID are passed as non-secret
process environment, persisted in builder setup state, and must match exactly
on every setup resume and filesystem transform so WSL registration remains
bound to one Windows user.

When the host starts the reusable builder, it also watches only Hyper-V Worker
Admin event 18590 for that VM and that start attempt with `ErrorCode0=0x10`.
That fatal pre-OS signature permits one immediate `Stop-VM -TurnOff` and
restart. Ordinary DHCP/IP timeouts retain the existing 15-minute failure and
are never broadly retried.

Before the staging disk is attached, the builder persists every physical
disk's unique ID, serial, path, location, and size. The host then stops the
builder and attaches only the exact operation-owned VHDX as a secondary SCSI
disk. After restart, the builder accepts exactly one disk that is absent from
the persisted inventory and matches the expected virtual size and SCSI target
identity. Disk number alone is never trusted.

Immediately before `wsl --mount`, LabLink inventories WSL block devices. After
the bare mount it requires exactly one newly added WSL `disk`, validates its
path, type, empty parent, expected size, and unmounted state, and passes only
that device to the root-run transform. The script asks `lsblk` only for that
disk's subtree, rejects any child whose type/`PKNAME` relationship is not an
exact partition of the new disk, and probes only those partitions read-only.
It therefore never scans or remounts the Ubuntu WSL distribution root. Exactly
one candidate must identify an Ubuntu root with cloud-init. The script then
mounts that root read-write and atomically installs:

```yaml
datasource_list: [ NoCloud, None ]
```

at `/etc/cloud/cloud.cfg.d/99-lablink-nocloud.cfg`, syncs, verifies the exact
content, unmounts the filesystem, and asks WSL to unmount the physical disk.

After attachment, cleanup defaults to retaining the exact staging disk.
Detachment is authorized only by a successfully parsed
`filesystem_updated` result containing explicit `safe_to_detach:true`, which
is emitted after the content verification and successful WSL unmount.
Transport loss, agent failure, malformed JSON, transform failure, ambiguous
roots, relationship mismatch, and detach-response loss persist diagnostic
state, stop the builder when the host is reachable, and keep or restore the
exact operation disk attachment. Unrelated data disks are never adopted,
detached, or removed.

After detach, the host validates the VHDX, computes SHA-256, publishes the VHDX
and metadata atomically, and marks both read-only. Status validation rechecks
the published hash, source identity, signer, virtual size, type, and block size.

## Standard NoCloud CIDATA

`create_linux_vm` continues to use a standard ISO9660/Joliet ISO labeled
`CIDATA` with root-level:

- `meta-data`
- `user-data`
- optional `network-config`
- LabLink agent, CA, guest certificate/key, token, and installer payloads

`meta-data` uses `dsmode: local`. Without custom network configuration, the
seed supplies Netplan v2 DHCPv4/DHCPv6 policy for the Hyper-V `hv_netvsc`
driver. The VM uses a differencing child of the prepared read-only parent,
Generation 2 Linux Secure Boot, VHD-first boot ordering, and KVP address
discovery.

IMAPI2FS ISO authoring is serialized only while the host creates and completely
writes an image. Parallel VM workflows contend on the exclusive
`%ProgramData%\LabLink\locks\cidata-imapi.lock` file handle for at most two
minutes; the file may persist, while closing or terminating the authoring
process releases the OS lock. A timeout fails explicitly with
`CIDATA_IMAPI_LOCK_TIMEOUT`. Validation, staging, VM creation, and enrollment
remain parallel and per-VM lifecycle locks remain independent.

At least one SSH key or saved `linux_password_credential` is required.
Passwords are converted in memory to salted SHA-512 crypt hashes; plaintext is
excluded from profiles, seed files, metadata, audit, errors, and output. The
systemd agent installer is idempotent, disables direct root login, verifies
SSH/service state, and registers only after the expected guest mTLS identity
is proven. It also enables cloud-init's manual cache-clean mode so later boots
trust the authenticated first-boot NoCloud cache after the secret CIDATA ISO is
removed, instead of degrading to `DataSourceNone`. The service retains
non-conflicting hardening such as `NoNewPrivileges` and `PrivateTmp`, but does
not use `ProtectSystem=strict` or a finite `ReadWritePaths` allowlist: the
intentional root remote-management agent must be able to perform requested
administrative writes under paths such as `/etc`, `/usr`, and `/opt`.

Same-name create/resume and delete share a case-insensitive per-VM lifecycle
lock. Persisted ownership, parent/child disk identity, CIDATA path, ACLs,
registration state, and cleanup phase are validated before mutation. Successful
enrollment detaches and deletes CIDATA. Unsafe mismatches fail closed; managed
post-boot state is retained for diagnosis and resume.

The secret staging directory is removed through its exact persisted ownership
record after ISO creation, and absence is verified before VM creation. Cleanup
failure aborts creation and retains the ownership record, ISO, and exact stage
identity for a later same-name reconciliation; errors never include payload
contents.

For a new VM with a cache miss, `create_linux_vm` resolves the Windows builder
profile and target, verifies its credential and fixed-source configuration,
and non-mutatingly checks the builder base VHD, VM root, vSwitch, and required
host commands before acquiring the per-VM lifecycle lock or reconciling any
artifacts. Existing managed VM resume is detected first and does not require
the current image cache, builder profile, original SSH public-key file, or
password credential. Access material is resolved only after inspection proves
that a new VM/seed path is required, and missing access fails before host
mutation. Every resume cleanup phase
(`cidata_attached`, `cidata_detached`, and `complete`) non-mutatingly validates
that Hyper-V has exactly the persisted child OS disk and that `Get-VHD`
reports the exact persisted parent before boot or mTLS; CIDATA reconfiguration
remains limited to `cidata_attached`.

See [`../configs/vm-defaults.example.json`](../configs/vm-defaults.example.json)
for Windows builder and Linux guest profiles.
