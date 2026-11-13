# Isolated VM and Orchestrator Design

Status: Approved requirements, implementation design

Target branch: `feat/isolated-vm-orchestrator`

Scope: LabLink-managed Ubuntu orchestrator appliances and isolated Windows or
Linux Hyper-V guests

## 1. Goals and non-goals

### 1.1 Goals

This feature adds a managed isolation topology to LabLink:

1. A dedicated Ubuntu 24.04 amd64 VM, called the orchestrator, is created on a
   remote Windows Hyper-V host through the existing Linux VM flow.
2. The orchestrator keeps its primary NIC on the existing main vSwitch. It has
   normal main-network and internet access and remains a regular LabLink node.
3. Each isolated network is a Hyper-V private vSwitch. The Hyper-V management
   OS is not connected to it.
4. The orchestrator receives one private NIC per isolated network and is the
   IPv4 gateway for the guests on that switch.
5. Windows and Linux guests use static IPv4 configuration. They are reachable
   by LabLink through a persistent TCP relay on the orchestrator, not by direct
   main-network attachment.
6. Per-VM NAT can be enabled or disabled without affecting the LabLink relay.
7. Durable shared state, exact immutable identities, operation journaling, and
   cross-process locks make the workflows resumable across multiple stdio
   LabLink server processes on one developer machine.
8. High-level tools perform complete workflows while lower-level relay and NAT
   primitives support diagnosis, validation, reconciliation, and adoption.

The design deliberately reuses current LabLink conventions:

- Tool registration remains in `internal/mcptools` and is wired from
  `cmd/lablink-server/main.go`.
- Hyper-V host work remains PowerShell executed through `Target` and `runPS`
  from `internal/mcptools/target.go`.
- Orchestrator creation composes the existing `create_linux_vm` path in
  `internal/mcptools/linux_vm.go`.
- Host resource checks extend `internal/hyperv/resource.go`.
- Guest enrollment reuses the PKI and registration patterns in
  `internal/mcptools/vm_enrollment.go`.
- Existing JSON node registry semantics in `internal/registry/registry.go`
  remain readable and writable by old releases.
- The new shared database follows the existing modernc SQLite, WAL,
  `busy_timeout`, and `BEGIN IMMEDIATE` conventions used by
  `internal/leasing/sqlite.go`; shared database open/migration and transaction
  helpers should be factored or reused rather than independently reinvented.
- Progress uses the existing MCP progress heartbeat and portal operation
  patterns, but durable operation state is added separately because
  `internal/ops/registry.go` is intentionally process-local.
- Approval planning and elicitation reuse the plan resolution and
  `RequestElicitation` flow in `internal/mcptools/vm_orchestrator.go`.
- Managed identity, ownership, resume inspection, exact cleanup, and retained
  failure behavior reuse the patterns in `internal/mcptools/linux_vm.go` and
  `internal/hyperv/linux_vm.go`.
- Private-switch and management-NIC discovery build on
  `internal/hyperv/vswitch.go` and `internal/hyperv/nics.go`.
- The byte-copy and half-close seam in `cmd/lablink-agent/forward.go` is the
  starting point for the persistent appliance relay manager.
- Connection reuse and reset continue through
  `internal/agentclient/client.go`'s `Pool`.
- Profile resolution remains in `internal/vmconfig/config.go`'s `Store`.

### 1.2 Non-goals

- Hyper-V host clustering, Failover Clustering, SCVMM, Replica, or live
  migration.
- Export/import migration of an orchestrator or isolated topology.
- Moving an orchestrator or guest to another Hyper-V host. A host mismatch is
  unsupported and fails closed.
- Backing up an orchestrator VM. The appliance database is operational state,
  not a backup.
- Protecting mutually untrusted guests on the same private vSwitch.
- Preventing source-address spoofing by guests with Hyper-V port ACLs.
- Enforcing IPv6 isolation. IPv6 is unmanaged and has no isolation guarantee.
- Per-destination or per-service NAT allowlists.
- A DNS proxy or split DNS service on the orchestrator.
- TLS termination, payload inspection, PROXY protocol, or application-aware
  behavior in the relay.
- A new audit metadata model. Existing audit behavior remains; durable
  operations are operational records, not a new security audit scope.
- Automatic global state replication between developer machines.

## 2. Terminology

| Term | Meaning |
|---|---|
| Hyper-V host | Registered Windows LabLink node that owns the VMs and switches. |
| Orchestrator | Managed Ubuntu 24.04 amd64 VM with a main NIC, private NICs, the privileged LabLink agent, relay listeners, and nftables policy. |
| Main network | Existing network reachable through the orchestrator's primary NIC and existing main vSwitch. |
| Private network | One Hyper-V private vSwitch, one `/26` subnet, one orchestrator private NIC, and zero or more isolated guests. |
| Isolated guest | Windows or Linux VM connected only to a managed private vSwitch. |
| Relay | Orchestrator userspace TCP listener on the main NIC that forwards opaque bytes to exactly one guest's TCP port 9091. |
| NAT state | Per-VM `enabled`, `draining`, or `disabled` IPv4 forwarding state. |
| Control-plane state | Shared SQLite state on the developer box, used by all local LabLink stdio server processes. |
| Appliance state | Persistent SQLite state inside the orchestrator, authoritative for live networks, NAT rules, relay mappings, and listener generations. |
| Generation | Monotonic resource version used for compare-and-swap mutations. |
| Revision | Immutable hash-bound version of an approval plan or durable operation input. |
| Immutable ID | Random UUID used as the durable identity of an orchestrator, network, guest, relay, or operation. |
| Display name | Mutable operator-facing label. It never changes Hyper-V names, TLS names, node names, IDs, paths, or allocation identity. |
| `resume_exact` | Retry mode that resumes an existing operation only when its operation ID and canonical argument hash match exactly. |

## 3. Threat and trust model

### 3.1 Trusted components

The following are trusted:

- The Windows Hyper-V host and its privileged LabLink agent.
- The Ubuntu orchestrator and its privileged integrated LabLink agent.
- The LabLink CA and existing shared-token transport configuration.
- Any LabLink server accepted by that transport. There is no per-user,
  per-server, or owner namespace in isolated state.
- All guests and peers on the same private vSwitch.

CA trust defines the management trust domain. The existing shared auth token
remains an additional transport prerequisite, but it does not create resource
ownership. A trusted LabLink server may list, reconcile, mutate, or adopt
resources when it has their immutable identity and can reach the relevant host
or orchestrator.

### 3.2 Isolation boundary

The intended boundary is:

- Hyper-V private switches exclude the management OS.
- Guests on different private switches cannot route through the orchestrator.
- Guests with NAT disabled cannot start new IPv4 forwarding flows through the
  orchestrator.
- The relay exposes only a guest's LabLink agent port 9091.

The following are explicit accepted caveats:

- Same-switch peers communicate directly at layer 2 and are trusted.
- A guest may spoof another source address on its switch. Hyper-V source ACLs
  are not required in the initial implementation.
- IPv6 is unmanaged. Link-local, router advertisement, or other IPv6 behavior
  may bypass the intended IPv4 policy; no IPv6 isolation guarantee is made.
- A compromised trusted LabLink server can mutate every topology in its trust
  domain.
- The relay has no idle timeout and no application-level connection cap.
  File-descriptor, memory, or connection exhaustion is an accepted risk.
- NAT is unrestricted when enabled: internet, DNS, and reachable main-network
  destinations are all available.
- The orchestrator keeps ordinary main-network and internet access.
- There is no orchestrator backup. Loss of the VM may require an approved
  cascade deletion of its children.

### 3.3 Privilege boundaries

- Hyper-V switch, VM, NIC, and storage changes execute on the Windows host
  through the existing agent and PowerShell path.
- The orchestrator agent runs as root. It owns generated systemd-networkd
  files, its appliance database, relay sockets, and the complete nftables
  ruleset.
- Guest agents retain their current privileged behavior: LocalSystem on
  Windows and root on Linux.
- Relay traffic remains guest-to-server mTLS. The orchestrator never receives
  guest private keys and never terminates guest TLS.

## 4. Topology

### 4.1 One orchestrator with two private networks

```text
                         Main network / Internet
                                  |
                      existing main Hyper-V vSwitch
                                  |
                 +----------------+----------------+
                 |                                 |
       Windows Hyper-V host                  Orchestrator VM
       LabLink agent :9091                   Ubuntu 24.04 amd64
                                                main NIC
                                           agent :9091
                                      relays :20000-39999
                                                |
                          +---------------------+---------------------+
                          |                                           |
                  private NIC A                               private NIC B
                  192.168.240.1/26                            192.168.240.65/26
                          |                                           |
              Hyper-V private switch A                   Hyper-V private switch B
              host has no switch NIC                     host has no switch NIC
                    /            \                              /           \
          Windows guest A1   Linux guest A2           Windows guest B1  Linux guest B2
          .10, agent :9091   .11, agent :9091         .74, agent :9091 .75, agent :9091
```

### 4.2 Management connection path

```text
LabLink server
      |
      | mTLS to orchestrator-main-ip:allocated-port
      v
orchestrator relay listener
      |
      | opaque TCP, no TLS termination, target fixed to guest-ip:9091
      v
isolated guest LabLink agent
```

The guest's certificate identity remains the guest's immutable LabLink node
name. `registry.Node.Address` contains the orchestrator main IP and relay port,
while `registry.Node.TLSServerName` contains the guest node identity. This is
already supported by `internal/agentclient/client.go`.

### 4.3 Address plan

Every orchestrator independently owns `192.168.240.0/20`, split into `/26`
subnets. Reuse across orchestrators is safe because each set is behind
different Hyper-V private switches.

For each `/26`:

| Address | Use |
|---|---|
| base address | Network address |
| base + 1 | Orchestrator gateway |
| base + 2 through base + 9 | Reserved |
| base + 10 through base + 62 | Guest allocation pool |
| base + 63 | Broadcast |

The server proposes the lowest available `/26` index and guest address unless
an exact persisted allocation is being resumed; the appliance transaction is
the final allocation authority. One orchestrator supports at most 16 private
networks and 100 guests, even though the `/20` contains more address space.

## 5. Component boundaries

### 5.1 LabLink server

The server owns:

- Planning and approval.
- Shared control-plane SQLite state.
- Cross-process locks and durable operation journal.
- Orchestrator discovery, compatibility checks, and capacity selection.
- Hyper-V host mutations through `runPS`.
- Node registry updates.
- High-level MCP workflows and primitive MCP tools.
- Portal read models.

The server does not claim that its cached live state is authoritative. It
reconciles against the Hyper-V host and the orchestrator agent.

### 5.2 Windows Hyper-V host agent

The existing host agent remains a generic execution and transfer endpoint. It
does not gain a separate Hyper-V daemon. New Go builders in `internal/hyperv`
generate bounded PowerShell for:

- Host-side locks.
- Private switch create/remove/validate.
- Orchestrator and guest NIC attach/remove/validate.
- Static MAC assignment.
- VM Notes ownership metadata.
- VM start, stop, exact storage deletion, and time synchronization settings.
- Host capacity and resource preflight.

### 5.3 Orchestrator agent

The integrated Linux agent gains an appliance manager. It owns:

- Appliance SQLite state.
- Generated systemd-networkd configuration for private NICs.
- Main-interface discovery and DNS resolver snapshots.
- The complete nftables ruleset.
- Per-VM NAT state and draining transitions.
- Relay listener lifecycle and metrics.
- Generation-checked appliance RPCs.

Appliance restoration completes before `GetInfo` reports
`appliance_ready=true`.

### 5.4 Isolated guest

The guest contains the existing LabLink agent and static network settings.
There is no guest-side relay component. Reconciliation uses the guest agent
through its orchestrator relay.

## 6. State ownership and SQLite schema

### 6.1 Hybrid state model

The existing `nodes.json` registry remains the compatibility surface for
generic LabLink tools. It continues to use the cross-process sidecar lock and
atomic replacement in `internal/registry/registry.go`.

The registry is already cross-process safe: reads reload after another process
writes, and read-modify-write cycles use the OS sidecar lock plus atomic
rename. Isolated work must not add another registry lock or bypass these
methods.

New state is stored in:

```text
<LABLINK_HOME>\isolated.db
```

The database is shared by all LabLink server processes on that developer box.
It uses modernc SQLite with:

```sql
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;
```

Writes start with `BEGIN IMMEDIATE`. Schema migrations use a single
monotonic `schema_version`.

The orchestrator stores appliance state at:

```text
/var/lib/lablink-agent/isolated-appliance.db
```

That database is authoritative for live network generations, relay mappings,
listener bind state, and NAT state. The server database contains desired
state, allocations, operation history, and the last confirmed appliance
generation.

The appliance, not any one server database, is the allocation authority.
Separate LabLink servers may have unrelated `isolated.db` files. A server may
propose a subnet, IP, MAC, relay port, or capacity reservation, but the
appliance accepts or rejects the complete reservation in one SQLite
transaction. The server commits/imports the returned reservation only after
the appliance has accepted it. This prevents two trusted servers with
independent databases from allocating the same live value.

### 6.2 Server schema

The initial schema is:

```sql
CREATE TABLE schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE orchestrators (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    physical_host_id TEXT NOT NULL,
    host_node TEXT NOT NULL,
    hyperv_name TEXT NOT NULL UNIQUE,
    hyperv_vm_id TEXT,
    node_name TEXT NOT NULL UNIQUE,
    profile_name TEXT NOT NULL,
    main_vswitch TEXT NOT NULL,
    main_mac TEXT,
    main_ip TEXT,
    agent_port INTEGER NOT NULL DEFAULT 9091,
    appliance_schema INTEGER NOT NULL DEFAULT 0,
    desired_generation INTEGER NOT NULL DEFAULT 0,
    applied_generation INTEGER NOT NULL DEFAULT 0,
    observed_generation INTEGER NOT NULL DEFAULT 0,
    host_fence INTEGER NOT NULL DEFAULT 0,
    lifecycle_state TEXT NOT NULL,
    health_state TEXT NOT NULL DEFAULT 'unknown',
    max_networks INTEGER NOT NULL DEFAULT 16,
    max_vms INTEGER NOT NULL DEFAULT 100,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    last_seen_unix INTEGER,
    CHECK (lifecycle_state IN
      ('planned','creating','customizing','ready','recovering','degraded','frozen',
       'deleting','lost','deleted'))
);

CREATE INDEX idx_orchestrators_host_age
    ON orchestrators(physical_host_id, created_at_unix);

CREATE TABLE private_networks (
    id TEXT PRIMARY KEY,
    orchestrator_id TEXT NOT NULL REFERENCES orchestrators(id),
    display_name TEXT NOT NULL,
    hyperv_switch_name TEXT NOT NULL,
    hyperv_switch_guid TEXT,
    orchestrator_adapter_id TEXT,
    subnet_index INTEGER NOT NULL,
    cidr TEXT NOT NULL,
    gateway_ipv4 TEXT NOT NULL,
    orchestrator_mac TEXT NOT NULL,
    dns_servers_json TEXT NOT NULL,
    desired_generation INTEGER NOT NULL,
    applied_generation INTEGER NOT NULL DEFAULT 0,
    observed_generation INTEGER NOT NULL DEFAULT 0,
    lifecycle_state TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    retired_at_unix INTEGER,
    CHECK (subnet_index >= 0 AND subnet_index < 64),
    CHECK (lifecycle_state IN
      ('allocating','creating','ready','degraded','deleting','deleted'))
);

CREATE TABLE isolated_vms (
    id TEXT PRIMARY KEY,
    orchestrator_id TEXT NOT NULL REFERENCES orchestrators(id),
    network_id TEXT NOT NULL REFERENCES private_networks(id),
    display_name TEXT NOT NULL,
    hyperv_name TEXT NOT NULL,
    hyperv_vm_id TEXT,
    hyperv_adapter_id TEXT,
    incarnation INTEGER NOT NULL DEFAULT 1,
    node_name TEXT NOT NULL,
    guest_os TEXT NOT NULL CHECK (guest_os IN ('windows','linux')),
    profile_name TEXT NOT NULL,
    ipv4 TEXT NOT NULL,
    mac TEXT NOT NULL,
    prefix_length INTEGER NOT NULL DEFAULT 26,
    gateway_ipv4 TEXT NOT NULL,
    dns_servers_json TEXT NOT NULL,
    storage_root TEXT NOT NULL,
    vm_path TEXT NOT NULL,
    vhd_path TEXT NOT NULL,
    desired_generation INTEGER NOT NULL,
    applied_generation INTEGER NOT NULL DEFAULT 0,
    observed_generation INTEGER NOT NULL DEFAULT 0,
    lifecycle_state TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    retired_at_unix INTEGER,
    CHECK (lifecycle_state IN
      ('allocating','creating','provisioning','ready','repairing','degraded',
       'deleting','deleted'))
);

CREATE TABLE relay_allocations (
    id TEXT PRIMARY KEY,
    vm_id TEXT NOT NULL REFERENCES isolated_vms(id),
    orchestrator_id TEXT NOT NULL REFERENCES orchestrators(id),
    listen_port INTEGER NOT NULL,
    target_ipv4 TEXT NOT NULL,
    target_port INTEGER NOT NULL DEFAULT 9091,
    desired_generation INTEGER NOT NULL,
    applied_generation INTEGER NOT NULL DEFAULT 0,
    observed_generation INTEGER NOT NULL DEFAULT 0,
    lifecycle_state TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    retired_at_unix INTEGER,
    CHECK (listen_port BETWEEN 20000 AND 39999),
    CHECK (target_port = 9091),
    CHECK (lifecycle_state IN
      ('allocated','binding','ready','degraded','retiring','removing','removed'))
);

CREATE TABLE nat_allocations (
    vm_id TEXT PRIMARY KEY REFERENCES isolated_vms(id),
    orchestrator_id TEXT NOT NULL REFERENCES orchestrators(id),
    desired_state TEXT NOT NULL,
    observed_state TEXT NOT NULL,
    conntrack_mark INTEGER NOT NULL,
    desired_generation INTEGER NOT NULL,
    applied_generation INTEGER NOT NULL DEFAULT 0,
    observed_generation INTEGER NOT NULL DEFAULT 0,
    drain_started_unix INTEGER,
    updated_at_unix INTEGER NOT NULL,
    CHECK (desired_state IN ('enabled','disabled')),
    CHECK (observed_state IN ('enabled','draining','disabled'))
);

CREATE TABLE active_resource_allocations (
    kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    value TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    appliance_reservation_id TEXT NOT NULL,
    allocated_at_unix INTEGER NOT NULL,
    PRIMARY KEY(kind, scope_id, value),
    UNIQUE(kind, resource_id)
);

CREATE TABLE resource_allocation_history (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    value TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    appliance_reservation_id TEXT NOT NULL,
    allocated_at_unix INTEGER NOT NULL,
    released_at_unix INTEGER NOT NULL,
    release_operation_id TEXT NOT NULL
);

CREATE UNIQUE INDEX uq_live_network_switch_name
    ON private_networks(hyperv_switch_name)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_live_network_subnet
    ON private_networks(orchestrator_id, subnet_index)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_live_network_mac
    ON private_networks(orchestrator_id, orchestrator_mac)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_live_vm_hyperv_name
    ON isolated_vms(hyperv_name)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_live_vm_node_name
    ON isolated_vms(node_name)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_live_vm_ip
    ON isolated_vms(orchestrator_id, ipv4)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_live_vm_mac
    ON isolated_vms(orchestrator_id, mac)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_live_relay_vm
    ON relay_allocations(vm_id)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_live_relay_port
    ON relay_allocations(orchestrator_id, listen_port)
    WHERE retired_at_unix IS NULL;

CREATE TABLE guest_pending_updates (
    vm_id TEXT NOT NULL REFERENCES isolated_vms(id),
    update_kind TEXT NOT NULL,
    desired_generation INTEGER NOT NULL,
    payload_json TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    last_attempt_unix INTEGER,
    last_error TEXT,
    PRIMARY KEY(vm_id, update_kind)
);

CREATE TABLE operations (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    host_node TEXT,
    orchestrator_id TEXT,
    network_id TEXT,
    argument_hash TEXT NOT NULL,
    request_json TEXT NOT NULL,
    plan_revision TEXT,
    status TEXT NOT NULL,
    current_phase TEXT NOT NULL,
    result_json TEXT,
    error_code TEXT,
    error_text TEXT,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    finished_at_unix INTEGER,
    CHECK (status IN
      ('planned','approval_required','running','paused','succeeded',
       'failed','cancelled'))
);

CREATE TABLE operation_phases (
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    phase_index INTEGER NOT NULL,
    phase_name TEXT NOT NULL,
    generation INTEGER,
    status TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    started_at_unix INTEGER,
    finished_at_unix INTEGER,
    detail_json TEXT,
    error_text TEXT,
    PRIMARY KEY(operation_id, phase_index, attempt),
    CHECK (status IN
      ('pending','running','succeeded','failed','skipped'))
);

CREATE TABLE operation_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    at_unix INTEGER NOT NULL,
    phase_name TEXT,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    detail_json TEXT
);

CREATE INDEX idx_operation_events_operation
    ON operation_events(operation_id, seq);

CREATE TABLE approval_plans (
    revision TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    plan_hash TEXT NOT NULL,
    state TEXT NOT NULL,
    approved_at_unix INTEGER,
    consumed_at_unix INTEGER,
    CHECK (state IN ('pending','approved','consumed','superseded'))
);

CREATE TABLE locks (
    lock_key TEXT PRIMARY KEY,
    holder_cookie TEXT NOT NULL,
    holder_hostname TEXT NOT NULL,
    holder_pid INTEGER NOT NULL,
    holder_process_start_unix INTEGER NOT NULL,
    operation_id TEXT NOT NULL,
    fence INTEGER NOT NULL,
    acquired_at_unix INTEGER NOT NULL,
    heartbeat_at_unix INTEGER NOT NULL,
    expires_at_unix INTEGER NOT NULL
);
```

`active_resource_allocations` is only a local mirror of appliance-confirmed
reservations. Release moves a row to `resource_allocation_history` and deletes
the active row in one transaction. Typed rows retain tombstones and foreign
keys, while partial unique indexes apply only to live rows. Therefore a
deleted subnet, IP, MAC, node name, Hyper-V name, or relay port can be safely
reused without deleting history.

### 6.3 Appliance schema

The orchestrator database contains only live appliance resources:

```sql
CREATE TABLE appliance_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE networks (
    id TEXT PRIMARY KEY,
    cidr TEXT NOT NULL,
    gateway_ipv4 TEXT NOT NULL,
    nic_mac TEXT NOT NULL,
    interface_name TEXT,
    dns_servers_json TEXT NOT NULL,
    desired_generation INTEGER NOT NULL,
    applied_generation INTEGER NOT NULL,
    observed_generation INTEGER NOT NULL,
    parent_generation INTEGER NOT NULL,
    state TEXT NOT NULL,
    retired_at_unix INTEGER
);

CREATE TABLE guests (
    id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(id),
    ipv4 TEXT NOT NULL,
    mac TEXT NOT NULL,
    desired_generation INTEGER NOT NULL,
    applied_generation INTEGER NOT NULL,
    observed_generation INTEGER NOT NULL,
    parent_generation INTEGER NOT NULL,
    retired_at_unix INTEGER
);

CREATE TABLE relays (
    id TEXT PRIMARY KEY,
    vm_id TEXT NOT NULL REFERENCES guests(id),
    listen_port INTEGER NOT NULL,
    target_ipv4 TEXT NOT NULL,
    target_port INTEGER NOT NULL CHECK(target_port = 9091),
    desired_generation INTEGER NOT NULL,
    applied_generation INTEGER NOT NULL,
    observed_generation INTEGER NOT NULL,
    parent_generation INTEGER NOT NULL,
    state TEXT NOT NULL,
    bound_main_ip TEXT,
    last_bind_error TEXT,
    retired_at_unix INTEGER
);

CREATE TABLE nat_state (
    vm_id TEXT PRIMARY KEY REFERENCES guests(id),
    state TEXT NOT NULL,
    conntrack_mark INTEGER NOT NULL,
    desired_generation INTEGER NOT NULL,
    applied_generation INTEGER NOT NULL,
    observed_generation INTEGER NOT NULL,
    parent_generation INTEGER NOT NULL,
    drain_started_unix INTEGER,
    CHECK(state IN ('enabled','draining','disabled'))
);

CREATE UNIQUE INDEX uq_appliance_live_network_mac
    ON networks(nic_mac)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_appliance_live_guest_ip
    ON guests(network_id, ipv4)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_appliance_live_guest_mac
    ON guests(mac)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_appliance_live_relay_vm
    ON relays(vm_id)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_appliance_live_relay_port
    ON relays(listen_port)
    WHERE retired_at_unix IS NULL;

CREATE TABLE applied_operations (
    mutation_id TEXT PRIMARY KEY,
    parent_operation_id TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    result_json TEXT NOT NULL,
    applied_at_unix INTEGER NOT NULL
);

CREATE TABLE reservations (
    id TEXT PRIMARY KEY,
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    network_id TEXT,
    subnet_index INTEGER,
    ipv4 TEXT,
    mac TEXT,
    listen_port INTEGER,
    conntrack_mark INTEGER,
    state TEXT NOT NULL,
    parent_generation INTEGER NOT NULL,
    created_at_unix INTEGER NOT NULL,
    retired_at_unix INTEGER
);

CREATE UNIQUE INDEX uq_appliance_live_subnet
    ON reservations(subnet_index)
    WHERE subnet_index IS NOT NULL AND retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_appliance_live_ip
    ON reservations(network_id, ipv4)
    WHERE ipv4 IS NOT NULL AND retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_appliance_live_mac
    ON reservations(mac)
    WHERE mac IS NOT NULL AND retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_appliance_live_port
    ON reservations(listen_port)
    WHERE listen_port IS NOT NULL AND retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_appliance_live_conntrack_mark
    ON reservations(conntrack_mark)
    WHERE conntrack_mark IS NOT NULL AND retired_at_unix IS NULL;

CREATE TABLE apply_intents (
    mutation_id TEXT PRIMARY KEY,
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    desired_generation INTEGER NOT NULL,
    parent_generation INTEGER NOT NULL,
    fence INTEGER NOT NULL,
    semantic_hash TEXT NOT NULL,
    compiled_hash TEXT,
    phase TEXT NOT NULL,
    error_text TEXT,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);
```

`applied_operations` provides appliance-side idempotency. Reusing a mutation
ID with a different semantic hash is rejected.

### 6.4 Authoritative reservation protocol

Allocation is a two-authority handshake, with the appliance deciding live
uniqueness:

1. The server canonicalizes host/orchestrator/network identity and reads the
   appliance inventory generation.
2. Under its local allocation lock, it chooses candidate values from the
   appliance's advertised free sets. The local database is only a cache.
3. `ReserveResources` sends all candidates, the expected parent generation,
   host fence, mutation ID, and semantic hash.
4. The appliance starts `BEGIN IMMEDIATE`, verifies the orchestrator is not
   frozen/deleting, verifies parent generation and fence, rechecks capacity,
   and inserts every reservation atomically.
5. On success it returns a reservation ID, resulting parent generation, and
   exact accepted values. The server imports those values into its local
   database.
6. On collision it returns `SUBNET_IN_USE`, `IP_IN_USE`, `MAC_IN_USE`,
   `PORT_IN_USE`, `CONNTRACK_MARK_IN_USE`, or `CAPACITY_EXHAUSTED`, plus current
   inventory generation and a redacted inventory summary. The server refreshes
   inventory and may propose another candidate only for automatic selection.
   An explicit requested value fails without substitution.

`GetApplianceState` supports paged discovery of all live and tombstoned
resources with immutable IDs and generations. A server with an empty or
different local database imports exact appliance records before mutation.
Import never changes live state. If server and appliance records disagree,
the appliance wins for subnet/IP/port/capacity and the host wins for Hyper-V
object identity; reconciliation records the discrepancy rather than merging
by display name.

Reservation recovery is deterministic:

- Appliance reservation present, local row absent: import it.
- Local row present, appliance reservation absent, no host object: retire the
  local row.
- Local row present, appliance reservation absent, host object present: mark
  `reservation_lost` and block mutation until explicit reconcile/adopt.
- Reservation present but host creation uncertain: inspect exact host IDs,
  then continue or retain for exact resume.
- A relay-port reservation is released after the relay-only barrier in
  Section 9.5; live VM absence is not required. Guest IP/MAC/conntrack-mark
  reservations require exact VM absence. Subnet and orchestrator-private-MAC
  reservations require exact network adapter and switch absence.

### 6.5 Generation rules

Every mutation carries:

- Immutable resource ID.
- Stable mutation ID derived from the parent operation.
- Canonical request hash.
- Expected generation.
- New generation.

Create uses generation 1; an absent resource is generation 0. Update and
remove increment by one. Remove commits a tombstone at the incremented
generation. Repair/recreate preserves the resource ID, increments
`incarnation`, and increments generation rather than resetting it. A new
resource after retirement receives a new immutable ID even if it reuses a
subnet, IP, name, or port.

Child mutations also carry the expected parent generation. The appliance
applies a mutation only when:

1. The operation has already been applied with the same hash, in which case
   the stored result is returned; or
2. The resource generation equals `expected_generation` and
   `new_generation == expected_generation + 1`.

Any other case returns `GENERATION_CONFLICT`,
`PARENT_GENERATION_CONFLICT`, `FENCE_REJECTED`, or `PARENT_FROZEN` with
current live state. The server must reconcile before retrying. Display-name
changes do not increment appliance generations because display names are not
appliance state.

## 7. Protobuf and agent capabilities

### 7.1 Additive `GetInfo` fields

`proto/agent/agent.proto` extends `GetInfoResponse` additively:

```proto
message GetInfoResponse {
  // Existing fields 1-6 remain unchanged.
  repeated string capabilities = 7;
  uint32 protocol_version = 8;
  bool appliance_ready = 9;
  uint64 appliance_generation = 10;
  string appliance_error = 11;
}
```

Initial capability strings:

```text
isolated.appliance.v1
isolated.network.v1
isolated.relay.v1
isolated.nat.v1
isolated.stats.v1
isolated.authority-release.v1
isolated.parent-lifecycle.v1
```

The isolated-appliance protocol version is **2**. Protocol v2 makes
`ReleaseApplianceAuthority` and `SetApplianceParentLifecycle` mandatory.
Servers reject protocol v1 appliances with an explicit upgrade-required
compatibility error before acquiring a physical-host fence.
Ordinary non-appliance agents remain on the ordinary LabLink contract; only
isolated-orchestrator workflows require protocol v2 and the complete capability
set.

The server requires the complete set for an orchestrator. An existing node
with missing capabilities is not partially used. The tool returns
`AGENT_CAPABILITY_MISSING`, the missing strings, current agent version, server
version, and explicit `update_agent(node=<orchestrator-node>)` guidance.

### 7.2 Appliance RPCs

The existing `NodeAgent` service gains structured RPCs rather than encoding
appliance mutations in arbitrary shell:

```proto
rpc GetApplianceState(GetApplianceStateRequest)
    returns (GetApplianceStateResponse);
rpc ReserveResources(ReserveResourcesRequest)
    returns (ReserveResourcesResponse);
rpc ReleaseResources(ReleaseResourcesRequest)
    returns (ReleaseResourcesResponse);
rpc ReleaseApplianceAuthority(MutationHeader) returns (FenceState);
rpc ApplyPrivateNetwork(ApplyPrivateNetworkRequest)
    returns (ApplyPrivateNetworkResponse);
rpc RemovePrivateNetwork(RemovePrivateNetworkRequest)
    returns (RemovePrivateNetworkResponse);
rpc RegisterIsolatedGuest(RegisterIsolatedGuestRequest)
    returns (RegisterIsolatedGuestResponse);
rpc RemoveIsolatedGuest(RemoveIsolatedGuestRequest)
    returns (RemoveIsolatedGuestResponse);
rpc ApplyRelay(ApplyRelayRequest) returns (Relay);
rpc RemoveRelay(RemoveRelayRequest) returns (Relay);
rpc ListRelays(ListRelaysRequest) returns (ListRelaysResponse);
rpc GetRelayStats(GetRelayStatsRequest) returns (GetRelayStatsResponse);
rpc RebindRelays(RebindRelaysRequest) returns (RebindRelaysResponse);
rpc ValidateRelay(ValidateRelayRequest) returns (ValidateRelayResponse);
rpc AdoptRelay(AdoptRelayRequest) returns (Relay);
rpc SetNatState(SetNatStateRequest) returns (NatState);
rpc ListNatState(ListNatStateRequest) returns (ListNatStateResponse);
rpc ReconcileNat(ReconcileNatRequest) returns (ReconcileNatResponse);
```

Every mutating request includes a common mutation header:

```proto
message MutationHeader {
  string parent_operation_id = 1;
  string mutation_id = 2;
  string semantic_hash = 3;
  string resource_id = 4;
  uint64 expected_generation = 5;
  uint64 new_generation = 6;
  string physical_host_id = 7;
  uint64 host_fence = 8;
  string parent_resource_id = 9;
  uint64 expected_parent_generation = 10;
  string host_lease_id = 11;
  bytes host_lease_secret = 12;
  string cascade_operation_id = 13;
  string cascade_plan_revision = 14;
  string cascade_plan_hash = 15;
  string cascade_item_id = 16;
  int64 host_lease_expires_unix = 17;
}
```

`host_lease_secret` is transport-only concurrency material. It is never
persisted by the server, hashed into operation semantics, logged, audited, or
returned by tools. Host and appliance persist only its cryptographic hash.
The appliance persists the exact host lease expiry, rejects expired leases,
and requires physical host ID, lease ID, secret hash, and expiry to match on
equal-fence requests. Before releasing a physical-host lease, the server calls
`ReleaseApplianceAuthority`; successful revocation blocks the old fence until
a strictly newer authenticated fence is installed. A zero expiry is accepted
only while bootstrapping the initial unclaimed authority row.

Lease state is exclusively a control-plane mutation-admission concern.
Expiry, release, or handoff causes no relay, NAT, VM, network, drain, retire,
freeze, or other lifecycle transition. After an explicit configuration command
commits, the appliance keeps running that static durable configuration without
an AI/MCP/server lease. Relay listeners, NAT forwarding, established conntrack
draining, statistics, and reboot restoration do not inspect lease presence.
Configuration changes occur only through a later authenticated explicit
mutation; repair/reconcile runs only when explicitly requested, apart from
startup restoration of the same persisted configuration.

`ApplyRelayRequest` contains `vm_id`, `network_id`, `listen_port`,
`target_ipv4`, and no target-port input. The implementation always uses 9091.

`GetRelayStatsResponse` contains:

- Listener state and bind address.
- Active and total accepted connections.
- Bytes guest-to-main and main-to-guest.
- Last successful connection time.
- Target dial failure count and last failure.
- Relay and appliance generations.

No RPC returns payload data.

### 7.3 Startup readiness

In `cmd/lablink-agent/main.go`, Linux startup becomes:

1. Load ordinary agent configuration.
2. Before enabling IPv4 forwarding, load the built-in emergency nftables
   policy that drops all forwarded traffic.
3. If appliance mode is configured, open and migrate appliance SQLite.
4. Preserve persisted `draining` NAT rows and their marked conntrack flows.
   The background appliance system transition completes them to `disabled`
   only after exact guest/network/generation/mark validation and a zero
   conntrack count; no external host lease is impersonated.
5. Recover incomplete apply intents using the protocol in Section 7.4.
6. Reconcile private NIC networkd files and interface addresses.
7. Rebuild, validate, and atomically load the complete nftables ruleset.
8. Enable IPv4 forwarding only after the valid ruleset is active.
9. Restore relay listeners and verify their bind state.
10. Start the gRPC server and report `appliance_ready=true`.

If restoration fails, the service may expose diagnostics with
`appliance_ready=false`, but health and selection logic must not treat it as a
healthy compatible orchestrator. Independently of readiness, the emergency
rules remain installed and IPv4 forwarding remains disabled. Readiness is an
observability signal, not the security boundary.

### 7.4 Appliance intent/apply/verify/commit protocol

Every network, NAT, listener, or interface mutation uses this crash protocol:

1. **Intent transaction.** Under `BEGIN IMMEDIATE`, validate mutation ID,
   semantic hash, host fence, parent state/generation, resource generation,
   reservation, and any cascade authority. A frozen/deleting parent is valid
   only when the installed approved item exactly matches item ID, resource
   kind/ID, action, and expected generation. Those cascade fields are persisted
   in `apply_intents` and survive recovery. Write desired rows and the intent,
   then commit.
2. **Compile.** Under the appliance ruleset mutex, read one consistent SQLite
   snapshot containing the complete desired topology. Compile networkd files,
   nftables text, listener delta, and a `compiled_hash` over the snapshot
   generation and canonical desired rows.
3. **Admission and pre-apply fence.** Enter the appliance target-side mutation
   gate described in Section 16.4. While holding it, reopen a read transaction
   immediately before external mutation. Verify the intent is still current,
   no handoff/freeze is pending, the lease/fence and parent generation still
   match, and the desired snapshot hash still equals `compiled_hash`.
   Otherwise leave the gate, discard the compilation, and restart from the
   latest snapshot.
4. **Apply while fenced.** Continue holding the same gate while writing files
   through create-fsync-rename, validate nftables with
   `nft --check`, atomically load the full ruleset, perform targeted networkd
   reload/reconfigure, and start/retire/rebind listeners.
5. **Observe.** Read kernel nftables state, sysctls, routes, addresses,
   interface MACs, listener sockets, and conntrack state. Observation must
   match the exact desired generation while the gate is still held.
6. **Commit.** In one SQLite transaction, verify the same fence and desired
   generation, then advance `applied_generation` and
   `observed_generation`, persist the result in `applied_operations`, and
   complete the intent. Release the target-side gate only after commit.

A crash before intent commit has no effect. A crash after intent commit leaves
a recoverable intent. A crash after external apply but before commit is
resolved by observing exact external state and either committing it or
reapplying the same generation. External artifacts include the resource ID,
generation, and compiled hash where their format permits comments or sidecar
metadata.

The agent never commits an older compiled snapshot after a newer desired
generation. `appliance_ready=true` requires every non-retired resource to have
`desired_generation == applied_generation == observed_generation`, a valid
full policy, correct forwarding sysctl, verified private interfaces, and
healthy required listeners. Failure leaves the fail-closed emergency policy
or the last verified policy active and reports the incomplete intent.

## 8. Connection resolution and registry changes

### 8.1 JSON compatibility

No required field is added to `registry.Node`. Isolated metadata uses the
existing `Labels map[string]string`:

```text
lablink.kind=isolated-orchestrator|isolated-vm
lablink.orchestrator_id=<uuid>
lablink.network_id=<uuid>          # guest only
lablink.isolated_vm_id=<uuid>      # guest only
lablink.relay_id=<uuid>            # guest only
lablink.display_name=<mutable text>
```

Old LabLink releases ignore these labels and can still parse `nodes.json`.
If implementation needs optional typed fields in addition to labels, they must
use `omitempty`, preserve unknown/absent-value behavior, and round-trip through
the existing YAML import/export tools. No isolated field may become required
for loading an older registry.

`TLSServerName` is specifically part of the compatibility contract. YAML
export writes optional `tls_server_name` whenever it is non-empty; YAML import
restores it exactly. It must not be derived from `Address`, because an isolated
guest's address names the orchestrator relay while its strict TLS identity
names the guest. Import/export tests must round-trip a relayed guest and then
complete a strict certificate-name verification through
`agentclient.Pool`.

### 8.2 Orchestrator registry entry

The orchestrator is an ordinary Linux node:

```text
Name:          immutable deterministic node name
Address:       <main-ip>:9091
TLSServerName: immutable node name
Role:          isolated-orchestrator
```

### 8.3 Guest registry entry

An isolated guest is registered as:

```text
Name:          immutable deterministic node name
Address:       <orchestrator-main-ip>:<allocated-relay-port>
TLSServerName: immutable guest node name
Role:          isolated-vm
```

The existing agent client already separates address from TLS server name, so
guest mTLS remains end to end through the byte relay.

### 8.4 Main IP changes

Relay listeners bind to the main NIC address observed when the appliance
starts. There is no runtime address watcher. A changed DHCP address takes
effect after an appliance restart or an explicit `rebind_isolated_relays`
operation.

The LabLink server does not silently rewrite registry addresses. The operator
invokes `reconcile_isolated_orchestrator`, which:

1. Obtains the current main IPv4 through the Hyper-V host or the still-working
   orchestrator connection.
2. Authenticates the orchestrator by immutable TLS name.
3. Updates the orchestrator registry address.
4. Updates every child guest registry address to the same IP and its
   persistent relay port.
5. Resets affected pooled gRPC connections.

This is the required manual, user-invoked address reconciliation.

### 8.5 Stable physical host identity and aliases

The registry node name is an alias, not physical host identity. On first
isolated preflight, the Windows host returns:

- `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`.
- `Win32_ComputerSystemProduct.UUID`.
- Windows installation and Hyper-V host version facts.

`physical_host_id` is the lowercase SHA-256 of a versioned canonical tuple of
MachineGuid and SMBIOS UUID. Placeholder, all-zero, all-`F`, or missing values
fail preflight instead of falling back to hostname. Reimage legitimately
changes host identity and is treated as a different host; migration is not
inferred.

Every registry alias used for a target is resolved to and persisted against
this ID. Case differences, DNS aliases, renamed registry nodes, `localhost`,
and alternate addresses are canonicalized before lock or allocation keys are
formed. Two aliases resolving to the same physical ID cannot create separate
orchestrator pools. An alias resolving to a different physical ID returns
`HOST_IDENTITY_CHANGED` and requires explicit operator reconciliation; it
never silently retargets resources.

## 9. Relay implementation

### 9.1 Listener manager

The relay manager is integrated into the Linux agent. It is not a separate
daemon. Each relay has one persistent port in `20000-39999`.

Listeners bind to the current unicast IPv4 address of the main interface, not
to a private interface. Startup restores every persisted listener on the
address observed at that time. Explicit rebind performs bind-new then
close-old; if bind-new fails, the old listener remains active and health
reports the failure.

The orchestrator firewall opens TCP 20000-39999 on the main interface. Only
ports with active listeners accept connections.

### 9.2 Data path

For each accepted connection:

1. Validate that the relay mapping still references a registered guest.
2. Dial exactly `<guest-static-ip>:9091`.
3. Copy bytes in both directions using fixed 64 KiB buffers.
4. Propagate half-close with `CloseWrite`.
5. Continue the opposite direction until it closes.

There is:

- No TLS termination.
- No PROXY header.
- No payload logging.
- No idle timeout.
- No application connection cap.
- No retry of an established connection onto another target.

Socket backpressure is the flow-control mechanism. Listener backlog,
file-descriptor limits, and memory pressure remain operating-system resource
limits and are surfaced by telemetry.

### 9.3 Relay identity and adoption

A relay can be adopted only when:

- Its immutable relay ID is supplied.
- The live mapping targets an existing immutable guest ID.
- The target IP equals the guest's live appliance allocation.
- The port is not allocated to another relay.
- Target port is 9091.
- The caller supplies the observed live generation.

Adoption imports an already-live mapping into the server database. It cannot
retarget a relay. Retargeting requires remove plus create with a new
generation.

A trusted LabLink server on another developer machine does not receive an
automatic copy of the first machine's control database. It can query live
appliance state and explicitly adopt exact resources because authorization is
not owner-scoped. This is reconciliation, not database replication or backup.

### 9.4 Telemetry

Per relay and aggregate telemetry includes:

- Bind/listener health.
- Bound main IPv4.
- Active connections.
- Total accepted connections.
- Bytes in each direction.
- Last successful target connection.
- Target dial failures and last error.
- Relay generation and appliance generation.

Counters reset on agent restart; generation and persistent mapping do not.

### 9.5 Rebind versus retirement barrier

Rebind and removal are different operations.

**Rebind** preserves the relay allocation and mapping. The manager binds the
same port on the new main address, switches new accepts to the new listener,
then closes only the old listening socket. Existing accepted connections
continue on their original sockets. Mapping generation is unchanged; bind
generation and observed main address advance.

**Relay-only retirement** removes a relay from a live VM and releases only the
listener/port allocation:

1. Mark the relay `retiring` in appliance SQLite under the current fence.
2. Remove it from the accept/dial registry and close the listening socket, so
   no new connection can be accepted or target dial started.
3. Reset every matching local `agentclient.Pool` connection after the registry
   entry is removed or made unavailable. Other trusted servers see
   `retiring` from appliance discovery and must also stop dialing.
4. Allow already accepted relay connections to half-close and drain during a
   bounded grace period. When the grace period expires, close both copies of
   each remaining connection and wait for the copy loops to terminate. The
   port remains reserved until active connection count reaches zero.
5. Verify zero active relay connections, no listener, and no in-progress dial.
6. Tombstone the relay mapping, move only the relay-port allocation to
   history, and make that port reusable.

Relay-only retirement does not require VM absence and does not delete NAT
conntrack entries. The live VM keeps its IP, MAC, conntrack mark, network,
storage, and NAT state. Its registry entry is removed or marked unreachable
before pooled clients are reset.

**VM retirement** first completes the relay-only barrier, then disables new
NAT flows, deletes flows with the VM's exact conntrack mark, removes the exact
Hyper-V VM/storage, and only after verified VM absence releases the guest IP,
guest MAC, conntrack mark, and VM capacity slot.

**Network retirement** is permitted only after every VM retirement is
complete. It removes the orchestrator interface and exact private switch, then
releases the subnet and orchestrator-private-NIC MAC. Orchestrator cascade
deletion applies these barriers in child-to-parent order.

Cancellation closes remaining relay copies promptly but leaves the durable
relay and port in `retiring`; exact resume completes the tombstone and release.
An uncancelled deletion force-closes connections after the grace period and
continues once zero active copies are verified.

## 10. Linux networking, nftables, NAT, draining, and DNS

### 10.1 Main NIC

The main NIC remains managed by the existing Ubuntu image configuration and
keeps normal connectivity. Appliance customization must not replace its DHCP
or static policy.

The agent records:

- Main-interface MAC and name.
- Current main IPv4 addresses.
- Default route.
- Resolver addresses from systemd-resolved or the effective resolver file.

Before reserving a subnet, the appliance compares it with every main-link IPv4
address prefix and every non-default destination route. The literal
`0.0.0.0/0` default route is excluded from overlap testing; it represents
upstream reachability and must not collide with every candidate `/26`.

Collision inputs include connected prefixes, static routes, DHCP classless
routes, policy-table routes with destination prefix other than `/0`, and
specific host routes, including a host route to a default gateway. "Associated
with the default route" does not mean expanding its next hop to all IPv4
space. Only the default destination prefix itself is ignored.

CIDR overlap uses interval math, not string-prefix comparison. An overlapping
`/26` is reserved as `main_route_conflict` and is never offered. If a specific
non-default route such as `192.168.240.0/20` or a covering prefix overlaps the
entire pool, the orchestrator has zero network capacity. Existing networks
that become overlapped are marked degraded and block new child creation; they
are not silently renumbered. There is no hidden VRF, policy routing, or
namespace workaround.

### 10.2 Private NICs

The Hyper-V host assigns a deterministic, locally administered, unicast MAC
derived from the network immutable ID and collision-checked in SQLite.

The agent writes one generated systemd-networkd file per private NIC, matched
by MAC, for example:

```ini
[Match]
MACAddress=02:4c:4c:12:34:56

[Network]
Address=192.168.240.1/26
IPv6AcceptRA=no
LinkLocalAddressing=no
```

Generated files live under `/etc/systemd/network` with an immutable-ID-based
name. Removing a network removes only its exact generated file after the host
NIC and switch are removed.

Disabling IPv6 in generated private-NIC configuration reduces accidental use
but does not create an IPv6 isolation guarantee.

The generic Linux seed currently emits a Netplan match for all `hv_netvsc`
interfaces. Appliance customization must remove that ambiguity before a
private NIC is hot-added:

1. Discover and persist the main NIC MAC, interface, address source, and
   default route.
2. Replace the generic all-`hv_netvsc` DHCP match with a MAC-scoped main-NIC
   Netplan/networkd definition that preserves its existing behavior.
3. Generate one MAC-scoped `.network` file for each private NIC.
4. Ensure no generic file can match a private MAC first. Because systemd-
   networkd uses the first matching `.network` file, filenames and match
   scopes are verified with `networkctl status` and the effective file path.
5. Use `networkctl reload` followed by targeted
   `networkctl reconfigure <private-interface>`; do not restart all networking.
6. Verify hot-add and reboot paths: main route unchanged, private interface has
   only its expected static IPv4, no DHCP lease, and exact MAC/file identity.

`IPForward=yes` is intentionally absent from networkd files. The appliance
manager alone changes `net.ipv4.ip_forward`, after a valid drop-first nftables
policy is active.

### 10.3 nftables ownership

The appliance owns the entire nftables ruleset and loads it atomically with
`nft -f`. It does not merge with UFW, firewalld, Docker rule management, or
other dynamic rule owners.

Both emergency and full policy files begin with `flush ruleset`; no unmanaged
table is assumed to remain.

Before taking ownership, customization automatically stops, disables, and
masks UFW and firewalld, verifies that each installed service is inactive and
masked, and then detects:

- Docker or another known daemon managing nftables/iptables rules.
- Unknown non-empty rules not carrying the LabLink appliance signature.

The neutralization step is an unconditional, idempotent bootstrap dependency
of both the appliance firewall and agent. Missing packages are ignored.
Failure to neutralize an installed manager, or any conflict found afterward,
fails bootstrap/readiness explicitly; it is not an approval request.

The normative IPv4 policy is one atomically loaded `inet lablink` table:

**Input chain, policy drop**

1. Accept loopback.
2. Drop `ct state invalid`.
3. From a private interface, classify ICMP before any established/related
   acceptance. Accept required IPv4 ICMP control traffic and echo only when
   the packet destination is that interface's exact gateway IPv4. Drop every
   other private-interface ICMP packet regardless of conntrack state,
   including established echo replies or related ICMP errors addressed to an
   orchestrator main/non-gateway IPv4.
4. From a private interface, accept relay TCP replies only when all of these
   are true: `ct state established`, `ct direction reply`, source IPv4 is the
   exact managed guest for an active relay, destination IPv4 is that private
   interface's exact gateway, TCP source port is 9091, and the connection is
   the reply path of an orchestrator-originated local relay socket. Then drop
   all other private-interface input, including private-to-local TCP/UDP such
   as DNS or agent port 9091.
5. For non-private input, accept `ct state established,related`.
6. On the main interface, accept TCP 9091 and TCP 20000-39999.
7. On the main interface, accept required IPv4 ICMP control traffic:
   destination-unreachable, fragmentation-needed, time-exceeded,
   parameter-problem, and echo for diagnostics.
8. Drop all other input.

The private-interface ICMP guard and terminal drop occur before both broad
established/related and main-interface ICMP rules. Therefore conntrack state
cannot bypass gateway-only ICMP, while the explicitly scoped relay TCP reply
path remains functional.

**Output chain, policy accept**

Orchestrator-originated management, package, DNS, and relay-to-guest sockets
remain allowed. Relay sockets are local OUTPUT/INPUT traffic and never depend
on the forwarding/NAT chains.

**Forward chain, policy drop**

1. Drop `ct state invalid`.
2. Drop any packet entering one private interface and leaving another private
   interface before established-state handling.
3. Accept established/related packets only when their persisted conntrack
   mark belongs to a VM whose state is `enabled` or `draining`.
4. Accept `ct state new` from a private interface to the main interface only
   for the exact source IPv4 of an `enabled` VM, and set that VM's persisted
   nonzero conntrack mark on the accepted new flow.
5. Do not accept new main-to-private forwarded traffic.
6. Drop all remaining forwarding.

**NAT postrouting**

- Masquerade exact source IPv4/conntrack-mark pairs in `enabled`.
- Retain masquerade for `draining` only until its existing zone is empty.
- Install no masquerade for `disabled`.

The first accepted new forwarded flow receives the VM's persisted nonzero
conntrack mark. Return packets use the same conntrack entry and mark. Draining
and retirement query/delete exact marked entries, with original source IP and
private interface as additional verification. Relay connections are local
sockets with mark 0 and are excluded from NAT flow counting and cleanup.

Same-switch traffic does not traverse the gateway and remains allowed.

### 10.4 Fail-closed boot and activation

The release installs an early
`lablink-appliance-firewall.service` ordered before `network-pre.target`,
`systemd-networkd.service`, and the appliance agent. It atomically loads a
built-in emergency ruleset with forward policy drop and writes
`net.ipv4.ip_forward=0`.

First appliance activation follows the same order: emergency rules first,
then main/private network configuration, then desired-policy apply, then
forwarding enable. Reboot never depends on a user-space readiness flag for
isolation. If the agent is absent, crashes, the database is corrupt, nftables
validation fails, or a ruleset cannot be restored, forwarding remains blocked.
The main interface still permits the orchestrator agent on 9091 for repair.

A successfully restored full policy may keep forwarding enabled across an
agent process crash because the verified kernel rules remain active. A
watchdog unit detects loss of the agent or policy signature and atomically
loads the emergency policy before disabling forwarding. Package update and
service restart ordering must not create a window with forwarding enabled and
no valid policy.

### 10.5 NAT states

`enabled`:

- New IPv4 forwarding is allowed from the VM's exact source IP to reachable
  main-network and internet destinations.
- Masquerade is active.
- DNS to copied main-NIC resolvers is ordinary forwarded traffic.
- Cross-private-network destinations remain blocked.

`draining`:

- Rules allowing new forwarded connections for that VM are removed.
- Established/related return traffic remains accepted.
- Existing conntrack flows drain naturally with no LabLink timeout.
- Relay behavior is unchanged.

`disabled`:

- No new forwarded IPv4 or DNS flow is allowed.
- No masquerade rule exists for the VM.
- Relay behavior is unchanged.

On explicit disable, the state becomes `draining` while flows in that VM's
exact persisted conntrack mark exist and becomes `disabled` when none remain.
On an agent-only restart, draining state and its established-flow rules are
restored before monitoring resumes. On an orchestrator reboot, conntrack state
is gone, so the exact internal system transition observes zero matching flows
and advances the NAT generation to `disabled`.

Persisted `enabled` state survives agent and orchestrator restart, but it is
restored only as part of a verified full ruleset after the emergency drop
policy is active. Persisted `disabled` remains disabled.

### 10.6 DNS behavior

There is no DNS proxy. At network or guest creation, the server snapshots the
orchestrator main NIC's effective IPv4 resolvers and writes those addresses
into guest static configuration.

Resolver extraction is link-specific:

1. Use `resolvectl dns <main-interface>` and, where supported, systemd-
   resolved JSON/status data for that exact link.
2. If resolved is unavailable, read `/run/systemd/resolve/resolv.conf`, not
   the stub `/etc/resolv.conf`.
3. Keep only unicast IPv4 addresses. Reject loopback, especially
   `127.0.0.53`, unspecified, multicast, and private-link gateway addresses.
4. Preserve resolver order and deduplicate, with at most three resolver
   addresses.

Split-DNS routing domains cannot be represented by Windows/Linux static
resolver lists and are not copied. Search domains are copied only when they
are ordinary DNS suffixes, not route-only `~domain` entries, with at most six
suffixes and 256 total characters. Truncation or split-DNS loss is reported in
network status and approval-independent progress.

If no usable upstream IPv4 resolver exists, the network is created with an
empty resolver list and `dns_state=no_upstream_resolver`. Offline/pre-staged
guests may still be created. Any bootstrap declaration requiring DNS, package
download, or domain join fails before guest mutation.

`reconcile_isolated_orchestrator(refresh_dns=true)`:

1. Reads the current effective main-NIC resolvers.
2. Increments affected network and guest desired generations.
3. Updates all online managed guests through their relays.
4. Writes/updates a durable `guest_pending_updates` row for each offline guest
   without changing its immutable allocation.

Pending updates contain the target DNS generation and canonical resolver/search
payload. Guest reconnect, `repair_isolated_vm`, and later DNS reconciliation
retry them idempotently; successful application deletes only the matching
pending row.

With NAT disabled, main-network DNS is normally unreachable. This is expected.

## 11. Hyper-V host controls and metadata

### 11.1 Private switch

Each network uses:

```powershell
New-VMSwitch -Name <immutable-name> -SwitchType Private
```

No management OS adapter is created. Reuse requires an exact name, private
type, and matching ownership metadata. A same-name unmanaged switch is never
adopted by a high-level operation.

After creation, the server persists the Hyper-V switch GUID returned by
`Get-VMSwitch.Id`; name alone is never sufficient for later mutation or
deletion.

### 11.2 VM NICs

The host:

- Adds one NIC to the orchestrator per private network.
- Adds exactly one private NIC to each isolated guest.
- Assigns deterministic static MAC addresses.
- Records network and resource IDs in adapter names and VM Notes.
- Persists and verifies switch GUID, `VMNetworkAdapter.Id`, adapter MAC, and VM
  GUID after every mutation.

The orchestrator main NIC remains first and attached to the existing main
vSwitch. Private adapters are never used as management adapters.

### 11.3 Metadata

Hyper-V VM Notes use separate prefixes:

```text
LABLINK_ISOLATED_ORCHESTRATOR:<compact-json>
LABLINK_ISOLATED_VM:<compact-json>
```

Metadata includes schema version, physical host ID, immutable IDs, host fence,
managed root, expected VHD paths, node name, network ID, IP, MAC, relay ID,
switch GUID, VM GUID, adapter ID, incarnation, and generation.
Private switch ownership is represented by the deterministic name plus a
host-side metadata record under:

```text
%ProgramData%\LabLink\isolated\<orchestrator-id>\networks\<network-id>.json
```

The record is atomically replaced and ACL-restricted to SYSTEM and
Administrators. Deletion requires exact agreement among SQLite, Hyper-V, and
the host metadata record.

After exact NIC and switch deletion succeeds, the deletion workflow removes
only the matching adapter and network metadata files by literal path. After
the orchestrator VM is deleted, it removes the exact orchestrator metadata
root only when no files or unexpected entries remain. Legacy metadata for a
durably deleted/lost orchestrator may be reconciled during a later fenced
create only when the exact VM, switch, and adapter identities are all absent
and every record's physical host, orchestrator ID, resource ID, owner marker,
and file name agree. Any ambiguity or surviving Hyper-V object fails closed.

Every mutating PowerShell script receives expected physical host ID, fence,
resource IDs, switch GUID, VM GUID, adapter ID/MAC, and generation. The script
re-reads and validates them inside the same script immediately before each
`New-*`, `Set-*`, `Connect-*`, `Disconnect-*`, `Remove-*`, or storage
operation. A server-side precheck alone is insufficient. A mismatch returns a
typed ownership/fence error before mutation.

Uncertain-create recovery is exact:

- If `New-VMSwitch`, `Add-VMNetworkAdapter`, or `New-VM` returned no result,
  discovery enumerates candidates by ownership metadata and immutable ID.
- Exactly one matching object with the expected host ID and attributes is
  adopted into the pending phase and its GUID/adapter ID persisted.
- Zero matches means the phase may retry with the same mutation ID.
- Multiple matches or a same-name object with different identity freezes the
  parent resource and requires explicit reconciliation.

Implementation therefore extends `internal/hyperv/vswitch.go`,
`internal/hyperv/nics.go`, and the isolated discovery helpers to return
switch/VM/adapter GUIDs. Delete parameter structs and
`internal/hyperv/delete.go` integration must require expected GUIDs and host
fence, not only names and paths.

### 11.4 Time synchronization

Before every guest start or restart, the host enables the Hyper-V Time
Synchronization integration service. Windows provisioning ensures
`vmictimesync` is enabled. Linux provisioning includes `hv_utils` and enables
the Hyper-V time synchronization path.

The host re-applies the integration-service setting during repair. This
repairs guest time before mTLS readiness checks and avoids relying on guest
internet access.

### 11.5 Storage ownership

The feature extends the exact ownership patterns already used by
`internal/hyperv/delete.go` and `internal/hyperv/linux_vm.go`.

- Every VM has a managed root and exact VM/VHD path persisted before mutation.
- Shared parent images are never deleted.
- `delete_isolated_vm` defaults `delete_storage=true` and deletes only the
  exact owned VM directory and child VHD.
- A mismatch in VM ID, path, parent chain, Notes identity, or ownership record
  fails closed.

## 12. Orchestrator discovery, creation, reuse, recovery, and deletion

### 12.1 Compatibility, health, and operation capacity

These are separate predicates:

**Compatibility** is static until software or host changes:

- Physical host ID matches the request.
- Host is amd64 Windows Server 2022 or 2025, or Windows 11
  Pro/Enterprise 24H2 or 25H2, with Hyper-V enabled, Windows PowerShell 5.1,
  and required Hyper-V cmdlets.
- Orchestrator is Ubuntu 24.04 amd64.
- Required capability strings, protocol range, appliance schema range,
  package manifest, and kernel facilities are supported.
- Hyper-V and appliance immutable identities match.

**Health** is current liveness:

- Host agent is authenticated and reachable.
- Orchestrator VM and main NIC are healthy.
- Orchestrator agent is authenticated, appliance policy is verified, and
  `appliance_ready=true`.
- No unresolved host fence, frozen/deleting parent, route overlap, or apply
  intent failure exists.

**Operation capacity** depends on the requested operation:

- Add network: free `/26`, effective private-adapter slot, switch budget, and
  host resources.
- Add guest to an existing network: free guest IP, MAC, relay port, conntrack
  zone, and total guest slot. It does not require a free network/adapter slot.
- Enable NAT: supported kernel facilities and a free persisted conntrack mark
  already reserved for the VM.
- Rebind/reconcile: no new allocation capacity.

The product ceiling is 16 private networks and 100 guests. Effective network
capacity is:

```text
min(16,
    host_reported_max_synthetic_adapters
      - 1 main adapter
      - other non-LabLink adapters)
```

The host capability probe records the effective adapter budget instead of
assuming the product ceiling is available. Reaching the network/adapter limit
does not prevent adding guests to an existing `/26`.

### 12.2 Selection

For automatic selection:

1. Query orchestrators for the target host ordered by `created_at_unix`
   ascending.
2. Reconcile compatibility, health, and capacity for the requested operation.
3. Select the oldest healthy compatible orchestrator with that operation's
   capacity.
4. If the oldest candidate is offline, attempt recovery before skipping it.
5. If no candidate is usable, run host resource preflight and produce an
   approval-gated creation plan.

Multiple orchestrators per host are allowed when resource preflight passes.

An explicit orchestrator on another host returns
`ORCHESTRATOR_HOST_MISMATCH`. There is no migration fallback.

An explicit orchestrator is never silently replaced by another candidate. It
returns the precise compatibility, health, frozen/deleting, or
operation-capacity failure. Automatic selection may skip a candidate only
after its required offline recovery attempt and records why it was skipped.

### 12.3 Recovery

Recovery checks the host by immutable Hyper-V identity:

- If the VM is Off, start it and wait for its existing main address.
- If Running, verify NICs and KVP address.
- Authenticate the expected TLS node name.
- Check capabilities and appliance readiness.

Recovery does not silently reconcile a changed main address in `nodes.json`.
If the address changed, the operation pauses with
`ADDRESS_RECONCILIATION_REQUIRED` and directs the caller to
`reconcile_isolated_orchestrator`.

Missing capabilities block with `update_agent` guidance. Recovery does not
automatically update an existing appliance.

### 12.4 Creation

The default orchestrator profile:

- References an existing Linux profile and existing main vSwitch.
- Uses Ubuntu 24.04 amd64.
- Uses 4 vCPU.
- Uses 8192 MB static memory.
- Registers the existing LabLink agent on port 9091.
- Uses a deterministic human prefix plus immutable short ID.

Creation phases:

1. Resolve target, profile, main vSwitch, names, and immutable IDs.
2. Acquire the shared host creation lock.
3. Reconcile exact stale metadata for durably deleted/lost orchestrators.
4. Recheck for a reusable orchestrator under the lock.
5. Run bounded host memory, storage, switch, and capacity preflight.
6. Persist the revisioned plan, release the planning fence, and return
   `approval_required`.
7. On an exact approved retry, reacquire the fence and recheck the same plan
   revision and host state.
8. Create through the existing Linux VM flow.
9. Verify exact VM identity, storage, main NIC, and mTLS registration.
10. Probe required appliance capabilities.
11. Install permitted packages from the existing main internet connection, or
    use the optional offline bundle.
12. Automatically neutralize known firewall managers, then fail bootstrap if
    the conflict scan still finds a firewall/NAT manager or unmanaged rules.
13. Configure appliance mode and persist its identity.
14. Restore the base nftables ruleset and relay firewall range.
15. Mark ready only after `appliance_ready=true`.

Post-fence stale-metadata reconciliation, reusable selection, and resource
preflight share a 60-second bound. Progress distinguishes
`host_fence_acquired`, `stale_metadata_reconcile`, `capacity_discovery`, and
`capacity_preflight`; timeout errors include the operation and fence.

Online package install is allowed because the orchestrator retains main
internet access.

Creation failures preserve partial resources by default. The durable operation
records the exact next phase. No broad cleanup occurs unless a future explicit
cleanup tool is requested.

### 12.5 Deletion

Deletion without `cascade=true` refuses while any non-deleted network, guest,
relay, or NAT allocation exists.

Deletion with cascade:

1. Builds a complete revisioned plan listing every immutable child, switch,
   NIC, VM, path, registry entry, and allocation.
2. Requires explicit approval for that exact revision.
3. Under the host deletion lock, atomically advances the host fence and sets
   the orchestrator `frozen/deleting` in server state, host metadata, and the
   appliance. All child create/update/repair/NAT/relay mutations then return
   `PARENT_FROZEN`.
4. Rechecks host and state under the new fence.
5. In deterministic guest-ID order, disables each guest NAT mapping, retires
   and drains its relay, retires the guest allocation, then deletes the exact
   VM and owned storage.
6. Removes private networks and orchestrator private NICs in deterministic
   network-ID order. Execution ordering does not rewrite the already approved
   child enumeration or plan revision.
7. Verifies that no guest, relay, NAT, or network children remain.
8. Deletes the orchestrator VM by persisted Hyper-V GUID after exact ownership
   metadata/cascade validation, treating an already-absent GUID as replay
   success and cleaning only its exact managed storage path.
9. Removes registry entries and tombstones allocations.

Freeze installs a narrow `cascade_authority` record on the server, host, and,
when reachable, appliance. It contains:

- Parent orchestrator ID and frozen generation.
- Approved parent operation ID.
- Approved plan revision and plan hash.
- Current host fence and lease.
- The exact enumerated child resource IDs, expected host/appliance identities,
  generations, and permitted cleanup action for each.

Frozen, deleting, or lost parents reject every child mutation by default.
They admit an exception only when the request carries the current
`cascade_authority` and the mutation ID/action/resource exactly matches one
unfinished item in that approved enumeration. The authority permits cleanup
only: stop accepts/dials, retire relay/NAT state, delete an enumerated guest
and exact storage, remove an enumerated adapter/switch/network, and tombstone
the corresponding allocation. It cannot create, repair, reconfigure, enable
NAT, rebind, adopt, rename, or operate on a child absent from the plan.

Each completed child item is durably marked under the same target-side
linearization barrier before the next item. An interrupted cascade may be
resumed by `resume_exact` with the same parent operation ID and approved plan
revision. A new process may reacquire the remote lease and a higher fence; the
handoff rebinds the unchanged cascade authority to that fence after verifying
the durable completed-item set. No new approval is required when the
enumeration and plan hash are unchanged. Any added child, identity drift,
changed action, or plan-hash mismatch pauses the cascade and requires a new
revision and approval.

If the orchestrator is lost, the approved cascade uses host metadata and
server state. It does not require the appliance database, but every deletion
still requires exact Hyper-V identity. If the host is unavailable, deletion
is blocked rather than guessed.

## 13. Guest provisioning and onboarding

### 13.1 Common sequence

1. Propose immutable VM ID, static IP, MAC, relay ID, relay port, and conntrack
   mark, then reserve them atomically on the authoritative appliance and
   import the accepted reservation into server SQLite.
2. Persist a durable create operation.
3. Register the guest allocation with the orchestrator appliance.
4. Create and validate the relay listener before starting the guest.
5. Create the Hyper-V VM using the selected existing Windows or Linux profile,
   replacing its network configuration with the isolated static configuration.
6. Attach only the managed private switch.
7. Enable Hyper-V time synchronization.
8. Apply and verify the requested pre-boot NAT state. For the default
   `nat_enabled=false` path, verify the VM has no new-flow forwarding rule. For
   NAT-dependent bootstrap, verify enabled forwarding, masquerade, and the
   exact conntrack mark before first boot.
9. Start the VM.
10. Connect through the relay, authenticate the guest's immutable TLS name,
    and verify static address, route, DNS, and time.
11. Register the relay address in `nodes.json`.
12. If requested, perform domain join only after relay enrollment and network
    verification, then complete its existing reboot/secure-channel checks.
13. Mark the VM ready only after host, appliance, relay, and guest identity
    agree.

### 13.2 Static configuration

Every guest receives:

- IPv4 address from base + 10 through base + 62.
- Prefix length 26.
- Gateway at base + 1.
- DNS resolver addresses copied from the orchestrator main NIC.
- Static MAC matching the Hyper-V adapter.

DHCP is not used.

### 13.3 Windows guests

Windows provisioning extends the existing unattend/differencing-disk flow:

- Inject static IP, prefix, gateway, DNS, and expected adapter MAC into the
  first-boot script.
- Match the adapter by MAC rather than friendly name.
- Keep the LabLink payload pre-staged in the guest disk.
- Install and start the agent on port 9091.
- Reject invalid Windows hostnames before mutation, preserving the existing
  15-character rule.

Domain join is rejected unless:

- Explicit reachable domain-service metadata is supplied.
- Required DNS and domain-controller endpoints pass preflight.
- NAT is enabled when those services are on the main network.
- Relay-based enrollment and static network verification have succeeded.
- The existing saved-secret domain-join flow then executes as a post-
  enrollment phase, never as first-boot unattend work.

Reachable-service metadata is a declaration and preflight input, not a
firewall allowlist.

### 13.4 Linux guests

Linux provisioning extends the existing NoCloud flow:

- Emit static Netplan v2 configuration matched by MAC.
- Set gateway and copied DNS addresses.
- Keep the existing pre-staged agent, CA, certificate, key, and installer
  payload.
- Preserve root-login and credential rules from `internal/linuxvm/seed.go`.
- Keep Hyper-V KVP and time integration enabled.

The isolated path must not use the current default DHCP network config.

### 13.5 Network-dependent bootstrap

Known network-dependent bootstrap actions are rejected unless one of these is
true:

- All required artifacts are pre-staged; or
- `nat_enabled=true` and the profile declares internet/main-network bootstrap
  requirements.

Known actions include domain join, package installation, explicit download
URLs, and profile-marked online setup. The system does not pretend to
semantically analyze arbitrary scripts. An arbitrary first-boot script must
declare `bootstrap_network_requirement=none|pre_staged|nat_enabled`; absent or
contradictory declarations fail before VM mutation.

### 13.6 Repair and recreate

`repair_isolated_vm` first attempts:

- Host VM/NIC/time-setting repair.
- Static network repair through the guest agent when reachable.
- Relay validation and rebind.
- NAT reconciliation.
- Registry address repair.

If repair fails, it automatically performs a full recreate:

- Preserve immutable isolated VM ID, node name, IP, MAC, relay ID, relay port,
  and display name.
- Stop and remove the old Hyper-V VM using exact identity.
- Delete the exact old owned child VHD and VM storage.
- Create a new Hyper-V VM and update its Hyper-V VM GUID.
- Reuse the expected guest TLS identity.
- Re-run onboarding and reconciliation.

The automatic recreate does not require a separate approval because this
behavior is part of the explicit repair tool contract.

## 14. MCP tools

### 14.1 Common mutation fields

Every mutating high-level tool supports:

| Field | Type | Behavior |
|---|---|---|
| `operation_id` | string, optional | Resume a known durable operation. |
| `resume_exact` | bool, default false | Required when reusing `operation_id`; canonical arguments must match. |
| `expected_generation` | integer, optional | Explicit optimistic-concurrency guard for primitive use. |

The high-level `operation_id` is not reused directly as every appliance or
host mutation ID. Each phase derives a stable mutation ID from:

```text
SHA-256("lablink-isolated-mutation-v1" ||
        parent-operation-id ||
        resource-id ||
        semantic-action ||
        stable-phase-key)
```

The same parent workflow therefore generates the same mutation ID after
process loss, while different phases cannot alias.

When a parent workflow starts a nested durable operation, such as a cascade
guest or network deletion, it derives a separate deterministic canonical UUID
from the same parent/resource/action/phase tuple. The UUID has the required
version and variant bits, remains stable for exact resume, and is still
validated by the normal strict operation-ID validator.

The semantic hash is computed from canonical resolved inputs: physical host
ID, immutable parent/resource IDs, resolved profile values, exact paths,
accepted allocation values, desired state, and semantic action. Maps are
key-sorted, paths and IDs use canonical casing/format, numbers use one JSON
representation, and omitted defaults are expanded before hashing.

Deletion reads each appliance guest, relay, and NAT generation immediately
before its appliance mutation. Host-only repair/incarnation generations remain
local to Hyper-V lifecycle state and are never used as appliance generation
guards. Interrupted deletion imports already-advanced appliance state before
continuing.

Adapter ownership is persisted both in the per-adapter host record and the
parent VM's `private_adapters` references. Parent fence re-claims preserve
those references. If the per-adapter record is missing, deletion may recreate
it only after exact network ownership, VM GUID, switch GUID/name, adapter
ID/name/static MAC, generation, and owner marker all agree with an
unambiguous Hyper-V observation; any mismatch fails closed before removal.
The persisted `mutation_id` remains creation/adoption provenance; a later
delete mutation is authorized independently by its guard and does not rewrite
or compare itself to that provenance.

After CIDATA cleanup is complete, empty optional CIDATA/ownership metadata
paths are valid. Inspect, resume, and delete scripts guard emptiness before
calling path cmdlets; immutable VM and VHD identity remains mandatory.

The semantic hash excludes retry and approval envelope fields:

- `operation_id`
- `resume_exact`
- `approved_plan_revision`
- elicitation responses
- progress/cancellation metadata
- attempt number
- expected/current generation and fence headers
- host lease ID/secret and expiry

Generation and fence values remain mandatory compare-and-swap guards but do
not change the meaning of the requested end state. A mutation ID replay with a
different semantic hash is always rejected.

Results contain one final fenced JSON object with:

```json
{
  "operation_id": "uuid",
  "status": "succeeded|paused|approval_required|failed",
  "phase": "phase_name",
  "resource_id": "uuid",
  "generation": 3,
  "progress": [],
  "next_action": null
}
```

### 14.2 Orchestrator tools

`create_isolated_orchestrator`

- Inputs: `target`, optional `orchestrator_id`, `display_name`, optional
  `profile`, optional `main_vswitch`, `dry_run`, `approved_plan_revision`,
  common operation fields.
- Behavior: discover/reuse oldest compatible orchestrator unless an exact ID
  is requested. If creation is needed, return or elicit an approval-bound
  plan. Defaults to 4 vCPU, 8 GB static memory.
- Approval: required only when a new orchestrator VM will be created.
  Firewall-manager neutralization is an unconditional bootstrap step.

`list_isolated_orchestrators`

- Inputs: optional `target`, `include_deleted`, `live`.
- `live=true` reconciles health read-only and reports capability/capacity.

`get_isolated_orchestrator`

- Inputs: exact `orchestrator_id`, optional `live`.

`reconcile_isolated_orchestrator`

- Inputs: exact `orchestrator_id`, `refresh_dns`, `repair_registry_addresses`,
  common operation fields.
- Behavior: reconciles host, appliance, relay listeners, NAT, registry
  addresses, and optionally guest DNS. No approval unless it discovers a need
  to disable a conflicting firewall/NAT manager.

`delete_isolated_orchestrator`

- Inputs: exact `orchestrator_id`, `cascade`, `approved_plan_revision`, common
  operation fields.
- Approval: always required for orchestrator deletion. A cascade plan lists
  all children.

### 14.3 Network tools

`add_isolated_network`

- Inputs: `target`, optional `orchestrator_id`, `display_name`, common
  operation fields.
- Behavior: selects/reuses an orchestrator or enters the approval-gated create
  path, allocates a `/26`, creates the private switch and orchestrator NIC,
  configures the gateway, and snapshots DNS.

`remove_isolated_network`

- Inputs: exact `network_id`, common operation fields.
- Refuses if any non-deleted guest remains. No force flag is provided.

`reconcile_isolated_network`

- Inputs: exact `network_id`, `refresh_dns`, common operation fields.
- Reconciles switch, NIC, gateway, generation, and optionally every managed
  guest's DNS.

### 14.4 VM tools

`create_isolated_vm`

- Inputs: exact `network_id`, `display_name`, `guest_os`, `profile`,
  `nat_enabled` default false, optional `domain_join`, optional
  `reachable_services`, `bootstrap_network_requirement`, common operation
  fields.
- Behavior: allocates and persists exact identity before host mutation.
- Approval: none. If the selected workflow needs a new orchestrator, only that
  nested orchestrator creation plan requires approval.

`delete_isolated_vm`

- Inputs: exact `isolated_vm_id`, `delete_storage` default true, common
  operation fields.
- Behavior: removes exactly owned VM storage, guest registry entry, relay,
  NAT, and allocations. Shared parents are never removed.

`list_isolated_vms`

- Inputs: optional `target`, `orchestrator_id`, `network_id`,
  `include_deleted`, `live`.

`get_isolated_vm`

- Inputs: exact `isolated_vm_id`, optional `live`.

`repair_isolated_vm`

- Inputs: exact `isolated_vm_id`, common operation fields.
- Behavior: repair first, then automatic full recreate and old child-VHD
  deletion if repair fails.

`rename_isolated_display_name`

- Inputs: `resource_type`, exact `resource_id`, `display_name`.
- Changes only SQLite display state and registry label. Hyper-V, TLS, paths,
  immutable IDs, and node names do not change.

### 14.5 NAT tools

`enable_isolated_vm_nat`

- Inputs: exact `isolated_vm_id`, common operation fields.
- Applies unrestricted IPv4 forwarding and masquerade.

`disable_isolated_vm_nat`

- Inputs: exact `isolated_vm_id`, common operation fields.
- Transitions to draining, then disabled after conntrack drains.

`get_isolated_vm_nat`

- Inputs: exact `isolated_vm_id`, optional `live`.

`list_isolated_vm_nat`

- Inputs: optional `orchestrator_id`, `network_id`, `state`, `live`.

`reconcile_isolated_vm_nat`

- Inputs: exact `isolated_vm_id`, common operation fields.
- Reapplies desired state with generation checking. It never changes relay
  state.

### 14.6 Relay primitives

`create_isolated_relay`

- Inputs: exact `orchestrator_id`, `isolated_vm_id`, optional exact
  `listen_port` for recovery, common operation fields.
- Target port is not an input and is always 9091.

`remove_isolated_relay`

- Inputs: exact `relay_id`, common operation fields.
- Behavior: executes the relay-only accept/dial/drain barrier and releases only
  the relay port. It may operate on a live VM and does not change NAT or guest
  IP/MAC/network allocations.

`list_isolated_relays`

- Inputs: optional `orchestrator_id`, `network_id`, `live`.

`get_isolated_relay_stats`

- Inputs: exact `relay_id` or `orchestrator_id` aggregate.

`rebind_isolated_relays`

- Inputs: exact `orchestrator_id`, common operation fields.
- Rebinds all listeners to the current main IPv4 without changing ports.

`validate_isolated_relay`

- Inputs: exact `relay_id`, `probe_target`.
- Validates listener, mapping, generation, and optionally TCP reachability to
  guest port 9091 without interpreting TLS.

`adopt_isolated_relay`

- Inputs: exact orchestrator, relay, VM, and network IDs plus observed
  generation and common operation fields.
- Imports only an exact already-live mapping.

### 14.7 Approval behavior

Destructive approvals may use the existing MCP elicitation support
demonstrated by `elicitVMFields` in
`internal/mcptools/vm_orchestrator.go`. Orchestrator creation always returns a
non-blocking `approval_required` result so it never holds a host fence while
waiting for user input.

The approval schema contains:

- Human-readable complete plan.
- `plan_revision`.
- `approve` boolean.
- Explicit cascade or conflict-disable acknowledgement where applicable.

If elicitation is unsupported, the tool returns `approval_required` and the
revision. The caller retries with `approved_plan_revision`.

An approval is consumed once. It is valid only when:

- The operation ID matches.
- The plan hash matches.
- The revision is still current.
- Host and resource generations still match the plan.

Any replan supersedes the old revision and requires new approval.

No approval is requested for ordinary network, guest, NAT, relay, repair, or
display-name mutations.

## 15. Durable operation state machines and rollback

### 15.1 General rules

- The server persists the operation before the first external mutation.
- Every phase is written before and after execution.
- Progress text is appended to `operation_events` and also emitted through
  existing MCP progress callbacks.
- Cancellation stops new phases but does not guess whether an in-flight remote
  mutation rolled back.
- On the next resume, the phase inspects exact live state before deciding
  whether to replay, advance, or fail.
- `resume_exact=true` requires the same operation ID and canonical argument
  hash. A different hash returns `RESUME_ARGUMENT_MISMATCH`.
- A display-name collision never identifies a resumable resource.
- Stable per-phase mutation IDs and semantic hashes follow Section 14.1.
- Parent freeze/fence and generation guards are checked before every external
  mutation, not only at workflow entry.

### 15.2 Orchestrator create

```text
planned
  -> host_lock
  -> reuse_recheck
  -> resource_preflight
  -> approval_required
  -> create_linux_vm
  -> verify_host_identity
  -> verify_mtls
  -> verify_capabilities
  -> install_appliance_dependencies
  -> neutralize_known_firewall_managers
  -> conflict_scan
  -> configure_appliance
  -> restore_firewall_and_relays
  -> ready
```

Default rollback: preserve partial VM, VHD, registry entry, and operation
state. Pre-VM temporary staging owned only by the operation may be removed.

### 15.3 Network create

```text
allocate
  -> host_network_lock
  -> create_private_switch
  -> add_orchestrator_nic
  -> appliance_apply_network
  -> verify_gateway
  -> ready
```

If a later phase fails, the switch and NIC are preserved and marked degraded
for exact resume. Automatic rollback is avoided because removing a live NIC
after an uncertain response could destroy a successfully applied network.

### 15.4 VM create

```text
allocate_identity
  -> appliance_register_guest
  -> relay_bind
  -> host_create_vm
  -> host_attach_private_nic
  -> guest_provision
  -> host_time_sync
  -> nat_apply_and_verify_preboot
  -> guest_start
  -> relay_mtls_verify
  -> registry_commit
  -> optional_domain_join
  -> ready
```

Failure preserves partial resources by default. Allocation remains reserved
to prevent another VM from claiming the IP or port. Resume inspects the exact
Hyper-V VM ID, paths, appliance generation, and relay mapping.

### 15.5 Repair

```text
inspect
  -> repair_host
  -> repair_relay
  -> repair_guest_network
  -> repair_nat
  -> verify
  -> ready

on repair failure:
  -> exact_delete_old_vm_and_vhd
  -> recreate_with_same_identity
  -> verify
  -> ready
```

### 15.6 NAT disable

```text
enabled
  -> remove_new_flow_rule
  -> draining
  -> poll_conntrack
  -> disabled
```

The MCP call may return `draining` while the durable operation remains
running or paused for later reconciliation. There is no forced drain timeout.

### 15.7 Deletion

Deletion journals child completion individually. A resumed cascade skips only
children proven absent or already deleted with exact identity. Allocation
rows are released after corresponding live resources are proven absent.
Every child phase carries the exact cascade authority from Section 12.5;
ordinary child credentials cannot mutate a frozen parent. Interrupted resume
may use a newly fenced lease only after target-side handoff rebinds the same
approved revision and unfinished enumeration.

## 16. Concurrency and cross-process locking

### 16.1 Lock hierarchy

Locks are acquired in this order:

```text
physical-host remote fence
  -> orchestrator lifecycle/freeze lock
    -> appliance allocation lock
      -> network lock
        -> VM lock
          -> relay or NAT child lock
```

Code must never acquire upward in the hierarchy.

Allocation order within the appliance transaction is fixed:

```text
subnet -> private NIC MAC -> guest IP -> guest MAC -> relay port
       -> conntrack mark -> capacity counters
```

One transaction reserves the complete requested set or none of it. Release
uses the reverse order only after retirement.

### 16.2 Shared SQLite locks

Lock keys include:

```text
host:<physical-host-id>:orchestrator-create
orchestrator:<orchestrator-id>
network:<network-id>
vm:<isolated-vm-id>
allocation:<orchestrator-id>
```

Local lock ownership uses the same verifiable identity shape as leasing:
hostname, PID, process creation time, and a cryptographically random
per-process cookie. On the same developer host, PID plus creation time is
checked to avoid PID reuse; inability to prove the process dead keeps the lock
conservatively held. A different developer host cannot prove local process
liveness and must rely on the remote lease/fence protocol below.

Each server startup sweeps only locks that normal acquisition could reclaim:
expired leases, or same-host leases whose exact PID and creation time are
proven dead. The monotonic fence history is retained. Unproven same-host locks
remain conservatively held.

### 16.3 Host-side lock

SQLite coordinates processes sharing one developer box, but not a second
trusted LabLink server. Orchestrator creation and deletion therefore also use
an atomic host-side lock under:

```text
%ProgramData%\LabLink\locks\isolated-orchestrator-<host-hash>
```

The host lock is a renewable lease plus monotonic fencing token, not only a
directory:

- Host metadata stores `physical_host_id`, lease ID, holder identity,
  operation ID, expiry, a hash of a random 256-bit lease secret, and
  monotonically increasing `fence`.
- Acquisition and renewal run in one PowerShell script under an exclusive
  file handle/atomic directory operation.
- Acquisition returns the lease ID, fence, expiry, and lease secret only over
  the authenticated host-agent channel. The server immediately installs the
  same lease ID/fence/secret hash/expiry in appliance state before child
  mutation.
- The holder renews host and appliance leases before one-third of the lease
  duration elapses. Losing either renewal cancels the workflow before another
  mutation.
- An expired lease may be reclaimed by another server without proving the
  remote process dead; reclamation atomically increments `fence`.
- Immediately after every deletion-path fence acquisition, the server
  re-claims the orchestrator VM, stamps that exact fence into parent Hyper-V
  metadata, and persists the resulting VM identity/fence before any child
  NIC, switch, or VM mutation. No second fence is acquired between that stamp
  and the guarded child mutation.
- The old holder cannot mutate after reclamation because every PowerShell
  mutation validates the current fence inside the mutation script.
- Host scripts validate lease ID, fence, unexpired lease, and secret inside
  every mutation. Appliance mutations carry the same values; the appliance
  validates the stored secret hash and expiry and permanently rejects lower
  fences. Installing a higher fence invalidates the previous lease
  immediately.

This prevents duplicate orchestrator creation and stale remote writers across
independent servers.

Before any child mutation, server, host script, and appliance all verify that
the orchestrator lifecycle state is not `frozen`, `deleting`, `lost`, or
`deleted`, except for the exact revision-bound `cascade_authority` cleanup
defined in Section 12.5. Deletion first changes state and fence, so an
already-running unrelated child operation with the old fence fails at its
next mutation boundary.

### 16.4 Target-side linearization barriers

Fence checking and the external side effect are one target-side critical
section. A check before a remote call and another check afterward is not
sufficient.

**Windows host barrier**

- Every isolated Hyper-V mutation script first participates in an atomic
  admission protocol under
  `%ProgramData%\LabLink\locks\isolated-host-admission`.
- Fence install, lease reclamation, freeze, and cascade handoff first publish
  a `handoff_pending` record with the proposed fence/revision. Publication
  closes admission for the old lease before waiting for the external-mutation
  gate.
- A normal mutation checks that no handoff is pending, acquires the exclusive
  host external-mutation gate, rechecks pending state, lease secret, expiry,
  fence, parent state, mutation ID, and ownership, then performs one bounded
  `New-*`, `Set-*`, `Connect-*`, `Disconnect-*`, `Remove-*`, or storage
  check-and-act while still holding the gate. Verification and host metadata
  commit occur before release.
- A handoff waits for the current gate holder, if any, to finish, then acquires
  the same gate, installs the new fence/freeze/cascade authority, fsyncs the
  host record, clears `handoff_pending`, and only then acknowledges handoff.
- Operations admitted before `handoff_pending` may finish before the
  acknowledgment. No old-fence operation can enter or perform an external
  Hyper-V effect after the acknowledgment.

The exclusive gate serializes individual host effects, not whole workflows.
Different network workflows may run concurrently between their short host
check-and-act sections.

**Appliance barrier**

- The appliance manager has one admission mutex/condition and one external
  apply gate covering nftables, networkd/interface changes, sysctls, and
  listener create/remove/rebind.
- Fence install, lease reclamation, freeze, and cascade handoff set
  `handoff_pending`, reject new old-lease admissions, wait for the admitted
  mutation count to reach zero, acquire the apply gate, persist the new
  authority, and acknowledge only after it is durable.
- An admitted mutation holds the apply gate from the final fence/parent check
  through external apply, observation, and SQLite applied/observed commit as
  defined in Section 7.4.
- Process death releases in-memory admission. On restart, the durable pending
  intent and fail-closed boot protocol recover state before mutation
  admission.

Thus a stale writer can either complete before handoff acknowledgment or be
rejected; it cannot perform a new nftables, networkd, interface, listener, or
Hyper-V effect after acknowledgment.

### 16.5 Per-network serialization

All mutations that affect one network, its orchestrator NIC, its guest
allocations, or its nftables slice are serialized by `network:<id>` in server
SQLite and by a keyed mutex inside the appliance agent.

Different networks on the same orchestrator may mutate in parallel. Global
nftables updates are compiled from the full appliance database and atomically
loaded under a short appliance ruleset mutex, so parallel network operations
cannot lose each other's rules.

The compiled snapshot/fence check in Section 7.4 prevents a slower network
operation from installing a stale full ruleset after another network has
committed a newer desired generation.

## 17. Portal

The portal remains loopback-only and protected by its per-process key.

It gains read-only tabs and APIs:

- Topology: host -> orchestrator -> network -> VM.
- Orchestrator status: health, capabilities, capacity, main IP, appliance
  generation, conflict state.
- Network status: subnet, gateway, DNS snapshot, switch/NIC health, generation.
- VM status: OS, IP, relay address, NAT state, host state, guest health.
- Relay status and counters.
- Durable operations: operation ID, revision, phase, progress, pause reason,
  error, and resume guidance.

Portal views read shared SQLite and may request bounded live status. They do
not mutate state and do not add approval buttons in the initial version.
Existing process-local operation and job views remain.

## 18. Versioning and compatibility

### 18.1 Database

- Server and appliance databases have independent monotonic schema versions.
- Migrations are forward-only and transactional.
- A newer unsupported schema fails startup for isolated features but must not
  corrupt or downgrade the database.
- Generic non-isolated LabLink tools continue to start when isolated state is
  unavailable, with isolated tools reporting a clear disabled reason.

### 18.2 Protobuf

- Existing field numbers are never reused.
- New `GetInfo` fields are additive.
- Capability strings gate behavior, not agent version string comparison
  alone.
- Unknown capability strings are ignored.
- Required missing capabilities block with `update_agent` guidance.

### 18.3 Node registry

- `nodes.json` remains JSON-compatible.
- Isolated details live primarily in labels and SQLite.
- Export/import of nodes does not export isolated control-plane state and is
  not a migration or backup mechanism.

### 18.4 Appliance compatibility

The server supports an explicit range of appliance schema and protocol
versions. Mutations require a compatible version; read-only status may show an
incompatible appliance with upgrade guidance.

### 18.5 Pinned dependencies and updater contract

The appliance dependency manifest is a checked-in, release-versioned artifact.
It pins exact Ubuntu 24.04 amd64 package versions, repository snapshot
identity, artifact SHA-256, and dependency closure for:

- `nftables`
- `conntrack`
- `iproute2`
- `systemd`
- `systemd-resolved`
- `ca-certificates`
- any package pulled by those exact versions

The online path does not run unconstrained `apt install`. It downloads from
the manifest's pinned Ubuntu snapshot/repository metadata, verifies signed
Release/InRelease metadata and package hashes, and installs
`package=exact-version`. The offline bundle contains the same manifest and
complete recursive `.deb` closure; both server and appliance verify every
hash and architecture before installation.

Preflight verifies these kernel facilities before appliance readiness:

```text
nf_tables
nf_conntrack
nf_conntrack_netlink
nf_nat
nft_chain_nat
IPv4 forwarding sysctl
hv_netvsc
hv_utils / Hyper-V time synchronization
```

Missing facilities produce an incompatible/degraded appliance and never
enable forwarding.

Database migrations are forward-only, transactional, and expand/contract
compatible for one released agent version:

- Release N+1 may add tables, columns with safe defaults, or indexes while N
  remains able to read the migrated schema.
- Destructive semantic changes require an intermediate release; they are not
  performed in the same update that removes N compatibility.
- The updater runs `--check-appliance-migration` before replacing the binary.
- Automatic binary rollback after migration is allowed only when the N+1
  manifest states that N can read the resulting schema. No persistent
  orchestrator backup is created.
- If rollback is unsafe, the updater keeps N+1 installed in fail-closed
  degraded mode and returns forward-repair guidance rather than running an old
  binary against an unreadable database.

An agent update is not successful merely because the service reconnects.
`update_agent` must verify expected agent version, required capability set,
supported DB schema, emergency/full policy signature, kernel facilities, and
`appliance_ready=true`. If post-update readiness fails, the updater follows
the compatibility-safe rollback rule above and reports the appliance as
unavailable for selection.

## 19. Failure and recovery matrix

| Failure | Detection | Recovery |
|---|---|---|
| Duplicate orchestrator requests | Shared and host lock plus recheck | One operation reuses; the other returns the existing ID. |
| Separate server databases choose same allocation | Appliance reservation transaction | One succeeds; loser receives typed collision, refreshes inventory, and retries only for automatic selection. |
| Stale remote lock holder resumes | Fence mismatch inside host/appliance mutation | Reject every stale mutation; current holder reconciles. |
| Parent enters deletion during child workflow | Frozen state and newer fence | Child stops at next mutation boundary with `PARENT_FROZEN`. |
| Host resource pressure | Existing resource safety preflight | Create no VM; return plan/preflight failure. |
| Linux VM create partially succeeds | Durable phase plus exact Hyper-V metadata | Preserve and `resume_exact`. |
| Orchestrator agent is old | Missing capabilities in `GetInfo` | Block with `update_agent` guidance. |
| Orchestrator is Off | Host VM state | Start and authenticate it. |
| Orchestrator IP changed | Host KVP differs from registry | Require user-invoked reconcile; then update parent and child addresses. |
| Orchestrator VM lost | Host exact ID absent | Mark lost; only approved cascade deletion may release children. |
| Orchestrator host mismatch | Persisted host differs from request | Fail; no migration. |
| Appliance DB unavailable | `appliance_ready=false` | Repair database/filesystem; do not select for new work. |
| Conflicting firewall manager | Bootstrap neutralization plus service/rules scan | Fail bootstrap/readiness if an installed manager cannot be neutralized or a conflict remains. |
| nftables load fails | Check/apply/observe error | Keep the last verified policy, or emergency drop policy on first activation; disable forwarding if policy signature cannot be verified. |
| Crash after external apply before SQLite commit | Pending apply intent plus observation | Commit exact observed generation or reapply the same intent. |
| Slow compile races newer desired state | Compiled-hash and generation pre-apply check | Discard stale compilation and rebuild. |
| Generic DHCP config claims private NIC | Effective networkd file/MAC verification | Abort hot-add, restore emergency policy, repair MAC-scoped files, targeted reconfigure. |
| Private switch exists unmanaged | Ownership/type mismatch | Fail closed; do not adopt by name. |
| Hyper-V create response lost | Exact host metadata/GUID discovery | Adopt exactly one matching object, retry on zero, freeze on multiple/mismatch. |
| Orchestrator NIC add response lost | Host inspection by VM ID/MAC/switch | Treat exact matching NIC as phase success. |
| Network appliance apply response lost | Operation replay and generation | Appliance returns stored idempotent result. |
| Guest create partially succeeds | Operation phase and VM Notes | Preserve allocation and exact-resume. |
| Relay bind port busy | Bind health and allocation check | Mark degraded; do not silently select a new persistent port. |
| Relay target unavailable | Dial failure telemetry | Guest repair; listener stays active. |
| Relay removal has active connections | Retirement state and connection count | Stop accepts/dials, allow bounded drain, then close remaining copies without releasing the port before zero active connections. |
| Main IP changes | Startup observation or explicit rebind | Rebind listeners on restart or explicit request; registry update remains manual. |
| Guest certificate mismatch | Existing TLS identity validation | Permanent failure; never register/adopt wrong guest. |
| Guest static network broken | Relay probe and host KVP | Repair, then automatic recreate if repair fails. |
| Guest repair fails | Repair state machine | Delete exact old VHD and recreate with same identity/allocation. |
| NAT enable response lost | Operation replay and generation | Read live state; replay idempotently. |
| NAT disable has long flows | Conntrack count | Remain draining indefinitely; no forced timeout. |
| Agent restarts while draining | Durable static restore | Restore draining rules and let the exact internal zero-conntrack transition complete. |
| DNS resolvers change | Explicit refresh reconcile | Update all reachable guests; mark offline guests pending. |
| No usable upstream resolver | Link-specific extraction rejects stub/loopback | Persist empty DNS state; reject DNS-dependent bootstrap. |
| YAML registry import loses TLS name | Round-trip validation | Reject import/test failure; never derive guest TLS name from relay address. |
| Server process exits | Durable SQLite phases | Another local process resumes exact operation. |
| Two networks mutate concurrently | Per-network locks plus atomic full ruleset compile | Parallel host work; serialized short nftables apply. |
| SQLite lock holder dies | Expiry plus process-liveness check | Conservatively steal and resume. |
| Local control DB lost | Live host/appliance still present | Use exact inspect/adopt primitives; no automatic backup claim. |
| Hyper-V host unavailable | Agent/health failure | Preserve state; no guessed deletion or allocation release. |
| Update migrates DB then readiness fails | Post-update capability/schema/policy check | Roll back only when manifest declares old binary schema-compatible; otherwise remain fail-closed on new binary. |
| Portal unavailable | Loopback HTTP failure | MCP tools continue; portal is observational only. |

## 20. Security considerations

- Every resource mutation uses immutable IDs and generation checks.
- Name matching alone never authorizes reuse, adoption, or deletion.
- Hyper-V storage deletion follows exact managed-root and VHD-chain checks.
- Guest TLS is end to end through the relay.
- Relay payloads are never logged or inspected.
- Relay target port is fixed to 9091 and target IP must belong to the exact
  guest allocation.
- Main-interface firewall rules allow the relay range, but only active
  listeners expose a service.
- Appliance package installation uses main internet only during approved
  customization and may instead use a verified offline bundle.
- UFW and firewalld are stopped, disabled, and masked automatically before
  the appliance firewall and agent start; remaining conflicts fail closed.
- Domain join requires explicit service declaration and reachability
  preflight.
- Arbitrary network-dependent bootstrap must declare how dependencies are
  satisfied.
- Secrets remain in existing credential/secret stores and enrollment payload
  paths. They are excluded from operation JSON, approval plans, events,
  errors, and portal views.
- No new ownership namespace is added. Trust remains broad by explicit
  requirement.
- Source spoofing, same-switch peer trust, unrestricted enabled NAT, unmanaged
  IPv6, and relay resource exhaustion remain documented accepted risks.

## 21. Performance and resource limits

Hard limits per orchestrator:

- 16 private switches/private NICs.
- 100 isolated guests.
- 20,000 possible relay ports, of which at most 100 are normally allocated.
- 53 guest addresses per `/26`.
- One userspace listener per VM.

Defaults:

- Orchestrator: 4 vCPU, 8 GB static memory.
- Guest limits remain profile-defined.
- Relay buffers: two fixed 64 KiB buffers per active connection, plus socket
  buffers and Go runtime overhead.

Resource preflight includes:

- Existing host memory and storage reserve checks.
- Projected orchestrator VM memory/storage.
- Existing orchestrator count and aggregate reserved memory.
- Hyper-V switch/NIC limits observable on the host.
- Relay port, subnet, and guest-capacity availability.

No artificial connection cap or idle timeout is introduced. Telemetry and
operating-system limits are the control mechanisms in the initial release.

## 22. Phased implementation plan

### Phase 1: shared state and capabilities

New:

- `internal/isolatedstate/schema.sql`
- `internal/isolatedstate/store.go`
- `internal/isolatedstate/models.go`
- `internal/isolatedstate/allocations.go`
- `internal/isolatedstate/operations.go`
- `internal/isolatedstate/locks.go`
- `internal/isolatedstate/import.go`
- `internal/isolated/ids.go`
- `internal/isolated/naming.go`
- `internal/isolated/capabilities.go`
- `internal/isolated/hostidentity.go`

Modify:

- `proto/agent/agent.proto` and generated Go files.
- `cmd/lablink-agent/main.go` for capability/readiness fields.
- `cmd/lablink-server/main.go` to open `isolated.db`.
- `internal/registry/registry.go` only for isolated label helper methods, while
  retaining serialized JSON compatibility.
- `internal/healthmon/monitor.go` to retain capability and appliance readiness
  for orchestrator nodes.
- `internal/mcptools/importexport.go` and its tests to guarantee optional
  `tls_server_name` preservation for relayed nodes.

Tests:

- Schema migration and WAL concurrency.
- Atomic allocation races across two store handles.
- Appliance-authoritative collisions across two unrelated server databases.
- Lock expiry/liveness.
- Remote lock renewal, reclamation, and stale-writer fencing.
- Operation hash and `resume_exact`.
- Generation conflict behavior.
- Old-agent protobuf compatibility.

### Phase 2: Linux orchestrator appliance

New:

- `internal/appliance/schema.sql`
- `internal/appliance/store.go`
- `internal/appliance/manager_linux.go`
- `internal/appliance/networkd_linux.go`
- `internal/appliance/nft_linux.go`
- `internal/appliance/mainnic_linux.go`
- `internal/appliance/dns_linux.go`
- `internal/appliance/apply_linux.go`
- `internal/appliance/emergency_policy_linux.go`
- `internal/appliance/conflicts_linux.go`
- `internal/orchestratorseed/config.go`

Modify:

- `cmd/lablink-agent/main.go` and Linux service startup.
- `internal/linuxvm/seed.go` or a dedicated orchestrator seed path to enable
  appliance mode without changing ordinary Linux guests.
- `internal/vmconfig/config.go` for orchestrator profile references and the
  4-vCPU/8-GB static defaults.
- `internal/mcptools/agent_update.go` capability guidance.
- `scripts/build-release.ps1` to package appliance support and the optional
  offline bundle manifest/artifacts alongside the existing Linux agent.
- A checked-in appliance dependency manifest and systemd unit templates for
  emergency firewall, watchdog, and agent ordering.

Tests:

- Main NIC preserved.
- MAC-matched private networkd files.
- Generic `hv_netvsc` DHCP match replacement and hot-add/reboot precedence.
- Complete atomic ruleset generation.
- Intent/apply crash recovery and stale compilation rejection.
- Fail-closed first activation, boot, service failure, and ruleset failure.
- Automatic firewall-manager neutralization and fail-closed conflict detection.
- Restart readiness and draining normalization.

### Phase 3: private networks and relays

New:

- `internal/hyperv/isolated_lock.go`
- `internal/hyperv/isolated_metadata.go`
- `internal/hyperv/isolated_network.go`
- `internal/hyperv/isolated_discovery.go`
- `internal/appliance/relay.go`
- `internal/appliance/relay_stats.go`
- `internal/mcptools/isolated_orchestrator.go`
- `internal/mcptools/isolated_network.go`
- `internal/mcptools/isolated_relay.go`
- `internal/isolated/orchestrator.go`
- `internal/isolated/network.go`

Modify:

- `cmd/lablink-agent/main.go` to register appliance RPCs.
- `cmd/lablink-server/main.go` to register isolated tools.
- `internal/agentclient/client.go` only as needed for connection-reset and
  capability helpers.
- `internal/mcptools/vm_enrollment.go` for relay-address guest registration.

Tests:

- Private switch excludes host.
- Deterministic MAC and subnet allocation.
- Relay opaque mTLS.
- Half-close and backpressure.
- Main-IP rebind.
- Retirement barrier and no premature port reuse.
- Stats and target failure.
- Adopt validation.

### Phase 4: Windows and Linux isolated guests

New:

- `internal/hyperv/isolated_vm.go`
- `internal/mcptools/isolated_vm.go`
- `internal/isolated/guest.go`
- `internal/isolated/repair.go`

Modify:

- `internal/mcptools/vm_orchestrator.go` to expose reusable Windows plan
  execution with injected static network policy.
- `internal/mcptools/linux_vm.go` to expose reusable Linux plan execution with
  injected static network policy.
- `internal/linuxvm/seed.go` for static MAC-matched Netplan.
- `internal/hyperv/linux_vm.go` and Windows VM builders for isolated Notes,
  NIC metadata, and time synchronization.
- `internal/mcptools/vm_delete.go` and `internal/hyperv/delete.go` to reuse
  exact deletion primitives with expected VM/switch/adapter GUIDs and fences.

Tests:

- Windows and Linux static network onboarding through relay.
- Pre-boot NAT application for NAT-dependent bootstrap.
- Domain join only after relay enrollment and network verification.
- No guest main NIC.
- DNS snapshot and reconcile.
- Domain-join rejection/preflight.
- Bootstrap dependency rejection.
- Repair followed by automatic recreate.
- Exact old VHD deletion.

### Phase 5: NAT, lifecycle, and portal

New:

- `internal/appliance/nat.go`
- `internal/appliance/conntrack_linux.go`
- `internal/mcptools/isolated_nat.go`
- `internal/isolated/nat.go`
- `internal/portal/isolated.go`

Modify:

- `internal/portal/server.go` for read-only topology/status/operation APIs.
- `internal/portal/index.go` for topology and durable operation views.
- `internal/ops/registry.go` only to link process-local operations to durable
  operation IDs where available.

Tests:

- NAT enable/disable/draining.
- No forced drain timeout.
- Restart preserves draining state; exact background completion advances it
  only after zero matching conntrack entries.
- NAT does not affect relay.
- Cross-network forwarding remains blocked.
- Portal is read-only and loopback/key protected.

### Completion gate

After end-to-end implementation:

1. Run targeted unit and integration tests.
2. Run `go test ./...`, `go vet ./...`, cross-builds, and release packaging.
3. Run live Hyper-V acceptance on at least two private networks with Windows
   and Linux guests.
4. Request an independent code review and an independent network architecture
   review.
5. Resolve required findings.
6. Merge only after all acceptance criteria pass.

Release validation must cover both modes:

- Online appliance bootstrap, where the orchestrator installs pinned required
  packages through its main internet connection.
- Offline bootstrap, where the release contains a versioned manifest,
  hashes/signatures, and all required amd64 package artifacts. The server
  verifies the bundle before transfer, and the orchestrator verifies it again
  before install. Ordinary releases need not include the large offline payload
  unless the release build explicitly enables that packaging mode.

## 23. Test and acceptance matrix

### 23.1 State and concurrency

| Test | Expected |
|---|---|
| Two processes allocate same subnet | One wins; no duplicate row. |
| Two processes allocate same relay port | One wins; loser retries another port. |
| Two unrelated server DBs allocate same IP/port | Appliance accepts one atomic reservation and returns typed collision to the other. |
| Server imports live appliance with empty DB | Exact resources/generations imported without mutation. |
| Parent generation changes during reservation | Whole reservation rejected; no partial capacity consumption. |
| Same operation ID, same hash | Stored idempotent result or exact resume. |
| Same operation ID, different hash | `RESUME_ARGUMENT_MISMATCH`. |
| Same parent workflow retries one phase | Stable mutation ID and semantic hash are identical. |
| Retry/approval envelope changes | Semantic hash remains identical. |
| Resolved profile/path/allocation changes | Semantic hash changes and replay is rejected. |
| Stale expected generation | `GENERATION_CONFLICT`, no mutation. |
| Dead lock holder | Conservative liveness check, then recovery. |
| Remote lock expires and is reclaimed | Fence increments; old holder fails host and appliance mutation. |
| Host mutation already holds gate when handoff starts | Handoff waits; mutation may finish before acknowledgment, never after it. |
| Old host writer arrives after `handoff_pending` | Admission/recheck rejects it before `New-VM` or any other external cmdlet. |
| Appliance apply holds gate when fence changes | Fence install waits for observe/commit; acknowledgment follows drain. |
| Old appliance writer arrives after handoff acknowledgment | No nftables, networkd, interface, sysctl, or listener effect occurs. |
| Parent freezes while child runs | Child's next host/appliance mutation fails. |
| Different networks mutate | Parallel except short atomic ruleset apply. |
| Same network mutates | Serialized. |
| Delete then reuse subnet/IP/port | Tombstone/history retained; partial live index permits safe reuse. |
| Crash after intent commit | Startup resumes or rolls back to observed exact state. |
| Crash after external apply | Observation commits same generation without duplicate side effects. |
| Older compile finishes last | Pre-apply hash/generation check prevents stale install. |

### 23.2 Orchestrator

| Test | Expected |
|---|---|
| Healthy compatible orchestrators exist | Oldest with capacity selected. |
| Oldest is Off | Recovery attempted before selecting newer one. |
| Missing capability | Block with exact `update_agent` guidance. |
| No capacity | Resource preflight and approved new orchestrator plan. |
| Host mismatch | Unsupported error, no mutation. |
| Two aliases name same host | Canonical physical host ID yields one lock/pool. |
| Alias changes to another machine | `HOST_IDENTITY_CHANGED`; no retarget. |
| Main NIC | Existing vSwitch and normal internet retained. |
| Default profile | Ubuntu 24.04 amd64, 4 vCPU, 8 GB static. |
| UFW/firewalld conflict | Bootstrap stops, disables, masks, and verifies the installed manager before firewall startup. |
| Docker or remaining firewall conflict | Bootstrap/readiness failure; no approval pause. |
| Create fails after VM creation | Partial VM retained and resumable. |
| Unsupported Windows/Hyper-V version | Compatibility failure before mutation. |
| Effective NIC budget below 16 | Capacity reflects main plus private adapters. |
| Network limit reached, existing network has IPs | Guest creation on existing network remains valid. |
| Explicit unhealthy orchestrator | Precise failure; no automatic substitution. |
| Main IP changes | Relays rebind on restart or explicit request; server addresses change only on reconcile. |
| Lost orchestrator delete without cascade | Refused. |
| Lost orchestrator cascade | Exact approved child plan executed from host state. |
| Frozen parent receives unrelated child repair/NAT/rebind | `PARENT_FROZEN`; no effect. |
| Frozen parent receives enumerated cascade cleanup | Exact current fence/revision/action is admitted. |
| Cascade names a child/action outside approved plan | Rejected before target-side external effect. |
| Cascade interrupted and same revision resumes | Completed items skipped; unfinished items continue under newly rebound fence without new approval. |
| Cascade inventory drifts before resume | Pause and require a new revision/approval. |

### 23.3 Networks

| Test | Expected |
|---|---|
| Create private network | Private switch, no host vNIC. |
| First subnet | `192.168.240.0/26`, gateway `.1`. |
| Reserved addresses | `.2-.9` never allocated. |
| Guest pool | `.10-.62` only. |
| 17th network | Capacity error. |
| Remove nonempty network | Refused. |
| Same CIDR on two orchestrators | Supported. |
| Candidate `/26` overlaps main address/route | Candidate reserved as conflict and not allocated. |
| Main link has only `0.0.0.0/0` plus non-overlapping connected route | Candidate `/26` remains available. |
| DHCP/static/policy route with non-default overlapping prefix | Candidate `/26` is rejected. |
| Specific host route inside candidate `/26` | Candidate `/26` is rejected. |
| Main route overlaps whole `/20` | Network capacity is zero; no VRF workaround. |
| Cross-network IPv4 | Blocked. |
| Same-switch peer traffic | Allowed directly. |

### 23.4 Relays

| Test | Expected |
|---|---|
| Guest mTLS through relay | Certificate verified as guest identity. |
| TLS capture at orchestrator | Opaque TLS only; no termination. |
| Target other than guest:9091 | Rejected. |
| Half-close | Opposite direction drains correctly. |
| Idle connection | No LabLink idle timeout. |
| Main IP change | Bind-new then close-old. |
| Agent restart | Persistent listeners restored before ready. |
| First boot with corrupt appliance DB | Emergency forward-drop policy active and IP forwarding off. |
| Agent/ruleset failure while running | Watchdog restores emergency policy before disabling forwarding. |
| Port conflict | Degraded, persistent port not silently changed. |
| Remove relay with active connection | Listener/dials stop; bounded drain or cancellation closes remaining copies; port stays reserved until zero active connections. |
| Remove relay from live VM after drain | Relay/port retire; VM, IP, MAC, mark, NAT, and subnet remain live. |
| Relay-only remove with active NAT flow | NAT conntrack is untouched and does not block relay-port release. |
| VM delete after relay retirement | VM absence and marked-flow retirement gate IP/MAC/mark release. |
| Rebind with active connection | Existing connection survives; allocation/generation is not retired. |
| Stats | Connections, bytes, failures, timestamps, generations accurate. |

### 23.5 Guests

| Test | Expected |
|---|---|
| Windows create | Static IP/gateway/DNS and relay enrollment. |
| Linux create | Static Netplan by MAC and relay enrollment. |
| Generic DHCP config exists | Main config becomes MAC-scoped; private NIC never obtains DHCP. |
| Private NIC hot-add | Targeted reload/reconfigure; main route remains unchanged. |
| Appliance reboot | Effective networkd file, MAC, static IP, and no DHCP reverified. |
| Guest NIC count | Only managed private NIC for isolated path. |
| Time skew before boot | Hyper-V time integration repairs before mTLS. |
| NAT default | Disabled. |
| NAT-dependent first boot | Enabled NAT is applied and verified before VM start. |
| DNS with NAT disabled | Main DNS unreachable as documented. |
| DNS refresh | All online guests updated; offline guests pending. |
| Domain join without services | Rejected before mutation. |
| Domain join with valid services | Runs only after relay mTLS and static network verification. |
| Online bootstrap without NAT/prestage | Rejected before mutation. |
| Display rename | Hyper-V and TLS identities unchanged. |
| Repairable network fault | Repaired without recreate. |
| Unrepairable fault | Old VHD deleted exactly; VM recreated with same allocation. |
| Delete default | Exact owned storage deleted; parent retained. |

### 23.6 NAT

| Test | Expected |
|---|---|
| Enable | Internet, DNS, and reachable main network work. |
| Destination allowlist attempt | Unsupported; NAT is unrestricted. |
| Disable with active flow | Existing flow drains, new flow blocked. |
| Draining with no flow | Becomes disabled. |
| Agent restart while draining | Conntrack removed; state disabled. |
| Orchestrator reboot | State disabled after restart. |
| Relay while NAT disabled | Still works. |
| Conntrack drain selection | Only entries with the VM's persisted nonzero mark and matching original source/interface are counted/deleted; relay mark 0 is untouched. |
| Cross-private established packet | Dropped before established handling. |
| Private guest to orchestrator TCP/UDP | Dropped; only specified ICMP gateway traffic allowed. |
| Private ICMP echo to exact gateway IPv4 | Accepted. |
| Private ICMP to another orchestrator local IPv4 | Dropped before broad ICMP rule. |
| Established private ICMP echo reply to a non-gateway local IPv4 | Dropped before any broad established acceptance. |
| Related private ICMP error to a non-gateway local IPv4 | Dropped before any broad related acceptance. |
| Permitted private ICMP to the exact gateway IPv4 | Accepted by the gateway/type guard. |
| Private reply on orchestrator-originated relay TCP flow | Accepted only for the exact managed guest, gateway destination, TCP source port 9091, established reply direction, and active relay mapping. |
| Private guest starts TCP to gateway 9091 or DNS port | Dropped. |
| Main-interface required ICMP and echo | Accepted by the main-scoped ICMP rule. |
| Spoofed source | Accepted caveat documented; no false guarantee. |
| IPv6 traffic | Unmanaged caveat surfaced. |

### 23.7 Approval and operations

| Test | Expected |
|---|---|
| Ordinary VM/network/NAT mutation | No elicitation. |
| Orchestrator create | Approval required for exact plan revision. |
| Plan changes after approval | Approval invalidated. |
| Orchestrator delete | Approval required. |
| Cascade contents change | New revision and approval required. |
| Conflict-manager disable | Automatic bootstrap action; failure blocks readiness. |
| MCP disconnect | Durable operation remains resumable. |
| Portal | Read-only topology/status/operation views. |

### 23.8 DNS, registry, and update compatibility

| Test | Expected |
|---|---|
| systemd-resolved stub in `/etc/resolv.conf` | `127.0.0.53` rejected; actual main-link upstreams used. |
| Split-DNS routing domains | Not copied; limitation surfaced. |
| Excess search domains | Deterministically bounded and status reports truncation. |
| No upstream resolver | Empty DNS state; DNS-dependent bootstrap rejected. |
| Guest offline during DNS refresh | Durable pending update persists and applies on reconnect. |
| YAML export/import of relayed guest | Address and optional `TLSServerName` round-trip exactly; strict mTLS succeeds. |
| Online package install | Exact manifest versions and signed repository/hash verification. |
| Offline package install | Complete dependency closure and every artifact hash verified. |
| Missing kernel facility | Forwarding remains blocked; appliance not ready. |
| Additive DB migration then update success | New agent reports capabilities/schema/policy/appliance ready. |
| Post-update readiness failure | Compatibility-safe rollback only; otherwise new binary remains fail-closed with repair guidance. |

### 23.9 Security regression

- Existing non-isolated tools and node registry tests remain green.
- Existing direct `forward_port` behavior remains unchanged.
- Existing Windows and Linux VM paths remain unchanged when isolated mode is
  not selected.
- Secrets do not appear in SQLite request JSON, events, approval plans, logs,
  portal output, or tool results.
- Every destructive test includes mismatched ID/path/name cases that must fail
  closed.
- Protobuf compatibility is tested with an old agent and a new server.
- Hyper-V uncertain-create tests cover zero, one, multiple, and mismatched
  switch/VM/adapter GUID discoveries.
- Every host mutation test changes the fence or ownership ID between precheck
  and script mutation and verifies fail-closed behavior.

## 24. Open questions

The reviewed architecture contracts are specified above. The following are
release or deployment facts that must be supplied and validated, not choices
that may be guessed by implementation:

- Each release must check in the exact Ubuntu package versions, snapshot
  identity, dependency closure, and artifact hashes required by Section 18.5.
- The supported-host CI/lab matrix must record the observed maximum synthetic
  adapter count for every supported Windows SKU/build; runtime capacity still
  uses the host probe and the effective-budget formula.
- Each deployment supplies the existing Ubuntu Linux profile, main vSwitch,
  managed storage roots, and parent image paths.
- Each deployment chooses online pinned package retrieval or supplies the
  optional verified offline bundle.

Implementation is not permitted to replace these facts with latest-version
downloads, hostname identity, assumed adapter limits, or unverified defaults.

## 25. Independent review closure matrix

| Finding | Normative resolution |
|---|---|
| Authoritative cross-server allocation | Sections 6.3-6.5 define appliance transactions, discovery/import, parent guards, typed collisions, and recovery. |
| Host identity and fencing | Sections 8.5 and 16 define physical identity, aliases, process identity, renewal/reclamation, lease secrets, fences, freeze, and lock order. |
| Crash-safe external apply | Section 7.4 defines intent, compile, pre-apply fence, apply, observe, commit, and readiness. |
| Tombstone reuse | Section 6.2-6.3 uses live-only partial indexes plus allocation history. |
| Pre-boot NAT and domain join order | Sections 13.1 and 15.4 apply/verify NAT before start and join only after relay/network verification. |
| Fail-closed boot | Sections 7.3 and 10.4 define emergency policy and forwarding-off ordering independent of readiness. |
| networkd precedence | Section 10.2 replaces generic `hv_netvsc` matching with MAC-scoped main/private definitions and targeted verification. |
| Retirement barrier | Section 9.5 separates rebind, relay-only port retirement, VM retirement, and network retirement with resource-specific release gates. |
| Hyper-V immutable identity | Section 11 persists and validates switch GUID, adapter ID/MAC, VM GUID, uncertain creates, and delete guards. |
| Main-route overlap | Section 10.1 rejects/reserves overlapping `/26` ranges without VRF fallback. |
| TLS name import/export | Section 8.1 requires exact optional `TLSServerName` YAML round-trip and strict verification. |
| Stable mutation identity | Sections 6.5 and 14.1 define per-phase mutation IDs, semantic hashes, canonical inputs, and generations. |
| Upstream DNS | Section 10.6 defines main-link extraction, stub rejection, split/search limits, no-resolver behavior, and pending updates. |
| IPv4 packet path | Sections 10.3-10.5 define ordered INPUT/FORWARD/NAT policy and exact marked conntrack handling. |
| Compatibility/health/capacity | Sections 12.1-12.2 separate predicates, host versions, effective adapter budget, and explicit/auto behavior. |
| Dependencies and updater | Section 18.5 pins package closure/facilities, migration compatibility, rollback rules, and post-update readiness. |
| Target-side fence linearization | Sections 7.4 and 16.4 serialize admission, handoff acknowledgment, and external host/appliance check-and-act. |
| Frozen-parent cascade authority | Sections 12.5 and 15.7 permit only enumerated revision-bound cleanup and define interrupted resume. |
| Default-route overlap semantics | Section 10.1 excludes only literal `0.0.0.0/0` while checking connected and all specific routes. |
| Relay-only versus VM retirement | Section 9.5 releases only the relay port for a live VM and separately gates VM/network allocation reuse. |
| Private/main ICMP ordering | Section 10.3 applies private gateway-only ICMP and terminal private drop before main-scoped ICMP acceptance. |
