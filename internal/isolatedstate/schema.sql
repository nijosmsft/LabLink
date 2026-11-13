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
