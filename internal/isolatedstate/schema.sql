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
    lifecycle_state TEXT NOT NULL,
    health_state TEXT NOT NULL DEFAULT 'unknown',
    max_networks INTEGER NOT NULL DEFAULT 16,
    max_vms INTEGER NOT NULL DEFAULT 100,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    last_seen_unix INTEGER
);

CREATE TABLE private_networks (
    id TEXT PRIMARY KEY,
    orchestrator_id TEXT NOT NULL REFERENCES orchestrators(id),
    display_name TEXT NOT NULL,
    hyperv_switch_name TEXT NOT NULL UNIQUE,
    hyperv_switch_guid TEXT,
    orchestrator_adapter_id TEXT,
    subnet_index INTEGER NOT NULL,
    cidr TEXT NOT NULL,
    gateway_ipv4 TEXT NOT NULL,
    orchestrator_mac TEXT NOT NULL,
    dns_servers_json TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    retired_at_unix INTEGER
);

CREATE TABLE isolated_vms (
    id TEXT PRIMARY KEY,
    orchestrator_id TEXT NOT NULL REFERENCES orchestrators(id),
    network_id TEXT NOT NULL REFERENCES private_networks(id),
    display_name TEXT NOT NULL,
    hyperv_name TEXT NOT NULL,
    hyperv_vm_id TEXT,
    hyperv_adapter_id TEXT,
    node_name TEXT NOT NULL,
    guest_os TEXT NOT NULL,
    profile_name TEXT NOT NULL,
    ipv4 TEXT NOT NULL,
    mac TEXT NOT NULL,
    prefix_length INTEGER NOT NULL DEFAULT 26,
    gateway_ipv4 TEXT NOT NULL,
    dns_servers_json TEXT NOT NULL,
    storage_root TEXT NOT NULL,
    vm_path TEXT NOT NULL,
    vhd_path TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    retired_at_unix INTEGER
);

CREATE UNIQUE INDEX uq_live_vm_name ON isolated_vms(hyperv_name)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_live_vm_node ON isolated_vms(node_name)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_live_vm_ip ON isolated_vms(orchestrator_id, ipv4)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_live_vm_mac ON isolated_vms(orchestrator_id, mac)
    WHERE retired_at_unix IS NULL;

CREATE TABLE relay_allocations (
    id TEXT PRIMARY KEY,
    vm_id TEXT NOT NULL REFERENCES isolated_vms(id),
    orchestrator_id TEXT NOT NULL REFERENCES orchestrators(id),
    listen_port INTEGER NOT NULL,
    target_ipv4 TEXT NOT NULL,
    target_port INTEGER NOT NULL DEFAULT 9091,
    lifecycle_state TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    retired_at_unix INTEGER
);

CREATE UNIQUE INDEX uq_live_relay_vm ON relay_allocations(vm_id)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX uq_live_relay_port ON relay_allocations(orchestrator_id, listen_port)
    WHERE retired_at_unix IS NULL;

CREATE TABLE nat_allocations (
    vm_id TEXT PRIMARY KEY REFERENCES isolated_vms(id),
    orchestrator_id TEXT NOT NULL REFERENCES orchestrators(id),
    state TEXT NOT NULL,
    conntrack_mark INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);
