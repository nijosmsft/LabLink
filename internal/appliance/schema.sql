CREATE TABLE IF NOT EXISTS appliance_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS appliance_status (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    inventory_generation INTEGER NOT NULL,
    ready INTEGER NOT NULL CHECK (ready IN (0, 1)),
    error_text TEXT NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

INSERT OR IGNORE INTO appliance_status
    (singleton, inventory_generation, ready, error_text, updated_at_unix)
VALUES (1, 0, 0, '', 0);

CREATE TABLE IF NOT EXISTS appliance_authority (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    physical_host_id TEXT NOT NULL,
    host_lease_id TEXT NOT NULL,
    host_lease_secret_hash TEXT NOT NULL,
    host_lease_expires_unix INTEGER NOT NULL,
    fence INTEGER NOT NULL,
    parent_generation INTEGER NOT NULL,
    parent_state TEXT NOT NULL CHECK (parent_state IN
        ('active','frozen','deleting','lost','deleted')),
    handoff_pending INTEGER NOT NULL CHECK (handoff_pending IN (0, 1)),
    updated_at_unix INTEGER NOT NULL
);

INSERT OR IGNORE INTO appliance_authority (
    singleton, physical_host_id, host_lease_id, host_lease_secret_hash,
    host_lease_expires_unix, fence, parent_generation, parent_state,
    handoff_pending, updated_at_unix
) VALUES (1, '', '', '', 0, 0, 0, 'active', 0, 0);

CREATE TABLE IF NOT EXISTS capacity_limits (
    kind TEXT PRIMARY KEY,
    max_units INTEGER NOT NULL CHECK (max_units >= 0)
);

INSERT OR IGNORE INTO capacity_limits(kind, max_units) VALUES
    ('network', 16),
    ('guest', 100),
    ('relay', 100);

CREATE TABLE IF NOT EXISTS networks (
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
    incarnation INTEGER NOT NULL DEFAULT 1,
    state TEXT NOT NULL,
    last_error TEXT,
    retired_at_unix INTEGER
);

CREATE TABLE IF NOT EXISTS guests (
    id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(id),
    ipv4 TEXT NOT NULL,
    mac TEXT NOT NULL,
    desired_generation INTEGER NOT NULL,
    applied_generation INTEGER NOT NULL,
    observed_generation INTEGER NOT NULL,
    parent_generation INTEGER NOT NULL,
    incarnation INTEGER NOT NULL DEFAULT 1,
    state TEXT NOT NULL,
    last_error TEXT,
    retired_at_unix INTEGER
);

CREATE TABLE IF NOT EXISTS relays (
    id TEXT PRIMARY KEY,
    vm_id TEXT NOT NULL REFERENCES guests(id),
    listen_port INTEGER NOT NULL CHECK (listen_port BETWEEN 20000 AND 39999),
    target_ipv4 TEXT NOT NULL,
    target_port INTEGER NOT NULL CHECK (target_port = 9091),
    desired_generation INTEGER NOT NULL,
    applied_generation INTEGER NOT NULL,
    observed_generation INTEGER NOT NULL,
    parent_generation INTEGER NOT NULL,
    incarnation INTEGER NOT NULL DEFAULT 1,
    state TEXT NOT NULL,
    bound_main_ip TEXT,
    last_bind_error TEXT,
    retired_at_unix INTEGER
);

CREATE TABLE IF NOT EXISTS nat_state (
    vm_id TEXT PRIMARY KEY REFERENCES guests(id),
    state TEXT NOT NULL CHECK (state IN ('enabled','draining','disabled')),
    conntrack_mark INTEGER NOT NULL,
    desired_generation INTEGER NOT NULL,
    applied_generation INTEGER NOT NULL,
    observed_generation INTEGER NOT NULL,
    parent_generation INTEGER NOT NULL,
    drain_started_unix INTEGER,
    last_error TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_appliance_live_network_mac
    ON networks(nic_mac)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_appliance_live_guest_ip
    ON guests(network_id, ipv4)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_appliance_live_guest_mac
    ON guests(mac)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_appliance_live_relay_vm
    ON relays(vm_id)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_appliance_live_relay_port
    ON relays(listen_port)
    WHERE retired_at_unix IS NULL;

CREATE TABLE IF NOT EXISTS applied_operations (
    mutation_id TEXT PRIMARY KEY,
    parent_operation_id TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    result_json TEXT NOT NULL,
    applied_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS reservations (
    id TEXT PRIMARY KEY,
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    network_id TEXT,
    subnet_index INTEGER,
    ipv4 TEXT,
    mac TEXT,
    listen_port INTEGER CHECK (listen_port IS NULL OR listen_port BETWEEN 1 AND 65535),
    conntrack_mark INTEGER,
    capacity_kind TEXT,
    capacity_units INTEGER CHECK (capacity_units IS NULL OR capacity_units > 0),
    state TEXT NOT NULL CHECK (state IN ('active','retired')),
    parent_generation INTEGER NOT NULL,
    created_at_unix INTEGER NOT NULL,
    retired_at_unix INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_appliance_live_resource_reservation
    ON reservations(resource_kind, resource_id)
    WHERE retired_at_unix IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_appliance_live_subnet
    ON reservations(subnet_index)
    WHERE subnet_index IS NOT NULL AND retired_at_unix IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_appliance_live_ip
    ON reservations(network_id, ipv4)
    WHERE ipv4 IS NOT NULL AND retired_at_unix IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_appliance_live_mac
    ON reservations(mac)
    WHERE mac IS NOT NULL AND retired_at_unix IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_appliance_live_port
    ON reservations(listen_port)
    WHERE listen_port IS NOT NULL AND retired_at_unix IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_appliance_live_conntrack_mark
    ON reservations(conntrack_mark)
    WHERE conntrack_mark IS NOT NULL AND retired_at_unix IS NULL;
CREATE INDEX IF NOT EXISTS idx_appliance_live_capacity
    ON reservations(capacity_kind)
    WHERE capacity_kind IS NOT NULL AND retired_at_unix IS NULL;

CREATE TABLE IF NOT EXISTS apply_intents (
    mutation_id TEXT PRIMARY KEY,
    parent_operation_id TEXT NOT NULL,
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    parent_resource_id TEXT NOT NULL,
    desired_generation INTEGER NOT NULL,
    parent_generation INTEGER NOT NULL,
    fence INTEGER NOT NULL,
    semantic_hash TEXT NOT NULL,
    compiled_hash TEXT,
    phase TEXT NOT NULL CHECK (phase IN
        ('pending','compiled','applying','failed','complete')),
    error_text TEXT,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_appliance_recovery_intents
    ON apply_intents(phase, created_at_unix, mutation_id);
