CREATE TABLE appliance_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE appliance_status (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    ready INTEGER NOT NULL CHECK (ready IN (0, 1)),
    error_text TEXT NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

INSERT INTO appliance_status(singleton, ready, error_text, updated_at_unix)
VALUES (1, 0, '', 0);

CREATE TABLE networks (
    id TEXT PRIMARY KEY,
    cidr TEXT NOT NULL,
    gateway_ipv4 TEXT NOT NULL,
    nic_mac TEXT NOT NULL UNIQUE,
    interface_name TEXT,
    dns_servers_json TEXT NOT NULL,
    state TEXT NOT NULL,
    last_error TEXT
);

CREATE TABLE guests (
    id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(id),
    ipv4 TEXT NOT NULL,
    mac TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL,
    last_error TEXT,
    UNIQUE(network_id, ipv4)
);

CREATE TABLE relays (
    id TEXT PRIMARY KEY,
    vm_id TEXT NOT NULL UNIQUE REFERENCES guests(id),
    listen_port INTEGER NOT NULL UNIQUE CHECK (listen_port BETWEEN 20000 AND 39999),
    target_ipv4 TEXT NOT NULL,
    target_port INTEGER NOT NULL CHECK (target_port = 9091),
    state TEXT NOT NULL,
    bound_main_ip TEXT,
    last_bind_error TEXT
);

CREATE TABLE nat_state (
    vm_id TEXT PRIMARY KEY REFERENCES guests(id),
    state TEXT NOT NULL CHECK (state IN ('enabled','disabled')),
    conntrack_mark INTEGER NOT NULL UNIQUE,
    last_error TEXT
);
