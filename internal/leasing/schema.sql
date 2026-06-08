-- LabLink lease store schema. Mirrors design memo Section 8.3.

PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
PRAGMA synchronous  = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS leases (
    id                    TEXT PRIMARY KEY,
    agent_id              TEXT NOT NULL,
    cookie                TEXT NOT NULL DEFAULT '',
    hostname              TEXT NOT NULL DEFAULT '',
    pid                   INTEGER NOT NULL DEFAULT 0,
    process_start_unix    INTEGER NOT NULL DEFAULT 0,
    reason                TEXT NOT NULL DEFAULT '',
    acquired_at_unix      INTEGER NOT NULL,
    expires_at_unix       INTEGER NOT NULL,
    monotonic_acquired_ns INTEGER NOT NULL DEFAULT 0,
    state                 TEXT NOT NULL CHECK (state IN
                                ('acquired','released','expired','forced')),
    released_at_unix      INTEGER
);

CREATE TABLE IF NOT EXISTS lease_nodes (
    lease_id   TEXT NOT NULL REFERENCES leases(id) ON DELETE CASCADE,
    node_name  TEXT NOT NULL,
    PRIMARY KEY (lease_id, node_name)
);

-- Hot-path index for "is this node held?" lookups during Acquire conflict
-- detection. SQLite forbids subqueries in partial-index WHERE clauses,
-- so we use a plain index on node_name; the activity filter (state='acquired')
-- is applied via JOIN to the leases table in the conflict-detection query.
CREATE INDEX IF NOT EXISTS idx_lease_nodes_node
    ON lease_nodes(node_name);

CREATE TABLE IF NOT EXISTS lease_audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    lease_id   TEXT NOT NULL,
    op         TEXT NOT NULL,
    agent_id   TEXT,
    at_unix    INTEGER NOT NULL,
    detail     TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_lease ON lease_audit(lease_id);
CREATE INDEX IF NOT EXISTS idx_audit_time  ON lease_audit(at_unix);
