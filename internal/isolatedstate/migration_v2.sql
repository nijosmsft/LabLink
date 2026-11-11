CREATE TABLE lock_fences (
    lock_key TEXT PRIMARY KEY,
    last_fence INTEGER NOT NULL CHECK (last_fence > 0)
);

INSERT INTO lock_fences(lock_key, last_fence)
SELECT lock_key, CASE WHEN fence > 0 THEN fence ELSE 1 END
FROM locks;

CREATE TABLE cascade_authorities (
    orchestrator_id TEXT PRIMARY KEY REFERENCES orchestrators(id),
    frozen_generation INTEGER NOT NULL,
    operation_id TEXT NOT NULL REFERENCES operations(id),
    plan_revision TEXT NOT NULL,
    plan_hash TEXT NOT NULL,
    host_fence INTEGER NOT NULL,
    lease_id TEXT NOT NULL,
    installed_at_unix INTEGER NOT NULL
);

CREATE TABLE cascade_authority_items (
    orchestrator_id TEXT NOT NULL REFERENCES cascade_authorities(orchestrator_id)
        ON DELETE CASCADE,
    mutation_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    expected_host_identity TEXT,
    expected_appliance_identity TEXT,
    expected_generation INTEGER NOT NULL,
    completed_at_unix INTEGER,
    PRIMARY KEY(orchestrator_id, mutation_id),
    UNIQUE(orchestrator_id, action, resource_type, resource_id)
);
