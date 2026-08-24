CREATE TABLE IF NOT EXISTS source_fetch_jobs (
    fetch_job_id text PRIMARY KEY,
    batch_id text NOT NULL REFERENCES extraction_batches(batch_id),
    source_id text NOT NULL REFERENCES official_sources(source_id),
    canonical_url text NOT NULL,
    status text NOT NULL CHECK (
        status IN ('pending', 'leased', 'completed', 'failed')
    ),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    attempt_limit integer NOT NULL DEFAULT 5 CHECK (attempt_limit > 0),
    retry_rounds integer NOT NULL DEFAULT 0 CHECK (retry_rounds >= 0),
    lease_owner text,
    lease_expires_at timestamptz,
    next_attempt_at timestamptz,
    lease_renewals integer NOT NULL DEFAULT 0 CHECK (lease_renewals >= 0),
    snapshot_hash char(64) REFERENCES source_snapshots(snapshot_hash),
    retrieval_id text REFERENCES source_snapshot_retrievals(retrieval_id),
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE (batch_id, source_id)
);

CREATE INDEX IF NOT EXISTS source_fetch_jobs_claim_idx
    ON source_fetch_jobs (
        batch_id, status, next_attempt_at, lease_expires_at,
        attempts, attempt_limit, created_at
    );

CREATE INDEX IF NOT EXISTS source_fetch_jobs_source_idx
    ON source_fetch_jobs (source_id, completed_at);
