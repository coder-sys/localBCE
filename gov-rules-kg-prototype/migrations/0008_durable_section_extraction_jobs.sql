ALTER TABLE source_sections
    ADD COLUMN IF NOT EXISTS extraction_pipeline_version text NOT NULL
        DEFAULT 'legacy-v1',
    ADD COLUMN IF NOT EXISTS active boolean NOT NULL DEFAULT true;

DO $$
DECLARE
    constraint_name text;
BEGIN
    SELECT conname INTO constraint_name
    FROM pg_constraint
    WHERE conrelid = 'source_sections'::regclass
      AND contype = 'u'
      AND pg_get_constraintdef(oid) =
          'UNIQUE (snapshot_hash, ordinal, normalized_text_hash)';
    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE source_sections DROP CONSTRAINT %I', constraint_name);
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS source_sections_pipeline_identity_idx
    ON source_sections (
        snapshot_hash, extraction_pipeline_version, ordinal, normalized_text_hash
    );

CREATE INDEX IF NOT EXISTS source_sections_active_pipeline_idx
    ON source_sections (active, extraction_pipeline_version, retrieval_id);

CREATE TABLE IF NOT EXISTS section_extraction_jobs (
    extraction_job_id text PRIMARY KEY,
    retrieval_id text NOT NULL REFERENCES source_snapshot_retrievals(retrieval_id),
    snapshot_hash char(64) NOT NULL REFERENCES source_snapshots(snapshot_hash),
    pipeline_version text NOT NULL,
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
    parser_name text,
    parser_version text,
    section_count integer CHECK (section_count >= 0),
    warnings jsonb NOT NULL DEFAULT '[]'::jsonb,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE (retrieval_id, pipeline_version)
);

CREATE INDEX IF NOT EXISTS section_extraction_jobs_claim_idx
    ON section_extraction_jobs (
        pipeline_version, status, next_attempt_at, lease_expires_at,
        attempts, attempt_limit, created_at
    );
