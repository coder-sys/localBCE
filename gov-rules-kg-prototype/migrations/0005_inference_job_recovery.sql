ALTER TABLE inference_jobs
    ADD COLUMN IF NOT EXISTS attempt_limit integer NOT NULL DEFAULT 5
        CHECK (attempt_limit > 0),
    ADD COLUMN IF NOT EXISTS retry_rounds integer NOT NULL DEFAULT 0
        CHECK (retry_rounds >= 0),
    ADD COLUMN IF NOT EXISTS lease_renewals integer NOT NULL DEFAULT 0
        CHECK (lease_renewals >= 0);

CREATE INDEX IF NOT EXISTS inference_jobs_recovery_idx
    ON inference_jobs (status, lease_expires_at, attempts, attempt_limit);
