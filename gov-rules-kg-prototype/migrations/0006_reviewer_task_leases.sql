ALTER TABLE reviewer_tasks
    ADD COLUMN IF NOT EXISTS claim_expires_at timestamptz,
    ADD COLUMN IF NOT EXISTS claim_attempts integer NOT NULL DEFAULT 0
        CHECK (claim_attempts >= 0);

ALTER TABLE quality_sample_plans
    ADD COLUMN IF NOT EXISTS claimed_at timestamptz,
    ADD COLUMN IF NOT EXISTS claim_expires_at timestamptz,
    ADD COLUMN IF NOT EXISTS claim_attempts integer NOT NULL DEFAULT 0
        CHECK (claim_attempts >= 0);

ALTER TABLE source_registry_candidates
    ADD COLUMN IF NOT EXISTS claimed_at timestamptz,
    ADD COLUMN IF NOT EXISTS claim_expires_at timestamptz,
    ADD COLUMN IF NOT EXISTS claim_attempts integer NOT NULL DEFAULT 0
        CHECK (claim_attempts >= 0);

-- Claims created before leases existed must be recoverable immediately instead
-- of remaining permanently assigned with a NULL expiry.
UPDATE reviewer_tasks
SET claim_expires_at = now()
WHERE status = 'claimed' AND claim_expires_at IS NULL;

UPDATE quality_sample_plans
SET claim_expires_at = now()
WHERE status IN ('claimed_policy', 'claimed_legal')
  AND claim_expires_at IS NULL;

UPDATE source_registry_candidates
SET claim_expires_at = now()
WHERE review_status = 'claimed_review' AND claim_expires_at IS NULL;

CREATE INDEX IF NOT EXISTS reviewer_tasks_lease_recovery_idx
    ON reviewer_tasks (status, claim_expires_at, task_type);

CREATE INDEX IF NOT EXISTS quality_sample_plans_lease_recovery_idx
    ON quality_sample_plans (status, claim_expires_at, release_id);

CREATE INDEX IF NOT EXISTS source_registry_candidates_lease_recovery_idx
    ON source_registry_candidates (review_status, claim_expires_at, program);
