BEGIN;

ALTER TABLE source_registry_candidates
    ADD COLUMN IF NOT EXISTS preflight_version text,
    ADD COLUMN IF NOT EXISTS preflight_score integer CHECK (
        preflight_score IS NULL OR preflight_score BETWEEN 0 AND 100
    ),
    ADD COLUMN IF NOT EXISTS preflight_blockers jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(preflight_blockers) = 'array'),
    ADD COLUMN IF NOT EXISTS preflight_signals jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(preflight_signals) = 'object'),
    ADD COLUMN IF NOT EXISTS preflight_hash char(64),
    ADD COLUMN IF NOT EXISTS preflight_assessed_at timestamptz;

CREATE INDEX IF NOT EXISTS source_registry_candidates_preflight_review_idx
    ON source_registry_candidates (
        review_status,
        preflight_version,
        preflight_score DESC,
        program,
        source_candidate_id
    );

INSERT INTO schema_migrations(version)
VALUES ('0013_source_candidate_preflight')
ON CONFLICT (version) DO NOTHING;

COMMIT;
