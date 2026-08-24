-- Source-registry reviews are valid only for the exact captured parent bytes.
ALTER TABLE source_registry_candidates
    DROP CONSTRAINT IF EXISTS source_registry_candidates_review_status_check;

ALTER TABLE source_registry_candidates
    ADD CONSTRAINT source_registry_candidates_review_status_check CHECK (
        review_status IN (
            'pending_review',
            'claimed_review',
            'approved_for_registry',
            'rejected',
            'superseded'
        )
    );

ALTER TABLE source_registry_candidates
    ADD COLUMN IF NOT EXISTS superseded_at timestamptz,
    ADD COLUMN IF NOT EXISTS supersession_reason text;

CREATE INDEX IF NOT EXISTS source_registry_candidates_lineage_idx
    ON source_registry_candidates (
        parent_source_id,
        parent_retrieval_id,
        parent_snapshot_hash,
        review_status
    );

INSERT INTO schema_migrations(version)
VALUES ('0011_source_candidate_lineage')
ON CONFLICT (version) DO NOTHING;
