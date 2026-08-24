BEGIN;

ALTER TABLE quality_sample_plans
    DROP CONSTRAINT IF EXISTS quality_sample_plans_status_check;

ALTER TABLE quality_sample_plans
    ADD CONSTRAINT quality_sample_plans_status_check CHECK (
        status IN (
            'pending_policy', 'claimed_policy', 'pending_legal',
            'claimed_legal', 'completed', 'invalidated'
        )
    ),
    ADD COLUMN IF NOT EXISTS invalidated_at timestamptz,
    ADD COLUMN IF NOT EXISTS invalidation_reason text;

DROP TRIGGER IF EXISTS corpus_release_cohorts_immutable ON corpus_release_cohorts;

ALTER TABLE corpus_release_cohorts
    ADD COLUMN IF NOT EXISTS draft_id text,
    ADD COLUMN IF NOT EXISTS draft_hash char(64),
    ADD COLUMN IF NOT EXISTS snapshot_hash char(64),
    ADD COLUMN IF NOT EXISTS section_id text,
    ADD COLUMN IF NOT EXISTS source_registry_version text,
    ADD COLUMN IF NOT EXISTS extraction_pipeline_version text;

WITH latest_drafts AS (
    SELECT DISTINCT ON (candidate_id)
           candidate_id, draft_id, canonical_hash
    FROM typed_rule_drafts
    ORDER BY candidate_id, draft_version DESC, draft_id
)
UPDATE corpus_release_cohorts cohorts
SET draft_id = drafts.draft_id,
    draft_hash = drafts.canonical_hash,
    snapshot_hash = candidates.snapshot_hash,
    section_id = candidates.section_id,
    source_registry_version = sources.registry_version,
    extraction_pipeline_version = sections.extraction_pipeline_version
FROM grounded_candidates candidates
JOIN latest_drafts drafts USING (candidate_id)
JOIN source_sections sections USING (section_id)
JOIN source_snapshot_retrievals retrievals USING (retrieval_id)
JOIN official_sources sources USING (source_id)
WHERE cohorts.candidate_id = candidates.candidate_id
  AND (
      cohorts.draft_id IS NULL
      OR cohorts.draft_hash IS NULL
      OR cohorts.snapshot_hash IS NULL
      OR cohorts.section_id IS NULL
      OR cohorts.source_registry_version IS NULL
      OR cohorts.extraction_pipeline_version IS NULL
  );

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM corpus_release_cohorts
        WHERE draft_id IS NULL
           OR draft_hash IS NULL
           OR snapshot_hash IS NULL
           OR section_id IS NULL
           OR source_registry_version IS NULL
           OR extraction_pipeline_version IS NULL
    ) THEN
        RAISE EXCEPTION 'existing corpus release cohort lacks complete current lineage';
    END IF;
END;
$$;

ALTER TABLE corpus_release_cohorts
    ALTER COLUMN draft_id SET NOT NULL,
    ALTER COLUMN draft_hash SET NOT NULL,
    ALTER COLUMN snapshot_hash SET NOT NULL,
    ALTER COLUMN section_id SET NOT NULL,
    ALTER COLUMN source_registry_version SET NOT NULL,
    ALTER COLUMN extraction_pipeline_version SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'corpus_release_cohorts_draft_fk'
    ) THEN
        ALTER TABLE corpus_release_cohorts
            ADD CONSTRAINT corpus_release_cohorts_draft_fk
            FOREIGN KEY (draft_id) REFERENCES typed_rule_drafts(draft_id);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'corpus_release_cohorts_snapshot_fk'
    ) THEN
        ALTER TABLE corpus_release_cohorts
            ADD CONSTRAINT corpus_release_cohorts_snapshot_fk
            FOREIGN KEY (snapshot_hash) REFERENCES source_snapshots(snapshot_hash);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'corpus_release_cohorts_section_fk'
    ) THEN
        ALTER TABLE corpus_release_cohorts
            ADD CONSTRAINT corpus_release_cohorts_section_fk
            FOREIGN KEY (section_id) REFERENCES source_sections(section_id);
    END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS quality_sample_plans_invalidation_idx
    ON quality_sample_plans (status, release_id, invalidated_at);

CREATE INDEX IF NOT EXISTS corpus_release_cohorts_lineage_idx
    ON corpus_release_cohorts (
        release_id, source_registry_version, extraction_pipeline_version
    );

CREATE TRIGGER corpus_release_cohorts_immutable
    BEFORE UPDATE OR DELETE ON corpus_release_cohorts
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

INSERT INTO schema_migrations(version) VALUES ('0009_quality_release_lineage')
ON CONFLICT (version) DO NOTHING;

COMMIT;
