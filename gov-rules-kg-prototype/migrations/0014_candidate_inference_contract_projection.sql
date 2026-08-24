BEGIN;

ALTER TABLE grounded_candidates
    ADD COLUMN IF NOT EXISTS extraction_contract_key char(64),
    ADD COLUMN IF NOT EXISTS critique_contract_key char(64);

ALTER TABLE corpus_release_cohorts
    ADD COLUMN IF NOT EXISTS extraction_contract_key char(64),
    ADD COLUMN IF NOT EXISTS critique_contract_key char(64);

CREATE INDEX IF NOT EXISTS grounded_candidates_current_contract_idx
    ON grounded_candidates (
        extraction_contract_key,
        critique_contract_key,
        grounding_status,
        primary_program,
        candidate_id
    );

INSERT INTO schema_migrations(version)
VALUES ('0014_candidate_inference_contract_projection')
ON CONFLICT (version) DO NOTHING;

COMMIT;
