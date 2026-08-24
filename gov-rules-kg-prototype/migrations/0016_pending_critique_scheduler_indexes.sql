BEGIN;

CREATE INDEX IF NOT EXISTS inference_jobs_section_contract_idx
    ON inference_jobs (
        section_id,
        pass,
        prompt_version,
        model_version,
        schema_version,
        (request_payload->>'response_contract_version')
    );

CREATE INDEX IF NOT EXISTS grounded_candidates_pending_critique_idx
    ON grounded_candidates (
        extraction_contract_key,
        section_id,
        candidate_id
    )
    WHERE grounding_status = 'pending'
      AND critique_contract_key IS NULL;

INSERT INTO schema_migrations(version)
VALUES ('0016_pending_critique_scheduler_indexes')
ON CONFLICT (version) DO NOTHING;

COMMIT;
