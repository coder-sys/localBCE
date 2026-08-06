BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS official_sources (
    source_id text PRIMARY KEY,
    registry_version text NOT NULL,
    canonical_url text NOT NULL,
    program text NOT NULL,
    jurisdiction jsonb NOT NULL,
    issuer text NOT NULL,
    source_type text NOT NULL,
    required boolean NOT NULL DEFAULT false,
    official boolean NOT NULL CHECK (official),
    active boolean NOT NULL DEFAULT true,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (registry_version, canonical_url, program)
);

CREATE TABLE IF NOT EXISTS source_snapshots (
    snapshot_hash char(64) PRIMARY KEY,
    mime_type text NOT NULL,
    compression text NOT NULL CHECK (compression = 'zlib'),
    compressed_bytes bytea NOT NULL,
    uncompressed_size bigint NOT NULL CHECK (uncompressed_size >= 0),
    text_layer_kind text NOT NULL CHECK (text_layer_kind IN ('native', 'ocr', 'none')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS source_snapshot_retrievals (
    retrieval_id text PRIMARY KEY,
    snapshot_hash char(64) NOT NULL REFERENCES source_snapshots(snapshot_hash),
    source_id text NOT NULL REFERENCES official_sources(source_id),
    canonical_url text NOT NULL,
    retrieved_at timestamptz NOT NULL,
    http_status integer NOT NULL CHECK (http_status BETWEEN 100 AND 599),
    issuer text NOT NULL,
    effective_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    response_headers jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (source_id, snapshot_hash, retrieved_at)
);

CREATE TABLE IF NOT EXISTS source_sections (
    section_id text PRIMARY KEY,
    snapshot_hash char(64) NOT NULL REFERENCES source_snapshots(snapshot_hash),
    retrieval_id text NOT NULL REFERENCES source_snapshot_retrievals(retrieval_id),
    parent_section_id text REFERENCES source_sections(section_id),
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    hierarchy_path jsonb NOT NULL,
    heading text,
    normalized_text text NOT NULL,
    normalized_text_hash char(64) NOT NULL,
    source_char_start bigint,
    source_char_end bigint,
    parser_name text NOT NULL,
    parser_version text NOT NULL,
    ocr_used boolean NOT NULL DEFAULT false,
    UNIQUE (snapshot_hash, ordinal, normalized_text_hash)
);

CREATE TABLE IF NOT EXISTS extraction_batches (
    batch_id text PRIMARY KEY,
    schema_version text NOT NULL,
    registry_version text NOT NULL,
    status text NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    configuration jsonb NOT NULL,
    idempotency_key char(64) NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    completed_at timestamptz,
    error text
);

CREATE TABLE IF NOT EXISTS inference_jobs (
    inference_job_id text PRIMARY KEY,
    section_id text NOT NULL REFERENCES source_sections(section_id),
    pass smallint NOT NULL CHECK (pass IN (1, 2)),
    prompt_version text NOT NULL,
    model_version text NOT NULL,
    schema_version text NOT NULL,
    idempotency_key char(64) NOT NULL UNIQUE,
    status text NOT NULL CHECK (status IN ('pending', 'leased', 'completed', 'failed', 'rejected')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    lease_owner text,
    lease_expires_at timestamptz,
    request_payload jsonb NOT NULL,
    response_payload jsonb,
    input_tokens bigint NOT NULL DEFAULT 0,
    output_tokens bigint NOT NULL DEFAULT 0,
    usage_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);

CREATE INDEX IF NOT EXISTS inference_jobs_claim_idx ON inference_jobs (status, pass, created_at);

CREATE TABLE IF NOT EXISTS grounded_candidates (
    candidate_id text PRIMARY KEY,
    primary_program text NOT NULL,
    section_id text NOT NULL REFERENCES source_sections(section_id),
    snapshot_hash char(64) NOT NULL REFERENCES source_snapshots(snapshot_hash),
    evidence_char_start bigint NOT NULL,
    evidence_char_end bigint NOT NULL,
    evidence_byte_start bigint NOT NULL,
    evidence_byte_end bigint NOT NULL,
    evidence_quote text NOT NULL,
    evidence_hash char(64) NOT NULL,
    extraction_job_id text NOT NULL REFERENCES inference_jobs(inference_job_id),
    critique_job_id text REFERENCES inference_jobs(inference_job_id),
    candidate_payload jsonb NOT NULL,
    grounding_status text NOT NULL CHECK (grounding_status IN ('pending', 'accepted', 'repair', 'rejected')),
    runtime_activation boolean NOT NULL DEFAULT false CHECK (NOT runtime_activation),
    proof_binding boolean NOT NULL DEFAULT false CHECK (NOT proof_binding),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (section_id, evidence_char_start, evidence_char_end, evidence_hash)
);

CREATE TABLE IF NOT EXISTS candidate_lineage (
    lineage_id text PRIMARY KEY,
    candidate_id text NOT NULL REFERENCES grounded_candidates(candidate_id),
    predecessor_candidate_id text,
    relation text NOT NULL CHECK (relation IN ('baseline_import', 'extracted_from', 'repaired_from', 'supersedes', 'cross_program_reference')),
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (candidate_id, relation, predecessor_candidate_id)
);

CREATE TABLE IF NOT EXISTS legacy_baseline_candidates (
    baseline_id text PRIMARY KEY,
    source_payload jsonb NOT NULL,
    source_payload_hash char(64) NOT NULL UNIQUE,
    program text NOT NULL,
    blocker_codes jsonb NOT NULL,
    runtime_activation boolean NOT NULL DEFAULT false CHECK (NOT runtime_activation),
    proof_binding boolean NOT NULL DEFAULT false CHECK (NOT proof_binding),
    imported_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS typed_rule_drafts (
    draft_id text PRIMARY KEY,
    candidate_id text NOT NULL REFERENCES grounded_candidates(candidate_id),
    draft_version integer NOT NULL CHECK (draft_version > 0),
    canonical_rule jsonb NOT NULL,
    canonical_hash char(64) NOT NULL,
    semantic_fingerprint char(64) NOT NULL,
    scope_fingerprint char(64) NOT NULL,
    outcome_hash char(64) NOT NULL,
    validation_errors jsonb NOT NULL DEFAULT '[]'::jsonb,
    blocker_codes jsonb NOT NULL DEFAULT '[]'::jsonb,
    frozen boolean NOT NULL DEFAULT false,
    runtime_eligibility_status text NOT NULL DEFAULT 'blocked' CHECK (runtime_eligibility_status IN ('blocked', 'shadow_only')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (candidate_id, draft_version),
    UNIQUE (candidate_id, canonical_hash)
);

CREATE INDEX IF NOT EXISTS typed_rule_drafts_semantic_idx
    ON typed_rule_drafts (semantic_fingerprint, outcome_hash);
CREATE INDEX IF NOT EXISTS typed_rule_drafts_scope_idx
    ON typed_rule_drafts (scope_fingerprint, outcome_hash);

CREATE TABLE IF NOT EXISTS duplicate_conflict_clusters (
    cluster_id text PRIMARY KEY,
    cluster_kind text NOT NULL CHECK (cluster_kind IN ('exact_duplicate', 'semantic_duplicate', 'overlapping_effective_period', 'conflicting_outcome')),
    status text NOT NULL CHECK (status IN ('open', 'resolved')),
    fingerprint char(64) NOT NULL,
    resolution jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz
);

CREATE TABLE IF NOT EXISTS duplicate_conflict_members (
    cluster_id text NOT NULL REFERENCES duplicate_conflict_clusters(cluster_id),
    draft_id text NOT NULL REFERENCES typed_rule_drafts(draft_id),
    PRIMARY KEY (cluster_id, draft_id)
);

CREATE TABLE IF NOT EXISTS reviewer_tasks (
    task_id text PRIMARY KEY,
    draft_id text NOT NULL REFERENCES typed_rule_drafts(draft_id),
    cluster_id text REFERENCES duplicate_conflict_clusters(cluster_id),
    task_type text NOT NULL CHECK (task_type IN ('policy_review', 'legal_verification', 'conflict_resolution', 'quality_review')),
    status text NOT NULL CHECK (status IN ('pending', 'claimed', 'completed', 'cancelled')),
    assigned_reviewer_id text,
    claimed_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (draft_id, task_type)
);

CREATE INDEX IF NOT EXISTS reviewer_tasks_claim_idx ON reviewer_tasks (task_type, status, created_at);

CREATE TABLE IF NOT EXISTS reviewer_decisions (
    decision_id text PRIMARY KEY,
    task_id text NOT NULL REFERENCES reviewer_tasks(task_id),
    draft_id text NOT NULL REFERENCES typed_rule_drafts(draft_id),
    reviewer_id text NOT NULL,
    reviewer_role text NOT NULL CHECK (reviewer_role IN ('policy_reviewer', 'legal_verifier', 'rules_admin')),
    decision text NOT NULL CHECK (decision IN ('approve', 'reject', 'request_changes', 'resolve')),
    draft_hash char(64) NOT NULL,
    rationale text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS review_audit_events (
    event_id text PRIMARY KEY,
    actor_id text NOT NULL,
    action text NOT NULL,
    entity_type text NOT NULL,
    entity_id text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS quality_samples (
    sample_id text PRIMARY KEY,
    release_id text,
    candidate_id text NOT NULL REFERENCES grounded_candidates(candidate_id),
    stratum text NOT NULL,
    mandatory_reason text,
    policy_reviewer_id text,
    legal_verifier_id text,
    measurements jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS corpus_releases (
    release_id text PRIMARY KEY,
    schema_version text NOT NULL,
    target_count integer NOT NULL CHECK (target_count IN (5100, 51000, 600000)),
    candidate_count integer NOT NULL CHECK (candidate_count >= 0),
    source_manifest_hash char(64) NOT NULL,
    prompt_versions jsonb NOT NULL,
    model_versions jsonb NOT NULL,
    program_coverage jsonb NOT NULL,
    blocker_counts jsonb NOT NULL,
    quality_metrics jsonb NOT NULL,
    reviewer_evidence jsonb NOT NULL,
    manifest jsonb NOT NULL,
    canonical_release_hash char(64) NOT NULL UNIQUE,
    gates_passed boolean NOT NULL DEFAULT false,
    runtime_activation boolean NOT NULL DEFAULT false CHECK (NOT runtime_activation),
    proof_binding boolean NOT NULL DEFAULT false CHECK (NOT proof_binding),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION reject_immutable_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% is immutable', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS source_snapshots_immutable ON source_snapshots;
CREATE TRIGGER source_snapshots_immutable BEFORE UPDATE OR DELETE ON source_snapshots
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

DROP TRIGGER IF EXISTS reviewer_decisions_immutable ON reviewer_decisions;
CREATE TRIGGER reviewer_decisions_immutable BEFORE UPDATE OR DELETE ON reviewer_decisions
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

DROP TRIGGER IF EXISTS review_audit_events_immutable ON review_audit_events;
CREATE TRIGGER review_audit_events_immutable BEFORE UPDATE OR DELETE ON review_audit_events
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

DROP TRIGGER IF EXISTS source_snapshot_retrievals_immutable ON source_snapshot_retrievals;
CREATE TRIGGER source_snapshot_retrievals_immutable BEFORE UPDATE OR DELETE ON source_snapshot_retrievals
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

DROP TRIGGER IF EXISTS source_sections_immutable ON source_sections;
CREATE TRIGGER source_sections_immutable BEFORE UPDATE OR DELETE ON source_sections
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

DROP TRIGGER IF EXISTS quality_samples_immutable ON quality_samples;
CREATE TRIGGER quality_samples_immutable BEFORE UPDATE OR DELETE ON quality_samples
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

CREATE OR REPLACE FUNCTION reject_frozen_draft_mutation() RETURNS trigger AS $$
BEGIN
    IF OLD.frozen THEN
        RAISE EXCEPTION 'frozen typed rule drafts are immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS typed_rule_drafts_frozen_immutable ON typed_rule_drafts;
CREATE TRIGGER typed_rule_drafts_frozen_immutable BEFORE UPDATE OR DELETE ON typed_rule_drafts
    FOR EACH ROW EXECUTE FUNCTION reject_frozen_draft_mutation();

DROP TRIGGER IF EXISTS corpus_releases_immutable ON corpus_releases;
CREATE TRIGGER corpus_releases_immutable BEFORE UPDATE OR DELETE ON corpus_releases
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

INSERT INTO schema_migrations(version) VALUES ('0001_grounded_rules_corpus')
ON CONFLICT (version) DO NOTHING;

COMMIT;
