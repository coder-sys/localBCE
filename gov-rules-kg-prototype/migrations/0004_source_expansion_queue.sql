BEGIN;

CREATE TABLE IF NOT EXISTS source_discovery_runs (
    discovery_run_id text PRIMARY KEY,
    retrieval_id text NOT NULL REFERENCES source_snapshot_retrievals(retrieval_id),
    snapshot_hash char(64) NOT NULL REFERENCES source_snapshots(snapshot_hash),
    parser_version text NOT NULL,
    candidate_count integer NOT NULL CHECK (candidate_count >= 0),
    canonical_run_hash char(64) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (retrieval_id, parser_version)
);

CREATE TABLE IF NOT EXISTS source_registry_candidates (
    source_candidate_id text PRIMARY KEY,
    discovery_run_id text NOT NULL REFERENCES source_discovery_runs(discovery_run_id),
    parent_source_id text NOT NULL REFERENCES official_sources(source_id),
    parent_retrieval_id text NOT NULL REFERENCES source_snapshot_retrievals(retrieval_id),
    parent_snapshot_hash char(64) NOT NULL REFERENCES source_snapshots(snapshot_hash),
    program text NOT NULL,
    candidate_url text NOT NULL,
    link_text text NOT NULL,
    source_locator jsonb NOT NULL,
    review_status text NOT NULL DEFAULT 'pending_review' CHECK (
        review_status IN ('pending_review', 'claimed_review', 'approved_for_registry', 'rejected')
    ),
    assigned_reviewer_id text,
    reviewed_at timestamptz,
    runtime_activation boolean NOT NULL DEFAULT false CHECK (NOT runtime_activation),
    proof_binding boolean NOT NULL DEFAULT false CHECK (NOT proof_binding),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (parent_retrieval_id, program, candidate_url)
);

CREATE INDEX IF NOT EXISTS source_registry_candidates_review_idx
    ON source_registry_candidates (review_status, program, source_candidate_id);

CREATE TABLE IF NOT EXISTS source_registry_candidate_decisions (
    source_decision_id text PRIMARY KEY,
    source_candidate_id text NOT NULL REFERENCES source_registry_candidates(source_candidate_id),
    reviewer_id text NOT NULL,
    reviewer_role text NOT NULL CHECK (reviewer_role = 'rules_admin'),
    decision text NOT NULL CHECK (decision IN ('approve_for_registry', 'reject')),
    rationale text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (source_candidate_id)
);

DROP TRIGGER IF EXISTS source_discovery_runs_immutable ON source_discovery_runs;
CREATE TRIGGER source_discovery_runs_immutable
    BEFORE UPDATE OR DELETE ON source_discovery_runs
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

DROP TRIGGER IF EXISTS source_registry_candidate_decisions_immutable
    ON source_registry_candidate_decisions;
CREATE TRIGGER source_registry_candidate_decisions_immutable
    BEFORE UPDATE OR DELETE ON source_registry_candidate_decisions
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

INSERT INTO schema_migrations(version) VALUES ('0004_source_expansion_queue')
ON CONFLICT (version) DO NOTHING;

COMMIT;
