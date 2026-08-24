BEGIN;

CREATE TABLE IF NOT EXISTS section_relevance_decisions (
    decision_id text PRIMARY KEY,
    section_id text NOT NULL REFERENCES source_sections(section_id),
    classifier_version text NOT NULL,
    section_hash char(64) NOT NULL,
    relevant boolean NOT NULL,
    score integer NOT NULL,
    reasons jsonb NOT NULL,
    decision_hash char(64) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (section_id, classifier_version)
);

CREATE INDEX IF NOT EXISTS section_relevance_inference_idx
    ON section_relevance_decisions (relevant, section_id);

-- A single evidence span can legitimately yield multiple atomic interpretations.
-- Candidate identity already includes the typed semantics, so the old evidence-only
-- unique constraint prevented deterministic repair and conflict analysis.
DO $$
DECLARE
    constraint_name text;
BEGIN
    SELECT conname INTO constraint_name
    FROM pg_constraint
    WHERE conrelid = 'grounded_candidates'::regclass
      AND contype = 'u'
      AND pg_get_constraintdef(oid) =
          'UNIQUE (section_id, evidence_char_start, evidence_char_end, evidence_hash)';
    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE grounded_candidates DROP CONSTRAINT %I', constraint_name);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS grounded_candidates_evidence_lookup_idx
    ON grounded_candidates (
        section_id,
        evidence_char_start,
        evidence_char_end,
        evidence_hash
    );

CREATE TABLE IF NOT EXISTS quality_sample_plans (
    sample_id text PRIMARY KEY,
    release_id text NOT NULL,
    corpus_target_count integer NOT NULL CHECK (corpus_target_count IN (5100, 51000, 600000)),
    candidate_id text NOT NULL REFERENCES grounded_candidates(candidate_id),
    draft_id text NOT NULL REFERENCES typed_rule_drafts(draft_id),
    draft_hash char(64) NOT NULL,
    stratum text NOT NULL,
    mandatory_reason text,
    status text NOT NULL CHECK (
        status IN ('pending_policy', 'claimed_policy', 'pending_legal', 'claimed_legal', 'completed')
    ),
    assigned_policy_reviewer_id text,
    assigned_legal_verifier_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE (release_id, candidate_id)
);

CREATE INDEX IF NOT EXISTS quality_sample_plans_claim_idx
    ON quality_sample_plans (status, release_id, sample_id);

CREATE TABLE IF NOT EXISTS corpus_release_cohorts (
    release_id text NOT NULL,
    corpus_target_count integer NOT NULL CHECK (corpus_target_count IN (5100, 51000, 600000)),
    candidate_id text NOT NULL REFERENCES grounded_candidates(candidate_id),
    selection_hash char(64) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (release_id, candidate_id)
);

CREATE TABLE IF NOT EXISTS quality_review_submissions (
    submission_id text PRIMARY KEY,
    sample_id text NOT NULL REFERENCES quality_sample_plans(sample_id),
    candidate_id text NOT NULL REFERENCES grounded_candidates(candidate_id),
    draft_hash char(64) NOT NULL,
    reviewer_id text NOT NULL,
    reviewer_role text NOT NULL CHECK (reviewer_role IN ('policy_reviewer', 'legal_verifier')),
    measurements jsonb NOT NULL,
    rationale text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (sample_id, reviewer_role)
);

DROP TRIGGER IF EXISTS section_relevance_decisions_immutable ON section_relevance_decisions;
CREATE TRIGGER section_relevance_decisions_immutable
    BEFORE UPDATE OR DELETE ON section_relevance_decisions
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

DROP TRIGGER IF EXISTS quality_review_submissions_immutable ON quality_review_submissions;
CREATE TRIGGER quality_review_submissions_immutable
    BEFORE UPDATE OR DELETE ON quality_review_submissions
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

DROP TRIGGER IF EXISTS corpus_release_cohorts_immutable ON corpus_release_cohorts;
CREATE TRIGGER corpus_release_cohorts_immutable
    BEFORE UPDATE OR DELETE ON corpus_release_cohorts
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

INSERT INTO schema_migrations(version) VALUES ('0002_scale_quality_and_repair')
ON CONFLICT (version) DO NOTHING;

COMMIT;
