BEGIN;

CREATE TABLE IF NOT EXISTS source_ocr_artifacts (
    ocr_artifact_id text PRIMARY KEY,
    retrieval_id text NOT NULL REFERENCES source_snapshot_retrievals(retrieval_id),
    artifact_hash char(64) NOT NULL,
    compression text NOT NULL CHECK (compression = 'zlib'),
    compressed_bytes bytea NOT NULL,
    uncompressed_size bigint NOT NULL CHECK (uncompressed_size > 0),
    normalized_text_hash char(64) NOT NULL,
    engine_name text NOT NULL CHECK (btrim(engine_name) <> ''),
    engine_version text NOT NULL CHECK (btrim(engine_version) <> ''),
    operator_id text NOT NULL CHECK (btrim(operator_id) <> ''),
    generated_at timestamptz NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (retrieval_id, artifact_hash, engine_name, engine_version)
);

CREATE TABLE IF NOT EXISTS source_ocr_artifact_sections (
    ocr_artifact_id text NOT NULL REFERENCES source_ocr_artifacts(ocr_artifact_id),
    section_id text NOT NULL REFERENCES source_sections(section_id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (ocr_artifact_id, section_id)
);

CREATE INDEX IF NOT EXISTS source_ocr_artifacts_retrieval_idx
    ON source_ocr_artifacts (retrieval_id, artifact_hash);

DROP TRIGGER IF EXISTS source_ocr_artifacts_immutable ON source_ocr_artifacts;
CREATE TRIGGER source_ocr_artifacts_immutable
    BEFORE UPDATE OR DELETE ON source_ocr_artifacts
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

DROP TRIGGER IF EXISTS source_ocr_artifact_sections_immutable
    ON source_ocr_artifact_sections;
CREATE TRIGGER source_ocr_artifact_sections_immutable
    BEFORE UPDATE OR DELETE ON source_ocr_artifact_sections
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

INSERT INTO schema_migrations(version)
VALUES ('0015_immutable_ocr_evidence')
ON CONFLICT (version) DO NOTHING;

COMMIT;
