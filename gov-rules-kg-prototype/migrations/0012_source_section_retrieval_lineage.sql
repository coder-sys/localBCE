CREATE TABLE IF NOT EXISTS source_section_retrieval_links (
    section_id text NOT NULL REFERENCES source_sections(section_id),
    retrieval_id text NOT NULL REFERENCES source_snapshot_retrievals(retrieval_id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (section_id, retrieval_id)
);

CREATE INDEX IF NOT EXISTS source_section_retrieval_links_retrieval_idx
    ON source_section_retrieval_links (retrieval_id, section_id);

CREATE OR REPLACE FUNCTION link_source_section_owner_retrieval()
RETURNS trigger AS $$
BEGIN
    INSERT INTO source_section_retrieval_links (section_id, retrieval_id)
    VALUES (NEW.section_id, NEW.retrieval_id)
    ON CONFLICT (section_id, retrieval_id) DO NOTHING;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS source_sections_link_owner_retrieval ON source_sections;
CREATE TRIGGER source_sections_link_owner_retrieval
    AFTER INSERT ON source_sections
    FOR EACH ROW EXECUTE FUNCTION link_source_section_owner_retrieval();

-- Preserve the original owner relationship, then recover every completed
-- extraction relationship for snapshots shared by more than one source entry.
INSERT INTO source_section_retrieval_links (section_id, retrieval_id)
SELECT section_id, retrieval_id
FROM source_sections
ON CONFLICT (section_id, retrieval_id) DO NOTHING;

INSERT INTO source_section_retrieval_links (section_id, retrieval_id)
SELECT sections.section_id, jobs.retrieval_id
FROM section_extraction_jobs jobs
JOIN source_sections sections
  ON sections.snapshot_hash = jobs.snapshot_hash
 AND sections.extraction_pipeline_version = jobs.pipeline_version
WHERE jobs.status = 'completed'
ON CONFLICT (section_id, retrieval_id) DO NOTHING;

DROP TRIGGER IF EXISTS source_section_retrieval_links_immutable
    ON source_section_retrieval_links;
CREATE TRIGGER source_section_retrieval_links_immutable
    BEFORE UPDATE OR DELETE ON source_section_retrieval_links
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

-- One deterministic context per section/program prevents a shared snapshot
-- from multiplying candidate volume while retaining all program provenance.
CREATE OR REPLACE VIEW source_section_program_contexts AS
SELECT DISTINCT ON (links.section_id, sources.program)
       links.section_id,
       links.retrieval_id,
       retrievals.source_id,
       retrievals.canonical_url,
       retrievals.retrieved_at,
       sources.program,
       sources.registry_version,
       sources.jurisdiction,
       sources.issuer,
       sources.source_type,
       sources.active AS source_active
FROM source_section_retrieval_links links
JOIN source_snapshot_retrievals retrievals USING (retrieval_id)
JOIN official_sources sources USING (source_id)
ORDER BY links.section_id, sources.program, sources.active DESC,
         retrievals.retrieved_at DESC, links.retrieval_id;

INSERT INTO schema_migrations(version)
VALUES ('0012_source_section_retrieval_lineage')
ON CONFLICT (version) DO NOTHING;
