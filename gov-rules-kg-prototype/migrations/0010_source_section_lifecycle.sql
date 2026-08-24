-- Preserve immutable section evidence while allowing parser lifecycle supersession.
CREATE OR REPLACE FUNCTION reject_source_section_content_mutation()
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION '% is immutable', TG_TABLE_NAME;
    END IF;

    IF (to_jsonb(NEW) - 'active') IS DISTINCT FROM
       (to_jsonb(OLD) - 'active') THEN
        RAISE EXCEPTION '% content is immutable', TG_TABLE_NAME;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS source_sections_immutable ON source_sections;
CREATE TRIGGER source_sections_immutable
    BEFORE UPDATE OR DELETE ON source_sections
    FOR EACH ROW EXECUTE FUNCTION reject_source_section_content_mutation();
