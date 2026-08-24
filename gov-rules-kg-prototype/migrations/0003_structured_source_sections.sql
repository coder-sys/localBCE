BEGIN;

ALTER TABLE source_sections
    ADD COLUMN IF NOT EXISTS source_locator jsonb NOT NULL DEFAULT '{}'::jsonb;

INSERT INTO schema_migrations(version) VALUES ('0003_structured_source_sections')
ON CONFLICT (version) DO NOTHING;

COMMIT;
