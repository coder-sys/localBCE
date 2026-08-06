# Grounded Rules Corpus Scale Lane

This lane produces source-grounded, non-binding rule candidates in PostgreSQL 16.
It does not replace the hardcoded G1-G10 adjudicator, activate candidate rules, or
bind any candidate to Groth16 or STARK proofs.

## Local Database

Set a development-only password in the shell, start PostgreSQL, and expose a
standard `DATABASE_URL`:

```bash
export RULES_POSTGRES_PASSWORD='local-only-value'
docker compose -f docker-compose.rules.yml up -d
export DATABASE_URL='postgresql://localbce_rules:local-only-value@127.0.0.1:5432/localbce_rules'
python -m gov_rules_kg.main rules-db-migrate
```

Passwords, Claude credentials, OIDC tokens, and database dumps must not be
committed. PostgreSQL is the only active bulk corpus store. Existing SQLite
commands and `data/rules_kg.sqlite` remain reference-only.

## Pipeline

```bash
python -m gov_rules_kg.main sources-sync
python -m gov_rules_kg.main sources-sync --fetch
python -m gov_rules_kg.main sections-extract
ANTHROPIC_API_KEY=... python -m gov_rules_kg.main claude-infer --concurrency 8
python -m gov_rules_kg.main quality-evaluate
python -m gov_rules_kg.main review-export
python -m gov_rules_kg.main corpus-release --release-id federal-5100-v1 --target 5100
python -m gov_rules_kg.main shadow-bundle-export --release-manifest reports/corpus_release_federal-5100-v1.json
```

`sources-sync` registers all 104 reviewed federal entrypoints across all 51
programs and imports the current 226 candidates as blocked baseline records.
`--fetch` captures exact response bytes. `sections-extract` produces deterministic
normalized text sections while retaining the immutable source hash and retrieval
metadata. OCR is never silently invoked.

`claude-infer` is pinned to the configured Claude model and performs extraction
and independent critique. There is no local model fallback. All evidence offsets,
types, operators, dates, hashes, and forbidden status fields are checked by local
code before candidates are accepted.

## Release Boundary

Releases are allowed only at 5,100, 51,000, and 600,000 unique primary candidates.
Program quotas differ by at most one. Source scarcity is reported instead of being
filled with unofficial or unsupported material.

Every release remains:

- `runtime_activation: false`
- `proof_binding: false`
- `production_usable: false`

Policy approval and legal verification must be performed by different reviewers.
A source or draft hash change makes earlier decisions inapplicable. Even a fully
reviewed record is only `legally_verified_shadow`; R5 requires a separate release.
