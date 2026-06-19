# Government Rules Knowledge Graph Prototype

This is a fresh, access-gated prototype for recursive government rules discovery.
It is intentionally separate from the existing `localBCE` Rust/ZK prototype.

Transactions, budgets, procurement, spending, and expenditure ingestion are out
of scope for this build.

## Working Directory

```text
gov-rules-kg-prototype/
```

Run it from a real, non-sandboxed environment. The recursive discovery engine
fetches live government sources and should stop at Phase 0 if those sources are
blocked.

## Install

```bash
cd /mnt/c/Users/sruja/Downloads/localBCE/gov-rules-kg-prototype
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -e .
python -m playwright install chromium
```

If Playwright warns that browser host dependencies are missing, install them
with:

```bash
sudo playwright install-deps
```

Core dependency gate:

- `pypdf`
- `PyMuPDF`
- `networkx`

If any core dependency is missing, the CLI stops before discovery.

## Run

Phase 0 access verification only:

```bash
python -m gov_rules_kg.main phase0
```

One bounded recursive discovery run:

```bash
python -m gov_rules_kg.main run --max-depth 4 --global-doc-cap 20000 --per-host-cap 500
```

For a tiny smoke run:

```bash
python -m gov_rules_kg.main run --max-depth 1 --global-doc-cap 25 --per-host-cap 10
```

Rule-section extraction can be scaled independently:

```bash
python -m gov_rules_kg.main run --max-depth 1 --global-doc-cap 25 --per-host-cap 10 --max-rule-sections-per-document 2500
```

Bulk federal eCFR expansion is opt-in:

```bash
python -m gov_rules_kg.main run --max-depth 1 --global-doc-cap 500 --per-host-cap 100 --max-rule-sections-per-document 5000 --ecfr-all-titles
```

Estimate the path to a larger target from the last run:

```bash
python -m gov_rules_kg.main bulk-plan --target-atomic-rules 1000000
```

Generate a reusable all-title eCFR source manifest:

```bash
python -m gov_rules_kg.main generate-ecfr-manifest --output data/source_manifests/ecfr_all_titles.json --summary-only
```

Run from a source manifest:

```bash
python -m gov_rules_kg.main run \
  --fast \
  --source-manifest data/source_manifests/ecfr_all_titles.json \
  --manifest-only \
  --max-depth 0 \
  --global-doc-cap 50 \
  --per-host-cap 50 \
  --max-rule-sections-per-document 10000 \
  --ai-provider claude \
  --claude-model claude-sonnet-4-6 \
  --claude-max-sections 25 \
  --fail-on-ai-fallback true \
  --allow-local-stub false
```

`--fast` keeps the run polite but lowers the delay and uses required-source
Phase 0 checks. `--manifest-only` skips the built-in demo/default discovery
seeds and runs only the provided source manifest plus access-only checks.

Write a scale playbook toward a large rule target:

```bash
python -m gov_rules_kg.main scale-playbook --target-atomic-rules 600000
cat reports/scale_playbook.md
```

For massive volume, use bulk ingest first. This skips Claude during ingestion
and writes light reports so the run spends time extracting rules, not generating
heavy graph/audit files:

```bash
python -m gov_rules_kg.main run \
  --bulk-ingest \
  --domain government_transaction_rules \
  --vertical healthcare_benefits \
  --program medicaid \
  --jurisdiction federal \
  --include-federal true \
  --include-states none \
  --source-manifest data/source_manifests/ecfr_all_titles.json \
  --max-depth 0 \
  --global-doc-cap 50 \
  --per-host-cap 50 \
  --max-rule-sections-per-document 10000 \
  --phase0-mode required \
  --progress-every-sections 250
```

After a bulk ingest finishes, generate the proof/reporting layer separately:

```bash
python -m gov_rules_kg.main proof-report
```

Use Claude for real AI extraction on a controlled sample:

```bash
export CLAUDE_API_KEY="your_key_here"
python -m gov_rules_kg.main run \
  --domain government_transaction_rules \
  --vertical healthcare_benefits \
  --program medicaid \
  --jurisdiction all \
  --include-federal true \
  --include-states CA,TX,NY,FL \
  --max-depth 1 \
  --global-doc-cap 25 \
  --per-host-cap 10 \
  --max-rule-sections-per-document 2500 \
  --ai-provider claude \
  --claude-model claude-sonnet-4-6 \
  --claude-max-sections 25 \
  --fail-on-ai-fallback true \
  --allow-local-stub false
```

For bulk work, keep `--claude-max-sections` set until cost and output quality
are reviewed. If `--ai-provider claude` is selected, the run now performs a
Claude preflight and aborts if the API key, model, or endpoint is unavailable.
Local stub extraction is allowed only when explicitly requested:

```bash
python -m gov_rules_kg.main run --ai-provider local --allow-local-stub true --fail-on-ai-fallback false
```

`ANTHROPIC_API_KEY` is also supported for compatibility, but `CLAUDE_API_KEY`
is preferred in this prototype.

Report-level commands:

```bash
python -m gov_rules_kg.main validate-citations
python -m gov_rules_kg.main review-queue --confidence-threshold 0.75
python -m gov_rules_kg.main export-executable --only-high-confidence true --min-confidence 0.85
python -m gov_rules_kg.main evaluate --gold-set ./tests/gold/medicaid_rules_gold.json
python -m gov_rules_kg.main compare-federal-state --program medicaid --state TX
python -m gov_rules_kg.main compare-states --program medicaid --states TX,CA
python -m gov_rules_kg.main proof-report
python -m gov_rules_kg.main scale-playbook --target-atomic-rules 600000
```

## Architecture

```text
Seed sources
  -> Phase 0 access gate
  -> polite fetcher
  -> cleaned text/PDF extractor
  -> low-quality/browser-warning page filter
  -> citation/entity/rule-section extractor
  -> Claude or local AI organizer for atomic rule units
  -> rule-type organization
  -> recursive queue with caps and visited set
  -> SQLite store
  -> ontology/classification/compliance extraction
  -> networkx graph export
  -> EDA + AI summary
  -> reports/demo_transcript.md + reports/rules_by_type.*
```

## Adapter Boundaries

The prototype uses embedded defaults:

- Store: SQLite
- Graph: networkx JSON export
- Search: SQLite FTS-compatible schema placeholder
- AI layer: local attribution-preserving stub

Swap points are isolated in:

- `src/gov_rules_kg/store.py`
- `src/gov_rules_kg/graph.py`
- `src/gov_rules_kg/ai.py`

PostgreSQL/Neo4j/Elasticsearch can be added behind these interfaces without
changing discovery logic.

## Data Model

Main SQLite tables:

- `documents`: canonical fetched/source documents
- `entities`: rules, statutes, regs, guidance, programs, agencies, requirements
- `edges`: citation and authority-chain relationships
- `fetch_log`: access attempts and status
- `checkpoints`: resumable run state
- `merge_candidates`: proposed canonical merges, gated before mass merge
- `audit_log`: lineage and mutations

Every entity and edge is traceable to `source_url` and `fetch_timestamp`.

## Recursion Safeguards

Enabled by default:

- hard max depth
- per-host cap
- global document cap
- per-document rule-section cap
- canonical visited set
- polite delays
- blocked-source marking as `NEEDS_MANUAL`
- low-quality browser-warning/navigation page skipping
- real-time JSON progress events for processed and skipped documents
- clean stop conditions

## Output

Reports are written under:

```text
reports/
```

Expected reports:

- `phase0_access.json`
- `run_report.json`
- `demo_transcript.md`
- `graph.json`
- `rules_by_type.json`
- `rules_by_type.md`
- `rules_by_family.json`
- `rules_by_citation.json`
- `rules_by_program.json`
- `rules_by_state.json`
- `federal_medicaid_rules.json`
- `state_medicaid_rules.json`
- `human_review_queue.json`
- `source_quality_report.json`
- `citation_index.json`
- `audit_report.json`
- `evaluation_report.json`
- `final_scorecard.json`
- `programmatic_proof_report.json`
- `programmatic_proof_report.md`
- `scale_playbook.json`
- `scale_playbook.md`

The extractor is designed to avoid raw page chrome. HTML tags, scripts, forms,
navigation, and browser-warning pages are filtered before rule extraction. If a
source serves a warning page instead of usable rules, the run records it as
`SKIPPED_LOW_QUALITY` and continues with other sources.

## Rule Volume Metrics

The report separates volume into several levels:

- `rule_sections_extracted`: all section-like rule blocks found.
- `relevant_rule_sections`: sections matching the current relevance scorer.
- `atomic_rule_units`: AI-organized clause/obligation/permission/prohibition
  units extracted from relevant sections.

For million-scale work, use `atomic_rule_units` as the volume metric and keep
`relevant_rule_sections` as the legal-section metric.

## Important

This is not a scraper designed to bypass access controls. If a source blocks
polite access, the engine marks it `NEEDS_MANUAL`, skips it, and continues.
