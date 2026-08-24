# Deterministic Rules Engine

## Active Policy

The active claim policy remains the current G1-G10 adjudication behavior. It
now has two compatible implementations:

- `hardcoded_g1_g10`: default `denial_reason()` behavior
- `versioned_g1_g10`: opt-in typed evaluation of `rules_active_v1.json`

The versioned bundle contains the exact 13 ordered denial branches used by the
current prototype. Its canonical SHA-256 is pinned in both the JSON bundle,
the Rust binary, and the example config:

```text
95d38b6d8fc9c44b65feace024a07c22b4f11771fe6b23283ce73bbe0a7cb8e3
```

The versioned backend fails closed when the schema, hash, rule IDs, priorities,
denial reasons, or current-claim result differ from `denial_reason()`. This
keeps Groth16 and STARK proof semantics aligned while the typed evaluator is
introduced.

Use `rust-engine/config.rules.example.json` for explicit opt-in configuration.
The normal `config.json` remains on the hard-coded default.

## Commands

From `rust-engine/`:

```bash
cargo run -- rules-validate rules_active_v1.json
cargo run -- rules-evaluate rules_active_v1.json
```

`rules-evaluate` reads the normal `claim_input.json`, evaluates without proof
generation or chain submission, and requires hard-coded parity.

## Claude Candidate Boundary

The source-grounded Claude corpus is a separate shadow lane:

```bash
cd gov-rules-kg-prototype
.venv/bin/python -m gov_rules_kg.main claude-web-export-rust-shadow

cd ../rust-engine
cargo run -- rules-shadow-validate \
  ../gov-rules-kg-prototype/reports/claude_web_rust_shadow_rules.json
```

Current export:

- 221 deterministic mapping candidates reviewed
- 191 strong mappings pass deterministic QA
- 30 attention candidates excluded
- 51 taxonomy programs covered
- runtime activation: false
- proof binding: false
- legal verification: candidate only

The Rust validator recomputes the canonical bundle hash and rejects missing
citations, non-HTTPS sources, unsupported operators, duplicate IDs, weak QA
status, or any rule that claims runtime/proof activation.

## Phase R2-R3 Canonical Schema And Promotion Queue

The strict intermediate schema is
`gov-rules-kg-prototype/schemas/localbce-government-rule-v1.schema.json`.
Canonical conditions use typed facts and an allowlisted comparison AST; free
text is permitted only as source evidence and citation material. Decimal
values are strings, dates use `YYYY-MM-DD`, and source hashes cover exact
bytes stored beneath `gov-rules-kg-prototype/evidence/`.

Build and validate the all-program promotion queue with:

```bash
cd gov-rules-kg-prototype
.venv/bin/python -m gov_rules_kg.main rules-build-promotion-queue
.venv/bin/python -m gov_rules_kg.main rules-validate-promotion-queue
```

The queue joins all 226 source candidates to 221 review/mapping records and
191 QA-passing shadow mappings across all 51 programs. It records deterministic
blocker codes for missing lineage, provenance, typed facts, effective dates,
human/legal review, unsupported operators, and duplicate conflicts. Draft
auto-mapping never creates an executable canonical rule from residual prose.

Current queue outputs:

- `reports/rules_promotion_queue_v1.json`
- `reports/rules_promotion_queue_v1_summary.json`
- `reports/rules_promotion_queue_v1.md`

Every current queue item remains blocked. None has an exact captured source
artifact plus legal approval, and no item is runtime eligible or proof bound.

## Phase R4 Non-Binding Rust Evaluation

Rust mirrors the canonical schema and can validate the queue or evaluate it
against a separate typed facts document:

```bash
cd rust-engine
cargo run -- rules-promotion-queue-validate \
  ../gov-rules-kg-prototype/reports/rules_promotion_queue_v1.json

cargo run -- rules-shadow-evaluate \
  ../gov-rules-kg-prototype/reports/rules_promotion_queue_v1.json \
  rule_facts.example.json
```

Each queued rule returns `matched`, `not_matched`, `not_applicable`, or
`insufficient_data`. Blocked or incomplete candidates return
`insufficient_data`; the evaluator never interprets their prose. The report
always declares `runtime_activation=false`, `proof_binding=false`, and
`adjudication_effect=false`.

This CLI does not add a rules backend, read normal claim input, generate a
proof, submit a transaction, or alter `adjudication_result.json`.

## Full Validation

```bash
bash scripts/validate_rules_pipeline.sh
```

The live STARK settlement validator also opts into `versioned_g1_g10`, so
approved and denied proof/settlement tests cover the rules engine and proof
backend together.

## Phase R1 Corpus Audit

The production rules track starts with a JSON/source-only inventory. It does
not read the legacy SQLite graph and does not activate any candidate corpus:

```bash
cd gov-rules-kg-prototype
python -m gov_rules_kg.main rules-corpus-audit
```

Outputs:

- `reports/rules_corpus_inventory.json`
- `reports/rules_corpus_inventory.md`

The report distinguishes active runtime rules, deterministic candidates,
promotion-ready candidates, shadow-only exports, references, and stale or
missing corpora. Counts for derivative reports are lineage counts, not
additive totals. In particular, machine validation or promotion readiness is
not legal verification and cannot confer runtime eligibility.

## PostgreSQL Grounded-Corpus Scale Lane

The R2-R4 scale lane is documented in
`gov-rules-kg-prototype/RULES_SCALE.md`. It uses PostgreSQL 16 for immutable
official-source snapshots, deterministic sections, two-pass Claude inference,
typed drafts, conflict clusters, separate policy/legal decisions, quality
samples, and corpus release manifests.

Official-source capture is a durable, idempotent PostgreSQL batch. Concurrent
workers claim fetch jobs with expiring leases, retry transient failures after a
delay, and atomically bind completed jobs to immutable snapshot and retrieval IDs.
Starting a later capture requires a new explicit capture ID.

Section extraction is also a durable, versioned queue. Concurrent workers use
expiring leases and `SKIP LOCKED`; completion atomically activates exactly one
pipeline version for inference while retaining superseded sections as inactive
lineage. Section IDs include the snapshot, pipeline, parser identity, ordinal, and
text hash. Parser changes therefore require an explicit pipeline-version bump, and
terminal parser failures require an explicit bounded retry action.

Inference completion is atomic with candidate or critique persistence. The
transaction requires both a live worker-owned inference lease and an active section;
parser-superseded sections cannot contribute to new drafts, quality cohorts, or
release candidates. Historical immutable release cohorts retain their exact original
candidate IDs and hashes.
Large inference runs page section scheduling and draft materialization instead of
loading an entire milestone into memory. Reports retain exact aggregate usage and
queue state while bounding per-request details, so a 5.1k, 51k, or 600k run remains
resumable without presenting partial drainage as completion.
The `corpus-progress` command reports per-program quotas and deficits using only the
currently active source-registry and parser lineage. Raw accepted counts are shown
separately from conflict-free deterministic candidates and cannot satisfy a milestone
unless every program reaches its assigned quota.
Quality cohorts pin the exact candidate, draft hash, source snapshot, parser section,
source-registry version, and extraction-pipeline version selected for review. A later
source, parser, candidate, or draft change invalidates that quality work and blocks the
release instead of reusing stale reviewer evidence.

Before paid inference, a versioned deterministic relevance classifier records
its decision and sections are scheduled round-robin across programs. Structured
Claude repairs create new candidate IDs with immutable `repaired_from` lineage.
Quality samples are planned deterministically with every mandatory risk record
and at least 20 samples per program; measurements count only after independent,
hash-bound policy and legal reviews reach conservative consensus.
Each milestone freezes an immutable, quota-balanced release cohort. Quality,
review evidence, blocker counts, manifests, and shadow exports are scoped to
that cohort and use only each candidate's latest draft, preventing cross-release
reviews or superseded drafts from satisfying a gate.
Release manifests bind the exact source-registry version and hash, pinned Claude
model and prompts, balanced quotas, quality verdict, and non-binding flags. The
standalone release validator recomputes those invariants before shadow export.

Structured source parser v2 preserves eCFR/GovInfo container headings, HTML
heading levels, list items, table rows, PDF page context, and source node/page
locators through PostgreSQL and into each Claude request.

Official-link discovery is a separate review-only queue. Discovered `.gov` links
retain parent snapshot lineage and cannot fetch themselves, edit the source
registry, activate rules, or bind proofs without a later reviewed registry release.
Rules-admin decisions are immutable and approval means only
`approved_for_registry`, not active-source or runtime status. Source approval is
bound to the exact parent snapshot. Newer different bytes or inactive/mismatched
parent lineage supersede the candidate and exclude it from registry releases;
the historical decision remains immutable for audit.

All PostgreSQL reviewer queues use owner-bound, expiring claims with explicit renew
and release operations. Stale claims are deterministically returned to their queue,
claim and expiry events are append-only audit records, and an expired owner cannot
submit a policy, legal, quality, conflict, or source decision.

It targets 600,000 deduplicated discovery candidates across all 51 programs
through 5,100, 51,000, and 600,000 milestones. A count is not a legal or
runtime status. Source scarcity fails a quota instead of allowing unofficial
material to fill it.

The verified PostgreSQL bootstrap currently has 128 configured source entrypoints
and active source/section coverage across all 51 programs. The source-v2 preflight,
using contract v8, contains 7,577 official-link lineage rows: 1,029 are eligible for
human source review, 6,548 are blocked, and 1,697 duplicate program/URL candidates cannot
inflate corpus volume. The current v13 contract checkpoint contains 13,996 grounded
candidates and 372 conflict-free deterministic candidates, while retaining zero
blocking failures for the current active source and inference lineage. Balance,
not raw volume, is the gate: grounded candidates fill 2,692 of 5,100 quota slots,
deterministic candidates fill 288 slots, 18 of 51 programs meet the grounded quota,
and only 1 of 51 programs meets its deterministic quota. Another 13,609 accepted
candidates lack source-stated effective dates, 13 have conflicting duplicate blockers,
2 have semantic-duplicate blockers, 129 reviewer tasks are pending, and no
corpus release exists. The full Python and PostgreSQL integration suites pass, but
the balanced 5,100 milestone has not passed, the 600,000 corpus has not been
produced, and every quality, policy, legal, and runtime gate remains incomplete.

`driver_licenses` and `building_permits` remain the immediate balanced-capacity
blockers, with only three active program sections each. Their discovery queues contain
51 and 5 blocker-free source links respectively, but all still require human source
review because deterministic topical scope is not legal or program-authority
verification. None is approved or eligible to expand the active registry automatically.
The preflight API exposes these 56 immediate capacity candidates as a deterministic
review packet pinned to SHA-256
`661790cf462592e2cf44372cedccea0fe050b743917d7f927a74a903c185db69`.
Every packet item remains an inactive registry candidate and explicitly records
`legal_verification=false`, `runtime_activation=false`, and `proof_binding=false`.
The credential-free `sources-preflight-validate` command independently checks the
packet hash, ordering, official URLs, scope evidence, completeness, and these
non-activation flags before reviewers rely on the artifact.

PostgreSQL is not connected to `rust-engine`. Only deterministic, hash-pinned
shadow exports may cross that boundary. Every scale release and export keeps:

- `runtime_activation=false`
- `proof_binding=false`
- `production_usable=false`

The imported 226-candidate corpus enters PostgreSQL only as a blocked baseline.
The old SQLite graph and reported 457k corpus remain reference-only.

## Deliberate Limits

`rust-engine/rules.json` and `rules_v9.json` remain target/reference ASTs. They
are not silently loaded by runtime. The 191 Claude shadow rules are not legal
verification and cannot become proof-bound policy without:

1. authoritative source and citation verification
2. jurisdiction and effective-date approval
3. a deterministic mapping to typed claim/oracle fields
4. reviewed expected outcomes and negative test vectors
5. a new versioned and signed ruleset hash
6. explicit runtime configuration and matching STARK ruleset commitment

This separation is intentional: source discovery can scale without allowing
unverified text to adjudicate a claim.

Phase R5 runtime expansion remains explicitly out of scope. Hardcoded G1-G10
is still the default, and the pinned `versioned_g1_g10` implementation remains
the only opt-in rules backend.
