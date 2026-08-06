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

It targets 600,000 deduplicated discovery candidates across all 51 programs
through 5,100, 51,000, and 600,000 milestones. A count is not a legal or
runtime status. Source scarcity fails a quota instead of allowing unofficial
material to fill it.

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
