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

## Full Validation

```bash
bash scripts/validate_rules_pipeline.sh
```

The live STARK settlement validator also opts into `versioned_g1_g10`, so
approved and denied proof/settlement tests cover the rules engine and proof
backend together.

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
