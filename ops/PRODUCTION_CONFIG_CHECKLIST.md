# Production Config Checklist

Status: operational checklist, not production approval.

This checklist applies only after all 93 internal packages close and the exact release passes the
final independent Security Audit Gate. `BL_PROOF_LANE=CAIRO_STARK_NATIVE` below describes the
current legacy readiness contract; S02 must replace it through a coordinated implementation,
configuration, mirror, and test migration before a deployment-ready candidate can exist.

Before any production deployment, `ops/production.env.example` must be copied to
a private environment store and every `REPLACE_*` value must be replaced by a
real audited root, hash, address, or key. Never commit the filled production
file.

Required checks:

1. Confirm this checklist is being run from a release package that contains
   `blind-ledger-app-layer/`, `ops/`, and `third_party/`.
2. Run `python -m pytest tests/test_production_readiness.py` from
   `blind-ledger-app-layer`.
3. Run `python -m pytest -q` from `blind-ledger-app-layer`.
4. Run `cargo test --manifest-path rules-engine-rust/Cargo.toml --lib --tests`
   from `blind-ledger-app-layer`.
5. Confirm `BL_PROOF_LANE=CAIRO_STARK_NATIVE`.
6. Confirm `BL_ONCHAIN_PROOF_ANCHOR=NATIVE_STARK_DIRECT_ANCHOR`.
7. Confirm `BL_ALLOW_TEST_DOUBLES=false`.
8. Confirm `BL_FORCE_PYTHON_RULES_ENGINE=false`.
9. Confirm `BL_ALLOW_LEGACY_PROOF_WRAPPER=false`.
10. Confirm `BL_NATIVE_STARK_VERIFIER_ARTIFACT_SHA256` matches the verifier pin
   manifest approved by governance.
11. Confirm governance multisig and timelock addresses match the deployed
   contracts.
12. Confirm all `release_candidate_blocker` entries in `ops/launch_blockers.json` are closed.
13. Confirm LB-002 accepted the exact source, suite, verifier, contract, image, infrastructure, and
    release identities being deployed.
14. Supply and validate every `activation_input`, then confirm all
    `production_activation_blocker` entries are closed. Do not convert a missing proof, audit,
    credential, signer, account, or authorization into accepted risk.
