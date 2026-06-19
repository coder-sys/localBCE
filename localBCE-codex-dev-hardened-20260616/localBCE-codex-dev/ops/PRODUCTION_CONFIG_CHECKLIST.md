# Production Config Checklist

Status: operational checklist, not production approval.

Before any production deployment, `ops/production.env.example` must be copied to
a private environment store and every `REPLACE_*` value must be replaced by a
real audited root, hash, address, or key. Never commit the filled production
file.

Required checks:

1. Run `python scripts/validate_operational_readiness.py`.
2. Run `python -m pytest tests/test_production_readiness.py` from
   `blind-ledger-app-layer`.
3. Confirm `BL_PROOF_LANE=CAIRO_STARK_NATIVE`.
4. Confirm `BL_ONCHAIN_PROOF_ANCHOR=NATIVE_STARK_DIRECT_ANCHOR`.
5. Confirm `BL_ALLOW_TEST_DOUBLES=false`.
6. Confirm `BL_FORCE_PYTHON_RULES_ENGINE=false`.
7. Confirm `BL_ALLOW_LEGACY_PROOF_WRAPPER=false`.
8. Confirm `BL_NATIVE_STARK_VERIFIER_ARTIFACT_SHA256` matches the verifier pin
   manifest approved by governance.
9. Confirm governance multisig and timelock addresses match the deployed
   contracts.
10. Confirm launch blockers in `ops/launch_blockers.json` are closed or formally
    accepted by the named owner.
