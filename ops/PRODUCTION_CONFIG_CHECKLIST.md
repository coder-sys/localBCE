# Production configuration checklist

Status: nonactivating operational checklist.

This checklist applies to the direct application-proof-to-database architecture. It does not
authorize real PHI or payments.

1. Verify the release contains `app/`, `experiments/`, `ops/`, `tests/`, and `tools/`.
2. Run `py -3.14 -B -m pytest tests/test_production_readiness.py`.
3. Run the full Python and Rust regression suites.
4. Confirm the exact qualified `proofSuiteId`; the current `proofSuiteId=null` sentinel is
   intentionally nonactivating and is not deployable.
5. Treat `NATIVE_STARK_DATABASE_TRANSITION` in `ops/production.env.example` as a disabled legacy
   compatibility sentinel only. It is not a selected verifier, evaluator, or production backend.
6. Confirm the verifier artifact, state schema, append-only log, anti-rollback, policy, oracle, and
   governance roots match the approved release.
7. Confirm test doubles, forced Python rules, and legacy proof wrappers are disabled.
8. Confirm every release-candidate blocker and the independent audit gate is closed for the exact
   source, verifier, state schema, custody, image, and release identities.
9. Supply live credentials and authorizations only after the audited release passes every gate.
