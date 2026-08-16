# Deployment runbook

Status: local, synthetic rehearsal only.

## Preflight

1. Verify `ops/` with `verify_ops_authority()`.
2. Run the Python and Rust test suites from the repository root.
3. Confirm `proofSuiteId` is selected only for an exact audited candidate; the current value remains null.
4. Pin the verifier artifact, schema, program, policy, ruleset, state schema, governance roots, and custody handles.
5. Confirm no real secrets or PHI are present in source or artifacts.
6. Rehearse serializable transaction races, idempotent retries, nullifier conflicts, crash-before-commit, backup/restore, rollback, and signer rotation.
7. Enable non-PHI monitoring and append-only audit commitments.

## Production gate

Do not activate until every release-candidate blocker is closed, the exact release passes the independent Security Audit Gate, production database/custody evidence passes, and operators supply authorized source credentials, payment accounts, signers, legal approval, and incident procedures.

The accepted verifier receipt and Blind Ledger clearance-state mutation must remain one atomic
fail-closed boundary. This boundary does not move funds: the incumbent adjudicates and the official
state payment rails execute the later payment. No L2 deployment is required. Optional Ethereum L1
checkpoints are a committed later capability and require a separate runbook; their cadence is not
fixed in the current phase.
