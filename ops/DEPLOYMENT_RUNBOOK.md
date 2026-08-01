# Deployment Runbook

Status: current local-development runbook; not a deployment-ready-candidate procedure.

`docs/DEPLOYMENT_READY_BUILD_CONTRACT.md` defines three separate gates: all 93 internal packages
close, the exact `DEPLOYMENT_READY_AUDIT_PENDING` release passes one independent Security Audit
Gate, and operators supply live activation configuration. Government endpoints, credentials,
signers, key handles, and accounts are activation inputs, not unfinished engineering.

`docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md` adds internal release evidence for CBAM,
state/scheduler safety, proof-carrying adapters, proof/data reconstruction, and multidimensional
capacity. Native-rollup and FOCIL paths remain disabled unless maturity gates pass; the pinned
validity-rollup path cannot depend on them.

Before R01-R12 deployment work, read
`docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md`, refetch the canonical fork/EIP sources,
and pin the exact deployed feature matrix. The deployment must remain a based validity rollup and
must fail closed on unknown fork IDs, transaction/proof types, data modes, or partial adapters.

## Preflight

1. Confirm the release zip packages `blind-ledger-app-layer/`, `ops/`, and
   `third_party/` together, and does not include generated `out/` artifacts or
   nested stale copies of `Blind Ledger Neer Version.zip`.
2. From `blind-ledger-app-layer`, run `python -m pytest -q`.
3. From `blind-ledger-app-layer`, run
   `cargo test --manifest-path rules-engine-rust/Cargo.toml --lib --tests`.
4. From `blind-ledger-app-layer/zk-cairo-sharp`, run `scarb build` and, where
   the prover is available, `scarb prove` plus `scarb verify` for the pinned
   witness path.
5. Confirm no filled production secrets are present in the repo.
6. Confirm `ops/verifier_artifact_pin.example.json` is replaced by a production
   verifier pin manifest before any live deployment.

## Production Deployment Gate

Do not deploy production contracts until:

- Every `release_candidate_blocker` in `ops/launch_blockers.json` is closed and terminal evidence
  shows all 93 internal packages complete.
- The exact release passes LB-002, the final independent Security Audit Gate.
- Heterogeneous semantic-STARK/shared-bus/hash-coprocessor verifier artifact is real, internally
  qualified, and audit-accepted.
- Verifier artifact hash is pinned by governance.
- The exact V2 12-field ABI and authenticated sidecar/schema/suite identities are pinned.
- Multisig/timelock config has passed a dry-run upgrade and rollback test.
- Monitoring for `StarkBatchSubmitted`, `RootUpdateProposed`,
  `RootUpdateApproved`, and `RootUpdateActivated` is active.
- Every `production_activation_blocker` is closed; no accepted-risk shortcut may substitute for a
  missing proof, audit, credential, signer, or authorization.
