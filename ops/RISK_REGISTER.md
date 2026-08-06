# Risk Register

The machine-readable launch blockers are in `ops/launch_blockers.json`.
`docs/DEPLOYMENT_READY_BUILD_CONTRACT.md` is the authoritative classification contract.

Current risk posture:

- Current synthetic demo: permitted only inside the existing synthetic-only boundaries; it is not
  deployment ready.
- Deployment-ready audit-pending candidate: the 93 internally finishable packages now close at the
  local/synthetic boundary, including government/oracle simulators and the R01-R12 rollup path;
  deployed verifier/state/custody, release identities, and the final audit gate remain required.
- Controlled pilot without real payments: possible only after the exact release passes the final
  audit and the required pilot activation inputs, verifier, monitoring, and signer drills complete.
- Real production claims/payments: blocked until the heterogeneous semantic-STARK/shared-bus/hash-
  coprocessor proof is reproducible and audited end to end, the production verifier artifact is pinned,
  key custody is live, official oracle access is approved, and compliance approval
  is complete.

Do not downgrade a release-candidate, audit, proof-binding, privacy, strict-PQ, settlement, or
activation blocker to accepted risk. Live endpoints, credentials, signers, key handles, accounts,
and jurisdictional authority are supplied during activation; their absence does not excuse missing
internal adapters, simulators, conformance tests, or deployment automation.

`docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md` adds release blockers for CBAM completeness, scheduler conflict safety, state-tier
migration/rollback, evidence-capsule exactness, proof/data reconstruction, and dependence on draft
Ethereum features. Current state maps and pinned validity-rollup settlement stay authoritative until
replacements pass versioned gates. Projected state-call reductions are not throughput results.

`docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md` owns the complete outer-chain change
risk. R01-R12 must pin a deployed baseline, keep based sequencing and validity mandatory, and reject
unknown or partial fork/EIP support; no live-map projection is release evidence.
The exact risk classes are INHERIT, L1-COMPAT, L2-PARITY, OPTIONAL and RESEARCH. An unknown fork
digest/interface or incomplete mandatory adapter pauses new batch acceptance/publication while the
reviewed exit/recovery path remains available from the last supported finalized state.
