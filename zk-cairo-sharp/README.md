# Cairo Native-STARK differential reference

Owner: the protected `zk-cairo-sharp/` compatibility lane. Status: historical and differential
evidence only. This reference is not a selected production proof backend, cannot authorize a
database transition or payment, and does not override `STATE.md`, `CURRENT_TASK.md`, or the active
Native-v3/database authorities.

## Retained scope

The Cairo 2 / Scarb 2.18 implementation provides semantic known-answer and mutation fixtures for
one `MultiLineDecisionInput` (`main`) and `BatchClaimInput` (`batch_main`). It binds governed facts,
policy, nullifier, and state-root inputs instead of accepting free flags. Generated proof artifacts
are not packaged in the source tree; a local regeneration is evidence only after independent
verification and readback.

The current live selection is explicitly unselected: `proofSuiteId=null`, `production_usable=false`,
and no Cairo artifact is a production release dependency. Native-v3
Phase 0, the trust-boundary profile, plaintext continuity, and Mirror evidence are synthetic
semantic/operational evidence; none is a Cairo proof or deployed formal verification.

## Differential attack coverage

The retained fixtures exercise fabricated facts, duplicate-by-omission, procedure substitution,
free ceilings, non-empty padding, stale roots, denied-claim nullifier forgery, authorization
substitution, claim-source/oracle drift, cent bounds, value conservation, and state-root binding.
They also preserve regression expectations for exact public inputs, source/custody qualification,
database isolation, retry, crash, recovery, and anti-rollback. These are attack classes and
compatibility checks, not a complete soundness or privacy claim.

## Evidence and nonclaims

Earlier local checkouts contained a Cairo proof checkpoint for this statement family, but its proof
JSON is intentionally excluded from the optimized source archive. Do not claim the checkpoint is
current without regenerating it in the current environment and independently verifying its exact
bytes, public inputs, and artifacts. Retired BL-PQ512/H4/CUDA, Privacy V2, fixed-shape, and
decisive-composition narratives remain in Git history and retained archives rather than selecting
this reference.

Ethereum is not a Cairo settlement boundary. No L2, rollup, sequencer, bridge, or Solidity payment
role is active. Production clearance remains blocked on the later qualified proof/backend, Lean,
database, custody, source-governance, and activation gates owned by the current authorities.
