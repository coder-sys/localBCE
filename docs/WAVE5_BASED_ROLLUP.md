# Wave 5 based-validity-rollup boundary

Status: internally complete at the local/synthetic, nonactivating boundary on 2026-08-05.
The implementation is in `app/wave5_rollup.py`, with the offline receipt runner in
`tools/wave5_conformance.py` and focused conformance/attack tests in
`tests/test_wave5_rollup.py` and `tests/attacks/test_wave5_rollup_attacks.py`.

## What this closes

The twelve R01-R12 interfaces are exercised as one deterministic fixture:

- R01 records a versioned baseline/future-shadow fork manifest, all 23 Strawmap EIP entries,
  disabled optional features, client/Engine/EVM pins, data modes, and explicit external-classical
  Ethereum boundary treatment.
- R02 builds a five-node EL/CL/L2 local deployment with fixed slots, gas/blob limits, transaction
  format, BAL mode, and selectable commitment-only data modes. It does not launch a real client or
  open a network socket.
- R03 binds the exact ordered 12-field V2 ABI, the fixed 744-byte authenticated sidecar, the
  candidate proof identity, the fork/chain/state/DA context, and a deterministic synthetic proof
  envelope. `SyntheticReferenceClaimVerifier` is an integration fixture, not the production ZK
  verifier; it cannot select `proofSuiteId` or enable activation.
- R04 derives an atomic L2 successor over nullifier, payment, wide state, keyed nonce, recent-root,
  and L1-anchor commitments. BAL and CBAM are separate commitments. Replay, stale-state, and
  settlement-binding failures are fail closed.
- R05 produces a bounded local L2 transition proof and runs baseline/future-shadow differential
  execution. Both profiles share one explicitly bound L2 semantics identity; the future profile is
  shadow-only and cannot be settled.
- R06 distinguishes head from finalized L1 state and settles only an accepted transition whose
  proof/state root and dual-PQ governance approval match the finalized block.
- R07 orders opaque transactions from the L1-origin inbox, checks inclusion-list withholding,
  duplicate/nonce conflicts, forced inclusion, and execution validation without a privileged
  canonical sequencer input.
- R08 publishes only fixed-size commitment cells, verifies partial fetch/reconstruction, retention,
  corruption, commitment equality, and commitment-only DA mode migration.
- R09 binds commitment-shaped bridge deposits and delayed withdrawals to finalized L1 state,
  replay domains, recipient/value commitments, and accounting conservation without public amounts.
- R10 supplies bounded opaque forced inclusion and safe delayed exits through the same finalized
  bridge boundary.
- R11 applies a manifest-bound future-shadow adapter only after dual-PQ approval and a timelock;
  unknown fork observation pauses the controller and a governed emergency rollback returns to the
  last pinned baseline.
- R12 runs the complete synthetic claim-to-L2-proof-to-finalized-L1-to-bridge-exit path plus DA
  migration and fork rollback, and emits a receipt with `proofSuiteId=null` and all activation flags
  false.

## Explicit nonclaims

This is not a live Ethereum deployment, a production EL/CL client, a production L2 EVM, a real
native Stark verifier, a selected proof suite, an HSM/FIPS custody module, an independently audited
release, or end-to-end post-quantum Ethereum security. No live credentials, PHI, encrypted medical
records, exact private amounts, payment authority, or network access are used. Ethereum's external
classical cryptography remains isolated and receives no Blind Ledger PQ credit. EIP-8025, EIP-8079,
EIP-8141, EIP-8184, EIP-8250, EIP-8272, and EIP-8297 remain disabled optional adapters.

The synthetic reference verifier proves byte-for-byte binding of this local envelope only. The
production claim verifier, production state/custody acceptance, HSM/FIPS qualification, final
release seal, independent audit, and operator activation remain downstream boundaries.
