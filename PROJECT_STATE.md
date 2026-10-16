# Project State

## Active Runtime

The checked-in runtime is adjudication-only:

- `proof_execution_enabled` is `false`.
- G1-G10 adjudication still writes `adjudication_result.json`.
- Approved and denied results do not generate proofs or submit transactions.
- `groth16` and `stark_attested` remain dormant compatibility implementations.

The active workflow is:

```text
claim_input.json
-> Rust G1-G10 adjudication
-> adjudication_result.json
-> optional RightRail-derived off-chain journal
-> deterministic reconciliation report
```

`bridge/rightrail_offchain.py` is the sole writer for its append-only journal.
It accepts only proof-free adjudication results and synthetic, redacted
remittance events. The external RightRail SQLite owner, payment actions, Lean
worker, UI, signers, and binaries remain inactive.

The retained, inactive STARK workflow is:

```text
claim_input.json
-> Rust G1-G10 adjudication
-> StarkBridgeInput
-> persistent indexed nullifier transition
-> real Winterfell proof and local verification
-> proof artifact and verifier handoff
-> controlled-attestation envelope
-> governed StarkAttestationVerifierV2 / StarkClaimsRegistryV2 candidate
-> finalized settlement journal
-> atomic local state update
```

## STARK Migration Status

The Groth16-to-STARK technical implementation remains complete for the selected
controlled-attestation profile, but both proof paths are disabled in the active
runtime.

Implemented and tested:

- production G1-G10 Winterfell AIR
- constrained claim facts, decision, failure code, and fact commitment
- AIR-bound claim-source, oracle-facts, fee-schedule, nullifier, public-input,
  and batch roots
- versioned real-proof artifact with local deserialization and verification
- persistent depth-10 indexed nullifier state
- lock, generation compare-and-swap, atomic write, replay rejection, and root
  reconciliation
- complete verifier handoff over 38 public inputs
- canonical 129-byte secp256k1 attestation envelope bound to registry and amount
- controlled-attestation Solidity verifier and STARK ClaimsRegistry
- approved and denied runtime settlement through `rust-engine`
- fail-closed, explicit `stark_attested` routing retained behind the disabled
  proof-execution gate
- disposable-Anvil end-to-end validation
- external-command signer validation with request/key/address/low-s checks
- parallel non-proxy V2 contracts with a 72-hour timelock and emergency pause
- versioned finality journal and idempotent post-submission reconciliation CLI
- canonical policy manifest, monitoring definitions, deployment pins, and CI
- inactive native-verifier mutation vectors and activation gates

The trust boundary is important: Solidity verifies an authorized attestor
signature over the settlement inputs and proof commitment. It does not execute
a native Winterfell verifier. The full proof is retained and locally reverified
off-chain. See `STARK_RUNTIME.md`.

## Current Validation

```bash
bash scripts/validate_stark_bridge_chain.sh
bash scripts/validate_stark_runtime_settlement.sh
bash scripts/validate_stark_v2_anvil.sh
RUN_STARK_RUNTIME_SETTLEMENT=1 bash scripts/validate_localbce.sh
```

The live runtime validator deploys disposable contracts, settles approved and
denied claims, reconciles on-chain and local nullifier roots, and confirms
replay rejection without invoking Groth16.

## Major Folders

- `rust-engine/`: active adjudication and proof-backend routing
- `zk/`: active Circom/Groth16 compatibility artifacts
- `blind-ledger/`: Groth16 and controlled-attestation STARK settlement contracts
- `stark-engine/`: Winterfell AIR, prover, state, artifacts, and settlement
- `gov-rules-kg-prototype/`: source-grounded rule discovery and review lane
- `zk-prover/`: future dedicated proving service scaffold
- `blind-ledger-app-layer/`: imported cofounder reference/audit lane
- `localBCE-codex-dev-hardened-20260616/`: imported hardened reference bundle
- `ops/`: inactive production planning and governance scaffolds

Imported bundles remain reference-only until specific behavior is reviewed and
ported into active folders.

## Compatibility Constraints

- `denial_reason()` remains the active G1-G10 adjudication source of truth.
- `rules.json` and `rules_v9.json` remain parallel and are not runtime-loaded.
- `adjudication_result.json` remains compatible.
- Existing Groth16 contracts and circuit artifacts remain untouched by the
  STARK backend.
- `proof_execution_enabled` absent or `false` prevents proof generation and
  chain submission.
- Re-enabling a compatibility backend requires an explicit local setting of
  `proof_execution_enabled: true`; no automatic fallback exists.
- STARK attestor keys must stay outside repository config and artifacts.

## Production Readiness

The governed V2 implementation is locally testable but is not deployed to
Sepolia. Safe creation, MPC credentials, funding, approved policy sources,
legal approval, finalized public canaries, operational drills, and independent
audits remain external launch blockers. The native EVM verifier is an inactive
candidate until complete transcript/FRI parity, EIP-170, gas, adversarial, and
audit gates pass.

## Rules Engine Status

The current G1-G10 policy is available as a typed, hash-pinned
`rules_active_v1.json` bundle behind the explicit `versioned_g1_g10` rules
backend. All 13 denial branches and the valid claim path are parity-tested
against `denial_reason()`. The hard-coded implementation remains the default.

The Claude pipeline exports 191 strong deterministic-QA mappings across all 51
taxonomy programs into a canonically hashed Rust-validated shadow bundle. The
30 attention candidates are excluded. Every exported candidate remains marked
non-runtime, not proof-bound, and not legally verified. See `RULES_ENGINE.md`.

The next policy work is legal/source verification and typed field mapping for
individual candidate families before creating any new active ruleset version.
