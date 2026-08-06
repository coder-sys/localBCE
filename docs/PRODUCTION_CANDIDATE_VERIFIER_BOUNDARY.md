# Blind Ledger production-candidate verifier boundary

Updated: 2026-08-06

Status: local, synthetic, nonactivating engineering evidence. This document describes a
per-proof candidate boundary; it does not claim production readiness, an independent audit,
live Ethereum settlement, HSM/FIPS custody, or operator activation.

## What is now implemented

The candidate path is an exact Rust-authoritative verifier for one selected proof package:

- `experiments/bl_pq512_crypto_core/src/bin/production_candidate_verify.rs` is the standalone
  local verifier.
- `experiments/bl_pq512_crypto_core/src/production_verifier.rs` parses the `BLPQENV1` version-2
  envelope, enforces the exact ordered 12-field public boundary (`12 * 32` bytes), checks the
  canonical 744-byte sidecar, and verifies the selected state-AIR proof package.
- `experiments/bl_pq512_crypto_core/src/selected_public_coin.rs` replays the complete private
  candidate transcript. Rust verifies both PQ signature families, derives the authenticated
  challenges, replays the fixed schedule, recomputes the transcript roots, and binds the result
  to the public outputs, sidecar, proof package, program, and selected bundle.
- `experiments/bl_pq512_crypto_foundation/production_candidate.py` accepts a nonzero
  `proofSuiteId` only after parsing the exact native Rust `OK` receipt and checking every
  receipt commitment. A caller-supplied success flag is not an admission input.

`proofSuiteId` is the selected-parameter identity derived from the nonzero selected-parameter,
program-binary, and public-coin-schedule commitments. It is carried and checked in the sidecar,
proof package, transcript, envelope, and native receipt. The resulting candidate record is
`BUILT_AUDIT_PENDING`, with `activation_allowed=false` and `production_usable=false`.

The native port now requires the lossless public-input projection. Each of the twelve canonical
`bytes32` outputs is split into nine little-endian 30-bit limbs, producing exactly 108 M31 inputs
without reduction or aliasing. `app/production_boundary.py` derives this file from the envelope
before invoking Rust, passes the projection schema identity, and rejects a caller-supplied static
vector. The Rust verifier recomputes the same 108 limbs and rejects any mismatch. The standalone
`production_candidate_verify` binary requires the projection-schema argument as well; there is no
six-argument compatibility mode in the active verifier path.

The local Privacy V2 and based-rollup seams are now executable around that port. `LocalSettlementV2`
recomputes the ordered twelve fields from the sidecar, governed roots, domain, and nonce, verifies
the native receipt, and publishes its in-memory state only after every binding succeeds.
`NativeRollupClaimVerifier` rechecks the same envelope against the Wave 5 claim context and suite
identity. `app/local_stack_candidate.py` independently recomputes the native, settlement, and
rollup commitments and emits a commitment-only `LOCAL_SYNTHETIC_NONACTIVATING` receipt. This is
local end-to-end engineering evidence, not an on-chain verifier or activation decision.

## Cross-language PQ boundary

The candidate transcript uses the RustCrypto `slh-dsa` FIPS-205 implementation through
`selected_slh_dsa_service`. It is a software-only internal reference service. It is not an HSM,
not a FIPS-validated module, and not production custody. The locked Python `pqcrypto` SPHINCS+
adapter remains available for historical evidence; its byte encoding is not silently mixed with
the RustCrypto candidate transcript. ML-DSA-87 remains on the existing locked adapter path.

## Hiding and custody status

The four historical Circle identifiers remain preserved as historical evidence:

`FINAL_CIRCLE_SPLIT_LOG_DEGREE_AND_PROVER_INTEGRATION`,
`FINAL_SHA3_AIR_INTERACTION_ORACLE_DIMENSIONS`,
`FINAL_MULTI_DOMAIN_FRI_ORACLE_WIDTHS_AFTER_SHA3_AIR_EXPANSION`, and
`INTERACTIVE_CIRCLE_SIMULATOR_TRANSCRIPT`.

`active_gkr_hiding.py` now supplies a source-bound rebase certificate for the active Construction
8.2 GKR/FRI path and reports no uncovered obligation in that current candidate composition. This
closes the current candidate-boundary bookkeeping without deleting or rewriting the historical
Circle record, and it is not an independent theorem review or production activation evidence.

`software_custody_candidate.py` supplies a source-bound software custody and anti-rollback
certificate. It deliberately reports `software_only=true`, `hsm_backed=false`,
`fips_validated=false`, `activation_allowed=false`, and `production_usable=false`. HSM/FIPS
qualification and an external anti-rollback authority remain required.

## Lifecycle separation

The candidate selector is separate from the legacy operational readiness registry. The repository
therefore has two intentionally different statements:

- A specific fresh synthetic proof can produce a nonzero candidate identity and a
  `BUILT_AUDIT_PENDING` record after the Rust receipt passes.
- `ops/launch_blockers.json`, the legacy release profile, and the global operational state remain
  `NOT_DEPLOYMENT_READY`, `UNSELECTED`, `proofSuiteId=null`, and activation-disabled. They are not
  flipped by a local proof and remain the fail-closed production gate.

This boundary does not implement the production/on-chain `INativeStarkVerifier` deployment, HSM/FIPS
custody, external live rollup integration, release authorization, or the independent audit. The
local exact settlement and Privacy V2 admission seam is implemented and remains nonactivating.
No live credentials, live Ethereum, government data, PHI, payment authority, or production artifact
was used.

## Verification receipt

The final local checks for this boundary were:

```text
cargo +1.96.0 fmt --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
exit=0

cargo +1.96.0 check --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --offline --locked --features std,parallel
Finished `dev` profile

cargo +1.96.0 test --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --release --offline --locked --features std,parallel
307 core tests passed; all binary/doc-test groups passed; 0 failed

cargo +1.96.0 clippy --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --all-targets --offline --locked --features std,parallel -- -D warnings
Finished `dev` profile

py -3.14 -m pytest tests/test_bl_pq512_production_candidate.py -k 'not real_rust' -q
4 passed, 1 deselected

py -3.14 -m pytest tests/test_bl_pq512_production_candidate.py -k real_rust -vv -s
1 passed, 4 deselected

candidate/transcript/Wave-3 containing tests: 28 passed, 1 deselected
PQ-governance containing tests: 44 passed
hiding/attack containing tests: 42 passed
```

The fresh end-to-end test generated a new synthetic proof, ran the standalone Rust verifier, parsed
its `OK` receipt, and constructed the candidate record. It did not persist a proof artifact in the
repository and did not change activation.
