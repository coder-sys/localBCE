# Cairo Proving Status

Status: source handoff only. A local multi-line Cairo/Stwo proof checkpoint has been produced previously in a developer checkout, but generated proof artifacts are not packaged in this archive. The production verifier lane is blocked on a real verifier implementation, exact output-ABI binding, audit, and artifact pinning.

Current architecture note: this is historical/differential proof evidence, not the active release
lane. Wave 2 targets the heterogeneous M31 semantic-STARK/shared-bus/Fp16 Boolean-GKR SHA3 proof in
`../docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`.

The target system is an Ethereum-settled based validity rollup. This claim circuit is the inner application proof; it is not the rollup proof and does not independently establish Ethereum finality. See `../docs/BASED_ZK_ROLLUP_ARCHITECTURE.md`.

The current S-two backend is not zero-knowledge according to official S-two documentation. Existing
proof checkpoints establish validity behavior only and are not approved for real PHI or witness
privacy claims. See https://docs.starknet.io/learn/S-two-book/why-stwo.

The retired flat trusted-flag executable is no longer a proof target. It allowed free eligibility/provider/auth flags, used an 8-slot spent-nullifier list, and carried a fixed charge ceiling. The active target is the multi-line `MultiLineDecisionInput` / `BatchClaimInput` statement in `src/lib.cairo`.

## Current Statement Shape

- Domain-and-arity-bound Poseidon calls.
- Governed claim-source, oracle-facts, ruleset, and merged `policyRoot`.
- Per-line service-line binding with procedure, charge, units, allowed amount, TAR-required status, and optional authorization.
- Governed policy rows instead of a hardcoded ceiling.
- Approved-only sorted/indexed nullifier predecessor transitions.
- Denied claims emit sentinel nullifier outputs and do not advance state.
- `u128` cent amounts with explicit bounds and line-total/value checks.

## Local Toolchain

- Scarb `2.18.0`.
- Cairo compiler `2.18.0`.
- Sierra `1.8.0`.
- Executables: `claim_main` and `batch_main`.

## Proof checkpoint policy

This optimized ZIP does not include generated Scarb target directories, execution traces, proof JSON, or public-input JSON. Regenerate them locally when proof evidence is needed, then record the raw command output, output path, proof hash, verifier output, and public-input manifest in review notes or the app-layer proof provenance file.

Treat any previous proof checkpoint as evidence for the exercised local statement and witness shape only. It is not a production audit, not a deployed verifier, and not a license to settle live payments.

## Remaining Production Blockers

- Resolve the current 12-value Cairo output versus 21-value settlement-input mismatch.
- Implement and audit a real L2 claim-proof verifier; the Solidity test mock is not evidence.
- Bind successful claim verification into a rollup validity proof accepted by Ethereum L1.
- Replace the V1 public amount/count/ciphertext statement with the versioned Privacy V2 statement.
- Complete and internally qualify the masked heterogeneous proof and atomic verifier before
  processing PHI.
- Independent cryptographic review of the circuit, witness generation, and proof lane.
- Audited native verifier artifact.
- Governance-pinned verifier artifact hash.
- Reproducible release packet tying witness, proof, verifier output, settlement payload, and public input manifest together.
- Official oracle/source ingestion and key custody.
