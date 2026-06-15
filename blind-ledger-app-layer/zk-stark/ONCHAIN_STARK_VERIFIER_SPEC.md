# Native On-Chain STARK Verifier Spec

Status: SPEC ONLY. PQ-at-the-anchor is not achieved until a real native STARK/FRI verifier is built, tested on-chain, gas-measured, and cryptographically audited.

## Objective

Blind Ledger needs an on-chain verifier that checks a transparent STARK proof directly at the chain trust anchor. The current runnable STARK core proves adjudication off-chain with Winterfell and verifies with Winterfell's Rust verifier. That is useful, but it is not yet an EVM-native verifier.

The production goal is: submit a batch root, result root, nullifier root transition, public decision commitments, and a native STARK proof; the settlement contract verifies FRI/STARK math on-chain before accepting the batch.

## What A Native Verifier Requires

- Field arithmetic for the selected STARK field.
- Transcript hashing and Fiat-Shamir challenge derivation.
- Merkle authentication checks for trace, constraint, and FRI layers.
- FRI folding verification and low-degree query checks.
- Boundary/public-input checks tying the proof to batch roots, result roots, nullifier roots, ruleset root, verifier version, and domain-separated chain/app identifiers.
- A Solidity or precompile implementation whose gas is measured against real proof bytes.

This is expensive because STARK proofs are larger than Groth16 proofs and FRI verification performs many hash operations. It is rare because Ethereum's EVM is not naturally optimized for native FRI verification; most production systems avoid direct EVM FRI verification unless they own the chain, have a verifier precompile, or accept high gas.

## Why Not SNARK-Wrap

SP1 and RISC Zero commonly use a Groth16 or PLONK wrapper for EVM verification. That gives a small proof and practical gas cost, but the on-chain trust anchor becomes pairing-based again. Groth16/PLONK over elliptic curves is not post-quantum.

Blind Ledger must not call a SNARK-wrapped STARK "end-to-end PQ." It is fair to call it "PQ-capable off-chain proving with a non-PQ EVM wrapper." That is not the target for federal/payment finality if PQ-at-anchor is a requirement.

## Options

### Option A: Native FRI Verifier Contract

- Gas/cost: likely high; must be measured after implementation. Expect the proof to be much larger than Groth16 and verifier work to be hash-heavy.
- PQ status at anchor: strongest option. The chain verifies the STARK directly with hash/FRI assumptions instead of pairings.
- Build effort: high. Requires expert implementation, test vectors, fuzzing, formal review of transcript binding, and careful gas engineering.
- Audit burden: high. Needs a cryptographic audit plus smart-contract audit.
- Best fit: if the L2/app-chain must offer trustless PQ verification on a conventional EVM surface.

### Option B: L2/App-Chain With STARK Verifier Precompile

- Gas/cost: lower on-chain gas if the verifier is native/precompiled, but this moves complexity into chain engineering.
- PQ status at anchor: strong if the precompile itself verifies native STARK/FRI and the settlement chain accepts its result under the intended trust model.
- Build effort: high infrastructure effort. Requires chain/runtime work, node operation, prover/verifier compatibility, and settlement design.
- Audit burden: high. Requires runtime/precompile audit, consensus/bridge review, and proof-system audit.
- Best fit: if Blind Ledger controls or partners on a payment L2 where verifier economics matter more than vanilla EVM portability.

### Option C: Off-Chain Verification In Secure Gov Environment, Anchor Commitments

- Gas/cost: cheapest on-chain. Store batch root, result root, nullifier root, ruleset root, and signed attestation.
- PQ status at anchor: partial. The proof can be PQ off-chain, but the chain is trusting the attestation environment rather than independently verifying the STARK.
- Build effort: moderate code effort plus governance/security integration.
- Audit burden: operational and controls-heavy. Needs key management, secure enclave or government environment controls, attestation policy, log retention, and dispute process.
- Best fit: an early regulated deployment where legal/operational trust is acceptable and direct EVM FRI cost is not.

## Recommended Path

Short term: keep Groth16 as the working demo and keep the Winterfell STARK core as the PQ-capable proof direction. Do not rewire payments to the STARK path until the verifier path is selected.

Raise-funded track: build Option A or Option B with external cryptographic help. Option B is the cleaner long-term architecture if Blind Ledger can influence the L2/app-chain environment. Option A is more portable but may be gas-expensive enough to force batching and aggregation from day one.

Deployment fallback: Option C can be an interim regulated workflow, but it is not fully trustless on-chain verification.

## Explicit Claim Boundary

Today the honest claim is: PQ-capable STARK proving exists off-chain, soundness-checked where runnable, PENDING CRYPTOGRAPHIC AUDIT. PQ-at-the-anchor is pending native STARK verification. No pairing-based SNARK wrapper should be represented as end-to-end post-quantum.
