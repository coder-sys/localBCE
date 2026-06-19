# Native On-Chain STARK Verifier Spec

Status: spec only. Production is blocked until a real native STARK verifier is
built, tested against real proof bytes, gas-measured, and independently audited.

## Objective

The settlement contract must verify native STARK proof math directly for the
batch public inputs:

- nullifier root transition,
- claim/result/payment roots,
- data availability root,
- encrypted claim data root,
- value conservation commitment,
- payment amount.

## Verifier Requirements

- STARK-field arithmetic.
- Transcript hashing and challenge derivation.
- Merkle authentication for trace, constraint, and FRI layers.
- FRI folding and low-degree query verification.
- Boundary checks tying the proof to the exact public input schema.
- Artifact hash pinning against the deployed verifier.
- Smart-contract and cryptographic audits.

## Non-Goals

Wrapper-style verifier anchors are not accepted as production. The active
production lane requires native STARK verification at the settlement anchor.

## Current Claim Boundary

Local STARK proving exists as a proof core. Production settlement remains
blocked until audited native verifier artifacts are pinned and tested against
real proof bytes.
