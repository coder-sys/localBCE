# Production Lane Decision

Status: architecture decision, not production ratification. Security ceiling remains
soundness-checked prototype, PENDING CRYPTOGRAPHIC AUDIT.

## Decision

The production proof lane is Cairo / STARK-native.

Groth16/BN254, Winterfell, and SP1 remain useful demo, comparison, and research
lanes, but they are not the production acceptance path unless a later signed
architecture decision replaces this file.

## Why Cairo / STARK-Native

- Transparent proof system direction: no trusted setup.
- Post-quantum plausible proof layer when verified through a native FRI/STARK
  trust anchor.
- Better long-term fit for federal/public-sector claims than a pairing-based
  on-chain anchor.
- Aligns with the existing `zk-cairo-sharp/` lane and the desired SHARP/S-two
  ecosystem direction.

## Non-Negotiable Production Conditions

The Cairo lane is not production-ready until all of these are true:

- A unified batch binding circuit exists and is audited.
- Raw claim facts and external facts are derived or verified inside the proof.
- Duplicate prevention uses an authoritative nullifier-root transition, not free
  witness slots.
- Payment roots are constrained to approved results and per-provider netting.
- Accumulator roots enforce benefit caps, unit/visit limits, deductibles, and
  prior-authorization consumption.
- Service date is bound to effective-dated ruleset, fee schedule, eligibility,
  provider status, and authorization roots.
- The BN254-vs-STARK field mismatch is resolved by STARK-field migration or a
  non-lossy limb bridge.
- Native STARK verification or an explicitly approved non-PQ anchoring strategy
  is deployed.
- Governance uses multisig, timelock, immutable verifier trust roots, monitoring,
  and emergency playbooks.

## Deprecated For Production

These lanes must not be accepted as production proof authority by default:

- `zk/` Groth16/BN254: good EVM demo economics, not PQ and trusted-setup based.
- `zk-stark/` Winterfell: useful runnable STARK PoC, no native Solidity verifier
  path in this repo.
- `zk-sp1/`: useful zkVM experiment, but EVM verifier paths are typically
  Groth16/PLONK wrapped and therefore not PQ at the on-chain anchor.

## Current Honest Status

The app layer is hardened enough for serious cofounder/security-audit handoff.
The cryptographic production engine is specified but not fully built or audited.

