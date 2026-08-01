# Security-freeze context

Run: `20260715T202353Z-security-freeze-r23`

Status: synthetic-only review packet; current proof configuration rejected; external review pending.

Current planning interpretation: “external review pending” is the final audit/promotion condition,
not an outside implementation dependency. The exact suite must first be selected, built, and
internally qualified under `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md`; this historical R23 packet
itself selects or activates nothing.

Current topology interpretation: this historical R23 packet is now consumed by the Wave 2
heterogeneous proof contract in `docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`. The direct SHA3
AIR remains a differential oracle; the release path uses a shared committed bus and masked Fp16
Boolean GKR coprocessor. R23 security floors and rejection findings remain unchanged.

The analysis target is the archive-selected source snapshot with SHA-256
`382c02a9a9890251f167f3e28023ae4a2caf67c28ee24075a69b587bb6b9b20e`. Its former redundant local
rollback copy was removed on 2026-07-22; this hash and the sealed R23 record are the audit identity.
The exact external interface is the ordered 12-field manifest in
`ops/native_stark_public_inputs_v2.json`.

## Security objective

Build a fixed-shape, batch-oriented private-claim proof whose application boundary remains exactly
12 fields while the authoritative proof context, state, transcript, and commitments target at least
128 quantum-query bits. Safety, auditability, privacy, modularity, and throughput are co-equal; no
component may borrow security from a stronger neighboring component.

## Evidence boundary

- R21 is sealed foundation evidence, not proof-suite qualification.
- The six-column S-two AIR is a narrow validity prototype.
- The Cairo/S-two and RISC Zero runs remain semantic/performance evidence only.
- The complete synthetic executable relation now exists, but no complete K128 heterogeneous proof,
  native hiding layer, selected strict-PQ suite, verifier, or authoritative wide state exists.
- Real data, real credentials, external systems, dependency upgrades, and ABI changes are excluded.

## Canonical analysis

The detailed formulas, rejected configuration, candidate architecture, primary research links, and
open review questions are in `docs/BL_PQ512_SECURITY_FREEZE.md`. The repository threat model is in
`docs/BL_PQ512_THREAT_MODEL.md`.
