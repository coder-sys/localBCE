# Cairo / SHARP Adjudication Port

This directory is the preferred native-STARK lane for Blind Ledger.

It ports the live G1-G10 adjudication semantics into a standalone Cairo executable
that can be executed and locally proven with Scarb's S-two integration. It is
separate from the existing Groth16 `zk/` and Winterfell `zk-stark/` work.

Status:

- Local Cairo compile/test target: implemented.
- Batch ID, raw claim root, ruleset root, adjudicator version, and nullifier state are
  bound into the public output commitment.
- G9 duplicate checking is derived from a bounded spent-nullifier witness instead
  of a naked trusted duplicate flag.
- Local S-two proof target: intended through `scarb prove`.
- Native Ethereum STARK verifier integration: not wired yet.
- Mainnet SHARP proving/settlement path: pending integration decision.
- Security label: soundness-checkable prototype, PENDING CRYPTOGRAPHIC AUDIT.

Important caveat:

This is not a drop-in verifier for the existing Winterfell proofs. The point of
this lane is to move the claim adjudication program into the Cairo/S-two/SHARP
ecosystem so that a native StarkWare-style STARK verifier can eventually verify
the proof at the Ethereum trust anchor without a Groth16/PLONK wrapper.

Security caveat:

The current Cairo lane is still a prototype. It binds to raw roots and a bounded
nullifier witness, but it does not yet parse raw 837 claim bytes inside Cairo or
verify a production sparse/indexed Merkle non-membership proof.

Architecture caveat:

The current app/nullifier stack uses BN254 Poseidon and `bytes32` roots, while
this Cairo lane uses the STARK field and Cairo native Poseidon. Those are not
drop-in compatible fields. Production must either migrate duplicate keys,
nullifier roots, and batch commitments into the STARK field end-to-end, or prove
a non-lossy limb-decomposition bridge inside Cairo. Until then, this is a
strategically correct prototype lane, not an interoperable replacement for the
current app/nullifier state.

Failure-code mapping in this Cairo executable:

- `0`: approved
- `1`: G1 member id present
- `2`: G2 eligibility active
- `3`: G3 provider NPI present
- `4`: G4 provider enrolled
- `5`: G5 service lines present
- `6`: G6 diagnosis present
- `7`: G7 prior authorization when required
- `8`: G8A charge valid
- `9`: G8B charge within allowable amount
- `10`: G9 not duplicate
- `11`: G10 no program integrity hold
