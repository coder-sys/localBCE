# Cairo / SHARP Adjudication Port

This directory is the preferred Cairo-native STARK prototype for Blind Ledger.

It ports the G1-G10 adjudication semantics into a standalone Cairo executable
that can be compiled and locally tested with Scarb.

## Status

- Local Cairo compile/test target: implemented.
- Batch ID, raw claim root, ruleset root, adjudicator version, and nullifier
  state are bound into the public output commitment.
- Duplicate checking is derived from bounded spent-nullifier state instead of a
  free duplicate flag.
- Native Ethereum STARK verifier integration: pending.
- Security label: soundness-checkable prototype, pending cryptographic audit.

## Caveat

This lane does not yet parse raw 837 claim bytes inside Cairo or verify a
production sparse/indexed Merkle non-membership proof. Production must keep the
STARK-field strategy end to end and pin the verifier artifact before settlement.
