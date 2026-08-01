# Cairo Binding Security Notes

Status: multi-line binding statement, source-level adversarial tests, and local
proof checkpoint are present; production remains pending independent
cryptographic audit and verifier-artifact pinning.

Current role: this Cairo statement is a differential attack oracle, not the active release proof.
The shared-bus substitution, byte/bit bridge, masked Boolean-GKR, and atomic-verifier attacks are
owned by `../docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` and cannot be discharged here.

## Current Shape

The current Cairo source models the hardened multi-line binding statement:

- domain-and-arity-bound Poseidon,
- governed claim/oracle/ruleset/policy roots,
- governed fact commitments instead of raw free flags,
- governed policy rows instead of hardcoded fee ceilings,
- per-line TAR/authorization binding,
- approved-only sorted/indexed nullifier predecessor transitions,
- cent bounds and value-conservation checks,
- on-chain root anchors for settlement through `StarkBatchSettlement`.

## Regression Guards

The Python source guard in
`blind-ledger-app-layer/tests/test_cairo_binding_source_guards.py` rejects the
old regressions:

- untagged `update_with(input)` commitment,
- `spent_nullifier_0..7` style witness slots,
- `nullifier_not_spent` free flag,
- hardcoded `MAX_ALLOWABLE_LINE_CHARGE_CENTS`,
- raw trusted eligibility/provider/prior-auth inputs.

The Cairo/unit and Python KAT names keep the threat model visible:

- fabricated facts,
- duplicate-by-omission,
- procedure substitution,
- free ceiling,
- non-empty slot insert,
- stale root,
- cross-implementation commitment equality,
- denied-claim nullifier output forgery,
- per-line prior-authorization substitution,
- claim-source and oracle-facts binding drift.

## Remaining Blockers

Production remains blocked until:

- a native verifier artifact is audited and pinned,
- public inputs are proven against the exact schema enforced by
  `StarkBatchSettlement`,
- official source/oracle custody replaces local test infrastructure,
- independent cryptographic review signs off the circuit, witness generation,
  proof artifacts, and verifier path.

The old shell wrappers and pre-current proof notes were removed so they cannot be mistaken for
current Cairo evidence. Cairo itself must not be mistaken for the active heterogeneous proof lane.
