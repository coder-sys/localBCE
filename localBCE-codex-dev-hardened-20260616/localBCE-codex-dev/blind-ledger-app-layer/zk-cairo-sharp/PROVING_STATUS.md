# Cairo Proving Status

Status: hardened binding library compiles and Cairo unit tests pass locally.

The previous flat trusted-flag Cairo executable has been retired. It accepted
free eligibility/provider/auth flags, used an 8-slot spent-nullifier list, and
contained a fixed charge ceiling. That interface is no longer a proof target.

The current `src/lib.cairo` is shaped around the production binding statement:

- domain-and-arity-bound Poseidon calls
- on-chain pinned claim, oracle, fee, ruleset, and nullifier roots
- governed oracle facts rather than raw free flags
- governed fee rows rather than a hardcoded ceiling
- sorted/indexed nullifier predecessor transition
- 2**59 cent bounds using `u128` amounts

Local toolchain:

- Scarb 2.18.0 installed under the user profile.
- `scarb build` passes.
- `scarb test` passes for the hardened binding source tests.
- `cairo-compile` and `cairo-run` are Cairo 0-era command names and are not part
  of this Scarb/Cairo 1 package.

Current limitation: the retired flat executable was intentionally removed, so
there is no hardened executable/prover fixture yet. Proof generation remains
blocked until a witness serializer/executable is added for `HardenedClaimInput`.

Production remains blocked until audited Cairo execution fixtures prove the
hardened statement and a native verifier artifact is pinned.
