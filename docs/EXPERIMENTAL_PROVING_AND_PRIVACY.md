# Experimental proving and privacy architecture

Current interpretation (2026-07-31): this document records historical experiments, not the active
release architecture. The current Wave 2 path is the heterogeneous M31 semantic-STARK/shared-bus/
Fp16 Boolean-GKR SHA3 construction in
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`. Measurements below are controls only and must not
be projected onto that complete proof.

## Scope

These changes exist only in the separate architecture workspace. The Desktop, Downloads, and
OneDrive release ZIPs were not modified. Existing production entrypoints remain available.

## Contract-ready encrypted audit data

The opt-in `aes_gcm` batch mode now creates a canonical encrypted audit bundle with AES-256-GCM,
stores the exact serialized ciphertext bytes on the submitted batch, and uses the raw SHA-256 of
those bytes as `encryptedClaimDataRoot`. This matches the existing settlement contract check:
`sha256(encryptedPayload) == encryptedClaimDataRoot`.

Because the root is also a Cairo field element, encryption uses a fresh random nonce until the raw
SHA-256 digest is below the Cairo field modulus. No modulo reduction is used. The legacy commitment
mode remains unchanged for compatibility.

Relevant source:

- `app/batch/encrypted_da.py`
- `app/batch/leaf.py`
- `app/batch/batch_orchestrator.py`

## Safe nullifier epoch rotation

The `stable_global` experiment separates two concepts:

- Rotating alias peppers remain useful for local privacy and duplicate aliases.
- One immutable global pepper creates the permanent proof-backed nullifier stored in the global
  indexed nullifier tree.

Rotating or losing the local alias caches therefore cannot make an already-spent claim spendable
again. The authority pins the mode and permanent pepper so a request cannot downgrade itself to a
rotating proof nullifier.

This is a safety architecture change, not a proving-speed improvement. It does not shrink the
nullifier tree and does not delete permanent spent state.

Relevant source:

- `app/batch/batch_orchestrator.py`
- `tests/test_batch_layer.py`

## Application-specific Stwo AIR

`experiments/stwo_batch_air` is pinned to official Stwo commit
`aeceb74c58184d7886ebd7f34a7453fee714ca40`. Each trace row represents one claim lane. The AIR
enforces:

- Decision is zero or one.
- Approved cents equal requested cents multiplied by the decision.
- Paid cents equal approved cents.
- Approved and paid running states are connected through a LogUp relation.
- The LogUp claimed sum reconciles the trace with public initial and final totals.

The prover uses Stwo's 16-lane packed M31 SIMD backend and its Rayon `parallel` feature. All heavy
Cargo output was directed outside the workspace.

### Measured proof runs

All rows below printed `proof_verified=true`. Compilation and process startup are excluded.

| Claim rows | Threads | Prove seconds | Verify seconds |
|---:|---:|---:|---:|
| 1,024 | 16 | 0.106334 | 0.000168 |
| 65,536 | 16 | 0.387810 | 0.000258 |

The thread sweep used 262,144 claim rows and three independently verified samples per setting.
`Pipeline seconds` is the median sum of twiddle, trace, commitment, LogUp interaction, prove, and
verify stages.

| Threads | Median prove seconds | Median pipeline seconds |
|---:|---:|---:|
| 1 | 1.088891 | 1.749012 |
| 2 | 0.573335 | 0.968879 |
| 4 | 0.346168 | 0.580503 |
| 8 | 0.363920 | 0.560072 |
| 16 | 0.592623 | 0.867316 |

Four threads were fastest for the prove call. Eight threads were fastest for the measured total
pipeline, about 3.12 times faster than one thread. Sixteen threads were slower because this proof
is small enough that scheduling and memory overhead dominate.

### Security boundary

This custom AIR does not yet bind claim identities, claim/result/payment Merkle roots, policy or
oracle evidence, permanent nullifiers, encrypted audit data, accumulators, or the then-current
experimental 21-field settlement-input schema. Its sub-second result cannot be compared to the full
Cairo proof as if it were a drop-in speedup. It is a verified prototype for one extracted statement.

At the time of this historical experiment, production replacement would have required all of the
following. The current H0-H6 contract supersedes this list for active implementation:

1. Bind every production root and amount in the custom AIR's public statement.
2. Reproduce nullifier, policy, oracle, encrypted-data, and accumulator constraints.
3. Add differential known-answer tests against the Cairo circuit for valid and adversarial batches.
4. Add a pinned verifier artifact and on-chain verifier path for this exact AIR.
5. Complete independent cryptographic and application-security audits.

## Validation record

At the custom AIR gate:

- Valid proof round trip: passed.
- Changed public total rejection: passed.
- Non-Boolean decision rejection during proving: passed with `ConstraintsNotSatisfied`.
