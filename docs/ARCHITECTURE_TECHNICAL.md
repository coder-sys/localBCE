# Technical architecture

The execution path is intentionally small:

```text
canonical signed inputs
  -> fixed-shape witness/proof generation
  -> native BL-PQ512 verification
  -> LocalSettlementV2 / production database port
  -> atomic nullifier + state + payment commitment update
  -> append-only signed audit commitment
```

## Invariants

- The database accepts no caller-supplied verification boolean.
- The proof envelope and all public fields are parsed canonically and size-bounded.
- Verification is tied to exact verifier, suite, schema, policy, ruleset, source, and state identities.
- State-before must equal the locked current state.
- Nullifiers are unique and consumed in the same transaction as payment state.
- Retried requests are idempotent; conflicting retries fail.
- A crash before commit changes nothing; recovery never replays a transition against a different root.
- Logs contain commitments and safe metadata, never PHI.

## Component seams

`NativeVerifierPort` owns proof verification. `LocalSettlementV2` demonstrates the atomic transition contract. Production adapters must preserve the same input and receipt semantics against a serializable database and external custody.

The detailed proof design remains in `PQ_ZK_SECURITY_ARCHITECTURE.md`. The exact public fields remain in `ops/native_stark_public_inputs_v2.json`.

There is no on-chain execution layer in the current stack.
