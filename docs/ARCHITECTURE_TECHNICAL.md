# Technical architecture

The execution path is intentionally small:

```text
canonical signed inputs
  -> fixed-shape witness/proof generation
  -> native BL-PQ512 verification
  -> TransactionalSettlementV2 / storage port
  -> atomic nullifier + state + payment commitment update
  -> append-only chained audit commitment
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

`NativeVerifierPort` owns proof verification. `LocalSettlementV2` remains the deterministic in-memory
model. `TransactionalSettlementV2` and `SQLiteSettlementStoreV2` supply the durable Phase 2
reference, including per-store keyed verifier authorization, serializable writes, exact retry
receipts, submitter-bound state with commitment-only audit provenance, backup/restore, audit-chain
readback, and a write-ahead external anti-rollback interface.
Pre-commit reservation and post-commit finalization failures are recovered only through the exact
reverified transition, without a second database advance; delayed duplicate finalization remains
idempotent after later progress. SQLite and the in-memory anchor are local
qualification tools, not production selections. Production adapters must preserve the same input
and receipt semantics against a qualified database and external custody.

The detailed proof design remains in `PQ_ZK_SECURITY_ARCHITECTURE.md`. The exact public fields remain in `ops/native_stark_public_inputs_v2.json`.

There is no on-chain execution layer in the current stack.
