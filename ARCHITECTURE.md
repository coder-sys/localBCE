# Blind Ledger architecture

The current design is a strong signed database with mandatory application zero-knowledge proofs. It is not a blockchain execution system.

```text
signed source evidence
        |
canonical fixed-shape witness
        |
mandatory private ZK proof
        |
native verifier
        |
atomic database transaction
  - lock batch nonce
  - recheck roots and policy version
  - reject reused nullifiers
  - apply payment/state transition
  - append tamper-evident audit record
        |
optional future periodic Ethereum L1 checkpoint
```

## Authority boundaries

| Component | Establishes | Does not establish |
| --- | --- | --- |
| Database | Current operational state, concurrency, idempotency, recovery | Truth of submitted evidence |
| ZK proof | The hidden witness satisfies the pinned program, policy, signatures, and state transition | Honesty of an authorized source |
| Government/oracle signature | Provenance, signer authority, exact signed bytes | Real-world truth or policy wisdom |
| Native verifier | Cryptographic proof acceptance | Database durability unless acceptance is atomic with the write |
| Future Ethereum checkpoint | Timestamped public commitment or on-chain verification of an aggregate | Live application availability or source honesty |

## Current implementation

- `app/production_boundary.py`: native verifier to atomic local state-transition seam.
- `app/batch/`: canonical fixed-shape batching, nullifiers, commitments, accumulators, and state binding.
- `app/oracle_attestation.py`: governed source-attestation verification.
- `experiments/bl_pq512_crypto_core/`: M31/Fp16, SHA3-512, GKR, hiding, proving, and verifier candidate.
- `ops/native_stark_public_inputs_v2.json`: ordered 12-field public boundary.
- `docs/PQ_ZK_SECURITY_ARCHITECTURE.md`: detailed proof design and security conditions.

No L2, Solidity settlement, sequencer, bridge, or public data-availability implementation survives in the active architecture.
