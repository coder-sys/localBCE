# Project map

| Path | Purpose |
| --- | --- |
| `app/` | Application, adapters, batching, readiness checks, and direct native-verifier/database boundary |
| `app/batch/` | Fixed-shape claim batching, nullifiers, commitments, accumulators, and state binding |
| `experiments/bl_pq512_crypto_core/` | Rust BL-PQ512 proof and verifier candidate |
| `experiments/bl_pq512_crypto_foundation/` | Foundation evidence, completion checks, and ops authority |
| `experiments/fixed_shape_claim_air/` | Executable AIR and claim/oracle composition experiments |
| `zk-cairo-sharp/` | Earlier Cairo proof research retained for evidence and comparison |
| `ops/` | Canonical operational configuration and launch blockers |
| `tests/` | Functional, adversarial, architecture, and evidence tests |
| `tools/` | Conformance and evidence utilities |
| `docs/` | Current architecture, proof design, roadmap, and historical evidence |

The deleted `contracts/` and Wave 5 modules belonged only to the abandoned L2 design.
