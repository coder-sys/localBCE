# Project map

| Path | Purpose |
| --- | --- |
| `app/` | Application, adapters, batching, readiness checks, and direct native-verifier/database boundary |
| `app/batch/` | Retained Privacy V2 batching/state reference; protected until native-v3 replacements accept |
| `experiments/bl_pq512_crypto_core/` | Retained Rust H4/CUDA, composition, and binary-field component evidence |
| `experiments/bl_pq512_crypto_foundation/` | Retained foundation, security-ledger, and operational evidence |
| `experiments/fixed_shape_claim_air/` | Executable AIR and claim/oracle composition experiments |
| `zk-cairo-sharp/` | Earlier Cairo proof research retained for evidence and comparison |
| `ops/` | Canonical operational configuration and launch blockers |
| `tests/` | Functional, adversarial, architecture, and evidence tests |
| `tools/` | Conformance and evidence utilities |
| `docs/NATIVE_V3_ARCHITECTURE.md` | Active proof, state, security, privacy, and CPU contract |
| `docs/LEAN_FORMAL_KERNEL.md` | Approved executable Lean semantic/state-transition kernel and theorem gates; not yet implemented |
| `docs/` | Transaction architecture, roadmap, implementation status, and historical evidence |

Current proof continuation starts at `CURRENT_TASK.md`, `docs/NATIVE_V3_ARCHITECTURE.md`, and the
formal target in `docs/LEAN_FORMAL_KERNEL.md`.
Legacy handoffs and decisive-composition documents are evidence only.

The deleted `contracts/` and Wave 5 modules belonged only to the abandoned L2 design. No L2,
Solidity, sequencer, bridge, or public data-availability layer is active.
