# Blind Ledger current technical stack

Updated: 2026-07-31

Status: canonical current-stack index. If an older checkpoint conflicts with this file, `STATE.md`,
`ARCHITECTURE.md`, or `docs/IMPLEMENTATION_ROADMAP.md`, the newer current files win. Historical
measurements and rejected designs are evidence, never executable fallbacks.

## Current product boundary

Blind Ledger is a nonactivating zero-knowledge payment-system prototype. Wave 1 is the sealed
synthetic semantic relation. Wave 2 is the strict post-quantum proof and throughput-recovery wave.
Six of 93 engineering packages are complete. `proofSuiteId=null`, activation is false, and real
PHI or payments are forbidden.

The H4 prototype is functionally attached for both profiles:

| Boundary | Current value |
| --- | --- |
| Semantic source | Exact `BLHBB101` bounded hash-bus source |
| Hash proof | 24 Keccak rounds, 168 layers, seven-layer/B=16 relay-free nonuniform GKR |
| Claims | One output plus four relay-free input claims |
| Native hiding | 508 GKR mask constraints per shard |
| PCS | Construction 8.2 random-padded interleaved Reed--Solomon, 73-word auxiliary plane |
| Authenticated schedule | 6,073 GKR rounds plus 13 PCS rounds = 6,086 |
| Public coin | ML-DSA-87 plus SLH-DSA-SHAKE-256f authenticated chain |
| Authority split | CUDA performs untrusted arithmetic; Rust parses, recomputes, replays, and verifies |
| K128 | One shard; 29.974129 seconds complete process; 288.412 MB internal host; 969.999360 MB tracked device; 0 MB scratch |
| K512 | Four ordered sequential shards on one GPU; 120.460733 seconds; 296.255 MB internal host; 969.999360 MB tracked per proof; 0 MB scratch |
| Manifest | `51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6` |

All memory values are decimal MB. These are accepted one-run H4 prototype measurements, not H5
p95 qualification or H6 suite activation.

## Active source ownership

| Layer | Current source | Role |
| --- | --- | --- |
| Application and batching | `app/`, `rules-engine-rust/` | Canonical ingestion, policy, batch, and protected state-binding surfaces |
| Sealed semantic relation | `experiments/fixed_shape_claim_air/` | Nonactivating Wave 1 semantic producer and exact global SHA3 schedule |
| Authoritative proof core | `experiments/bl_pq512_crypto_core/` | Fp16, GKR, PCS, authenticated public coin, independent verifier, resource gates |
| Current GPU workers | `experiments/bl_pq512_crypto_core/cuda/cuda_hash_bus_b16_gkr_worker.py`, `cuda_fp16_zk_rs_interleaved_k128_prototype.py`, and their manifest-bound local verifier modules | Untrusted acceleration only |
| Historical semantic reference | `zk-cairo-sharp/` | Protected differential source; not the selected proof backend |
| Settlement shell | `contracts/` | Protected mock/test settlement boundary; no production `INativeStarkVerifier` exists |
| Operations | `ops/` plus required canonical sibling `../ops/` | Policy and verifier artifacts; the sibling canonical tree is currently absent in this workspace |

## Current execution order

1. Select and atomically bind the Gate 2E authoritative state plane and migration.
2. Close the complete composition, simulator, leakage, and state/proof receipt ledger.
3. Run H5: one warm-up plus ten unique K128 and ten unique K512 proofs with external resource and
   driver monitoring; qualify p95 below 30/180 seconds.
4. Run H6 suite, parser, mutation, rollback, recovery, reproducibility, and activation gates.
5. Implement the production native verifier and containing L2/L1 settlement path in later roadmap
   packages.

## Deliberately retained controls

The V1-layer compaction test, exact two-claim GKR/PCS differential, and retired-format rejection KAT
remain because they prove migration equivalence or fail-closed rejection. They do not expose a
fallback acceptance path. Any control that ceases to protect a current invariant must be removed
with its dependency and test evidence.

## Removed executable alternatives

The standalone RISC Zero and vendored Stwo experiments were removed from the active source tree on
2026-07-31 after confirming that no application or selected-proof module imported them. Their exact
evidence, source identities, rejection reasons, and recovery boundary are retained in
`docs/REJECTED_ARCHITECTURES.md` and Git history. They must not be restored as active dependencies.
