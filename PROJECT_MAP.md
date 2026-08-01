# Project map

Current entrypoint: `docs/CURRENT_TECH_STACK.md`. `WAVE2_HANDOFF_2026-07-26.md` is historical
recovery evidence and does not define the current proof architecture.

| Path | What it is | Edit risk |
| --- | --- | --- |
| `app/` | Python app layer: ingestion, adjudication, batching, portals, and API helpers. | Medium to high. |
| `app/batch/` | Batch construction, nullifiers, leaves, Merkle roots, STARK binding, and Poseidon helper integration. | High. Most files are protected. |
| `app/batch/pq_tree_reference.py` and `pq_sparse_tree_reference.py` | Synthetic-only independent legacy/SHA3-512 complete/sparse governed-map roots plus exact membership/nonmembership paths. No production domains or activation. | High for reference semantics; preserve exact KATs. |
| `app/batch/pq_strong_nullifier_reference.py` | Synthetic full-width depth-64 indexed replay transition with exact predecessor/insertion multiproofs. Not authoritative state or an AIR. | High for replay-reference semantics. |
| `app/batch/pq_nullifier_derivation.py` | Exact A12 attempt/cover framing, independent legacy/SHA3-512 derivation, pepper commitment, and registry-authority rotation guard. Not a proof-system hash or production state owner. | Trust-critical replay semantics; preserve byte KATs and fail-closed lifecycle. |
| `app/policy/` | Policy-schema helpers and fixtures. | Medium. |
| `rules-engine-rust/` | Rust rules engine used by adjudication when available. | High for policy semantics. |
| `zk-cairo-sharp/` | Cairo circuit and Scarb project. | Protected. Do not edit without explicit approval. |
| `contracts/` | On-chain verifier/settlement Solidity code. | Protected. Do not edit without explicit approval. |
| `tests/` | Unit, integration, known-answer, and readiness tests. | Medium. Do not weaken tests. |
| `tests/attacks/` | Security/attack regression tests. | High. Do not skip or weaken. |
| `tools/` | Measurement and utility scripts. | Medium. |
| `experiments/` | Sealed semantic references and the selected BL-PQ512 proof prototype. Standalone RISC Zero and Stwo backends are retired and removed. | Medium to high. |
| `experiments/fixed_shape_claim_air/claim_truth_reference.py` | Fixed-length synthetic claim/oracle/policy/ruleset records and fail-closed governed dual-root comparison. Not an AIR or verifier. | High for Wave 1A reference semantics. |
| `experiments/fixed_shape_claim_air/authenticated_payment_reference.py` | Synthetic aggregate payment state and fixed per-slot operation-log transition. Not the future per-member/provider authenticated maps. | High for money/state semantics. |
| `experiments/fixed_shape_claim_air/wave1a_relation_reference.py` | Composed K128 host relation over governed paths, A12-derived authoritative wide keys, cursor-authenticated depth-64 replay transitions, payment state, projected 12-field compatibility ABI, and wide commitments. It is not itself an AIR. | High; never promote its REFERENCE domains or `physical_air_constrained=false` boundary. |
| `experiments/fixed_shape_claim_air/physical_air_reference.py` | Historical R33 16-table metadata/inventory estimator. It recomputes the host relation but contains no trace cells or polynomial constraints and reports `physical_relation_constrained=false`. | Audit history only; never use its declared dimensions as theorem or performance inputs. |
| `experiments/fixed_shape_claim_air/executable_air.py` and `*_executable_air.py` | Sealed nonactivating current Wave 1 (historical Wave 1A) executable M31 relation: exact source arrays/tree, oracle/policy/ruleset commitments, dual-PQ truth authority, A12, salt-use, replay, payment keys/maps/log, economic arithmetic, authoritative master commitments, public projections, 55,776-message global boundary gate, and a canonical segmented SHA3 schedule. | Soundness-critical Wave 1 terminal. It is not a proof system, durable state, production verifier, or activation surface; current Wave 2 must consume the exact schedule and component traces. |
| `experiments/fixed_shape_claim_air/wave1a_global_sha3_schedule.py`, `master_inputs_adapter.py`, `wave1a_global_executable_air.py`, and `experiments/bl_pq512_crypto_core/src/wave1a_global_schedule.rs` | Exact K128/K256/K512 global SHA3 call order, narrow component-to-master adapter, and named cross-component lookup boundaries. K128 is 46,858 calls in six contiguous segments with a cross-language SHA3-512 commitment. | High; changing order/count/domain/adapter fields changes the proved statement and requires full Wave 1A reseal. |
| `experiments/bl_pq512_crypto_core/src/payment_log.rs` and `src/bin/payment_log_stream.rs` | Exact streamed v3 payment-operation/v2 log SHA3 schedule, strict binary cross-language harness, count/commitment report, and tamper rejection. It avoids owned full-profile Python Keccak traces. | Soundness-critical Wave 1A substrate globally bound through the canonical segmented schedule; it grants no proof-throughput, durable-state, or activation claim. |
| `experiments/bl_pq512_crypto_foundation/claim_source_commitment.py`, `experiments/fixed_shape_claim_air/claim_source_encoding_executable_air.py`, `experiments/fixed_shape_claim_air/claim_source_arrays_executable_air.py`, and `experiments/bl_pq512_crypto_core/src/claim_source.rs` | Reversible 5,648-byte compact claim-source encoding, degree-2 rank/scalar/diagnosis/service AIR, slot-ordered dense SHA3 tree, membership verifier, and bounded Rust full-profile trace stream. The legacy 8,525-byte generic reference encoding remains unchanged. | Soundness-critical nonactivating Wave 1A component; its hashes and dual-PQ authority are globally bound. Durable source registries remain Wave 1C/adapter work. |
| `experiments/fixed_shape_claim_air/oracle_bundle_encoding_executable_air.py`, `experiments/bl_pq512_crypto_core/src/oracle_bundle.rs`, and `experiments/bl_pq512_crypto_core/src/bin/oracle_stream.rs` | Degree-2 packed-oracle encoding AIR for the complete four-byte slot, six facts, 150 authorization flags, canonical padding, exact 42-byte token-rank links, and a bounded Rust execution-hash stream. | Soundness-critical nonactivating Wave 1A component; execution/audit roots and dual-PQ signer/epoch authority are globally bound. Live provider operations remain adapter work. |
| `experiments/fixed_shape_claim_air/claim_oracle_executable_air.py` | Degree-2 claim/oracle composition binding real-state, six facts, and all 50 authorization rows to adjudication semantics. | Claim-semantics bridge, streamed SHA3 roots, and dual-PQ signer/epoch authority are bound at the sealed Wave 1A boundary; live provider operations remain adapter work. |
| `experiments/fixed_shape_claim_air/authenticated_replay_state_reference.py` | Depth-64 ordered replay-state wrapper authenticating `nextAppendIndex` and enforcing exact sequential allocation. | High for replay determinism; synthetic reference only. |
| `experiments/fixed_shape_claim_air/ordered_map_reference.py`, `ordered_map_batch_reference.py`, `ordered_map_batch_executable_air.py`, and `authenticated_payment_maps_reference.py` | Compact depth-64 maps retaining full 512-bit keys/values, insert-only authenticated allocation, nonallocating dummy updates, fixed four-operation slot economics, endpoint multiproofs, sorted sequential-memory AIR, exact fixed hash ports, and a governed 24-bit privacy envelope. | High for state soundness and throughput; Wave 1A global composition is sealed, while durable sharding and rollback/migration proofs remain Wave 1C work. |
| `experiments/fixed_shape_claim_air/witness_schema_reference.py` | Executable v0 witness-schema subset plus noncryptographic relational decoder. It explicitly leaves leaf/path/proof/payment authentication false. | High for parser semantics. |
| `experiments/bl_pq512_crypto_foundation/` | Nonactivating Python references for the frozen Fp16 algebra, interactive public coin, exact software PQ adapters, bounded retry/quarantine governance, and strict proof-body framing. | Trust-critical protocol reference; preserve domain framing, caps, and fail-closed boundaries. |
| `experiments/bl_pq512_crypto_core/` | `no_std` Rust strict-PQ substrate and active nonactivating proof engine: Fp16, SHA3-512 Merkle commitments, authenticated public-coin integration, OODS/DEEP/Circle-FRI, native mask plumbing, streamed oracle storage, bounded proof grammar, and independent verification. | Soundness-critical current Wave 2 implementation. The kernel proof is real; complete K128 proving, simulator/leakage convergence, final parameters, suite identity, and activation remain open. |
| `experiments/bl_pq512_crypto_core/src/proof_format.rs`, `fri_pipeline.rs`, `disk_fri.rs`, and `resource_preflight.rs` | Current v1 proof grammar, per-query pair openings, memory/disk FRI paths, and verifier-derived monolithic/scratch resource estimator. | Highest-risk Wave 2 throughput boundary. Grammar/storage changes require a new version, canonical multiproof reconstruction, exact byte attribution, independent verifier tests, and unchanged theorem/query semantics. |
| `docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` | Authoritative current Wave 2 shared-bus Boolean GKR architecture, exact K128/K512 geometry, hiding/PCS boundary, verifier order, resources, and H4 evidence. | H4 is prototype-accepted; Gate 2E, H5, H6, suite identity, and activation remain open. |
| `docs/history/` | Verbatim former roadmap, throughput, coprocessor, and crate-README checkpoint narratives. | Non-executable provenance only; active work must not follow imperative language from this directory. |
| `docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md` | Cross-wave contract for CBAM, state-topology bake-off, conflict-DAG scheduling, proof-carrying adapters, formal spine, and maturity-gated Ethereum alignment. | Prospective work allocation. It adds no package, changes no status, and makes no measured speed or activation claim. |
| `docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md` | Complete live Strawmap snapshot: all 23 linked EIPs, every non-EIP planned through-line, maturity rules, compulsory based-validity invariants, and exact R01-R12 acceptance work. | Current outer-chain compatibility contract. It adds no package or completion credit and never turns a draft into a release dependency. |
| `docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md` | Mandatory Wave 2 gate for persistent sparse memory, transparent dictionaries, touched-projection RAM, compact memory consistency, and native-hiding PQ commitment selection against the existing SHA3-512 control. | Trust-critical prospective architecture. It selects no primitive by documentation and requires exact theorem, migration, independent-verifier, and laptop evidence. |
| `CONTINUATION_MANDATE.md` | Mandatory post-compaction persistence, product-ideology, recovery, download, evidence, and legitimate-hard-stop instructions. | Read immediately after `AGENTS.md`; it never authorizes weakening a gate or bypassing higher-priority instructions. |
| `docs/REJECTED_ARCHITECTURES.md` | Non-executable ledger for removed or dominated proof backends, layouts, formats, and optimizations. | Preserve exact identities and rejection reasons; never treat it as a fallback catalog. |
| `ops/` | App-layer compatibility mirror of the sibling `../ops` policy/verifier artifacts. | High for deployment integrity. Keep mirrored. |
| `../ops/` | Canonical operational artifacts used by code paths that resolve from the app layer to a sibling ops directory. | High for deployment integrity. |
| `../third_party/forge-std/` | Vendored Forge standard library. | Low unless changing Solidity test toolchain. |
| `docs/` | Architecture and operating docs. | Low to medium. Keep aligned with code. |

The architectural source of truth is `docs/BASED_ZK_ROLLUP_ARCHITECTURE.md`. Read it and
`docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md` before editing proof, verifier,
settlement, sequencing, data availability, bridge, privacy, Ethereum compatibility, or finality
behavior.

The claim proof's selected witness-hiding and strict post-quantum profile is maintained in
`docs/PQ_ZK_SECURITY_ARCHITECTURE.md`. It preserves the 12-field external application ABI while
making authenticated SHA3-512 proof/verifier state authoritative. It is a selected design, not an
implemented or audited production system.

The ordered implementation status, remaining phases, and next-run acceptance gates are maintained
in `docs/IMPLEMENTATION_ROADMAP.md`.

The active strict-PQ proof/resource diagnosis, accepted optimization order, rejected shortcuts, and
Wave 2A-2F gates are maintained in `docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md`.
The selected implementation priority and H0-H6 qualification contract are maintained in
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`.
The frontier and committed-state addenda are folded into those gates and existing Waves 3-6. Gate
2F is the complete latency-proof gate inside Wave 2, not a seventh engineering wave.

The build/audit/activation boundary is maintained in
`docs/DEPLOYMENT_READY_BUILD_CONTRACT.md`. The counted roadmap includes the 73 claim/PQ/operations
packages, I01-I08 government/oracle adapters, and R01-R12 containing-rollup packages: 93 internal
packages total. Independent audit work is one separate, uncounted gate.

Current proving optimization policy is in `docs/PROVING_OPTIMIZATION_REVIEW.md`; verbatim former
measurements and paper screens are under `docs/history/`. The throughput-recovery plan controls
current measured work.

## Source organization rule

The app-layer root is not the archive root. Engineers and agents should enter `blind-ledger-app-layer/` first, then run tests and tools there. Sibling directories exist only for path compatibility and external tool dependencies.
