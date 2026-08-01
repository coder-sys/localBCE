# R25 fixed-shape claim foundation

Status: synthetic-only, nonactivating engineering reference.

Current role: Wave 1 seals this package's executable semantic relation and exact SHA3 schedule.
Wave 2 keeps its physical SHA3 components as differential oracles but proves release hashes through
the shared committed bus and Boolean coprocessor in
`../../docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`. No semantic byte or constraint is weakened.

This isolated package makes provisional fixed-shape claim semantics and logical trace schedules
reviewable. It is not a production AIR, prover, verifier, proof suite, witness-hiding construction,
or post-quantum security claim. It must never process real PHI or advance settlement state.

It implements only:

- provisional K128, K256, and K512 calibration profiles;
- thirteen ordered private-denial predicates;
- original-attempt-only real claims;
- canonical service-line ordering with line_id as the final tie-breaker; and
- identical logical row and state-operation counts for approvals, denials, and covers;
- K256 position/kind/revision alignment between claim slots and the 257-operation replay schedule;
- independently recomputed legacy/SHA3-512 membership paths for fixed claim-source,
  oracle/authorization, sparse policy, and ruleset records;
- a full-width depth-64 indexed replay-tree reference with no legacy replay authority;
- exact A12 real-attempt and cover byte preimages with authoritative SHA3-512 derivations, proved
  nonzero Stark252 compatibility projections, and registry-lifetime pepper-authority binding;
- an authenticated aggregate payment state whose operation root advances for every slot;
- depth-64 ordered benefit, provider-obligation, payer-reserve, and provider-payable maps retaining
  complete 512-bit keys and typed fixed-width 512-bit values;
- one endpoint batch multiproof per map plus a sorted memory chain proving equivalence to the exact
  sequential upsert and duplicate-rejection semantics;
- insert-only allocator consumption, four precommitted non-economic dummy leaves, and a governed
  24-bit shard envelope with fixed worst-case proof/hash dimensions;
- a typed SHA3-512 benefit scope over payer authority, plan, benefit-period bounds, and asset
  registry, embedded in the composite state root and every member-benefit key; and
- a composed K128 host KAT over the exact ordered 12-field ABI and an independent SHA3-512 batch
  commitment.

The provisional host relation derives plan payable as gross allowed minus authenticated synthetic
patient responsibility. The aggregate and map references enforce exact reserve debit, provider
credit, payable conservation, sequence/cursor advancement, unique obligations, scope-stable member
benefits, and one operation-log append per slot. The map-state schema is explicitly v3 after the
depth-64/fixed-value migration. Updates prove the allocator position empty without consuming it;
denial/cover therefore do not create durable throwaway records. Old sparse-map roots and unscoped
member keys are not silently reused.

The payment-state modules freeze strict composite-state bytes, SHA3-512 roots, exact economic
conservation, and ordered operation-log commitments. R34 rejects falsey non-mapping balance inputs
instead of converting them to an empty map, rejects scope subclasses that could override committed
bytes, and binds benefits to one explicit payer/plan/period scope. They remain synthetic in-memory
references, not durable authoritative settlement state.

The host reference authenticates its synthetic claim/oracle/policy/ruleset paths, internally derives
and verifies attempt/cover nullifiers, authenticates the wide replay-tree transition,
aggregate and scoped map payment transitions, ordered 12 compatibility fields, and wide batch commitment.
`nullifier_derivations_authenticated=true` is invariant. The host reference alone still lacks
source/oracle PQ signatures and epochs, authoritative durable state, concrete low-degree hash/PCS
constraints, native hiding, and a selected strict-PQ proof suite; the executable modules below now
constrain the Wave 1A source/oracle authority and low-degree application relation. The historical 16-table
`physical_air_reference.py` object is a declared inventory estimator: it contains metadata and host
recomputation, not trace cells or constraint equations, and now reports
`physical_relation_constrained=false`. This reference supports the A12 semantic freeze but is not
the Wave 1A terminal. The proof, authoritative-state, and production packages remain open.

## R36 executable-AIR repair chronology

The following bullets record the incremental R36 checkpoints. Their open-boundary statements are
historical and are superseded by the 2026-07-21 seal below:

- `executable_air.py` defines explicit M31 cells, derived-degree expression trees, local/boundary/
  transition identities, fixed verifier columns, weighted lookup multisets, canonical program/trace
  commitments, and independent typed/serialized evaluators;
- `stark252_projection_air.py` constrains the exact SHA3-512 integer reduction modulo `p-1`, strict
  remainder bound, nonzero alias, and digest/alias byte links without a second hash lane;
- `a12_nullifier_executable_air.py` constrains the canonical attempt/cover grammar, authority
  pepper commitment, authoritative SHA3-512 nullifier, and compatibility projection;
- `sha3_512_executable_air.py` constrains SHA3-512 padding, absorption, all 24 Keccak rounds, and
  digest-producing state through fixed XOR8/AND-NOT8/SPLIT8 truth tables;
- `application_sha3_executable_air.py` batches all fixed-capacity calls into five physical tables,
  fixes call-index isolation, shares truth/range tables once, and keeps private values out of the
  program commitment;
- `authenticated_replay_state_reference.py` authenticates the depth-64 allocator cursor, and
  `replay_header_executable_air.py` constrains cursor consumption/successor arithmetic, root
  chaining, and exact SHA3-512 state headers;
- `claim_gate_executable_air.py`, `claim_result_executable_air.py`, and
  `claim_semantics_executable_air.py` constrain service aggregation, all 13 gates, cover behavior,
  first-failure selection, claimed results, u32 decomposition, and payment conservation.
- `ordered_map_batch_reference.py` fixes 24-bit shard bounds and exact privacy-padded node, leaf,
  header, SHA3-call, and Keccak-permutation maxima for each operation capacity.
- `ordered_map_batch_executable_air.py` materializes the fixed operation, sorted-memory, endpoint,
  proof, node, header, byte/property, and hash-port tables. It enforces canonical M31 integer
  encodings, rejects sentinel-key updates, removes unused auxiliary freedom, and optionally composes
  every live and dummy port with the exact batched SHA3-512 AIR.
- `authenticated_payment_maps_executable_air.py` namespaces and composes benefit, obligation, and
  ledger batches, shares one byte/property table instead of cloning three, and binds lane endpoint
  states.
- `claim_payment_maps_executable_air.py` links claim results to four authenticated operations per
  slot and constrains class shape, canonical values, checked benefit/reserve/payable arithmetic, and
  service-derived authorization-use accumulation. Key derivations and the global log binding remain
  explicit false boundaries.
- `token_rank_executable_air.py` proves the unique 42-byte identifier rank is below `37^64` and
  enforces required nonempty identifiers once for source, oracle, adapter, and payment consumers;
  required state remains private trace data rather than a verifier-fixed column.
- `claim_source_encoding_executable_air.py` binds all 13,184 K128 identifier ranks to exact compact-
  bundle offsets and constrains fixed/scalar framing, sequence, counts, original-attempt fields, and
  NPI digit/Luhn rules. Array ordering/uniqueness, streamed SHA3 composition, and source-authority
  verification remain explicit false/open boundaries.
- `claim_source_arrays_executable_air.py` reuses the compact bundle table and constrains diagnosis
  grammar/count/strict ordering/uniqueness plus service prefixes/counts/procedure framing, line-ID
  presence, and original-line-index uniqueness. Full service sort, hashes, and authority remain
  explicit false/open boundaries.
- `oracle_bundle_encoding_executable_air.py` binds the full four-byte slot index, six fact bits, all
  150 authorization bits, canonical unused-bit zeros, and 6,400 K128 token ranks to exact 2,133-byte
  bundle offsets. It constrains token presence equivalence and witness-independent program shape;
  claim-semantics, streamed-hash, and PQ signer/epoch composition remain explicit false boundaries.
- `claim_oracle_executable_air.py` composes adjudication with oracle real-state, all six facts, and
  every authorization row. Coherent-but-conflicting standalone oracle traces fail at the bridge;
  streamed-hash and PQ signer/epoch composition remain false/open.

The 2026-07-21 seal completes Wave 1A at its synthetic, nonactivating executable-relation boundary.
Source arrays/tree, oracle/policy/ruleset commitments, dual-PQ truth authority, A12, salt reuse,
replay, payment keys/maps/log, master commitments, public projection, and all named global links are
constrained. `wave1a_global_sha3_schedule.py` fixes one six-segment global call order without cloning
the already evaluated component Keccak traces. K128 has 46,858 calls and the compact global boundary
evaluates 55,776 messages. Wave 1B proof construction, native hiding, durable state, production
verification, and activation remain open.

The v3 payment operation-log preimage commits authenticated keys and before/after values rather
than redundant intermediate Merkle roots. The K128 claim/payment bridge evaluates 30,047,077
identities and 41,373,848 lookup messages at degree three. The exact 256-call K128 log schedule is
streamed in Rust at 1,920 permutations and 46,080 Keccak rows. Owned Python construction exceeded a
300-second bound, so it is not the throughput path. The component-level flag remains honest in that
standalone object; the sealed global relation binds the exact streamed schedule without cloning it.

## R25 measured reference status

The sealed R25 run exercises all five shapes for each of K128, K256, and K512: 15 serial host-model
measurements. It also pins 20 deterministic corpus cases, all 8,191 nonempty combinations of the 13
denial gates, and all 3,840 K256 case/position placements. These are host/reference tests, not proof
or physical-AIR qualification.

Fresh terminal full-capacity host-model totals were `0.7136005s` for K128, `1.3989518s` for K256,
and `2.5877058s` for K512. For the heaviest K512 case, fixture creation was `15.886984%`, logical
trace construction `41.423886%`, payment economics `42.246367%`, and operation logging `0.442763%`;
Python tracemalloc peaked at `5,510,060` bytes. Every record explicitly has
`physical_air_rows=null`, `physical_air_columns=null`, `proofs_generated=0`,
`proof_suite_id=null`, and `activation_allowed=false`. Exact records are in
`cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/stages/06_k128_k256_k512_measurement.json`.
