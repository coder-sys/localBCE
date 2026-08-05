# Wave 1A executable AIR specification

Updated: 2026-07-22

Current roadmap name: **Wave 1 - claim relation and executable AIR**. `Wave 1A` is retained in this
filename and in historical evidence identifiers for traceability. Current Wave 2 is the former
Wave 1B proof work; current Wave 3 is the former Wave 1C verifier/state/custody work.

## 0. Authoritative closure record (2026-07-21)

Wave 1A is complete at its defined nonactivating executable-relation boundary. Later historical
progress notes in this document are retained for audit chronology; any statement that a Wave 1A
component listed below is still open is superseded by this closure record.

The sealed relation includes canonical claim-source arrays and tree, oracle and policy execution
and audit roots, ruleset commitment, dual-family ML-DSA-87 plus SLH-DSA-SHAKE-256f authority and
epoch binding, full-width A12 attempt/cover nullifiers, replay pepper authority, raw-salt reuse
insertion, complete depth-64 replay transitions, three economic maps, exact payment-key and chained
operation-log SHA3, slot/economic conservation, four authoritative master commitments, and the
unchanged 12-field public ABI projected from full 512-bit authorities.

The SHA3 engine is stored as independently executable component segments and consumed in one exact
global order. This avoids cloning millions of Keccak rows into a second Python trace. The physical
SHA3 AIR is the sealed differential specification; Wave 2 may implement the same relation through
the shared-bus Boolean coprocessor without reopening Wave 1 semantics. K128 has
46,858 calls across `(truth, A12, salt, replay, payment, master)` with offsets/counts
`(0,516)`, `(516,129)`, `(645,1)`, `(646,9360)`, `(10006,36848)`, `(46854,4)`.
K256 has 88,198 calls and K512 has 165,762. Python and `no_std` Rust pin the schedule commitment.

Closure evidence: 53/53 selected trust-critical Python tests after focused rerun, 55,776 evaluated
global boundary lookup messages plus targeted replay-root rejection, 78/78 Rust tests, offline Rust
format, and Clippy with warnings denied. The heaviest payment instance evaluates 112,485,087
identities and 220,993,014 lookup messages at degree three. Wave 1 itself still emits no proof and
grants no activation, deployment, production privacy, or durable-state claim. Current Wave 2 owns
the proof engine, native hiding, proof grammar, prover/verifier, final parameter selection, and
proof-level convergence. Its real 28,643,096-byte kernel proof does not yet prove this complete K128
relation or close those gates.

Status: **IMPLEMENTATION SPEC — SYNTHETIC ONLY — NONACTIVATING**

## 1. Purpose

This document replaces the mistaken treatment of
`experiments/fixed_shape_claim_air/physical_air_reference.py` as an AIR. That R33 module is retained
as historical inventory evidence only. The Wave 1A handoff is complete only when the frozen host
semantics are represented by explicit trace cells and independently evaluated low-degree
constraints.

The implementation maximizes, in order of hard gates:

1. correctness, privacy, fail-closed safety, and post-quantum protection on Blind Ledger surfaces;
2. auditability, reproducibility, modularity, and provider-neutral government/oracle integration;
3. end-to-end throughput for fixed batches containing hundreds of claims.

Throughput may remove duplicated computation. It may not remove authenticated information, weaken a
constraint, truncate an identifier, make a schedule decision-dependent, or substitute a host check
for a proof constraint.

## 2. Completion definition

The executable AIR must provide all of the following:

- a canonical serialized program containing every table, column, fixed column, identity, boundary,
  transition, lookup message, public input, and domain identifier;
- concrete trace-cell matrices or deterministic streaming column generators;
- an expression tree whose algebraic degree is computed from the tree rather than declared;
- independent evaluation of all local, boundary, and transition identities;
- independent source/destination multiset evaluation for every lookup or permutation argument;
- exact canonical public binding to the ordered 12-field Privacy V2 boundary;
- exact byte-oriented SHA3-512 constraints and exact nonzero Stark252 compatibility projections;
- constraint-level mutation tests for each semantic family;
- Python/`no_std` Rust program, trace, evaluator, and known-answer parity;
- dimensions measured from the executable program and trace, never copied from R33 metadata;
- `physical_relation_constrained=true` only after all preceding items pass.

No host verifier, digest of a Python object, or successful reference recomputation substitutes for
any item above.

Historical R36 mid-run evidence was deliberately narrower than closure: the M31 kernel, exact
SHA3-512, compact fixed-capacity call batching, A12, Stark252 projection, ordered public bytes,
claim semantics, cursor-authenticated replay host state, and executable replay headers have focused
direct/serialized/mutation coverage. The ordered-map batch component adds fixed operation,
sorted-memory, endpoint, multiproof, node, state-header, shared byte/property, and hash-port tables.
Its uncomposed 8-table program passes 12 focused honest/attack tests; a one-operation, 136-call
instance composes every live and dummy port with exact SHA3 and is separately checked by typed and
serialized evaluators plus a rebalanced-byte dummy-digest attack. The Rust cryptographic substrate
also streams the complete K128 economic SHA3 schedule; this is trace-generation evidence, not proof
throughput. Three economic lanes now share one byte table and are linked to claim economics through
a checked 64-bit bridge; authorization uses are accumulated from fixed service rows. Rust also
streams the exact 128-slot operation-log schedule. At that checkpoint key derivations, replay
paths, governed commitments, global composition, and Rust parity remained open. Section 0 records
their later Wave 1A closure.

The current locked Rust 1.96.0 substrate gate passes 78 unit tests and every binary target,
offline formatting, and strict all-target clippy with warnings denied.

## 3. Fixed external and semantic boundary

The external Privacy V2 ABI remains exactly these ordered `bytes32` fields:

1. `protocolVersion`
2. `settlementDomain`
3. `batchNonce`
4. `nullifierRootBefore`
5. `nullifierRootAfter`
6. `claimSourceRoot`
7. `oracleFactsRoot`
8. `policyRoot`
9. `rulesetRoot`
10. `opaqueBatchCommitment`
11. `valueConservationCommitment`
12. `settlementCommitment`

The A12 real-attempt and cover derivations, first-failure ordering, money bounds, canonical ordering,
wide replay transition, scoped economic keys, and public-field order remain unchanged. Reference
modules are independent semantic oracles and are not edited to force the AIR to pass.

## 4. Minimal table architecture

The implementation uses small, composable tables. A table exists only when it owns a distinct
algebraic or lookup boundary.

| Table | Responsibility |
| --- | --- |
| `slot` | fixed slot kind, enable bits, counts, ordering, gate results, first failure, money, and links |
| `service` | fixed service-line schedule, canonical identifiers, authorization index, and line money |
| `range` | byte and bounded integer decomposition shared by all consumers |
| `sha3` | exact SHA3-512 absorb, padding, Keccak-f[1600] rounds, digest output, and fixed call-index isolation in five shared physical tables |
| `projection` | exact SHA3-512 integer reduction modulo `p-1`, nonzero alias, and byte links |
| `dense_tree` | bottom-up claim and oracle-bundle leaf/internal/root schedule |
| `path64` | full-key ordered replay and economic-map membership/update paths |
| `state` | scoped economic transitions, conservation, operation append, and ordered roots |
| `public` | ordered 12-field binding and wide governance/batch commitments |

Logical views may expose claim, oracle, policy, replay, and payment components without creating
separate physical copies of shared range, hash, or path work.

## 5. Throughput-preserving reductions

### 5.1 Compact claim-source bundle

Each slot has one reversible 5,648-byte bundle. The executable source component proves the exact
identifier-rank offsets, the strict `rank < 37^64` bound, required nonempty ranks, fixed header,
slot/real/cover framing, source-sequence nonzero rule, original-attempt fields, count bounds, NPI
digit grammar, and NPI Luhn check. Required/nonzero token state stays outside verifier-fixed columns
and is linked to real-slot/line semantics. Its current mixed K128 KAT evaluates 1,985,280 degree-2
identities and 4,807,424 lookup messages. Full service-array sort ordering, streamed SHA3-row
composition, and PQ authority/epoch verification remain open; `hashes_constrained=false` and
`source_authority_constrained=false` are therefore mandatory.

The composed source-array component additionally constrains diagnosis grammar, padding, exact count,
strict ordering and uniqueness; service live prefixes/counts, procedure grammar/padding, line-ID
presence, and original-line-index uniqueness. Its mixed K128 KAT evaluates 2,736,707 degree-2
identities and 5,217,246 lookup messages. Full service-line sort order remains false/open because the
existing token ordering must be proved without cloning a second token decoder.

### 5.2 Claim-scoped oracle bundle

Each claim authenticates one fixed 2,133-byte bundle containing the fact record, 50 canonical
authorization tokens, enable flags, and fixed framing. The execution root commits the ordered bundle
leaf; a separate binary audit root reuses the same leaves. A PQ attestation binds both roots, the
profile, snapshot, and epoch.

The executable encoding component constrains the full four-byte slot index, six fact bits, all 150
authorization bits, canonical zero padding in the last flag byte, exact token offsets, and
`authorization present` iff the canonical rank is nonzero. Its mixed K128 KAT evaluates 988,542
degree-2 identities and 2,241,792 lookup messages. Claim-semantics cross-links, streamed SHA3 rows,
and PQ signer/epoch verification remain open; the corresponding false flags are mandatory.

The composed claim/oracle program binds oracle real-state and all six facts to the claim slot, then
binds every fixed authorization row to the matching service row. Its mixed K128 KAT evaluates
1,975,926 degree-2 identities and 2,937,984 lookup messages. Coherent conflicting oracle traces are
rejected specifically at the composition lookup. This closes the claim-semantics cross-link, not
the streamed SHA3 or PQ signer/epoch boundaries.

The exact packed-oracle execution hash schedule separately streams in Rust with Python parity at
K128: 129 calls, 3,954 permutations, and 94,896 Keccak rows. This establishes the bounded throughput
path and exact root/schedule bytes; the streamed rows still need global AIR composition.

This preserves every authorization token and its order while removing 51 independent membership
paths. K128's packed reference schedule falls from the superseded 98,047 estimate to 3,954 oracle
SHA3 permutations. The encoding AIR numbers above are measured, but hash-row integration is not yet
security credit.

### 5.3 One policy authentication per claim

The policy payload already contains all fixed service-line policy entries. The AIR authenticates the
payload once per claim and constrains each enabled service line to the corresponding in-payload
entry. It does not prove 50 identical policy paths.

### 5.4 Bottom-up dense trees

Claim and oracle-bundle trees are constructed once, bottom-up, at their fixed capacity. Membership
links reference those shared nodes. A verifier does not rehash a complete path for every leaf.

### 5.4 Depth-64 append-indexed ordered full-key maps

Replay and economic state use the reviewed linked ordered-map construction, made deterministic at
the AIR boundary. Sparse Merkle positions are sequential 64-bit append indices; each occupied leaf
stores its complete 512-bit key plus the complete successor key and successor index. The zero and
maximum sentinels anchor the list. Non-membership is proved by an authenticated predecessor whose
successor brackets the candidate. Insertion updates that predecessor, proves the allocated leaf was
empty, and writes the new leaf with the old successor.

The state header authenticates `nextAppendIndex`. Every insertion must use that exact index and
increments it without wrapping. An update proves the same allocator position empty but does not
advance it. This closes a determinism gap in the older synthetic reference,
whose host builder allocated sequentially but whose verifier did not authenticate the allocator.
Full 512-bit comparisons, predecessor/successor links, both path indices, empty-slot status, root
chaining, and position collision rejection are constraints. The logical position is 64 bits and
never truncates or replaces the key. The governed physical candidate restricts live positions to a
24-bit shard and constrains the remaining high bits zero. This replaces 512-level key-bit sparse
paths without weakening full-key authentication.

Economic maps authenticate batch endpoints rather than rehashing four full roots for every upsert.
The changed-position set contains every predecessor/target and every consumed allocator index.
Canonical multiproof nodes reconstruct both endpoint roots. A separately sorted memory table binds
each operation's target/allocator access, enforces `after(i)=before(i+1)` for repeated positions, and
binds the first/last access to the authenticated endpoint leaves. This is permitted only because the
reference verifier proves equality with the sequential transition. Replay remains sequential.

Economic denial and cover operations use four scope/domain/epoch-bound zero-valued leaves created
once at shard initialization. They run the same target/allocator path work as economic upserts, but
do not allocate a new leaf or advance the cursor. The operation log still advances per slot. This
removes permanent dummy-state growth without revealing the private selector.

The candidate fixes `mapShardIndexBits=24`, allowing 16,777,214 allocated non-sentinel positions
per shard. Position high bits above that bound are zero, and node/leaf/proof tables pad to the
worst-case frontier. Live selectors and dummy rows are constrained, so key distribution,
approval/denial/cover mix, insertion/update mix, and repeated keys cannot change trace dimensions or
proof size. At K128 the three map lanes have exact fixed maxima of 34,026 node hashes, 2,048
leaf-hash slots, six state headers, 36,080 SHA3-512 calls, and 74,208 Keccak permutations. Durable
rollover/migration remains current Wave 3 state work. Full Wave 1 global/Rust composition is sealed
by Section 0; activation is still forbidden because an authoritative durable state, production
verifier, and production suite identity do not yet exist. The later nonactivating H4/H5/H6 candidate
evidence does not change that boundary.
The Python executable specification now materializes these padded table families and proves exact
SHA3 composition on a bounded fixture; the Rust backend streams all 1,780,992 K128 economic Keccak
round rows without retaining the full Python object graph.

The audit-log operation domain is v3. It commits the four complete keys and four before/after value
pairs already constrained by the batch relation, rather than intermediate Merkle roots that would
require a redundant per-operation tree computation. The authenticated payload remains 768 bytes
per slot. Rust streams the K128 operation/log schedule in 256 calls, 1,920 permutations, and 46,080
Keccak rows. The sealed global bridge binds this exact schedule without duplicating its full owned
Keccak trace in Python.

The fixed-privacy payment-key stream uses governed capacities 203/216/203/203 bytes for benefit,
obligation, reserve, and payable. K128 is exactly 512 calls, 1,664 permutations, and 39,936 Keccak
rows. The sealed global boundary binds every key preimage to authenticated claim-source bytes; the
component-level stream remains independently testable cross-language evidence.

### 5.5 Single production economic relation

The scoped benefit, provider obligation, payer reserve, provider payable, and operation-log relation
is the production AIR boundary. The older aggregate-payment module remains an independent historical
semantic oracle and migration fixture; it is not a second production state transition.

## 6. Constraint rules

- Booleans use `b * (b - 1) = 0`.
- Fixed-count cursors and indices use transition identities and range lookups.
- Integers are reconstructed from bytes with explicit non-wrapping carry constraints.
- Comparisons use bounded difference/borrow witnesses; Python ordering is never trusted.
- First failure is a prefix product over the frozen gate order.
- Approval, denial, and cover have identical row counts, hash calls, path calls, state operations,
  public outputs, and error behavior.
- Disabled values are canonical zeros selected by constrained enable bits.
- Every lookup message is typed and length-framed. Multisets include multiplicity.
- Every hash call binds domain, type, length, position, and full payload.
- Padding rows use a constrained selector and canonical zero state; padding cannot satisfy a live
  lookup or public boundary.

## 7. Cryptographic components

### SHA3-512

The existing byte-oriented reference supplies explicit XOR, AND-NOT, split, rotation, padding, and
round witnesses. Wave 1A adds an independent polynomial/lookup evaluator and connects every
application digest input/output to this component. Host `hashlib` results are KAT oracles only.

### Stark252 compatibility projection

SHA3-512 is the sole authoritative digest. The current one-felt ABI value is exactly
`OS2IP(digest) mod (p-1) + 1`. The AIR constrains the 64-byte integer, fixed-modulus multiplication,
carry chain, strict remainder bound, and nonzero alias bytes. The historical Starknet-Poseidon
adapter is outside the successor proof and has no replay or settlement authority.

### BL-PQ512 proof layer

Current Wave 1 emits concrete measured tables and the exact hash-call schedule. Current Wave 2 keeps
the non-hash tables in the degree-16 M31/Fp16 semantic STARK and binds every hash port through one
committed bus to a Boolean GKR SHA3 coprocessor over Fp16. The sealed SHA3 AIR remains the executable
differential oracle rather than the release PCS layout. The shared bus, native masks, adaptive
simulator, authenticated public coin, atomic verifier, and complete K128 proof must still qualify.
The existing real kernel proof is regression evidence, not the application proof; the rejected
QM31/Blake2s/default S-two suite remains forbidden.

## 8. Acceptance and stop gates

Stop and retain evidence if:

- a reference-valid witness fails without a proved reference defect;
- a mutated semantic value satisfies the AIR;
- a hash, lookup, state, or public value is host-checked but unconstrained;
- Python and Rust evaluator results differ;
- a reduction changes authenticated bytes, key width, ordering, or fixed schedule;
- theorem selection requires a declared or host-recomputation count;
- an unreviewed cryptographic constant or reduction would need to be invented;
- `proofSuiteId`, activation, production use, or real-PHI authorization becomes non-null/true.

Wave 1 closure does not select the proof suite. Wave 2 closure will not authorize activation. The
final independently audited, sealed deployment candidate remains the only activation boundary.
