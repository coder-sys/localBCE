# BL-PQ512 committed sparse-state and PQ commitment plan

Updated: 2026-08-01

Status: mandatory Wave 2 research, implementation, and selection gate. This document does not
select or activate a proof suite or state layout. `proofSuiteId` remains null, production use is
forbidden, and real PHI or payment credentials remain forbidden.

Current evidence boundary: read the newest dated section of `../STATE.md`; the original transfer
record is `../WAVE2_HANDOFF_2026-07-26.md`. The H4 GPU/GKR/Construction 8.2 prototype now passes one
K128 and one four-shard K512 attempt through independent verification, but it does not qualify,
replace, or close this state-selection gate. The historical 782/706 controls were not canonical
state derivations. Every candidate's semantic-equivalence, fixed-shape leakage, atomic CAS,
equivocation, rollback, reorganization, recovery, migration, and 256-bit security/encryption
composition obligations below remain open. H5 must run only after this gate selects and binds the
state plane used by the candidate being qualified.

Execution authority: the deterministic continuation contract near the top of
`IMPLEMENTATION_ROADMAP.md` defines the exact 2E-0 through 2E-7 sequence, finalist measurement
boundary, H5 separation, terminal handoff, and STOP rules. S0/2E-0 is now frozen with exact
K128/K512 fixture identities, independent negative controls, and fresh-process state-only and
 complete-boundary measurements. S1/2E-1 bounded interfaces is also frozen and tested. S2/2E-2
scalar C1-C4 controls are now implemented and parity-tested; S3/2E-3 reference commitment screening
is complete with no backend admitted; S4/2E-4 through S7/2E-7 reference boundaries and the
terminal composition/simulator/leakage/state-proof receipt ledger are now implemented, tested, and
still unsealed. The immediate work is reviewed state/commitment admission and atomic H4 binding,
not another paper benchmark; scalar work counters and reference-ledger timing are not throughput
or selection evidence.

## 1. Decision

Replay and payment state account for 46,208 of K128's 46,858 SHA3 calls, or 98.61%. The existing
depth-64 SHA3-512 endpoint-multiproof and sorted-memory construction remains the correctness and
differential control, but it is no longer the only implementation candidate.

Wave 2 must build and measure a committed sparse-state path that proves one fixed-shape batch
transition over only the touched replay/payment cells instead of proving the current authenticated
tree work as the release topology. The candidate combines a public-coin persistent-memory or
dictionary relation with a transparent, native-hiding, post-quantum commitment/compression layer.
It advances only if the complete construction satisfies every Blind Ledger hard gate and beats the
control on the frozen end-to-end benchmark. If no candidate passes, the control remains selected
and the rejection evidence becomes part of the audit packet.

This is an internal build obligation, not a dependency on paper authors, an outside engineer, an
external prover, or a future upstream release.

## 2. Frozen invariants

Every candidate must preserve:

- the sealed Wave 1 claim, replay, payment, money, approval/denial/cover, and attempt-identity
  semantics;
- fixed K128/K512 shape, dummy work, canonical ordering, exact full-width keys and values, and
  sequential equivalence for conflicting operations;
- the exact ordered 12-field external ABI and the non-PHI public boundary;
- one atomic old-state to new-state proof, with no host-trusted membership, absence, uniqueness,
  index assignment, update, root equality, or commitment equality;
- full native hiding for the state commitment, openings, memory argument, bridge, transcript, and
  all abort/retry artifacts;
- Blind Ledger's authenticated interactive public coin, with zero launch Fiat--Shamir/QROM or
  grinding credit;
- at least 256 bits of cryptographic security/encryption strength for each theorem/error-ledger term
  and after composition;
- no RSA, ECC, pairings, KZG, IPA, trusted setup, designated verifier, external proving service, or
  cached-witness/cached-proof qualification shortcut; and
- reproducible scalar and optimized implementations, canonical bounded grammar, independent
  verification, modular replacement boundaries, and complete audit evidence.

The public authoritative state identifier remains SHA3-512. A non-Merkle state commitment may be
published only through a new versioned schema/profile that hashes a domain-separated canonical
tuple containing the commitment bytes, state epoch, capacity, layout identifier, and parameter
identity. The proof must establish that the committed sparse state is exactly the state produced by
the sealed relation. The existing tree-root grammar cannot be silently reinterpreted, and migration
requires old/new equivalence, rollback, reorganization, and recovery proofs.

## 3. Required candidates

### C0 - existing control

Retain the current SHA3-512 endpoint multiproof, sorted access memory, shared hash bus, and masked
Fp16 Boolean-GKR coprocessor. This is the semantic and differential control, not an assumed winner.

### C1 - persistent sparse-memory argument

Implement the public-coin algebraic memory layer from the volatile/persistent-memory line without
its Pedersen, pairing, Groth, bellman, or Fiat--Shamir compressor. Prove touched-cell membership or
absence, read consistency, write consistency, uniqueness, disjointness, and the final state
transition in one padded batch. Evaluate both dense-capacity and sparse-capacity variants.

The published isolated speedups of up to 51.3x and the sparse estimate of up to 143x are research
motivation only. The same work reports only up to 2.55x in its example rollup because other work
dominates. Blind Ledger receives no percentage credit before its own complete benchmark.

### C2 - transparent dictionary relation

Adapt the generic Index/Value polynomial separation, append-only index invariant, value consistency,
and zero-check/sumcheck structure from IRONDICT. Replace its BN254/KZH, Schnorr VRF, structured
reference string, random-oracle proof, and large-server assumptions. Collision handling, label
uniqueness, absence, index stability, size leakage, and adversarial probing must be proved under the
Blind Ledger fixed-shape privacy model.

IRONDICT's 35 ms verification and 8 kB proof headlines are not Blind Ledger performance evidence:
its server measurements used 144 CPU cores and 1,116 GB RAM, and its billion-entry update epoch was
approximately 15 minutes.

### C3 - touched-projection RAM fallback

Prototype projection-code and batching-efficient RAM only far enough to determine whether the
touched-subdatabase technique can compose with the selected Blind Ledger commitment layer. Reject
the published KZG implementation. Treat the projection-code construction's approximately quadratic
online prover work as a hard risk to measure, not an acceptable hidden cost.

### C4 - compact memory-consistency relation

Evaluate the public-coin arithmetic relation from Two Shuffles Make a RAM as a replacement for the
memory-consistency subrelation. Do not import its concrete VOLE/two-party backend. Account explicitly
for its `O(n)` initialization/teardown and reject it for persistent global state unless the selected
persistent commitment removes that scan without weakening soundness.

## 4. PQ commitment and compression bake-off

The state relation and commitment backend are separate modules. Wave 2 must implement a common
interface and compare at least:

1. **Jindo-style lattice PCS:** leading evaluation-hiding experiment because it supports multilinear
   polynomials, diverse fields, sublinear masking, and batched evaluation. Its recent preprint,
   license, assumptions, parameters, and interactive composition require independent review.
2. **Grand Danois/Hachi-style Module-SIS PCS:** succinct alternatives requiring exact M31/Fp16
   mapping, hiding, update, grammar, and concrete-parameter evidence. Paper proof sizes are not
   qualification evidence.
3. **RoKoko-style lattice argument:** a tensor/sumcheck performance control. It cannot advance
   unless native hiding and a complete zero-knowledge composition are supplied; its AVX-512-oriented
   measurements are not reference-laptop evidence.
4. **Transparent hash/code fallback:** retain a black-box symmetric or code-based path when it is
   the only construction with a defensible strict-PQ theorem, even if it loses the initial speed
   comparison.

No construction is accepted merely because it is called lattice-based or post-quantum. The review
must address quantum oblivious-LWE sampling results, knowledge soundness, extraction, adaptive
openings, binding under updates, hiding, rejection sampling, aborts, retries, multi-target loss,
parameter generation, and implementation side channels. Unsupported standard-model assumptions
fail closed.

## 5. Wave 2 execution stages

1. **S0 - exact control record (complete).** Freeze the same K128/K512 state fixtures, access manifests,
   conflict order, old/new roots, call counts, machine identity, and complete timing boundary.
2. **S1 - common state interface (complete).** Define canonical state-layout, commitment, opening, update,
   migration, and independent-verifier interfaces with bounded byte grammars and domain tags.
3. **S2 - relation prototypes (complete).** Implement C1 dense/sparse, C2, C3, and C4 as
   independently testable scalar references and prove parity with C0 on membership, absence,
   duplicate, collision, conflicting update, denial, cover, transactional nonmutation, and
   malformed-state corpora.
4. **S3 - commitment prototypes (reference screening complete).** The common fixed-width commitment
   interface, exact descriptor identities, dual-PQ authenticated-public-coin round, and independent
   verifier are implemented in `pq_commitment_screening.py`. Five descriptors are screened. The
   three lattice families lack pinned construction evidence, the retired hash-pad control fails its
   public-coin/quantum review, and the clean-room `TRANSPARENT_SHAKE256_1024` candidate is rejected
   only for missing complete H4 composition. All five remain rejected; no backend is admitted or
   selected.
5. **S4 - atomic composition (reference complete).** `atomic_state_composition.py` independently
   replays the scalar relation, binds the S3 authenticated opening to the fixed projection and BLTR
   transition, hashes private relation material in the canonical payload, and constructs an
   independent-verifier receipt. The H4 identity is deferred; no relation or commitment backend is
   admitted, selected, or activated. Its focused and attack tests pass 6/6.
6. **S5 - migration and operations (reference complete).** `state_migration_recovery.py` provides
   immutable checkpoints, independently verified S4 publication, store-owned pending CAS records,
   reference root/manifest equivalence, versioned layout/parameter/verifier rotation, and strictly
   newer-epoch rollback/recovery. Corrupted, stale, downgraded, partial, replayed, and mixed-profile
   cases fail closed; the 10-test focused/attack suite passes. This is not a production migration
   theorem or durable custody result.
7. **S6 - exact bake-off (reference boundary complete).** `gate_2e_selection.py` repeats the
   identical synthetic S2/S3/S4 component twice for each of the five screened backends and K128/K512
   profiles, with independent verification, observed timing labels, derived work labels, and no
   proof/complete-boundary credit. All five S3 screens reject, so no finalist receives a complete
   warm-up or externally monitored complete proof.
8. **S7 - selection/handoff (reference boundary complete).** The selector recomputes every rejection,
   retains C0 as an unselected control with no timing credit, and emits an explicitly unsealed
   handoff. `selected_backend_id=null`, `proofSuiteId=null`, and activation is false. Tracked
   `ops/` authority is verified; the former sibling-layout blocker is closed. A production state
   plane is not selected until a reviewed backend and complete H4 binding exist.

The smallest nonactivating state boundary is implemented separately in
`experiments/bl_pq512_crypto_foundation/state_plane.py`. It provides fixed-shape SHA3-512 roots,
all-slot replay, a pad-masked commitment, independent verification, and crash-safe file CAS. The
native H4 coordinator consumes the version-2 compatibility envelope and now also consumes a
version-3 `BLSB01`/`BLSA02` envelope from `state_air_proof.py`. Version 3 contains a compact packed
state-transition AIR, a private streamed dual-PQ FRI package, and a fixed evidence record; Rust
independently evaluates it, compares every packed trace column with the exact operations, verifies
the FRI package, and binds the component into the v3 parent, authenticated interactive
session/schedule, exact child grammar, and atomic receipt. The full
`state_plane_executable_air.py` remains the version-2 compatibility path; the compact path keeps
SHA3 roots on H4's authenticated bus rather than duplicating their Boolean traces. This is still
component/prerequisite evidence only: the current hash-pad review rejects Gate 2E admission, no
reviewed PQ backend or full proof-native H4 PCS/ZK composition is available, and the
simulator/leakage ledger remains open. `proofSuiteId` and activation remain closed.

The next admission boundary is explicit:

Complete the remaining admission obligations before selecting the state plane: a reviewed backend,
full proof-native H4 GKR/PCS composition, simulator, leakage, and state-receipt/security closure.
The v3 component is the native verifier boundary needed for that work; it is not itself backend
selection or Gate 2E closure.

### Current state-bus prerequisite

The native H4 seam now has a versioned, proof-native source boundary without changing the accepted
state-free profile. `BLHBSN02`/version 2 snapshots and `BLHBB102`/version 2 B16 boundaries append
exactly two state-root SHA3 calls to the authenticated bus. Their fixed capacity is
`claim_slots*137+512`: 18,048 for K128 and 70,656 for K512, adding 266 and 1,040 live
permutations. The resulting live permutation totals are 113,996 and 412,446. Rust independently
checks the two root-call input/output patterns before child proof creation, and the worker derives
the totals from the descriptor rather than a duplicated profile constant. The original
`BLHBSN01`/`BLHBB101` bytes and descriptor commitment remain unchanged for the state-free profile.

This seam proves that state roots enter the authenticated source/child boundary. Together with the
v3 compact state-AIR/FRI component it provides native state-file composition evidence, but it does
not yet put the complete state relation inside the custom H4 GKR/PCS proof, select a qualified
backend, or produce a new manifest-bound H4 K128/K512 proof. H5 remains blocked.

The new isolated candidate is `TRANSPARENT_SHAKE256_1024`,
`BL-PQ512-TRANSPARENT-SHAKE256-1024-V1`: SHAKE256-1024 with a 128-byte mask and 128-byte
commitment, committed before the later authenticated coin. Its conservative ledger is 341-bit
quantum collision, 32-bit multi-target loss, 309-bit effective binding, and 480-bit effective
hiding. It is a reviewed reference candidate but remains rejected solely for missing complete H4
composition; no `proofSuiteId` is assigned.

## 6. Acceptance gates

## 6.1 Current S2 evidence boundary

The scalar controls pass both frozen synthetic profiles with the same candidate-independent
semantic digest and C0 boundary: four lane geometries, fixed two-access rows per operation,
membership and absence, sequential cursor behavior, changed state/update identities, the
representative approved/duplicate/conflict/denial/cover/correction outcomes, and 80 cents of
plan/debit/credit totals. The seven C0 negative classes reject for every C1/C2/C3/C4 control,
including C1 dense and C1 sparse. The parity record identity is
`fc99b31b333a6ec3a19cc55099bd612dcd1d7964115301bbcb9d512d8efe184bc320f04af65f3aa8417bf03fe368e05dddc1d2bd7fd2b2005280e777f0d496c4`.

The C1 dense full-capacity scan, C3 touched-projection quadratic online counter, and C4
initialization/persistent-scan counter are derived scalar risk labels. They are not measurements,
commitment evidence, proof evidence, or candidate-selection credit. Candidate-specific roots are
not host-compared to C0 roots; atomic root binding is deferred to S4. No commitment backend,
native-hiding simulator, migration proof, H4 composition, `proofSuiteId`, or activation decision
is closed by S2.

The selected candidate must:

- produce exactly the same accepted/denied/cover outcomes, economic transition, replay behavior,
  and ordered 12-field values as the sealed relation;
- reject forged membership, forged absence, duplicate labels, duplicate nullifiers, inconsistent
  indices, stale reads, write omission/reordering, commitment equivocation, root substitution,
  migration rollback, transcript splicing, and malformed encodings;
- prove a complete native-hiding simulator for public coin, retries, aborts, retained artifacts, and
  cross-module openings;
- pass the exact 256-bit strict-PQ security/encryption ledger with no unreviewed assumption or external
  classical authority on a Blind Ledger-controlled boundary;
- remain at or below 5,000,000,000 peak resident bytes and strictly below 5,000,000,000 scratch
  bytes without swap on the reference Dell G15; and
- complete at least one fresh K128/100-live and K512/500-live finalist proof below the 30/180-second
  gates before selection, then pass H5's separate one-warm-up-plus-ten campaign under the frozen
  full-boundary method before qualification.

Failure of a paper number, asymptotic claim, microbenchmark, or isolated state proof to meet these
conditions is a normal candidate rejection, not permission to relax a gate.

## 6.2 Terminal Gate 2E evidence ledger

`experiments/bl_pq512_crypto_foundation/gate_2e_terminal_ledger.py` now provides the bounded
terminal evidence record for the current synthetic references. It replays S4, derives S5
checkpoints, verifies both C0 profile shapes and all seven C0 negative classes, checks the fixed
12-field/public-private boundary, and recomputes S6/S7 selection and handoff identities. The
11-record ledger remains reference-only and unsealed with
`status=UNSEALED_BLOCKED_GATE_2E_TERMINAL_LEDGER`. When supplied, it records the new state-plane
identity as `STATE_PLANE_IMPLEMENTED_H4_PENDING`; the default preflight remains
`STATE_PLANE_NOT_PROVIDED`. The ledger does not admit a relation or PQ commitment, close the
complete simulator or leakage scan, establish state constraints inside H4, qualify H5, assign
`proofSuiteId`, or authorize activation. The separate tracked-ops authority is verified.

The hash-pad review at `docs/BL_PQ512_HASH_PAD_COMMITMENT_SECURITY_REVIEW.md` is an explicit
rejection record, not selection evidence. It credits only the exact one-time-pad condition for
ciphertext hiding and the independently replayed reference opening. It gives no generic SHA3
collision, QROM, Fiat-Shamir, grinding, or unfrozen public-coin-order credit.

When a reviewed candidate is eventually admitted, the resulting decision has the following
meaning: This selects the Gate 2E candidate; it is not H5 qualification. The admission handoff
must:

Close the remaining admission work by selecting a reviewed state/commitment backend and completing
the proof-native H4 PCS/ZK composition, simulator/leakage ledger, and qualification evidence. The
native executable-AIR consumption, exact-witness v3 FRI composition, and canonical-envelope seams
above are necessary prerequisite/component evidence, not admission or H5 credit.

## 6.3 H5 qualification preflight

`experiments/bl_pq512_crypto_foundation/h5_qualification_preflight.py` is the current bounded
H5 boundary while admission is absent. It independently replays the terminal ledger, validates
the reference hardware record, verifies the one tracked commit-bound `ops/` authority, and freezes
one uncounted warm-up plus ten unique measured launches for each
profile. The total is exactly 22 fresh launches. Cached proofs, cached witnesses, automatic retry,
partial-campaign substitution, CUDA launch, `proofSuiteId`, and activation remain forbidden.

The current record is:

```text
status=BLOCKED_H5_PREFLIGHT
preflight_digest_sha3_512=5c6a04878f8268dfd4fb33b3583fd27f0aff8624f90f720a9f6b45fb8dff849538ee7aac6ea3d36d72971d1223bf595c9cec0d35f3230705047518c5741432e1
canonical_ops_status=VERIFIED_TRACKED_SHA3_512_AUTHORITY
reference_hardware_status=READY
fresh_launch_count=22
proofSuiteId=None
activation_allowed=False
```

It remains blocked by the unsealed/unselected Gate 2E state, deferred H4 binding, incomplete
simulator/leakage/strict-PQ evidence, absent external monitoring, absent source readback, and no
complete-proof campaign. The preflight suite
passed 6 tests in 44.60 seconds; no H5 measurement credit is claimed. The recorded disk reserve
is 15,000 ppm (1.5%), requiring 7,310,026,937 free bytes; the immutable 5,000,000,000-byte
RSS/scratch and zero-swap gates remain unchanged.

## 6.4 H6 qualification preflight

`experiments/bl_pq512_crypto_foundation/h6_qualification_preflight.py` now replays the blocked H5
and terminal Gate 2E context and independently reads
`docs/bl_pq512_suite_candidate_v1.json`. It requires the candidate registry to remain
`CANDIDATE_UNQUALIFIED`, with eight null module identities, null `proofSuiteId`, and activation
disabled. It emits exactly twelve H6 obligation records: five `BLOCKED`, five `OPEN`, and two
`REFERENCE_ONLY`, with 22 distinct blockers. No record may be closed by this preflight.

Current raw record:

```text
status=BLOCKED_H6_PREFLIGHT
h5_preflight_digest_sha3_512=5c6a04878f8268dfd4fb33b3583fd27f0aff8624f90f720a9f6b45fb8dff849538ee7aac6ea3d36d72971d1223bf595c9cec0d35f3230705047518c5741432e1
suite_registry_digest_sha3_512=307439093721aeaa9a70ef00d546f06af5f50b73781f9f19b8b02cca8c3d36ee1ef36e9981d49a59d10d8d7768fec079d40e05b6c008d7913c9caf4cc52cf974
suite_registry_canonical_digest_sha3_512=d082aaec00392f6ae7c7c37a52b6b18ab0fccd5fb08654ec9e326d8c20dd355e13f02b240577823f18b06f50aa165d25f5479d2ba1067beb80dd20ab9d6724e0
preflight_digest_sha3_512=aaadf06e7416be5d20fb35b815fff3ccf419c1689e03dfb0a5ec62f0c2cedc89e0dd2856a11096f0225a9799fc61e25642656f679e9dd179126d8c6df66cae5c
proofSuiteId=None
activation_allowed=False
```

Focused and containing verification:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_h6_qualification_preflight.py tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py
6 passed in 30.02s

py -3.14 -m pytest -q tests/test_bl_pq512_state_interface.py tests/attacks/test_bl_pq512_state_interface_attacks.py tests/test_bl_pq512_scalar_state_relation_controls.py tests/attacks/test_bl_pq512_scalar_state_relation_controls_attacks.py tests/test_bl_pq512_pq_commitment_screening.py tests/attacks/test_bl_pq512_pq_commitment_screening_attacks.py tests/test_bl_pq512_atomic_state_composition.py tests/attacks/test_bl_pq512_atomic_state_composition_attacks.py tests/test_bl_pq512_state_migration_recovery.py tests/attacks/test_bl_pq512_state_migration_recovery_attacks.py tests/test_bl_pq512_gate_2e_selection.py tests/attacks/test_bl_pq512_gate_2e_selection_attacks.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py tests/test_bl_pq512_h5_qualification_preflight.py tests/attacks/test_bl_pq512_h5_qualification_preflight_attacks.py tests/test_bl_pq512_h6_qualification_preflight.py tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py
85 passed in 151.88s (0:02:31)
```

This is H6 evidence-boundary scaffolding, not theorem, simulator, attack, reproducibility,
resource, qualification, state-admission, H5, or activation evidence.

## 7. Primary research record

- Persistent/volatile memory AIPs: https://eprint.iacr.org/2024/979.pdf
- Two Shuffles Make a RAM: https://www.usenix.org/system/files/usenixsecurity24-yang-yibin.pdf
- Projection-code and black-box ZK RAM: https://escholarship.org/content/qt9405r7n6/qt9405r7n6.pdf
- Batching-efficient RAM: https://eprint.iacr.org/2024/840.pdf
- IRONDICT: https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_hafezi.pdf
- Jindo: https://eprint.iacr.org/2026/044
- RoKoko: https://eprint.iacr.org/2026/575
- Grand Danois: https://eprint.iacr.org/2026/1196
- Hachi: https://eprint.iacr.org/2026/156
- Quantum oblivious LWE sampling: https://eprint.iacr.org/2024/030
- Lower bound on short accumulator/vector-commitment updates: https://eprint.iacr.org/2025/1558

These sources supply constructions, measurements, and attack questions. None selects a Blind
Ledger primitive, proves its composed theorem, supplies production qualification, or replaces the
final independent audit.
