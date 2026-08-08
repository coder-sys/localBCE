# BL-PQ512 committed sparse-state and PQ commitment plan

Updated: 2026-08-05

Status: mandatory Wave 2 research, implementation, and selection gate. This document does not
select or activate a proof suite or state layout. `proofSuiteId` remains null, production use is
forbidden, and real PHI or payment credentials remain forbidden.

Current evidence boundary in the full workspace: read the newest current-status section of
`../STATE.md`; the original transfer record is `../WAVE2_HANDOFF_2026-07-26.md`. The published
source archive intentionally omits those workspace-only records; archive readers should use the
current architecture documents and `RELEASE_FILE_MANIFEST.json` instead. The H4/GKR/Construction
8.2 candidate context is sealed nonactivating, H5 passed the exact 22-launch campaign, and H6 closed
the twelve bounded candidate-evidence obligations. This plan still governs replaceable production
state-plane work:
no production state layout or suite identity is selected, `proofSuiteId=null`, and real PHI or
payment credentials remain forbidden.

This defines the Gate 2E candidate work and selection boundary; it is not itself a production state
or commitment selection and is not H5 qualification. H5 is separately governed by its exact
repeated complete-proof campaign, and neither boundary selects a production suite or enables
activation.

Execution authority: the deterministic continuation contract near the top of
`IMPLEMENTATION_ROADMAP.md` defines the exact 2E-0 through 2E-7 sequence, finalist measurement
boundary, H5 separation, terminal handoff, and STOP rules. S0/2E-0 is now frozen with exact
K128/K512 fixture identities, independent negative controls, and fresh-process state-only and
 complete-boundary measurements. S1/2E-1 bounded interfaces is also frozen and tested. S2/2E-2
scalar C1-C4 controls are now implemented and parity-tested; S3/2E-3 reference commitment
screening is complete with no production backend admitted; S4/2E-4 through S7/2E-7 reference
boundaries and the terminal composition/simulator/leakage/state-proof receipt ledger are implemented
and tested. The later qualified context seals the nonactivating candidate evidence. The immediate
work is production state/verifier/custody integration, not another paper benchmark; scalar work
counters and reference-ledger timing are not throughput or selection evidence.

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
   public-coin/quantum review, and at the S3 screening boundary the clean-room
   `TRANSPARENT_SHAKE256_1024` candidate was held for missing complete H4 composition. All five
   reject at that boundary; the later qualified context uses the clean-room candidate as
   nonactivating candidate evidence. No production backend is admitted or selected.
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
  proof/complete-boundary credit. All five S3 screens reject at that reference boundary; the later
  qualified context is separately recorded and remains nonactivating.
8. **S7 - selection/handoff (reference boundary complete).** The selector recomputes every rejection,
  retains C0 as an unselected control with no timing credit, and emits an explicitly unsealed
  pre-manifest handoff. `selected_backend_id=null`, `proofSuiteId=null`, and activation is false.
  Tracked `ops/` authority is verified; the former sibling-layout blocker is closed. The later
  qualified candidate context is nonactivating; a production state plane is still not selected.

The smallest nonactivating state boundary is implemented separately in
`experiments/bl_pq512_crypto_foundation/state_plane.py`. It provides fixed-shape SHA3-512 roots,
all-slot replay, a pad-masked commitment, independent verification, and crash-safe file CAS. The
native H4 coordinator consumes the version-2 compatibility envelope and now also consumes a
version-3 `BLSB01`/`BLSA02` envelope from `state_air_proof.py`. Version 3 contains the
`BL-PQ512-STATE-RELATION-AIR-v2` compact packed state-transition AIR, including two fixed-capacity
46-wide operation-to-snapshot lookups, a private streamed dual-PQ FRI package, and a fixed evidence
record; Rust independently evaluates it, compares every packed operation/snapshot column with the
exact witness, verifies the FRI package, and binds the component into the v3 parent, authenticated interactive
session/schedule, exact child grammar, and atomic receipt. The full
`state_plane_executable_air.py` remains the version-2 compatibility path; the compact path keeps
SHA3 roots on H4's authenticated bus rather than duplicating their Boolean traces. This is
component/prerequisite evidence only: the hash-pad candidate remains rejected, while the later
clean-room candidate context is nonactivating. The bounded H6 candidate-evidence manifest closes
the candidate leakage/strict-PQ records; no production PQ backend or state layout is selected.
`proofSuiteId` and activation remain closed.

The next production boundary is explicit:

Select and bind a production state plane only after the later verifier, custody, migration,
resource-telemetry, and release gates are complete. The v3 component is the native verifier
boundary needed for that work; the already qualified H4/H5/H6 candidate evidence is nonactivating
and does not itself authorize production.

The Gate 2E handoff therefore requires:
   Bind the selected state plane into
   the actual H4 parent only after the state, proof, verifier, and settlement identities are
   atomically defined and independently replayable.

### Current state-bus prerequisite

The native H4 seam now has a versioned, proof-native source boundary without changing the accepted
state-free profile. `BLHBSN02`/version 2 snapshots and `BLHBB102`/version 2 B16 boundaries append
exactly two state-root SHA3 calls to the authenticated bus. Their fixed capacity is
`claim_slots*137+512`: 18,048 for K128 and 70,656 for K512, adding 502 and 1,964 live
permutations. The resulting live permutation totals are 114,232 and 413,370. Rust independently
checks the two root-call input/output patterns before child proof creation, and the worker derives
the totals from the descriptor rather than a duplicated profile constant. The original
`BLHBSN01`/`BLHBB101` bytes and descriptor commitment remain unchanged for the state-free profile.

This seam proves that state roots enter the authenticated source/child boundary. Together with the
v3 compact state-AIR/FRI component it provides native state-file composition evidence and an
algebraic ordered operation-to-snapshot equality boundary, but it does not yet put the complete
state relation inside the custom H4 GKR/PCS proof, select a production backend, or produce a new
manifest-bound H4 K128/K512 proof. The exact H5 campaign and bounded H6 evidence are recorded
above; this prerequisite seam receives no additional qualification credit.

The current Rust H4 bridge now carries that state component into the same PCS shape: a fixed
64-wire lane at wire offset 1,600, two boundary-one state-relation claims, twelve square-free state
claims, and two grouped coefficient openings. It produces nineteen fixed claims and exact
6,727/6,995 K128/K512 rounds. The relation now
checks operation/snapshot equality, authenticated slot index/order, Boolean presence, and
empty-slot zeroing; the Rust source builder and native Rust/Python snapshot decoders reject
duplicate present keys before source commitment. Proof-native high-cardinality uniqueness,
membership/absence, and money/state conservation remain open for production state selection and
must pass the later verifier/custody gates.

The new isolated candidate is `TRANSPARENT_SHAKE256_1024`,
`BL-PQ512-TRANSPARENT-SHAKE256-1024-V1`: SHAKE256-1024 with a 128-byte mask and 128-byte
commitment, committed before the later authenticated coin. Its conservative ledger is 341-bit
quantum collision, 32-bit multi-target loss, 309-bit effective binding, and 480-bit effective
hiding. It was rejected at the screening boundary solely for missing complete H4 composition. The
later H4/H5/H6 candidate context records this clean-room path as nonactivating evidence; no
production `proofSuiteId` is assigned.

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

`experiments/bl_pq512_crypto_foundation/gate_2e_terminal_ledger.py` provides both the preserved
pre-campaign reference record and the later qualified nonactivating context. The historical
11-record ledger is retained as
`status=UNSEALED_BLOCKED_GATE_2E_TERMINAL_LEDGER`; it does not represent the current status. The
latest context is `SEALED_GATE_2E_TERMINAL_LEDGER` with the nonactivating state-bound candidate,
independent replay, and no production suite identity. The exact H5 campaign and bounded H6
candidate-evidence manifest are recorded separately below and are closed without activation.
`proofSuiteId` remains null; production verifier/state/custody and release work remain open.
The separate tracked-ops authority is verified.

The hash-pad review at `docs/BL_PQ512_HASH_PAD_COMMITMENT_SECURITY_REVIEW.md` is an explicit
rejection record, not selection evidence. It credits only the exact one-time-pad condition for
ciphertext hiding and the independently replayed reference opening. It gives no generic SHA3
collision, QROM, Fiat-Shamir, grinding, or unfrozen public-coin-order credit.

The qualified context already records the nonactivating candidate boundary; it does not select a
production state/commitment backend or activate a suite. The remaining production boundary is to
complete the verifier/state/custody, migration, resource-telemetry, release, and final-audit work.
The native executable-AIR consumption, exact-witness v3 FRI composition, and canonical-envelope
seams above are prerequisite/component evidence, not a production selection or activation decision.

## 6.3 Current qualification records

The current H5 record is `QUALIFIED_H5_CAMPAIGN_NONACTIVATING`: the exact 22-launch
campaign passed with p95 values of 32.360845 seconds for K128 and 148.861885 seconds for K512.
The current H6 record is `QUALIFIED_H6_NONACTIVATING`: all twelve candidate-evidence
records are closed and its blocker tuple is empty. These records remain nonactivating because the
production verifier, durable state/custody, release identity, and final audit are still open;
`proofSuiteId` remains null.

### Historical H5 qualification preflight (superseded record)

The following pre-manifest record is retained verbatim as historical evidence. At that time,
`experiments/bl_pq512_crypto_foundation/h5_qualification_preflight.py` was the bounded
H5 boundary while admission was absent. It independently replayed the terminal ledger, validated
the reference hardware record, verified the one tracked commit-bound `ops/` authority, and froze
one uncounted warm-up plus ten unique measured launches for each profile. The total was exactly
22 fresh launches. Cached proofs, cached witnesses, automatic retry, partial-campaign substitution,
CUDA launch, `proofSuiteId`, and activation remained forbidden.

The historical record was:

```text
status=BLOCKED_H5_PREFLIGHT
preflight_digest_sha3_512=9c8cd9e4836576487431af85e3c1ae2b458d44580c144ceeda971f500cd9be279910ea88045761f59699d7b67a8520920a17f07b33d173ce9270d0d064d31693
canonical_ops_status=VERIFIED_TRACKED_SHA3_512_AUTHORITY
reference_hardware_status=READY
fresh_launch_count=22
proofSuiteId=None
activation_allowed=False
```

It was blocked by the unsealed/unselected Gate 2E state, deferred H4 binding, incomplete
leakage/strict-PQ evidence, absent external monitoring, absent source readback, and no
complete-proof campaign. The preflight suite passed 6 tests in 44.60 seconds; no H5 measurement
credit was claimed. The recorded disk reserve
is 15,000 ppm (1.5%), requiring 7,310,026,937 free bytes; the immutable 5,000,000,000-byte
RSS/scratch and zero-swap gates remain unchanged.

### Historical H6 qualification preflight (superseded record)

The following pre-manifest record is retained verbatim as historical evidence. At that time,
`experiments/bl_pq512_crypto_foundation/h6_qualification_preflight.py` replayed the blocked H5
and terminal Gate 2E context and independently read
`docs/bl_pq512_suite_candidate_v1.json`. It required the candidate registry to remain
`CANDIDATE_UNQUALIFIED`, with eight null module identities, null `proofSuiteId`, and activation
disabled. It emitted exactly twelve H6 obligation records: five `BLOCKED`, five `OPEN`, and two
`REFERENCE_ONLY`, with 22 distinct blockers. No record could be closed by that preflight.

Historical raw record:

```text
status=BLOCKED_H6_PREFLIGHT
h5_preflight_digest_sha3_512=9c8cd9e4836576487431af85e3c1ae2b458d44580c144ceeda971f500cd9be279910ea88045761f59699d7b67a8520920a17f07b33d173ce9270d0d064d31693
suite_registry_digest_sha3_512=307439093721aeaa9a70ef00d546f06af5f50b73781f9f19b8b02cca8c3d36ee1ef36e9981d49a59d10d8d7768fec079d40e05b6c008d7913c9caf4cc52cf974
suite_registry_canonical_digest_sha3_512=4dd71275a1c400c8d19a2bd53792f92c70375e159982034b6a56108c1a2f924929edd35dc20150930e2bd09462a48ae6ebc41dd80853850d274bc269dcfe583e
preflight_digest_sha3_512=f4257066c4d1bd6d810e1b96227aa6b286216b5f0385335d3f839cb3c8e0020bb0bc7e4512fd101fb9280a2ae1090c62560620c2a9b7ef659f9d9f3febeade32
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

This is the preserved pre-manifest record, not the current qualification status. The current
candidate-evidence closure is recorded above; it still does not select a production suite or
authorize activation.

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
