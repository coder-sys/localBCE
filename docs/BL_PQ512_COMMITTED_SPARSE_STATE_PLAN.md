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
is complete with no backend admitted; the immediate work is S4/2E-4 atomic composition. Do not begin
with a paper benchmark or treat scalar work counters as throughput evidence.

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
   verifier are implemented in `pq_commitment_screening.py`. All four descriptors remain rejected
   because exact reviewed theorem/source/parameter and complete-proof evidence is missing; no backend
   is admitted or selected.
5. **S4 - atomic composition.** Bind the semantic AIR, CBAM, state relation, commitment, SHA3-512
   state identifier, proof grammar, and verifier decision into one non-spliceable transcript.
6. **S5 - migration and operations.** Prove old-tree/new-commitment equivalence at the profile
   boundary and test reorganization, checkpoint, restoration, rollback, partial-write, crash, and
   key/parameter migration behavior.
7. **S6 - exact bake-off.** Screen every admitted candidate with repeated identical state-component
   measurements, then run one uncounted complete warm-up and at least one unique, externally
   monitored, independently verified complete batch per profile for each finalist. Record complete
   input-to-independent-verification wall/CPU time, proof bytes, verifier time, peak RSS, scratch
   high-water mark, I/O, cleanup, and failure behavior. Report p50/p95 only when the sample count
   honestly supports them. This selects the Gate 2E candidate; it is not H5 qualification.
8. **S7 - selection.** Select the highest-throughput candidate satisfying every hard constraint, or
   retain C0 with exact rejection reasons. Pin its source, parameters, schema, module identities,
   KATs, theorem ledger, benchmark records, and migration plan. Bind the selected state plane into
   the actual H4 parent, transcript, proof grammar, independent verifier, and atomic receipt before
   starting H5's separate warm-up-plus-ten campaign.

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
