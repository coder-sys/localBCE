# Frontier throughput and Ethereum-alignment addendum

Updated: 2026-08-05

Status: authoritative cross-wave research and implementation addendum. It adds acceptance work to
existing packages; it does not add packages, reopen sealed Wave 1 semantics, select a proof suite,
authorize real PHI, or make an unmeasured performance claim.

Current proof checkpoint: the manifest-bound H4 heterogeneous prototype independently verifies
K128 and four-shard K512 in 29.974129/120.460733 seconds. Gate 2E is sealed nonactivating, H5
passed the exact 22-launch p95/resource campaign, and H6 closed the twelve bounded candidate-
evidence obligations. The state plane, production verifier/custody, rollup, and suite identity
remain unselected; `proofSuiteId=null` and activation remain false.

## Plain English

Blind Ledger's largest remaining cost is repeatedly proving authenticated replay and payment-state
bookkeeping. The next frontier work attacks that cost directly, schedules independent claims in
parallel without races, and makes government/oracle inputs independently auditable. Ethereum's
roadmap is a compatibility target, not permission to weaken privacy or post-quantum security.

The current semantic-AIR/shared-bus/Boolean-GKR design remains the primary Wave 2 path. A candidate
replaces any part of it only after an exact, reproducible K128 bake-off passes the same semantics,
privacy, strict-PQ, auditability, memory, scratch, and independent-verification gates.

The committed sparse-state work in `docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md` is now mandatory
Wave 2 gate 2E. It broadens the state bake-off beyond Shout/Twist: persistent public-coin memory,
transparent dictionaries, touched-projection RAM, compact shuffle-based memory consistency, and
native-hiding PQ commitments must be implemented behind one interface and measured against the
existing SHA3-512 control. This changes work allocation, not the sealed relation or activation state.

The new R&D direction is **subfield-first streamed GKR**. It does not replace Fp16 security or the
selected coprocessor. It keeps verifier challenges and final soundness in Fp16, but avoids storing
and multiplying full 64-byte Fp16 values while the bulk witness data is still Boolean/M31. Large
arrays stay in M31 or the smallest justified tower level, are consumed through deterministic
read/write streams, and are promoted only after folding has made them correspondingly smaller.

## Frozen bounds

- Keep the exact ordered 12-field external ABI and authenticated wide sidecar.
- Keep SHA3-512, Fp16 challenges, a 256-bit per-term and composed cryptographic
  security/encryption floor, native hiding, and
  dual-PQ-authenticated interactive public coin on Blind Ledger-controlled proof surfaces.
- Put no raw or encrypted PHI, exact private amount, claim document, or decision metadata in public
  calldata, blobs, inclusion lists, logs, or proofs.
- Treat Ethereum settlement cryptography as an external classical boundary. It cannot support a
  Blind Ledger end-to-end PQ claim.
- Keep `proofSuiteId=null` and activation false until existing qualification and downstream gates close.
- Keep 93 internal packages. The work below belongs to existing Waves 2-6.
- Treat end-to-end latency as a hard architecture gate on the reference Dell G15: a fixed-shape
  K128 job carrying 100 live claims must produce and independently verify in under 35 seconds, and
  a fixed-shape K512 job carrying 500 live claims must do so in under 180 seconds. These targets do
  not relax any security, privacy, correctness, memory, scratch, or audit gate.

## 1. Claim Batch Access Manifest

Wave 2 targets a canonical, proof-authenticated, privacy-padded **Claim Batch Access Manifest
(CBAM)** for every proof job. It contains opaque identifiers only and declares state pages read/written,
hash-bus ordinal ranges, governed oracle/root dependencies, sequencing/retry/idempotency domains,
deterministic conflict edges, and bounded CPU/GPU/RAM/scratch/network/proof-byte envelopes.

The prover cannot self-award resources or omit conflicts. Critical fields are independently
reconstructed from the profile, public statement, and authenticated sidecar. Fixed capacity and
dummy entries prevent occupancy or decision-class disclosure.

The current C0 implementation is deliberately narrower: a profile-fixed census plus a separate
nonactivating per-job binding. The binding commits to the fixed census, masked private access-body
reference, batch/sidecar/state roots, attempt, retry, and sequence identifiers; canonical decoders
reject altered lengths, ordering, or trailing bytes. It does **not** reveal page tokens and does
**not** claim native hiding or proof authentication. H0/H3 must bind the same relation into the
selected native-hiding proof before CBAM can be treated as release evidence.

## 2. Authenticated-state topology bake-off

K128 assigns 46,208 of 46,858 SHA3 calls (98.61%) to replay and payment state. Existing depth-64
maps remain the control. Wave 2 measures and Wave 3 may select a versioned alternative using:

- append-only PQ-authenticated history plus the smallest necessary mutable index;
- packed spent/nullifier pages and batched page roots;
- recent-root rings with explicit cold-root resurrection proofs;
- hot, checkpoint, and durable tiers with one atomic authenticated transition; and
- shared multiproofs reconstructing every endpoint and ordered update.

A changed root, page, or migration grammar is a statement/state-layout change, not a silent
optimization. It requires a new schema/profile epoch, semantic-equivalence evidence, KATs,
migration/rollback attacks, fixed-shape privacy evidence, and atomic activation. The 12-field ABI
shape remains unchanged.

If only state-call count changed, the exact model is
`projected_calls(r) = 650 + 46,208 / r`, where `r` is the state-call reduction factor. The resulting
structural upper-bound reductions are 1.97x at 2x, 3.84x at 4x, 7.29x at 8x, 13.24x at 16x,
22.38x at 32x, and 34.15x at 64x. Even deleting every state call leaves 650 non-state calls, so the
absolute state-only ceiling is 72.09x. These are Amdahl-style call-count projections, not
prover-speed predictions; they forbid attributing a 100x-1000x end-to-end claim to state work alone.

### 2.1 Three-plane memory-proof candidate

The 2026-07-22 incorporation screen passed **roadmap admission only**. Existing tests confirmed that
the current control already has one endpoint multiproof, a sorted memory-access chain, fixed
privacy padding, and exact shared/global SHA3 schedules. The candidate therefore does not replace a
naive per-operation Merkle path design. It must beat the optimized control under identical K128
semantics and resource gates.

The measured bake-off has three separately reviewable planes:

1. a Shout-like read-only argument for governed policy/oracle tables and other immutable epoch data;
2. a Twist-like read/write argument for replay and payment memory; and
3. the selected masked Fp16 Boolean GKR coprocessor for the unchanged SHA3-512 hash bus.

All three planes bind atomically to the same CBAM, authenticated public coin, state roots, ordinals,
and fixed-shape padding. Twist/Shout-style memory checking cannot authenticate the old/new
SHA3-512 roots by itself. The candidate must retain a canonical page/frontier/global-multiproof
root bridge, preserve sequential equivalence and exact full-width keys/values, and reject any
host-trusted equality. A Shout/Twist result receives no credit unless its total prover time, peak
RSS, scratch, proof bytes, verifier work, and simulator evidence beat the existing ordered-map
control at K128.

This is a research candidate, not a selected proof component. The source paper is a revised
preprint and reports results under its own protocol/security setting; Blind Ledger must reproduce
the construction over its field, transcript, hiding, hash, and 256-bit security/encryption ledger.

### 2.2 Committed sparse-state replacement bake-off

Wave 2 must test whether the SHA3-512 tree work can be replaced, rather than only accelerated, by
one fixed-shape proof over the touched state projection. C0 is the current endpoint-multiproof/
sorted-memory/shared-hash-bus control. C1-C4 are public-coin persistent sparse memory, an
IRONDICT-derived Index/Value relation, touched-projection RAM, and the Two-Shuffles
memory-consistency relation. Published pairing, KZG, VOLE, structured-setup, random-oracle, and
two-party backends are not imported.

The relation and PCS are separate modules. Jindo-style evaluation-hiding lattice commitments are
the leading hiding experiment; Grand Danois/Hachi-style, RoKoko-style, and transparent hash/code
paths are independent controls. No candidate inherits a paper's post-quantum, zero-knowledge,
performance, or setup claim. Exact assumptions, parameters, quantum knowledge soundness, adaptive
binding, native hiding, public-coin composition, grammar, field mapping, and side channels must be
qualified internally.

A selected non-Merkle commitment uses a new schema/profile and a domain-separated SHA3-512 state
identifier over its canonical commitment, epoch, capacity, layout, and parameter identity. The
proof must establish exact sealed-relation state equivalence. Silent root reinterpretation,
host-trusted equality, KZG/IPA/pairings, trusted setup, designated verification, cached-proof credit,
and launch Fiat--Shamir remain forbidden. Wave 3 may deploy only the exact Wave 2 selection and must
finish migration, rollback, reorganization, recovery, and custody qualification.

## 3. Deterministic parallel execution

CBAM dependencies form a canonical conflict DAG. A bounded scheduler may execute nonconflicting
claim groups and proof stages concurrently, but commits them in one authenticated order. Retries
retain the same governed attempt identity. Wave 2 first publishes a K128 conflict census; no
parallel-throughput percentage is accepted before measurement. Race, stale-read, cancellation,
retry, and scheduler-equivocation tests are mandatory.

Admission control independently bounds CPU, GPU, RAM, scratch, I/O, public-coin latency,
state-conflict pressure, and settlement/DA capacity. One scalar must not hide a saturated resource.

Latency qualification uses unique synthetic batches, one uncounted warm-up, and ten measured
steady-state runs. The input-to-independently-verified-output p95 must remain below 35 seconds for
K128/100-live and 180 seconds for K512/500-live. Reused witnesses, cached proofs, omitted privacy
work, weaker parameters, swap dependence, or excluded verification time invalidate the run.

## 4. Proof-system frontier bake-off

### 4.1 Subfield-first streamed GKR

This is the first pre-K128 proof-plane candidate allowed to modify the internal arithmetic schedule
of the selected Boolean GKR. The all-Fp16 implementation remains the differential control.

The candidate combines three primary-source techniques without importing their incompatible proof
systems wholesale:

1. small-characteristic sumcheck keeps early high-volume prover work in the base field while the
   verifier still samples full extension-field challenges;
2. tower sumcheck progressively promotes messages through a prime-power extension tower and has an
   explicit GKR formulation; and
3. read/write streaming keeps large, data-independent prover arrays in sequential external streams
   or bounded slabs instead of duplicating them in RAM.

Blind Ledger's frozen `M31 -> Fp2 -> Fp4 -> Fp8 -> Fp16` tower is structurally relevant, but neither
paper proves the complete Blind Ledger native-hiding, authenticated-public-coin, abort/retry, or
256-bit security/encryption composition. Those remain hard acceptance gates. Base-field challenges,
repetition in
place of Fp16 challenges, Fiat--Shamir, and paper-default security parameters are not admitted.

The local scalar substrate now removes generic nonresidue multiplications from the quadratic tower.
An Fp16 multiplication consequently uses 81 rather than 192 M31 multiplications in the reference
code. The exact Python field vectors and 95 Rust library tests pass. In three release-mode runs per
K128/K256/K512 point on the reference laptop, the same Fp16 square/multiply/add loop improved by
1.69x-1.80x; the optimized M31 loop still delivered roughly 199x-237x the Fp16 update rate. These
are field-kernel measurements, not proof-throughput claims.

If two eligible `w=1,600` accumulator arrays can remain four-byte M31 values until a four-round
fold, their raw storage is 181,968,000 bytes instead of 2,911,488,000 bytes. Substituting only that
term changes the existing 3,591,988,768-byte raw-state subtotal to 862,468,768 bytes: a 16x
accumulator reduction and 4.165x subtotal reduction. Cross-term storage, native masks, generated
width, commitments, allocator overhead, and streaming scratch are not yet included; only measured
K128 peak RSS and scratch may close the gate.

The governing release envelope is now peak resident memory no more than 5,000,000,000 bytes,
scratch strictly below 5,000,000,000 bytes, and no swap on the reference Dell. The projected
862,468,768-byte subtotal is therefore only a design budget: masking, commitments, streams,
allocator/OS overhead, the semantic plane, and independent verification must all fit inside the
same measured process boundary.

Wave 2 must implement an exact costed prototype for degree-two and degree-three GKR sums, select the
promotion round from measured M31/base-extension/Fp16 costs, prove message and terminal-claim parity,
apply native masks at every promoted level, and run the full simulator/error ledger. Scribe and
Hobbit are algorithmic controls for sequential streaming and space accounting only. Scribe's
concrete group PCS is non-PQ, while Hobbit states only plausible PQ security and uses its own PCS,
hash, Fiat--Shamir, and proof-size trade-offs; neither is a selectable Blind Ledger suite.

The H4 primary path has now produced a complete one-run K128 prototype, so WHIR, STIR,
DEEP-commitment, and related transparent PCS work may be measured only as isolated post-H4 research.
No active-path replacement is permitted before the selected state plane, H5, and H6 close under the
same gates. A candidate gets no paper-benchmark credit and must use the
Blind Ledger field/hash/transcript/hiding profile, zero grinding credit, full error ledger,
canonical bounded grammar, and Dell resource gates. Examples with roughly 80-100-bit security,
shorter digests, Fiat--Shamir-only compilation, or no native hiding are ineligible.

This bake-off may improve outer proof size, verifier work, and recursion. It may not replace the
application-specific inner AIR with a general VM or weaken authoritative SHA3-512 roots.

VEIL is admitted as a second, isolated native-hiding candidate for the multilinear/GKR plane. Its
paper reports a non-intrusive wrapper and low overhead in a 31-bit-field proof of concept, which is
architecturally relevant but not Blind Ledger evidence. It may replace no existing mask until an
exact Fp16, interactive authenticated-public-coin, abort/retry, cross-module, SHA3-512, and
256-bit simulator/security proof passes. The current native-hiding path remains authoritative
meanwhile.

Neo/SuperNeo remain quarantined post-K128 folding/aggregation candidates. Hachi may be measured
before K128 only as an isolated PCS candidate inside mandatory gate 2E; any Hachi aggregation use
remains post-K128. Their Module-SIS/Ajtai assumptions, parameters, extension-field mapping, proof
grammar, custody implications, and independent verifier must receive a separate security ledger.
They cannot become authoritative state commitments without winning 2E, silently replace the
transparent base proof, or add a trusted setup.

## 5. Proof-carrying government and oracle adapters

Wave 4 adapters emit a canonical **evidence capsule** binding exact response bytes or streaming
hash, schema/profile/version, deterministic normalization, endpoint/tenant, freshness/epoch,
dual-PQ authority, completeness/absence evidence, idempotency, and audit-safe error class. The
proof consumes the capsule commitment; the public chain sees only the permitted opaque binding.

The provider-neutral core supports versioned profiles for FHIR R4, US Core, Bulk Data, Da Vinci
PAS/PDex/CRD/DTR, and X12 translation where required. Profiles are not hard-coded adjudication
semantics or outside engineering dependencies. Live credentials remain activation inputs.

## 6. Ethereum-facing settlement modes

1. **Pinned validity-rollup mode:** buildable release path with its own L2 transition proof and L1 verifier.
2. **Native-rollup adapter mode:** optional only if EIP-8079 or a successor is finalized,
   implemented, independently tested, and preserves Blind Ledger invariants.
3. **Fail-closed recovery mode:** stops advances while preserving exits, evidence, and deterministic
   recovery; it never bypasses proof verification.

The rollup adds proof/data coupling, blob reconstruction tests, cell/delta-aware transport, keyed
replay protection, recent-root checkpoints, optional shadow verification, and PQ-signed Blind
Ledger checkpoints. FOCIL/EIP-7805 compatibility carries opaque bounded transaction/proof-job
commitments only, never PHI or private evidence. Draft EIPs are not release dependencies.

## 7. Formal-verification spine

Existing packages add machine-checked or independently executable specifications for Fp16
identities, SHA3/domain encodings, the public-coin state machine, proof grammar/allocation bounds,
multiproof reconstruction, exact 12-field composition, replay/value conservation, and atomic state
transition. External libraries may inspire or cross-check work; no outside team/service is needed.

## Wave ownership

| Existing wave | Added work; no new package |
| --- | --- |
| Wave 2 | CBAM; K128 state-call/conflict census; deterministic DAG; resource attribution; formal hooks; mandatory committed sparse-state/PQ-commitment implementation and selection; conditional outer-proof measurement after base K128. |
| Wave 3 | Deployment of the selected state topology; tiered durable state; recent-root ring; migrations; PQ checkpoints; atomic proof-carrying reads/writes. |
| Wave 4 | Evidence-capsule SDK; FHIR/PAS/PDex/CRD/DTR and other profiles; simulators and conformance. |
| Wave 5 | Proof/data coupling; opaque FOCIL-compatible forced path; partial-DA recovery; keyed replay; maturity-gated native-rollup adapter. |
| Wave 6 | Multidimensional capacity controller; shadow verifier; formal-spine reconciliation; frontier selection and release evidence. |

## Explicit rejects

- claiming 100x/1000x throughput without complete K128 measurements;
- publishing plaintext or encrypted medical documents through blobs, public storage, or inclusion lists;
- KZG, IPA, Verkle, ECC, trusted setup, or non-PQ signatures on authoritative Blind Ledger surfaces;
- calling an ephemeral classical signature post-quantum;
- depending on native rollups or another draft EIP for release;
- importing Groth16/Poseidon or general-VM benchmarks as Blind Ledger evidence;
- weakening fixed-shape privacy, canonical parsing, retry identity, or independent verification; or
- multiplying unrelated best-case ratios into a fictional end-to-end speedup.

## Primary references

- Ethereum roadmap tracker: https://strawmap.org/
- Complete Blind Ledger Strawmap/EIP compatibility contract:
  `docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md`
- EIP-8079, Native rollups: https://eips.ethereum.org/EIPS/eip-8079
- EIP-7805, FOCIL: https://eips.ethereum.org/EIPS/eip-7805
- EIP-7594, PeerDAS: https://eips.ethereum.org/EIPS/eip-7594
- EIP-7999, unified multidimensional fee market: https://eips.ethereum.org/EIPS/eip-7999
- EIP-7928, block-level access lists: https://eips.ethereum.org/EIPS/eip-7928
- Twist and Shout memory checking: https://eprint.iacr.org/2025/105
- VEIL zero-knowledge compiler: https://eprint.iacr.org/2026/683
- Neo and SuperNeo post-quantum folding: https://eprint.iacr.org/2026/242
- Hachi lattice multilinear commitments: https://eprint.iacr.org/2026/156
- Persistent/volatile memory AIPs: https://eprint.iacr.org/2024/979.pdf
- Two Shuffles Make a RAM: https://www.usenix.org/system/files/usenixsecurity24-yang-yibin.pdf
- Projection-code and black-box ZK RAM: https://escholarship.org/content/qt9405r7n6/qt9405r7n6.pdf
- Batching-efficient RAM: https://eprint.iacr.org/2024/840.pdf
- IRONDICT: https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_hafezi.pdf
- Jindo lattice PCS: https://eprint.iacr.org/2026/044
- RoKoko lattice argument: https://eprint.iacr.org/2026/575
- Grand Danois lattice PCS: https://eprint.iacr.org/2026/1196
- Quantum oblivious LWE sampling: https://eprint.iacr.org/2024/030
- Small-characteristic sumcheck: https://eprint.iacr.org/2024/1046
- Tower-field sumcheck and GKR: https://eprint.iacr.org/2025/594
- Scribe read/write-streaming SNARK: https://www.usenix.org/conference/usenixsecurity26/presentation/baweja
- Hobbit space-efficient transparent PQ-candidate SNARK: https://www.usenix.org/conference/usenixsecurity25/presentation/pappas
- CMS-0057-F: https://www.cms.gov/newsroom/fact-sheets/cms-interoperability-prior-authorization-final-rule-cms-0057-f
- HL7 Da Vinci PAS: https://hl7.org/fhir/us/davinci-pas/
- HL7 FHIR Bulk Data: https://hl7.org/fhir/uv/bulkdata/

These sources define ecosystem directions and interoperability targets. None certifies Blind
Ledger, supplies its security theorem, or substitutes for implementation and audit.
