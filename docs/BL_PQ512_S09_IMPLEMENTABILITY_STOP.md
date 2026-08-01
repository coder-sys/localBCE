# BL-PQ512 S09 implementability stop

Updated: 2026-07-19

Status: **historical S09 stop record. H4 has superseded the R35 implementation checkpoint, but
full proof-suite selection and activation must still stop.**

Current superseding implementation note: `docs/CURRENT_TECH_STACK.md` is the active inventory. H4
now executes the shared-bus bridge, native-masked GKR, Construction 8.2 PCS, and atomic K128/K512
coordinator. The old direct-SHA3-STARK and Circle-FRI/BaseFold resource layouts are retired. This
record still governs suite activation and forbids guessing the remaining state, simulator,
composition, custody, or theorem constants.

Historical machine-readable result from this checkpoint (not current runtime state):

```text
R35_WAVE1B_THEOREM_BACKEND_IN_PROGRESS_S09_ACTIVATION_STOPS_OPEN
proofSuiteId = null
activationAllowed = false
physicalRelationIrConstrained = true
interfaceCircleFriImplemented = true
interfaceNativeHidingParametersImplemented = true
concreteStarkBackendSelected = false
proofGenerated = false
productionUsable = false
```

This is the exact remaining STOP record for S09. It is not a request for an outside engineer and
does not move engineering out of the roadmap. The old assumption that progress required an upstream
degree-16/SHA3-512/Fiat--Shamir module is superseded by
`docs/BL_PQ512_S09_INTERNAL_SOLUTION.md`. Blind Ledger can implement the selected interactive
public-coin construction internally, then submit the sealed release to the one final independent
audit. The stop remains because silently guessing PCS/FRI, hiding, retry, or proof-format constants
would violate the product's absolute-PQ and auditability requirements.

## Current upstream capability

The official S-two repository currently implements its production profile around the
`M31 -> CM31 -> QM31` tower, with QM31 as the secure challenge field. The available channel families
include Blake2s as the default plus Blake3, Poseidon252, and Keccak256 variants. Its own security
documentation makes parameter selection the consumer's responsibility and states that the
implementation is not constant time.

That is useful upstream engineering, but it does not implement Blind Ledger's conditional
degree-16/SHA3-512/native-hiding target. The official repository does not supply all of the following
as one theorem-matched, reviewed module:

- a canonical M31 degree-16 tower, basis, irreducible polynomials, conjugations, encodings, and
  uniform challenge sampler;
- SHA3-512 Fiat-Shamir and full-width proof-tree commitments with Blind Ledger's typed domains;
- an exact Circle-FRI rate/distance/list/fold/query layout matched to an applicable theorem and its
  concrete constants;
- the complete multi-table/LogUp/composition/OODS/DEEP/FRI challenge schedule and positive-error
  ledger for the final AIR;
- native witness hiding with a simulator covering every trace, lookup/permutation, quotient, DEEP,
  and FRI oracle plus abort/denominator behavior; or
- Blind Ledger's canonical proof-body sections, lengths, parser allocation limits, and downgrade-
  resistant verifier identity.

Primary upstream: <https://github.com/starkware-libs/stwo>. The preceding source-level conclusion is
also recorded in
`cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/01_official_upstream_cryptographic_implementability_review.json`.

## Internal replacement selected on 2026-07-18

The authoritative launch transcript is now a PQ-authenticated, interactive public-coin protocol,
not Fiat--Shamir. Every challenge is generated after its prover commitment by typed SHA3-512
commit/reveal rounds, authenticated through production ML-DSA-87 and SLH-DSA-SHAKE-256f adapter
ports. This removes the QROM Fiat--Shamir reduction from the authoritative launch path without
weakening the field, hash, hiding, or FRI requirements. A future noninteractive module remains
disabled until separately qualified.

The degree-16 tower, basis, 64-byte canonical encoding, arithmetic, inversion, exact Euler-criterion
checks, and unbiased SHA3-512 rejection sampler execute in the Python reference. R32 adds an isolated
`no_std` Rust scalar core with Frobenius/conjugation, typed SHA3-512 Merkle domains, differential
KATs, and no unsafe code. It also adds exact locked software ML-DSA-87/SLH-DSA adapters, bounded
retry/quarantine governance, and an 88-byte-header bounded proof-grammar reference. These are
nonactivating substrate modules, not a production PCS/verifier or suite.

The R32 source inventory confirms that vendored S-two's high-level proof engine is structurally tied
to QM31 across AIR, composition, OODS, PCS/FRI, proof objects, and SIMD. The vendor remains
byte-stable. Production work must use a reviewed sibling engine over reusable low-level primitives
or a separately reviewed patch series; a channel/configuration toggle is not a valid migration.

R35 therefore builds the sibling modules directly. Python and `no_std` Rust now agree on the
Fp8-excluding OODS sampler, explicit two-claim conjugate-pair quotient identities, scalar Circle-FRI fold cascade, and
typed projection-consistent SHA3-512 commitments. The Python theorem worksheet derives six
unselected interface candidates, the typed public-coin schedule fixes every prover-message/challenge
boundary, and the pre-dense-schedule native-hiding worksheet applies the conservative mask bound to all 16 physical
tables. R35 also implements the constructive direct hiding map, canonical quotient-mask/source-
aligned split kernel, and a byte-oriented low-degree SHA3-512 round AIR with independent Python/Rust
KATs. The current 52-callsite inventory executes and retains both earlier K128 host envelopes only
as historical evidence. R36's current claim-tree plus packed-oracle topology is proved at
14,322/28,644/57,288 permutations for K128/K256/K512; non-dense application-port schedules and lookup-
interaction packing remain.
None of that selects a final rate or lookup-interaction packing or proves the complete Circle
zero-knowledge simulator.

## Why the existing physical kernel cannot be promoted

The current physical calibration kernel has 267 trace columns, one interaction column, and 476
constraints for a narrow decision-priority/payment-conservation relation. Its proofs use the
rejected QM31/Blake2s/default configuration, have `witness_hiding=false`, and omit the complete
ordered 12-field statement, authenticated claim/oracle/policy paths, A12 derivation, authoritative
the authoritative wide replay transition, wide payment/governance state, and native hiding.

Adding the missing application constraints to that kernel would produce a larger validity-only
prototype under a proof suite already rejected by S08. It would not become BL-PQ512, and calling it
the production physical AIR would create an unsafe migration target. The kernel remains calibration
evidence only.

## Exact unresolved selections

S09 cannot assign a suite ID until every row below is non-null and KAT-tested:

| Selection | Required evidence |
| --- | --- |
| Degree-16 algebra | Python and `no_std` Rust tower/basis/bytes/arithmetic/inversion/Frobenius/conjugation/trace/norm/sampler KATs now exist; optimized scalar/SIMD integration, independently derived tables, constant-time/side-channel evidence, review, and final module identity remain |
| Circle-FRI/PCS | R35 implements scalar degree-corrected folds, authenticated Fp8-excluding OODS, typed cross-domain SHA3-512 trees, mandatory independent per-domain FRI masks, global nonresetting batch powers, gap-complete variable-width folding, an exact six-candidate interface sweep, a Python/Rust K512 schedule KAT, and the executable SHA3 AIR with a 1,632-column/1,024-lookup core and 1,704-column/1,096-first-round-lookup sponge envelope. Application hash-port/lookup-interaction expansion, final code-rate/distance/list selection, production scalar/SIMD prover/verifier integration, reviewed constants, and final module identity remain |
| Transcript | Public-coin framing, rejection sampling, fail-closed per-session state, exact software PQ adapters, four-attempt suite-diverse quarantine, audit roots, a 22-round interface-candidate schedule, and fixed typed prover messages now exist. Final SHA3-expanded AIR dimensions, HSM/custody services, durable anti-rollback publication/recovery, deadlines, governance authentication, and the final abort-grinding ledger remain. No QROM theorem is required for the authoritative interactive mode |
| Native hiding | R35 applies the conservative trace-mask bound to all 16 tables, makes independent per-domain FRI batch masks mandatory and pre-challenge committed, binds the exact interface domain/width/offset/fold layout, constructively proves the direct multi-extension/base-query trace-evaluation map, and implements the canonical quotient mask plus source-aligned split rule in Python/Rust. Final split log-degree/prover integration, interaction/SHA3-expanded oracle widths, complete simulator, abort/denominator proof, repeated-proof leakage tests, and side-channel qualification remain |
| Proof grammar | Strict `BLPQPF01` reference header, header-first allocation bound, out-of-band identity, ordered fixed sections, SHA3-512 digests, downgrade rejection, and malformed corpus exist; final PCS-dependent section codes/order/lengths, verifier identity, transport time/admission bounds, and independent differential fuzzing remain |
| Final AIR envelope | R33 declares K128/K256/K512 metadata estimates but supplies no executable AIR; those values and the host-recomputation counts are historical only. R35 supplies a reusable SHA3 round witness/lookup shape and classifies 48 SHA3 callsites. Dense shared-node topology and exact padding are proved at K128/K256/K512. R36 must build the application AIR, fix every non-dense schedule, independently evaluate all identities/lookups, measure concrete application/SHA3/Poseidon expansion, select interaction packing, derive final PCS/FRI expansion, and substitute every positive theorem term into S07 |

The candidate registry continues to pin only the local degree-16/public-coin direction while
correctly retaining null *selected* Circle-FRI parameters, final transcript schedule, final proof-
body sections/length, module IDs, and `proofSuiteId`. R35 interface sweeps and schedule candidates
do not silently populate a final registry cell.

## Work allowed while S09 is stopped

The stop does not block internal cryptographic implementation or independent product work. It
permits:

- A12 application semantics, exact encoders, vectors, and fail-closed registry bindings;
- semantic trace schedules and authenticated state/reference implementations that do not claim AIR
  or proof authentication;
- modular provider-neutral government/oracle adapters and local/sandbox simulators;
- parser, state-machine, migration, rollback, supply-chain, observability, and release engineering
  behind the disabled suite registry; and
- production degree-16, SHA3-512 PCS, public-coin orchestration, theorem/parameter, proof-format, and
  hiding implementation behind the nonactivating registry; and
- isolated algebra/transcript/hiding prototypes that cannot be activated or mistaken for the
  selected suite.

It forbids generating or retaining a proof as BL-PQ512, setting a suite/module ID, changing
`CANDIDATE_UNQUALIFIED`, enabling production parsing/state, reusing QM31/Blake2s as a compatibility
fallback, or calling the complete relation IR a concrete private STARK or production AIR.

## Resume gate

R33 satisfied only the semantic-reference portion of the prior resume condition; its physical-
relation object is metadata, not executable AIR. R36 reopens and builds that missing constraint
boundary before the partially implemented R35 ports may be instantiated. Work continues without an
outside implementation dependency. Suite identification and BL-PQ512 proof generation remain stopped until a reviewed
record integrates the complete SHA3-expanded AIR and production sibling engine, proves the Circle
hiding simulator, supplies every remaining registry cell, keeps the 12-field ABI fixed, substitutes
every positive term into S07, and passes the algebra/public-coin/FRI/hiding/parser KAT and attack
gates. Only then may `UNSELECTED` move to `BUILT_AUDIT_PENDING`.
