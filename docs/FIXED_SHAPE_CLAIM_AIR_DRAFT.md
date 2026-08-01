# Fixed-shape claim AIR foundation draft

Updated: 2026-07-22

Current-roadmap note: this document is a historical foundation input to current Wave 1 (claim
relation and executable AIR), which is now sealed at its synthetic nonactivating boundary in
`docs/WAVE1A_EXECUTABLE_AIR_SPEC.md`. Current Wave 2 is the former Wave 1B proof work; current Wave 3
is the former Wave 1C verifier/state/custody work. Later closure records supersede this draft's old
forward-looking status statements but do not erase its evidence chronology.

Physical-topology note: the sealed SHA3 AIR remains the independent differential specification.
Wave 2's release priority is the shared-bus Boolean GKR coprocessor in
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`; this changes how SHA3 is proved, not the call
schedule, bytes, digests, state semantics, fixed shape, or external 12-field ABI.

Status: **SYNTHETIC-ONLY REVIEW DRAFT -- NOT A PRODUCTION FREEZE**

This draft is an internally finishable input under `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md`.
Independent audit occurs after the exact AIR, proof suite, verifier, state, rollup, and release are
implemented and internally qualified; no outside reviewer is required to write this AIR.

This document is the review artifact for roadmap packages `A01-A06`. R33 implements its bounded
host semantics and a nonactivating relation-inventory estimator, but not an executable AIR. It does
not close the package-specific constraint, backend, review, or capacity gates, authorize real PHI,
or establish zero knowledge or post-quantum proof security. The exact external Privacy V2 ABI remains the ordered 12 fields already defined in
`ops/native_stark_public_inputs_v2.json`.

The cryptographic feasibility gates `S07-S09` remain upstream hard blockers. In particular, this
draft does not select a field-extension security budget, FRI query count, blow-up factor, grinding
factor, PCS, transcript, tree hash, or proof size. R33 declares a 16-table relation-interface
inventory behind abstract ports; its counts are estimates, not frozen theorem inputs. R35
provides a reusable byte-oriented SHA3-512 witness/lookup shape with a 1,632-column/1,024-lookup core and complete
1,704-column/1,096-first-round-lookup sponge envelope. The R35 static-inventory checkpoint contained
52 scoped callsites, 25 AIR-required; its first conservative K128 host-verifier envelope recorded
401,275 conservative AIR invocations, 1,205,016 permutations, and 28,920,384 Keccak round rows.
Those dynamic counts and the later `51*K` rerun are historical. R36 proved one exact 2,133-byte
bundle per claim preserves all six facts, 50 authorization tokens, enable flags, and ordering. The
proof hashes K bundles plus one ordered execution root; a separate audit tree reuses those digests.
The current claim-tree plus packed-oracle schedule is proved across K128/K256/K512 at
14,322/28,644/57,288 permutations. Non-dense application-port schedules, lookup-interaction
packing, PCS/FRI expansion, and final physical AIR row count remain `TBD` pending current Wave 2
convergence. R28's
narrow rejected-suite calibration remains historical evidence only.

## 1. Scope and non-negotiable boundaries

- Synthetic data only. The v0 schema is forbidden for real claims and production settlement.
- The 12 public fields retain their exact count, order, names, types, and forbidden-field boundary.
- Exact amounts, decisions, real-claim counts, cover counts, and medical data remain private.
- Every outer slot performs the same logical claim, governance, authorization, policy, value, and
  nullifier work. No approval, denial, or cover path may exit early.
- Each real attempt and each cover slot consumes both a legacy compatibility nullifier and a strong
  shadow-state nullifier. A12 freezes the exact application preimages and independent legacy/
  SHA3-512 derivations; S09 must still select and constrain the proof-system primitives.
- Legacy and wide records are derived independently from the same canonical raw record. A wide root
  must never be obtained by hashing a legacy felt root.
- The application-specific AIR is modular tables and constraints, not one general-purpose VM per
  claim.

## 2. Evidence that prevents a premature freeze

The current application accepts up to 1,024 claims, uses a shared depth-10 configuration for
several unrelated trees, and caps service lines at 50. That is not a coherent proof capacity. One
claim can contribute one claim-facts oracle leaf and as many as 50 authorization leaves, so a
depth-10 oracle tree holds only 20 worst-case all-authorization claims (`floor(1024 / 51)`).

Before this foundation reconciliation, the semantic implementations disagreed at trust-critical
boundaries:

- Python and the RISC semantic model ordered text lexicographically, while Cairo compared the packed
  felt representation; variable-length values could therefore order differently.
- Python retained duplicate diagnoses in its sorted commitment, while the RISC semantic model
  rejected duplicate diagnoses.
- Some lanes treat missing provider, service-line, diagnosis, or charge data as a private denial;
  other lanes reject the same absence structurally before their nominal denial gate.
- Application identifier limits can exceed the proof layer's current 31-byte packed-text limit.

The length-first ordering, diagnosis rejection, and current Python claim/prior-authorization/service-
line identifier grammar now have explicit source checks and focused regressions. The missing-data
classification, new multipart witness representation, canonical line-ID binding, and complete AIR
remain open implementation work. In particular, the current legacy semantic oracles do not become
the new A07-A16 proof merely because their input boundary is stricter. The provisional rules below
must be implemented identically in Python, Rust, Cairo, the RISC semantic oracle, and the future AIR
before `A01-A06` can close.

## 3. Independent provisional capacity knobs (`A01`)

`K=256` is the design point for batching hundreds of claims. `K=128` and `K=512` are calibration
profiles, not separate semantic protocols. The final governed K must be selected from measured
worst-case memory and proving evidence. Until then, all three profiles remain non-production.

| Knob | K128 calibration | K256 design point | K512 calibration | Status |
| --- | ---: | ---: | ---: | --- |
| Outer claim slots `K` | 128 | 256 | 512 | Provisional; measure all three |
| Service-line slots per claim `L` | 50 | 50 | 50 | Existing source-backed cap |
| Diagnosis slots per claim `D` | 16 | 16 | 16 | Provisional business limit; never truncate |
| Claim-level government facts `F` | 6 | 6 | 6 | Exact current decision fact set |
| Authorization slots per claim `A` | 50 | 50 | 50 | One per line, active or cover |
| Claim-source tree depth | 7 | 8 | 9 | Exact K-leaf batch tree |
| Oracle tree depth | 13 | 14 | 15 | Holds `K * (1 + A)` leaves |
| Governed policy tree depth | 16 | 16 | 16 | Provisional, independent knob |
| Real policy-row capacity | 65,533 | 65,533 | 65,533 | `2^16 - 3` after header and sentinels |
| Legacy nullifier tree depth | 32 | 32 | 32 | Current compatibility shape |
| Strong nullifier tree depth | 64 | 64 | 64 | Provisional state-capacity shape, not a security claim |

An input over any reviewed bound is rejected before proving with a stable structural error. It is
never truncated, split invisibly, or converted into a denial. A 1,024-item application submission
maps to four K256 proof jobs at the design point. Recursive aggregation is a later, separate design
and is not assumed here.

Tree depths are deliberately independent. Increasing claim capacity cannot silently change policy
or nullifier state, and a large policy registry cannot silently enlarge every batch tree.

## 4. Fixed logical tables for hundreds of claims (`A05`)

The canonical witness contains exactly K outer slots. The trace generator expands those records
into the following fixed logical tables. Padding to a power of two is part of the selected capacity
profile, not a function of the real-claim count.

| Logical table | K128 | K256 | K512 |
| --- | ---: | ---: | ---: |
| Claim slots | 128 | 256 | 512 |
| Service-line rows (`K * 50`) | 6,400 -> 8,192 | 12,800 -> 16,384 | 25,600 -> 32,768 |
| Diagnosis rows (`K * 16`) | 2,048 | 4,096 | 8,192 |
| Fact rows (`K * 6`) | 768 -> 1,024 | 1,536 -> 2,048 | 3,072 -> 4,096 |
| Authorization rows (`K * 50`) | 6,400 -> 8,192 | 12,800 -> 16,384 | 25,600 -> 32,768 |
| Policy-query rows (`K * 50`) | 6,400 -> 8,192 | 12,800 -> 16,384 | 25,600 -> 32,768 |
| Claim-source leaves | 128 | 256 | 512 |
| Oracle leaves (`K * 51`) | 6,528 -> 8,192 | 13,056 -> 16,384 | 26,112 -> 32,768 |
| Legacy predecessor/insertion path nodes | 8,192 | 16,384 | 32,768 |
| Strong predecessor/insertion path nodes | 16,384 | 32,768 | 65,536 |
| Legacy nullifier transitions | 128 | 256 | 512 |
| Strong nullifier transitions | 128 | 256 | 512 |

The claim-source and oracle trees are batch-local: build each tree bottom-up once from its complete
fixed leaf table. Do not reverify a duplicate full Merkle path for every leaf. Governed policy rows
come from persistent verifier state, so the trace generator creates an authenticated, sorted,
deduplicated policy dictionary and fixed query table. Any optimization that changes the accepted
root or query semantics requires a separate reviewed decision.

Nullifier updates remain sequential in canonical slot order for the safety baseline. The economic
maps now have a separately checked endpoint batch multiproof: every target and allocator position is
authenticated once, while a sorted memory-access chain proves exact equivalence to the reviewed
sequential upserts and duplicate behavior. This optimization does not yet apply to replay state.
The physical tables must pad the economic frontier to one governed profile bound so key distribution
cannot alter row count or proof size.

R33 historically declares the relation-interface schedule and estimated rows, columns, maximum degree,
message widths, and commitment groups. Concrete full-application SHA3/PCS expansion, composition
degree, FRI query count, and proof byte length remain **TBD** for current Wave 2. The 28,643,096-byte
kernel proof is not this full K128 answer. Approval, all 13 denials, and cover must report identical
values for every final dimension under one governed profile.

## 5. Synthetic foundation witness schema (`A02`)

The machine-readable interchange schema is
`schemas/bl_pq512_witness_v0.schema.json`. Its fixed identity is
`BL-PQ512-WITNESS-SYNTHETIC-FOUNDATION-v0`.

The schema:

- rejects unknown and missing properties at every object boundary;
- has exact arrays for the 12 public ABI entries, diagnoses, facts, service lines,
  authorizations, policy paths, and both nullifier paths;
- couples each calibration profile to its exact K, claim-source depth, oracle depth, and outer
  slot count;
- includes `synthetic_only=true` and `production_frozen=false` as constants;
- carries no plaintext free-form medical narrative and represents every listed variable-length
  proof-bound identifier with the same fixed three-part, at-most-64-byte canonical encoding;
- keeps the slot discriminator and all economics private inside the witness.

JSON is an interchange representation, not the bytes absorbed by the future transcript. The
provisional v0 canonical binary encoding is deterministic:

1. Prefix the eight ASCII bytes `BLPQWIT0`.
2. Traverse object properties in the exact order of each schema `required` array and arrays in
   increasing index order. Fixed arrays carry no runtime length word.
3. Encode booleans and small enums as one unsigned byte; encode integers as the smallest schema-
   declared fixed width, unsigned and big-endian.
4. Decode each felt hex string into exactly 32 big-endian bytes and each wide value into exactly 64
   big-endian bytes. A semantic decoder additionally rejects a felt greater than or equal to the
   Stark field modulus.
5. Encode `source_authority_id`, `claim_id`, `member_id`, every service-line `line_id`, prior-
   authorization value, and authorization token with `app/multipart_ascii.py`: retain 0-64 canonical
   ASCII bytes without truncation; split them at offsets 0, 30, and 60 with capacities 30, 30, and
   4; and emit exactly three felt parts. Each part is the 31-byte big-endian integer
   `chunk_length || chunk || zero_right_padding_to_30`. The interchange object contains the total
   `byte_length` and exactly three 32-byte lowercase felt hex strings. A decoder recomputes every
   chunk length and padding byte, verifies total length and canonical uppercase token syntax, and
   rejects every alternate representation. Empty denial/padding sentinels use length zero and three
   zero parts. No caller may truncate, hash, or modulo-reduce an identifier to fit one felt.
6. Reject trailing data, duplicate JSON keys, non-integer numbers, unknown profile identifiers, a
   slot index different from its array position, and any count field different from the number of
   enabled fixed slots.

This encoding is a reviewable foundation convention. It is not a proof-transcript, PCS, tree-hash,
or domain-separation decision under `S07-S09`.

The variable-length token grammar is the existing application rule in `app/shared_context.py`:
`^[A-Z0-9][A-Z0-9-]{0,63}$`. The encoder does not uppercase, trim, or otherwise normalize; a value
that is not already canonical is rejected. Fixed-format values are deliberately separate:
`provider_npi` remains exactly ten ASCII digits with its source-level check-digit rule, while
diagnosis and procedure codes retain their own bounded code grammars. Those fields are not silently
reclassified as multipart identifiers.

## 6. Canonical ordering and duplicates (`A03`)

R24 pins the current v1 money boundary used by every semantic lane. Source money is already an
ASCII string matching `^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,2})?$`; a JSON number, boolean, float,
decimal, integer, whitespace, sign, exponent, comma, leading-zero alternative, empty fraction, or
third fractional digit is structural invalidity and is never normalized. Decoding computes exact
integer cents and never rounds.

Proof money is already an exact integer--not a boolean--in `0..4,294,967,295` inclusive. Numeric
strings, floats, decimals, booleans, and integer subclasses are rejected rather than coerced. This
u32 bound applies independently to each claim total, enabled-line charge, enabled-line unit value,
governed allowed amount, approved amount, and payment amount. The per-claim line-charge sum uses
checked wider arithmetic, must fit u32, and must equal the authenticated claim total exactly. A K256
batch or provider total uses checked wider arithmetic and cannot exceed `1,099,511,627,520`; it is
never narrowed into a claim field. The relation has no tolerance, float arithmetic, wrap,
saturation, felt reduction, modulo repair, or truncation.

Zero is a valid encoding. For an otherwise well-formed real claim, a zero total or zero charge or
units on any enabled line reaches private G8A and produces hidden code 10 with zero payment. No
enabled lines reaches G5. Cover and disabled rows retain canonical zeros. A line-total mismatch,
per-claim sum overflow, bad type, or bad encoding is structural and never becomes G8A.

The canonical text ordering key is `(ASCII byte length, ASCII bytes)`. For the legacy single-part
length-prefixed text this matches numeric packed-felt order. Multipart values are first reconstructed
and validated, then compared by total length and bytes; their three felt integers are never compared
independently. Python, Rust, Cairo, and the RISC model must compare this explicit key rather than
their native string ordering.

- Enabled service lines sort by `(procedure packed-text key, charge cents, units cents,
  prior-authorization packed-text key, line-id packed-text key)`. Repeated enabled line IDs are
  structural errors. Two lines with identical economic fields are preserved when and only when
  their canonical line IDs differ.
- Enabled diagnosis codes sort by their packed-text key and duplicates are rejected. Disabled
  diagnosis padding repeats only the exact empty reserved value and is excluded from uniqueness.
- Fact rows have the fixed order listed in section 8; extra or missing fact IDs are rejected.
- Policy rows sort by the canonical procedure packed-text key, then physical leaf index.
- Real claims sort by `(source authority packed-text key, source sequence, attempt version,
  revision kind, claim-id packed-text key)` before receiving consecutive outer slot indices.
- Exact duplicate attempt identities are structural replay errors, not two claims and not a denial.
  BL-PQ512-v1 is original-attempt-only; corrections, replacements, and voids are structural
  `REVISION_NOT_AUTHORIZED` until a separately governed revision-capable schema exists.
- Cover slots occupy all remaining indices after the last real slot. The real count and cover count
  remain private.

The original line index remains proof-bound audit provenance but is not a sorting tiebreaker. The
line ID is the deterministic final key, so input permutation cannot change the canonical order.
Disabled line slots repeat only the exact empty reserved identity and are excluded from duplicate
checks. No enabled line is silently deduplicated.

## 7. Real, denial, and cover semantics (`A04`)

Each slot has a private committed kind: `REAL` or `COVER`.

- A real approval has decision `1`, failure code `0`, and payment equal to the exact plan-payable
  amount after authenticated patient responsibility is subtracted from gross allowed value. The
  composite benefit, obligation, double-entry ledger, reserve, and operation-log transition in
  `BL_PQ512_S07_S12_PREIMPLEMENTATION_FREEZE.md` is authoritative; the historical foundation
  vector rule that equated payable with allowed is not valid input for the R25 successor corpus.
- A real denial has decision `0`, one of the 13 failure codes, and zero payment.
- A cover has decision `0`, failure code `0`, zero economic values, and profile-reserved canonical
  claim, line, diagnosis, fact, authorization, and policy records.
- Cover records are not omitted and do not turn constraints off. They execute the same rows, tree
  construction, policy query, accumulators, and two nullifier transitions as real records.
- Cover commitments and nullifiers must be domain-separated from every real record and from one
  another by at least profile identity, epoch, batch nonce, and slot index. The derivation also uses
  a fresh private 512-bit cover nonce. Domain codes 257/258 and the exact A12 byte grammar are frozen
  in `BL_PQ512_A12_NULLIFIER_FREEZE.md`; their physical AIR realization remains an S09/A13-A16 item.
- Legacy and strong nullifiers are independently derived from the same canonical slot preimage.
  Neither is obtained by hashing the other.
- Zero, reuse, or any real/cover or cover/cover collision is a fatal batch-construction error. The
  builder must not retry a single slot until it passes; a reviewed whole-batch nonce rotation is the
  only candidate recovery rule and requires audit logging and new vectors.

The logical cover record is exact even though its future cryptographic domain tags remain open:

| Cover surface | Required logical value |
| --- | --- |
| Outer slot | `source_sequence=0`, decision/failure/allowed/payment all zero; slot index still equals array position; private salt is fresh and nonzero |
| Header | Empty multipart source, claim, and member IDs; empty provider; day, attempt, revision, parent, diagnosis count, line count, and charge all zero |
| Diagnoses | All 16 disabled; each code empty; each slot index equals its array position |
| Service lines | All 50 disabled; original index zero; empty multipart line ID and prior authorization; empty procedure; zero charge/units; canonical absent-policy row; slot index equals position |
| Claim facts | The same six ordered fact IDs; value false and `verified=true`; cover attestation commitment recomputed rather than supplied arbitrarily |
| Authorizations | All 50 not required and absent; dates zero; empty multipart token; slot index equals position |
| Derived values | Claim/oracle leaves, commitments, both nullifiers, roots, and paths are recomputed from the canonical cover record, batch context, salt, and slot index; arbitrary caller values are rejected |

For real claims, only enabled diagnoses and enabled lines participate in counts, sorting, and
duplicate checks. All disabled inner slots must equal the same canonical padding rows above.
Relational checks that JSON Schema cannot express--array position, enabled counts, sortedness,
uniqueness, recomputed leaves, and path validity--are mandatory semantic-decoder and AIR checks, not
optional normalization. `experiments/fixed_shape_claim_air/witness_schema_reference.py` now executes
the Draft 2020-12 keyword subset used by this exact schema and then checks multipart decoding,
positions, enabled counts, semantic ordering, exact money, fresh/nonzero unique slot salts and both
nullifiers, and sequential nullifier-root framing. Its result explicitly sets
`cryptographic_artifacts_authenticated=false` and enumerates every leaf/path/commitment/proof/payment
surface it cannot yet recompute. Complete authenticated witness/AIR validation remains an explicit
A07-A16 dependency.

Selectors may constrain row type, but the host trace generator may not branch around work according
to a private kind or decision. A future leakage test must confirm identical trace/proof dimensions
and repeated-proof unlinkability after the witness-hiding layer exists.

## 8. Exact adjudication order and rejection taxonomy (`A06`)

These are the exact private denial gates and codes already shared by the policy artifact and the
semantic implementations:

| Code | Gate ID | Private denial reason |
| ---: | --- | --- |
| 1 | `G1_MEMBER_ID_PRESENT` | `member_id_missing` |
| 2 | `G2_ELIGIBILITY_ACTIVE` | `eligibility_inactive` |
| 3 | `G2B_PATIENT_NOT_DECEASED` | `patient_deceased` |
| 4 | `G3_PROVIDER_NPI_PRESENT` | `provider_npi_missing` |
| 5 | `G4_PROVIDER_ENROLLED` | `provider_not_enrolled` |
| 6 | `G4B_PROVIDER_NOT_SUSPENDED` | `provider_suspended` |
| 7 | `G5_SERVICE_LINES_PRESENT` | `service_line_missing` |
| 8 | `G6_DIAGNOSIS_PRESENT` | `diagnosis_missing` |
| 9 | `G7_PRIOR_AUTH_WHEN_REQUIRED` | `prior_authorization_required` |
| 10 | `G8A_CHARGE_VALID` | `invalid_charge` |
| 11 | `G8B_FEE_SCHEDULE_PRESENT` | `fee_schedule_missing` |
| 12 | `G9_NOT_DUPLICATE` | `duplicate_claim` |
| 13 | `G10_NO_PROGRAM_INTEGRITY_HOLD` | `program_integrity_hold` |

All 13 booleans are evaluated for every real slot. The first zero in this order is selected
arithmetically; proof generation does not return early. Code zero means approval for a real slot and
the reserved no-denial value for a cover slot, distinguished only by the private slot kind.

Authenticated absence is different from malformed evidence:

- Empty member and provider sentinels, zero enabled service lines, zero enabled diagnoses, and a
  canonical zero charge are representable authenticated facts and reach gates 1, 4, 7, 8, or 10.
- A nonempty malformed identifier, invalid NPI, over-bound count, duplicate diagnosis, invalid
  money encoding or type, total mismatch, overflow, unknown fact, bad path, missing policy evidence,
  unauthenticated oracle record, wrong version/profile, or extra/missing schema field is structural
  invalidity. It rejects the witness before a denial is produced.
- Authenticated policy nonmembership passes gate 9's TAR check and fails gate 11. Missing or
  ambiguous policy evidence is structural invalidity, not policy nonmembership.

## 9. Required convergence and calibration tests

Before review can freeze these packages:

1. Exercise every bound at `max-1`, `max`, and `max+1`, including the worst case of 50 required
   authorizations in every claim.
2. Reject missing, extra, duplicate, reordered, truncated, trailing, overlength, and noncanonical
   schema input.
3. Use variable-length procedure and authorization tokens, all input permutations, duplicate
   diagnoses, and duplicate service-line identities in cross-language vectors.
4. Test approval, each individual denial, every denial pair, all denials together, and malformed
   counterparts. Python, Rust, Cairo, and RISC must agree on accept/reject, decision, and first code.
5. Put real approvals, every denial, and covers at every slot position. Test zero, reused, and
   cross-domain nullifiers and both sequential root transitions.
6. Compare bottom-up claim/oracle roots and sequential nullifier roots with independent reference
   implementations.
7. Assert the exact ordered 12-field ABI and scan public artifacts for decisions, amounts, counts,
   and synthetic witness tokens.
8. Measure K128, K256, and K512 using the worst fixed shape. Record peak resident memory, trace
   construction, commitments, proving, verification, proof bytes, and each stage percentage. Stop
   on paging, OOM, a cross-language mismatch, or any unexplained dimension change.

Only measured evidence and morning review can convert the K256 design point into a governed
capacity. This draft intentionally leaves `A01-A06` open.

## 10. Wave 1A executable reference evidence (non-normative)

The 2026-07-18 Wave 1A development slice adds executable, synthetic-only evidence without selecting
a proof suite or changing the protected 12-field boundary:

- `witness_schema_reference.py` validates the complete fixed K128/K256/K512 interchange shape and
  the noncryptographic relations described above. A K128 fixture containing one approval and 127
  covers passes; duplicate JSON keys, floats, nested extras, count drift, broken nullifier chains,
  and a felt at the field modulus reject.
- `claim_truth_reference.py` turns every real or cover slot into fixed-length claim-source,
  oracle/authorization, and policy records, binds the exact gate taxonomy in a ruleset record, and
  derives the historical legacy root plus the authoritative SHA3-512 root from the same canonical
  bytes. The successor public relation uses only the wide root and its proved nonzero projection.
  A separately supplied governed-root tuple is mandatory at its fail-closed comparison boundary.
- `pq_sparse_tree_reference.py` adds a level-default sparse dual-tree candidate for the depth-16
  governed policy map. Work is proportional to populated entries times depth rather than all 65,536
  leaves. This is a synthetic reference domain, not a selected production Merkle construction.
- `pq_tree_reference.py` retains historical Poseidon bulk/scalar parity evidence. That adapter is
  outside the successor authoritative proof and is not a replay or settlement lane.
- Dense and sparse references emit and independently verify historical legacy plus authoritative
  SHA3-512 membership/nonmembership paths. Only the wide paths feed the successor relation;
  `claim_truth_reference.py` still retains both to detect migration drift.
- `pq_strong_nullifier_reference.py` implements a synthetic depth-64 full-width indexed tree with
  exact predecessor/insertion multiproofs. `authenticated_payment_reference.py` advances an
  aggregate SHA3-512 payment state and operation-log root for all K slots.
- `wave1a_relation_reference.py` composes a pinned K128 approval/denial/cover KAT across all governed
  paths, 129 authoritative replay transitions including salt-use, payment
  state, internally derived A12 attempt/cover keys, the exact 12 ordered compatibility fields, and a
  wide batch commitment.

The K128 governed-root KAT and source/oracle/policy/path/replay/payment/ordered-field mutation tests
pass. Real and cover payloads have identical lengths inside each reference lane. The composed
relation requires `nullifier_derivations_authenticated=true`: the verifier recomputes the frozen
A12 derivations and rejects authority/pepper drift against the registry binding. No concrete proof
AIR, authoritative durable state, proof
transcript, native hiding, strict-PQ suite, or production verifier exists. `A02-A16`, `P01-P10`, and
`T01-T10` therefore remain open under their complete closure conditions except that A12 is complete
as an application-semantics freeze.

## 11. R25 host-reference evidence (non-normative)

R25 implements the provisional relation as a synthetic host reference, not a physical AIR. It
exercises K128, K256, and K512 over all-cover, approval-plus-cover, denial-plus-cover,
mixed-half-real, and full-capacity-real shapes. The accompanying deterministic corpus contains 20
named cases; property coverage evaluates all 8,191 nonempty failure subsets and 3,840 K256
case/position placements.

The heaviest fresh K512/full-capacity host-model construction took `2.5877058s`, with
`15.886984%` fixture construction, `41.423886%` logical trace, `42.246367%` payment economics, and
`0.442763%` operation logging. This does not measure proving. Physical rows and columns remain
unknown, proof count is zero, and no capacity, proof suite, hiding construction, or strict-PQ
parameter is selected by this evidence. A01-A16 therefore remain open.

## 12. Unsealed R26 physical calibration observations (non-normative and rejected)

R26 source implements a narrow physical AIR for decision priority and limb-based payment conservation so
that physical dimensions and prover costs are no longer inferred from the Python host model. It is
not the complete claim AIR described by this document. In particular, it does not prove the
12-field statement, source/oracle/policy membership, authoritative nullifier transitions,
SHA3-512 shadow state, native witness hiding, or the `BL-PQ512-v1` proof profile. Fixture class is
local calibration metadata and is not proof-bound. R26 has no terminal manifest or terminal seal;
R28 requalified the applicable measurements under its own terminal evidence without retroactively
sealing R26.

The serialized synthetic matrix exercised 17 shapes for each of K128, K256, and K512: approval,
each of 13 individual denial gates, cover, mixed, and maximum approval. All 51 proofs verified and
were immediately discarded; no proof artifact was written. Every shape used 267 physical trace
columns, one interaction column, and 476 constraints. The measured rows and proving ranges were:

| Profile | Rows | Average prove | Prove range | Maximum verify | Maximum estimated proof bytes | Maximum peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| K128 | 128 | `0.051942850s` | `0.048704777-0.057718529s` | `0.002575530s` | 12,052 | 4,964 KiB |
| K256 | 256 | `0.070609592s` | `0.065606690-0.082520215s` | `0.001694571s` | 13,028 | 5,760 KiB |
| K512 | 512 | `0.086222081s` | `0.077236848-0.105594107s` | `0.001752768s` | 14,100 | 7,252 KiB |

The matrix is permanently labelled `REJECTED_VALIDITY_ONLY_CALIBRATION`, with
`witness_hiding=false`, `proofSuiteId=null`, and activation forbidden. A paired
witness-hiding-required invocation exited with `WITNESS_HIDING_UNAVAILABLE` before fixture, trace,
commitment, or proof timing. The separate legacy 1,024-claim validity-only calibration reported
`0.115831s` proving, `0.000197s` verification, and 4,084 KiB peak RSS; it binds only aggregate
decision and value conservation and has the same non-private boundary.

The proof-size estimate varied between fixtures even when the physical row/column dimensions were
identical. The unsealed R26 observations therefore do not establish fixed proof bytes, shape indistinguishability, or
inference resistance.

These measurements establish that the earlier multi-second Python host construction was not a
physical-proof latency estimate. They do not select K256, demonstrate witness privacy, establish a
quantum-security budget, or close any A01-A16 package. All A01-A16 packages remain open.

## 13. R33 historical Wave 1A relation-inventory estimate (nonactivating)

R33 implements the complete host semantic relation, then declares an inventory in
`experiments/fixed_shape_claim_air/physical_air_reference.py`. Sixteen proposed tables cover canonical
witnesses, claim gates/money, service lines, diagnoses, facts, authorizations, claim/oracle/policy
paths, legacy/strong replay, benefit and obligation maps, private asset transfer, operation logging,
and the exact ordered public statement. The schedule depends only on the calibration profile, not on
approval, denial, or cover.

`authenticated_payment_maps_reference.py` uses domain-separated depth-64 append-indexed ordered maps
with complete 512-bit keys and typed fixed-width 512-bit values. Positions never replace or truncate
keys. Approvals update scoped member benefit counters, create a unique claim/provider obligation,
debit funded payer reserve, and credit provider payable. Denials and covers update four
scope/domain/epoch-bound, precommitted zero-valued dummy leaves under the same
one-benefit/one-obligation/two-ledger schedule. Inserts consume the authenticated allocator;
updates prove its current leaf empty but leave the cursor unchanged. Every slot appends a typed
operation commitment, so zero-economic slots do not create durable records or allocator holes.

`ordered_map_batch_reference.py` removes redundant per-upsert upper-path hashing without weakening
the sequential relation. The mixed K128 fixture uses 398 internal-node hashes because its 127
zero-economic slots reuse dummy leaves; this observed count is never a proof dimension. The
governed physical envelope uses 24-bit shards and pads the three K128 lanes to 34,026 node hashes,
2,048 leaf-hash slots, six headers, 36,080 SHA3-512 calls, and 74,208 Keccak permutations.
Independent four-root paths would require 131,072 internal-node hashes before equivalent padding.
The optimization is accepted only because endpoint roots, allocator cursors, predecessor links,
empty allocated slots, operation order, and per-position before/after chains are all rechecked.
The schedule bound is executable and attack-tested; the padded AIR tables and durable
rollover/migration proof remain open.

R34 corrects the scope and canonical-input boundary. `BenefitScopeV1` commits payer authority, plan
ID, inclusive benefit-period start/end ordinal days, and the fixed asset-registry root under its own
SHA3-512 domain. The v2 payment-state root includes that commitment, member-benefit keys include the
same commitment, and a batch rejects any before/after scope drift. Different payer, plan, or period
therefore produces a different state namespace. `None` remains the only default for an empty
provider-balance map; falsey non-mappings such as `[]`, `""`, `0`, and `False` are rejected rather
than silently reinterpreted. Authoritative publication and custody of the scoped before-state remain
Wave 1C work. The canonical boundary accepts only the exact frozen `BenefitScopeV1` type, preventing
a Python subclass from overriding the committed bytes.

The following values are historical declarations. The module has no trace cells, polynomial
identities, boundary/transition evaluator, lookup-multiset check, or serialized verifier statement;
the values MUST NOT drive theorem selection, security estimates, or performance claims.

| Profile | Declared logical rows | Declared padded rows | Declared columns | Declared constraints | Declared max degree | Declared message width | Commitment groups | Declared padded cells | Historical `D_eff` estimate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| K128 | 753,164 | 848,272 | 2,279 | 4,844 | 3 | 276 | 4 | 114,853,632 | 1,427,283,902,464 |
| K256 | 1,519,500 | 1,696,528 | 2,279 | 4,844 | 3 | 276 | 4 | 229,705,856 | 2,854,567,804,928 |
| K512 | 3,065,484 | 3,397,136 | 2,279 | 4,844 | 3 | 276 | 4 | 459,803,520 | 5,709,135,609,856 |

`test_data/bl_wave1a_physical_relation_vectors_v1.json` pins the metadata, and the independently
typed Rust surface in `experiments/bl_pq512_crypto_core/src/wave1a_dimensions.rs` repeats every
declared dimension and SHA3-512 program commitment. This is declaration parity, not independent AIR
verification. The Python harness recomputes the full host relation,
every slot binding, and the program/trace commitment and rejects wrong profile, root, slot, program,
backend, proof, or production flags.

This paragraph records the historical R33 metadata checkpoint, not the current boundary. The
semantic reference is retained and still reports `physical_relation_constrained=false`; R36 later
built and independently evaluated the executable Wave 1A relation described in
`docs/WAVE1A_EXECUTABLE_AIR_SPEC.md`. Current Wave 2 now has a real independently verified kernel
proof, but not a complete K128 application proof, qualified native hiding, compact final grammar, or
suite ID; `proofSuiteId=null`, activation and production use remain false.
