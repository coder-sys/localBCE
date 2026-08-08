# BL-PQ512 S07-S12 pre-implementation freeze

Status: **synthetic-only, review-ready local specification; not an activated proof suite and not a
production-security claim.**

Run: `20260715T221859Z-s07-s12-freeze-r24`

Executable status: **the complete synthetic specification/reference matrix is accepted and recorded
in `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/terminal_manifest.json` with its
adjacent SHA-256 seal; it generated zero proofs.**

Current planning interpretation: this sealed freeze remains historical evidence and the R24 suite
remains rejected. `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md` now defines implementation as
internally finishable and moves independent review to the single final audit gate. That planning
change does not select a suite, assign `proofSuiteId`, activate a verifier, or alter sealed R24
evidence.

Current architecture interpretation: R24 remains the immutable rejection/parameter freeze. Wave 2
now realizes its replacement direction as the heterogeneous semantic-STARK/shared-bus/Boolean-GKR
construction in `docs/CURRENT_TECH_STACK.md`. H4 now attaches the bridge, native GKR masks,
Construction 8.2 PCS, and complete one-run K128/K512 proofs through independent verification. This
does not alter sealed R24 bytes or select `proofSuiteId`. The later Gate 2E context is sealed
nonactivating, the exact H5 campaign passed, and the bounded H6 candidate-evidence manifest closed
all twelve records; production verifier/state/custody, suite selection, and activation remain open.

This is the durable context-restoration document for the R24 work through roadmap items S07-S12.
It preserves the exact Privacy V2 `bytes32[12]` boundary. It does not generate a proof, activate a
verifier, select an unreviewed proof suite, use real data, or authorize real deployment.

## 1. Outcome in plain English

The old fast proof path is permanently rejected for BL-PQ512. Its QM31 challenge field,
BLAKE2s-256 commitment/transcript path, default three-query FRI configuration, proof-borne
parameters, and missing native witness hiding cannot meet the stated privacy and post-quantum
requirements.

The replacement direction is now physically specified: retain M31 for semantic trace arithmetic,
use Fp16 challenges, keep SHA3-512 authoritative, and prove the repeated Boolean hash work in a
masked shared-bus coprocessor instead of the generic wide-column PCS. It is not yet a qualified
suite. The suite identifier therefore remains unset and activation remains forbidden.

R24 pushes the design through S12 by making the budget, rejection result, candidate encoding,
sidecar, lifecycle, formal relation, error taxonomy, and remaining blockers explicit. It does not
mislabel unresolved cryptography or unimplemented payment semantics as complete.

## 2. Non-negotiable boundaries

1. The external application ABI remains exactly 12 ordered `bytes32` values with the names and
   types in `ops/native_stark_public_inputs_v2.json`.
2. The authoritative strict-PQ context is a separate fixed-length sidecar and verifier state. It is
   not a thirteenth ABI field and is never reduced to one felt or one `bytes32`.
3. All examples, vectors, adapters, witnesses, and tests are synthetic only.
4. A proof selects no field, hash, FRI, query, grinding, parser, schema, or verifier parameter.
5. Unknown, zero, mixed, inactive, old, malformed, alternate, truncated, or trailing encodings
   fail before large allocation or proof work.
6. Grinding receives zero credited security bits. The authoritative interactive profile has no
   prover-selected grinding credit.
7. No real PHI, credentials, external mutations, dependency upgrades, or release claims are
   permitted by this freeze.

## 3. S07 quantum-security budget

The conservative candidate policy is:

| Quantity | Candidate ceiling or target |
| --- | ---: |
| Quantum work/query boundary | at least `2^128` total quantum random-oracle queries |
| Total quantum random-oracle queries `Q` | at most `2^128` |
| Separately attackable lifetime targets `N` | at most `2^64` |
| Positive error terms `J` | at most 64 |
| Per-term round-by-round exponent `s` | at least 384 |
| Hash output | 512 bits |
| Residual adversarial-advantage target at that query boundary | at most `2^-32` |
| Grinding credit | 0 bits |

For the historical schematic Fiat-Shamir/QROM reduction considered by R24

```text
C * N * J * (Q^2 * 2^-s + Q^3 * 2^-h),
```

equal half-budget sufficient exponents for the two displayed branches are:

```text
s >= 2*128 + 64 + 6 + 33 + ceil(log2(C)) = 359 + ceil(log2(C))
h >= 3*128 + 64 + 6 + 33 + ceil(log2(C)) = 487 + ceil(log2(C))
```

Choosing `s=384` and `h=512` makes each displayed branch `C*2^-58`; adding the two branches gives
`C*2^-57`. The combined displayed bound therefore has 57 exponent bits before constants and only
25 bits of multiplicative slack over the provisional `2^-32` residual target. Under exactly these
two branches and no other positive term, that target requires `C<=2^25`. Every additional positive
term needs its own explicit sub-budget or a proved domination argument.

This draft targets the pair `(Q*, epsilon*)=(2^128, 2^-32)`: 128 is the quantum work/query boundary,
while 32 is the negative logarithm of the permitted residual adversarial advantage at that boundary.
It is not a spontaneous system-failure probability, and satisfying this pair is necessary but not
sufficient for an at-least-128-bit quantum work-factor claim. The displayed `Theta` expression is
schematic rather than an upper-bound theorem. This worksheet is not a security proof for the
complete multi-table Circle-STARK, LogUp, native-hiding, and transcript composition. The later S09
solution excludes Fiat--Shamir from the authoritative interactive launch profile; this worksheet is
retained only as rationale for keeping any future noninteractive module separately gated.

`J` counts every positive error contribution. Splitting one contribution across tables, rounds,
folds, commitments, or reductions does not make it disappear from the union bound.

If the same residual-advantage policy is adopted for statistical hiding across `2^64` proofs, the per-proof
distance must be at most `2^-96`; with 64 separately accounted leakage terms, each term must be at
most `2^-102`. This is a candidate policy target pending the final simulator, not a proved property.

## 4. S08 rejection and conditional algebra/FRI envelope

The current configuration is rejected:

- QM31 supplies fewer than 124 classical challenge bits and roughly 62 generic quantum-search
  bits before degree, table, target, and reduction losses.
- BLAKE2s-256 has an idealized generic quantum collision ceiling of about 85.33 bits.
- The current S-two default is 10 grinding bits, blowup log 2, and three queries. Its 13-bit helper
  value is not a total classical or quantum security claim.
- The current verifier accepts configuration carried with the proof. A BL-PQ512 verifier must pin
  the complete suite independently before parsing proof-selected content.
- Extra queries cannot repair an undersized challenge field or commitment digest.

For base `p=2^31-1`, requiring `D_eff / p^d <= 2^-384` gives:

| Extension degree | Maximum integer `D_eff` |
| ---: | ---: |
| 12 or lower | impossible even for 1 |
| 13 | 524,287 |
| 14 | 1,125,899,899,502,592 |
| 15 | 2,417,851,622,340,759,801,823,231 |
| 16 | 5,192,296,819,849,201,535,970,351,266,136,064 |

Degree 16 is the first viable power-of-two/quadratic-tower candidate after degree 8. It is not the
only possible mathematical degree. Until exact AIR dimensions exist, the conservative pre-code
envelope is `D_eff <= 2^111`.

For the isolated query term:

```text
epsilon_query = (1-theta)^queries
queries_min = ceil(384 / -log2(1-theta))
```

At the illustrative, unselected `theta=0.45`, the minimum is 446 queries and 512 queries provide
`441.598195840033` query bits. In the proven Johnson regime with rate `rho=2^-beta`, the contribution
is strictly below `beta/2` bits per query; near the boundary the minimum integer counts are 769,
385, 257, and 193 for `beta=1,2,3,4`. The final rate, distance, list bound, folding schedule, query
policy, and count remain unset.

## 5. S09 candidate suite and encoding freeze

The machine-readable candidate is `docs/bl_pq512_suite_candidate_v1.json`. Its required state is:

```json
{
  "status": "CANDIDATE_UNQUALIFIED",
  "activationAllowed": false,
  "proofSuiteId": null
}
```

Zero bytes are not a placeholder suite ID. An active sidecar must contain a known nonzero 64-byte
suite ID selected from authenticated state. R24 freezes the registry structure, big-endian framing,
domain taxonomy, strict parsing, and downgrade rules; it does not freeze the degree-16 polynomial,
PCS/FRI theorem instantiation, exact challenge schedule, proof sections, native-hiding inventory,
or final proof-suite identity.

Suite identity is modular. Independent module identities cover:

1. application encoding/framing;
2. SHA3-512 application state trees;
3. challenge-field algebra;
4. PCS/Circle-FRI;
5. interactive public-coin transcript;
6. witness hiding;
7. security budget and multi-target accounting; and
8. proof-body format.

The composite `proofSuiteId` binds all eight module identities. Custody KEMs and authorization
signatures have separate independently rotatable profile identities; they are not silently folded
into the proof-system ID.

All unsigned integers are big-endian. Canonical Stark felts are exactly 32 big-endian bytes and
strictly below the Stark field modulus. M31 values are exactly four big-endian bytes and strictly
below `2^31-1`. No signed integers, floats, Unicode normalization, modulo repair, implicit lengths,
language-native serialization, or alternate byte order is allowed.

## 6. S04 authenticated sidecar candidate

The exact candidate sidecar is **744 bytes**, separate from both the 12 fields and the proof body:

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 8 | ASCII `BLPQSC01` |
| 8 | 2 | encoding version, `u16be`, exactly 1 |
| 10 | 2 | flags, `u16be`, exactly 0 |
| 12 | 4 | total length, `u32be`, exactly 744 |
| 16 | 64 | `profileId` |
| 80 | 64 | `proofSuiteId` |
| 144 | 64 | `schemaId` |
| 208 | 64 | `verifierArtifactIdentity` |
| 272 | 64 | `strongSettlementDomainId` |
| 336 | 8 | `epoch`, `u64be` |
| 344 | 8 | `sequenceBefore`, `u64be` |
| 352 | 8 | `sequenceAfter`, `u64be` |
| 360 | 64 | `strongNullifierRootBefore` |
| 424 | 64 | `strongNullifierRootAfter` |
| 488 | 64 | `strongGovernanceCommitment` |
| 552 | 64 | `strongPaymentStateRootBefore` |
| 616 | 64 | `strongPaymentStateRootAfter` |
| 680 | 64 | `strongBatchCommitment` |

Every 64-byte value is nonzero. `epoch>0`; `sequenceBefore<2^64-1`;
`sequenceAfter=sequenceBefore+1`; the two nullifier roots differ; and the two payment-state roots
differ because every slot appends a fixed operation record even when economics are zero. This
prevents root equality from revealing an all-denied or all-cover batch.

The historical `strongNullifierRoot` name denotes the authoritative typed replay registry, not a
claim-nullifier-only set. Its depth-64 append-indexed linked ordered tree retains each complete
512-bit key and successor key/index, and its authenticated header carries the next append index. Every
K=256 transition inserts the 256 ordered attempt-or-cover nullifiers and then exactly one hidden
`SALT_USE` key at canonical insertion position 256. The salt-use preimage is exactly:

```text
ASCII("BLPQSALT") || u16be(1) || u16be(259) || u16be(64) || rawMasterSalt[64]
```

and `saltUseTag=SHA3-512(preimage)`. It deliberately contains no nonce, batch, sequence, epoch,
settlement domain, profile, schema, or suite, so changing context cannot disguise reuse of the same
raw master salt. The relation proves nonmembership under the before root and insertion under the
after root; the tag and salt stay private. This replay state survives epoch, domain, schema, suite,
migration, and recovery changes. A separate salt registry may be diagnostic only. This proves
non-reuse, not entropy quality; CSPRNG health remains an operational gate. The current synthetic
state reference still uses a separate salt registry and therefore remains implementation-parity
evidence to replace, not an implementation of this candidate rule.

The 2026-07-18 A12 continuation separately freezes the slot-key identity in
`docs/BL_PQ512_A12_NULLIFIER_FREEZE.md` and the candidate registry. A real attempt uses only the
governed source authority, source claim ID, and attempt/revision/parent tuple plus one private
registry-lifetime pepper. Batch, slot, claim facts, decision, policy/oracle state, payer/provider/
member data, epoch/profile/domain, and proof randomness are excluded. A cover binds profile, strong
domain, epoch, batch nonce, slot index, and a fresh private 512-bit nonce under domain 258. Each slot
has one authoritative SHA3-512 key; its ABI felt is the proved nonzero reduction modulo `p-1`.
The governance commitment binds the replay authority ID and pepper
commitment; any batch-level change fails closed and requires a future atomic full-registry migration.
This closes A12 semantics, not the physical AIR or S09 proof primitive selection.

For the synthetic KAT salt `a5` repeated 64 times, the tag is
`19efd77aca927b75afed0876e377870cf9ec7c30e30f9cd5cc196471e9897d0af3d9c0cee84d5c59e01acc9f3abddb2134b63c42098ac930fc29b538bb759b4f`.

`strongSettlementDomainId` gives the state transition a full-width authoritative domain binding.
The ACTIVE tuple also authenticates the exact legacy protocol alias `BE32(2)` and the exact canonical
legacy settlement-domain felt. Its profile/governance record binds that legacy/strong domain pair;
the circuit requires fields 0 and 1 to equal the authenticated aliases and the sidecar ID to equal
the authenticated strong ID. The strong ID is never derived by padding, truncating, or hashing the
legacy alias, and a matching alias cannot excuse a mismatching strong ID. `strongBatchCommitment` is a typed
SHA3-512 commitment over the exact 680-byte sidecar prefix, all 12 ordered legacy fields, the
canonical private-batch commitment, the hidden strong value commitment, and one fresh hidden
64-byte master salt. It excludes itself and proof randomness, avoiding a circular definition and
allowing proof-body rerandomization without changing the authenticated statement.

The preferred verifier API receives three distinct objects:

```text
publicOutputs[12], sidecar[744], proofBody[]
```

Exact repeats of the same authenticated public statement necessarily expose identical
`publicOutputs` and sidecar and are therefore linkable as repeats. Zero knowledge cannot remove
that statement-level equality. The privacy requirement is randomized proof transcripts, witness
privacy, and no additional linkability beyond what the authenticated public statement itself
reveals; it is not absolute unlinkability of identical statements.

If a portable envelope is required, its fixed header is:

```text
magic             8 bytes  "BLPQEN01"
containerVersion  u16be    1
flags             u16be    0
sidecarLength     u32be    744
proofLength       u64be
sidecar           744 bytes
proofBody         proofLength bytes
```

This envelope contains only the sidecar and complete proof body. The exact 384 ordered bytes of
`publicOutputs[12]` remain a mandatory out-of-band settlement argument, are not included in
`proofLength`, and may not also appear in the envelope. The transcript absorbs those 384 bytes
before its first challenge and the strong batch commitment binds them. Missing, duplicated,
reordered, or trailing public-output bytes fail; no parser may infer them from the proof.

The proof-suite registry and sole authenticated ACTIVE tuple, not the proof, pin the permitted proof
length, section grammar, profile, suite, schema, verifier artifact, strong domain, epoch, and legacy
aliases. Structural decode is separate from trusted ACTIVE-state comparison. The parser rejects the
suite and lengths before proof-body allocation and rejects every missing, duplicate, reordered,
unknown, zero, inactive, staged, retired, mixed, truncated, oversized, or trailing value. With
`proofSuiteId=null`, `proofLength=null`, or proof sections unset, every proof remains invalid.

## 7. Pre-freeze A01/A05/A11/P05 decisions consumed by S12

These are exact normative inputs, not claims that their implementation packages are complete:

- v1 design point: `K=256`, `L=50`, `D=16`, `F=6`, `A=50`;
- a 1,024-claim application submission becomes four separately sequenced K256 proof jobs;
- K128 and K512 remain measurement profiles, not alternate semantics;
- every outer slot executes the same claim, fact, authorization, policy, value, legacy-nullifier,
  strong-nullifier, payment-state, and operation-log schedule;
- claim and oracle trees are built bottom-up once; persistent policy uses a fixed authenticated
  dictionary/query table; nullifier updates are sequential in canonical slot order;
- the authoritative strong nullifier is a depth-64 append-indexed linked ordered tree whose records
  retain and compare full 512-bit keys and successor links; an authenticated next-append counter
  makes allocation deterministic; a 64-bit capacity index never replaces or truncates the key; and
- physical AIR rows, columns, degrees, proof bytes, and measured resources remain A05/A16 inputs.

Money is exact unsigned integer cents. Decimal text never enters the proof relation. Every
proof-level claim total, enabled-line charge, enabled-line unit value, governed allowed amount,
approved amount, and payment amount must already be an exact integer--not a boolean--in
`0..4,294,967,295` inclusive. Numeric strings, floats, decimals, booleans, integer subclasses, and
other host values are rejected at that boundary rather than coerced. The per-claim line-charge sum
uses checked wider arithmetic, must itself fit the u32 claim bound, and must equal the authenticated
claim total exactly. A mismatch or arithmetic overflow is structural, never a private denial.

Every K256 slot remains individually u32-bounded. Batch and provider totals use checked wider
arithmetic and are at most `256 * (2^32-1) = 1,099,511,627,520`; no wide aggregate may be narrowed
into a per-claim field. There is no tolerance, rounding, float arithmetic, wrap, saturation, felt
reduction, modulo repair, or truncation in the relation.

Source money must arrive as an ASCII string matching
`^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,2})?$`. JSON numbers, booleans, floats, decimals, integers,
whitespace, signs, exponent notation, commas, leading-zero alternatives, empty fractions, and third
fractional digits are rejected without conversion or normalization. Decoding computes exact
integer cents and never rounds. The prototype's legacy application dataclasses may hold a decoded
major-unit compatibility value outside the proof boundary; source parsing and proof serialization
must never treat that bridge as an alternate wire encoding. Cairo, RISC, and the future AIR receive
only the already-decoded integer.

Zero is a valid encoding. On an otherwise well-formed real claim, a zero total or zero charge or
units on any enabled line fails private gate `G8A_CHARGE_VALID` with hidden code 10 and zero payment.
No enabled lines fails G5. Cover and disabled rows retain their canonical zeros. Exact line-total
mismatch, per-claim sum overflow, or any noncanonical type/encoding remains structural and cannot
be converted into G8A.

The private composite payment state is:

```text
StrongPaymentStateV1 {
  version,
  epoch,
  sequence,
  assetRegistryRoot512,
  benefitAccumulatorRoot512,
  obligationRoot512,
  privateAssetLedgerRoot512,
  operationLogRoot512
}
```

Approval computes gross allowed, patient responsibility, and plan payable; updates benefit cap,
deductible, visits, and authorization state; creates one unique provider obligation; debits a
funded payer-reserve account; and credits provider-payable. Denial and cover have zero economics but
update four scope/domain/epoch-bound, precommitted zero-valued dummy leaves under the same
one-benefit/one-obligation/two-ledger schedule and append one typed operation
commitment. `sum(debits)=sum(credits)=sum(planPayable)`. Insufficient reserve, duplicate obligation,
overflow, underflow, root mismatch, or conservation mismatch is structural batch rejection, never
a private claim denial.

Only the composite payment roots are public in the sidecar. Subroots, amounts, decisions, and
counts remain private. Legacy fields 9 and 10 remain compatibility commitments and are not the
authoritative payment state.

## 8. S10 lifecycle specification

Normal activation uses:

```text
UNCONFIGURED -> STAGED -> READY -> ACTIVE
```

Upgrade and recovery use:

```text
ACTIVE -> DRAINING -> READY(new complete tuple) -> ACTIVE(new complete tuple)
```

`RECOVERY_LOCKED` is the only destination after ambiguous commit/readback. `RETIRED` is terminal.
STAGED and READY accept no proofs.

READY requires a drained queue; exact source, dependency, tool, SBOM, schema, suite, verifier, and
artifact readback; same-record dual-root migration evidence; all synthetic KAT/attack gates; a
complete checkpoint; and all required approvals. Activation is one compare-and-swap of the complete
tuple:

```text
profile, suite, schema, verifier, epoch, legacyProtocolVersion, legacySettlementDomain,
strongDomain, globalSequence,
legacyNullifierRoot, strongNullifierRoot, governanceCommitment,
paymentStateRoot, nonceRegistryRoot, batchRegistryRoot
```

ACTIVE accepts exactly one tuple with no fallback or simultaneous old/new verifier. Every accepted
transition authenticates the exact before tuple, increments the global sequence once, consumes a
fresh nonce and batch identity, verifies typed outputs, and performs one durable atomic
commit-and-readback. Two proofs from one before-state cannot both commit.

Pre-activation rollback discards the entire staged tuple and proves the old tuple unchanged.
Post-activation rollback-in-place is forbidden. Recovery restores one complete checkpoint under a
never-used epoch and strong settlement domain while retaining a globally increasing sequence; all
pending old proofs become invalid.

Any relation, encoding, capacity, field, hash, PCS, FRI, or hiding change requires a new profile or
suite identity. A same-relation verifier rebuild or governance-set change still requires a new
epoch and artifact/governance identities.

## 9. S11 supply-chain status

S11 remains open. R24 verified the in-scope inventory as seven `Cargo.lock` files plus one
root-package-only `Scarb.lock`. Across the overlapping Cargo locks there are 1,206 package entries:
1,185 registry entries with recorded checksums and 21 local/path entries. The foundation SBOM has
only 14 package records, 13 with license `NOASSERTION`, and does not analyze files. These are useful
inventory facts, not a reproducible-build qualification. The package still lacks:

- one complete hash-locked Python transitive dependency set;
- exact root compiler, linker, native-library, container/VM, and operating-system inputs;
- complete license and provenance records;
- the future isolated S-two fork and independent verifier artifact identities;
- clean offline/locked rebuild coverage for every required artifact; and
- a matching second independent builder with reproducible artifact readback.

No documentation wording can replace those artifacts.

## 10. S12 formal relation

The target relation is:

```text
R(activeStateBefore, legacy[12], sidecar744, witnessK256; activeStateAfter) = 1
```

if and only if all of the following hold:

1. `legacy` is exactly 12 canonical Stark felts in the pinned order and sidecar744 parses exactly.
2. Profile, suite, schema, verifier, epoch, strong domain, sequence, and every before-root equal the
   sole ACTIVE state tuple.
3. The witness contains exactly 256 outer slots and every nested count, bound, order, uniqueness,
   padding, text, integer, and encoding rule holds.
4. Each real slot authenticates its claim source, six fixed facts, authorizations, policy/ruleset,
   all 13 gates, and exact first-failure code. Authenticated absence reaches a private denial;
   malformed or unauthenticated evidence is structural rejection.
5. Approval, denial, and cover execute the same logical schedule and each inserts one independently
   derived legacy nullifier and one typed full-512-bit strong replay key in canonical slot order.
   After all 256 slot keys, the relation inserts the one context-free master-salt-use tag described
   above into the same authenticated root.
6. The exact benefit, obligation, double-entry ledger, value-conservation, and operation-log
   transition produces the sidecar payment roots.
7. All 12 legacy fields are recomputed under the v1 formulas, never accepted from the caller.
   Fields 0 and 1 equal the authenticated ACTIVE aliases; fields 9-11 remain compatibility
   commitments.
8. Strong governance binds the protocol/domain alias pair and every legacy alias at fields 5-8 to
   its independently authenticated full-width identity or root.
9. The private batch, strong value, master salt, and strong batch commitments recompute exactly.
10. Sequence, nonce, batch identity, and the one raw master salt are fresh, and `activeStateAfter`
    is the single atomic successor. Every other salt or masking value must be domain-separated from
    that master under the final P05 derivation or receive its own proved freshness rule; P05 remains
    open until those derivations are frozen.

No branch, amount, decision, denial code, claim count, cover count, PHI, payment subroot, or raw or
encrypted medical payload may become public.

BL-PQ512-v1 is original-attempt-only: `attemptVersion=1`, `revisionKind=ORIGINAL`, and
`parentAttemptVersion=0`. Correction, replacement, and void attempts are structural
`REVISION_NOT_AUTHORIZED` until a separately governed revision-capable schema is frozen. The future
124-proof campaign must test correction as an expected rejection unless that later schema exists.

## 11. Error taxonomy and external behavior

Private denial codes 0-13 are valid witness results and remain hidden. They are not parser or
verifier errors.

Structural families include:

```text
STRUCTURAL_ENCODING
STRUCTURAL_BOUND
STRUCTURAL_MONEY_ENCODING
STRUCTURAL_MONEY_RANGE
STRUCTURAL_MONEY_TOTAL_MISMATCH
STRUCTURAL_ARITHMETIC_OVERFLOW
STRUCTURAL_ORDER
STRUCTURAL_DUPLICATE
STRUCTURAL_AUTHORITY
STRUCTURAL_PATH
STRUCTURAL_NULLIFIER
STRUCTURAL_PAYMENT_STATE
STRUCTURAL_VALUE_CONSERVATION
REVISION_NOT_AUTHORIZED
```

Verifier/state families include:

```text
ENVELOPE_INVALID
PROFILE_INACTIVE
SUITE_INACTIVE
SCHEMA_INACTIVE
VERIFIER_ARTIFACT_MISMATCH
PROOF_INVALID
VERIFIED_OUTPUT_MISMATCH
STALE_STATE
REPLAY
GOVERNANCE_MISMATCH
PAYMENT_STATE_MISMATCH
ATOMIC_COMMIT_FAILED
READBACK_AMBIGUOUS
RESOURCE_LIMIT
ENTROPY_FAILURE
```

Internal audit records may retain the stable family and synthetic correlation identifier without
PHI. The external API exposes one fixed-size, fixed-cadence `REJECTED` response for all invalid or
denied outcomes unless a separately reviewed business interface permits a disclosure.

## 12. Acceptance gates before any activation

Activation remains impossible until all of these are true:

1. Internal qualification approves the exact S07 accounting, interactive Circle-STARK soundness,
   challenge-service assumptions, and finite retry/abort-grinding ledger; the sealed result later
   enters the single independent audit gate.
2. The final physical AIR proves its exact `D_eff`, table/message/fold counts, and conservative
   soundness envelope.
3. The degree-16 tower/basis, PCS/Circle-FRI layout, transcript, query policy, proof grammar, and
   complete suite ID are selected and KAT-tested.
4. A complete native-hiding simulator and oracle inventory prove the adopted lifetime privacy
   target, proof-transcript rerandomization, and no additional linkability beyond equality of the
   authenticated public statement.
5. Python, Rust, Cairo, RISC, the custom AIR, parser, verifier, and state owner agree on every
   semantic and byte boundary.
6. The payment/benefit/double-entry relation exists in every semantic lane and the AIR.
7. Sidecar, downgrade, stale-state, replay, malformed-proof, competing-before-state, and atomicity
   attacks pass.
8. S11 reproducibility and supply-chain gates pass.
9. All fixed-shape, privacy-artifact, leakage, cadence, resource, Rust, Cairo, database-boundary, and release
   gates pass using synthetic data.
10. Independent cryptographic, implementation, privacy, and operations reviews approve release.

## 13. Honest roadmap status after R24

| Package | R24 result |
| --- | --- |
| S07 | Audited quantitative draft; remains open pending complete theorem/constants, final AIR, custody reductions, and external review |
| S08 | Current suite conclusively rejected; conditional envelope corrected; remains open pending exact AIR and selected construction |
| S09 | Exact candidate registry/framing/domain/downgrade specification; suite ID remains null and activation forbidden |
| S10 | Exact lifecycle draft and candidate parser/sidecar attacks; remains open until selected identities, payment semantics, lifecycle reference implementation, and atomicity/competing-state attack coverage exist |
| S11 | Inventory plus one local offline/locked RISC-host rebuild; remains open for complete pins, provenance, licenses, coverage of every required artifact, and matching two-builder reproducibility |
| S12 | Complete formal-statement draft and blocker ledger; remains open until its cryptographic and semantic dependencies actually pass |

The local work is substantial, but package status follows evidence rather than wording.

The historical R24 regression inventory was 674 unique Python nodes (572 non-attack, one exact
differential, and 101 attack) plus 198 Python subtests. With 48 rules-Rust tests, 48 RISC-model
tests, four custom-AIR tests, ten Cairo declarations, and 23 now-retired Forge tests, the observed
top-level total was 807. Nine Cairo declarations remained empty-bodied. These are historical
coverage counts, not the current test inventory or proof throughput.

### R33 Wave 1A semantic handoff and R36 executable-AIR correction

R33 completes the synthetic, nonactivating host semantic boundary authorized by this freeze. It
adds authenticated per-member benefit accumulators, unique provider obligations, payer-reserve and
provider-payable balances, reserved equal-work denial/cover map lanes, and a typed operation-log
append for every slot. Its 16-table object declares proposed rows, columns, constraints, degree,
message width, commitment groups, cells, and an interface-level `D_eff` estimate. A later audit
proved that it hashes host results but has no trace cells, identities, lookup argument, or constraint
evaluator. Python/`no_std` Rust parity pins the same declarations only; it does not freeze an AIR.

This satisfies the Wave 1A semantic handoff, not the executable-AIR handoff or activation gate 2.
R36 must build explicit application/SHA3-512/Poseidon constraints and independently evaluate them
before Wave 1B expands the measured program into theorem-matched PCS/FRI, native hiding, and the
concrete S07 error ledger. R33/R36 keep `physicalRelationConstrained=false`, `proofSuiteId=null`,
`activationAllowed=false`, `concreteStarkBackendSelected=false`, `proofGenerated=false`, and
`productionUsable=false`.

R34 is a corrective amendment to that handoff. It replaces the unscoped member key with a typed
payer-authority/plan/benefit-period scope, commits the scope into the v2 payment-state root and every
member-benefit key, rejects scope drift, and rejects falsey non-mapping initial balance inputs. It
does not instantiate a proof port or alter any activation flag.

R35 begins the Wave 1B instantiation without changing this freeze. Authenticated Fp8-excluding OODS,
scalar degree-corrected Circle-FRI, projection-consistent SHA3-512 mixed-domain trees, an exact six-
candidate interface sweep, typed theorem messages, and the conservative pre-dense-schedule 16-table hiding worksheet
now execute. A cross-language direct Circle trace-evaluation CRT certificate covers the OODS point,
its transition translate, and base queries. A canonical quotient mask and source-aligned split rule
now execute, as does a byte-oriented SHA3-512 AIR reference with a 1,632-column/1,024-lookup core
and full 1,704-column/1,096-first-round-lookup sponge envelope with
Python/Rust KAT parity. An exhaustive 52-callsite classification and first K128 conservative
host-verifier measurement recorded 401,275 AIR calls, 1,205,016 permutations, and 28,920,384 Keccak
round rows without selecting parameters. The later `51*K` rerun is also historical: R36 replaced
the redundant per-record paths with one exact, bijective 2,133-byte bundle per claim and a single
ordered execution root, while a separate audit tree reuses the leaf digests. The current claim-tree
compact-source plus packed-oracle schedule costs 14,322/28,644/57,288 permutations at K128/K256/K512. Fixed
non-dense application-port
schedules, final split log-degree/prover integration,
lookup-interaction expansion, selected rate/query profile, Circle simulator, production prover/verifier, and complete
S07 substitution remain open. `proofSuiteId=null`,
`activationAllowed=false`, and proof generation remains forbidden.

## 14. Primary references

- S-two whitepaper: <https://eprint.iacr.org/2026/532>
- Fiat-Shamir security of FRI and related SNARKs: <https://eprint.iacr.org/2023/1071>
- Circle STARKs: <https://eprint.iacr.org/2024/278>
- Adding zero knowledge to STARKs: <https://eprint.iacr.org/2024/1037>
- Brassard-Hoyer-Tapp quantum collision algorithm: <https://arxiv.org/abs/quant-ph/9705002>
- NIST FIPS 202: <https://csrc.nist.gov/pubs/fips/202/final>
- NIST FIPS 203: <https://csrc.nist.gov/pubs/fips/203/final>
- NIST FIPS 204: <https://csrc.nist.gov/pubs/fips/204/final>
- NIST FIPS 205: <https://csrc.nist.gov/pubs/fips/205/final>
