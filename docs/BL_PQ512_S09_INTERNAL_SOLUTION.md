# BL-PQ512 S09 internal cryptographic construction

Updated: 2026-07-22

Status: **historical construction-lineage record. H4 supersedes this document's R35 kernel and
BaseFold/Circle-FRI implementation status with the current 168-layer native-masked GKR plus
Construction 8.2 prototype in `docs/CURRENT_TECH_STACK.md`. At this record's checkpoint, S09,
H5, and H6 were still open. Later current records close the bounded H4/H5/H6 candidate evidence
without assigning `proofSuiteId`; production verifier/state/custody and final module identity remain
open.**

Machine-readable safety state:

```text
authoritativeTranscript = PQ_AUTHENTICATED_PUBLIC_COIN_INTERACTIVE
fiatShamirAllowed = false
qromReductionRequiredForAuthoritativeMode = false
proofSuiteId = null
activationAllowed = false
productionUsable = false
```

This record resolves the false choice between promoting the rejected QM31/Blake2s kernel and waiting
for an outside library to ship Blind Ledger's exact suite. Blind Ledger will build the missing
cryptographic modules internally and submit only the finished sealed release to the final independent
audit. It does not relax the strict post-quantum target.

## 1. Evidence classification

### Observed

- The vendored S-two proof engine hard-wires QM31 as its secure field and does not contain a
  degree-16 secure-field implementation.
- The vendored dependency graph contains Blake2 but no SHA3/Keccak implementation suitable for the
  required full-width proof commitments.
- S-two's prover draws challenges after trace, composition, and FRI commitments, then derives query
  positions after its final channel state. Its channel and Merkle interfaces are partly modular, but
  secure-field types are used throughout the proof engine.
- The current physical kernel is validity-only, uses the rejected suite, and has no native witness
  hiding.
- The R32 integration inventory found 77 vendored Rust files coupled to `SecureField`/QM31. The
  high-level AIR, composition, OODS, PCS/FRI, proof object, and SIMD path cannot be converted by a
  channel feature toggle; reusable low-level M31/domain/FFT primitives must sit below a separately
  reviewed sibling engine or reviewed vendor patch series.

### Inferred

- Adapting S-two is a real internal fork, not a configuration change. The field, channel, PCS,
  serialization, verifier, and tests must change together.
- Applying Fiat--Shamir would require an exact quantum-random-oracle reduction and constants for the
  final protocol. Keeping Fiat--Shamir out of the authoritative launch profile removes that transform
  and its unresolved QROM loss from the launch proof.
- An accepted interactive transcript remains subject to the soundness theorem and parameters of the
  underlying public-coin Circle-STARK. Public-coin operation does not repair a weak FRI profile or
  missing hiding.

### Selected

1. Keep M31 trace arithmetic and extend the existing S-two tower to an M31 degree-16 challenge field.
2. Use SHA3-512 for proof-system commitments, transcript roots, contribution commitments, challenge
   derivation, and audit roots.
3. Make a PQ-authenticated, public-coin, interactive transcript the only authoritative launch mode.
4. Keep noninteractive Fiat--Shamir disabled. It may be added later only as a separately identified
   module after its exact QROM theorem, constants, and multi-target accounting pass the same gates.
5. Recover throughput with independent-session parallelism and pipelining, never by reducing the
   field, hash width, queries, hiding, or audit evidence.

## 2. Frozen degree-16 algebra reference

Let `p = 2^31 - 1`. The reference tower is:

```text
Fp   = M31
Fp2  = Fp[i]  / (i^2 + 1)
Fp4  = Fp2[u] / (u^2 - (2+i))
Fp8  = Fp4[v] / (v^2 - u)
Fp16 = Fp8[w] / (w^2 - v)
```

The canonical flat basis is:

```text
1, i, u, iu, v, iv, uv, iuv,
w, iw, uw, iuw, vw, ivw, uvw, iuvw
```

An element is exactly 16 canonical M31 coefficients. Each coefficient is four-byte big-endian and
strictly less than `p`; the complete encoding is exactly 64 bytes. There is no modulo repair,
alternate basis, alternate endianness, or short encoding.

The executable reference evaluates the exact Euler criterion at every quadratic step. Its current
results are:

```text
-1 nonsquare in Fp        = true
2+i nonsquare in Fp2      = true
u nonsquare in Fp4        = true
v nonsquare in Fp8        = true
```

Uniform field challenges use SHA3-512 rejection sampling. With `q = p^16`, a 512-bit integer `x` is
accepted only when

```text
x < floor(2^512 / q) * q.
```

The acceptance multiplier is exactly 65,536. Accepted values map through `x mod q` and then 16
base-`p` digits in the frozen basis. A fixed 16-attempt cap aborts on exhaustion; the exact random-
oracle abort fraction is below `2^-432`. Out-of-range values are never reduced without rejection.

Reference and vectors:

- `experiments/bl_pq512_crypto_foundation/field16_reference.py`
- `experiments/bl_pq512_crypto_core/`
- `test_data/bl_pq512_s09_foundation_vectors.json`
- `tests/test_bl_pq512_s09_foundation.py`
- `tests/attacks/test_bl_pq512_s09_foundation_attacks.py`

R32's Rust crate is `no_std`, forbids unsafe code, pins `sha3=0.10.9` with default features disabled,
and differentially covers the Python multiplication/inverse/sampler KATs plus Frobenius,
`Frob^8=conjugation`, trace/norm, and `w^16-4w^8+5=0`. It is a scalar substrate, not a production
proof module. Branch-minimized source is not constant-time machine-code evidence; production closure
still requires optimized scalar/SIMD parity, independent constant derivation, side-channel review,
proof-engine integration, and a non-null reviewed module identity.

## 3. Authoritative public-coin transcript

The final AIR will register one immutable ordered schedule. Each round has a typed kind, ordinal,
output kind, and output count. R35 now executes the exact theorem order for every unselected
interface candidate: interaction challenges, composition coefficient, OODS point, FRI batch
coefficient, 17 indexed FRI fold coefficients, and the final query seed (22 rounds total). The
candidate parameters remain separately bound by the candidate descriptor. The final selected
schedule remains null until the SHA3-expanded AIR and PCS are frozen.

For every round:

1. The session binds the exact 384 public-output bytes, 744-byte sidecar, candidate descriptor,
   contributor/key registry, and full schedule into a SHA3-512 initial root.
2. The prover publishes the typed round message bound to the previous transcript root.
3. Every registered challenge service publishes a signed SHA3-512 commitment to an independent
   64-byte secret. No reveal is accepted before every commitment exists.
4. Every service publishes a PQ-signed reveal. The envelope binds session, round, descriptor,
   previous root, prover-message digest, contributor ID, key ID, and payload.
5. A missing reveal, bad signature, duplicate, wrong order, or commitment mismatch fails closed. An
   incomplete session produces no accepted challenge or proof.
6. SHA3-512 derives the public challenge seed from the ordered commitments and reveals. Degree-16
   challenges use the rejection sampler above; query positions use separate unbiased rejection.
7. The complete signed evidence and derived challenges produce an append-only SHA3-512 audit root.

Production authentication accepts only adapters for FIPS 204 ML-DSA-87 and FIPS 205 SLH-DSA-
SHAKE-256f, requires at least two registered internal challenge services, and requires both algorithm
families. R32 exercises exact locked `pqcrypto==0.4.0` implementations with strict key/signature
sizes and rejects synthetic verifiers in production mode. Those adapters are software-only internal
evidence: they do not establish HSM custody, FIPS cryptographic-module validation, side-channel
qualification, independent administration, or production approval.

### Security assumptions and retry boundary

The authoritative interactive proof assumes at least one correctly operated internal challenge
service supplies unpredictable randomness after the prover message is fixed. PQ signatures provide
origin authentication; they do not create entropy. SHA3-512 commitment binding prevents a service
from changing its committed reveal.

A service that withholds its reveal can abort a single session. Across retries, selective abort can
condition which session completes unless enrollment, removal, attempt burning, retry limits, and the
resulting finite grinding factor are governed and included in S07. Therefore production contributor
governance and cross-session retry accounting remain an explicit blocker. The implementation does
not claim that a per-session abort rule alone solves that system-level issue.

The safest launch policy is a fixed epoch registry of independently administered internal challenge
services, automatic immutable publication of every abort, immediate quarantine/removal on a missed
reveal, no re-enrollment within the epoch, and an S07 bound covering the maximum failed attempts.
R32 implements the in-memory fail-closed portion: immutable epoch/statement binding, pre-burned
ordinals `0..3`, a two-bit maximum selective-abort allowance, both PQ suites on every retry,
quarantine, no same-epoch re-enrollment, signed-envelope validation, and a SHA3-512 local audit
chain. S09 still requires durable create-only publication, anti-rollback/crash recovery, deadlines,
governance authentication/timestamps, independent service administration, and final S07 accounting.

### OODS fixed-subfield gate

The two-point Circle-STARK theorem requires the OODS point and its order-two conjugate to be
distinct. For the selected Fp16/Fp8 tower, a stereographic parameter `t` must therefore be sampled
uniformly from `Fp16` with the embedded `Fp8` subfield removed: reject exactly when its upper eight
frozen-basis coefficients are zero
before constructing the circle point. This also excludes `t^2=-1`, so `1+t^2` is nonzero. The bad
fixed-subfield probability is about `2^-248`, above the `2^-384` per-term budget; it cannot be
ignored as a negligible tail. R35 implements SHA3-512 domain-separated rejection with a fixed
16-attempt cap and replayable accepted-attempt evidence in Python and Rust. The typed public-coin
OODS round uses that sampler. This closes the isolated sampler gap, not final PCS integration or the
complete positive abort ledger.

## 4. Why this preserves the product requirements

| Requirement | Construction consequence |
| --- | --- |
| Absolute PQ on Blind Ledger boundaries | No elliptic-curve or RSA authentication; SHA3-512 plus standardized PQ signatures; no Fiat--Shamir/QROM launch dependency |
| Maximum safety | Rejected QM31/Blake2s remains rejected; malformed, reordered, unsigned, incomplete, or equivocated rounds fail closed |
| Maximum throughput after safety | Move the six SHA3 internal tables out of the semantic AIR's generic release PCS and prove one shared committed bus with a bit-sliced Boolean GKR coprocessor over Fp16; compact theorem-neutral grammar, preserve M31 SIMD, and pipeline independent sessions; grinding receives zero security credit |
| Maximum auditability | Fixed schedule, typed length framing, signed contributions, KATs, exact roots, and full round evidence are replay-verifiable |
| Maximum modularity | Field, transcript, PQ signature adapter, PCS/FRI, hiding, proof grammar, and application state retain separate module identities |
| Government/oracle integration | Core challenge and proof semantics do not depend on a vendor API; adapters can implement the narrow PQ verification and evidence-publication ports |

Interactive operation adds network rounds and requires durable session orchestration. That is an
accepted latency tradeoff for the launch profile. Throughput is maximized through algorithmic
recovery, bounded streaming, SIMD/parallel execution, and independent-session pipelining; the
security target is not traded for single-proof latency.

## 5. Wave 2 implementation state (historical Wave 1B/R35 lineage)

The current kernel boundary has advanced beyond the older scalar-interface state recorded below:

- two fresh regression runs generated and independently verified the same proof shape:
  28,643,096 bytes, 945 transcript-derived query draws, 4,789 trace masks, 946 quotient masks, and
  15 FRI folds. Worker wall times were 50,070 ms and 47,178 ms. In the latter run, measured
  composition and DEEP work took 13,248 ms and 12,219 ms; openings took 224 ms. This is real kernel
  evidence, not a complete K128 proof or a production throughput claim;
- v1 authenticates each left/right FRI opening with a separate adjacent Merkle path at every query
  and layer. It therefore carries 226,800 FRI path digests and 28,350 opened FRI values. An exact
  canonical global-multiproof model over the same 945 draws, with all draw multiplicities retained,
  needs 8,118 path digests and 9,982 opened values. That removes 15,171,200 bytes of duplicated
  path/value payload (52.966% of the current proof) before replacement grammar metadata. This is a
  representation change only; it is admissible only if roots, leaf indices, node ordering,
  multiplicities, transcript binding, and independent verification remain identical;
- the authoritative `BLPQPRF2` encoder/decoder and v2 verifier now implement that representation
  change in both production-shaped workers. The verifier reconstructs query and layer coordinates
  from authenticated inputs and verifies the decoded compact bytes. Canonical cross-domain
  sibling/value maps additionally emit each repeated tree node and opened row once and reconstruct
  every opening proof. The latest real dual-PQ run reduced 28,643,096 bytes to 6,755,933 bytes, a
  21,887,163-byte (76.41%)
  saving, while retaining all 945 query draws and opening values. This closes the global proof-wire
  authentication de-duplication artifact, not all of Gate 2B;
- the current full K128 resource model requires a 23,171,830,448-byte raw witness and rejects a
  9,034,606,313,472-byte monolithic live layout. Its conservative streamed plan is still
  950,757,738,236 bytes of scratch, including duplicated row/column main, interaction, and
  composition layouts. Removing only those modeled duplicate layouts projects 554,259,695,356
  bytes under the same formula; this is a design target, not an implemented or measured result; and
- 46,208 of 46,858 K128 SHA3-512 calls (98.61%) come from replay/economic state. Wave 2 must compare
  the current direct Boolean and byte-lookup layouts as differential controls while implementing the
  selected shared-bus Boolean GKR coprocessor in
  `docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`. Exact bit-packed 25-state K128 storage is
  568,650,000 bytes; the `w=1,600` raw-state-layer baseline is 3,591,988,768 bytes and `w=2,048` is
  4,407,205,408 bytes, before generated-width and protocol overhead measurements. The
  554-951 GB direct-STARK layouts are retired release architectures. No candidate may replace
  SHA3-512, outsource state trust, vary public shape, or receive throughput credit before exact
  masking, simulator, theorem, independent-verifier, and end-to-end K128 measurements pass.

The authoritative execution order, acceptance gates, and rejected shortcuts are in
`docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md`.

The following older R35/interface evidence remains valid historical input unless a current
measurement above explicitly supersedes it:

- Wave 1A supplies one canonical six-segment SHA3 call order. K128 has 46,858 calls at
  `(0,516)`, `(516,129)`, `(645,1)`, `(646,9360)`, `(10006,36848)`, `(46854,4)`; K256 has 88,198
  and K512 has 165,762. Python and `no_std` Rust pin the schedule, while each component retains its
  independently evaluated physical SHA3 AIR. Wave 1B must stream these segments in order rather
  than allocate a redundant global clone;

- the six interface candidates use blowups `2,4,8,16,32,64`, 17 folds each, and query counts
  `926,567,463,421,402,393`; no candidate is selected and final SHA3/AIR expansion is not yet
  substituted;
- mixed-domain SHA3-512 PCS trees have typed layout and stage identities, canonical Fp16/M31
  openings, projection-consistent authentication paths, and a separate typed FRI-mask root;
- FRI batching requires one independent one-column Fp16 mask on every input domain. Data columns
  use globally unique positive powers across the entire descending domain sequence, so the second
  domain never resets at `lambda`; a missing, duplicate, reordered, or mismatched mask fails closed;
- domain gaps are real protocol rounds, not skipped challenges. For K512 at blowup 2, hiding-row
  expansion groups all 16 tables into evaluation logs `(21,20,18,16,14,5)` with trace widths
  `(172,460,200,312,1047,88)`, offsets `(0,172,632,832,1144,2191)`, six masks, and every fold log
  from 21 through 5. The source-aligned accumulation orders each attached circle function before
  the prior-layer terms, avoiding a pointless `alpha^2` multiplier on the largest domain;
- degree correction uses the OODS point and its Fp16/Fp8 conjugate. Both query evaluations are
  explicit inputs; conjugating the first claim is allowed only for a base-field-defined function
  where that identity is proved. The interpolant chooses a canonical nonfixed coordinate, covering
  the exceptional case left by a y-only separator;
- theorem-scheduled public-coin sessions require a fixed 144-byte typed prover message before every
  challenge. The FRI batch message binds both the OODS-claim digest and nonzero mask root before the
  batching coefficient is generated; and
- for the pre-dense-schedule K512/blowup-2 interface, the conservative hiding worksheet obtains
  `h=4694`, 2,191 private trace
  columns, 10,284,554 independent M31 randomizer coefficients, and a greater-than-308-million-bit
  entropy lower bound. Four small private tables require extension to 8,192 rows. Public statement
  rows receive no false private-mask credit. The exact dense SHA3 schedule supersedes those
  interface dimensions for final parameter use; the registry requires a hiding/FRI rerun.
- the direct Circle trace-evaluation map is constructive: a stereographic numerator basis and
  exact polynomial CRT jointly interpolate multiple degree-16 extension evaluations and base-domain
  queries. The K512 KAT includes the OODS point and its real log-20 transition translate plus 926
  base queries, giving rank 958 and free dimension 3,736. Python and Rust agree on certificate
  SHA3-512 `79148ba5b5ee6655478cd478cf3dd159bb8d458d1b6dad0245ee2db0ba223d4c766e0764f9909d05cba9efd0ea98329f53a70618553bf53ea1cd3ead86b6fb04`.
- canonical quotient masking now uses `left_hat=left+phi*t` and `right_hat=right-t`, with
  `h_q=n_oods+n_fri=927`. The split factor is source-aligned as
  `phi(Q)=x([2^(L-1)]Q)` and matches across Python/Rust; final `L` remains derived from the complete
  expanded AIR.
- the byte-oriented SHA3-512 AIR reference executes all 24 Keccak-f[1600] rounds and exact SHA3
  padding. It freezes a 1,632-column/1,024-lookup Keccak core plus 72 block columns/absorb lookups,
  for a 1,704-column trace and maximum 1,096 first-round lookups at composed degree 3. Cross-language
  shape SHA3-512 is
  `824d0d5adb44dc5a7f61960f7ad61ccb5a34aff177a51616afd0de6b49bbb4adea54e216cb0d0ea5bbe59f4818468e6bc3deafec21bdeddb4db797d899784e1c`.
- every live scoped application/reference SHA3 callsite is AST-locked: 25 are AIR-required, four
  are public/precomputed, seven are host evidence, 11 are deferred Wave 1C verifier/state work, and
  three are superseded. Five removed sparse-map ports remain historical-only dispositions. The
  isolated K128 historical physical-verifier phase reconciles all 404,482 calls.
  Adding the pepper-commitment constraint hidden by host object construction gives a conservative
  401,275-call, 1,205,016-permutation, 28,920,384-round-row AIR envelope with canonical inventory
  SHA3-512
  `b17a271256ae467773e5dcc0ee4432bd9cab46fcf5b6d986cf09f5da3f428bdcc5af594b20f85af956b008150a8af5c6580da7b453a8275c541ad0ab482fa27e`.
  This is historical audit evidence after the executable oracle relation was corrected from K
  packed records to one fact plus 50 authorization records per slot. It must not drive parameters.
- the current topology hashes the dense claim tree once, one exact 2,133-byte oracle bundle per
  claim, and one ordered oracle execution root. The separate audit tree reuses those bundle leaf
  digests. K128/K256/K512 require 385/769/1,537 shared hash invocations,
896/2,048/4,608 claim-membership links, and 14,322/28,644/57,288 SHA3 permutations. The old
  `51*K` measurement remains historical only. Its 50-live-callsite inventory digest was
  `d86734cefb1c6e3e89cc0c5a3d05547c08ac8243da2a09a2ce031d80a349ddf7b93c363e9a63b8b4de836abb7f3e74706167d1559f16db602fc48fba12739f3c`.
  H0 now independently enumerates both governed source trees and reconciles 79/79 current callsites:
  39 `AIR_REQUIRED`, five public-precomputed, 21 host-evidence-only, 11 Wave-1C verifier-state,
  and three superseded-reference sites. Its current inventory digest is
  `618c06447efc67bca80ca9bb4c59a89970e7c42a26ea6a45a298c8dc8e1e8b2643f3c51a923d1b89ebb6a2311dc22edfffeea70471a9f97c5378b8a43fb607c2`;
  new files and noncanonical alias, attribute, `hashlib.new`, dynamic-import, and dynamic-`getattr`
  forms fail closed. Current K128 bus-mapping and resource evidence remain open.
- the economic-map candidate fixes 24-bit shards and K128 worst-case padding at 34,026 node hashes,
  2,048 leaf-hash slots, six headers, 36,080 SHA3-512 calls, 74,208 permutations, and 1,780,992
  Keccak round rows. Inserts alone consume capacity; denial/cover update precommitted dummy leaves.
  These bounds are selected and attack-tested; padding rows and map/memory AIR constraints are now
  materialized and independently evaluated in Wave 1A. Interaction packing and proof-engine
  integration remain open.

Together these are executable interface, scalar-reference, and real kernel-proof results. They are
not a complete K128 application proof, a selected production profile, a zero-knowledge claim, or a
production throughput result.

## 6. Gates that remain before S09 can close

The internal solution removes the old outside-library/QROM design impasse and R32 implements several
reusable boundaries. It does **not** close S09. These items remain:

1. freeze and reproduce the reference K128/K256/K512 workload, hardware, latency, resource, byte,
   and run-to-run variance envelope; attribute every major proof byte, SHA3/state row, allocation,
   spill, and I/O transfer;
2. replace v1 per-opening FRI paths with a canonical, independently verified global multiproof and
   deduplicated opening grammar that retains every transcript draw and multiplicity; eliminate only
   theorem-neutral storage/layout duplication;
3. implement H0-H3 of the shared-bus Boolean GKR coprocessor: exact byte/bit bridge, Fp16 repeated-
   circuit sumcheck, SHA3-512 hiding bus PCS, authenticated interactive public coin, native masks,
   complete adaptive simulator, independent verifier, and the `<=5,000,000,000`-byte
   peak-RSS / `<5,000,000,000`-byte scratch / no-swap preflight;
4. implement H4-H5: integrate the sealed Wave 1 semantic AIR and coprocessor atomically, retain the
   old SHA3 AIR only as a differential oracle, finish scalar/SIMD/optional-GPU parity, and generate a
   complete independently verified fixed-shape K128 proof with exact resource/throughput evidence;
5. bind the final AIR-dependent interaction/LogUp/composition/OODS/DEEP/FRI dimensions, Circle split
   log-degree, constructive direct-map and quotient-mask kernel into a complete interactive Circle
   simulator; pass abort/denominator, repeated-proof leakage, fixed-shape, parser differential,
   independent-verifier, and full K128 proof gates;
6. qualify durable ML-DSA and SLH-DSA custody and public-coin services: enrollment, create-only audit
   publication, anti-rollback/crash recovery, deadlines, liveness, independent administration, and
   finite selective-abort/grinding accounting; and
7. freeze the final proof-body grammar, module and verifier identities, production transport limits,
   application/SHA3/PCS/FRI-expanded dimensions, and substitute every positive term into S07.

Until all seven pass, `proofSuiteId` stays null, `activationAllowed=false`, current S-two receipts
remain validity-only, and no real PHI may enter the path.

## 7. Primary references

- Circle STARKs: <https://eprint.iacr.org/2024/278.pdf>
- S-two Whitepaper: <https://eprint.iacr.org/2026/532.pdf>
- Fiat--Shamir Security of FRI and Related SNARKs: <https://eprint.iacr.org/2023/1071.pdf>
- Adding Zero Knowledge to STARKs: <https://eprint.iacr.org/2024/1037.pdf>
- Official S-two repository: <https://github.com/starkware-libs/stwo>
- NIST FIPS 202 (SHA-3): <https://csrc.nist.gov/pubs/fips/202/final>
- NIST FIPS 204 (ML-DSA): <https://csrc.nist.gov/pubs/fips/204/final>
- NIST FIPS 205 (SLH-DSA): <https://csrc.nist.gov/pubs/fips/205/final>
