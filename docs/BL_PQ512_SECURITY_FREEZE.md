# BL-PQ512 security-feasibility review

Updated: 2026-07-18

Status: **historical review-ready synthetic-only S07-S09 research; the S-two parameters described
here remain rejected. The later H4/H5/H6 candidate evidence is nonactivating; no production proof
suite is selected or activated.**

Current architecture addendum: the replacement direction is now the heterogeneous construction in
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`. The sealed M31 semantic AIR uses a shared hiding
bus with an Fp16 Boolean GKR SHA3 coprocessor. This preserves every rejection and security floor in
this freeze while retiring the 554-951 GB direct-SHA3-STARK layouts.

Planning addendum: this research freeze preserves the current rejection and evidence boundary.
Under `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md`, S07-S09 selection, implementation, and internal
qualification are Blind Ledger engineering work. The completed exact release later enters the one
independent audit gate; audit is not a prerequisite for writing the implementation.

This document is the durable security-feasibility record for roadmap packages S07-S09. It preserves
the exact ordered 12-field Privacy V2 ABI and treats every legacy felt as a compatibility value, not
as a strict post-quantum authority. It does not authorize real data, dependency changes, verifier
activation, settlement, or a claim that `BL-PQ512-v1` has passed external cryptographic review.

The later R24 continuation corrects the exact algebra/query worksheet and adds the nonactivatable
suite registry, 744-byte sidecar candidate, lifecycle, and S12 formal-statement draft in
`docs/BL_PQ512_S07_S12_PREIMPLEMENTATION_FREEZE.md`. The suite described by this freeze remains
rejected. The current H4/H5/H6 candidate evidence is recorded in the active Wave 2 documents,
remains nonactivating, and leaves `proofSuiteId` unset.

## Executive result

The application-specific M31 semantic AIR direction remains viable, but the present monolithic
S-two proof configuration does not. The fault is structural, not a lack of CPU or GPU tuning:

- the prototype uses QM31, a roughly 124-bit challenge field, for algebraic soundness events that
  have independent positive error terms proportional to `1 / |QM31|`;
- it uses Blake2s-256 for the Fiat-Shamir channel and Merkle commitments;
- it uses a three-query, two-times-blowup, ten-bit-grinding test default whose library helper reports
  only 13 nominal classical bits;
- the current S-two whitepaper explicitly defers quantum-random-oracle analysis; and
- the complete AIR dimensions needed to instantiate the soundness equations do not yet exist.

More FRI queries or more grinding cannot remove the QM31 field-error terms, and neither repairs a
256-bit commitment tree. S08 therefore rejects the current configuration. The selected
implementation priority keeps fast M31 semantic arithmetic, moves challenges to Fp16, uses
full-width SHA3-512, and removes internal SHA3 tables from the semantic release PCS in favor of the
shared-bus Boolean coprocessor. It still requires the exact bridge, native-hiding simulator,
interactive theorem/error ledger, code, tests, and independent review. Launch does not rely on a
Fiat--Shamir/QROM transform.

## Non-negotiable scope

- The external ABI remains exactly 12 ordered `bytes32` values as pinned in
  `ops/native_stark_public_inputs_v2.json`.
- No one-felt value is authoritative for arbitrary-collision, membership, replay, or deduplication
  security in `BL-PQ512-v1`.
- Full-width sidecar values, proof commitments, state roots, verifier identity, schema identity, and
  suite identity are never truncated, reduced to a felt, or accepted one 256-bit limb at a time.
- All work and all tests remain synthetic-only.
- The current RISC Zero and Cairo paths remain semantic/differential oracles. They are not silently
  changed to make a new AIR agree.
- A deterministic acceptance bug, parser ambiguity, missing constraint, or unhiding oracle has error
  probability one. It cannot be hidden inside a probabilistic security budget.

## Observed current prototype

| Item | Observed value | Security meaning |
| --- | --- | --- |
| Base field | `M31 = 2^31 - 1` | Retain for trace arithmetic and SIMD throughput |
| Challenge field | `QM31 = M31^4`, `log2(|QM31|) = 123.9999999973` | Too small as the sole challenge space for strict 128-quantum-bit soundness |
| FRI configuration | `pow_bits=10`, `log_blowup_factor=1`, `n_queries=3`, last-layer bound `0`, fold step `1` | Library helper returns `10 + 1*3 = 13`; this is a test heuristic, not a complete proof bound |
| Transcript/tree | Blake2s-256 | Generic quantum collision ceiling is about `2^(256/3) = 2^85.33` |
| Verifier suite pin | Reads `proof.stark_proof.config` | No out-of-band exact-suite or minimum-security enforcement |
| Witness hiding | None | Validity-only; private trace commitments are not formally hidden |

The current prototype draws multiple QM31 values for different LogUp, composition, OODS, quotient,
and FRI tasks. Those are not independent repetitions of the same bad event, so their security does
not multiply.

## S07 security-budget framework

### Declared review worksheet

The following values are a conservative review worksheet, not an activated proof suite:

| Symbol | Draft value | Meaning |
| --- | ---: | --- |
| `lambda_Q` | `128` | Quantum-oracle-query boundary under review |
| `mu` | `64` | Stress cap of `2^64` separately attackable lifetime targets |
| `kappa` | `32` | Residual-success allowance at the query boundary before final policy review |
| `J` | `<= 64` | Provisional cap counting every positive error term, including every table, round, fold, commitment, and reduction term |
| `s_round` | `>= 384` | Candidate minimum classical round-by-round error exponent before QROM loss |

For target count `N_i`, attack advantage composes as:

```text
Adv_total(q) <= sum_i N_i * Adv_i(q)
```

For additive terms `2^-s_i`, the total exponent is bounded by:

```text
s_total >= min_i(s_i - ceil(log2(N_i))) - ceil(log2(J))
```

For FRI compiled with Fiat-Shamir, the available QROM analysis has the schematic form:

```text
epsilon_quantum = Theta(Q^2 * epsilon_rbr + Q^3 / 2^hash_bits)
```

At `Q=2^128`, `N=2^64`, `J<=64`, `epsilon_rbr<=2^-384`, and a 512-bit transcript, the round branch
has exponent `384 - 256 - 64 - 6 = 58` before theorem constants. The hash branch has the same
exponent: `512 - 384 - 64 - 6 = 58`. Adding those two equal branches gives exponent 57, not 58.
Against a provisional residual-advantage target of `2^-32` at the `2^128` query boundary, the
combined displayed bound leaves 25 bits of multiplicative slack; with no omitted terms it requires
`C<=2^25`. Every additional positive term needs an explicit sub-budget or a proved domination
argument. The 128 figure is the quantum work/query boundary, while 32 is the negative logarithm of
the residual attack advantage allowed at that boundary. The displayed QROM expression is schematic;
it is not yet an upper-bound theorem for the intended multi-table Circle-STARK/LogUp/native-hiding
system.

### Hash and state budget

For an ideal `n`-bit hash, generic quantum bounds have the shapes:

```text
Adv_target_preimage(q) <= C_pre * N * q^2 / 2^n
Adv_arbitrary_collision(q) <= C_col * N * q^3 / 2^n
```

SHA3-512 therefore has idealized single-target work ceilings of about 256 quantum bits for target
preimages and 170.67 quantum bits for arbitrary collisions. With `2^64` attackable targets, the
corresponding simple work estimates are about 224 and 149.33 bits. Exact constants, long-message
second-preimage behavior, concrete Keccak assumptions, and domain multiplicity remain review items.

The 12 Stark felts do not combine into one 3,012-bit digest. A roughly 251-bit felt has idealized
ceilings near 125.5 quantum bits for a fixed target and 83.67 for an arbitrary collision. Across 12
separately attackable fields those ceilings are lower. This is why the full SHA3-512 sidecar and
shadow state are authoritative while the 12 fields remain exact compatibility outputs.

### Algebraic, PCS, and FRI budget

The interactive proof ledger must instantiate every positive term, including:

```text
epsilon_IOP = epsilon_LogUp
            + epsilon_composition
            + epsilon_DEEP
            + epsilon_FRI
            + epsilon_other

epsilon_FRI = epsilon_batching
            + sum(epsilon_fold_k)
            + (1 - theta)^queries
```

Representative S-two round terms contain table counts, message widths, list sizes, constraint
degree, and maximum table height in numerators divided by the challenge-field size. This is the
reason S08 cannot be finalized before a conservative AIR envelope exists and cannot be released
before the measured AIR is substituted back into the equations.

If an algebraic bad event is bounded by `D_eff / |F|`, then the current 256-bit round budget
requires:

```text
log2(|F|) - log2(D_eff) >= 256
```

QM31 supplies less than 124 bits before `D_eff`. An M31 octic extension supplies less than 248 bits
and is also insufficient. For `p=2^31-1`, the exact largest integer numerators permitted by
`D_eff / p^d <= 2^-256` are:

| Extension degree `d` | Maximum `D_eff` |
| ---: | ---: |
| 8 or lower | Impossible even for `D_eff=1` |
| 9 | 8,388,607 |
| 10 | 18,014,398,425,595,904 |
| 11 | 3,868,562,602,950,975,044,766,924,712 |
| 12 | 8,307,674,927,232,972,851,342,063,796,066,713,713 |
| 13 | 17,840,596,050,824,724,157,452,044,005,284,010,792,268,594,614 |
| 14 | 38,312,388,271,878,875,991,414,117,688,071,794,766,968,321,144,048,845,915 |
| 15 | 82,275,227,291,374,676,156,302,730,140,067,626,224,004,645,423,889,228,096,339,965,416 |
| 16 | 176,684,705,161,434,791,698,851,528,957,249,246,790,158,334,899,835,500,476,343,016,434,434,053 |

Degree 16 remains the selected power-of-two/quadratic-tower candidate and provides substantial
margin above the 256-bit floor; it is not the only mathematically possible degree. The conservative
pre-code rule for degree 16 is `D_eff <= 2^239`. The irreducible polynomial/tower, encodings,
conjugation, sampling, arithmetic, and theorem coverage are all still unselected.

### Grinding

No strict-PQ budget may credit the library's classical grinding count directly. Ideal quantum search
can reduce a `z`-bit grind to roughly `z/2` work bits, and the protocol-specific QROM treatment has
not been supplied. The conservative candidate gives grinding zero security credit. Throughput work
should prefer reviewed query/field security over exponentially expensive prover grinding.

### Salts and zero knowledge

For a uniform `h`-bit salt used `S` times, accidental reuse is bounded by approximately
`S(S-1)/2^(h+1)`. With `h=512` and `S<=2^64`, that term is below `2^-385`.

That calculation is useful only if salts stay secret, fresh, unlogged, non-caller-controlled, and
hidden by the proof. Statistical zero knowledge has a separate lifetime ledger:

```text
Delta_lifetime <= N_proofs * epsilon_ZK
```

Every trace, quotient, lookup/permutation, DEEP, and FRI oracle must have a simulator-covered mask.
Mask reuse, an unmasked oracle, witness-dependent aborts, or a deterministic production prover are
hard failures rather than small leakage terms.

### Encryption, signatures, and custody

The proof budget does not make classical custody post-quantum. Review candidates are ML-KEM-1024,
ML-DSA-87, and an `n=32` SLH-DSA parameter set, all in NIST's highest standardized families. They
are candidates, not selections. KEM combiners, multi-user losses, AEAD nonce uniqueness, KDF
binding, signature message binding, downgrade rejection, HSM support, side channels, and current
NIST errata must be resolved before P11/P12 or O01 can close. A NIST category is a practical resource
class, not an automatic proof of an exact query-bit claim.

## S08 result: current configuration rejected

S08 records the following hard conclusions:

1. More FRI queries reduce only the query/proximity term; they do not remove the independent
   composition, OODS, LogUp, batching, or fold terms proportional to `1 / |F|`.
2. More grinding does not widen the challenge field or commitment digest.
3. One QM31 challenge has an ideal best-case quantum-search ceiling near 62 bits before degrees,
   tables, targets, and QROM losses.
4. Two genuinely repeated QM31 checks still supply less than 124 best-case quantum-search bits.
5. Blake2s-256 independently caps generic quantum collision work near 85.33 bits.
6. The current default's 13-bit helper result is test-only and must never be presented as total
   classical or post-quantum security.
7. S08 cannot close against an AIR whose physical rows, columns, degree, tables, commitments, and
   message dimensions remain unknown.

### Candidate feasibility envelope

The following is the leading engineering hypothesis to be reviewed, not a parameter freeze:

- retain M31 for the witness trace and FFTs;
- use a reviewed M31 degree-16 challenge field for every algebraic soundness event;
- use SHA3-512 for transcript, Merkle/PCS nodes, roots, suite/schema/artifact identities, and
  application-wide authoritative bindings, with distinct typed domains;
- use only the proven Circle-FRI regime and an implementation whose query/Merkle layout matches the
  theorem being invoked;
- give grinding zero credited security bits and measure a query-heavy alternative;
- target `epsilon_rbr <= 2^-384` and require the exact AIR to prove the conservative
  `D_eff <= 2^111` envelope;
- enforce a conservative maximum trace/domain envelope before AIR implementation, then fail closed
  and return to architecture review if the completed AIR exceeds it;
- pin the verifier's suite out of band and reject any proof-supplied downgrade before allocation;
- absorb all 12 fields and the complete sidecar before the first challenge; and
- re-run the full calculation after the physical AIR, native masks, and parser exist.

For the isolated query term, `epsilon_query=(1-theta)^s` and
`s_min=ceil(384 / -log2(1-theta))`. An illustrative, non-selected worksheet with a proved distance
parameter `theta=0.45` therefore requires at least 446 queries; 512 uniform queries provide
`441.598195840033` query bits. In the proven Johnson regime with code rate `rho=2^-beta`,
`theta < 1-sqrt(rho)`, so the query contribution is strictly below `beta/2` bits per query. Near
that boundary the integer minima are 769, 385, 257, and 193 queries for `beta=1,2,3,4`
respectively. None of these figures selects a rate, distance, or query count: list bounds, layout,
table dimensions, non-query terms, proof size, verification cost, and QROM constants must all be
instantiated first. S-two's `log_blowup * query_count` helper is not a security proof.

## S09 options and conditional recommendation

| Option | Security posture | Throughput/audit tradeoff | Disposition |
| --- | --- | --- | --- |
| Current QM31 + Blake2s + default PCS | Fails field, hash, query, suite-pin, and hiding floors | Fast only because it is an intentionally weak validity prototype | Rejected |
| M31 octic + SHA3-512 | Hash repaired; challenge space still below the strict target before losses | Less extension work than degree 16 | Rejected |
| Four independently repeated QM31 proof checks + SHA3-512 | Potentially enough raw error exponent if a QROM parallel-repetition theorem applies | Reuses mature QM31 code but repeats composition/PCS/FRI work and enlarges proofs | Contingency research |
| M31 degree-16 challenges + SHA3-512 | Supplies the only current single-proof challenge margin compatible with the worksheet | Keeps base-field SIMD work; widens security-critical extension operations | Conditional lead |
| M31 degree-16 + SHA3-512 + PQ-authenticated interactive public coin | Removes the Fiat--Shamir/QROM transform from the authoritative launch mode while preserving the wide field/hash target | Adds network rounds and durable challenge-service orchestration; independent proofs remain pipelineable | **Selected construction direction; implementation gates remain open** |
| Current implementation in unique-decoding mode | Avoids some list-decoding assumptions but not QM31/Blake2s ceilings | Likely many queries/large proofs | Bring-up fallback only after wide field/hash |

The selected construction direction is a narrow, isolated S-two-derived fork that retains M31 trace
arithmetic, uses a reviewed degree-16 challenge field and SHA3-512 throughout the proof system,
implements a theorem-matched Circle-FRI layout, adds complete native witness hiding, and replaces
authoritative Fiat--Shamir with PQ-authenticated interactive public-coin challenges. This selects an
architecture, not a proof suite: S09 remains open until the exact production modules and complete
S07-S09 ledger qualify. The final independent audit remains mandatory before activation.

### 2026-07-18 upstream implementability recheck

The current official S-two source remains centered on the `M31 -> CM31 -> QM31` tower and does not
provide Blind Ledger's degree-16/SHA3-512/native-hiding suite as a theorem-matched module. It also
leaves consumer parameter security to integrators and is not constant time. Therefore the existing
QM31/Blake2s physical calibration kernel cannot be promoted. Blind Ledger no longer waits for an
upstream drop-in: the internally selected replacement and executable nonactivating algebra/public-
coin foundations are specified in `docs/BL_PQ512_S09_INTERNAL_SOLUTION.md`. The remaining stop and
resume conditions are in `docs/BL_PQ512_S09_IMPLEMENTABILITY_STOP.md`; `proofSuiteId` remains null.

The proof-suite registry must cover field/tower constants, canonical encodings, endianness, typed
domains, challenge sampling and rejection, all commitment layers, query generation, grinding,
sidecar order, proof-body framing, verifier/schema/artifact identities, strong application roots,
and downgrade rejection. KEM/signature/custody modules retain separate independently rotatable IDs
bound by the activation profile. No verifier may read any security choice from untrusted proof bytes
without comparing it to authenticated out-of-band state.

## Native witness-hiding decision boundary

The construction under review masks each private trace polynomial as `w + Z_H*r`, randomizes every
quotient component, commits an independent FRI batch mask before its batching challenge, uses fresh
domain-separated OS-CSPRNG randomness, and covers every implicit opening. The fixed-shape AIR must
also make approval, denial, and padding indistinguishable in rows, columns, queries, proof bytes,
state-operation counts, error behavior, and scheduling.

This is a coherent construction direction, not an audit result. Closure requires a Circle-STARK-
specific simulator, exact mask-degree/entropy accounting for the final query pattern, abort and
denominator analysis, composition with the selected interactive public-coin schedule, repeated-proof
unlinkability tests, and an independent review. The current validity prototype remains explicitly
non-private.

## Roadmap dependency correction

S08 depends on AIR bounds, while the old roadmap placed every AIR decision after S08. S04 and S10
also referenced A11/P05 and S12 in ways that formed a cycle. The safe order is:

```text
S03/S05/S06 application boundary
        |
        v
S07 budget + S08 current rejection + S09 candidate families
        |
        v
pre-freeze A01/A05/A11/P05 normative design inputs
        |
        v
S02/S04/S10 reconciliation and S12 formal statement
        |
        v
A/Z/P/T implementation lanes
        |
        v
A16 measured AIR -> Z10 exact parameter revalidation -> qualification
```

The downstream A/P packages remain open; only their normative design inputs move earlier. Exact
parameters must be checked twice: once against a conservative pre-code envelope and again against
the measured AIR before a suite ID can be released.

## Mandatory internal-resolution and final-audit questions

1. Is the declared quantum metric sufficient, including gates, depth, memory, residual advantage,
   and the `2^64` lifetime-target stress cap?
2. Which theorem and exact constants cover this multi-round, multi-table, LogUp-using Circle STARK
   in the QROM?
3. Does the proposed degree-16 tower preserve every Circle/FRI theorem hypothesis, and is its
   challenge sampler uniform and canonical?
4. Which paper-covered Merkle/query layout will the fork implement, and is any conjectural decoding
   regime excluded?
5. Does the completed AIR stay inside the field-numerator and domain envelopes?
6. Does the native-hiding simulator cover every oracle, decomposition, neighbor, conjugate,
   denominator, abort, and repeated proof?
7. Are SHA3-512 domains/encodings injective and full width throughout?
8. Are the KEM, signature, KDF, AEAD, and hybrid-combiner selections valid under current NIST errata
   and multi-user use?

Until those questions are answered, S07, S08, and S09 remain open and implementation must not claim
strict-PQ soundness or witness privacy.

## Primary research anchors

- Dan Carmon et al., *S-two Whitepaper*, ePrint 2026/532:
  https://eprint.iacr.org/2026/532
- Ulrich Haboeck, David Levit, and Shahar Papini, *Circle STARKs*:
  https://eprint.iacr.org/2024/278.pdf
- Alexander Block et al., *Fiat-Shamir Security of FRI and Related SNARKs*:
  https://eprint.iacr.org/2023/1071.pdf
- Ulrich Haboeck and Al Kindi, *A note on adding zero-knowledge to STARKs*:
  https://eprint.iacr.org/2024/1037.pdf
- Brassard, Hoyer, and Tapp, *Quantum Algorithm for the Collision Problem*:
  https://arxiv.org/abs/quant-ph/9705002
- NIST FIPS 202, SHA-3:
  https://csrc.nist.gov/pubs/fips/202/final
- NIST post-quantum evaluation criteria:
  https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-%28evaluation-criteria%29
- NIST FIPS 203, FIPS 204, and FIPS 205:
  https://csrc.nist.gov/pubs/fips/203/final
  https://csrc.nist.gov/pubs/fips/204/final
  https://csrc.nist.gov/pubs/fips/205/final
