# Direct-mask FAEST_256F degree-three contract

Version: `direct-mask-contract/v1`
Status: synthetic, nonactivating, unqualified computation/admission contract.
Machine source: [`manifest.json`](manifest.json); arithmetic implementation:
[`calculator.py`](calculator.py).
The reviewed conditional proof records are [`LOCAL_CERTIFICATE_PROOF.md`](LOCAL_CERTIFICATE_PROOF.md)
and [`PRIVACY_REDUCTION_PROOF.md`](PRIVACY_REDUCTION_PROOF.md). They are mathematical inputs to
this nonactivating contract, not qualification or activation evidence.

This is a small fork specification, not a claim that upstream FAEST exposes this generic protocol.
The implementation input is donor commit `60707e6aca0e0c320c67be76e178c7379f075e61` (tree
`2febe1822c0586d6ecaf7418d7d9056e5f190a29`). The reusable cryptographic source is the non-EM
FAEST v3.0.0 gitlink at commit `ebefcbd8adda5faf447ef3dba5103794d17b4281`; vendor bytes and its
license are not changed here.

## Fixed suite and circuit facts

The inherited FAEST_256F facts are `lambda=256`, `tau=33` VOLE trees, eight grinding bits,
`T_open=229`, and `17*256 + 16*128 = 6400` leaves. The field is

```text
F2[X] / (X^256 + X^10 + X^5 + X^2 + 1)
```

The AES-byte embedding is the pinned `bf256_byte_combine` map with little-endian generator bytes
`e7 fe de 0b 42 88 97 96 67 4e 47 a0 38 8d d6 be 6a e1 f1 f8 45 98 22 df 33 58 c9 20 cf a8 c9 04`.
The contract remains explicitly non-EM.

The generic relation degree is exactly `d=3`; six field masks are allocated by `(d-1)+4`.
The verified read-only kernel gate exports `ell=125,048` witness bits and `m=172,232`
constraints, with zero padding constraints. Its ordinary bit-VOLE row count is
`B_rows = 125,048 + 6*256 = 126,584`, or `15,823` bytes. The immutable kernel identity and
approved shared algebra hashes are recorded in `manifest.json` under `actual_export`; this does
not make the full proof, wire contract, or security composition complete.

The earlier `ell=117,328`, `m=156,788` values remain an illustrative planning estimate only.
They are not used by finite report, hash, privacy, or QROM calculations and cannot pass admission.
Admission also requires exact exporter dimensions, byte alignment, bitness, constrained padding,
field-domain, degree-three homogenization, fixed tree geometry, and PQ/E2E ownership.

## Wire facts and protocol boundary

The immutable outer-wire facts reconcile as

```text
statement=1,147, header=40, nu=96, nonces=3*64,
m1=506,416, m2=15,887, m3=96, m4=10,496,
frame = statement + header + nu + nonces + m1 + m2 + m3 + m4 = 534,370 bytes.
```

The proof body excludes the statement, header, and `nu`, and is independently allocated as
`m1+m2+m3+m4+3*64 = 533,087` bytes. The wire facts are evidence owned by E2E, not an E2E
protocol approval. Canonical byte encoding and domain strings remain an E2E-owned obligation.

The proposed transcript binds the full canonical public statement, including context, `U`, `T`,
`C`, the relation identifier, and admitted generic parameters. It binds the non-EM leaf-hash
parameter in the first challenge, uses challenge widths `8*lambda+b=2112`, `3*lambda+b=832`,
and `lambda=256` bits with `b=64`, and models a fresh 512-bit nonce for every final candidate.
Retry exhaustion is fail-closed. The generic path retains BAVC commit/reconstruct, bit-row
transposition, per-tree corrections, `convert_to_vole`, and the existing `W_CRT` map; removal
of upstream CRT multiplication labels, `c_mult`, special high-bit, `H5`, and `F/G/W_GATE`
computations is a proposed fork operation, not a vendor edit.

## Exact retry and BAVC combinatorics

The raw FS3 challenge is a 256-bit little-endian integer. `decode_all_chall_3` consumes 17
8-bit coordinates followed by 16 7-bit coordinates, so exactly 248 raw bits remain after the
eight high grinding bits. For group `g<17`, choice `v<128` maps to leaf `33*v+g`, while
`128<=v<256` maps to `4224+17*(v-128)+g`. For `g>=17`, the map is `33*v+g`.

For the 6,400-leaf heap, each selected leaf is marked together with its ancestors through the
root. Let `n_h` be the size of that union. The BAVC gate is
`n_h - 2*tau + 1 <= T_open`, equivalently `n_h <= 294` for this suite.

The exact finite definition is

```text
p_good = sum_{gamma3=0}^{2^248-1}
         I[opening_node_count(decode_all_chall_3(gamma3)) <= 294] / 2^256.
```

`calculator.py` exposes the decoder, leaf map, path-union count, opening gate, and a bounded
exhaustive enumerator for small structural analogues. The production numerator is deliberately
`UNKNOWN`: high-memory BDD/CNF/Stirling attempts were stopped by the resource guard, and no
Monte Carlo or guessed `1/256` substitute is admissible. The exact expression therefore remains
distinct from a numerically evaluated probability.

For independent fresh challenges, a retry cap `R` has
`p_abort=(1-p_good)^R`, expected candidate count
`(1-(1-p_good)^R)/p_good` (with the zero-probability limit `R`), and maximum
`R` counted FS3 candidates/QROM retry queries and `512*R` nonce bits. The report retains
`R=4096,8192,16384` symbolically.

The actual nonce sampling model is with replacement. If `S(R,d)` is a Stirling number of the
second kind and `(2^512)_d` is a falling factorial, its exact finite abort expression is

```text
sum_{d=0}^R S(R,d) * (2^512)_d / 2^(512*R) * (1-p_good)^d.
```

The rigorous collision split is
`min(1,(1-p_good)^R + binom(R,2)/2^512)`. Large Stirling sums are resource-guarded; the
implementation evaluates them only for small exact test probabilities.

## Separate security ledgers

The statistical false-acceptance ledger is

```text
epsilon_stat <= E_U * 2^-257 + other_stat,
```

where one independently issued uniform nonzero `U` has the source-pair bound
`binom(2^256,2)/(2^768-1) < 2^-257`, and the non-EM leaf event is bounded by `33/2^256`.
The VOLE/hash terms `epsilon_v`, `epsilon_z`, `e_KOS`, and `e_poly` are internal to the global
ideal-QROM proof and are not added again to this statistical ledger. A reused `U` is charged once;
independent reissuance adds explicitly declared `E_U` events.
The initial U issuance is included in `E_U`; `reissued_parameter_count` counts only additional
independent reissues. For zero additional reissues the additional event sum is exactly zero, not
a strict bound below zero. Reuse of one U is not reissuance.

The ideal-QROM false-acceptance ledger is conditional on the completed, query-only fork-specific
local-certificate argument in [`LOCAL_CERTIFICATE_PROOF.md`](LOCAL_CERTIFICATE_PROOF.md):

```text
B_snd(q) = min(1, 1020*q^3/2^512 + 360*q^2/2^256)
q = Q + 37*A + 38*V + R_retry + 38.
```

Here `A` counts proof attempts entering commitment/challenge machinery, `V` counts verifier
invocations entering this backend, `R_retry` counts every final candidate, and `Q` is the
adversary's coherent QRO-query model parameter. The literal oracle-call accounting is recorded
separately as `38*A + 39*V + R_retry`, with 38 local witness-completion rows. There is no extra
`101` or `2^32` multiplier in this QROM event. The bound is not a product qualification claim.
The local-certificate one-row insertion/replacement term is
`delta(j) <= 102*j/2^512 + 33/2^256 + 3/2^256 = 102*j/2^512 + 36/2^256`.
The record defines the typed witness predicate, replacement-stable extraction, chronological
certificate rows, and the inefficient finite selector used by the conditional query-model proof.
It does not claim an efficient concrete SHAKE reduction or a final-database theorem.

Concrete false acceptance remains
`E_U*2^-257 + B_snd(q) + Adv_SHAKE_snd + Adv_source_auth + Adv_U_generation`.
Those primitive/source-generation advantages are currently `UNKNOWN`.

Privacy remains a separate ledger, with the completed conditional simulator and hybrid argument in
[`PRIVACY_REDUCTION_PROOF.md`](PRIVACY_REDUCTION_PROOF.md):

```text
epsilon_priv <= min(1, epsilon_coins + epsilon_AR + epsilon_bitMH
                       + epsilon_source + Adv_SHAKE_priv).
```

Adaptive reprogramming is recorded as
`epsilon_AR <= min(1, sum_{r=1}^P [sqrt(qhat_r*2^-512) + 1/2*qhat_r*2^-512])`, with
`P <= 2*A + R_retry` and `q_hist = Q + 38*A + 39*V + R_retry`. The Q1 AES-256 games use
classical access to the hidden-key challenge on at most 4/2,048/989 distinct inputs, plus public
AES computation and an independent QRO; they do not grant Q2 superposition access. Their complete
bit-hiding term is

```text
epsilon_bitMH <= min(1, M * (397*alpha_4(T*,Q*) + 33*alpha_2048(T*,Q*)
                              + 33*alpha_989(T*,Q*) + 85,297,284/2^128)).
epsilon_source <= min(1, S * (alpha_8(T*,Q*) + alpha_50(T*,Q*) + 1253/2^128)).
```

`M <= A`; `S` counts distinct fresh source root/pad commitments, so a reproof of one unchanged
source assertion does not increment `S`. `R_retry` includes the first final candidate. The
full-history overlay uses `Q* <= 2*q_hist` and `O(P*L_FS)` comparison work per QRO call. `T*`,
`L_FS`, the adversary bound, and all pinned-routine/overlay costs are explicitly `UNKNOWN`;
source-counted AES block totals are not measured quantum work. The illustrative `2^-69.7`
switching value is neither an attack probability nor an automatic policy violation.

## Durable counters and resources

The existing operational reservation ledger retains 101 reservations per current batch under a
global `2^32` cap: 42,524,428 complete batches leave 68 reservations. This is an operational
reservation rule, not a theorem-event multiplier. A durable, nonrefundable reservation is written
before the relevant cryptographic/challenge operation (or as a bounded up-front reservation), and
the outcome is recorded separately. Crash, cleanup failure, abandoned/restarted handoff, and
unknown outcome never refund a consumed reservation or counter; recovery never resumes a consumed
partial proof or replays retained private material.

The machine contract records increment, rollback, and recovery semantics for `A`, `V`, `R_retry`,
`M`, `E_U`, `S` (distinct source root/pad commitments), and exact byte-identical retransmits.
`M <= A`; `P <= 2*A + R_retry`; and `R_retry` includes the first final candidate. `S` is not
incremented for a reproof/retransmission of an unchanged source assertion. Counters persist only
opaque issuance identities and counts: never source roots, pads, `x`, commitment/proof bytes, or
stable exact-byte hashes. Exact retransmit is audit-only when it causes no fresh commitment,
proving, or verification; verifying retransmitted bytes still increments `V`. `Q` is not an
application counter.

Source-counted block coefficients are `6,406,396*A + 6,373,495*V + 58*S`; they are not measured
quantum work. The resource ledger also requires finite retry/lifetime budgets, source-`U`
reuse/reissue counts, every named primitive advantage, a declared `T*` model, and all routine and
oracle-overlay costs before declaring runtime complete. Structural resource input completeness is a
declaration-only shape check: `runtime_fields_declared` does not verify the work model, and
`resources_declared` does not imply `runtime_complete`. Runtime qualification remains false with
the explicit `unverified_runtime_cost_model` reason until a reviewed unit/evidence model exists;
unknown values are not treated as zero.

No component calculation establishes source truth, cryptographic security, quantum soundness,
privacy, implementation correspondence, codec/resource/adapter conformance, deployment linkage,
production readiness, or activation. Descriptor validity, a passing local test, and the exact
wire/combination formulas leave `qualified`, `selected`, `production_usable`, and `activation`
false. The remaining gates are the evaluated `p_good` numerator, E2E wire contract, quantum
analysis, finite resource/advantage declarations, source-U lifetime/reissuance accounting, and
whole-composition implementation/correspondence verification under the existing authority set.
