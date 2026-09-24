# Direct-mask filtered finite-security contract v2

This is `direct-mask-contract/v2-filtered`, a synthetic, nonactivating contract for the
filtered direct-mask candidate. The machine source is [`manifest_v2.json`](manifest_v2.json)
and the exact calculator is [`calculator_v2.py`](calculator_v2.py). The existing v1
manifest, calculator, and proof records are preserved and remain the v1 record; this v2
contract never qualifies or silently replaces them.

## Fixed candidate

The candidate retains the reviewed read-only geometry: `GF(2^256)`, degree `3`,
`ell=125048`, `m=172232`, `a=125049`, `m-1=172231`, `tau=33`, `L=6400`, six masks,
`S0=2^248`, `T_open=229`, and path-union acceptance threshold `n_h<=294`, with
`n_h - 2*tau + 1 <= T_open`; statement `1147` bytes and frame `534370` bytes.
The proposed inner wire is `DMV2`, wire version `2`, with signed canonical
`x.challenge_mode=2`; `DMV1`, version `1`, and challenge mode `1` are rejected by the
v2 contract. Source-commitment and relation identifiers are retained. Profile 13 is not
frozen or authorized, and Profile 12 does not inherit this proposal.

The v2 transcript models one typed, domain-separated `2112`-bit random-oracle output
with little-endian squeezing. Vendor H0/H1 rows use their exact raw canonical byte
encodings and do not receive the FS transcript prefix or part-length words. Only FS1,
FS2, and FS3 use the ASCII prefix `BL/DMV/FAEST-256F/v2` (20 bytes, no NUL), their
distinct three-byte ASCII domains, and length-prefixed canonical parts:

| domain | payload | required filter | byte-level rule |
| --- | ---: | --- | --- |
| H0 | 768 bits | bits `[768,778)` all zero | input `iv[16]||00`, exactly 17 bytes; squeeze 98 bytes; retain bytes `0:96`, byte 96 is zero and low 2 bits of byte 97 are zero |
| H1 vector | 512 bits | none | `128*96||01` is 12289 bytes and `256*96||01` is 24577 bytes |
| H1 outer | 512 bits | none | `33*64||01`, exactly 2113 bytes |
| FS1 | 2112 bits | none | prefix/domain plus `[statement,uhash,m1,sigma1]`; squeeze 264 bytes |
| FS2 | 832 bits | bits `[832,838)` all zero | prefix/domain plus `[statement,uhash,m1,sigma1,gamma1,m2,sigma2]`; squeeze 105 bytes; low 6 bits of byte 104 are zero |
| FS3 | 256 bits | bits `[256,263)` all zero | prefix/domain plus `[statement,uhash,m1,sigma1,gamma1,m2,sigma2,gamma2,m3,sigma3]`; squeeze 33 bytes; low 7 bits of byte 32 are zero |

Every canonical FS input includes `m1` of length `506416` bytes; its other fixed part
lengths are `statement=1147`, `uhash=96`, `nonce=64`, `gamma1=264`, `m2=15887`,
`gamma2=104`, and `m3=96` bytes. Each FS part is encoded as
`uint32_le(byte_length)||bytes`, including the final part. Unused suffix bits of the
common `2112`-bit output are independently sampled and ignored.

The filtered suffixes are discarded. The original 8 grinding bits, 248-bit decoder,
and exact BAVC opening checks remain mandatory.

## Required honest call order

`U` is a nonzero 96-byte, State-issued public challenge/vector. It is part of the public
statement and is independent of SOURCE coins; the contract does not claim that `U` is
independent of the statement that contains it. An honest attempt searches fresh public 128-bit IVs for H0 before creating
the BAVC commitment or sampling hidden commitment randomness. After H0 passes, hidden
randomness is sampled once, `sigma1` is fresh, `m2` is held fixed while fresh `sigma2`
values are searched for FS2; after FS2 passes, `m3` is computed and held fixed while fresh `sigma3` values are
searched for the original FS3 checks plus the FS3 filter. A rejected H0, FS2, or FS3
candidate does not rebuild the commitment. Prefix caching is valid only for a
byte-identical fixed input including its final length word; every candidate still has a
fresh nonce. H0 is never reprogrammed in the privacy game.

The public filter spaces are `2^128` IVs with per-try H0 probability `2^-10` and
`2^512` sigma2 values with per-try FS2 probability `2^-6`; the FS3 filter contributes
`2^-7` before the original FS3 gate.

The v2 candidate counters are required before a runtime claim can be admitted. `R0`, `R2`,
and `R3` count reservations made before entropy/oracle work. Each reservation has exactly
one terminal outcome; `*_first` is a separate subset count and is never added to outcomes.
Actual stage oracle evaluations are separate counters and must be at most reservations:

```text
R0 = h0_accepted + h0_rejected + h0_aborted,  h0_first = A
R2 = fs2_accepted + fs2_rejected + fs2_aborted
R3 = fs3_accepted + fs3_rejected + fs3_aborted
h0_accepted <= h0_first,  fs2_accepted <= fs2_first,  fs3_accepted <= fs3_first
h0_oracle_evaluations <= R0,  fs2_oracle_evaluations <= R2,  fs3_oracle_evaluations <= R3
fs2_first <= A and fs2_first <= R2,  fs3_first <= A and fs3_first <= R3
fs2_first = 0 implies R2 = 0,  fs3_first = 0 implies R3 = 0
A,V <= 2^32,  Q <= 2^128
R0 <= 2^16 A,  R2 <= 2^12 A,  R3 <= 2^22 A
M <= A    (only under the one-commitment-per-attempt algorithm)
P <= A + R2 + R3
```

First, rejected, crashed, abandoned, and pre-abort reservations are all charged. An RNG
failure before an oracle query is an aborted reservation with zero observed evaluations;
a crash or unknown result after reservation is aborted/unknown and later classified once
without incrementing `R`. Retry exhaustion charges every reservation and fails closed.
The manifest contains exact first-accept, reject-then-accept, all-reject, RNG-failure, and
crash/unknown cases. Missing, `UNKNOWN`, negative, boolean, non-integral, or over-cap values
fail closed. These checks are calculator admission checks only; the calculator does not
enforce them in native code or in product state.

## Filtered certificate ledger

For a fixed database with at most `j` rows outside the bad predicate, a one-row
insertion/replacement uses the following exact typed bounds:

```text
e0   = 33*binom(2^256,2)/2^778
eKOS = binom(2^248,3)*2^-1024*(1+125049^5/2^64)
e2   = (1+172231^2/2^64)/2^262
e3   = 3/2^263

H0 leaf-bad or completion : j/2^768 + e0
H1 vector                 : 34*j/2^512
H1 outer                  : 2*j/2^512
FS1                       : 2*j/2^2112 + eKOS
FS2                       : 2*j/2^832 + e2
FS3                       : e3
other typed input         : 0
```

The exact one-typed-insertion result is the maximum of these row bounds, not an
independent union sum. The exact density checks `a < 2^17` and `m-1 < 2^18` imply
`max(e0,eKOS,e2,e3)=e3`, and the calculator verifies the conservative simplification

```text
delta(j) <= 102*j/2^512 + 3/2^263.
```

H1 and full FS1/FS2 payload collisions count even when their rows are later rejected.
Witness sizes are `1` for H0 leaf-bad, `2` for a typed collision, `36` for an H1
chain, `37` for an FS1 chain, and `38` for FS2/FS3 completion. Replacement stability
and chronological extraction are mandatory. A completed descendant only matches a
pre-existing target payload; the inserted input contributes one typed row.

The conditional FAEST reference is [FAEST v3.0, Lemma 10.44, Eq. (16)](https://faest.info/faest-spec-v3.0.pdf),
fetched through the v3.0 resource link with locator PDF lines `L10147-L10168`,
zero-based PDF page index `121` (printed page `122`). The source states

```text
sqrt(Pr_{z<-A^H}[<z,P,H>]) <=
  sum_{k=1..q_alg+qP} sqrt(10*max_{x,D: |D|<=k and not P(D)}
    Pr_{u<-Y}[P(D[x->u])]).
```

The PDF was fetched through the v3.0 resource link (recorded resource `turn209view0`),
and its web resource has no local byte hash. It is used only for this generic
output-local-witness/replacement theorem; DMV2 is a synthetic degree-three filtered
fork and does not inherit applicability merely because the PDF is named. The literal
game correspondence below is therefore recorded as a conditional derivation, with
source correspondence, privacy assumptions, and operational exclusions still pending.

For clarity, the following `qP=38` and `q_hist` values are retained only for the
base filtered DMV2 certificate above. They are not the query ledger for the
single-answer wide-seed proposal below. For that proposal, `qP_single=41` and
the generator/verifier QRO calls are added explicitly.

Here `q_alg` is the pre-completion query ledger
`Q+35*A+38*V+R0+R2+R3`, and `q_eff=q_alg+qP=q_alg+38` includes the query-only
local-witness completion. With the filtered insertion bound
`delta(k)<=102*k/2^512+3/2^263`, the exact reduction chain is:

```text
sqrt(p_false) <= sum_{k=1..q_eff} sqrt(10*delta(k))
p_false <= (sum_{k=1..q_eff} sqrt(10*delta(k)))^2
          <= q_eff*sum_{k=1..q_eff} 10*delta(k)
          = 510*q_eff^2*(q_eff+1)/2^512 + 30*q_eff^2/2^263
          <= 1020*q_eff^3/2^512 + 30*q_eff^2/2^263.
```

## Conditional theorem and filtered-game correspondence

The soundness game is a static partial-oracle game over one typed ideal random oracle
`H:X -> Y`, with the five disjoint input families `H0`, `H1`, `FS1`, `FS2`, and `FS3`.
The filtered output-local predicate `P_F(D)` is defined on the finite partial database
`D` as follows:

- `LeafBad_F` is `H0`-filter-pass **and** the old `LeafBad(iv,nu)` predicate.
- Collision predicates are unchanged: two distinct active H1 512-bit payload rows,
  two distinct FS1 full-2112-bit answer rows, or two distinct FS2 832-bit payload rows
  with equal corresponding retained outputs/payloads. These rows count even when an independent suffix filter later
  rejects them; both 128- and 256-leaf H1 vector forms are active.
- `B1^F` is an explicit complete H0-passing good-`nu` chain plus old `B1`.
- `B2^F` is such a chain, local `B1` absent for that selected chain, an FS2 row whose
  six-bit suffix passes, plus old `B2`.
- `B3^F` is a valid H0/FS2-passing chain, prior local B1/B2 algebraic bad events absent
  for that selected chain, an FS3 row whose seven-bit suffix passes, plus old `B3`.

Every ancestor and filter-suffix condition is explicit in the selected witness. A
rejected terminal row alone cannot trigger a filter-discounted algebraic event. The
absence conditions above are local to the selected explicit rows and fixed deterministic
algorithms, not a choice over arbitrary global rows. Thus every false accepted filtered
proof forces `P_F` because the verifier checks the H0, FS2, and FS3 suffixes. The witness
sizes remain `1`, `2`, `36`, `37`, and `38`, so `qP=38`. Each witness is determined only
by its listed rows; if a row is replaced, remove it first, use monotonicity to preserve
`P_F=false`, and apply the same fresh-insertion bound. Rejected rows remain in the
database for collision accounting. A query-only selector may output the complete
verifier input list and perform finite exhaustive membership testing without another
oracle query; it is intentionally inefficient and does not claim an efficient reduction.

The typed encodings are part of the conditional premise, not an inferred property of
the current v1 C source:

| typed input | canonical encoding and retained answer |
| --- | --- |
| `H0` | vendor `iv[16] || 00`, exactly 17 bytes, no FS prefix or part lengths; squeeze 98 bytes, retain `raw[0:96]` as 768-bit `nu`, and require `raw[96]=0` and low 2 bits of `raw[97]=0` |
| `H1` vector | both vendor forms: `C_0 || ... || C_127 || 01` is 12289 bytes and `C_0 || ... || C_255 || 01` is 24577 bytes; retain 512 bits |
| `H1` outer | `h_0 || ... || h_32 || 01`, exactly 2113 bytes; retain 512 bits |
| `FS1` | ASCII `BL/DMV/FAEST-256F/v2 || FS1` (no NUL), then length-prefixed `[statement,uhash,m1,sigma1]`; squeeze 264 bytes and retain all 2112 bits |
| `FS2` | ASCII `BL/DMV/FAEST-256F/v2 || FS2` (no NUL), then length-prefixed `[statement,uhash,m1,sigma1,gamma1,m2,sigma2]`; squeeze 105 bytes, retain 832 bits and require the independent 6-bit suffix to be zero |
| `FS3` | ASCII `BL/DMV/FAEST-256F/v2 || FS3` (no NUL), then length-prefixed `[statement,uhash,m1,sigma1,gamma1,m2,sigma2,gamma2,m3,sigma3]`; squeeze 33 bytes, retain 256 bits and require the independent 7-bit suffix to be zero |

For FS1/FS2/FS3, every part is `uint32_le(byte_length)||bytes`, including the final
part's length word. The canonical lengths include `statement=1147`, `uhash=96`,
`m1=506416`, `nonce=64`, `gamma1=264`, `m2=15887`, `gamma2=104`, and `m3=96`
bytes. The unused suffix bits of the common 2112-bit H output are independently sampled
and ignored. The distinct vendor tags/lengths and the FS-only prefix plus distinct
three-byte domains make the canonical active input families disjoint.

For every filter, the full answer is sampled first. If `Y=(p,s)` is uniform with payload
width `b` and filter width `f>0`, then

```text
Pr[Y=(p,0^f) | pass] = 2^-b
Pr[Y=(p,s) | reject] = 2^-(b+f)/(1-2^-f),  s != 0^f.
```

Thus the payload remains uniform under either branch; rejected full answers are still
records in the game. `FS3` opening is not a filter-only event: the original grinding
bits, decoder, and final opening equation use the retained `gamma3` payload. The exact
`g` over those payloads remains `UNKNOWN`.

The filtered alteration is local to the typed row bounds. The direct filter factors apply
only when the corresponding filtered witness is present:

| row/event | conditional adaptation |
| --- | --- |
| `H0` | The independent 10-bit suffix gives `e0=33*binom(2^256,2)/2^778` for the joint `LeafBad_F` direct event. The retained `j/2^768` completion term is deliberately conservative and is not claimed to gain the filter factor. |
| `FS2` | The 6-bit suffix is independent of the original 832-bit payload; the direct `B2^F` term is the old `epsilon_z` times `2^-6`, namely `e2=(1+172231^2/2^64)/2^262`. The `2*j/2^832` collision/completion term remains conservative, and rejected FS2 rows remain collision rows. |
| `FS3` | For a fixed chain, `B3` has at most three accepting 256-bit payloads. The independent suffix changes only this terminal event to `e3=(3/2^256)*2^-7=3/2^263`; the v1 answer is not multiplied wholesale by `2^-7`. |

The one-row insertion ledger is therefore:

```text
H0       : j/2^768 + e0       (completion conservative; e0 only for LeafBad_F)
H1 vector: 34*j/2^512         (both 128- and 256-leaf vector forms)
H1 outer : 2*j/2^512
FS1      : 2*j/2^2112 + eKOS
FS2      : 2*j/2^832 + e2      (e2 only for direct B2^F)
FS3      : e3                  (only for direct B3^F)
other    : 0
```

Collisions, ancestor completion, and direct algebraic events are separate cases. A
single typed insertion takes the maximum over these rows, not an independent union sum.

The single typed insertion still takes the maximum over row types, yielding
`delta(j) <= 102*j/2^512 + 3/2^263`. H0 is never programmed. In the DMV2 game,
root and six-mask commitment coins are sampled only after the public-IV H0 search and
are independent of its accepted answer; this is a required premise, not evidence from
the current v1 source. The honest and simulator chronology is identical: fresh IV
search, one post-H0 commitment, fresh `sigma1`, fixed-`m2` FS2 search, fixed-`m3`
FS3 search, full-answer filter decisions, payload-dependent opening, and the same
stop/abort/retry outcome. Only an H0 record whose suffix passes and whose old LeafBad
predicate is false supplies good `nu`/`uhash` to the algebraic chain; rejected H0 records
remain in `D` for collision accounting but cannot supply its accepted row.

The remaining premises are not just native: source correspondence and durable DMV2
counter enforcement, the fixed-prefix/fresh-nonce honest-search condition used for
adaptive reprogramming, and the simulator's operational exclusions/concrete primitive
advantages all remain pending. The separate DMV2 source must be reviewed against the
exact encodings, causal call order, full-answer filters, unchanged-commitment retries,
and `R0/R2/R3` ledger before any native, product, or security claim is made.

## Exact query, privacy, and opportunity-count scope

The soundness ledger uses the following global query count:

```text
q      = Q + 35*A + 38*V + R0 + R2 + R3 + 38
q_hist = Q + 39*A + 41*V + R0 + R2 + R3
```

`35*A` is the per-attempt `33` H1 vector rows, one H1 outer row, and one FS1 row;
`R0`, `R2`, and `R3` are all candidate oracle calls; `38*V` is the typed verifier
ledger; and the final `38` is query-only local-witness completion. `q_hist` is the
whole-history upper-bound ledger including duplicate/reconstruction history and
aborted reservations. These formulas are conditional ledger identities, not native
counter enforcement.

The privacy game applies [GHHM Theorem 2.1](https://arxiv.org/html/2010.15103) only
to FS1 and to every FS2/FS3 event, including rejected candidates. The fetched source
record is [GHHM Theorem 2.1, Eq. (2), lines 160-173](https://arxiv.org/html/2010.15103):
its reprogramming operation samples the input distribution and then a fresh uniform
answer, and its bound is the sum of
`sqrt(qhat_r*p_max^(r)) + (qhat_r*p_max^(r))/2` over events. At each honest event the
complete typed prefix is fixed before a fresh independent 512-bit nonce is sampled;
the honest-search assumption is therefore `p_max <= 2^-512`. This does not assert that
an adaptively prequeried adversary's input is fresh.

The simulator correspondence is causal. It samples every full independent FS answer
in chronological order before testing its suffix, then selects the first
suffix/opening-passing index or the prescribed abort. Because `m2` is fixed across
rejected FS2 candidates, the selected `gamma2` remains uniform; the FS3
grinding/decoder/`T_open` gate depends only on `gamma3` indices, not seeds or witness.
Thus earlier rejected answers, queried prefixes, and selected answers have the same
joint distribution as the honest history, with `m2` and `m3` unchanged across retries
and chronological overwrite semantics for repeated inputs. No commitment or masks are
rebuilt on retry, all reprogramming charges are retained, and H0 search is real and
unprogrammed. After selecting `gamma2`/`gamma3`, the reviewed pointwise hidden-path and
six-mask endpoint change of variables is reused; no second GHHM hop is applied.

Only the final proof or prescribed abort is returned. Timing, partial-memory,
crash/recovery, and hostile-reset leakage remain outside this theorem, as do concrete
primitive advantages and RNG/custody premises.

The counter scopes are exact: `Q` is all adversarial QRO queries, `A` all admitted
honest invocations including failed/crashed/abandoned/pre-abort attempts, `V` all
backend verifier invocations, `R0/R2/R3` all durable reservations including rejected
and aborted/unknown outcomes, and `M` fresh commitments with `M<=A` only under the
one-commitment-per-attempt premise. `P<=A+R2+R3` is a conservative upper bound on
FS1/FS2/FS3 adaptive-reprogramming events; a reservation with no observed answer is
charged in the ledger but creates no H0 event. `S` counts distinct source commitments
and `E_U` counts independent source-U issuances; both are separate source opportunities,
not proof opportunities inferred from `A`. The 101 state reservations remain unchanged.
Caps, booleans, and counter identities are calculator admission conditions only; no
calculator result or current native source globally enforces them.

### Counter provenance and the Queue/State boundary

`concrete_feasibility.opportunity_scope.global_lifetime_accounting` in the manifest is a
declared model premise, not evidence that a producer measured the complete experiment. The
calculator validates caller-supplied counter shapes, identities, caps, and booleans; it receives
no authenticated global event ledger. A valid input therefore remains conditional arithmetic:
`runtime_admission.admitted` is false, and the report marks its global-lifetime scope
`UNATTESTED_GLOBAL_LIFETIME`. The offline adversary's `Q` queries are public QRO queries and may
be generated without contacting State or Queue, so neither service can enforce `Q` by reservation.

An untrusted caller can induce repeated eligible attempts, retries, verifier launches, distinct
source issuances, and cloned local histories unless the owning boundary makes each event consume
one durable permit. The honest producer must charge a service event before its work, including a
later abort or unknown result. The cryptographic caps cover the union for one complete experiment,
not whichever Queue, key epoch, process, or profile happened to report a counter.

The v2 counting map distinguishes the cryptographic experiment from any one service database:

| Count | Counted event and actor/caller capability | Namespace, lifetime, reset, and clone rule | Current enforceable point | Unclosed cryptographic assumption |
| --- | --- | --- | --- |
| `A` | Each admitted honest proof invocation, including failure/abort/crash/abandon/unknown. The honest prover creates it; an untrusted caller can induce repeated eligible requests and retries. | Union all requests, hosts, sessions, epochs, and profile instances for one DMV2 experiment; don't reset on a new request ID or key epoch. Clones must share one counter head. | Profile 12 reserves `A_upper=1` per batch at source admission in its SQLite history; this is not a global DMV2 `A` receipt. | Prove the honest path charges every invocation before work and that the caller cannot obtain extra attempts from a forked ledger. |
| `S` | Each distinct fresh source commitment/root expansion. A caller may request new source work; reproof of one immutable source does not add `S`. | Deduplicate by stable source-commitment ID across the complete experiment; no reset on process, queue, or key rotation; cloned histories share one head. | Profile 12 reserves `S_upper=4096` per source admission. This local upper bound is not the v2 observed distinct-source ledger. | Establish source identity, freshness, independence, and custody across retries and all issuing instances. |
| `M` | Each actual fresh BAVC commitment after H0 passes. The honest prover generates it; adversarial inputs/retries can induce more work. | Bind every commitment to its parent attempt. A reused commitment adds no new `M`; each regenerated one does. | Profile 12 reserves `M_upper=100` per batch while `A_upper=1`; those Profile 12 fields must not be mapped to v2 `A`/`M`. Profile 12 does not inherit this proposal. | `M<=A` requires the specific one-commitment-per-attempt algorithm; actual source correspondence must prove reuse across retries. |
| `E_U` (`U`) | Each independent issuance of a nonzero 96-byte State source value `U`; State issues it and a caller may induce another issuance. This is separate from `S` and proof attempts. | Count unique issuance events in the same global experiment across all issuers/queues; no reset on key rotation or clone. | Profile 12 reserves one `U` issuance per batch in its local history; it does not establish cross-queue/clone uniqueness. | Prove nonzero generation, independent source coins, RNG/custody, and how internal rejected zero samples are classified. |
| `V` | Every backend verifier invocation. Queue/process control launches it; an untrusted caller can induce retries or repeated claims. Charge before execution, retaining failed/unknown launches. | One experiment-wide total across Queue instances and restarts; clones must consult the same monotone head. | Profile 12 reserves `V_upper=1` before process execution in one database. There is no verified cross-database or clone-resistant union. | Prove that each actual backend invocation has exactly one prior charge and no launch path bypasses it. |
| `Q` | Every adversarial quantum random-oracle query in the ideal-QRO game, including offline work outside the service. The adversary directly controls this capability. | One complete adversary experiment; no per-host, per-tenant, per-epoch, or per-profile reset. | No State/Queue API can observe or reserve arbitrary offline public-QRO work. `Q<=2^128` is a cryptographic-model bound, not a service-enforced fact. | Supply a model-matched bound on total adversarial query/work resources; product counters cannot establish it. |
| `R0` | Each H0 candidate reservation before entropy/oracle work. The honest prover samples candidates; adversarial statements can induce attempts. Accepted, rejected, aborted, and unknown outcomes stay charged. | Stage-specific experiment-wide total linked to `A`; no attempt, crash, or clone reset. Count actual H0 evaluations separately and require them `<=R0`. | Profile 12 stores one aggregate 101-unit proof reservation per batch, not H0 reservations, outcomes, or evaluations. No mapping to v2 `R0` is established. | Prove reservation-before-query ordering, full outcome coverage, and the actual stage oracle evaluation count. |
| `R2` | Each FS2 candidate reservation before entropy/oracle work, including rejected/aborted/unknown candidates; the honest prover's retry loop is the event producer. | Stage-specific experiment-wide total linked to `A`; no attempt, crash, or clone reset. Actual FS2 evaluations remain separate and `<=R2`. | The Profile 12 aggregate reservation does not identify FS2 candidates, outcomes, or evaluations. No mapping to v2 `R2` is established. | Prove retry call order and accounting of every filtered candidate, including crashes after reserve. |
| `R3` | Each FS3 candidate reservation before entropy/oracle work, including rejected/aborted/unknown candidates; the honest prover's retry loop is the event producer. | Stage-specific experiment-wide total linked to `A`; no attempt, crash, or clone reset. Actual FS3 evaluations remain separate and `<=R3`. | The Profile 12 aggregate reservation does not identify FS3 candidates, outcomes, or evaluations. No mapping to v2 `R3` is established. | Prove retry call order and accounting of every filtered candidate, including crashes after reserve. |

The inspected Queue source is schema 13 / Profile 12. Its `queue_metadata` keeps local
`proof_attempts_used`, `source_a_used`, `source_s_used`, `source_m_used`, `source_u_used`, and
`verifier_v_used` totals; it reserves 101 proof units per exact-100 batch before issue, source
upper bounds during source admission, and `V_upper=1` immediately before verifier execution.
Unknown outcomes retain these local charges. The independent decoder reconciles the counters to
that database's rows. This is useful per-database accounting, but it has no `Q` counter and no
separate `R0/R2/R3` outcome ledger. Queue issue retries are idempotent only through the keyed v1
API and the same authoritative SQLite history; the legacy unkeyed API has no same-request retry
identity. The Queue task record explicitly says external rollback protection is not added, so a
valid database clone can fork a local lifetime unless a separate monotonic State authority rejects
the fork. Key epoch, `queue_id`, and a local hash chain do not by themselves provide that global
anti-clone authority. See Queue `app/minimal_clearance_verification_queue.py:3019-3150,
2730-3010,3477-3510,3980-3981`, its independent decoder, and
`docs/LEAN_FORMAL_KERNEL.md:497-509`.

#### Proposed State/Queue receipt: `BL/DIRECT-MASK/OPPORTUNITY-LEDGER/v1`

This is an interface proposal for a State/Queue owner adapter, not an implemented owner API or a
qualification claim. A distinct caller-held local Lean reducer now exists at
`formal/lean/BlindLedger/OpportunityAccountingV1.lean`; it is not this schema, has no global
authority, and does not change runtime admission. The proposed State/Queue API can enforce
service-generated counts only when the authoritative State writer and every producer use the same
non-forkable lifetime ledger. The request is:

```text
ReserveOpportunityV1 {
  schema: "BL/DIRECT-MASK/OPPORTUNITY-LEDGER/v1",
  scope_id: State-issued deployment-lifetime identifier,
  profile_digest: exact State-selected profile digest,
  event_id: stable unique ID for exact retry,
  kind: A | S | M | E_U | V | R0 | R2 | R3,
  delta: positive integer charge,
  parent_attempt_id: required for M, R0, R2, R3,
  source_id: required for deduplicating S and E_U,
  key_epoch: audit metadata only; never a budget namespace
}
```

State must commit the event and counter increment before the corresponding generation, candidate,
or verifier work. It returns an authenticated receipt binding `scope_id`, `profile_digest`,
`event_id`, `kind`, `delta`, monotone ledger sequence, prior/new totals, prior/new ledger roots,
and `RESERVED` status. The exact retry returns the same receipt; a changed payload under the same
`event_id` conflicts. `COMPLETED`, `REJECTED`, `ABORTED`, and `UNKNOWN` only finalize the charged
event and never refund it. Queue and the independent decoder verify the receipt inside the
existing Queue/State transaction before submit/claim/outbox mutation. A profile reset or key
rotation cannot reset totals; separate profiles need an explicit State root that unions their
receipts for a system-lifetime claim.

This interface still cannot measure adversarial offline `Q`. It also cannot prevent a cloned or
rolled-back Queue SQLite ledger from spending a second local budget unless its exact ledger root is
bound to an independently durable monotonic State anchor. State has an optional external
`AntiRollbackReference` port, but the inspected Queue counter history is not bound to it; the
bundled `InMemoryAntiRollbackReference` is test-only, and production custody must replace it with
an independently durable authority. The Queue task explicitly says external rollback protection
is not added. Reuse that State protocol only if the same ledger root, prepare/finalize recovery,
and clone rejection are proved end to end; do not add a parallel authority. Until that binding,
every producer binding, and the offline-Q model are independently evidenced, receipts are
unavailable and private-proof qualification remains blocked. The 101-unit Profile 12 reservation
stays unchanged and is not reinterpreted as `A`, `M`, `E_U`, `V`, `R0`, `R2`, or `R3`.

### Local executable reducer v1 (not a global receipt)

The reusable Security-owned Lean reducer is `formal/lean/BlindLedger/OpportunityAccountingV1.lean`.
Its separate schema is `BL/DIRECT-MASK/LOCAL-OPPORTUNITY-ACCOUNTING/v1`, and its versioned
interface, event map, cap rules, receipt encoding, owner commit/recovery contract, and explicit
limitations are recorded in `OPPORTUNITY_ACCOUNTING_V1.md`. The focused Lean examples are
source-only until Security receives the direct guarded-lane handoff. This reducer does not track
offline `Q`, authenticate or force producers, provide atomic/durable storage, establish a global
namespace, or issue an authenticated receipt. It also records service-reported stage evaluation starts
separately and enforces local `EVAL_R0<=R0`, `EVAL_R2<=R2`, and `EVAL_R3<=R3`; this is not evidence
that a producer actually invoked the evaluator. It does not alter DMV2 algebra or theorem statements,
the calculator's global-admission denial, Queue/Profile 12, State, or runtime admission.

## Query and privacy ledgers

The conditional ideal-QROM soundness expression is

```text
B_snd(q_eff) = min(1, 1020*q_eff^3/2^512 + 30*q_eff^2/2^263)
q_alg = Q + 35*A + 38*V + R0 + R2 + R3
q_eff = q_alg + qP = q_alg + 38
q_hist = Q + 39*A + 41*V + R0 + R2 + R3
```

At all declared caps, the exact calculator proves `B_snd(q_eff) < 1/4`; its exact probe
at `q_eff=ceil(2^128.5)` is still below `1/2`, so the half-success threshold is greater
than `128.5` bits. This is a conditional constant-success query bound. It is not a
`2^-128` false-acceptance probability, and it is not a concrete quantum gate/work
bound. The statistical ledger remains separate:

```text
epsilon_stat <= E_U*2^-257 + other_stat.
```

The privacy ledger programs FS1 and every rejected or accepted FS2/FS3 answer
chronologically, with the complete uniform answer sampled before applying the public
filter. It uses the adaptive reprogramming expression from [Tight adaptive
reprogramming in the QROM](https://arxiv.org/html/2010.15103):

```text
epsilon_AR <= min(1, sum_r [sqrt(qhat_r*2^-512) + qhat_r*2^-512/2])
P <= A + R2 + R3
```

With the literal v2 history, the cap is
`q_hist <= 2^128*(1+2^-73)` and the calculator verifies the proposed exact cap
`epsilon_AR < 2^-137` by integer square comparison. No rounded label is used.
Here `P <= 4198401*2^32` at the declared `A` cap; this is an adaptive-event cap, not
a soundness-event multiplier. There is no extra `101` or lifetime union multiplier on
the already-global QROM event.

For the preserved v2 baseline, the bit-hiding and source-hiding switching ledgers are:

```text
M*(397*alpha4 + 33*alpha2048 + 33*alpha989 + 85297284/2^128)
S*(alpha8 + alpha50 + 1253/2^128)
```

`M<=A` yields `85297284/2^96`. The combined `85298537/2^96` is reported only when
`S<=2^32` is separately enforced; it is never inferred from `S<=A`. The `alpha` terms,
`T*`, RNG/custody deviation, protocol SHAKE instantiation, and concrete primitive
advantages remain unknown. Hidden-key AES access is classical-input Q1; public AES
quantum computation is a separate model. No generic SHAKE-to-RO assertion is made.
The preserved v2 baseline privacy composition remains
`epsilon_priv <= min(1,epsilon_coins+epsilon_AR+epsilon_bitMH+epsilon_source+Adv_SHAKE_priv)`.

## Concrete PQ feasibility (bounded, non-qualifying)

The product authority applies the finite-lifetime `2^-128` requirement to the
complete statistical bad-event ledger and requires a separate computational PQ
work/query ledger. It does not establish that every computational privacy distance
must itself be at most `2^-128`. The comparison below therefore preserves an
additional conditional question: what happens if the complete `epsilon_priv` bound
is required to meet `2^-128`?

The v1 privacy reduction places the two fixed-width terms inside computational
privacy hybrids, not inside the protocol false-acceptance event ledger. In the
bit-hiding hybrid, classical hidden-key PRP-to-independent-random-block switching
costs at most `choose(s,2)/2^128` per challenge-key hybrid, giving

```text
epsilon_bitMH <= M*(397*alpha4 + 33*alpha2048 + 33*alpha989
                    + 85297284/2^128)
85297284 = 397*choose(4,2) + 33*choose(2048,2) + 33*choose(989,2)
```

The source-hiding hybrid independently gives

```text
epsilon_source <= S*(alpha8 + alpha50 + 1253/2^128)
1253 = choose(8,2) + choose(50,2)
```

Thus the fixed switching remainder is

```text
epsilon_switch = (85297284*M + 1253*S)/2^128
```

It can meet an additional whole-`epsilon_priv` `2^-128` requirement by itself only
if `85297284*M + 1253*S <= 1`. At the smallest nontrivial deployment, `M=S=1`,
the term is exactly `85298537/2^128`, strictly greater than `2^-128`. At the
declared lifetime caps `M=S=2^32`, it is exactly `85298537/2^96`. These are
conditional comparisons against the additional threshold, not statistical-ledger
claims and not attacks. The known statistical terms remain separately governed by
the finite theorem ledger; unknown `epsilon_coins`, `Adv_SHAKE_priv`, `alpha_s`,
and `T*` are not set to zero.

### Candidate computational work/success model

For a separate feasibility comparison, use a reversible-work threshold `T* < 2^128`
and require the total computational privacy distinguishing upper bound to stay below
`1/2`. This is the constant-success analogue of the accepted query-bound probe; it
does not replace the statistical `2^-128` ledger. At the declared caps, using the
accepted strict cap `epsilon_AR < 2^-137`, define

```text
B_alpha_exact = 1/2 - 85298537/2^96 - epsilon_AR_cap
                 - epsilon_coins - Adv_SHAKE_priv
B_alpha_safe = 1/2 - 85298537/2^96 - 2^-137
               - epsilon_coins - Adv_SHAKE_priv
```

The exact necessary-and-sufficient condition for this additive computational model is

```text
2^32*(397*alpha4(T*,Q*) + 33*alpha2048(T*,Q*) + 33*alpha989(T*,Q*))
 + 2^32*(alpha8(T*,Q*) + alpha50(T*,Q*)) <= B_alpha_exact
```

Replacing `epsilon_AR_cap` by its strict accepted upper bound `2^-137` yields the
safe sufficient threshold `alpha_s(T*,Q*) <= B_alpha_safe/(465*2^32)` when all
five primitive advantages share one cap. Before the still-unknown
`epsilon_coins+Adv_SHAKE_priv` subtraction, the safe sufficient threshold is

```text
87112285931760246646436326036005099405311
------------------------------------------------
347954309815741366765933284973092661319684419831726080
```

The corresponding safe weighted budget before those unknown terms is

```text
87112285931760246646436326036005099405311
------------------------------------------------
174224571863520493293247799005065324265472
```

These are thresholds for the named candidate model only. The AES block counts
`6,406,396*A`, `6,373,495*V`, and `58*S` do not instantiate `T*`; QRO queries are
not treated as equal-cost AES gates, and unspecified polynomial overhead is not
converted into a work claim.

The defensible work model is

```text
T* = T_adversary + T_pinned(A,V,S,Q,P) + T_fixed_circuit
     + T_hash_transpose_pack + T_opening + T_overlay
```

The pinned AES operation envelope is `6,406,396*A` blocks for commitment generation,
`6,373,495*V` blocks for reconstruction, and `58*S` source blocks. At the declared
`A,V,S=2^32` caps this is exactly `54,889,462,999,547,904` AES blocks. This is an
operation-count envelope, not a quantum gate, depth, memory, or wall-clock bound:
reversible AES costs, adversary work, exact SHAKE work, fixed circuit/hash/packing
work, opening checks, and the QRO overlay must still be instantiated. Hidden-key AES
access remains the classical-input Q1 model; public AES quantum computation is a
separate work component.

### Generic key-search primitive-game screen

The current additive reduction can be tested against a concrete generic search
algorithm without granting its hidden-key oracle to the real transcript adversary.
Let `N=2^256` candidate AES-256 keys and `n=2^128` possible block outputs. Query
one hidden key on three distinct classical input blocks, then use the public
reversible AES circuit to define the Grover predicate

```text
f(K)=1 iff AES_K(P_i)=C_i for every i in {1,2,3}.
```

For an independent false key in the ideal-permutation model, the exact matching
probability is `p=1/(n*(n-1)*(n-2))`. The real world has one distinguished correct
key, so its false-key union bound is `lambda_real=(N-1)*p`. The random-permutation
world has no distinguished correct key: all `N` public candidate keys can be
consistent, so its acceptance union bound is separately `lambda_ideal=N*p`.
The two bounds are therefore

```text
lambda_real=(N-1)/(n*(n-1)*(n-2))
  = 340282366920938463463374607431768211457
    /115792089237316195423570985008687907852589419931798687112530834793049593217024.

lambda_ideal=N/(n*(n-1)*(n-2))
  = 170141183460469231731687303715884105728
    /57896044618658097711785492504343953926124568782438874324533730092808912502785.
```

Three pairs are the source-model minimum for an AES-256 key-search screen; four
pairs are the conservative exact-permutation choice for a roughly `2^-256` union
bound. Three are sufficient here because the distinguisher accepts any consistent
candidate and retains the two exact world-specific bounds explicitly. Define the
distinguisher to output one only when its measured candidate matches all three
pairs. With distinguishing advantage defined as the absolute real-versus-random
acceptance gap, the primitive game gives the lower bound

```text
Adv_j >= (1-lambda_real)*sin^2((2*j+1)*arcsin(2^-128))-lambda_ideal.
```

The random-permutation acceptance probability is at most `lambda_ideal`, because
there is no designated correct key and all `N` candidate keys are included in its
union. In the real world, with probability at least `1-lambda_real` there is no
false candidate, leaving the correct key as the unique marked item. This is a Q1
game: the three hidden-key queries are classical and preprocessing only; the search
uses public AES evaluation and zero QRO queries. This is not a transcript attack.

At the declared caps, write `u=epsilon_coins+Adv_SHAKE_priv`. The exact uniform
alpha threshold is

```text
theta(epsilon_AR_cap,u) =
  (1/2 - 85298537/2^96 - epsilon_AR_cap - u)/(465*2^32).
```

The most certificate-favorable screen sets all three unknown deductions to zero,
including `epsilon_AR_cap=0`; this is a necessary-feasibility screen, not a security
assumption. It gives

```text
theta_best =
13204693752377389598895558877
--------------------------------
52743766872745461836823064151924072775680
  ~= 2.503555308106125e-13.
```

The exact break-even iteration definition is

```text
j_break = min { j >= 0 :
  (1-lambda_real)*sin^2((2*j+1)*arcsin(2^-128))-lambda_ideal
    > theta(epsilon_AR_cap,u) }.
```

This uses the standard Grover rotation and the retained [Zalka optimal-search
convention](https://arxiv.org/abs/quant-ph/9711070); it is a primitive-game query
screen, not a claim that the direct-mask adversary receives a quantum AES oracle.

At the certificate-favorable screen, a high-precision numerical evaluation gives
`j_break ~= 85131060672178469145225451028192`. A separately rationally certified
choice is `j=85131060672178469145225451128192`: with
`x=2^-128`, `z=(2*j+1)x`, and `sin(z)>=z-z^3/6`, its exact Fraction lower bound
with the separate `lambda_real` and `lambda_ideal` terms is strictly above
`theta_best`. The angle replacement is bounded before use: for `0<=x<=1/2`,
`x<=arcsin(x)<=2x`; the certified integer satisfies `0<z<1/4`, hence the actual
angle lies in `z <= (2j+1)arcsin(x) <= 2z < 1/2 < pi/2`. Sine is increasing on
that interval, so `sin(actual_angle)>=sin(z)>=z-z^3/6`. Increasing `u` or
`epsilon_AR_cap` only lowers the threshold and therefore cannot rescue this screen.

Use the logical `G`-count convention from [Jaques et al.'s full AES Grover-oracle
implementation](https://arxiv.org/html/1910.01700v1): one CNOT, one-qubit Clifford,
T gate, or measurement is one work unit; disjoint gates may run in parallel; width
is retained; `P=1` and QRO queries are zero for this screen. Their AES-256, three-pair
oracle costs are:

```text
                 G-cost       full depth     width
in-place MC      1,844,106       3,347       6,913 qubits
Maximov MC       1,852,812       1,956      11,905 qubits
```

Table 8 already includes the AES comparison and encryption uncomputation, so neither
is charged again inside an iteration. Table 3's AES-256 in-place operator has
`402,878` CNOTs, `114,778` one-qubit Clifford gates, `75,072` T gates and `18,768`
measurements, hence `611,496 G`; this corrected operator cost is used only for the
separate history/validation accounting.

For the missing diffusion, use the exact standard Clifford+T Toffoli circuit (1) in
[Selinger](https://arxiv.org/html/1210.0974), transcribed as six CNOTs, two H gates,
one S gate and seven T/T-dagger gates, with conservative serial depth `16` and no
measurement.
Compute a 256-bit AND into `255` clean chain ancillas with `255` forward Toffolis,
apply `Z` to the final chain bit, and reverse all `255` Toffolis. Surround this
phase with `H^256 X^256` and `X^256 H^256`. The clean chain returns exactly to zero;
the phase is `I-2|1^256><1^256|`, so the resulting diffusion differs from
`2|+^256><+^256|-I` only by a global minus sign.

The explicit diffusion count is

```text
510*16 + 512 H + 512 X + 1 Z = 9,185 G
serial depth = 2*255*16 + 4 layer gates + 1 Z = 8,165
width = 256 key qubits + 255 clean chain qubits = 511 qubits.
```

Using the in-place AES oracle, one complete Grover iteration is therefore
`1,844,106+9,185=1,853,291 G`, serial depth `3,347+8,165=11,512`, and peak width
`6,913` because the diffusion chain reuses cleaned AES workspace. The Maximov
alternative is `1,861,997 G` and depth `10,121`; the in-place variant is the selected
minimum-work strategy.

The exhibited primitive-game algorithm has its own complete cost and does not
artificially include product history or QRO overlay. It initializes the source
width conservatively (`6,913` clean-state preparations), applies `256` H gates for
the initial key superposition, makes the three classical hidden-key queries, runs
`j` complete iterations, measures the `256` key bits, and validates the candidate
with three public AES evaluations and three classical block comparisons. For one
integer G screen, the three final AES evaluations are conservatively charged as
`3*611,496=1,834,488 G`-equivalent; the three hidden-key queries and three
comparisons remain separately reported classical resources. The fixed G cost is
therefore `1,841,913`, and the strict primitive condition is

```text
T_primitive_G = 1,841,913 + j*1,853,291 < 2^128.
```

At the certified break-even iteration count, this complete primitive cost is
`157772628564202307260624021546819921785 G`, strictly below `2^128`, and its
rational lower-bound advantage is `2.503555308106125e-13`, just above the
certificate-favorable threshold. At the strict full primitive work cap,

```text
j_primitive_cap = 183609787626950362065846436113792
T_primitive_G  = 340282366920938463463374607431767531385
slack          = 680071 G below 2^128.
```

The serial depth at that cap is
`2113715875161452568102024172541973507` (log2 approximately `120.66919287921058`),
with width `6,913`. The exact rational lower bound there is
`1.1645891989497403e-12`; the current weighted lower bound is
`2.325870723085247`, above the known residual `1/2-85298537/2^96`.

The product reduction's whole-history simulation is a separate auxiliary screen.
At the caps, `54,889,462,999,547,904` AES blocks charged once at `611,496 G` cost
`33,564,687,066,371,545,104,384 G` (`~2^74.82936`), not part of the primitive
algorithm's `T*`. If that history is included, the one joint inequality is

```text
T_product_G = known_history_G + T_overlay_once + T_nonAES_once
               + 1,841,913 + j*1,853,291 < 2^128.
```

The unknown overlay and non-AES costs consume the same residual; the per-iteration
and one-time margins are not independently spendable. With those unknowns set to
zero only for this auxiliary screen, the strict cap is
`j=183609787626950343954990091173065`, total
`340282366920938463463374607431767753212 G`, leaving `458244 G`. At the certified
break-even count, the product auxiliary residual before unknown costs is
`182509738356736122638063519513403185287 G`.

From the fully counted primitive cap, keeping the weighted term below the known
residual would require an effective weight no larger than `429,335,941,335`, or a
conditional reduction factor of at least `4.651741446173654` from
`465*2^32`. At the certified break-even count the corresponding figures are
`1,997,159,792,639` and `1.0000000000005007`; these are margin diagnostics, not
unconditional remedies or sufficient security theorems. The earlier `4.698...`
figure was tied to an oracle-only optimistic cost and is not retained as a remedy
requirement. The hybrid loss remains a hybrid/triangle loss, not a demonstrated
multi-target attack. The transcript grants neither a joint target oracle nor
hidden-key superposition access; parallel Grover width/depth tradeoffs do not remove
the loss.

This yields a quantitative conditional obstruction to the current additive
certificate under the fully counted single-key ideal-cipher primitive game, while
leaving the real full-round AES Q1 multi-instance theorem and product overlay/non-AES
costs open. It is not an attack on the real transcript, and no native consequence,
target/cap change, primitive replacement, profile qualification, or activation follows.

### Tighter composed privacy analysis: literal exposure and the accepted boundary

The following is the joint exposure map used for the next reduction attempt. It is
anchored to the retained v1 source, not to a claim that the proposed DMV2 call order
is implemented. In `vendor/faest-ref/bavc.c:22-40`, one 256-bit root seed is expanded
through a 6,399-internal-node, 6,400-leaf heap by `PRG_2lambda` with public IV/tweaks.
In `:326-385`, the opening marks 33 selected leaves and their ancestors, emits the
33 selected commitment values and a canonical frontier of at most `T_open=229`
256-bit seeds, and reconstructs the unmarked subtrees. Thus the public frame exposes
the statement, `nu`, three 64-byte nonces, `m1=506416`, `m2=15887`, `m3=96`, and
`m4=10496` bytes (534370 bytes including the 40-byte header), but does not expose
the root, selected-leaf seeds, selected-leaf `PRG_4lambda` outputs, or hidden
direct-mask streams. The 33 selected commitment values occupy `33*96=3168`
bytes and the maximum frontier seed area occupies `229*32=7328` bytes.

The selected leaves are one per group: 17 groups of width 8 and 16 groups of width
7. Their hidden internal-path union has at most
`1+33*ceil(log2(6400)-1)=397` nodes. At each hidden leaf,
`vendor/faest-ref/bavc.c:61-67` uses an 8-AES-block `PRG_4lambda` expansion; the
direct row conversion in the retained v1 source uses each resulting `sd` block as
an AES stream key and charges 989 output blocks for the declared row length. The
conservative leaf hybrid budget is `8*max(N_i)=2048`. These are structured
dependencies: sibling child seeds share a parent PRG, all descendants share the
root, and a stream key is derived from the leaf expansion. The six 256-bit masks
are packed direct-VOLE rows/u bits and are covered by the joint change of variables;
they are not six new independent AES targets.

For a fresh request, `A` includes every admitted success, abort, crash, abandonment,
or unknown outcome; `M` counts fresh commitments only; `S` counts distinct source
commitments/root expansions; and `P<=A+R2+R3` retains every FS1/FS2/FS3
reprogramming event. H0 is searched before root/mask coins, one commitment is reused
across retries, and every full FS answer is sampled before its filter/opening test.
The source hybrid has its own dependence boundary:

```text
G0(r)=AES256_r(0)||...||AES256_r(7) -> (K,Z)
T=U*iota(K)+Z
G1(K)=AES256_K(2^127+j), j=0..49
C=V xor G1(K)
```

`K` is not independent of `r` before the G0 hop, and G1 is not an independent-key
experiment before that hop. Reproofing one immutable source does not increment `S`.
The global adversary can evaluate public AES, test every public field, and query the
typed QRO across all requests. It cannot query hidden-key AES in superposition.

Two possible composition routes were considered. A black-box multi-target search
route is rejected for this transcript. The primary model in
[Banegas--Bernstein, Section 1.5 and Section 2](https://eprint.iacr.org/2017/789)
supplies a quantum database oracle and independent target images; its exact database
formulation is a different access interface. DMV2 supplies no coherent target table,
and no joint hidden-key oracle. It does publish selected 96-byte leaf commitment
values, and a candidate seed has a public predicate through the exact IV/group
tweak, PRG expansion, universal hash, and commitment comparison. The missing
interface is therefore independent target images plus coherent access, not predicate
existence. Importing that lemma, dividing the hybrid weight by a target count, or
treating parallel Grover copies as free would still change the game. A redesigned
version would also have to charge target-table construction, coherent lookup/QRAM
memory, every target comparison, uncomputation, QRO overlay, and width; it is
outside this phase.

The selected route is a direct structured-generator theorem, recorded as an
explicit conditional interface rather than an invented numeric result. Let
`beta_joint(T*,Q*,Mem*)` be the maximum advantage of one adversary distinguishing
the complete real tree/leaf-stream/source generator from the independent endpoint,
with the exact public transcript, global QRO, classical hidden-key Q1 reduction
access only, one total work/query/memory budget, and all reversible simulation costs.
The tighter conditional composition is

```text
epsilon_priv <= min(1,
    epsilon_coins + epsilon_AR
    + beta_joint(T*,Q*,Mem*)
    + (85297284*M + 1253*S)/2^128
    + Adv_SHAKE_priv).
```

At `M=S=2^32`, and using the separately accepted safe
`epsilon_AR < 2^-137`, the unknown direct-generator term must satisfy

```text
beta_joint(T*,Q*,Mem*)
  <= 1/2 - 85298537/2^96 - 2^-137
     - epsilon_coins - Adv_SHAKE_priv.
```

With only `epsilon_coins=Adv_SHAKE_priv=0` for this diagnostic, the exact known
right-hand side is
`87112285931760246646436326036005099405311 /
174224571863520493293247799005065324265472`.
This is a complete conditional inequality, not a claim that the right-hand side is
met. The only currently proved upper bound for `beta_joint` is the retained hybrid
triangle bound:

```text
beta_joint <= 2^32*(397*alpha4 + 33*alpha2048 + 33*alpha989)
           + 2^32*(alpha8 + alpha50).
```

The old expression remains valid because each reduction receives a full counted
history; it cannot be rewritten as `sum_i c_i*alpha_i(T_i,Q_i)` with
`sum_i T_i<=T*` without a new joint theorem. Separate alpha suprema are not one
simultaneous adversary. At the fully counted single-key screen, the current effective
weight is `465*2^32=1,997,159,792,640`, while the known residual and the exhibited
primitive lower bound require an effective weight no larger than `429,335,941,335`,
or a reduction factor of at least `4.651741446173654`. This is a conditional
design handoff, not a real-transcript attack.

The joint work ledger is one inequality, not independent allowances:

```text
T_joint = T_adversary + T_pinned + T_fixed_circuit
        + T_hash_transpose_pack + T_opening + T_table
        + T_coherent_access + T_candidate_checks
        + T_reversible_uncompute + T_overlay < 2^128.
```

`Q_joint` includes all global QRO queries and the reversible programmed-entry
overlay. `Mem*` includes transcript/frontier storage, AES workspace, candidate or
table storage, coherent lookup workspace, and overlay/program memory. Any table,
candidate predicate, or overlay must be computed, compared, copied, and uncomputed
or retained and charged. Parallel depth/width changes do not reduce total G work.
The known product history remains charged once at the caps:
`33,564,687,066,371,545,104,384 G`; it is not multiplied per hybrid, and its
unknown overlay/non-AES cost shares the same residual.

The smallest quantitative proof remedy is therefore a model-matched theorem for
`beta_joint` under this exact dependence/access boundary, reaching effective loss
`<=429335941335` at the fully counted cap. If a future architecture instead creates
the missing black-box target access, it must change the exact hidden-key
dependence/access boundary, for example by using independent leaf targets and a
charged coherent table. That would move opening storage from the current
229-seed/10496-byte contract toward disclosure of up to `6367*32` bytes of
per-leaf seeds before commitments, and would change prover/verifier work and wire
size. No such redesign, target/cap/field/mask/protocol/native/product/Profile13, or
activation change is authorized here.

The real full-round model-matched primitive result is still missing. [FIPS 197](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf)
specifies AES-256's 256-bit key and 128-bit block, but supplies no `alpha_s(T*,Q*)`
for this experiment. [Zhandry's QRF paper](https://eprint.iacr.org/2012/182)
distinguishes a quantum adversary with classical queries from one with superposition
queries; Q2 results are not silently transferred to this Q1 ledger. [Zalka's search
bound](https://arxiv.org/abs/quant-ph/9711070) applies to black-box unstructured
search with quantum oracle access, so it is not substituted for the hidden-key Q1
PRP/PRF advantage. The multi-user literature requires explicit user/key accounting:
[Hoang--Tessaro](https://eprint.iacr.org/2017/145.pdf) gives a classical
ideal-cipher example, while [Banegas--Bernstein](https://eprint.iacr.org/2017/789)
shows that multiple quantum targets can change search costs; neither supplies a
numeric bound for this Q1/QROM construction. [The AES quantum analysis](https://eprint.iacr.org/2019/272)
contains Q1 reduced-round analysis and a single-secret-key security study, but not
the full-round, independent-key, multi-instance PRP/PRF theorem required here. The
Q1 attack result for permutation-based PRFs
([Sun et al.](https://eprint.iacr.org/2025/501)) is construction-specific and does
not establish an attack on raw full-round AES-256 from this protocol's transcript.
[FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
defines SHAKE as an XOF and leaves application security to additional considerations;
it does not provide `Adv_SHAKE_priv`, and no generic SHAKE-to-random-oracle
equivalence is assumed.

The current decision is: no applicable attack is established against the switching
terms or retained transcript; the additional whole-`epsilon_priv` `2^-128`
comparison fails even at `M=S=1`; and the fully counted single-key ideal-cipher
primitive algorithm obstructs the current additive certificate below strict
`2^128` G work. The remaining product gap is the full-round independent-key Q1
multi-instance reduction plus product QRO-overlay/non-AES costs. The fully counted
`4.651741446173654` loss figure is only a conditional necessary margin diagnostic,
not an unconditional remedy or sufficient real-AES theorem. This task does not
lower the statistical target or caps, replace a primitive, qualify a profile, or
permit activation.

## Bounded wide-seed generator feasibility comparison (unselected design)

This section records the authorized design-only comparison between the current AES
generator and one explicit domain-separated ideal-random-oracle seed expander. It
does not select a new protocol, change the v2 wire, authorize native work, or add
security credit. The calculator returns the same record under
`constant_success_work_model.bounded_generator_feasibility_proposal` and requires
the status `UNSELECTED_IDEAL_ORACLE_WIDE_SEED_PROPOSAL`.

The authoritative candidate in this section is the single-answer design
`DMV-RO-WIDE-SEED-v2`. The older multi-block design is retained below as
`DMV-RO-WIDE-SEED-v1` superseded evidence only. The two designs are not
byte-equivalent; no v1 number is silently relabeled as v2.

The literal public predicate is available in the current transcript. The selected
33 leaf commitments are public 96-byte values. Given the public IV/group tweak, a
candidate current leaf seed can be expanded with the public eight-block
`PRG_4lambda`, evaluated through `leaf_hash_256` and
`com=nu*iota(sd)+tail`, and compared with the published commitment. This is a
charged reversible public computation; it does not grant a hidden-key AES Q2
oracle or an independent-target database oracle.

Selected leaf and stream seeds remain hidden. The opening publishes the 33 selected
96-byte commitment values and the canonical frontier; the verifier reconstructs
unselected leaves from disclosed frontier material. No selected seed bytes are
added, and no soundness argument may treat their disclosure as necessary. Any
binding proof must instead charge explicit global-QRO rows or a separately proved
completion/extraction step.

The current geometry is 6,399 internal nodes, 6,400 leaves, and 12,799 heap nodes
per fresh BAVC commitment. The current leaf expansion uses eight AES blocks, the
leaf commitment remains 96 bytes, and the current direct row stream is 15,823
bytes (989 AES output blocks). The literal opening check is
`n_h - 2*33 + 1 <= 229`, so an accepted opening has `n_h <= 294` and at most 261
marked internal nodes. It discloses at most 229 frontier seeds. The accepted
opening therefore hides at most `261+33+33=327` tree/stream seeds, but the
conservative lifetime coupling uses all `12,799+6,400=19,199` secret seeds per
fresh commitment for failed, retried, rejected, crashed, abandoned, or aborted
attempts. Each new proof invocation samples fresh BAVC commitment/mask coins and
a fresh root after H0, consumes `A`, and creates a fresh `M` commitment. Internal
FS retries, rejected candidates, and prescribed aborts reuse that root. A reproof
of one immutable SOURCE commitment is a new proof invocation with fresh BAVC
coins/root and increments `A/M` but not `S`; exact byte-identical retransmission
creates no new proof instance and increments none of `A/M/S`, although its
verification work is charged.

The candidate `G` is one typed ideal random oracle whose answer is always the full
`2112` bits. The literal framing is `LP(b)=uint32_le(len(b))||b`, with all integer
fields little-endian and all seed/IV byte strings fixed-width. Every input begins
`uint8_le(0xd7)||LP(ASCII("DMV-RO-WIDE-SEED-v2"))`, where the version is exactly
19 bytes, followed by `uint16_le(w)` and one domain byte:
`TREE_CHILD=0x01`, `LEAF_OUTPUT=0x02`, `ROW_STREAM=0x03`. The secret seed is
included in every seeded input, not omitted:

```text
TREE_CHILD = 0xd7 || LP(version) || uint16_le(w) || 0x01
             || LP(IV[16]) || LP(parent_seed[w/8])
             || uint32_le(node_index) || uint8_le(child_role)
             || uint32_le(counter), child_role in {0x01,0x02}, counter=0

LEAF_OUTPUT = 0xd7 || LP(version) || uint16_le(w) || 0x02
              || LP(IV[16]) || LP(leaf_seed[w/8])
              || uint32_le(leaf_index) || uint8_le(0x10)
              || uint32_le(0), counter=0 only

ROW_STREAM = 0xd7 || LP(version) || uint16_le(w) || 0x03
             || LP(IV[16]) || LP(stream_seed[w/8])
             || uint32_le(leaf_index) || uint32_le(row_index)
             || uint8_le(0x20) || uint32_le(counter),
             counter=0..ceil(15823/(w/8))-1
```

`G` returns one full `2112`-bit answer for every call. `TREE_CHILD` retains its
first `w` bits. `LEAF_OUTPUT` uses only its counter-0 answer and retains exactly
the first `1024+w` bits as `sd[256]||tail[768]||stream_seed[w]`. `ROW_STREAM`
takes the first `w` bits of each counter answer, concatenates them in counter
order, and truncates to exactly 15,823 bytes; unused suffixes and the final
partial block are discarded. There is no implicit padding or second oracle call.
The 0xd7 prefix and exact lengths make these inputs disjoint from the existing
FS/vendor families. One fresh `w`-bit root is expanded with two counter-0
`TREE_CHILD` calls per internal node. The source G0/G1 AES generator is retained:

```text
G0(r)=AES256_r(0)||...||AES256_r(7) -> (K,Z)
T=U*iota(K)+Z
G1(K)=AES256_K(2^127+j), j=0..49
C=V xor G1(K)
```

Widening the BAVC root, leaf, and stream seeds does not widen source `K`. The
existing `alpha8` and `alpha50` terms remain explicit; removing them would change
the source relation and requires a new source binding, hiding, transcript, native,
and verifier proof.

At the unchanged caps `M=S=A=2^32`, `Q=2^128`, the retained base history and
overlay counts are:

```text
P = 4,198,401*2^32 = 18,031,994,990,493,696
q_hist = 2^128 + 4,264,016*2^32
        = 340282366920938463463392921241037832192
Q*_base = 2*q_hist + P
         = 680564733841876926926803874477066158080
N_seed = 19,199*2^32 = 82,459,077,115,904
N_leaf = 6,400*2^32 = 27,487,790,694,400 (historical v2 diagnostic; not used by v3)
```

The old v1 multi-block arithmetic is preserved explicitly as superseded evidence:

| seed width | old leaf H blocks | old stream H blocks/row | old H calls/commitment | old H calls at caps | frontier seed | m4 / frame incl. 40-byte header |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 384 bits | 4 | 330 | 2,150,398 | 9,235,889,083,383,808 | 48 bytes | 14,160 / 538,034 bytes |
| 512 bits | 3 | 248 | 1,619,198 | 6,954,402,455,748,608 | 64 bytes | 17,824 / 541,698 bytes |

For the authoritative v2 single-answer design, the generator H-query count per
fresh commitment is
`2*6399 + 6400*(1+ceil(15823/(w/8)))`. The conditional verifier reconstruction
ledger charges
`2*(6400-1) + (1+ceil(15823/(w/8)))*(6400-33)` per verification. These are
QRO calls only; coherent parsing, comparison, copying, uncomputation, overlay,
and memory remain separate work costs. The evaluated alternatives are:

| seed width | leaf H blocks | stream H blocks/row | generator H calls/commitment | generator H calls at caps | verifier H calls/verification | verifier H calls at caps | frontier seed | m4 / frame incl. 40-byte header |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 384 bits | 1 | 330 | 2,131,198 | 9,153,425,711,300,608 | 2,120,275 | 9,106,511,783,526,400 | 48 bytes | 14,160 / 538,034 bytes |
| 512 bits | 1 | 248 | 1,606,398 | 6,899,426,874,359,808 | 1,598,181 | 6,864,135,128,088,576 | 64 bytes | 17,824 / 541,698 bytes |

For the candidate row ledger, let `G_M(w)` and `G_V(w)` be those generator and
verifier counts at the actual admitted `M` and `V`. The new global ledgers are

```text
q_hist_v2 = (Q + 39*A + 41*V + R0 + R2 + R3) + G_M(w) + G_V(w)
q_alg_v2  = (Q + 35*A + 38*V + R0 + R2 + R3) + G_M(w) + G_V(w)
qP_single = 41 = 38 + 3
q_eff_single = q_alg_v2 + qP_single
q_total = (2*q_hist + P) + G_M(w) + G_V(w)
```

The `+3` is a conservative local-completion charge for the candidate H0/LEAF
rows in a row-complete binding witness. It is not selected-seed disclosure and
does not authorize an uncharged search.

The former coupling expression is superseded, not a bound. The directly
applicable primary source is the corrected author revision of [Saito--Xagawa--
Yamakawa, Lemma 2.2](https://eprint.iacr.org/2017/1005.pdf). The revision is
dated 2021-08-25; its statement is PDF page 6, extracted lines L403--L426, and
its proof is Appendix C.1, PDF page 26, L2312--L2405. For independent random
oracles `H:{0,1}^ell x X -> Y` and `H':X -> Y`, a quantum adversary
distinguishing `(H,H(s,.))` for uniform `s` from `(H,H')`, with at most `q_H`
oracle queries, has advantage at most:

```text
2*q_H*2^(-ell/2)
```

All oracle accesses may be quantum. The revision note explicitly corrects the
earlier coefficient; the conference coefficient is not used.

For the literal candidate, `ell=w` is the hidden parent/leaf/stream seed and
`Y={0,1}^2112` is the full answer of the one global typed QRO. `X` is the public
context after the exact `0xd7`, length-prefix, version, width, domain, IV, index,
role, and counter fields are parsed. The real candidate evaluates
`H(s,x)=G(Encode(s,x))`; the keyed endpoint evaluates an independent `H'(x)` for
that one hidden seed. It retains the full 2112-bit answer and only then projects
the first `w` bits, or the first `1024+w` bits for `LEAF_OUTPUT`, or the first
15,823 bytes for `ROW_STREAM`; the final partial block is truncated and no
implicit padding is added to the transcript. Suffix bits are not a second free
oracle.

The global query is routed coherently: a reversible parser computes a valid-
candidate flag and selects the keyed restriction for valid encodings, while
invalid inputs and all existing FS/vendor domains use the same complement/base
oracle. The query superposition is never measured. One generator, adversary,
verifier, FS lookup, or programmed-overlay access is one global QRO call in the
same history; routing, parsing, comparisons, copying, uncomputation, truncation,
padding, overlay selection, and memory are separate `G`/workspace costs. The
reduction keeps an unknown challenge seed as an internal key handle and never
serializes it.

The privacy hybrid now has a concrete induction. Step 1 first pre-samples and
programs FS challenges with the existing retry/abort chronology. Step 2 replaces
hidden tree ancestors in topological order, then hidden leaf outputs and hidden
row streams; replaced ancestors give uniform child seeds, while disclosed frontier
subtrees and public unmarked descendants remain real. One `H'(x)` function covers
all contexts for one seed, including repeated IV/role/counter uses. Failed,
rejected, reused, reproofed, and aborted candidates remain in the global history.
Step 3 is the existing six-mask affine change of variables, applied only to the
endpoint's hidden uniform streams. The FS overlay is disjoint by the literal
encoding and is charged once through the existing `epsilon_AR`/global history;
the keyed replacement does not create a second oracle budget or rerun FS
programming.

Fresh root and derived seed values are counted over the full retry/abort lifetime,
`N_seed=19,199*M`. Internal retries reuse one commitment/root, but a new proof
invocation, including a reproof of one immutable SOURCE commitment, uses fresh
BAVC coins/root and consumes `A/M`; only `S` stays unchanged for that source
reproof. Exact byte-identical retransmission creates no new proof instance, while
verification work remains charged. Equal bytes at different contexts are handled
by the same keyed function, not by independent targets. The conservative endpoint
conditions distinct fresh seed values and charges `binom(N_seed,2)/2^w`; this is a
seed-induction conditioning term, not a binding claim. With `q_total` equal to the
complete global history, the conditional ideal-generator privacy term is:

```text
epsilon_keyed_o2h_privacy(w)
  <= min(1, 2*N_seed*q_total*2^(-w/2) + binom(N_seed,2)/2^w).
```

This is the proved primitive subclaim under the stated ideal keyed game and
existing Step 1/Step 3 endpoint. It does not qualify the complete candidate.

Soundness remains separate. Conditioned on no old-style different-`sd` equal-
commitment event, the exact new event is:

```text
Bad_stream_fork_F = two distinct accepted leaf seeds for one exact public IV,
                    leaf/group context, opening position, and 96-byte com,
                    with equal sd and tail but distinct stream_seed or
                    ROW_STREAM output.
```

The old AES `LeafBad_F`/local-certificate credit is not inherited by the G
candidate. The selected leaf/stream seeds remain hidden; the public commitments
and frontier do not by themselves put the selected `LEAF_OUTPUT` rows in the
global QRO database. Honest-leaf birthday counts do not bound an adaptive
commitment fork. A row-complete local witness is therefore conditional on an
explicit QRO-row or charged completion/extraction premise. No exhaustive
`2^w` enumeration of unqueried seeds is free, so this exact premise—not a
disclosure change—stops the complete epsilon bound and width minimum.

The retained local-certificate route gives the following replacement-stable
conditional ledger. It uses the supplied `LOCAL_CERTIFICATE_PROOF.md` sections
5--7 and the stated FAEST Lemma 10.44/Eq. (16) output-local-witness route; it
does not transfer the old all-key AES LeafBad union to w-bit QRO seeds. For
`k` rows in the pre-insertion database, the typed last-row entries are:

```text
H0           binom(k,2)/2^778 + k/2^768
LEAF_OUTPUT  k/2^1024 + k/2^768
H1 vector   34*k/2^512
H1 outer    2*k/2^512
FS1         2*k/2^2112 + e_KOS,  e_KOS <= 3/2^256
FS2         2*k/2^832 + epsilon_z, epsilon_z <= 3/2^256
FS3         3/2^256
other       0
```

The first H0 term is the exact 768-bit `nu` target plus the independent H0 filter
for existing LEAF pairs with different `sd`; the second is conservative completion.
The LEAF term covers a same-context `1024`-bit `sd||tail` PrefixFork with a
different stream and a different-`sd` equal-commitment target against an existing
passing H0 row. An already-passing suffix is not counted again. A single insertion
uses the maximum typed row bound, and replacement first removes the replaced row.
The safe algebraic upper bound is

```text
delta_single(k) <= binom(k,2)/2^778 + k/2^768 + k/2^1024
                  + 34*k/2^512 + 2*k/2^2112 + 2*k/2^832
                  + 3/2^256.
```

The two new witness relations are explicit: `PrefixFork` has two distinct
`LEAF_OUTPUT` rows at one exact IV/leaf context with equal first `1024` bits and
different w-bit streams; `CommitFork` has two such rows with different `sd`, equal
`com` under the actual filtered H0 row, and that passing H0 row. The old filtered
chain remains explicit. Its conservative local-completion charge is
`qP_single=41=38+3`: the retained 38-row chain plus at most the three H0/LEAF
rows for the candidate binding witness. This is a query charge, not selected-seed
disclosure.

If every selected LEAF row is already in the global QRO database or is obtained by
that separately charged completion, then with
`q_eff_single=q_alg_v2+qP_single` the conditional theorem route is

```text
sqrt(p_false) <= sum_{k=1..q_eff_single} sqrt(10*delta_single(k))
p_false <= (sum_{k=1..q_eff_single} sqrt(10*delta_single(k)))^2.
```

The current hidden-selected-seed verifier does not prove that row-completeness
premise for every accepted false proof. The candidate therefore remains
conditional even though the explicit row ledger and the exact qP charge are
recorded.

The old arithmetic sensitivity values remain in the calculator as superseded
conditional evaluations only:

```text
w=384: old-formula value 4.3426941769355606e-22; m4=14160; frame=538034
w=512: old-formula value 9.6095026892492341e-61; m4=17824; frame=541698
```

They establish no epsilon bound and no sufficient width. The exact known
half-success residual before candidate/source-alpha terms remains
`87112285931760246646623896747156522926079 /
174224571863520493293247799005065324265472`, but the composed record now contains
the conditional keyed privacy term. Privacy and soundness remain separate ledgers:
the keyed term is a privacy-only diagnostic, while the row-complete soundness
expression below is conditional on explicit selected LEAF rows or charged
completion.

At the declared caps, the calculator's conditional keyed term is `1.7880462110042572e-05`
for `w=384` and `9.6930179323764516e-25` for `w=512`. These values include the
full `q_total` history and the distinct-seed conditioning term; they are privacy-
only diagnostics and do not establish a complete candidate width.

```text
epsilon_priv(w) <= min(1,
    epsilon_coins + epsilon_AR + epsilon_keyed_o2h_privacy(w)
    + S*(alpha8 + alpha50 + 1253/2^128)
    + Adv_H_SHAKE(w) + epsilon_source_U + epsilon_operational).
```

The separate row-complete soundness expression is

```text
epsilon_snd_single_row_complete(w)
  <= min(1, (sum_{k=1..q_eff_single}
             sqrt(10*delta_single(k)))^2)
```

It is not folded into the privacy line and does not qualify the candidate until
its row-completeness premise, concrete SHAKE/QRO realization, source-U,
operational, and source-alpha terms are all closed.

Therefore the minimum sufficient seed width is `UNKNOWN_HIDDEN_LEAF_ROW_COMPLETION`; 384
bits is only the least evaluated arithmetic width, not a security minimum. [FIPS
202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) describes SHAKE256
as an XOF with 512-bit capacity and rate 136 bytes and a classical strength
statement up to 256 bits; it does not supply the missing concrete QROM realization,
stream-fork binding, or work theorem. No unproved AES lower bound is used.

The engineering consequences are limited and explicit. `m1`, `m2`, `m3`, the
statement, `nu`, nonces, relation, six masks, and the 3,168-byte selected
commitment region remain unchanged. A future implementation would need width-aware
48- or 64-byte root/tree/frontier/stream-seed handling in BAVC generation, opening,
verification, and row conversion while retaining 256-bit `sd` and 96-byte leaf
commitments. It would also need new version/profile/source/wire fingerprints,
domain identifiers, independent-verifier fixtures, and cross-version rejection.
A new proof correspondence must cover the H domains, seed partition, public
predicate, opening gate, retry/abort fallback, frontier reconstruction, leaf and
stream distributions, filtered soundness, same-commitment stream binding, the
six-mask privacy endpoint, and the retained G0/G1 source hybrids. No native
benchmark or execution was performed; the proposal remains unselected and no
width is recommended.

## v3 fixed-table binding design (unselected, soundness-only candidate)

The driver authorized a separate design investigation after the v2 single-answer
proposal's hidden-selected-LEAF witness premise was rejected. The authoritative
identity is `DMV-RO-WIDE-SEED-v3`; the implemented DMV2 protocol and the v2
single-answer proposal remain separate evidence. This section does not change the
wire, authorize native work, or assign security credit. The machine record is
`bounded_generator_feasibility_proposal_v3` in `manifest_v2.json`.

For each `w` in `{384,512}`, set

```text
r = 2*w + 288
nu_bits = r + w - 1 = 3*w + 287
```

One typed `G` answer is always the full 2,112 bits (264 bytes). All bit strings use
little-endian bit numbering within bytes: bit `i` is bit `i mod 8` of byte
`floor(i/8)`. `LP(b)` is `uint32_le(len(b)) || b`; all integer fields are little
endian and all seeds/IVs are fixed width. The version is the exact 19-byte ASCII
string `DMV-RO-WIDE-SEED-v3`. The four candidate domains are disjoint through
the `0xd7 || LP(version) || uint16_le(w) || domain` prefix:

```text
H0 = 0xd7 || LP(version) || uint16_le(w) || 00 || LP(IV[16]) || uint32_le(0)
     exactly 51 input bytes

TREE_CHILD = ... || 01 || LP(IV[16]) || LP(parent_seed[w/8])
              || uint32_le(node_index) || uint8_le(child_role) || uint32_le(0)

LEAF_OUTPUT = ... || 02 || LP(IV[16]) || LP(leaf_seed[w/8])
              || uint32_le(leaf_index) || uint8_le(0x10) || uint32_le(0)

ROW_STREAM = ... || 03 || LP(IV[16]) || LP(stream_seed[w/8])
             || uint32_le(leaf_index) || uint32_le(row_index)
             || uint8_le(0x20) || uint32_le(counter)
```

`LEAF_OUTPUT` counter zero retains bits `[0,w)` as `stream_seed` and bits
`[w,w+r)` as `tail`; the remaining full-answer suffix is discarded. The public
commitment is the `r`-bit value

```text
com = T_nu(stream_seed) XOR tail,
T_nu[i,j] = nu[i-j+w-1], 0 <= i < r, 0 <= j < w.
```

`ROW_STREAM` is keyed by `stream_seed`, not by an independent 256-bit `sd`. It
takes the first `w` bits of each counter answer, concatenates counter order, and
truncates to 15,823 bytes. Equal stream seeds therefore induce identical row
streams at a fixed public context and are not a uniqueness failure. The existing
GF(2^256) relation, ordinary rows, six masks, source `G0/G1`, and `alpha8`/`alpha50`
terms remain unchanged.

The H0 answer supplies the first `nu_bits` as `nu` and the following independent
10 filter bits. The filter accepts exactly when
`bits[nu_bits,nu_bits+10) == 0`. The unused high bits of the serialized final
`nu` byte are set to zero; unused H0 squeeze bits are discarded, not required to
be zero. The exact widths are:

| `w` | `r` | `nu_bits` | active H0 bits | H0 squeeze | serialized `nu` | commitment | `m4` | frame incl. 40-byte header |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 384 | 1,056 | 1,439 | 1,449 | 182 B | 180 B | 132 B | 15,348 B | 539,306 B |
| 512 | 1,312 | 1,823 | 1,833 | 230 B | 228 B | 164 B | 20,068 B | 544,074 B |

The frame calculation is `534370 - 96 - 10496 + serialized_nu + m4`: the
statement (1,147 B), `m1` (506,416 B), `m2` (15,887 B), `m3` (96 B), three
64-byte nonces, and the 40-byte header remain unchanged. `m4` is
`33*(r/8) + 229*(w/8)`. The width-bound H1 vector inputs are
`28+128*(r/8)` and `28+256*(r/8)` bytes, namely 16,924/33,820 B at 384 bits and
21,020/42,012 B at 512 bits. H1's outer input is 2,140 B. FS uses the exact
length-prefixed domains below; `LP(b)` is `uint32_le(len(b)) || b`, including
the final part length word, and the literal ASCII tags have no NUL terminator:

```text
FS1 = ASCII("BL/DMV/FAEST-256F/v3") || ASCII("FS1")
      || LP(statement) || LP(uhash) || LP(m1) || LP(sigma1)
FS2 = ASCII("BL/DMV/FAEST-256F/v3") || ASCII("FS2")
      || LP(statement) || LP(uhash) || LP(m1) || LP(sigma1)
      || LP(gamma1) || LP(m2) || LP(sigma2)
FS3 = ASCII("BL/DMV/FAEST-256F/v3") || ASCII("FS3")
      || LP(statement) || LP(uhash) || LP(m1) || LP(sigma1)
      || LP(gamma1) || LP(m2) || LP(sigma2)
      || LP(gamma2) || LP(m3) || LP(sigma3)
```

`uhash` has length 180/228 B respectively; FS2 and FS3 retain their 6- and
7-bit filters.

The Toeplitz rank argument is exact. For nonzero `d`, let
`j0=min{j:d_j=1}` and, for each output row `i`, select the `nu` coordinate
`k_i=i-j0+w-1`. The coefficient of `nu[k_i]` is one, while every other nonzero
coordinate of `d` contributes only a lower-index coordinate. The selected `r` by
`r` submatrix is triangular with diagonal one. Thus the map
`nu -> T_nu*d` has rank `r`, and every fixed nonzero difference has collision
probability exactly `2^-r` for a fixed target.

The stronger soundness game fixes the complete finite table of full 2,112-bit
answers on every legal `TREE_CHILD`, `LEAF_OUTPUT`, and `ROW_STREAM` input,
independently of H0/H1/FS, and gives that table only to the soundness adversary.
The exact domains make the restrictions independent. For each fixed table the
query-only adversary is more informed than the actual adversary, so averaging the
fixed-table bound dominates the actual game. The table is unchanged under any
H0/H1/FS replacement. Exhaustive opening enumeration is permitted only as a
finite membership selector in this stronger game: it does not search an
unqueried generator row, make actual oracle evaluations free, or reduce the
actual generator/verifier query ledger. The table is explicitly unavailable in
the privacy experiment.

There are exactly 6,400 leaf-index contexts, not the old 33 tweak factor. For a
fixed H0 row, the distinct-stream equal-commitment union is at most

```text
6400 * binom(2^w, 2) / 2^r,
```

and the independent H0 filter gives

```text
e_leaf_v3 = 6400 * binom(2^w, 2) / 2^(r+10).
```

The fixed-table witness has one variable H0 row for this event. The table removes
hidden-LEAF extraction, but an inserted H0 row can still match one of `j` stored
FS/uhash targets, so its conservative row bound is
`e_leaf_v3 + j/2^nu_bits`; the target term receives no ten-bit filter gain. The
retained local chain has
witness sizes 1 (H0), 2 (typed collision), 36 (H1 chain), 37 (FS1 chain), and
38 (FS2/FS3 chain), so the derived completion charge is `qP=38`, not 41.
The one-insertion entries are

```text
H0           e_leaf_v3 + j/2^nu_bits
H1 vector    34*j/2^512
H1 outer     2*j/2^512
FS1          2*j/2^2112 + eKOS
FS2          2*j/2^832 + (1+172231^2/2^64)/2^262
FS3          3/2^263
other        0
```

The FS2 and FS3 terms retain their established joint-filter gains; the prior
loose `3/2^256` direct terms are not reused. A single insertion takes the maximum
over typed roles, not an independent union sum. With

```text
q_alg_v3 = Q + 35*A + 38*V + R0 + R2 + R3 + G_M(w) + G_V(w)
q_eff_v3 = q_alg_v3 + 38
```

the conditional stronger-game bound is

```text
delta_v3(k) = max(e_leaf_v3 + k/2^nu_bits,
                  34*k/2^512,
                  2*k/2^512,
                  2*k/2^2112 + eKOS,
                  2*k/2^832 + e2,
                  e3)
p_false_v3 <= min(1, (sum_{k=1..q_eff_v3} sqrt(10*delta_v3(k)))^2).
```

The direct constants are not union-summed. The calculator compares the exact
fractions `e_leaf_v3`, `eKOS`, `e2`, and `e3` at both widths and then compares
the complete monotone row envelope at `k=q_eff_v3`. In both widths `FS3=e3`
is the exact row maximum; every other row is monotone in `k`, so this proves
`delta_v3(k)=e3` for every `1<=k<=q_eff_v3` and simplifies the cap result to

```text
p_false_v3 <= 30*q_eff_v3^2/2^263.
```

The actual generator query ledger remains charged. Per fresh commitment it is
`2*6399 + 6400*(1+ceil(15823/(w/8)))`, giving 2,131,198 calls at 384 bits and
1,606,398 at 512 bits. Per verification it is 2,120,275 and 1,598,181 calls.
Oracle uncomputation, parsing, comparisons, and memory remain separate work
costs. At the declared caps, the calculator emits the exact integer ledger and
fractional soundness result; it does not convert either into a 2^-128 false-
acceptance claim.

Privacy has a conditional one-hop construction for the same v3 design, pending
independent review of the opaque-key coupling. The corrected Saito--Xagawa--
Yamakawa Lemma 2.2 ([author revision](https://eprint.iacr.org/2017/1005.pdf),
2021-08-25, PDF page 6; proof Appendix C.1 page 26) gives
`2*q_H*2^(-w/2)` for the pair

```text
H:{0,1}^w x X -> {0,1}^2112,
F:X -> {0,1}^2112,
```

where the challenger samples one hidden uniform `s` and supplies either
`F(x)=H(s,x)` or an independent random `F`. The reduction never receives or
chooses `s`. The reduction is online; it samples only independent honest
randomness inside the currently admitted request and never freezes future
adversary requests or future transcript values:

The reversible target parser factors each exact generator input as
`Encode_w(k,x)`, with the one seed field `k` removed from `x`:

```text
x_TREE = 0xd7 || LP(version) || uint16_le(w) || 01 || LP(IV[16])
         || uint32_le(node_index) || uint8_le(child_role) || uint32_le(0)
x_LEAF = 0xd7 || LP(version) || uint16_le(w) || 02 || LP(IV[16])
         || uint32_le(leaf_index) || uint8_le(0x10) || uint32_le(0)
x_ROW  = 0xd7 || LP(version) || uint16_le(w) || 03 || LP(IV[16])
         || uint32_le(leaf_index) || uint32_le(row_index)
         || uint8_le(0x20) || uint32_le(counter)
```

The factored `k` is respectively `LP(parent_seed)`, `LP(leaf_seed)`, or
`LP(stream_seed)` in the original literal input. The target is selected by a
deterministic admitted-request/provenance ordinal. Within the current request,
an independent challenge tape fixes candidate path indices before generator
calls; selection never inspects `s` or `K_s` bytes or future adversary requests.

1. At admission of the current honest request, sample only its independent
   nonce/challenge tape, including a bounded lazy sequence of potential FS
   answers. When an FS event is actually reached, construct its concrete typed
   input, install that point and answer chronologically, and apply repeated-input
   overwrite semantics. Unused future tape entries are not revealed. The first
   deterministic passing `gamma3` index vector is selected from the current
   request's independent tape; this gate depends on indices, not a seed or
   witness. H0 stays real, retries reuse `m2`/`m3` as specified, and only the
   final proof or a prescribed abort is returned.
2. The telescoping schedule identifies one target provenance slot at a time:
   397 marked TREE_CHILD parent-key slots in ancestor order, then 33
   LEAF_OUTPUT slots, then 33 ROW_STREAM stream-key slots. Each adjacent-world
   reduction uses one SXY pair `(H,F)` for exactly one target ordinal; it does
   not pass a private seed to the challenger or instantiate simultaneous
   challenges. If the target ordinal is never reached, no `F` call occurs and
   the adjacent executions are identical for that run.
3. In a TREE_CHILD hop, the target parent seed is the opaque handle `K_s`.
   The reduction calls `F(x)` for every target child-role/context. `F` returns
   concrete full 2,112-bit bytes; projected child seeds and any disclosed
   sibling/frontier projections are concrete. The handle has no consumer other
   than the target keyed restriction: it is not serialized, hashed, inserted in
   H1/FS/message/verifier bytes, or used by an unmarked call.
4. In a LEAF_OUTPUT hop, the target leaf seed is `K_s` and the reduction calls
   `F(x)` at the exact counter-zero leaf context. The returned concrete bytes
   supply `stream_seed` and `tail`, so the reduction computes and publishes
   `com=T_nu(stream_seed) XOR tail`; unused answer suffix bits have no honest
   consumer and the hidden leaf key is not serialized.
5. In a ROW_STREAM hop, the prior random-leaf endpoint uses the exact bijection
   `(stream_seed,tail) -> (stream_seed,T_nu(stream_seed) XOR tail)` and samples
   `(stream_seed,com)` directly. The stream seed is represented by `K_s`; the
   reduction calls `F(x)` for every exact row counter context and projects the
   first `w` bits into the existing message and six-mask computation. It never
   computes `T_nu(K_s)` or retains a tail.

The one-hop dataflow is:

```text
for adjacent worlds W_(t-1), W_t and one target ordinal t:
    run the adversary and current honest request online
    sample only the current request's independent challenge tape
    install each FS point after its actual concrete input is known
    expose public H to every adversary superposition and non-target global query
    call F_t(x) only for reached target honest classical contexts
    use concrete F_t projections for every later disclosed or protocol-consumed byte
    route every overlay hit/miss through the two-query H circuit and clear all work
    compare W_(t-1): F_t=H(s,.) with W_t: F_t=independent random F
after the 463*M adjacent hops, apply the exact six-mask map, then source G0/G1
alpha8/alpha50 hybrids once in their recorded order
```

The SXY pair is a reduction interface, not a second public oracle. The
challenger samples `s`; the reduction stores only `K_s` and calls `F_t(x)` at
target honest contexts. It never computes `H(s,x)` by constructing `s`, never
passes a chosen key to SXY, and never exposes `F_t` to the adversary. For every
simulated global query with input `x` and caller output register `y`, the clean
reversible circuit is:

```text
a <- 0; match/value/route ancillas <- 0
a <- a XOR H(x)                                      # first H query, all branches
compute legal-domain and exact programmed-table match/value reversibly
y <- y XOR a                                          # controlled on a miss
y <- y XOR programmed_value                           # controlled on a hit
a <- a XOR H(x)                                      # second H query, all branches
uncompute match/value/route ancillas
```

There is no materialized `z` register: the reversible miss/hit route controls
the caller-register XOR directly. The miss path XORs the computed base answer,
and the hit path XORs the programmed value; both retain `a` until the
unconditional second query clears it. Legal generator inputs,
H0/H1/FS inputs, invalid/framing inputs, and all complement routes use the same
public `H`; only the private target honest classical call uses `F_t`. Thus public
superposition guesses see original `H` plus the online FS overlay. Repeated
target contexts use the same `F_t` function and answer. Exact duplicate slots
are de-duplicated by provenance/context identity, while every H/F forward and
uncomputation call remains charged.

Aborted attempts are included rather than discarded. If an abort reaches a real
`gamma3` reservation, use its first current-request tape index vector; if it has
no such reservation, sample a virtual vector locally. The virtual path is not
returned, not serialized, not used in a returned computation, and does not
increment `A`, `V`, `Q`, `R`, or `P`. Since the programmed gate and retry/abort
outcome depend only on the current request's independent tape, the reduction
does not precommit future adversary requests or future FS entries.
Exact source retransmission creates no new generator commitment or seed slots;
a fresh proof invocation has fresh coins, while verifier calls add public-base
queries but no seed slots. Frontier and other later disclosures are generated
from concrete `F_t` or `H` answer projections before serialization, so no
opaque parent, selected stream seed, leaf tail, or other seed-dependent private
coordinate is silently exposed.

The finite privacy ledger charges one complete history per hybrid, not a history
multiplied into the query bound. With

```text
q_hist_v3 = Q + 39*A + 41*V + R0 + R2 + R3 + G_M(w) + G_V(w)
P <= A + R2 + R3
q_H_v3 <= 2*q_hist_v3 + P
N_hybrid = (397 + 33 + 33)*M = 463*M
N_seed = 19199*M
```

At the declared caps, the corrected public-base history ledger is

```text
q_H_v3(384) = 680564733841876926926840394352055812096
q_H_v3(512) = 680564733841876926926831401601071054848
```

These are one complete history's forward/uncomputation overlay budgets. The
`463*M` factor is the separate telescoping loss; it is not applied again to
`q_H_v3`.

the two public-base calls per simulated query include the forward evaluation and
the hit uncomputation. The keyed generator part of the conditional reduction is

```text
epsilon_generator_v3(w) <= min(1,
    2*N_hybrid*q_H_v3/2^(w/2)).
```

No separate seed-collision term is required for this one-hop privacy expression.
Each target handle is uniform and independent of public `H` because it is an
initial private coin or a projection of an earlier private random-function
answer. Equality of concrete bytes with another provenance slot is not inspected
or conditioned on: non-target real routes continue through `H`, while
provenance-private replacement functions remain distinct. The unconditional SXY
pair therefore covers equal-byte cases directly. Repeated contexts under one
provenance slot are not new slots, and `N_seed` remains an endpoint audit count,
not a birthday term. The fixed generator table is not used in this privacy
experiment.

After the generator endpoint, the six-mask change of variables is the exact
existing one: sample `d_w`, `a1`, `a2`, and `tilde_u[4]` uniformly, reconstruct
`q,D,q',B,m2,m3,m4`, and rebuild the FS inputs/nonces. The conditional privacy
composition is therefore

```text
epsilon_priv_v3 <= epsilon_coins + epsilon_AR + epsilon_generator_v3
                  + epsilon_source + Adv_SHAKE_priv
                  + epsilon_operational.
```

The source-U binding event is not an additive source-hiding loss when the
source-hiding reduction does not condition on it.  Keep its integrity and
applicability statement separately, under the source-U theorem, custody and
independence, and global operation-reference premises:

```text
Pr[Bad_U union Bad_ref]
  <= E_U*2^-257 + binom(N_ref,2)/2^256.
```

This separation does not drop the source-U premise.  It prevents an integrity
event from being silently counted as privacy loss (or silently omitted from the
applicability boundary).

The predecessor `epsilon_bitMH` expression is not a distinct v3 transition:
its 397/33/33 block replacements are exactly the TREE_CHILD/LEAF_OUTPUT/
ROW_STREAM one-hop schedule already charged by `epsilon_generator_v3`. Adding
it again would double-charge the same output-hiding changes. A concrete
SHAKE/G realization remains a separate `Adv_SHAKE_priv` term.

The generator term is emitted for both 384- and 512-bit ledgers as a provisional
conditional diagnostic pending review of the one-hop opaque-handle construction;
the full privacy claim remains stopped at the concrete SHAKE/operational/
independent-verifier terms, while source-U custody/independence remains a
separate applicability and integrity premise.

The accepted scoped event allocation for this conditional v3 record is:

```text
Bad_FA := a false statement accepted in the one global fixed-table/QRO verifier history.
```

`Bad_FA` is the existing complete query event and is charged once. There is no
second `epsilon_soundness_stat`, `epsilon_aggregation_stat`, or
`epsilon_transcript_stat` row, and no additional multiplier on `q_H_v3` or
`463*M`. A failure of global nonrefundable `N_opp`/`operation_ref` authority is
an applicability failure, not a fabricated statistical epsilon. Honest aborts
and repeated canonical H0 inputs are availability outcomes unless a separate
security predicate is actually shown; a repeated canonical H0 input is the same
QRO row. The current 100-value relation/batch is not an enabled cryptographic
aggregation theorem, so this candidate has no separate aggregate event.

The distinct external statistical allocation remains conditional on its source
and control premises:

```text
Pr[Bad_U union Bad_ref]
  <= E_U*2^-257 + binom(N_ref,2)/2^256.
```

The established nonzero-`U` source-pair scope is the v1 fraction recorded at
`CONTRACT.md:111-115`, `binom(2^256,2)/(2^768-1)<2^-257`. This does not qualify
source custody/global issuance or global operation-reference authority, and it
is not a complete product qualification.

Under the accepted unconditional one-hop coupling, no additional `Bad_seed`
term is present: incidental equal concrete seed values are not inspected or
conditioned on. This is not a claim that seed collisions are impossible. If a
different proof conditions on no equal seed slots, that collision exception is a
distinct statistical coupling event and must be named and charged once rather
than relabeled or silently dropped.

This computational expression does not discharge the product's lifetime
statistical ledger. The authority boundary is one global, nonrefundable
`N_opp<=2^32` opportunity budget, with a separately false-able aggregate counted
alongside its member opportunities only when a selected theorem actually has
such an aggregate; this v3 candidate has no aggregate theorem. It is not a
`q_H` multiplier and does not create fresh budgets per key epoch, host,
tenant, session, retry, abort, or crash. A separate `<=2^-128` statistical
soundness/knowledge and binding composition is not established here. Global
`operation_ref` coordination, abort/retry/reset mapping, source-U
custody/independence, and the H0 duplicate-IV premise (if a trial-independence
theorem requires it) remain explicit open rows. Conditional quantities such as
`E_U*2^-257+other_stat`, `binom(2^32,2)/2^256`, and
`binom(2^48,2)/2^128` are not silently promoted to proved ledger terms.

Accordingly v3 remains unselected, inactive, `production_usable=false`, and
`proofSuiteId=null`. Its minimum sufficient width is
`UNKNOWN_PRIVACY_AND_CONCRETE_PRIMITIVE_SECURITY`; 384 and 512 are evaluated
widths, not recommendations. Concrete SHAKE/G security, source-alpha, source-U,
operational, native, and independent-verifier gates remain separate and open.

### Source-view collision correction and endpoint normalization

The admissible source-view game uses the native relation exactly.  Each of the
100 source words is an inclusive 64-bit value in

```text
I = [0x1122334455667788, 0xddeeff0011223344]
m = |I| = 14757394086155238333 >= 3*2^64/4.
```

The first world is the legal constant vector `V0=(a,...,a)` with
`a=0x1122334455667788`.  The second world is not the inadmissible all-zero
vector.  It samples each word with at most 128 independent 64-bit candidates,
keeps the first candidate in `I`, and, if any word exhausts its candidates,
uses `V0` for the complete vector.  Thus there are at most 12,800 candidate
draws.  Each word is uniform on `I` conditional on no fallback, the accepted
words are independent under that conditioning, and the fallback probability is
bounded by `100*4^-128`; the fallback contributes zero to the collision event.

The public source view has 50 128-bit blocks
`C_j = G1_j XOR V_j`, with the 50 distinct AES pad inputs
`LE128(2^127+j)`, `j=0..49`.  The distinguisher performs all
`binom(50,2)=1225` 128-bit comparisons and returns one when a collision occurs
in the 25 disjoint block pairs.  Under a fixed AES permutation, `V0` has no
collision because distinct pad outputs remain distinct after XOR with the same
128-bit value.  For any 64-bit difference `d`,

```text
|I intersect (I XOR d)| >= 2*m - 2^64,
Pr[x XOR y = d] >= 2^-65,
Pr[one 128-bit block-pair collision] >= 2^-130.
```

The 25 disjoint events are independent for the conditional interval world, so

```text
p_uniform >= 1-(1-2^-130)^25 > 2^-127,
p_bounded >= (1-100*4^-128)*(1-(1-2^-130)^25) > 2^-128.
```

The last strict inequality is retained: `100*4^-128 < 1/2`, so multiplying
the strict `p_uniform > 2^-127` lower bound by the positive factor greater than
`1/2` gives a value strictly greater than `2^-128`.  Since the `V0` event has
probability zero, this is a lower bound on the normalized source-game
distinguishing distance for this diagnostic.  It is a mathematical lower bound
for the admissible source-view experiment, not a measured leak or a
constant-advantage computational break.  It is not added as another switching
or privacy residual: the existing source-hiding term remains
`S*(alpha8+alpha50+1253/2^128)`.

The endpoint convention is explicit.  Define

```text
Delta_LR = abs(Pr[D(View0)=1] - Pr[D(View1)=1]),
E0 = distance(View0, CommonIdeal),
E1 = distance(View1, CommonIdeal).
```

When the same common ideal and full-history postprocessing premises justify the
two one-sided bounds, `E_one_sided` bounds both sides and

```text
Delta_LR <= min(1,E0+E1) <= min(1,2*E_one_sided),
Pguess = (1+Delta_LR)/2.
```

Therefore the strict half-success diagnostic requires
`E_one_sided < 1/4`, not merely `E_one_sided < 1/2`.  A one-sided endpoint
bound and normalized left/right distance are not interchangeable.  At the
declared `M=S=2^32` caps, with

```text
u = epsilon_coins + Adv_SHAKE_priv + epsilon_operational,
```

the source-alpha condition sufficient for that strict diagnostic is

```text
alpha8 + alpha50
  < (1/4 - u - 2^-137 - epsilon_generator_v3(w))/2^32 - 1253/2^128.
```

The inequality is strict and retains the unallocated nonnegative losses.  With
`u=0` only as a diagnostic, the right-hand ceiling is approximately
`5.8207560516346235e-11` at `w=384` and
`5.8207660913467407e-11` at `w=512`.  These residual calculations do not
establish either source alpha term, concrete SHAKE security, or a complete
privacy qualification.

### Ideal-QROM applicability and conditional overlay resources

The v3 `q_H_v3`, fixed-table soundness, and
`epsilon_generator_v3(w)` values are conditional ideal-QROM values.  They use
independent random-function answers on the typed v3 domains.  The concrete
SHAKE instantiation remains `Adv_SHAKE_priv=UNKNOWN`; no generic
SHAKE-to-random-oracle numerical bridge or renaming is assumed, and the ideal
QROM values do not close the concrete privacy gate.

The proof's `O(P*L_FS)` lookup term can be expanded only as a conditional
implementation envelope.  For a flat table that linearly compares every input
against every programmed point, the versioned v3 FS3 input lengths are:

| width | FS1 bytes | FS2 bytes | FS3 bytes | FS3 bits |
| ---: | ---: | ---: | ---: | ---: |
| 384 | 507846 | 524073 | 524349 | 4194792 |
| 512 | 507894 | 524121 | 524397 | 4195176 |

These lengths include the 20-byte `BL/DMV/FAEST-256F/v3` prefix, the three-byte
`FS1`/`FS2`/`FS3` tag, and every `uint32_le` length word.  At the declared
`P=4198401*2^32=18031994990493696` program-point cap, the calculator reports
the exact flat-table memory and comparison envelopes below.  `q_hist_v3` is
the forward complete-history call count; `q_H_v3` is the corresponding
forward/uncomputation public-QRO ledger.

| width | flat table memory (bits) | forward history comparisons | forward+reverse comparisons |
| ---: | ---: | ---: | ---: |
| 384 | 75678551903582954717184 | 25739117598396162384954568886952808626667439683062626412134400 | 51478235196792324769910501722451625350191002479241042195382272 |
| 512 | 75685476189659304296448 | 25741473810851460317809021680262130681366234657737442586525696 | 51482947621702920635619407433928961301069455544396043788484608 |

The table entry is `L_FS_bits+2112` bits, and the comparison unit is one
input-bit comparison.  These figures are not measured runtime, not a lower
bound for every simulator, and not a claim that a dictionary, structured
lookup, QRAM, or another access model is available.  Exact gate, memory,
access, and depth qualification remains open.

## Availability and limits

Let `g` be the exact number of 248-bit decoded payloads whose selected paths pass the
original BAVC opening gate; the old 8 grinding bits are a separate filter. The filtered
candidate probability is `g/2^263`, and exact `g` remains `UNKNOWN`.

The calculator now derives exact grouped first- and second-moment quantities from the
pinned source mapping. The decoder has 33 independent uniform groups: 17 width-8 and 16
width-7. The decoded-choice denominator is exactly
`2^(17*8+16*7) = 2^248`; the separate 8 grinding bits give the intermediate factor
`g/2^256` before the FS3 filter and do not enter the decoded-choice denominator. For each heap node `v`, it
counts the selectable leaves `c[i,v]` below `v` using the source `pos_in_tree` formula
and the source heap parent rule. Therefore:

```text
Pr[v is unmarked] = product_i(1-c[i,v]/2^width_i)
E[n_h] = sum_v (1-product_i(1-c[i,v]/2^width_i))
Pr[n_h >= 295] <= min(1,(E[n_h]-33)/(295-33))
```

The exact computation evaluates 12,799 heap nodes and 33 group count vectors, with 6,400
injectively mapped selectable leaves. Its result is `E[n_h]` approximately `286.95746842306727`
and the exact Markov tail is approximately `0.9693033145918598`, yielding a nonvacuous
first-moment lower bound
`g >= 13884505219020294333661197535521673725749848932958108781260395804633668208`.
The report preserves the exact fractions:

```text
E[n_h] = 4056079686396258357959731046931203993723285108487866225520421144400144512907
         / 14134776518227074636666380005943348126619871175004951664972849610340958208
Pr[n_h >= 295] <= 27401771460265380877478935165916591645380376791700021531116924482892312153
                 / 28269553036454149273332760011886696253239742350009903329945699220681916416
```
This does not evaluate `g`; it is a lower bound under the source-derived uniform/independent
decoder-group assumptions. The lower bound uses 33 as a proven deterministic minimum because
the pinned leaf map is injective across groups.

The calculator then groups identical 33-component count vectors. For a signature `c`, let
`Z(c)=product_i(d_i-c_i)` with `d_i` equal to the group choice count, and let `D=2^248`.
For disjoint node paths the joint unmarked numerator is `Z(c_v+c_w)`; for a nested pair it
is `Z(c_ancestor)`; and for a self pair it is `Z(c_v)`. The grouped baseline over ordered
signature pairs is `B=sum n_c*n_d*Z(c+d)` (evaluated by symmetry over unordered signature
pairs). The exact self and proper-ancestor corrections are:

```text
J = B + sum_v[Z(c_v)-Z(2*c_v)]
      + 2*sum_(a proper ancestor of b)[Z(c_a)-Z(c_a+c_b)]
Var[n_h] = J/D - (S/D)^2,  S=sum_v Z(c_v)
```

Here `Z(c+d)` for a nested virtual pair can be signed and is only a baseline term, not a
probability. The calculator finds 390 distinct signatures, 76,245 unordered signature
pairs, 150,018 one-orientation ancestor pairs, and 163,501,566 disjoint ordered pairs.
The exact grouped certificate is:

```text
S = 5659357599052546237335464532772406677724302273932816324302946592587320946921120
B = 70809329022621126312654488267015680139361614768222667425222972991402743186647023776
self correction = 101118433472237148122782004415351158504788008179058446659583726311743426203296
ancestor correction = 715355992110525482649420903912955836336654366068198457131913015975259146225076
J = 70810145497046709075285260469924008446356456210596914682126764488145030189219452148
```

With `t=295-E[n_h]`, Cantelli gives
`Pr[n_h >= 295] <= Var[n_h]/(Var[n_h]+t^2)`. The selected tail is the minimum of this
bound and the first-moment bound. The exact variance and selected Cantelli tail are
preserved in the machine report; numerically they are approximately `49.78036376169439`
and `0.4349047625214373`, respectively. This yields the stronger conditional lower bound
`g >= 255599836584766103482634859835523518456497083189896055288886800712843385174`.
The exact value of `g` remains `UNKNOWN`.

Before the grouped pair phase, the calculator reports 390 signatures, a deterministic upper
bound of 13,262,007 group-factor multiplications, an 8,651,416-byte working-array bound,
and intended runtime `O(N*K + K*(K+1)/2*K + N*log2(N)*K)`. One 60-second deadline starts
before path-vector work and is checked periodically during vector construction, moment
precomputation, resource preflight, grouped baseline, self correction, and ancestor
correction, including an explicit check immediately before the pair phase. It stops if the
fixed limits `2^25` multiplications, 128 MiB, or 60 seconds are exceeded; no limit is widened. A direct
pair summation over a small actual-node subset, including self, nested, and disjoint pairs,
is checked against the grouped identity.

The earlier observed `1.552630` seconds and `1.846347` seconds are separate wall-clock
measurements of separate commands/runs, not one exact runtime measurement or a theorem
bound. A later run is reported separately.

For the existing fixed-prefix/fresh-uniform-RO collision split, the exact unknown-`g`
expression is retained. When only the lower bound is available, the calculator uses the
rational inequality `(1-p_good_lower)^R <= 1/sum_{k=0..min(16,R)} binom(R,k)*p_good_lower^k`,
which is stronger than the retained reciprocal inequality, and adds the exact
`binom(R,2)/2^512` collision term. For `R=2^22`, the partial sum has 17 terms. The
`p_good_lower=0,R=0` endpoint returns one exactly. The calculator never constructs a power
with a huge retry exponent.
Adaptive trials are not assumed geometric, and this is not a product-qualified availability
claim. No BDD/SAT, exhaustive `2^248` enumeration, large solver, or Monte Carlo substitute
was run.

## v1 source correspondence

The correspondence record is also machine-readable under `source_correspondence` in
[`manifest_v2.json`](manifest_v2.json). It is anchored to the read-only source commits
`392e53e2b3d5936cb9cb2681b9e2d803143b1e17` (VOLE) and
`530e880ef6cbd5fa4e023f42d3aa66a0d213d9e2` (pipeline):

- `direct_mask_vole.h:15-40` contains the v1 geometry, nonce sizes, and `DMV1` version.
- `direct_mask_vole.c:270-334` contains v1 commitment generation; `:504-590` contains the v1 H0/FS transcript helpers; `:941-1120` contains the v1 prover order, one FS2 draw at `:1071-1074`, and the FS3 retry loop at `:1107-1120`.
- `vendor/faest-ref/utils.c:39-61` contains the pinned 17 width-8/16 width-7 decoder groups; `vendor/faest-ref/bavc.c:103-114` contains `pos_in_tree`; and `vendor/faest-ref/bavc.c:338-360` contains the path-union/opening check.
- `direct_mask_wire.c:160-170,424-434` validates challenge mode `1` and `DMV1`; `direct_mask_source_proof.c:354-413` validates the v1 retry cap and calls `dm_wire_prove_kernel_os`.
- `direct_mask_pipeline_source.c:54-104` validates overlap/capacity and input parsing before source-proof work; `direct_mask_pipeline_codec.c:78-126` contains the fixed-size/magic/epoch/retry/nonzero-`U` source-input parser. There is no monolithic `direct_mask_pipeline.c` in this checkout.

These are source facts and proposed call-site obligations, not evidence that v2 is
implemented. No native source, product state, or v1 contract file is changed here.

The current v1 source still samples commitment material before its unconstrained
transcript searches, accepts `DMV1`/challenge mode `1`, and does not enforce the v2
filters or counter identities. Product state does not select v2. Therefore this artifact
does not claim native implementation correspondence, source truth, statistical or
computational 128-bit security, concrete quantum work, availability, production use,
deployment, or activation.

Run the static report with:

```text
python -m tools.direct_mask_contract.calculator_v2 --mode report
```

Runtime admission requires a separate JSON object containing every counter and
precondition flag named by `manifest_v2.json`:

```text
python -m tools.direct_mask_contract.calculator_v2 --mode admit --counters <counters.json>
```
