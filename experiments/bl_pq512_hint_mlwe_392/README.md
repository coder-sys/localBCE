# Retired Hint-MLWE 392-bit feasibility reference

This isolated experiment records the former 392-bit acceptance profile. It is retained for
historical and research reference only; it is not an active Gate 2E control, release gate, proof
backend, or selected suite. The live release criterion is now a 256-bit cryptographic
security/encryption floor and a 5,000,000,000-byte peak-RAM ceiling. The directory name and
historical bounds are retained so past results and imports remain reproducible. This isolated
experiment was the first implementation step for evaluating a rejection-free Hint-MLWE
commit-and-prove redesign under the frozen BL-PQ512
requirements.

It does three deliberately narrow things:

1. audits the exact public upstream commit without modifying it;
2. rejects 128-bit parameters, sub-392-bit challenge spaces, SHAKE128
   Fiat--Shamir, and unpinned estimator evidence;
3. checks per-term and composed error bounds with exact rational arithmetic.

The primary theorem ledger currently derives:

- `epsilon <= 2^-397` for the combined published simulatability path
  (`2ε + 8ε + 2ε + 8ε = 20ε`) to retain at least 392 bits;
- each Gaussian lattice-vector dimension at least 393 for the paper's
  `2^(-dimension+1)` completeness tail bound (this is not a ring-degree
  requirement);
- four 129-bit or three 147-bit challenges as arithmetic repetition floors,
  with repetition still blocked because the paper does not supply the required
  composition theorem.

Passing the gate returns `FEASIBILITY_ONLY`. It is not a theorem proof,
parameter selection, roadmap amendment, implementation activation, or K128/K512
qualification. The paper's complete theorem and reduction ledger, a pinned and
reviewed lattice-estimator run, an authenticated interactive transcript proof,
and measured laptop resources remain mandatory.

The repetition helper reports only the arithmetic lower bound. For the
published 129-bit and 147-bit challenge spaces those bounds are four and three
independent repetitions, respectively. No repetition is accepted by the gate
without a theorem-specific derivation artifact.

Run the source audit:

```powershell
python -m experiments.bl_pq512_hint_mlwe_392.source_audit <upstream-checkout>
```

The former focused pytest gate was removed from active collection during the 2026-08-05 gate/test
cleanup because no current Wave 2 module, qualification manifest, or production boundary consumes
this path. The reference source and its rejection rationale remain available here and in
`docs/REJECTED_ARCHITECTURES.md`; removing the active test does not admit the construction.

Run the pinned full-attack baseline screen from the lattice-estimator checkout
with that checkout on `PYTHONPATH`:

```powershell
sage <path-to-this-experiment>/estimator_screen.sage published adps16_quantum
```

The screen runs the complete default LWE and SIS attack sets, separately checks
quantum exhaustive search, emits a SHA3-512 digest of its canonical inputs,
counts missing estimator results, and caps its conclusion at
`FEASIBILITY_ONLY`.

Run the Blind Ledger relation expressibility mapping:

```powershell
python -m experiments.bl_pq512_hint_mlwe_392.relation_expressibility
```

It returns a literal `YES` or `NO`, maps each sealed claim component into the
framework's linear/quadratic relation set, and separately lists protocol and
state-machine obligations that a claim relation cannot enforce by itself.

Run the direct SHA3 relation cost screen:

```powershell
python -m experiments.bl_pq512_hint_mlwe_392.relation_cost_screen
```

The direct lane is rejected if the real committed-witness rank invalidates the
parameter theorem, the current upstream dense matrix reaches the strict
former 3,000,000,000-byte resident limit, or the proof alone reaches that historical
5,000,000,000-byte scratch limit. The compact hybrid lane remains unqualified until
its exact non-SHA3 witness rank is compiled and screened; it receives no credit
from the rejected direct lane.

The compact capacity preflight is:

```powershell
python -m experiments.bl_pq512_hint_mlwe_392.compact_hybrid_capacity
```

It counts the six exact private scalar fields in the workspace's
`MasterSlotRecordV2`, excluding the fixed index and public nullifier. K512
exhausts all 3,072 coefficients at `m1=12` before hidden state or auxiliaries;
K128 has capacity headroom but is not admitted without an exact relation
manifest and semantic-equivalence proof.

The bounded `m1=13,16,24,32` option screen is:

```powershell
python -m experiments.bl_pq512_hint_mlwe_392.message_rank_options
```

Each modulus is a Sage-verified prime of the form `b^2+1`; exact geometry and
the measured ADPS16-quantum uSVP and knowledge-SIS results are frozen. These
are option screens only. Full default attacks, the BKW model gap, the exact
relation compiler, production authentication, and laptop proof measurements
remain mandatory.

The authenticated-state access lower-bound screen is:

```powershell
python -m experiments.bl_pq512_hint_mlwe_392.state_access_capacity
```

It derives 641 K128 and 2,561 K512 ordered-map operations from the governed
CBAM. Even granting the largest screened modulus a full 69 payload bits per
Hint coefficient, binding only each operation's 512-bit key and 512-bit
before/after values requires `m1>=61` for K128 and `m1>=241` for K512. The
screened `m1<=32` compact options are therefore rejected before paths, linked
leaves, ordering/range auxiliaries, claim semantics, or hiding are counted.
This does not reject every possible future Hint parameter set; it rejects the
current compact-hybrid options and prevents the six-scalar placeholder from
receiving state-transition credit.

The sealed-workload derivation is:

```powershell
python -m experiments.bl_pq512_hint_mlwe_392.hidden_state_workload_derivation
```

Replacing only replay/payment state leaves 16,830 K128 and 67,098 K512
permutations. Authenticating governed input columns directly can remove the
claim-truth hashing without delegating adjudication, but the sealed
deterministic A12 nullifier derivation must remain. Before the still-unspecified
state-commitment bridge, this gives lower bounds of 706 and 2,674
permutations. The hard-coded 782/894 pair is not an admissible derivation:
K512/894 requires removing deterministic nullifier work and therefore changing
replay identity.

The sparse persistent-memory capacity screen is:

```powershell
python -m experiments.bl_pq512_hint_mlwe_392.persistent_memory_capacity_screen
```

The primary paper's sparse protocol commits initial/final address and value
vectors of length `C` and estimates `7C+51A` verifier constraints. Four frozen
`2^24` Blind Ledger lanes give `C=2^26`: the four raw Fp16 vectors alone are
17,179,869,184 bytes. C1 is therefore rejected on the reference laptop before
its forbidden Pedersen/Groth compiler, missing native hiding, and missing
atomic composition are considered.

The remaining C2-C4 state screens are:

```powershell
python -m experiments.bl_pq512_hint_mlwe_392.irondict_capacity_screen
python -m experiments.bl_pq512_hint_mlwe_392.projection_ram_capacity_screen
python -m experiments.bl_pq512_hint_mlwe_392.two_shuffles_capacity_screen
```

C2's useful sparse update depends on a homomorphic PCS. With the active
transparent PCS, one `2^26`-cell polynomial needs 16 measured `2^22`
commitment shards. The strict resident limit permits only one 2-GiB codeword
at a time even while optimistically omitting every other allocation. Before
zerocheck, hiding, and verification, the GKR-plus-PCS floors are
350.5187922 seconds for K128 and 430.4069121 seconds for K512. The released
KZH backend is pairing/SRS based and forbidden, so C2 is rejected with the
current backend rather than credited with its 35-ms verifier headline.

C3's near-linear-size construction has `O~(k^2)` projection time. One distinct
512-bit state value per governed operation gives `k=328,192` for K128 and
`k=1,311,232` for K512: quadratic scales of 107,709,988,864 and
1,719,329,357,824. The alternative reduces projection time only by using a
superlinear whole-database encoding. Because the primary work supplies no
concrete parameters or reference implementation, C3 is not admitted and no
asymptotic expression is mislabeled as a laptop benchmark.

C4's exact tuple-value gate formula is `5T+3n`. At `n=2^26`, it requires
201,329,797 K128 or 201,339,397 K512 private input gates. Mapping those gates
onto the measured PCS needs 49 shards and, at one resident codeword at a time,
49 waves, or 935.8225016 seconds of PCS proving alone. This rejects C4 on the current laptop
path; its constant-per-access headline assumes `T` is much greater than `n`,
whereas Blind Ledger has `T/n` below `0.00004`.
