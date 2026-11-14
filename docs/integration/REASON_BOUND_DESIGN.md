# Per-payment reason bound for TOKEN/v1 — design for owner approval

Status: approved by the owner on 2026-11-14 (all defaults in section 12) and implemented in the commit that adds this file; section 13 records where the implementation differs from the text below. The owner chose "option 1" (G4_DESIGN.md:136, section 11 item 14): replace the total-count guard with a proved per-payment bound, with no wire change and no gate_verify re-pin. Under RIGHTRAIL_BASE_PLAN.md:138-145 the owner, as RightRail lead, approves every change inside `rightrail/`. Every Lean run goes through `scripts/rr_guarded_interim.ps1` and is labelled interim evidence (plan:130-137).

All paths are under `rightrail/lean/BlindLedger/Gate/` unless noted. Line numbers were checked against the worktree of `codex/rightrail-reason-bound` at 7fa9c383 (G4 committed, plus log). The rules have 31 `Reason` constructors (Rules/Spec.lean:126-148).

## 1. Summary

**Chosen design.** Classify every reason by one Boolean per snapshot source: the source's `usable` bit, which is a property of the batch's `Ctx`, not of the line. A function `may b r` says whether reason `r` can fire when the sources' bits are `b`. A soundness lemma ties `may` to `fires`, so a wrong classification that lets a firing code escape does not build. A finite check, `decide +kernel` over every bit tuple, shows at most 32 codes are allowed under any tuple. A second, tag-sensitive kernel check pins today's maximum over every tuple at 24 (section 4a). A short theorem next to `rowOf` then shows every payment row built from one batch's decisions has at most `maxReasonCodes` codes, and a one-line kernel lemma next to `reasonCode_ascending` shows every reason's code passes the decoder's `codeOk`. This takes the decision-procedure design as the base (small, about 80-100 lines, every step copied from a proof that already builds), the minimal design's stable public statements (bound stated as the literal 32 for all `Ctx`, so later rules change definitions, not statements), and the group design's no-wildcard classification and per-group view, kept as the documented fallback proof if the bit count grows past about 12. The per-group design was not taken whole: its partition and sum lemmas are the fiddliest part in core-only Lean (no Mathlib, lake-manifest.json `"packages":[]`), and today's 6 bits do not need them.

- **What is proved.** Liveness, not safety. Overflow already fails closed: the decoder caps the count at `nat 1 0 maxReasonCodes` (Spec.lean:460, cap at Spec.lean:32), reads each code with `code`, which refuses a name that fails `codeOk` (Spec.lean:119-122, 129-131), needs the list ascending (Spec.lean:472), `tokensOk` decodes every token (StateV2.lean:6763-6773), and `custodyOk` guards on it (StateV2.lean:7756). The new theorems show an honest batch never hits any of the three `reasonCodes` refusals: the count by `rowOf_reasons_le`, `decideRegT_rows_le` and the runtime corollary `custodyOk_rows_le`, `codeOk` by the new `reasonCode_codeOk`, and order by the existing `reasonCode_ascending` (StateV2.lean:6704-6705). The runtime link is `decideIdx_refines` (StateV2.lean:5130-5141), applied to the `o` that custodyOk binds at :7748, after that bind and before the `tokensOk` guard (:7756): it equates `o`'s decisions and `o.pays` with `decideRegT`'s on a true base, so `decideRegT_rows_le` bounds custodyOk's `prs` (:7751-7752). Runtime liveness therefore holds only outside that theorem's `Collision` disjunct (:5141). custody_binds (StateV2.lean:7790-7791) is not the link: its hypothesis `custodyOk … = some e` already passed the `tokensOk` guard, so using it for liveness would be circular. A row's codes are `(reasons.filter rs.contains).map reasonCode` (StateV2.lean:6760), a sublist of `reasons` mapped, so the last two apply to it by one `List.filter_sublist` step. The byte size is not proved; section 11 shows by the layout arithmetic that it cannot overflow at a cap of 32.
- **What does not change.** Gate/Spec.lean, TOKEN/v1, `maxReasonCodes`, `maxTokenBytes` (Spec.lean:35), `fires` (Rules/Spec.lean:403-437), every digest domain and format, artifacts/**. gate_verify's closure is Producer, Payer and Batch (VerifyCli.lean:1-3), so it is not re-pinned.
- **What does change.** New definitions and theorems (section 4), deletion of the `#guard` at Rules/Run.lean:58-59, and therefore Run's `source` digest (Run.lean:69-73).

## 2. What a payment is and how codes reach a token

- **One payment is one `Request`,** one (programId, paymentId). It is not a batch. `reqsOf` refuses a batch whose payment ids repeat (StateV2.lean:6481-6485). `linesOf` gives every line of a request `pay = payNat program paymentId` (StateV2.lean:6477-6478, `payNat` 6463).
- **One flow per payment** is a decoder fact: every line must carry the payment's flow, member key and payee (Spec.lean:318), and a ruled flow needs at least one line (Spec.lean:320). It is not a Rules fact.
- **Per line.** `decideLine` sets `reasons := reasons.filter (fires c seen l)` (Rules/Spec.lean:463-468). So a line's reasons are a sublist of the master list, with no duplicates (`reasons_sublist`, `reasons_nodup`, Rules/Theorems.lean:226-229).
- **One `Ctx` per batch.** `decideAll` uses one `c` for every line (Rules/Spec.lean:470-472). `decideBatchIn` calls `decideAll c …` (Rules/Spec.lean:529-530), and `decideReg` is `decideBatchIn c …` (Rules/Spec.lean:606-607). `decideRegT c` is `bumpRes c (decideReg …)` (StateV2.lean:2207), and `bumpRes` rewrites only the set dates, not the decisions (StateV2.lean:2201-2205). `ready` keeps a payment whole (Rules/Spec.lean:593-594).
- **Per payment.** `rowOf` (StateV2.lean:6751-6760):
  - unruled flow: HUMAN_REVIEW with `reasons = []` (6755-6757);
  - ruled flow: `rs := (ds.filter (·.1.pay == pay)).flatMap (·.2.2)` (6759), then `reasons := (reasons.filter rs.contains).map reasonCode` (6760).
  - So a token's codes are the union of the reasons of every line of that payment, re-filtered through `reasons`: deduplicated and in master order by construction. `reasonCode` is the UTF-8 of the name (StateV2.lean:6669-6690).
- **Into the token.** custody_binds builds rows from `decideRegT cc …` with `cc := carried bt.ctx rel unr` (StateV2.lean:7796-7799), and the custody tokens are a permutation of those rows (StateV2.lean:7801). `carried` changes only the set fields (Rules/Spec.lean:611-612), so the snapshot bits are those of `bt.ctx`. The runtime twin is `custodyOk` (StateV2.lean:7751-7752).
- **What the wire needs of the codes.** At most `maxReasonCodes` of them (Spec.lean:460), each passing `codeOk` (`[A-Z][A-Z0-9_]{0,63}`, Spec.lean:119-122, read by `code`, 129-131), strictly ascending (Spec.lean:472; `ascending`, `lexLt` Spec.lean:134-142). `reasonCode_ascending` (StateV2.lean:6704-6705) already covers every sublist of `reasons`. Nothing today proves `codeOk` of `reasonCode`; the new `reasonCode_codeOk` closes that.
- **No length theorem exists today.** `rowOf_commit` (ReadManifest.lean:293-295) covers only the commit field. `c15_peel` and custody_binds (StateV2.lean:7763-7771, 7790-7803) bind tokens to rows but bound nothing. The only link to the cap is the `#guard` at Rules/Run.lean:59, which holds only because 31 ≤ 32.

## 3. Co-occurrence and the per-payment count

The key fact: every snapshot code's certain, unverified or STALE status reads only the snapshot's `usable` bit.
- `certain` = usable and a valid date (Rules/Spec.lean:318-320).
- `unverified` = isSome, not usable, and a valid date (Rules/Spec.lean:323-325).
- Every STALE code is `!usable` or `!chained` of a Ctx field (Rules/Spec.lean:430-437).
- `MEMBER_NOT_ENROLLED` is `notEnrolled`, which is `certain …` (Rules/Spec.lean:338).
- The exception: `SHARE_OF_COST_UNMET_UNVERIFIED` also fires on a usable snapshot through `socDoubt` (Rules/Spec.lean:428-429). It is classed "may always fire".

| Group | Codes | Bit (Ctx only) | Allowed when usable | Allowed when not | Max per payment | Where |
|---|---|---|---|---|---|---|
| Line keys | ALREADY_DECIDED, CAP_MEMBER_MONTH_DUPLICATE, COLLIDES_WITH_UNRESOLVED_NEAR, DUPLICATE_OF_UNRESOLVED, FFS_DUPLICATE_LINE, FFS_DUPLICATE_UNVERIFIED, FFS_NEAR_DUPLICATE | none | all | all | 7 (6 FFS, 3 CAP_820) | Rules/Spec.lean:404, 407-414 |
| Dates | SERVICE_DATE_FUTURE, SERVICE_DATE_INVALID | none | all | all | 2 | Rules/Spec.lean:425-426 |
| Sets | STALE_RELEASED, STALE_UNRESOLVED | none | all | all | 2 | Rules/Spec.lean:435, 437 |
| DMF (R1) | MEMBER_DECEASED, _UNVERIFIED, STALE_DMF | `usable c.today 90 okDeath c.dmf` | certain | _UNVERIFIED, STALE | 2 | Rules/Spec.lean:415-416, 430 |
| Provider death (R3) | PROVIDER_DECEASED, _UNVERIFIED, STALE_PROVIDER_DEATH | `usable … 90 okDeath c.providerDeaths` | certain | _UNVERIFIED, STALE | 2 | Rules/Spec.lean:421-422, 434 |
| Exclusion (R3) | PROVIDER_EXCLUDED, _UNVERIFIED, STALE_EXCLUSION | `usable … 31 okExclusion c.exclusions` | certain | _UNVERIFIED, STALE | 2 | Rules/Spec.lean:423-424, 433 |
| Enrollment (R5) | MEMBER_NOT_ENROLLED, _UNVERIFIED, STALE_ENROLLMENT | `usable … 7 okSpan c.enrollment` | certain | _UNVERIFIED, STALE | 2 | Rules/Spec.lean:338, 417-418, 432 |
| Eligibility (G2) | PROGRAM_NOT_ELIGIBLE, BENEFIT_LEVEL_MISSING, both _UNVERIFIED, STALE_ELIGIBILITY | `usable … 7 okElig c.eligibility` | PNE, BLM | PNE_U, BLM_U, STALE | 3 | Rules/Spec.lean:405-406, 419-420, 431 |
| Share of cost (G4) | SHARE_OF_COST_UNMET, _UNMET_UNVERIFIED, STALE_SHARE_OF_COST | `usable … 7 okSoc c.shareOfCost` | UNMET, UNMET_U | UNMET_U, STALE | 2 | Rules/Spec.lean:427-429, 436 |

Notes:
- Per-line exclusions (`g2_exclusive`, `g4_exclusive`, Rules/Theorems.lean:328-330, 358-360; the key pairs at Rules/Spec.lean:409-414) do not lower the per-payment count: two lines of one payment can carry one code each. The proof uses only the per-Ctx split.
- The bit is the hypothesis that matters. Lines decided under different `Ctx` values could reach each snapshot group's full count (3, 3, 3, 3, 5, 3). Example: MEMBER_DECEASED on one line and STALE_DMF on another is impossible only because both read the same `c.dmf` and `c.today`.
- FFS_DUPLICATE_UNVERIFIED implies an unchained set (Rules/Spec.lean:293-294, 395-396). That is an implication, not an exclusion, so it does not lower the max.
- **Count per tuple.** With `may` as in section 4a, the 12 unconditioned codes always count; each snapshot group adds its "usable" column when its bit is true and its "not" column when false. The all-false tuple gives 12 + 2+2+2+2+3+1 = **24**, the maximum over all 64 tuples (every group's "not" column is at least its "usable" column). The all-true tuple gives 12 + 1+1+1+1+2+1 = **19**.

Per-payment counts:

| Case | Bound from `may` (kernel-checked max) | With the flow fact (argued, not proved) | Codes in the enum |
|---|---|---|---|
| Today | **24** | **23** FFS, **20** CAP_820 | 31 |
| After G10, lean shapes, 3-code G8 and G10 | **32** (zero headroom) | 31 | 45 |
| After G10, lean shapes, 2-code G8 and G10 | **30** | 29 | 43 |
| After G10, G2 shape for G5 and G6 | 34, fails the build | 33, fails | 47 |

Today's 23 matches G4_DESIGN.md:128. The 29 matches G4_DESIGN.md:130. The 34 matches G4_DESIGN.md:129's "about 33" plus the key code the flow fact would remove. G2-shape G5 and G6 alone, before G8 and G10, give 24 + 3 + 3 = 30 and would build. That every code a bit allows can fire together in one payment is argued from `Fact` (Rules/Theorems.lean:54-97), not proved; the theorem is an upper bound only. The proved per-payment bound is 32, the literal in the public statements (`pay_budget`, `rowOf_reasons_le`); the first column is the maximum of the `may` classification, kernel-checked by the private headroom pin (section 4a) and not itself a public per-payment theorem.

## 4. Theorem statements

### 4a. Rules/Theorems.lean, new section "Reason budget" after `reasons_nodup` (:228-229)

Theorems.lean imports only Rules.Spec (Rules/Theorems.lean:1), so it uses the literal 32. It is not in Run's hashed `source` (Run.lean:69-73).

```lean
/-- Each snapshot source's usable bit.  All lines of a batch read one `Ctx`, so these are per batch. -/
structure Bits where
  dmf : Bool
  pd : Bool
  ex : Bool
  en : Bool
  el : Bool
  soc : Bool
  deriving DecidableEq, Repr

def bitsOf (c : Ctx) : Bits :=
  ⟨usable c.today 90 okDeath c.dmf, usable c.today 90 okDeath c.providerDeaths,
   usable c.today 31 okExclusion c.exclusions, usable c.today 7 okSpan c.enrollment,
   usable c.today 7 okElig c.eligibility, usable c.today 7 okSoc c.shareOfCost⟩

/-- Whether `r` can fire under bits `b`.  No wildcard: a new reason does not compile until it is classified. -/
def may (b : Bits) : Reason → Bool
  | .ALREADY_DECIDED | .CAP_MEMBER_MONTH_DUPLICATE | .COLLIDES_WITH_UNRESOLVED_NEAR | .DUPLICATE_OF_UNRESOLVED
  | .FFS_DUPLICATE_LINE | .FFS_DUPLICATE_UNVERIFIED | .FFS_NEAR_DUPLICATE
  | .SERVICE_DATE_FUTURE | .SERVICE_DATE_INVALID | .STALE_RELEASED | .STALE_UNRESOLVED
  | .SHARE_OF_COST_UNMET_UNVERIFIED => true
  | .MEMBER_DECEASED => b.dmf
  | .MEMBER_DECEASED_UNVERIFIED | .STALE_DMF => !b.dmf
  | .PROVIDER_DECEASED => b.pd
  | .PROVIDER_DECEASED_UNVERIFIED | .STALE_PROVIDER_DEATH => !b.pd
  | .PROVIDER_EXCLUDED => b.ex
  | .PROVIDER_EXCLUDED_UNVERIFIED | .STALE_EXCLUSION => !b.ex
  | .MEMBER_NOT_ENROLLED => b.en
  | .MEMBER_NOT_ENROLLED_UNVERIFIED | .STALE_ENROLLMENT => !b.en
  | .PROGRAM_NOT_ELIGIBLE | .BENEFIT_LEVEL_MISSING => b.el
  | .PROGRAM_NOT_ELIGIBLE_UNVERIFIED | .BENEFIT_LEVEL_MISSING_UNVERIFIED | .STALE_ELIGIBILITY => !b.el
  | .SHARE_OF_COST_UNMET => b.soc
  | .STALE_SHARE_OF_COST => !b.soc

/-- The link: a reason that fires is allowed by the batch's bits. -/
theorem may_sound {c seen l} (r : Reason) (h : fires c seen l r = true) : may (bitsOf c) r = true

theorem decideAll_may (c : Ctx) :
    ∀ (seen : List Key) (ls : List Line), ∀ d ∈ decideAll c seen ls, ∀ r ∈ d.reasons, may (bitsOf c) r = true

/-- The finite check, closed by the kernel. -/
private theorem budget_bool : ∀ a b d e f g : Bool, (reasons.filter (may ⟨a, b, d, e, f, g⟩)).length ≤ 32

theorem budget (b : Bits) : (reasons.filter (may b)).length ≤ 32

/-- Per payment: reasons that all fired under one batch's bits give at most 32 distinct codes. -/
theorem pay_budget (b : Bits) (rs : List Reason) (h : ∀ r ∈ rs, may b r = true) :
    (reasons.filter rs.contains).length ≤ 32

-- Headroom pin (not a protected statement; bumped deliberately with each rule).  The maximum over
-- every tuple is 24 today, reached at the all-false tuple.  Both by `decide +kernel`.
private theorem headroom_le : ∀ a b d e f g : Bool, (reasons.filter (may ⟨a, b, d, e, f, g⟩)).length ≤ 24
private theorem headroom_eq : (reasons.filter (may ⟨false, false, false, false, false, false⟩)).length = 24
```

The headroom pin is **tag-sensitive**: it counts `may`'s classification, not the enum. `headroom_le` alone would also pass with a tighter `may`; `headroom_eq` at the all-false witness makes 24 the exact maximum, so the reviewer sees the slack to 32 (8 today) and any change to it. (An earlier draft of this design proposed a `#guard … == 24` at the all-false tuple only; it never existed in the tree and is not part of this design.)

What the pin sees and what it does not. A loose tag (a `may` arm made `true` where the right tag is narrower) is still sound: `may_sound` holds for any over-approximation, and `budget_bool` still bounds it by 32. The pin detects any loosening of a certain-code arm (`b.x` to `true`), which raises the all-false count (example: `.MEMBER_DECEASED => true` gives 25), any loosening of a share-of-cost arm, and a second loosened `!b.x` arm in the same source. It does **not** see one `!b.x` arm per source loosened to `true` for DMF, provider death, exclusion, enrollment or eligibility (for example `.STALE_DMF => true`, or `.PROGRAM_NOT_ELIGIBLE_UNVERIFIED => true`): the source's usable-side count rises only to its not-usable-side count, so no tuple exceeds 24. Several such loosenings in different sources stay invisible together. These remain sound for the reason above; they only hide slack the bound never relied on. Decision 2 lists the stricter pins that would see them.

### 4b. StateV2.lean

StateV2 sees Rules.Theorems through Rules.ShardRun → Rules.Shards → Rules.Theorems (StateV2.lean:51; Rules/ShardRun.lean:1; Rules/Shards.lean:1), and `maxReasonCodes` and `codeOk` through Producer (StateV2.lean:48).

Right after `reasonCode_ascending` (StateV2.lean:6704-6705), before `wireOf` (:6707):

```lean
/-- Every reason's code passes the decoder's `code` check (Spec.lean:119-122, 129-131), so with
    `reasonCode_ascending` and `rowOf_reasons_le` every row's `reasonCodes` field decodes. -/
theorem reasonCode_codeOk : reasons.all (codeOk ∘ reasonCode) = true := by decide +kernel
```

Right after `rowOf` (after :6760):

```lean
/-- A row built from decisions that all fired under one `Bits` carries at most `maxReasonCodes`
    codes, so its TOKEN/v1 leaf passes the decoder's count (Spec.lean:460). -/
theorem rowOf_reasons_le {rev pays ds rset x row} (b : Rules.Bits)
    (hds : ∀ y ∈ ds, ∀ r ∈ y.2.2, Rules.may b r = true)
    (h : rowOf rev pays ds rset x = some row) : row.reasons.length ≤ maxReasonCodes

/-- Every row built from one batch's decisions fits one token.  With `c := carried bt.ctx rel unr`
    this is custody_binds' `rows` (StateV2.lean:7796-7799).  For the runtime, `decideIdx_refines`
    (StateV2.lean:5130-5141) holds for the `o` bound at :7748, before the `tokensOk` guard (:7756),
    so this bounds custodyOk's `prs` (:7751-7752) outside its `Collision` disjunct; see
    `custodyOk_rows_le`.  custody_binds is not used for that: it assumes custodyOk already passed :7756. -/
theorem decideRegT_rows_le (c : Ctx) (k : Nat) (os : List Owner) (b : List Line) (rev : Nat → Nat)
    (pays : List (Nat × Outcome × Nat)) (rset : Bytes) (xs : List (Bytes × Request)) :
    ∀ row ∈ xs.filterMap (rowOf rev pays ((decideRegT c k os b).decisions.map
      fun x => (x.line, x.outcome, x.reasons)) rset), row.reasons.length ≤ maxReasonCodes
```

Right after `decideRegT_rows_le` (it needs `decideIdx_refines`, :5130-5141, which is earlier in the file):

```lean
/-- Runtime liveness of the count: the rows custodyOk builds from `decideIdx`'s output `o`
    (StateV2.lean:7748-7752) fit one token, on a true base, unless a named collision.  Its hypothesis
    is `decideIdx … = some o`, which holds before the `tokensOk` guard (:7756), so it is not circular. -/
theorem custodyOk_rows_le (hH : HashLen sha3) (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line)
    (rel unr : Snapshot Line) (hi : Inv rel unr) (h : Head) (ha : headOf sha3 rel unr = some h)
    (d : Bytes) (hd : digestV2 sha3 h = some d) (w : Witness) (o : OutV2)
    (ho : decideIdx sha3 c₀ k os b d w = some o) (rev : Nat → Nat) (rset : Bytes)
    (xs : List (Bytes × Request)) :
    (∀ row ∈ xs.filterMap (rowOf rev o.pays (o.decisions.map
      fun x => (x.line, x.outcome, x.reasons)) rset), row.reasons.length ≤ maxReasonCodes) ∨
    Collision sha3 (witnessInputs sha3 c₀ k os b w) (stateInputs sha3 rel unr)
```

- The row theorems `rowOf_reasons_le` and `decideRegT_rows_le` are stated for every `c`, so `carried` and the identity of each batch's `Ctx` need no lemma.
- The hypothesis is batch-wide ("every decision in `ds` came from one `c`"), so it holds under every `pay` filter. No payment-distinctness and no flow fact is used.
- `custodyOk_rows_le` is stated over the `o` of `decideIdx` with the hypotheses of `decideIdx_refines` (a true base: `Inv rel unr` and the base digest), so custodyOk's `prs` is that conclusion with `c₀ := bt.ctx`, `d := sh.base`, `w := i.witness`, `xs := i.reqs.zip rs`. Runtime liveness holds only in its left disjunct, never inside `Collision`.
- The stated bound is 32, not the tight 24. Later rules change `Bits`, `bitsOf`, `may`, `budget_bool` and the headroom pin, never these statements.
- `reasonCode_codeOk` is restated by nobody: a new reason with a name failing `codeOk` breaks it at build time, next to the existing name-order guard (Run.lean:50).

## 5. Proof plan

Each step builds on its own. Sizes are estimates.

1. **`may_sound`** (about 5-10 lines). `revert h; cases r <;> simp (config := { contextual := true }) [fires, may, bitsOf, certain, unverified, notEnrolled]`. Leave `memberDead`, `pending`, `socDoubt` and similar folded, as atoms. Same shape as `fires_iff` (Rules/Theorems.lean:111-119), which already builds with a heavier simp set. Fallback per arm: `simp only [Bool.and_eq_true, Bool.not_eq_true'] at h ⊢; exact h.1.1`.
2. **`decideAll_may`** (about 8 lines). Induction on `ls`, generalizing `seen`, over `decideAll` (Rules/Spec.lean:470-472); `List.mem_filter` on `decideLine` (Rules/Spec.lean:463-465), then `may_sound`. It does not use `fires_iff`, which keeps the axioms small.
3. **`budget_bool`, `budget`, `headroom_le`, `headroom_eq`** (about 6 lines). Each `by decide +kernel` (the `Decidable (∀ x : Bool, p x)` instance is core, Init/Data/Bool.lean:34). Never `native_decide`: lean/tools/semantic_assurance_gate.py:31-32 refuses `Lean.ofReduceBool`. Fallback: `cases` on the six bits, then `decide`. `budget b` is `by cases b; exact budget_bool ..`.
4. **`pay_budget`** (about 6 lines). Rewrite both lengths with `List.countP_eq_length_filter` (core Count.lean:79), apply `List.countP_mono_left` (Count.lean:224) with `rs.contains r → may b r` via `List.contains_iff_mem` (Lemmas.lean:523) and `h`, then `budget b`.
5. **`reasonCode_codeOk`** (1 line). `by decide +kernel`, the same tactic and the same `reasons.map reasonCode` evaluation as `g1_reasons_pw` (StateV2.lean:6693-6694), which already builds.
6. **`rowOf_reasons_le`** (about 15 lines). Copy the peel of `rowOf_commit` (ReadManifest.lean:293-302): `obtain ⟨raw, r⟩ := x; unfold rowOf at h; cases hr : r.flow.ruled`. Unruled: `reasons = []`, length 0. Ruled: `Option.bind_eq_some_iff`, `List.length_map`, then `pay_budget b _` with `List.mem_flatMap` (Lemmas.lean:2129) and `List.mem_filter` feeding `hds`. Finish with `(by decide : 32 ≤ maxReasonCodes)`, which stays valid if the cap is raised and fails if it is lowered below 32.
7. **`decideRegT_rows_le`** (about 8 lines). `List.mem_filterMap` (Lemmas.lean:1514), then step 6 with `b := Rules.bitsOf c`; `hds` from `List.mem_map` and `decideAll_may c`. `(decideRegT c k os b).decisions` reduces to a `decideAll c …` term by definition (StateV2.lean:2207 → Rules/Spec.lean:606-607 → 529-530). If elaboration does not see it: `simp only [decideRegT, bumpRes, decideReg, decideBatchIn] at hd`.
8. **`custodyOk_rows_le`** (about 6 lines). `rcases decideIdx_refines sha3 hH c₀ k os b rel unr hi h ha d hd w o ho with ⟨hm, -, -, -, hp, -⟩ | hc` (StateV2.lean:5130-5141; the conjunct order is at :5135-5140). Left: `left; rw [hm, hp]; exact decideRegT_rows_le _ k os b rev _ rset xs`. Right: `right; exact hc`. If the `let`s in `decideIdx_refines`' statement block the destructuring, `dsimp only` the result first. It uses nothing from custody_binds, so it does not assume the `tokensOk` guard (:7756) it is meant to discharge.
9. **Axiom pins.** `#guard_msgs in #print axioms` for `may_sound`, `decideAll_may`, `budget`, `pay_budget` at the end of Theorems.lean's pin block (Rules/Theorems.lean:904-955; G4's pins are 946-955 and G4 put its pins there only, G4_DESIGN.md:40), placed after :955 and before `end BlindLedger.Gate.Rules` (:957). Pins for `reasonCode_codeOk`, `rowOf_reasons_le`, `decideRegT_rows_le` and `custodyOk_rows_le` in AxiomCheck.lean, which imports StateV2 (AxiomCheck.lean:6), in the pattern at AxiomCheck.lean:254-262, with an AXIOMS.txt entry. The private `budget_bool`, `headroom_le` and `headroom_eq` are not pinned.

Expected axioms (to confirm when built): `budget` and `reasonCode_codeOk` none; `may_sound`, `decideAll_may` `[propext]` at most; `pay_budget`, `rowOf_reasons_le`, `decideRegT_rows_le` a subset of `[propext, Classical.choice, Quot.sound]`; `custodyOk_rows_le` the union of `decideRegT_rows_le`'s and `decideIdx_refines`'s. Never `sorryAx`, `Lean.ofReduceBool` or `Lean.trustCompiler`.

Total: about 80-100 lines, about 55 in Theorems.lean and about 36 in StateV2.lean. No Mathlib needed.

## 6. What replaces the guard

- Delete Rules/Run.lean:58-59 (the comment and `#guard reasons.length ≤ BlindLedger.Gate.maxReasonCodes`). Put nothing executable in its place: Run must not import Theorems, which would pull proofs into the runner's build closure. A one-line comment points to `Rules.pay_budget`, `StateV2.decideRegT_rows_le` and `StateV2.custodyOk_rows_le`.
- **The check runs under the default build.** A plain `lake build` builds the `defaultTargets` (lakefile.toml:3), among them the `BlindLedger` library, whose root imports Rules.Theorems (BlindLedger.lean:8), and `gate_axioms`, rooted at AxiomCheck (lakefile.toml:45-47), which imports StateV2 (AxiomCheck.lean:6). So `budget_bool`, the headroom pin, `may_sound` and the StateV2 theorems are all checked by `lake build`.
- **The unit test does not run it.** `test_proofs_are_current` runs `lake build --no-build` over its PROOFS list (tests/test_gate_rules_vectors.py:19-20, 34): it only reports a module whose build is stale and never elaborates anything, and the whole class is skipped when the `gate_rules` exe is missing (:23-24). It is a staleness alarm, not the check.
- **Guarded command after any Rules/Spec.lean, Rules/Theorems.lean or StateV2.lean change** (and so after every later rule): from the worktree root, `scripts/rr_guarded_interim.ps1 -Worktree <worktree>\rightrail\lean -Suffix reason-bound-build -MinFree <bytes> -Exe <lake.exe> -ArgList build`, that is the default `lake build` under the guard (scripts/rr_guarded_interim.ps1:10-15, 26-36). A rule commit is not done until that run passes.
- The tripwire effect stays, now per payment. A rule whose codes overflow fails `budget_bool` at build time; a rule whose classification lets a firing code escape fails `may_sound`; a rule that moves the tight maximum fails the headroom pin until it is bumped.
- Deleting the guard changes Run's `source` digest (Run.lean:69-73). The unit test recomputes it (tests/test_gate_rules_vectors.py:26-30).

## 7. How each later rule extends it

Each snapshot-backed rule adds one `Ctx` field, one `Bits` field with its `usable …` term in `bitsOf`, and `may` arms: certain codes map to the bit, the shared `_UNVERIFIED` and STALE codes map to its negation. `budget_bool` and `headroom_le` each gain one `∀ _ : Bool`, and `headroom_eq`'s witness tuple one `false`. The compiler flags every site: the `may` match has no wildcard and the anonymous constructor changes arity. `may_sound` is reproved by the same tactic with the new fact definitions in its simp set. The headroom literal (24 today) is bumped deliberately, so the reviewer sees the new slack. `reasonCode_codeOk` needs no edit; it checks each new name.

Code names below are placeholders for the owner. Each must pass `codeOk` (64 characters, Spec.lean:119-122; checked by `reasonCode_codeOk`) and the name-order guard (Run.lean:50), and each unverified or STALE code must be in `review` (Run.lean:56).

| Rule (localBCE) | Codes (lean shape) | Bit | `may` arms | Per-payment cost | Running total |
|---|---|---|---|---|---|
| G5 new conditions, rust-engine/src/main.rs:249-254 | PROVIDER_NOT_ENROLLED, PROVIDER_TYPE_INVALID (certain, first failing per line, like `g2_exclusive`); one shared PROVIDER_ENROLLMENT_UNVERIFIED; STALE_PROVIDER_ENROLLMENT | `pe`, new provider-enrollment snapshot | 2 × `b.pe`, 2 × `!b.pe` | 2 | 26 |
| G6, main.rs:255-260 | BILLING_CODE_INVALID, UNITS_INVALID; one shared `_UNVERIFIED`; one STALE | `ct`, code-table snapshot | 2 × `b.ct`, 2 × `!b.ct` | 2 | 28 |
| G6 variant: pinned constant table, like `allowedAid` (Rules/Spec.lean:353) | the 2 certain codes only | none | `true`, `true` | 2 | 28 |
| G8, main.rs:264-266 | X, X_UNVERIFIED, STALE (3-code); or X, STALE (2-code) | `dd` | `b.dd`, `!b.dd`, `!b.dd` | 2 (or 1) | 30 (or 29) |
| G10, main.rs:270-272 | same shapes as G8 | `pc` | same | 2 (or 1) | **32** (or **30**) |

Design rules for these rules, or each costs +1 per code:
- **One shared `_UNVERIFIED` per source.** A source's cost is max(#certain, #unverified + #STALE). The G2 shape (one `_UNVERIFIED` per fact) costs 3 for a two-fact source. G2-shape G5 and G6 alone give 30 and would build; with 3-code G8 and G10 after them they give 34, which fails `budget_bool`. The shared code keeps "a present but unusable snapshot still shows its fact for review" (Rules/Spec.lean:72-75); only the two unverified facts share a code, and certain facts stay separate.
- **No "doubt" branch on a usable snapshot**, as `SHARE_OF_COST_UNMET_UNVERIFIED` has (Rules/Spec.lean:428-429). Such a code must map to `true` and costs +1.
- **After G10 at 3-code shapes there is no slack.** Any further rule needs the flow fact (+1), a shape change, or a cap raise. The cap raise is a TOKEN/v1 change with a gate_verify re-pin; past 34 codes it also needs a `maxTokenBytes` raise (section 11; G4_DESIGN.md:136).
- **Bit count.** After G10: 10 bits (9 with a pinned G6 table). `budget_bool` and `headroom_le` then check 1,024 tuples × 45 reasons each, about 92,000 `may` evaluations together. Past about 12-14 bits, switch the private `budget_bool` and `headroom_le` to per-group caps summed (`grp : Reason → Grp` with no wildcard, one `cap_X` lemma per group by `decide +kernel` over 2 values, a partition lemma by induction with `List.length_eq_countP_add_countP`, Count.lean:66). That is linear forever and costs about 40-60 extra lines. The public statements in section 4 do not change.

## 8. Tests and mutants

**Mutants are one-off manual checks.** tools/gate_rules_mutants.py cannot run them: it edits only Rules/Spec.lean, Fast.lean and Run.lean (gate_rules_mutants.py:3-11, 439, 458-462), counts a vectors-invisible mutant as killed only if a module in its PROOFS list fails to build (:32-36, 478-479), and StateV2 is not in that list (:34-35). Every mutant it lists must be killed or it exits non-zero (:488-489), so a documented survivor cannot be listed there either. Default: each mutant below is applied to a scratch copy of the lean tree (never the tracked tree), built under the guard with the target named, and its result (fails where expected, with the error location; or builds) is recorded in the commit message. They are not regression-run afterwards. The owner alternative is in decision 13.

- **M1, wrong tag (count-preserving swap):** `may` arms `.MEMBER_DECEASED => !b.dmf` and `.STALE_DMF => b.dmf` (MEMBER_DECEASED_UNVERIFIED stays `!b.dmf`). Target `BlindLedger.Gate.Rules.Theorems`. The DMF group still allows 1 code when usable and 2 when not, so every tuple's count is unchanged: `budget_bool`, `headroom_le` and `headroom_eq` build, and `may_sound` is the only failure (MEMBER_DECEASED fires on `usable`, STALE_DMF on `!usable`). This is `may_sound`'s distinctive value: it catches a wrong `may` tag that no count sees. (The single-arm variant `.STALE_DMF => b.dmf` alone moves the all-false count to 23, so it is expected to fail at `may_sound` and `headroom_eq`, with `headroom_le` building; it is not the default because the pin, not only `may_sound`, kills it.)
- **M2, Spec mutant on a firing arm (redundant cross-check):** weaken MEMBER_DECEASED from `certain` to `c.dmf.isSome && …` (Rules/Spec.lean:415). `may_sound` fails. This is not new coverage: a Spec-only change to `fires` already fails `FastEq` (the twin no longer equals the Spec), which is in the tool's PROOFS (gate_rules_mutants.py:34). It confirms `may_sound` reads the live `fires`.
- **M3, loose certain tag:** `.MEMBER_DECEASED => true`. Target `BlindLedger.Gate.Rules.Theorems`. `may_sound` and `budget_bool` build (the tag is loose but sound; 25 ≤ 32); `headroom_le` and `headroom_eq` fail (the all-false count becomes 25). This shows the pin is tag-sensitive. The old M3, `.STALE_DMF => true`, is now an expected survivor: it is one of the loose tags the pin does not see (section 4a), and is listed so the reviewer knows it is invisible, not untested.
- **M4, budget overflow:** in a scratch copy, add G2-shape G5 and G6 (5 codes each: 2 certain tagged `b.pe` / `b.ct`, 2 `_UNVERIFIED` and 1 STALE tagged `!b.pe` / `!b.ct`) **and** 3-code G8 and G10 placeholders (X `b.dd` / `b.pc`, X_UNVERIFIED and STALE `!b.dd` / `!b.pc`). Only Rules/Spec.lean (constructors in name order, `reasons`, `fires` arms `false`, `review` arms) and Theorems.lean (four `Bits` fields, `may` arms, binders, and a `False` arm in `Fact` for each new constructor, since `Fact` has no wildcard, Rules/Theorems.lean:54-97) change; target `BlindLedger.Gate.Rules.Theorems`. `budget_bool` fails: worst case 24 + 3 + 3 + 2 + 2 = 34. G2-shape G5 and G6 alone give 30 and would build. `budget_bool` and the headroom pin (`headroom_le`, `headroom_eq`) are the only expected errors; a kill counts only if one is at `budget_bool`, and any other error (a missing `Fact` arm, `may_sound`) means the scratch copy is incomplete. The per-payment successor of the old tripwire.
- **M5, new Reason with no `may` arm:** add one certain code (so no `review` entry, Run.lean:56), placed in name order (Run.lean:50), with its `reasons` entry, a `fires` arm `false` and a `Fact` arm `False`, and omit only its `may` arm. Target `BlindLedger.Gate.Rules.Theorems`. The expected errors are the missing case at `may` (no wildcard; Lean still adds `may` with an admitted branch) and, following from it, the kernel-decide failures at `budget_bool`, `headroom_le` and `headroom_eq`, which now evaluate `may` on the new constructor and reach `sorryAx`. The kill is counted by the `may` error. Any other error (a missing `Fact` arm, `may_sound`) means the scratch copy is incomplete.
- **M6, lower the cap** (Spec.lean:32 to 23): `rowOf_reasons_le` fails at `32 ≤ maxReasonCodes`. Target `BlindLedger.Gate.AxiomCheck` (StateV2 is outside the tool's PROOFS). Expected; never ship it. It is a protected wire edit anyway.

Vectors:
- **V1 (optional rules vector, tightness witness):** one FFS payment of three or more lines; DMF, provider-death, exclusion, enrollment, eligibility and share-of-cost snapshots present but unusable; both sets unchained; one line with a future date, another with an invalid date (unverified codes need a valid date, so that line carries none); key collisions spread across lines. Expected 23 codes, which encode, decode and pass `tokensOk`. A CAP_820 twin reaches 20. Re-count before writing. Default: not added; the theorem is the evidence, and a vector adds a conformance XI.2 item. If added, it goes in rules_v3.vectors, the file the runner uses (tests/test_gate_rules_vectors.py:38), not rules_v2. Snapshots persist across cases (tests/gate_rules/rules_v3.vectors:4), so its placement needs care: it must restore every snapshot it changes.
- **V2 (Python codec):** a 33-code `TokenLeaf` raises `GateCodecError` (app/right_rail_gate_codec.py:67, 402). Add it if absent. It touches no Lean. Its line cost is section 9 item 5.

## 9. XI.2 items

One commit, one "XI.2:" paragraph each (rightrail/STATUS.md:3; G4_DESIGN.md:586-625 shape).
1. **Lean statements (additions only).** Definitions `Rules.Bits`, `Rules.bitsOf`, `Rules.may`. Theorems `Rules.may_sound`, `Rules.decideAll_may`, `Rules.budget`, `Rules.pay_budget` (private `budget_bool`), `StateV2.reasonCode_codeOk`, `StateV2.rowOf_reasons_le`, `StateV2.decideRegT_rows_le`, `StateV2.custodyOk_rows_le` (runtime liveness of the count for custodyOk's `prs`, StateV2.lean:7751-7752, via `decideIdx_refines`, :5130-5141, outside its `Collision` disjunct), with axiom pins and built values quoted. Private, non-protected headroom pin `headroom_le` and `headroom_eq` (maximum 24 over every tuple). Nothing withdrawn or restated: custody_binds (StateV2.lean:7790-7803), `decideIdx_refines` (5130-5141), `reasonCode_ascending` (6704), `Fact` and `fires` are unchanged.
2. **Tripwire removal.** Rules/Run.lean:58-59 deleted. The withdrawn claim is "every reason fits one token while the set is ≤ cap"; it is replaced by the proved claims that every row built from one batch's decisions has at most `maxReasonCodes` codes (and custodyOk's rows too, outside `decideIdx_refines`' `Collision` disjunct) and that every reason's code passes `codeOk`. Run's `source` digest changes and is recomputed by the unit test.
3. **Superseded design text.** G4_DESIGN.md:126-131 ("not proved") and :134-135 (tripwire) are superseded by a proved per-payment bound of 32 (maxReasonCodes); the classification's maximum is 24, kernel-checked by the private headroom pin; the real maximum of 23 stays argued.
4. **No-change attestations.** Gate/Spec.lean:32, :35, :119-122, :129-131 and :460, TOKEN/v1, the READ-SET tag (StateV2.lean:6726), every digest domain, conformance and artifacts/**. gate_verify needs no re-pin (VerifyCli.lean:1-3). Plan:99's "pinned worker re-pinned" did not apply to G2 or G4 (LOG.md:250-252, G4_DESIGN.md:45); the lead confirms it does not apply here either.
5. **Bloat (Decision 5 / Art. XII).** `EVIDENCE_CODE_LINES` (tests/test_bloat_budget.py:18) is raised by the measured line delta of V2, the Python 33-code test, as an exact actual, with its felt effect: "a hand-built leaf with more reason codes than TOKEN/v1 allows is refused by the Python encoder, so no such token is signed". `PRODUCT_CODE_LINES` (:16) is unchanged as long as tools/gate_rules_mutants.py is not extended (decision 13 default); the tool is product code there (it lives under `tools/`, not `tests/` or `lean/`, :59-61). Lean lines are not counted (:17, 59), so the theorems, the headroom pin and the deleted guard move no ceiling. Markdown ceilings: this design file lives under `docs/`, outside `rightrail/`, so it is outside `MARKDOWN_BYTES`.

## 10. Rebuild estimate

To be measured by the lead under the guard; these are estimates only.
- **Theorems.lean** changes, so Rules.Shards, Rules.ShardRun, Rules.DecideLayer, Rules.FastEq (Rules/FastEq.lean:1) and everything above them rebuild.
- **Run.lean** changes, so its downstream closure rebuilds: Rules.FastEq (Rules/FastEq.lean:3) → Rules.Resident (Rules/Resident.lean:1) → Engine.OneProc (Engine/OneProc.lean:1, the `gate_engine` exe, lakefile.toml:62-65); FastEq → Rules.ShardRun (Rules/ShardRun.lean:2) → StateV2 (StateV2.lean:51) and its dependents (ReadManifest, AxiomCheck, Engine.Snap); ShardRun → Rules.DecideLayer and Engine.Log; ReadManifest also imports Run directly (ReadManifest.lean:3); RulesMain (Rules/RulesMain.lean:1, the `gate_rules` exe) relinks and its `source` digest changes. The Theorems and Run closures overlap; together they are the closure G4 rebuilt. StateV2 dominates, as it did for G4. The new proof work itself is small next to that.
- **Kernel work today:** `budget_bool` and `headroom_le` each 64 tuples × 31 reasons, about 4,000 `may` evaluations together, plus `reasonCode_codeOk` over 31 names (the same evaluation `g1_reasons_pw` already does): under a second natively, well under a minute emulated. After G10, about 92,000: seconds natively, perhaps a few minutes emulated. If either check takes more than about 2 minutes under the guard, take the per-group fallback (section 7).
- **`may_sound`:** 31 Bool-level simp goals, smaller than the `fires_iff` goals that already build.
- **The command** is the guarded default `lake build` of section 6. It rebuilds every module above. Then `test_proofs_are_current` passes, because it only checks that FastEq, Resident, Theorems, Sha3FastEq and ReadManifest are not stale (tests/test_gate_rules_vectors.py:19-20, 34; G4_DESIGN.md:39).
- **The mutants of section 8** are extra scratch-copy builds: M1, M3, M4, M5 to Theorems only (cheap); M2 to Theorems; M6 to AxiomCheck (a full StateV2 rebuild).
- No tests can run that need the ML-DSA-87 signer exe, which is not built here (OPEN_QUESTIONS.md:20); and without the `gate_rules` exe the whole vectors class, `test_proofs_are_current` included, is skipped (tests/test_gate_rules_vectors.py:23-24).

## 11. Risks

- **Zero headroom after G10** at 3-code G8 and G10 (32 of 32). Any later rule forces the flow fact, a shape change or a cap raise. Low risk now, decided by D4 and D5.
- **Tactic risk in `rowOf_reasons_le`:** the `do`-match peel. Medium, bounded by the `rowOf_commit` template that already builds (ReadManifest.lean:293-302).
- **Definitional unfolding of `decideRegT`** in step 7 may need an explicit `simp only`. Low.
- **Runtime twin.** custodyOk builds `prs` from `decideIdx`'s output `o` (StateV2.lean:7748-7752), not from `decideRegT` directly. custody_binds (StateV2.lean:7790-7791) cannot carry the liveness claim: it assumes `custodyOk … = some e`, which already passed the `tokensOk` guard (:7756), so it would be circular. The link is `decideIdx_refines` (StateV2.lean:5130-5141): its hypothesis is only `decideIdx … = some o`, which holds right after :7748 and before :7756, and on a true base it equates `o`'s (line, outcome, reasons) map and `o.pays` with `decideRegT (carried bt.ctx rel unr) …`'s (:5135-5139). So `decideRegT_rows_le` bounds custodyOk's `prs`, stated as `custodyOk_rows_le`, but only outside that theorem's `Collision` disjunct (:5141): runtime liveness holds only there. Inside it nothing is claimed; an overflowing runtime row is still refused, never truncated (Spec.lean:460; StateV2.lean:6772-6773, 7756).
- **Token size (`maxTokenBytes` 4096, Spec.lean:35) is not proved, but it cannot overflow at the current cap.** From `pLeaf` and `pToken` (Spec.lean:446-488): every field except the codes is fixed or capped: domain 17 bytes (Spec.lean:48), five `ident`s at most 2 + 128 bytes each (`blob 1 65535` has a 2-byte length prefix, Spec.lean:93; `identOk` caps 128 bytes, :113-116), member key 32 (:41), shard 4, revision, amount and five times 8, three 1-byte tags, linesRoot and four digests of 64 (:24), the 1-byte code count, then up to 10 path digests of 64 with a 1-byte count (:27) and the checkpoint digest of 64. That is at most 1,788 bytes. Each code is a `blob` too: 2 + len(name) bytes, name at most 64 bytes (`codeOk`, :119-122). Today's 24-code worst case (the all-false tuple) has names totalling 523 bytes, the longest BENEFIT_LEVEL_MISSING_UNVERIFIED at 32: 523 + 2 × 24 = 571 bytes, a token of at most 2,359 bytes. Even 32 codes of 64 bytes take 32 × 66 = 2,112, a token of at most 3,900 ≤ 4,096. So no name-length rule is needed at cap 32; a cap raise past 34 with long names could exceed 4,096 (35 × 66 = 2,310 > 4,096 − 1,788 = 2,308). This is arithmetic, not a theorem.
- **Over-approximation hides real slack.** The proved per-payment bound is 32; the classification's kernel-checked maximum is 24 where the argued maximum is 23. Cost: one code of budget, recoverable by the flow fact (D4).
- **Loose tags the pin does not see** (section 4a): sound, but they can hide slack until a rule needs it. Bounded by decision 2's alternatives.
- **Manual mutants are not regression-run.** They prove the checks bite once, at this commit; a later edit that weakens `may_sound`'s link is caught only by review unless decision 13's alternative is taken.
- **Python never computes codes** (app/right_rail_gate_decide.py:223, 227-241). The proof covers the Lean path; the Python encoder's own cap (app/right_rail_gate_codec.py:402) stays the guard for hand-built leaves.

## 12. Decisions for the owner

Each default is approvable in one word ("yes"); the alternative follows.
1. **Approach.** Default: per-source bits, `may`, `may_sound`, and one `decide +kernel` check (sections 4-5). Alternative: per-group caps summed now (linear, about 120-170 lines).
2. **Stated bound and headroom pin.** Default: the literal 32 for every `Ctx`, stable across rules, plus the non-protected, tag-sensitive headroom pin `headroom_le` (maximum ≤ 24 over every tuple) and `headroom_eq` (= 24 at the all-false tuple), both by `decide +kernel`. Alternatives: add a second equality at the all-true tuple (19 today), which sees every single loosening to `true`, including the ones the default does not see (about 2 lines); or pin all 64 per-tuple counts (sees every tag change; restated with each rule, 1,024 counts after G10); or state the tight 24 publicly and restate it with each rule.
3. **Placement.** Default: append to Rules/Theorems.lean (outside Run's digest) and StateV2.lean after `reasonCode_ascending` and after `rowOf`. Alternative: a new Rules/Budget.lean imported by StateV2.
4. **Flow fact.** Default: not now (about 40 lines, medium risk; buys 1 code). Alternative: prove that every line of a payment shares the request flow (Spec.lean:318 via `linesOf`, StateV2.lean:6477-6478) now.
5. **G8 and G10 shape.** Default: 3-code (X, X_UNVERIFIED, STALE), consistent with R1, R3 and R5, ending at 32 with zero headroom. Alternative: 2-code, ending at 30 but dropping the review code for a present but unusable snapshot.
6. **G5 and G6 shape.** Default: one shared `_UNVERIFIED` per source (required once G8 and G10 follow at 3-code shapes; the G2 shape then gives 34 and fails the build, though G5 and G6 alone at G2 shape give 30).
7. **G6 source.** Default: a code-table snapshot (4 codes, one bit). Alternative: a pinned constant table like `allowedAid` (2 codes, no bit, no STALE).
8. **When the guard goes.** Default: delete Run.lean:58-59 in the same commit as the theorems. Alternative: keep it until the G5 commit, which edits Rules/Spec.lean and changes Run's digest anyway, saving one digest change.
9. **Custody lift.** Default: include `decideRegT_rows_le` (about 8 lines), which `custodyOk_rows_le` (decision 15) is proved from. Alternative: stop at `rowOf_reasons_le`; this also forces decision 15's alternative and narrows section 1's runtime-liveness claim to single rows.
10. **Vectors.** Default: add V2 (Python 33-code refusal) only, with its `EVIDENCE_CODE_LINES` raise (section 9 item 5); no new rules vector. Alternative: also add V1, the 23-code tightness vector, as a conformance XI.2 item.
11. **Fallback trigger.** Default: switch `budget_bool` and `headroom_le` to per-group caps only if either takes more than about 2 minutes under the guard or the bits pass 12.
12. **Headroom policy after G10.** Default: any rule after G10 needs D4 (flow fact) first, then a shape review; a cap raise (TOKEN/v1 bump, gate_verify re-pin, and past 34 codes a `maxTokenBytes` raise) only as a last resort.
13. **Mutant tooling.** Default: M1-M6 are one-off manual scratch-copy checks run under the guard, results recorded in the commit message; tools/gate_rules_mutants.py is not changed and `PRODUCT_CODE_LINES` does not move. Alternative: extend the tool with a Theorems.lean mutant list, StateV2 (or AxiomCheck) in PROOFS, and an expected-survivor category for documented loose tags; cost is product code under tests/test_bloat_budget.py:16 (G4's 25 mutants cost +40 lines), roughly +20-40 `PRODUCT_CODE_LINES` with an Art. XII felt effect, plus a full StateV2 rebuild for every mutant the vectors miss.
14. **`codeOk` lemma.** Default: add `reasonCode_codeOk` (1 line, `decide +kernel`) after `reasonCode_ascending`, with an AxiomCheck pin, so the liveness claim covers the whole `reasonCodes` field (count, `codeOk`, order). Alternative: leave `codeOk` to the decoder's refusal and the vectors, and narrow section 1's claim to count and order.
15. **Runtime corollary.** Default: add `custodyOk_rows_le` (about 6 lines, after `decideRegT_rows_le`, with an AxiomCheck pin), stated over the `o` of `decideIdx` and proved from `decideIdx_refines` (StateV2.lean:5130-5141), so the count's runtime liveness for custodyOk's `prs` (:7751-7752) is a theorem, not an argument, and is explicitly limited to the non-`Collision` disjunct. custody_binds is not used for it, because it assumes the `tokensOk` guard (:7756) already passed. Alternative: leave the runtime link as the section 11 argument and claim liveness for `decideRegT`'s rows only.

## 13. Implementation record (2026-11-14)

Where the implementation differs from the text above:
- **`decideAll_may`** sits after `mem_decideAll` (Lean has no forward references) and uses it instead of a fresh induction.
- **`rowOf_reasons_le`** unfolds `StateV2.rowOf`: the bare name is ambiguous with `BlindLedger.Gate.rowOf` from AnchorTheorems. Its implicit binders carry explicit types.
- **`decideRegT_rows_le`** uses the step 7 fallback `simp only [decideRegT, bumpRes, decideReg, decideBatchIn]` directly.
- **`custodyOk_rows_le`** destructures `decideIdx_refines` with its seven conjuncts and rewrites only the decisions map: `decideRegT_rows_le` holds for every `pays`, so `o.pays` needs no rewrite.
- **`tools/gate_print_axioms.lean`** gains the four StateV2 names, because `AxiomRecordTests` requires it to list exactly AxiomCheck's pins.
- **V2** is four lines added to the existing `EncoderLawTests.test_encoder_refuses_noncanonical_values`: a 32-code leaf encodes and a 33-code leaf raises `GateCodecError("reason_codes")`. `EVIDENCE_CODE_LINES` rose by exactly 4.
- **Built axioms** (the predictions in section 5 were partly wrong): `may_sound` and `decideAll_may` [propext, Quot.sound]; `budget` none; `pay_budget` [propext]; `reasonCode_codeOk` [propext]; `rowOf_reasons_le` and `decideRegT_rows_le` [propext, Quot.sound]; `custodyOk_rows_le` [propext, Classical.choice, Quot.sound].
- **Mutants M1-M6**, each in a scratch copy of the lean tree under the guard, all as predicted (the `#guard_msgs` failures that follow a failed proof are knock-on `sorryAx` pins):
  - M1 (count-preserving DMF tag swap): only `may_sound` fails; `budget_bool`, `headroom_le` and `headroom_eq` build.
  - M2 (MEMBER_DECEASED weakened in Spec): `fires_iff` and `may_sound` fail.
  - M3 (`.MEMBER_DECEASED => true`): `headroom_le` and `headroom_eq` fail; `budget` builds.
  - M4 (G2-shape G5 and G6, 3-code G8 and G10): `budget_bool`, `headroom_le` and `headroom_eq` fail.
  - M5 (new reason, no `may` arm): missing case at `may`, then the kernel checks that evaluate it.
  - M6 (`maxReasonCodes` 23): `rowOf_reasons_le` fails at `32 ≤ maxReasonCodes`.
