import BlindLedger.Gate.Engine3.StepH
import BlindLedger.Gate.Engine3.Verify
import BlindLedger.Gate.Engine3.Hist
import BlindLedger.Gate.Engine3.VMirror
import BlindLedger.Gate.Engine3.RowsStore

/-! The payment numbering of an Engine3 batch.  `stepH` numbers the requests (`Run.payIdx`: a covered request whose
    lines fit and are ruled and not empty gets the next number); `Hist.read` numbers the lines of the kept requests
    (`Hist.payLines`: each ruled request with lines gets the next number, once per line) and gives each layout line
    that number as its payment (`assemble`).  The checker has its own copies (`Verify.payIdxC`, `VMirror.payLinesV`).

    - `payIdx_spec`, `payIdxC_spec`: the request numbering, as the list `numFrom 0` over the requests zipped with their
      cover and fit flags; `numFrom_lt`: every number is below the count `np`.
    - `payLines_pidx`, `payLinesV_pidx`: the line numbering, as `linesNum 0` over the kept requests.
    - `lines_agree`: over the kept requests, `linesNum` gives each line the number `numFrom` gives its request.
    - `payIdx_lines`, `payIdxC_lines`: together, the line numbers `payLines` gives are, line for line, the request
      numbers `payIdx` gives; `admB_sizes` discharges their size hypotheses for the flags `stepH`/`stepC` pass
      (`payIdx_lines_admB`, `payIdxC_lines_admB`).
    - `assemble_pay`: the layout's lines have those numbers as their payments, in order.

    `numFrom_lt` bounds the request numbers; `assemble_pay_lt` (checker: `assemble_payC_lt`) composes it with
    `payIdx_lines_admB` and `assemble_pay`: every layout line's payment is below `np` (given a number for each line).
    Read from the code, not proved: that `Hist.read`/`VMirror.read` pass `payLines`' numbers to `assemble` (one call,
    `IO`) and, by their `pidx.size != b.size` check, give `assemble` a `req` of `pidx`'s size (`hs`).  Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Flat.PayNum

open BlindLedger.Gate.Rules
open BlindLedger.Gate.Flat.Rows (LineIn)

/-! ## Streams over arrays -/

private theorem sub_start {α} (a : Array α) (k : Nat) (hk : k ≤ a.size) : (a.toSubarray k).start = k := by
  unfold Array.toSubarray
  repeat' split
  all_goals first | rfl | omega

private theorem sub_stop {α} (a : Array α) (k : Nat) : (a.toSubarray k).stop = a.size := by
  unfold Array.toSubarray
  repeat' split
  all_goals first | rfl | omega

private theorem next_sub {α} (a : Array α) (k : Nat) (hk : k < a.size) :
    Std.Stream.next? (a.toSubarray k) = some (a[k], a.toSubarray (k + 1)) := by
  simp only [Std.Stream.next?]
  rw [dif_pos (by rw [sub_start a k (Nat.le_of_lt hk), sub_stop]; exact hk)]
  simp [Array.toSubarray, Subarray.start, Subarray.array, Nat.le_of_lt hk, Nat.succ_le_of_lt hk]

/-! ## The request numbering -/

/-- A request that gets a number when covered and fitting: ruled, with lines. -/
def ruledL (x : Run.Req) : Bool := x.ra.flow.ruled && !x.ra.lines.isEmpty

/-- The request numbers from `n`, over the requests with their cover and fit flags. -/
def numFrom : Nat → List (Run.Req × Bool × Bool) → List (Option Nat)
  | _, [] => []
  | n, (x, c, u) :: t => if (c && !u && ruledL x) = true then some n :: numFrom (n + 1) t else none :: numFrom n t

/-- The count after numbering from `n`. -/
def cntFrom : Nat → List (Run.Req × Bool × Bool) → Nat
  | n, [] => n
  | n, (x, c, u) :: t => if (c && !u && ruledL x) = true then cntFrom (n + 1) t else cntFrom n t

private theorem loop (cv uv : Array Bool)
    (F : Run.Req → Array (Option Nat) × Nat × Subarray Bool × Subarray Bool →
      Id (ForInStep (Array (Option Nat) × Nat × Subarray Bool × Subarray Bool)))
    (hF : ∀ x ix n k (hc : k < cv.size) (hu : k < uv.size),
      F x (ix, n, cv.toSubarray k, uv.toSubarray k) =
        pure (ForInStep.yield (if (cv[k] && !uv[k] && ruledL x) = true then
          (ix.push (some n), n + 1, cv.toSubarray (k + 1), uv.toSubarray (k + 1))
          else (ix.push none, n, cv.toSubarray (k + 1), uv.toSubarray (k + 1))))) :
    ∀ (l : List Run.Req) (ix : Array (Option Nat)) (n k : Nat), k + l.length ≤ cv.size → k + l.length ≤ uv.size →
      let z := l.zip ((cv.toList.drop k).zip (uv.toList.drop k))
      forIn (m := Id) l (ix, n, cv.toSubarray k, uv.toSubarray k) F =
        ((ix.toList ++ numFrom n z).toArray, cntFrom n z, cv.toSubarray (k + l.length), uv.toSubarray (k + l.length))
  | [], ix, n, k, _, _ => by simp [numFrom, cntFrom]; rfl
  | x :: l, ix, n, k, hc, hu => by
    intro z
    have hc' : k < cv.size := by simp at hc; omega
    have hu' : k < uv.size := by simp at hu; omega
    have dc : cv.toList.drop k = cv[k] :: cv.toList.drop (k + 1) := by
      rw [List.drop_eq_getElem_cons (by simpa using hc')]; simp
    have du : uv.toList.drop k = uv[k] :: uv.toList.drop (k + 1) := by
      rw [List.drop_eq_getElem_cons (by simpa using hu')]; simp
    have hz : z = (x, cv[k], uv[k]) :: l.zip ((cv.toList.drop (k + 1)).zip (uv.toList.drop (k + 1))) := by
      simp only [z, dc, du, List.zip_cons_cons]
    rw [List.forIn_cons, hF x ix n k hc' hu', hz]
    have hc2 : k + 1 + l.length ≤ cv.size := by simp at hc; omega
    have hu2 : k + 1 + l.length ≤ uv.size := by simp at hu; omega
    by_cases hp : (cv[k] && !uv[k] && ruledL x) = true
    · simp only [if_pos hp, numFrom, cntFrom, pure_bind]
      rw [loop cv uv F hF l _ _ (k + 1) hc2 hu2]
      simp [Nat.add_assoc, Nat.add_comm 1]
    · simp only [if_neg hp, numFrom, cntFrom, pure_bind]
      rw [loop cv uv F hF l _ _ (k + 1) hc2 hu2]
      simp [Nat.add_assoc, Nat.add_comm 1]

/-- The engine's request numbering (`stepH`), as `numFrom 0` and `cntFrom 0`. -/
theorem payIdx_spec (reqs : Array Run.Req) (covR unfR : Array Bool) (hc : covR.size = reqs.size)
    (hu : unfR.size = reqs.size) :
    let z := reqs.toList.zip (covR.toList.zip unfR.toList)
    BlindLedger.Gate.Engine3.Run.payIdx reqs covR unfR = ((numFrom 0 z).toArray, cntFrom 0 z) := by
  intro z
  unfold BlindLedger.Gate.Engine3.Run.payIdx
  simp only [Id.run, ← Array.forIn_toList]
  rw [show Std.toStream covR = covR.toSubarray 0 from rfl, show Std.toStream unfR = unfR.toSubarray 0 from rfl]
  rw [loop covR unfR _ ?_ reqs.toList _ 0 0 (by simp [hc]) (by simp [hu])]
  · rfl
  · intro x ix n k hck huk
    simp only [next_sub unfR k huk, next_sub covR k hck]
    have e : (covR[k] && !unfR[k] && x.ra.flow.ruled && !x.ra.lines.isEmpty) = (covR[k] && !unfR[k] && ruledL x) := by
      simp only [ruledL, Bool.and_assoc]
    split <;> rename_i h <;> rw [e] at h
    · rw [if_pos h]
    · rw [if_neg h]

/-- The checker's copy (`stepC`), the same. -/
theorem payIdxC_spec (reqs : Array Run.Req) (covR unfR : Array Bool) (hc : covR.size = reqs.size)
    (hu : unfR.size = reqs.size) :
    let z := reqs.toList.zip (covR.toList.zip unfR.toList)
    BlindLedger.Gate.Engine3.Verify.payIdxC reqs covR unfR = ((numFrom 0 z).toArray, cntFrom 0 z) := by
  intro z
  unfold BlindLedger.Gate.Engine3.Verify.payIdxC
  simp only [Id.run, ← Array.forIn_toList]
  rw [show Std.toStream covR = covR.toSubarray 0 from rfl, show Std.toStream unfR = unfR.toSubarray 0 from rfl]
  rw [loop covR unfR _ ?_ reqs.toList _ 0 0 (by simp [hc]) (by simp [hu])]
  · rfl
  · intro x ix n k hck huk
    simp only [next_sub unfR k huk, next_sub covR k hck]
    have e : (covR[k] && !unfR[k] && x.ra.flow.ruled && !x.ra.lines.isEmpty) = (covR[k] && !unfR[k] && ruledL x) := by
      simp only [ruledL, Bool.and_assoc]
    split <;> rename_i h <;> rw [e] at h
    · rw [if_pos h]
    · rw [if_neg h]

private theorem cnt_ge : ∀ (n : Nat) (z : List (Run.Req × Bool × Bool)), n ≤ cntFrom n z
  | _, [] => Nat.le_refl _
  | n, (x, c, u) :: t => by
    by_cases hp : (c && !u && ruledL x) = true
    · simp only [cntFrom, if_pos hp]; have := cnt_ge (n + 1) t; omega
    · simp only [cntFrom, if_neg hp]; exact cnt_ge n t

/-- Every number `numFrom n` gives is at least `n` and below the count: `stepH`'s `msk[p]!` and `fl[p]!` read inside
    `payFlags`' arrays of size `np`. -/
theorem numFrom_lt : ∀ (n : Nat) (z : List (Run.Req × Bool × Bool)) (p : Nat), some p ∈ numFrom n z →
    n ≤ p ∧ p < cntFrom n z
  | _, [], p, h => by simp [numFrom] at h
  | n, (x, c, u) :: t, p, h => by
    by_cases hp : (c && !u && ruledL x) = true
    · simp only [numFrom, cntFrom, if_pos hp, List.mem_cons, Option.some.injEq] at h ⊢
      rcases h with rfl | h
      · exact ⟨Nat.le_refl _, Nat.lt_of_lt_of_le (Nat.lt_succ_self _) (cnt_ge (p + 1) t)⟩
      · have := numFrom_lt (n + 1) t p h; omega
    · simp only [numFrom, cntFrom, if_neg hp, List.mem_cons, reduceCtorEq, false_or] at h ⊢
      exact numFrom_lt n t p h

/-! ## The line numbering -/

/-- The line numbers from `n`: each ruled request with lines gets the next number, once per line. -/
def linesNum : Nat → List Run.Req → List Nat
  | _, [] => []
  | n, x :: t => if ruledL x = true then List.replicate x.ra.lines.length n ++ linesNum (n + 1) t else linesNum n t

/-- Over the kept requests (covered, lines fit), `linesNum` gives each line the number `numFrom` gives its request. -/
theorem lines_agree : ∀ (n : Nat) (z : List (Run.Req × Bool × Bool)),
    linesNum n (z.filterMap fun (x, c, u) => if (c && !u) = true then some x else none) =
      (z.zip (numFrom n z)).flatMap fun (e, o) => match o with
        | some p => List.replicate e.1.ra.lines.length p
        | none => []
  | _, [] => rfl
  | n, (x, c, u) :: t => by
    by_cases hk : (c && !u) = true
    · by_cases hr : ruledL x = true
      · have hp : (c && !u && ruledL x) = true := by simp [hk, hr]
        simp only [List.filterMap_cons, if_pos hk, linesNum, if_pos hr, numFrom, if_pos hp, List.zip_cons_cons,
          List.flatMap_cons, lines_agree (n + 1) t]
      · have hp : (c && !u && ruledL x) = false := by simp [hk, hr]
        simp only [List.filterMap_cons, if_pos hk, linesNum, hr, numFrom, hp, List.zip_cons_cons,
          List.flatMap_cons, lines_agree n t]
        simp
    · have hp : ¬(c && !u && ruledL x) = true := by simp_all
      rw [List.filterMap_cons]
      dsimp only
      rw [if_neg hk]
      dsimp only
      simp only [numFrom, if_neg hp, List.zip_cons_cons, List.flatMap_cons, List.nil_append]
      exact lines_agree n t

private theorem inner_push {α β : Type} (G : α → β × Array Nat → Id (ForInStep (β × Array Nat))) (v : Nat)
    (g : α → β → β) (h : ∀ a st, G a st = pure (ForInStep.yield (g a st.1, st.2.push v))) :
    ∀ (l : List α) (st : β × Array Nat), (forIn (m := Id) l st G).2.toList = st.2.toList ++ List.replicate l.length v
  | [], st => by simp; rfl
  | a :: l, st => by
    rw [List.forIn_cons, h a st, pure_bind]
    simp only
    rw [inner_push G v g h l]
    simp [List.replicate_succ, List.append_assoc]

private abbrev PSt := Option (Option (ByteArray × Array Nat)) × ByteArray × Array Nat × Nat

private theorem outer (F : Run.Req → PSt → Id (ForInStep PSt))
    (hF : ∀ x lb (pidx : Array Nat) np, F x (none, lb, pidx, np) = pure (ForInStep.done (some none, lb, pidx, np)) ∨
      ∃ (lb' : ByteArray) (pidx' : Array Nat), F x (none, lb, pidx, np) =
          pure (ForInStep.yield (none, lb', pidx', if ruledL x = true then np + 1 else np)) ∧
        pidx'.toList = pidx.toList ++ (if ruledL x = true then List.replicate x.ra.lines.length np else [])) :
    ∀ (l : List Run.Req) lb (pidx : Array Nat) np,
      (forIn (m := Id) l (none, lb, pidx, np) F).1 = some none ∨
      ((forIn (m := Id) l (none, lb, pidx, np) F).1 = none ∧
        (forIn (m := Id) l (none, lb, pidx, np) F).2.2.1.toList = pidx.toList ++ linesNum np l)
  | [], lb, pidx, np => Or.inr ⟨rfl, by simp only [linesNum, List.append_nil]; rfl⟩
  | x :: l, lb, pidx, np => by
    rcases hF x lb pidx np with h | ⟨lb', pidx', h, hp⟩
    · left; rw [List.forIn_cons, h]; rfl
    · rw [List.forIn_cons, h, pure_bind]
      dsimp only
      rcases outer F hF l lb' pidx' _ with h2 | ⟨h2, h3⟩
      · exact Or.inl h2
      · refine Or.inr ⟨h2, ?_⟩
        rw [h3, hp]
        by_cases hr : ruledL x = true
        · simp [hr, linesNum, List.append_assoc]
        · simp [hr, linesNum]

private theorem from_res (F : Run.Req → PSt → Id (ForInStep PSt))
    (hF : ∀ x lb (pidx : Array Nat) np, F x (none, lb, pidx, np) = pure (ForInStep.done (some none, lb, pidx, np)) ∨
      ∃ (lb' : ByteArray) (pidx' : Array Nat), F x (none, lb, pidx, np) =
          pure (ForInStep.yield (none, lb', pidx', if ruledL x = true then np + 1 else np)) ∧
        pidx'.toList = pidx.toList ++ (if ruledL x = true then List.replicate x.ra.lines.length np else []))
    (l : List Run.Req) (lb0 : ByteArray) (p0 : Array Nat) (res : PSt)
    (hres : forIn (m := Id) l ((none, lb0, p0, 0) : PSt) F = res) :
    res.1 = some none ∨ (res.1 = none ∧ res.2.2.1.toList = p0.toList ++ linesNum 0 l) := by
  subst hres; exact outer F hF l lb0 p0 0

/-- The engine's line numbering (`Hist.payLines`), when it gives lines: `linesNum 0` over the kept requests. -/
theorem payLines_pidx (reqs : Array Run.Req) (nb : Nat) (lb : ByteArray) (pidx : Array Nat)
    (h : BlindLedger.Gate.Engine3.Hist.payLines reqs nb = some (lb, pidx)) : pidx.toList = linesNum 0 reqs.toList := by
  unfold BlindLedger.Gate.Engine3.Hist.payLines at h
  simp only [Id.run, ← Array.forIn_toList] at h
  generalize hres : forIn (m := Id) reqs.toList _ _ = res at h
  have key := from_res _ ?hF _ _ _ _ hres
  · simp only [bind] at h
    rcases key with h1 | ⟨h1, h2⟩
    · rw [h1] at h; exact absurd h (by simp [pure])
    · rw [h1] at h
      simp only [pure, Option.some.injEq, Prod.mk.injEq] at h
      rw [← h.2, h2]
      simp
  · intro x lb pidx np
    have e : (x.ra.flow.ruled && !x.ra.lines.isEmpty) = ruledL x := rfl
    by_cases hr : ruledL x = true
    · simp only [e, hr, if_true]
      split
      · rename_i pf _
        right
        refine ⟨_, _, rfl, ?_⟩
        rw [inner_push _ np (fun ln b => BlindLedger.Gate.Engine3.ReadB.storeLine b ln pf) (fun _ _ => rfl)]
      · left; rfl
    · simp only [e, hr, Bool.false_eq_true, if_false]
      right
      exact ⟨_, _, rfl, by simp⟩

/-- The checker's copy (`VMirror.payLinesV`), the same. -/
theorem payLinesV_pidx (reqs : Array Run.Req) (nb : Nat) (lb : ByteArray) (pidx : Array Nat)
    (h : BlindLedger.Gate.Engine3.VMirror.payLinesV reqs nb = some (lb, pidx)) :
    pidx.toList = linesNum 0 reqs.toList := by
  unfold BlindLedger.Gate.Engine3.VMirror.payLinesV at h
  simp only [Id.run, ← Array.forIn_toList] at h
  generalize hres : forIn (m := Id) reqs.toList _ _ = res at h
  have key := from_res _ ?hF _ _ _ _ hres
  · simp only [bind] at h
    rcases key with h1 | ⟨h1, h2⟩
    · rw [h1] at h; exact absurd h (by simp [pure])
    · rw [h1] at h
      simp only [pure, Option.some.injEq, Prod.mk.injEq] at h
      rw [← h.2, h2]
      simp
  · intro x lb pidx np
    have e : (x.ra.flow.ruled && !x.ra.lines.isEmpty) = ruledL x := rfl
    by_cases hr : ruledL x = true
    · simp only [e, hr, if_true]
      split
      · rename_i pf _
        right
        refine ⟨_, _, rfl, ?_⟩
        rw [inner_push _ np (fun ln b => BlindLedger.Gate.Engine3.ReadB.storeLine b ln pf) (fun _ _ => rfl)]
      · left; rfl
    · simp only [e, hr, Bool.false_eq_true, if_false]
      right
      exact ⟨_, _, rfl, by simp⟩

/-! ## The two numberings agree -/

/-- The kept requests as `stepH` builds them: covered and fitting, in request order. -/
private theorem kept_toList (reqs : Array Run.Req) (covR unfR : Array Bool) :
    ((reqs.zip (covR.zip unfR)).filterMap fun (x, c, u) => if (c && !u) = true then some x else none).toList =
      (reqs.toList.zip (covR.toList.zip unfR.toList)).filterMap
        fun (x, c, u) => if (c && !u) = true then some x else none := by
  simp [Array.toList_zip]

/-- The engine's two numberings agree: the line numbers `Hist.payLines` gives the kept requests are, line for line,
    the numbers `Run.payIdx` gives their requests. -/
theorem payIdx_lines (reqs : Array Run.Req) (covR unfR : Array Bool) (hc : covR.size = reqs.size)
    (hu : unfR.size = reqs.size) (nb : Nat) (lb : ByteArray) (pidx : Array Nat)
    (h : BlindLedger.Gate.Engine3.Hist.payLines
      ((reqs.zip (covR.zip unfR)).filterMap fun (x, c, u) => if (c && !u) = true then some x else none) nb =
        some (lb, pidx)) :
    let z := reqs.toList.zip (covR.toList.zip unfR.toList)
    pidx.toList = (z.zip (BlindLedger.Gate.Engine3.Run.payIdx reqs covR unfR).1.toList).flatMap fun (e, o) =>
      match o with
      | some p => List.replicate e.1.ra.lines.length p
      | none => [] := by
  intro z
  rw [payLines_pidx _ _ _ _ h, kept_toList, lines_agree, payIdx_spec reqs covR unfR hc hu]

/-- The checker's two numberings agree, the same. -/
theorem payIdxC_lines (reqs : Array Run.Req) (covR unfR : Array Bool) (hc : covR.size = reqs.size)
    (hu : unfR.size = reqs.size) (nb : Nat) (lb : ByteArray) (pidx : Array Nat)
    (h : BlindLedger.Gate.Engine3.VMirror.payLinesV
      ((reqs.zip (covR.zip unfR)).filterMap fun (x, c, u) => if (c && !u) = true then some x else none) nb =
        some (lb, pidx)) :
    let z := reqs.toList.zip (covR.toList.zip unfR.toList)
    pidx.toList = (z.zip (BlindLedger.Gate.Engine3.Verify.payIdxC reqs covR unfR).1.toList).flatMap fun (e, o) =>
      match o with
      | some p => List.replicate e.1.ra.lines.length p
      | none => [] := by
  intro z
  rw [payLinesV_pidx _ _ _ _ h, kept_toList, lines_agree, payIdxC_spec reqs covR unfR hc hu]

/-- `admB`'s cover and fit flags have one entry per request, so `payIdx_lines`' size hypotheses hold for the arrays
    `stepH` and `stepC` pass (`(ab.cov, ab.unf)` of `admB adm reqs`). -/
theorem admB_sizes (adm : Except String Run.Admitted) (reqs : Array Run.Req) :
    (BlindLedger.Gate.Engine3.Run.admB adm reqs).cov.size = reqs.size ∧
      (BlindLedger.Gate.Engine3.Run.admB adm reqs).unf.size = reqs.size := by
  have hc : (BlindLedger.Gate.Engine3.Run.covB adm reqs).size = reqs.size := by
    unfold BlindLedger.Gate.Engine3.Run.covB
    split <;> simp
  refine ⟨hc, ?_⟩
  simp [BlindLedger.Gate.Engine3.Run.admB, hc]

/-- `payIdx_lines` on the arrays `stepH` passes: `admB`'s cover and fit flags. -/
theorem payIdx_lines_admB (adm : Except String Run.Admitted) (reqs : Array Run.Req) (nb : Nat) (lb : ByteArray)
    (pidx : Array Nat)
    (h : BlindLedger.Gate.Engine3.Hist.payLines
      ((reqs.zip ((BlindLedger.Gate.Engine3.Run.admB adm reqs).cov.zip (BlindLedger.Gate.Engine3.Run.admB adm reqs).unf)).filterMap
        fun (x, c, u) => if (c && !u) = true then some x else none) nb = some (lb, pidx)) :
    let ab := BlindLedger.Gate.Engine3.Run.admB adm reqs
    let z := reqs.toList.zip (ab.cov.toList.zip ab.unf.toList)
    pidx.toList = (z.zip (BlindLedger.Gate.Engine3.Run.payIdx reqs ab.cov ab.unf).1.toList).flatMap fun (e, o) =>
      match o with
      | some p => List.replicate e.1.ra.lines.length p
      | none => [] :=
  payIdx_lines reqs _ _ (admB_sizes adm reqs).1 (admB_sizes adm reqs).2 nb lb pidx h

/-- `payIdxC_lines` on the arrays `stepC` passes, the same. -/
theorem payIdxC_lines_admB (adm : Except String Run.Admitted) (reqs : Array Run.Req) (nb : Nat) (lb : ByteArray)
    (pidx : Array Nat)
    (h : BlindLedger.Gate.Engine3.VMirror.payLinesV
      ((reqs.zip ((BlindLedger.Gate.Engine3.Run.admB adm reqs).cov.zip (BlindLedger.Gate.Engine3.Run.admB adm reqs).unf)).filterMap
        fun (x, c, u) => if (c && !u) = true then some x else none) nb = some (lb, pidx)) :
    let ab := BlindLedger.Gate.Engine3.Run.admB adm reqs
    let z := reqs.toList.zip (ab.cov.toList.zip ab.unf.toList)
    pidx.toList = (z.zip (BlindLedger.Gate.Engine3.Verify.payIdxC reqs ab.cov ab.unf).1.toList).flatMap fun (e, o) =>
      match o with
      | some p => List.replicate e.1.ra.lines.length p
      | none => [] :=
  payIdxC_lines reqs _ _ (admB_sizes adm reqs).1 (admB_sizes adm reqs).2 nb lb pidx h

/-! ## The layout's payments -/

private abbrev ASt := Array Bool × Array Bool × Array (Option UInt32) × Array (Option UInt32) × Array LineIn

private theorem lines_loop (pidx : Array Nat) (F : Nat → ASt → Id (ForInStep ASt))
    (hF : ∀ i (st : ASt), ∃ (a b : Array Bool) (c d : Array (Option UInt32)) (e : LineIn),
      F i st = pure (ForInStep.yield (a, b, c, d, st.2.2.2.2.push e)) ∧ e.pay = pidx[i]!) :
    ∀ (l : List Nat) (st : ASt),
      (forIn (m := Id) l st F).2.2.2.2.toList.map (·.pay) = st.2.2.2.2.toList.map (·.pay) ++ l.map (pidx[·]!)
  | [], st => by simp; rfl
  | i :: l, st => by
    obtain ⟨a, b, c, d, e, h, he⟩ := hF i st
    rw [List.forIn_cons, h, pure_bind]
    simp only
    rw [lines_loop pidx F hF l]
    simp [he]

/-- `assemble` gives line `i` the payment `pidx[i]!`, for every line of the batch, in order. -/
theorem assemble_pay (hr hu : BlindLedger.Gate.Flat.Head) (today : Nat) (byp lim : List (Nat × Nat))
    (fx : BlindLedger.Gate.Engine3.FeedsX) (f : List Nat) (redo : Std.HashSet BlindLedger.Gate.Engine3.W9)
    (req : Array BlindLedger.Gate.Engine3.RowX) (pidx : Array Nat) (idx : Array Nat)
    (uIdOf : BlindLedger.Gate.Engine3.RowX → Nat) (hu1 hr1 : Array BlindLedger.Gate.Engine3.Hit)
    (relP : Array BlindLedger.Gate.Engine3.RowX) (relSeq : Array Nat) (unrP : Array BlindLedger.Gate.Engine3.RowX)
    (unrSeq : Array Nat) :
    (BlindLedger.Gate.Engine3.assemble hr hu today byp lim fx f redo req pidx idx uIdOf hu1 hr1 relP relSeq unrP
      unrSeq).lines.toList.map (·.pay) = (List.range req.size).map (pidx[·]!) := by
  unfold BlindLedger.Gate.Engine3.assemble
  simp only [Id.run, bind, pure]
  rw [Std.Legacy.Range.forIn_eq_forIn_range']
  rw [lines_loop pidx _ ?_]
  · simp [List.range_eq_range']
  · intro i st
    split
    · exact ⟨_, _, _, _, _, rfl, rfl⟩
    · exact ⟨_, _, _, _, _, rfl, rfl⟩

/-! ## Every layout payment is below `np` -/

/-- Every line number laid out from `numFrom 0 z` is below the count `cntFrom 0 z`. -/
private theorem pidx_lt (z : List (Run.Req × Bool × Bool)) (pidx : Array Nat)
    (hl : pidx.toList = (z.zip (numFrom 0 z)).flatMap fun (e, o) => match o with
      | some p => List.replicate e.1.ra.lines.length p
      | none => []) :
    ∀ q ∈ pidx.toList, q < cntFrom 0 z := by
  intro q hq
  rw [hl, List.mem_flatMap] at hq
  obtain ⟨⟨e, o⟩, hm, hq⟩ := hq
  cases o with
  | none => simp at hq
  | some p =>
    simp only [List.mem_replicate] at hq
    obtain ⟨-, rfl⟩ := hq
    exact (numFrom_lt 0 z q (List.of_mem_zip hm).2).2

/-- `assemble` on numbers below `np`, with a number for each line, gives every line a payment below `np`. -/
private theorem assemble_lt (hr hu : BlindLedger.Gate.Flat.Head) (today : Nat) (byp lim : List (Nat × Nat))
    (fx : BlindLedger.Gate.Engine3.FeedsX) (f : List Nat) (redo : Std.HashSet BlindLedger.Gate.Engine3.W9)
    (req : Array BlindLedger.Gate.Engine3.RowX) (pidx : Array Nat) (idx : Array Nat)
    (uIdOf : BlindLedger.Gate.Engine3.RowX → Nat) (hu1 hr1 : Array BlindLedger.Gate.Engine3.Hit)
    (relP : Array BlindLedger.Gate.Engine3.RowX) (relSeq : Array Nat) (unrP : Array BlindLedger.Gate.Engine3.RowX)
    (unrSeq : Array Nat) (np : Nat) (hq : ∀ q ∈ pidx.toList, q < np) (hs : req.size ≤ pidx.size) :
    ∀ y ∈ (BlindLedger.Gate.Engine3.assemble hr hu today byp lim fx f redo req pidx idx uIdOf hu1 hr1 relP relSeq
      unrP unrSeq).lines.toList, y.pay < np := by
  intro y hy
  have hm : y.pay ∈ (List.range req.size).map (pidx[·]!) := by
    rw [← assemble_pay hr hu today byp lim fx f redo req pidx idx uIdOf hu1 hr1 relP relSeq unrP unrSeq]
    exact List.mem_map.mpr ⟨y, hy, rfl⟩
  obtain ⟨i, hi, hpi⟩ := List.mem_map.mp hm
  rw [List.mem_range] at hi
  have hi' : i < pidx.size := Nat.lt_of_lt_of_le hi hs
  rw [← hpi, getElem!_pos pidx i hi']
  exact hq _ (Array.getElem_mem_toList hi')

/-- The engine's layout payments are below `np`: when `Hist.payLines` numbers the requests `stepH` keeps (on `admB`'s
    flags) and `assemble` has a number for each line (`req.size ≤ pidx.size`), every line's payment is below the count `Run.payIdx`
    gives (`numFrom_lt`, `payIdx_lines_admB`, `assemble_pay`). -/
theorem assemble_pay_lt (adm : Except String Run.Admitted) (reqs : Array Run.Req) (nb : Nat) (lb : ByteArray)
    (pidx : Array Nat)
    (h : BlindLedger.Gate.Engine3.Hist.payLines
      ((reqs.zip ((BlindLedger.Gate.Engine3.Run.admB adm reqs).cov.zip (BlindLedger.Gate.Engine3.Run.admB adm reqs).unf)).filterMap
        fun (x, c, u) => if (c && !u) = true then some x else none) nb = some (lb, pidx))
    (hr hu : BlindLedger.Gate.Flat.Head) (today : Nat) (byp lim : List (Nat × Nat))
    (fx : BlindLedger.Gate.Engine3.FeedsX) (f : List Nat) (redo : Std.HashSet BlindLedger.Gate.Engine3.W9)
    (req : Array BlindLedger.Gate.Engine3.RowX) (idx : Array Nat)
    (uIdOf : BlindLedger.Gate.Engine3.RowX → Nat) (hu1 hr1 : Array BlindLedger.Gate.Engine3.Hit)
    (relP : Array BlindLedger.Gate.Engine3.RowX) (relSeq : Array Nat) (unrP : Array BlindLedger.Gate.Engine3.RowX)
    (unrSeq : Array Nat) (hs : req.size ≤ pidx.size) :
    let ab := BlindLedger.Gate.Engine3.Run.admB adm reqs
    ∀ y ∈ (BlindLedger.Gate.Engine3.assemble hr hu today byp lim fx f redo req pidx idx uIdOf hu1 hr1 relP relSeq
      unrP unrSeq).lines.toList, y.pay < (BlindLedger.Gate.Engine3.Run.payIdx reqs ab.cov ab.unf).2 := by
  intro ab
  have hsp := payIdx_spec reqs ab.cov ab.unf (admB_sizes adm reqs).1 (admB_sizes adm reqs).2
  have hl := payIdx_lines_admB adm reqs nb lb pidx h
  dsimp only at hsp hl
  rw [hsp] at hl ⊢
  exact assemble_lt hr hu today byp lim fx f redo req pidx idx uIdOf hu1 hr1 relP relSeq unrP unrSeq _
    (pidx_lt _ pidx hl) hs

/-- The checker's copy (`VMirror.payLinesV`, `Verify.payIdxC`), the same. -/
theorem assemble_payC_lt (adm : Except String Run.Admitted) (reqs : Array Run.Req) (nb : Nat) (lb : ByteArray)
    (pidx : Array Nat)
    (h : BlindLedger.Gate.Engine3.VMirror.payLinesV
      ((reqs.zip ((BlindLedger.Gate.Engine3.Run.admB adm reqs).cov.zip (BlindLedger.Gate.Engine3.Run.admB adm reqs).unf)).filterMap
        fun (x, c, u) => if (c && !u) = true then some x else none) nb = some (lb, pidx))
    (hr hu : BlindLedger.Gate.Flat.Head) (today : Nat) (byp lim : List (Nat × Nat))
    (fx : BlindLedger.Gate.Engine3.FeedsX) (f : List Nat) (redo : Std.HashSet BlindLedger.Gate.Engine3.W9)
    (req : Array BlindLedger.Gate.Engine3.RowX) (idx : Array Nat)
    (uIdOf : BlindLedger.Gate.Engine3.RowX → Nat) (hu1 hr1 : Array BlindLedger.Gate.Engine3.Hit)
    (relP : Array BlindLedger.Gate.Engine3.RowX) (relSeq : Array Nat) (unrP : Array BlindLedger.Gate.Engine3.RowX)
    (unrSeq : Array Nat) (hs : req.size ≤ pidx.size) :
    let ab := BlindLedger.Gate.Engine3.Run.admB adm reqs
    ∀ y ∈ (BlindLedger.Gate.Engine3.assemble hr hu today byp lim fx f redo req pidx idx uIdOf hu1 hr1 relP relSeq
      unrP unrSeq).lines.toList, y.pay < (BlindLedger.Gate.Engine3.Verify.payIdxC reqs ab.cov ab.unf).2 := by
  intro ab
  have hsp := payIdxC_spec reqs ab.cov ab.unf (admB_sizes adm reqs).1 (admB_sizes adm reqs).2
  have hl := payIdxC_lines_admB adm reqs nb lb pidx h
  dsimp only at hsp hl
  rw [hsp] at hl ⊢
  exact assemble_lt hr hu today byp lim fx f redo req pidx idx uIdOf hu1 hr1 relP relSeq unrP unrSeq _
    (pidx_lt _ pidx hl) hs

end BlindLedger.Gate.Flat.PayNum
