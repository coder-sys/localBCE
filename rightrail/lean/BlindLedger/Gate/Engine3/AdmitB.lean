import BlindLedger.Gate.Engine3.DecodeB
import BlindLedger.Gate.Engine3.Step

/-! What admission fixes for each request of a batch, read from the request bytes (`DecodeB`), once per batch.  All requests of
    a batch share one tenant and program (`DecodeB.authB` refuses a frame otherwise), so a grant entry is looked up once per
    flow, not once per request; a request's fit is read from its identifier lengths (`DecodeB.lineFits`), with no number built.
    `specAdm` is the same from the request's `Line`s (`Fast.reqOfFast`), as `StepH` computed it before.
    Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Engine3.Run

open BlindLedger.Gate BlindLedger.Gate.Rules BlindLedger.Gate.Frame.Fast

/-- Spec checks run on batch 1 and every this-many-th batch: `RR_E3_SPEC` (default 64; the tests set 1). -/
initialize specEvery : Nat ← do
  pure (max 1 (((← IO.getEnv "RR_E3_SPEC").bind (·.toNat?)).getD 64))

def specDue (batch : Nat) : BaseIO Bool := pure (batch % specEvery == 1 % specEvery)

/-- The last admission and the inputs it was made from. -/
abbrev AdmKey := (Bytes × Keyset.Ratchet × Nat × Nat × Option Nat × Option Nat × Bytes) × (Option Bytes × Option Bytes × List (Nat × Bytes))

initialize admLast : IO.Ref (Option (AdmKey × Except String Run.Admitted)) ← IO.mkRef none

/-- `Run.admit` with `mlDsaMemo`, kept for the next batch when its inputs are the same: with no bypass in the frame it reads
    the requests only for the first one's tenant, so a batch of the same authority record (pin, ratchet, stored floor, day,
    asserted floor, asserted key-set floor, tenant, key set, its steps and grant) is admitted once, not once per batch (decoding the key set and the
    grant and counting their signatures was 12 us a line).  `admitB_eq` covers it; the sampled spec check recomputes it. -/
def admitC (pin : Bytes) (rat : Keyset.Ratchet) (stored : Nat) (st : Run.St) : IO (Except String Run.Admitted) := do
  match st.reqs[0]?, st.byps with
  | some e0, [] =>
    let k := ((pin, rat, stored, st.today, st.floorIn, st.kfloorIn, e0.r.tenantId), (st.keyset, st.grant, st.ksteps))
    if let some (k', r) := ← admLast.get then
      if k' == k then return r
    let r := Run.admit mlDsaMemo pin rat stored st
    admLast.set (some (k, r))
    pure r
  | _, _ => pure (Run.admit mlDsaMemo pin rat stored st)

/-- The batch's coverage, which requests have a line that does not fit, and where each kept line sits. -/
structure AdmB where
  cov : Array Bool
  /-- Every line of the request fits the store widths. -/
  fit : Array Bool
  unf : Array Bool
  /-- For each line of a covered request that fits: its position in the batch's lines (those of covered requests, in order). -/
  bPos : Array Nat

def flowIx : WireFlow → Nat
  | .FFS_CYCLE => 0
  | .FFS_CLAIM => 1
  | .CAP_820 => 2
  | .SDP => 3
  | .PLAN_PAY => 4

/-- The lines `Run.Req.ls` holds: those of a flow with rules. -/
def nLines (x : Run.Req) : Nat := if x.ra.flow.ruled then x.ra.lines.length else 0

/-- Whether a grant entry covers each request: one lookup per flow, for the batch's program. -/
def covB (adm : Except String Run.Admitted) (reqs : Array Run.Req) : Array Bool :=
  match adm, reqs[0]? with
  | .ok a, some e0 =>
    let c := flows.toArray.map fun f => (Authority.entryFor a.grant e0.ra.programId.toList f).isSome
    reqs.map fun x => c[flowIx x.ra.flow]!
  | _, _ => reqs.map fun _ => false

/-- Each request's grant entry, looked up once per flow like `covB` (`entriesOf` is the per-request form the spec path uses). -/
def entsB (adm : Except String Run.Admitted) (reqs : Array Run.Req) : Array (Option Authority.Entry) :=
  match adm, reqs[0]? with
  | .ok a, some e0 =>
    let c := flows.toArray.map fun f => Authority.entryFor a.grant e0.ra.programId.toList f
    reqs.map fun x => c[flowIx x.ra.flow]!
  | _, _ => reqs.map fun _ => none

/-- `Run.limOf` from each request's entry (`entsB`): the (payment number, holds mask) of each request whose entry is
    HOLD-level. -/
def limB (reqs : Array Run.Req) (ens : Array (Option Authority.Entry)) : List (Nat × Nat) :=
  (reqs.zip ens).toList.filterMap fun (x, en) => en.bind fun en => if en.authority == .HOLD then some (x.q, en.holds) else none

/-- A `limB` entry comes only from a HOLD-level entry (as `Rules.Run.limOf_sound`): payment `p` gets holds mask `m` only
    when a request for payment `p` is paired with a HOLD-level entry whose holds mask is `m`. -/
theorem limB_sound {reqs : Array Run.Req} {ens : Array (Option Authority.Entry)} {p m : Nat}
    (h : (p, m) ∈ limB reqs ens) :
    ∃ x en, (x, some en) ∈ (reqs.zip ens).toList ∧ x.q = p ∧ en.authority = .HOLD ∧ en.holds = m := by
  obtain ⟨⟨x, en⟩, hx, hf⟩ := List.mem_filterMap.mp h
  cases en with
  | none => simp at hf
  | some en =>
    simp only [Option.bind_some] at hf
    split at hf
    · rename_i hh
      simp only [Option.some.injEq, Prod.mk.injEq] at hf
      exact ⟨x, en, hx, hf.1, beq_iff_eq.mp hh, hf.2⟩
    · simp at hf

/-- The positions of the lines `Hist.read` takes, given which requests are covered and which are unfit. -/
def posOf (reqs : Array Run.Req) (cov unf : Array Bool) : Array Nat := Id.run do
  let mut bPos : Array Nat := #[]
  let mut n := 0
  for x in reqs, c in cov, u in unf do
    if c then
      if !u then
        for _ in [0:nLines x] do
          bPos := bPos.push n
          n := n + 1
      else n := n + nLines x
  pure bPos

def admB (adm : Except String Run.Admitted) (reqs : Array Run.Req) : AdmB :=
  let cov := covB adm reqs
  let fit := reqs.map (reqFits ·.ra)
  let unf := (cov.zip fit).map fun (c, f) => c && !f
  ⟨cov, fit, unf, posOf reqs cov unf⟩

/-- The same from the requests' `Line`s: what `StepH` computed before the byte form.  `reqs` are `reqOfFast`'s. -/
def specAdm (adm : Except String Run.Admitted) (reqs : Array Run.Req) : AdmB :=
  let fitsV3 (l : Line) : Bool := fitsS l && fitsLine2 l
  let cov : Array Bool := reqs.map fun x => match adm with
    | .ok a => (Authority.entryFor a.grant x.ra.programId.toList x.ra.flow).isSome
    | .error _ => false
  let fit : Array Bool := reqs.map fun x => x.ls.all fitsV3
  let unf : Array Bool := (cov.zip fit).map fun (c, f) => c && !f
  let bPos := Id.run do
    let mut bPos : Array Nat := #[]
    let mut n := 0
    for x in reqs, c in cov, u in unf do
      if c then
        if u then n := n + x.ls.length
        else
          for _ in x.ls do
            bPos := bPos.push n
            n := n + 1
    pure bPos
  ⟨cov, fit, unf, bPos⟩

/-- Whether two admission results agree where the engine reads them. -/
def sameAdm (a b : Except String Run.Admitted) : Bool :=
  match a, b with
  | .error x, .error y => x == y
  | .ok x, .ok y =>
    x.grant.id == y.grant.id && x.grant.serial == y.grant.serial && x.ksDigest == y.ksDigest && x.ratchet == y.ratchet && x.notes == y.notes &&
      x.byps.map (fun z => (z.id, z.request, z.program, z.payment, z.overrides)) ==
        y.byps.map (fun z => (z.id, z.request, z.program, z.payment, z.overrides))
  | _, _ => false

/-- The byte decoder's requests against the reader's (`reqOfFast`) on the same bytes: the request, its bytes, and its
    payment number from the payment key. -/
def sameReqs (xs rs : Array Run.Req) : Bool :=
  xs.size == rs.size && (xs.zip rs).all fun (x, r) =>
    x.x == r.x && r.q == idNatA (payKeyOf x.ra) && x.ra.tenantId == r.ra.tenantId && x.ra.programId == r.ra.programId &&
      x.ra.flow == r.ra.flow && x.ra.commandKey == r.ra.commandKey && x.ra.paymentId == r.ra.paymentId &&
      x.ra.memberKey == r.ra.memberKey && x.ra.payeeRef == r.ra.payeeRef && x.ra.amountCents == r.ra.amountCents &&
      x.ra.period == r.ra.period && x.ra.lines == r.ra.lines && x.ra.evidenceRefs == r.ra.evidenceRefs

/-! Why `admB` is `specAdm`: a line's fit read from its identifier ends (`lineFits`) is the fit of the line the spec reader
    parses; the coverage table holds the one grant lookup of each flow; the two position loops take the same steps. -/

private theorem shr_eq_zero (n w : Nat) : ((n >>> (8 * w) == 0) = true) = (n < 256 ^ w) := by
  rw [Nat.shiftRight_eq_div_pow, Nat.pow_mul]
  simp only [show (2 : Nat) ^ 8 = 256 from rfl]
  have : 0 < 256 ^ w := Nat.pow_pos_iff.mpr (Or.inl (by omega))
  simp only [beq_iff_eq]
  exact propext (Nat.div_eq_zero_iff_lt this)

private theorem isN33_idNat (xs : Bytes) (h : xs.length = 32) : isN33 (idNat xs) = true := by
  unfold isN33 idNat
  rw [beNat_cons, h]
  have h1 := Keyset.beNat_lt_pow 32 xs h
  simp only [show (1 : UInt8).toNat = 1 from rfl, Nat.one_mul, beq_iff_eq, show (2 : Nat) ^ 256 = 256 ^ 32 from rfl]
  rw [Nat.add_comm, Nat.add_div_right _ (by decide), Nat.div_eq_of_lt h1]

/-- `decide p = true` is `p` for any instance (simp's `decide_eq_true_eq` wants the one it finds itself). -/
private theorem decide_true_eq {p : Prop} {i : Decidable p} : (@decide p i = true) = p := by
  cases i <;> simp [decide, *]

/-- The fit `lineFits` reads from a line's bytes is the fit of the line the spec reader parses from them, when `pk` is
    the length of the payment key that numbers it (`pay`). -/
private theorem lineFits_parse (l : Bytes) (w : WireLineFull) (pay pk : Nat) (L : Line)
    (hp : parse pLineFull maxLineBytes l = some w) (hL : lineOf pay w = some L)
    (hpay : pay < 256 ^ 72 ↔ pk < 72) :
    lineFits l.toByteArray 0 l.toByteArray.size pk = (fitsS L && fitsLine2 L) := by
  have hb : l.toByteArray.toList = l := Flat.Bin.toList_toByteArray l
  have hn : l.toByteArray.size = l.length := by simp
  generalize hB : l.toByteArray = b at hb hn
  have h0 := parse_some hp
  have hs0 : l = (b.toList.take b.size).drop 0 := by simp [hb, hn]
  have hl : b.size ≤ b.size := Nat.le_refl _
  have hsz : b.toList.length = b.size := (Flat.Bin.size_eq_length' b).symm
  have hmk : memberKeyBytes = 32 := rfl
  unfold lineFits
  rw [Bool.eq_iff_iff]
  simp only [Bool.and_eq_true, decide_true_eq, fitsS, fitsLine2, Line.fields, List.all_cons, List.all_nil, Bool.and_true]
  simp only [show (0 : Nat) + 1 = 1 from rfl, show (0 : Nat) + 3 = 3 from rfl]
  rw [hs0] at h0
  simp only [pLineFull, StateT.run_bind] at h0
  obtain ⟨⟨fl, m1⟩, h1, h0⟩ := obind_some h0
  simp only [tag, StateT.run_bind] at h1
  obtain ⟨⟨t, m1'⟩, ht, h1⟩ := obind_some h1
  obtain ⟨t1, rfl, t3, t4, rfl⟩ := nat_step hl (Nat.zero_le _) ht
  have hm1 : m1 = (b.toList.take b.size).drop (0 + 1) := by
    split at h1
    · simp only [StateT.run_pure] at h1; cases h1; rfl
    · cases h1
  subst hm1
  obtain ⟨⟨lineId, m2⟩, h2, h0⟩ := obind_some h0
  obtain ⟨i1, rfl, rfl⟩ := ident_step hl h2
  have bi := identEnd_bounds i1
  simp only [show (0 : Nat) + 1 = 1 from rfl, show (1 : Nat) + 2 = 3 from rfl] at *
  generalize hie : identEnd b 1 b.size = ie at *
  obtain ⟨⟨mem, m3⟩, h3, h0⟩ := obind_some h0
  obtain ⟨i3, rfl, rfl⟩ := take_step hl bi.2 h3
  simp only [hmk] at *
  obtain ⟨⟨payee, m4⟩, h4, h0⟩ := obind_some h0
  obtain ⟨i4, rfl, rfl⟩ := ident_step hl h4
  have bp := identEnd_bounds i4
  generalize hpe : identEnd b (ie + 32) b.size = pe at *
  obtain ⟨⟨rend, m5⟩, h5, h0⟩ := obind_some h0
  obtain ⟨i5, rfl, rfl⟩ := ident_step hl h5
  have br := identEnd_bounds i5
  generalize hre : identEnd b pe b.size = re at *
  obtain ⟨⟨date, m6⟩, h6, h0⟩ := obind_some h0
  obtain ⟨i6, rfl, -, -, rfl⟩ := nat_step hl br.2 h6
  obtain ⟨⟨proc, m7⟩, h7, h0⟩ := obind_some h0
  obtain ⟨i7, rfl, rfl⟩ := ident_step hl h7
  have bo := identEnd_bounds i7
  generalize hoe : identEnd b (re + 4) b.size = oe at *
  obtain ⟨⟨units, m8⟩, h8, h0⟩ := obind_some h0
  obtain ⟨i8, rfl, -, -, rfl⟩ := nat_step hl bo.2 h8
  obtain ⟨⟨cents, m9⟩, h9, h0⟩ := obind_some h0
  obtain ⟨i9, rfl, -, c4, rfl⟩ := nat_step hl i8 h9
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h0
  obtain ⟨rfl, -⟩ := h0
  simp only [lineOf, Option.map_eq_some_iff] at hL
  obtain ⟨f, hf, rfl⟩ := hL
  have l1 : (List.take (ie - 3) (List.drop 3 b.toList)).length = ie - 3 := by simp; omega
  have l2 : (List.take 32 (List.drop ie b.toList)).length = 32 := by simp; omega
  have l3 : (List.take (pe - (ie + 32 + 2)) (List.drop (ie + 32 + 2) b.toList)).length = pe - (ie + 32 + 2) := by simp; omega
  have l4 : (List.take (re - (pe + 2)) (List.drop (pe + 2) b.toList)).length = re - (pe + 2) := by simp; omega
  have l5 : (List.take (oe - (re + 4 + 2)) (List.drop (re + 4 + 2) b.toList)).length = oe - (re + 4 + 2) := by simp; omega
  have d4 : beNat (List.take 4 (List.drop re b.toList)) < 256 ^ 4 := Keyset.beNat_lt_pow 4 _ (by simp; omega)
  have u4 : beNat (List.take 4 (List.drop oe b.toList)) < 256 ^ 4 := Keyset.beNat_lt_pow 4 _ (by simp; omega)
  have c8 : beNat (List.take 8 (List.drop (oe + 4) b.toList)) < 256 ^ 8 := Keyset.beNat_lt_pow 8 _ (by simp; omega)
  have hft : (f.tag < 256 ^ 1) := by cases f <;> decide
  have h232 : (2 : Nat) ^ 32 = 256 ^ 4 := rfl
  have h264 : (2 : Nat) ^ 64 = 256 ^ 8 := rfl
  simp only [shr_eq_zero, idNat_lt, l1, l2, l3, l4, l5, isN33_idNat _ l2, h232, h264, d4, u4, c8, hft, true_and, and_true]
  simp only [idW, idWidth, payW, provW, procW]
  by_cases hq : pk < 72
  · have q1 : pay < 256 ^ 72 := hpay.mpr hq
    have q2 : pay < 256 ^ payWidth := Nat.lt_of_lt_of_le q1 (Nat.pow_le_pow_right (by decide) (by decide))
    simp only [q1, q2, true_and, and_true]
    simp only [payWidth]
    omega
  · have q1 : ¬ pay < 256 ^ 72 := fun h => hq (hpay.mp h)
    simp only [q1, false_and, and_false, iff_false, not_and]
    simp only [payWidth]
    omega

private theorem mapM_all {α β : Type} (f : α → Option β) (g : α → Bool) (h : β → Bool)
    (hfg : ∀ a b, f a = some b → g a = h b) :
    ∀ (l : List α) (ls : List β), l.mapM f = some ls → l.all g = ls.all h ∧ l.length = ls.length
  | [], ls, e => by
    simp only [List.mapM_nil, Option.pure_def, Option.some.injEq] at e
    subst e; simp
  | a :: l, ls, e => by
    cases hfa : f a with
    | none => simp [List.mapM_cons, hfa] at e
    | some b =>
      cases hl : l.mapM f with
      | none => simp [List.mapM_cons, hfa, hl] at e
      | some bs =>
        simp [List.mapM_cons, hfa, hl] at e
        subst e
        have ih := mapM_all f g h hfg l bs hl
        simp [hfg a b hfa, ih.1, ih.2]

/-- A request `Run.reqOf` reads: its fit from its line bytes is the fit of its lines, and `nLines` counts them. -/
private theorem reqOf_fit {x : ByteArray} {r : Run.Req} (h : Run.reqOf x = some r) :
    reqFits r.ra = r.ls.all (fun l => fitsS l && fitsLine2 l) ∧ nLines r = r.ls.length := by
  unfold Run.reqOf at h
  cases hm : decodeRequest x.toList with
  | none => simp [hm] at h
  | some m =>
    cases hf : m.flow.ruled with
    | false =>
      simp [hm, hf] at h
      subst h
      simp [reqFits, nLines, RequestBA.ofModel, hf]
    | true =>
      cases hl : linesOf m with
      | none => simp [hm, hf, hl] at h
      | some ls =>
        simp [hm, hf, hl] at h
        subst h
        have hpk : (payKeyOf (RequestBA.ofModel m)).size = (identField m.programId ++ identField m.paymentId).length := by
          simp [payKeyOf, RequestBA.ofModel, ByteArray.size_append, ByteArray.size_push, ByteArray.size_empty, identField,
            Keyset.natBE_length]
          omega
        unfold linesOf at hl
        have key := mapM_all _
          (fun l : Bytes => lineFits l.toByteArray 0 l.toByteArray.size (payKeyOf (RequestBA.ofModel m)).size)
          (fun l => fitsS l && fitsLine2 l)
          (fun a L hfa => by
            obtain ⟨w, hw, hL⟩ := Option.bind_eq_some_iff.mp hfa
            exact lineFits_parse a w _ _ L hw hL (by rw [hpk]; exact idNat_lt _ _)) m.lines ls hl
        constructor
        · simp only [reqFits, RequestBA.ofModel, hf, Bool.not_true, Bool.false_or, List.all_map]
          exact key.1
        · simp only [nLines, RequestBA.ofModel, hf, if_true, List.length_map]
          exact key.2

private theorem forIn_congr_list {α β σ : Type} : ∀ (l1 : List α) (l2 : List β) (_ : l1.length = l2.length) (s : σ)
    (f : α → σ → Id (ForInStep σ)) (g : β → σ → Id (ForInStep σ))
    (_ : ∀ i (h1 : i < l1.length) (h2 : i < l2.length) s, f l1[i] s = g l2[i] s), forIn l1 s f = forIn l2 s g
  | [], [], _, _, _, _, _ => rfl
  | [], _ :: _, hl, _, _, _, _ => absurd hl (by simp)
  | _ :: _, [], hl, _, _, _, _ => absurd hl (by simp)
  | a :: as, b :: bs, hl, s, f, g, h => by
    have h0 : f a s = g b s := h 0 (by simp) (by simp) s
    rw [List.forIn_cons, List.forIn_cons, h0]
    generalize g b s = r
    cases r with
    | done t => rfl
    | yield t =>
      exact forIn_congr_list as bs (by simpa using hl) t f g
        (fun i h1 h2 s => h (i + 1) (by simp only [List.length_cons]; omega) (by simp only [List.length_cons]; omega) s)

private theorem forIn_congr_arr {α β σ γ : Type} (a1 : Array α) (a2 : Array β) (hl : a1.size = a2.size) (s : σ)
    (f : α → σ → Id (ForInStep σ)) (g : β → σ → Id (ForInStep σ))
    (h : ∀ i (h1 : i < a1.size) (h2 : i < a2.size) s, f a1[i] s = g a2[i] s) (K K' : σ → Id γ) (hK : ∀ s, K s = K' s) :
    (forIn a1 s f >>= K) = (forIn a2 s g >>= K') := by
  obtain rfl : K = K' := funext hK
  rw [← Array.forIn_toList, ← Array.forIn_toList, forIn_congr_list a1.toList a2.toList (by simpa using hl) s f g
    (fun i h1 h2 s => by simpa using h i (by simpa using h1) (by simpa using h2) s)]

private theorem forIn_range_list {β σ : Type} (l : List β) (s : σ) (f : σ → Id (ForInStep σ)) :
    forIn [0:l.length] s (fun _ r => f r) = forIn l s (fun _ r => f r) := by
  rw [Std.Legacy.Range.forIn_eq_forIn_range']
  exact forIn_congr_list _ _ (by simp [Std.Legacy.Range.size]) s _ _ (fun _ _ _ _ => rfl)

private theorem ite_not_bool {α : Sort _} (u : Bool) (a b : α) :
    (if (!u) = true then a else b) = (if u = true then b else a) := by
  cases u <;> rfl

/-- `posOf` is `specAdm`'s position loop when each request's `nLines` is the number of lines `rs` holds for it. -/
private theorem posOf_eq (reqs rs : Array Run.Req) (cov unf : Array Bool) (hs : rs.size = reqs.size)
    (hn : ∀ i (h1 : i < reqs.size) (h2 : i < rs.size), nLines reqs[i] = rs[i].ls.length) :
    posOf reqs cov unf = (Id.run do
      let mut bPos : Array Nat := #[]
      let mut n := 0
      for x in rs, c in cov, u in unf do
        if c then
          if u then n := n + x.ls.length
          else
            for _ in x.ls do
              bPos := bPos.push n
              n := n + 1
      pure bPos) := by
  unfold posOf
  simp only [Id.run]
  refine forIn_congr_arr reqs rs hs.symm _ _ _ ?_ _ _ (fun _ => rfl)
  intro i h1 h2 s
  (simp only [hn i h1 h2, forIn_range_list, ite_not_bool]) <;> rfl

private theorem covFlow (g : WireFlow → Bool) (f : WireFlow) : (flows.toArray.map g)[flowIx f]! = g f := by
  have hb : flowIx f < (flows.toArray.map g).size := by cases f <;> simp [flows, flowIx]
  rw [getElem!_pos (flows.toArray.map g) (flowIx f) hb, Array.getElem_map]
  cases f <;> rfl

/-- Byte admission is the admission from the lines: for requests `reqs` (as `DecodeB` reads them, one program) and `rs`, the
    same requests as `Run.reqOf` reads them, with the same decoded request `ra`.  `hra` is needed (`admitB_eq_needs_ra`):
    admission reads each request's `ra`, which `hr` does not tie to `rs`.  It holds where `StepH` uses `admB`: `reqs` are
    `decodeB`'s, whose `ra` is the one `decodeRows` reads (`decodeB_eq`), and `rs` are `reqOfFast`'s, whose `ra` is
    `decodeRows`' too; the sampled check `sameReqs` compares every field of `ra`. -/
theorem admitB_eq (adm : Except String Run.Admitted) (reqs rs : Array Run.Req) (hs : rs.size = reqs.size)
    (hr : ∀ i (h : i < reqs.size), Run.reqOf reqs[i].x = rs[i]?)
    (hra : ∀ i (h1 : i < reqs.size) (h2 : i < rs.size), rs[i].ra = reqs[i].ra)
    (hp : ∀ x ∈ reqs, ∀ e0 ∈ reqs[0]?, x.ra.programId = e0.ra.programId) : admB adm reqs = specAdm adm rs := by
  have hR : ∀ i (h2 : i < rs.size), reqFits rs[i].ra = rs[i].ls.all (fun l => fitsS l && fitsLine2 l) ∧
      nLines rs[i] = rs[i].ls.length :=
    fun i h2 => reqOf_fit ((hr i (by omega)).trans (Array.getElem?_eq_getElem h2))
  have hcov : (admB adm reqs).cov = (specAdm adm rs).cov := by
    simp only [admB, specAdm]
    unfold covB
    cases adm with
    | error e =>
      apply Array.ext
      · simp [hs]
      · intro i h1 h2; simp
    | ok a =>
      cases h0 : reqs[0]? with
      | none =>
        have hz : reqs.size = 0 := by simp only [Array.getElem?_eq_none_iff] at h0; omega
        apply Array.ext
        · simp [hs]
        · intro i h1 _; exfalso; simp at h1; omega
      | some e0 =>
        apply Array.ext
        · simp [hs]
        · intro i h1 h2
          have hi2 : i < rs.size := by simpa using h2
          have hi1 : i < reqs.size := by omega
          dsimp only
          simp only [Array.getElem_map]
          rw [hra i hi1 hi2, hp reqs[i] (Array.getElem_mem hi1) e0 (Option.mem_def.mpr h0)]
          exact covFlow (fun f => (Authority.entryFor a.grant e0.ra.programId.toList f).isSome) reqs[i].ra.flow
  have hfit : (admB adm reqs).fit = (specAdm adm rs).fit := by
    simp only [admB, specAdm]
    apply Array.ext
    · simp [hs]
    · intro i h1 h2
      have hi2 : i < rs.size := by simpa using h2
      have hi1 : i < reqs.size := by omega
      simp only [Array.getElem_map]
      rw [← hra i hi1 hi2]
      exact (hR i hi2).1
  have hunf : (admB adm reqs).unf = (specAdm adm rs).unf := by
    show ((admB adm reqs).cov.zip (admB adm reqs).fit).map _ = ((specAdm adm rs).cov.zip (specAdm adm rs).fit).map _
    rw [hcov, hfit]
  have hpos : (admB adm reqs).bPos = (specAdm adm rs).bPos := by
    show posOf reqs (admB adm reqs).cov (admB adm reqs).unf = _
    rw [hcov, hunf]
    exact posOf_eq reqs rs _ _ hs fun i h1 h2 => by
      rw [← (hR i h2).2]; simp only [nLines, hra i h1 h2]
  have ext : ∀ a b : AdmB, a.cov = b.cov → a.fit = b.fit → a.unf = b.unf → a.bPos = b.bPos → a = b := by
    intro a b; cases a; cases b; simp only [AdmB.mk.injEq]; exact fun h1 h2 h3 h4 => ⟨h1, h2, h3, h4⟩
  exact ext _ _ hcov hfit hunf hpos

/-- `admitB_eq` without `hra` is false: a request whose bytes `x` decode to `rs`' request, but whose `ra` has a line that
    does not fit, is unfit to `admB` and fit to `specAdm`. -/
theorem admitB_eq_needs_ra : ¬ (∀ (adm : Except String Run.Admitted) (reqs rs : Array Run.Req) (_ : rs.size = reqs.size)
    (_ : ∀ i (h : i < reqs.size), Run.reqOf reqs[i].x = rs[i]?)
    (_ : ∀ x ∈ reqs, ∀ e0 ∈ reqs[0]?, x.ra.programId = e0.ra.programId), admB adm reqs = specAdm adm rs) := by
  intro h
  obtain ⟨x0, r0, hr0, hl⟩ : ∃ x r, Run.reqOf x = some r ∧ r.ls = [] := by
    have hs : (Run.reqOf (domain "DECIDE-REQUEST" ++ identField [65] ++ identField [66] ++ [4] ++ identField [67] ++
        identField [68] ++ List.replicate 32 7 ++ identField [69] ++ List.replicate 8 0 ++ identField [70] ++ [0, 0] ++
        [0, 0]).toByteArray).map (fun r => r.ls.length) = some 0 := by decide +kernel
    obtain ⟨r, hr, hl⟩ := Option.map_eq_some_iff.mp hs
    exact ⟨_, r, hr, by simpa using hl⟩
  obtain ⟨ra, hbad⟩ : ∃ ra : RequestBA, reqFits ra = false :=
    ⟨⟨.empty, .empty, .FFS_CYCLE, .empty, (List.replicate 70 (65 : UInt8)).toByteArray, .empty, .empty, 0, .empty,
      [ByteArray.empty], []⟩, by decide +kernel⟩
  have h1 := h (.error "e") #[{ r0 with ra := ra, x := x0 }] #[r0] rfl (by
    intro i hi
    have : i = 0 := by simp at hi; omega
    subst this
    simpa using hr0) (by intro x hx e0 he; simp at hx he; subst hx; subst he; rfl)
  have h2 := congrArg AdmB.fit h1
  simp [admB, specAdm, hbad, hl] at h2

end BlindLedger.Gate.Engine3.Run
