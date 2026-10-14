import BlindLedger.Gate.Rules.FastEq
import BlindLedger.Gate.AnchorTheorems
import BlindLedger.Sha3FastEq
import Std.Data.String.ToNat

/-! HIST-FLAT design A: the resident rules worker's goals (rr-core, 2026-10-14; r2 after rr-review
    `rrb/state/hist-flat-a-review-20261014.md` F1-F4). Design: `rrb/state/hist-flat-design-A-20261013.md`. Every theorem
    here is proved (no `sorry`); the worker (`gate_rules_worker`) serves frames through `frame`.
    Defs: `addsBytes`, `addsField`, `rowsOf`, `pinIncr`, `Res`, `Res.digest`, `Res.Ok`, `refresh`, `Res.Fits`,
    `Res.memoOf`, `Res.fit`, `resume`, `Worker`, `Inv`, `breaks`, `refit`, `stepRes`, `runRes`, `frame`; `extend` (fresh
    rows onto `rel`/`unr` and the posting lists) and `commitRes` (`Run.commit` deciding with the kept index and
    digesting from the kept buffers).

    Composition. A worker frame runs `stepRes` over a `Worker` (kept `Res`, a `live` flag, the frame's `St`). `live`
    is set only by a successful `resume` (`resume_fits`) or by `Res.fit` (an O(n) check, run after `load` and after a
    commit made while not live: `fit_fits`, `load_fits`, `commit_genesis_fits`), and cleared by any line that may
    change the sets the frame reads (`breaks`). `commitRes` runs only while `live` (`stepRes_inv`, T2), so every
    non-resume line steps as `step` (`stepRes_step`), and a frame with `resume D` after any head prints and ends as the
    same frame with `load a adds D` (`resume_eq_load`, `runRes_eq_load`). `adds` may be the sealed join of every
    batch's RULES_ADDS: it parses to the resident sets in their order (`parseAdds_append`, `commit_adds`,
    `resident_inv`), which fixes `with=` order. RULES_DIGEST is `Fast.setsDigestF hB` of the committed sets (T3,
    `Memo.ok`; `setsDigestF_eq` ties it to `Gate.setsDigest`); the kept index decides as `decideBatchIn` (T4 with
    `decideBatchFIn_eq`). These fix outputs, not cost: O(fresh) for `extend`/`commitRes` is a review and bench claim.

    Out of scope: `counterparts_cap_eq` (the `with=` cap). It changes the RULES_LINE text, the vectors and OUTPUT_DIGEST,
    so it is a format change via rr-core + ONEP; design A is byte-identical to the full replay. -/

namespace BlindLedger.Gate.Rules.Resident

open BlindLedger.Gate.Rules Run

/-- The `RULES_ADDS` bytes `commit` prints for fresh released rows `r` (tag 1) and unresolved rows `u` (tag 2). -/
def addsBytes (r u : List Line) : Option ByteArray := do
  pure (((← r.mapM (rowBytesFast 1)) ++ (← u.mapM (rowBytesFast 2))).foldl (· ++ ·) ByteArray.empty)

/-- The `load` adds field for `b`: `-` for none. -/
def addsField (b : ByteArray) : String := if b.size = 0 then "-" else hexOf b

/-- A set's rows as `Fast.pinBytes` writes them (no tag), in set order. -/
def rowsOf (s : List Line) : Option (List ByteArray) := s.mapM fun x => Fast.pushRow .empty (Line.fields x)

/-- `Fast.pinBytes` of `⟨asOf, count, s ++ fresh⟩` from `buf`, the sorted rows of `s`: the header, then `buf` merged
    with the sorted fresh rows; and the merged buffer for the next batch. No row of `s` is re-serialized or re-sorted. -/
def pinIncr (domain : String) (kind asOf count : Nat) (buf : Array ByteArray) (fresh : List Line) :
    Option (ByteArray × Array ByteArray) := do
  let head ← Fast.pushRow (domain.toUTF8.push 0) [(4, kind), (4, asOf), (4, count)]
  let buf' := (List.merge buf.toList ((← rowsOf fresh).mergeSort Fast.baLe) Fast.baLe).toArray
  pure (buf'.foldl (· ++ ·) head, buf')

/-- What the worker keeps between frames: the checkpoint sets with their digest (`Memo.ok`), each set's rows sorted,
    and the index over the sets (`none`: build it at the next commit). -/
def Res.BufOk (m : Memo) (rbuf ubuf : Array ByteArray) : Prop :=
  (∃ rs, rowsOf m.r.entries = some rs ∧ rbuf.toList = rs.mergeSort Fast.baLe) ∧
  (∃ us, rowsOf m.u.entries = some us ∧ ubuf.toList = us.mergeSort Fast.baLe)

structure Res where
  m : Memo
  rbuf : Array ByteArray
  ubuf : Array ByteArray
  ix : Option Fast.Ix
  bok : Res.BufOk m rbuf ubuf

/-- The digest of sets `r`, `u` that extend the kept ones, and their buffers, from the kept buffers. -/
def Res.digest (x : Res) (r u : Snapshot Line) : Option (List UInt8 × Array ByteArray × Array ByteArray) := do
  let (a, rb) ← pinIncr "RR/GATE/RELEASED/v1" 5 r.asOf r.count x.rbuf (r.entries.drop x.m.r.entries.length)
  let (b, ub) ← pinIncr "RR/GATE/UNRESOLVED/v1" 6 u.asOf u.count x.ubuf (u.entries.drop x.m.u.entries.length)
  pure (Gate.stateDigest (fun y => hB ⟨y.toArray⟩) (hB a) (hB b), rb, ub)

/-- The buffers are the sets' sorted rows, the sets have the shape `load` leaves (one date, counts = lengths), and a
    kept index was built over them. -/
def Res.Ok (x : Res) : Prop :=
  (∃ rs, rowsOf x.m.r.entries = some rs ∧ x.rbuf.toList = rs.mergeSort Fast.baLe) ∧
  (∃ us, rowsOf x.m.u.entries = some us ∧ x.ubuf.toList = us.mergeSort Fast.baLe) ∧
  x.m.u.asOf = x.m.r.asOf ∧ x.m.r.count = x.m.r.entries.length ∧ x.m.u.count = x.m.u.entries.length ∧
  ∀ i, x.ix = some i → ∃ c b, i = Fast.Ix.build c b ∧ c.released = some x.m.r ∧ c.releasedPrior = x.m.r ∧
    c.unresolved = some x.m.u ∧ c.unresolvedPrior = x.m.u

/-- `i` with the per-frame parts of `Fast.Ix.build c b` (redo, batch, the four snapshots); the set parts kept. -/
def refresh (i : Fast.Ix) (c : Ctx) (b : List Line) : Fast.Ix :=
  { i with redo := Std.HashSet.ofList c.redo, batch := Std.HashSet.ofList b,
           dmfSome := c.dmf.isSome, pdSome := c.providerDeaths.isSome, exclSome := c.exclusions.isSome,
           spanSome := c.enrollment.isSome,
           dmfOk := usable c.today 90 okDeath c.dmf, pdOk := usable c.today 90 okDeath c.providerDeaths,
           exclOk := usable c.today 31 okExclusion c.exclusions, spanOk := usable c.today 7 okSpan c.enrollment,
           dmf := Fast.group (·.id) (entries c.dmf), pdeath := Fast.group (·.id) (entries c.providerDeaths),
           excl := Fast.group (·.id) (entries c.exclusions), span := Fast.group (·.member) (entries c.enrollment) }

/-- The index over `r'`, `u'` (the sets after a commit) from `i` over their prefixes. O(fresh). -/
def extend (i : Fast.Ix) (r' u' : Snapshot Line) : Fast.Ix :=
  let fr := r'.entries.drop i.relN
  let fu := u'.entries.drop i.unrN
  { i with relChained := r'.count == i.relN + fr.length && validDate r'.asOf && decide (r'.asOf ≤ i.today),
           unrChained := u'.count == i.unrN + fu.length && validDate u'.asOf && decide (u'.asOf ≤ i.today),
           relV := r', unrV := u', relN := i.relN + fr.length, unrN := i.unrN + fu.length,
           rel := i.rel ++ fr.toArray, unr := i.unr ++ fu.toArray,
           relPost := (fr.foldl Fast.postStep (i.relPost, i.relN)).1,
           unrPost := (fu.foldl Fast.postStep (i.unrPost, i.unrN)).1 }

/-- `x` is `st`'s checkpoint: `st`'s priors and the sets `st` reads are `x`'s. -/
def Res.Fits (x : Res) (st : St) : Prop :=
  x.Ok ∧ st.rprior = x.m.r ∧ st.uprior = x.m.u ∧ st.sealed = true ∧
  (st.ctx (st.pinned.getD st.pin)).released = some x.m.r ∧ (st.ctx (st.pinned.getD st.pin)).unresolved = some x.m.u

/-- `st`'s priors with their digest: `st.memo` when it is for them (after `load`), else computed. -/
def Res.memoOf (st : St) : Memo := match st.memo with
  | some m => if m.r = st.rprior ∧ m.u = st.uprior then m else ⟨st.rprior, st.uprior, _, rfl⟩
  | none => ⟨st.rprior, st.uprior, _, rfl⟩

theorem baLe_trans (a b c : ByteArray) (h1 : Fast.baLe a b = true) (h2 : Fast.baLe b c = true) : Fast.baLe a c = true := by
  simp only [Fast.baLe_eq, decide_eq_true_eq] at *
  exact List.le_trans h1 h2

theorem baLe_total (a b : ByteArray) : (Fast.baLe a b || Fast.baLe b a) = true := by
  simp only [Fast.baLe_eq, Bool.or_eq_true, decide_eq_true_eq]
  exact List.le_total _ _

theorem baLe_anti (a b : ByteArray) (h1 : Fast.baLe a b = true) (h2 : Fast.baLe b a = true) : a = b := by
  simp only [Fast.baLe_eq, decide_eq_true_eq] at *
  have := List.le_antisymm h1 h2
  cases a; cases b; simp_all [Array.toList_inj]

theorem merge_sort_eq (xs ys : List ByteArray) :
    List.merge (xs.mergeSort Fast.baLe) (ys.mergeSort Fast.baLe) Fast.baLe = (xs ++ ys).mergeSort Fast.baLe := by
  apply List.Perm.eq_of_pairwise (le := fun a b => Fast.baLe a b = true)
  · intro a b _ _ h1 h2; exact baLe_anti a b h1 h2
  · exact List.pairwise_merge baLe_trans baLe_total _ _ (List.pairwise_mergeSort baLe_trans baLe_total _) (List.pairwise_mergeSort baLe_trans baLe_total _)
  · exact List.pairwise_mergeSort baLe_trans baLe_total _
  · exact (List.merge_perm_append _).trans ((List.mergeSort_perm xs _).append (List.mergeSort_perm ys _)) |>.trans (List.mergeSort_perm _ _).symm

theorem emptyCap_append (n : Nat) (h : ByteArray) : ByteArray.emptyWithCapacity n ++ h = h := by
  show ByteArray.empty ++ h = h
  exact ByteArray.empty_append

theorem rowsOf_append (s fresh : List Line) (rs : List ByteArray) (hs : rowsOf s = some rs) :
    rowsOf (s ++ fresh) = (rowsOf fresh).map (rs ++ ·) := by
  unfold rowsOf at hs ⊢
  rw [List.mapM_append, hs]
  cases List.mapM (fun x => Fast.pushRow ByteArray.empty x.fields) fresh <;> rfl

/-- T3: the incremental pin is `Fast.pinBytes` of the extended set, and the merged buffer is its sorted rows. Rules out
    a merge that misorders, drops or duplicates a row. -/
theorem pinIncr_eq (domain : String) (kind : Nat) (s : Snapshot Line) (fresh : List Line) (buf : Array ByteArray)
    (rs : List ByteArray) (hs : rowsOf s.entries = some rs) (hb : buf.toList = rs.mergeSort Fast.baLe) :
    (pinIncr domain kind s.asOf (s.count + fresh.length) buf fresh).map (·.1) =
      Fast.pinBytes domain kind Line.fields ⟨s.asOf, s.count + fresh.length, s.entries ++ fresh⟩ ∧
    ∀ p b', pinIncr domain kind s.asOf (s.count + fresh.length) buf fresh = some (p, b') →
      ∃ rs', rowsOf (s.entries ++ fresh) = some rs' ∧ b'.toList = rs'.mergeSort Fast.baLe := by
  have key := rowsOf_append _ fresh _ hs
  have hbuf : buf = (rs.mergeSort Fast.baLe).toArray := by
    apply Array.ext'; simpa using hb
  subst hbuf
  have key' := key
  unfold rowsOf at key'
  constructor
  · simp only [pinIncr, Fast.pinBytes, rowsOf]
    generalize domain.toUTF8.push 0 = hd
    generalize hho : Fast.pushRow hd [(4, kind), (4, s.asOf), (4, s.count + fresh.length)] = ho
    cases ho with
    | none => simp
    | some head =>
      cases hf : List.mapM (fun x => Fast.pushRow ByteArray.empty (Line.fields x)) fresh with
      | none => simp [key', hf]
      | some rf =>
        simp [key', hf, emptyCap_append, merge_sort_eq]
  · intro p b' h
    cases hf : rowsOf fresh with
    | none => simp [pinIncr, hf] at h
    | some rf =>
      refine ⟨rs ++ rf, by rw [key, hf]; rfl, ?_⟩
      simp [pinIncr, hf] at h
      obtain ⟨head, -, h⟩ := Option.bind_eq_some_iff.1 h
      have h2 := (Prod.mk.inj (Option.some.inj h)).2
      rw [← h2, ← merge_sort_eq]

/-- T3: the kept digest of the extended sets is the full `Fast.setsDigestF` (the printed RULES_DIGEST), and the new
    buffers keep `Res.Ok`. Rules out a resident digest that differs from the full re-serialization. -/
theorem digest_eq_buf (x : Res) (fr fu : List Line) :
    let r : Snapshot Line := ⟨x.m.r.asOf, x.m.r.count + fr.length, x.m.r.entries ++ fr⟩
    let u : Snapshot Line := ⟨x.m.u.asOf, x.m.u.count + fu.length, x.m.u.entries ++ fu⟩
    (x.digest r u).map (·.1) = Fast.setsDigestF hB r u ∧
    ∀ d rb ub, x.digest r u = some (d, rb, ub) →
      (∃ rs, rowsOf r.entries = some rs ∧ rb.toList = rs.mergeSort Fast.baLe) ∧
      (∃ us, rowsOf u.entries = some us ∧ ub.toList = us.mergeSort Fast.baLe) := by
  intro r u
  obtain ⟨⟨rs, hrs, hrb⟩, ⟨us, hus, hub⟩⟩ := x.bok
  have h1 := pinIncr_eq "RR/GATE/RELEASED/v1" 5 x.m.r fr x.rbuf rs hrs hrb
  have h2 := pinIncr_eq "RR/GATE/UNRESOLVED/v1" 6 x.m.u fu x.ubuf us hus hub
  have d1 : r.entries.drop x.m.r.entries.length = fr := List.drop_left
  have d2 : u.entries.drop x.m.u.entries.length = fu := List.drop_left
  constructor
  · simp only [Res.digest, Fast.setsDigestF, r, u, d1, d2] at *
    rw [← h1.1, ← h2.1]
    cases ha : pinIncr "RR/GATE/RELEASED/v1" 5 x.m.r.asOf (x.m.r.count + fr.length) x.rbuf fr <;>
      cases hb : pinIncr "RR/GATE/UNRESOLVED/v1" 6 x.m.u.asOf (x.m.u.count + fu.length) x.ubuf fu <;> simp
  · intro d rb ub h
    simp only [Res.digest, r, u, d1, d2] at h
    obtain ⟨⟨a, rb'⟩, ha, h⟩ := Option.bind_eq_some_iff.1 h
    obtain ⟨⟨b, ub'⟩, hb, h⟩ := Option.bind_eq_some_iff.1 h
    have h := Option.some.inj h
    simp only [Prod.mk.injEq] at h
    obtain ⟨-, rfl, rfl⟩ := h
    exact ⟨h1.2 a rb' ha, h2.2 b ub' hb⟩

theorem digest_eq (x : Res) (hx : x.Ok) (fr fu : List Line) :
    let r : Snapshot Line := ⟨x.m.r.asOf, x.m.r.count + fr.length, x.m.r.entries ++ fr⟩
    let u : Snapshot Line := ⟨x.m.u.asOf, x.m.u.count + fu.length, x.m.u.entries ++ fu⟩
    (x.digest r u).map (·.1) = Fast.setsDigestF hB r u ∧
    ∀ d rb ub, x.digest r u = some (d, rb, ub) →
      (∃ rs, rowsOf r.entries = some rs ∧ rb.toList = rs.mergeSort Fast.baLe) ∧
      (∃ us, rowsOf u.entries = some us ∧ ub.toList = us.mergeSort Fast.baLe) := by
  have _ := hx
  exact digest_eq_buf x fr fu

/-- A `Res` fitting `st`, built and checked in O(n), or `none` (the worker stays on the full path). -/
def Res.fit (st : St) : Option Res :=
  let m := Res.memoOf st
  let c := st.ctx (st.pinned.getD st.pin)
  if st.sealed = true ∧ m.u.asOf = m.r.asOf ∧ m.r.count = m.r.entries.length ∧
      m.u.count = m.u.entries.length ∧ c.released = some m.r ∧ c.unresolved = some m.u then
    match hr : rowsOf m.r.entries, hu : rowsOf m.u.entries with
    | some rs, some us => some { m, rbuf := (rs.mergeSort Fast.baLe).toArray, ubuf := (us.mergeSort Fast.baLe).toArray,
                                 ix := none, bok := ⟨⟨rs, hr, by simp⟩, ⟨us, hu, by simp⟩⟩ }
    | _, _ => none
  else none

/-- The `Res` after a commit that appended `fr`, `fu` to the kept sets, from `x`'s buffers and `i` extended by them, or
    `none` when the fresh rows do not serialize (a field over its width: the worker then falls back, `refit`). The new
    sets are built from the kept ones, so `Memo.ok` is `digest_eq_buf` and nothing is checked at run time. -/
def Res.next (x : Res) (i : Fast.Ix) (fr fu : List Line) : Option Res :=
  match hd : x.digest ⟨x.m.r.asOf, x.m.r.count + fr.length, x.m.r.entries ++ fr⟩
      ⟨x.m.u.asOf, x.m.u.count + fu.length, x.m.u.entries ++ fu⟩ with
  | none => none
  | some (d, rb, ub) =>
    let h := (digest_eq_buf x fr fu).1
    let hk := (digest_eq_buf x fr fu).2 d rb ub hd
    some { m := ⟨⟨x.m.r.asOf, x.m.r.count + fr.length, x.m.r.entries ++ fr⟩,
                 ⟨x.m.u.asOf, x.m.u.count + fu.length, x.m.u.entries ++ fu⟩, some d, by simpa [hd] using h⟩,
           rbuf := rb, ubuf := ub, ix := some (extend i ⟨x.m.r.asOf, x.m.r.count + fr.length, x.m.r.entries ++ fr⟩
             ⟨x.m.u.asOf, x.m.u.count + fu.length, x.m.u.entries ++ fu⟩), bok := hk }

/-- The index for a commit over `c`, `b`: the kept one refreshed (same `today`), else a build. -/
def Res.ixFor (x : Res) (c : Ctx) (b : List Line) : Fast.Ix :=
  match x.ix with
  | some i => if i.today = c.today then refresh i c b else Fast.Ix.build c b
  | none => Fast.Ix.build c b

/-- `commit` with the kept index (`refresh`, or a build if `today` moved), the kept buffers (`Res.digest`) and the
    kept digest as `prior`; plus the next `Res` (`none`: fall back to `refit`). -/
def commitRes (x : Res) (st : St) (unanchored : Bool) : Option Res × St × List String :=
  let p := st.pinned.getD st.pin
  let c := st.ctx p
  let prior := x.m.d
  if !st.anchor.all fun a => prior == some (Gate.natBE Gate.digestBytes a) then (some x, commit st unanchored) else
  let lines := st.batch.toList.map (·.1)
  let (b, f, wait) : List Line × List Nat × List Line := match st.owners with
    | some (k, os) =>
      let b := Fast.readyF k os lines
      let ps := Std.HashSet.ofList (b.map (·.pay))
      (b, Fast.foreignOfF k os b, lines.filter fun l => !ps.contains l.pay)
    | none => (lines, st.foreign, [])
  let ix := x.ixFor c b
  let r := ix.runIn f b
  let exp := st.batch.toList.filterMap (·.2)
  let got := r.decisions.map render ++ wait.map (lineText · ++ " WAIT -")
  let fr := st.owners.map fun (k, os) => uniq (Fast.settleFreeF r.released.entries r.unresolved.entries (pendingOf k os))
  let frOk := st.free.all (some · == fr)
  let bad := st.pays.filter fun (q, o) => name (ix.payOutcome r.decisions q) != o
  let (ok, n, msg) :=
    if exp.isEmpty then (true, 0, [])
    else if exp.length == lines.length && sorted exp == sorted got then (true, lines.length, [])
    else (false, 0, ((sorted got).filter (!exp.contains ·)).map ("RULES_GOT " ++ ·))
  let ok := ok && bad.isEmpty && !unanchored && frOk
  let msg := msg ++ bad.map (fun (q, o) => s!"RULES_PAY {q} expected={o}") ++
    (if unanchored then ["RULES_ANCHORED commit"] else []) ++ (if frOk then [] else [s!"RULES_FREE_EXPECTED {st.free}"])
  let fresh := (r.released.entries.drop ix.relN, r.unresolved.entries.drop ix.unrN)
  let adds := do pure (((← fresh.1.mapM (rowBytesFast 1)) ++ (← fresh.2.mapM (rowBytesFast 2))).foldl (· ++ ·) ByteArray.empty)
  let shown := fr.elim [] fun ids => got.map ("RULES_LINE " ++ ·) ++ [" ".intercalate ("RULES_FREE" :: ids.map toString)] ++
    ((x.digest r.released r.unresolved).map (·.1)).toList.map (fun d => s!"RULES_DIGEST {hexOf d.toByteArray}") ++
    adds.toList.map (fun b => s!"RULES_ADDS {hexOf b}") ++
    (prior.bind (reads p c)).toList.map fun b => s!"RULES_READS {hexOf b.toByteArray}"
  (x.next ix fresh.1 fresh.2,
   { st with pinned := some p, anchor := none, sealed := true,
             extra := st.extra ++ fresh.1, held := st.held ++ fresh.2,
             rprior := r.released, uprior := r.unresolved, batch := #[], redo := [], foreign := [], owners := none,
             free := none, pays := [],
             done := st.done ++ r.decisions, checked := st.checked + (if ok then n + st.pays.length else 0),
             failed := st.failed + (if ok then 0 else 1) },
   shown ++ if ok then [] else "RULES_VECTOR_MISMATCH commit" :: msg)

/-- `resume h`: `load`'s accepted branch with the kept sets, no parse, replay or digest; fail closed on any other
    anchor or no kept sets. -/
def resume (o : Option Res) (st : St) (h : String) : Option (St × List String) := do
  guard (h.length == 128)
  let anchor := Gate.beNat (← unhexFast h).toList
  match o.filter fun x => x.m.d == some (Gate.natBE Gate.digestBytes anchor) with
  | some x => pure ({ st with
      snaps := ("released", x.m.r.asOf, 0, ← emptyPin "released" x.m.r.asOf) ::
        ("unresolved", x.m.r.asOf, 0, ← emptyPin "unresolved" x.m.r.asOf) :: st.snaps,
      rows := st.rows.filter fun r => r.1 != "released" && r.1 != "unresolved", pinned := none, anchor := none,
      extra := x.m.r.entries, held := x.m.u.entries, rprior := x.m.r, uprior := x.m.u, sealed := true,
      memo := some x.m }, [])
  | none => pure ({ st with failed := st.failed + 1 }, ["RULES_STATE_MISMATCH resume"])

/-- The worker across lines: the kept `Res` (kept across frames), whether it fits `st`, and the frame's state. -/
structure Worker where
  x : Option Res
  live : Bool
  st : St

/-- Every kept `Res` is `Ok`; while `live`, it fits the state. -/
def Inv (w : Worker) : Prop := (∀ y, w.x = some y → y.Ok) ∧ (w.live = true → ∃ y, w.x = some y ∧ y.Fits w.st)

/-- Lines that may change the sets the next commit reads (or its `today`): they clear `live`. -/
def breaks : List String → Bool
  | k :: _ => ["case", "today", "snap", "drop", "dmf", "pdeath", "excl", "span", "released", "unresolved"].contains k
  | [] => false

/-- After a full `load` or commit: live on `Res.fit st` if the frame has not failed, else the old `Res` kept (only
    `resume` reads it) and not live. A failed frame's state is never adopted. -/
def refit (w : Worker) (st : St) : Worker :=
  match (if st.failed = 0 then Res.fit st else none) with
  | some y => { x := some y, live := true, st }
  | none => { w with live := false, st }

def stepRes (w : Worker) : List String → Option (Worker × List String)
  | ["resume", h] => do
    let (st, out) ← resume w.x w.st h
    pure ({ w with st, live := out.isEmpty || w.live }, out)
  | fs =>
    let u := fs == ["commit", "UNANCHORED"]
    if fs == ["commit"] || u then
      match w.x, w.live with
      | some x, true =>
        let (y, st, out) := commitRes x w.st u
        pure (match y with | some y => { x := some y, live := true, st } | none => refit w st, out)
      | _, _ => let (st, out) := commit w.st u; pure (refit w st, out)
    else do
      let (st, out) ← step w.st fs
      pure (if fs.head? == some "load" then refit w st else { w with st, live := w.live && !breaks fs }, out)

/-- A worker frame from the kept `Res`. -/
def runRes (x : Option Res) (text : String) : Array String × Bool × Worker :=
  runOn stepRes (·.st) (fun w => { w with st := { w.st with failed := w.st.failed + 1 } }) { x, live := false, st := {} } text

/-- One worker frame, the shape `Run.serve` threads: the output lines and the `Res` kept for the next frame. -/
def frame (x : Option Res) (text : String) : Array String × Option Res :=
  let r := runRes x text; (r.1, r.2.2.x)

/-- `runWith` is the shipped loop: rules out a frame loop that drifts from `runText`. -/
theorem runWith_eq_runText (text : String) : ((runWith text).1, (runWith text).2.1) = runText text := rfl

theorem foldl_agree (g g' : Nat → UInt8) (l : List Nat) :
    ∀ a, (∀ i ∈ l, g i = g' i) →
      l.foldl (fun n i => n * 256 + (g i).toNat) a = l.foldl (fun n i => n * 256 + (g' i).toNat) a := by
  induction l with
  | nil => intros; rfl
  | cons x l ih =>
    intro a h
    simp only [List.foldl_cons]
    rw [h x (by simp)]
    exact ih _ (fun i hi => h i (by simp [hi]))

theorem fold_congr (b b' : ByteArray) (ws : List Nat) :
    ∀ (r : Array Nat) (p p' : Nat), (∀ j < ws.sum, b.get! (p + j) = b'.get! (p' + j)) →
    (ws.foldl (fun (r, o) w => (r.push ((List.range w).foldl (fun n i => n * 256 + (b.get! (o + i)).toNat) 0), o + w)) (r, p)).1 =
    (ws.foldl (fun (r, o) w => (r.push ((List.range w).foldl (fun n i => n * 256 + (b'.get! (o + i)).toNat) 0), o + w)) (r, p')).1 := by
  induction ws with
  | nil => intros; rfl
  | cons w ws ih =>
    intro r p p' h
    simp only [List.foldl_cons]
    have hb : (List.range w).foldl (fun n i => n * 256 + (b.get! (p + i)).toNat) 0 =
        (List.range w).foldl (fun n i => n * 256 + (b'.get! (p' + i)).toNat) 0 :=
      foldl_agree (fun i => b.get! (p + i)) (fun i => b'.get! (p' + i)) _ 0
        (fun i hi => h i (by simp at hi ⊢; omega))
    rw [hb]
    apply ih
    intro j hj
    have := h (w + j) (by simp; omega)
    rwa [← Nat.add_assoc, ← Nat.add_assoc] at this
theorem parseRow_congr (b b' : ByteArray) (o o' : Nat) (h : ∀ j < 1 + rowWidths.sum, b.get! (o + j) = b'.get! (o' + j)) :
    parseRow b o = parseRow b' o' := by
  unfold parseRow
  have h0 := h 0 (by omega)
  have := fold_congr b b' rowWidths #[] (o + 1) (o' + 1) (fun j hj => by
    have := h (j + 1) (by omega)
    rwa [show o + 1 + j = o + (j + 1) by omega, show o' + 1 + j = o' + (j + 1) by omega])
  simp only [Nat.add_zero] at h0
  dsimp only
  rw [this, h0]
theorem get!_append_left (a b : ByteArray) (i : Nat) (h : i < a.size) : (a ++ b).get! i = a.get! i := by
  simp only [ByteArray.get!, getElem!_def, ByteArray.data_append]
  rw [Array.getElem?_append_left (by simpa using h)]

theorem get!_append_right (a b : ByteArray) (i : Nat) : (a ++ b).get! (a.size + i) = b.get! i := by
  simp only [ByteArray.get!, getElem!_def, ByteArray.data_append]
  rw [Array.getElem?_append_right (by simp)]
  simp

theorem mapM_ext_opt {α β : Type} (l : List α) (f g : α → Option β) (h : ∀ x ∈ l, f x = g x) : l.mapM f = l.mapM g := by
  induction l with
  | nil => rfl
  | cons x l ih =>
    simp only [List.mapM_cons]
    rw [h x (by simp), ih (fun y hy => h y (by simp [hy]))]

theorem parseAdds_some (bs : ByteArray) (r u : List Line) (h : parseAdds bs = some (r, u)) :
    ∃ k rows, bs.size = (1 + rowWidths.sum) * k ∧
      (List.range k).mapM (fun i => parseRow bs ((1 + rowWidths.sum) * i)) = some rows ∧
      rows.all (fun (t, _) => t == 1 || t == 2) = true ∧
      r = (rows.filter (·.1 == 1)).map (·.2) ∧ u = (rows.filter (·.1 == 2)).map (·.2) := by
  unfold parseAdds at h
  by_cases hm : (bs.size % (1 + rowWidths.sum) == 0) = true
  · have hd : (1 + rowWidths.sum) ∣ bs.size := Nat.dvd_of_mod_eq_zero (by simpa using hm)
    obtain ⟨k, hk⟩ := hd
    simp only [guard, failure, hm, if_true] at h
    cases hr : (List.range (bs.size / (1 + rowWidths.sum))).mapM (fun i => parseRow bs ((1 + rowWidths.sum) * i)) with
    | none => simp [hr] at h
    | some rows =>
      simp only [hr] at h
      by_cases ht : (rows.all fun (t, _) => t == 1 || t == 2) = true
      · simp [ht] at h
        refine ⟨k, rows, hk, ?_, ht, h.1.symm, h.2.symm⟩
        rw [hk, Nat.mul_div_cancel_left _ (by omega)] at hr
        exact hr
      · simp [ht] at h
  · simp [guard, failure, hm] at h


/-- F4: the join of sealed adds parses to the joined rows, per set and in order. -/
theorem parseAdds_append (a b : ByteArray) (r u r' u' : List Line) (ha : parseAdds a = some (r, u))
    (hb : parseAdds b = some (r', u')) : parseAdds (a ++ b) = some (r ++ r', u ++ u') := by
  obtain ⟨ka, rowsA, hsa, hma, hta, rfl, rfl⟩ := parseAdds_some a r u ha
  obtain ⟨kb, rowsB, hsb, hmb, htb, rfl, rfl⟩ := parseAdds_some b r' u' hb
  have hpos : 0 < (1 + rowWidths.sum) := by omega
  have hsz : (a ++ b).size = (1 + rowWidths.sum) * (ka + kb) := by rw [ByteArray.size_append, hsa, hsb, Nat.mul_add]
  have hmod : ((a ++ b).size % (1 + rowWidths.sum) == 0) = true := by rw [hsz]; simp
  have hrows : (List.range (ka + kb)).mapM (fun i => parseRow (a ++ b) ((1 + rowWidths.sum) * i)) = some (rowsA ++ rowsB) := by
    rw [List.range_add, List.mapM_append, List.mapM_map]
    have h1 : (List.range ka).mapM (fun i => parseRow (a ++ b) ((1 + rowWidths.sum) * i)) = some rowsA := by
      rw [← hma]
      apply mapM_ext_opt
      intro i hi
      have hi := List.mem_range.1 hi
      apply parseRow_congr
      intro j hj
      have : (1 + rowWidths.sum) * i + j < a.size := by
        have h3 : (1 + rowWidths.sum) * (i + 1) ≤ (1 + rowWidths.sum) * ka := Nat.mul_le_mul_left (1 + rowWidths.sum) hi
        rw [Nat.mul_add, Nat.mul_one] at h3
        omega
      exact get!_append_left a b _ this
    have h2 : (List.range kb).mapM ((fun i => parseRow (a ++ b) ((1 + rowWidths.sum) * i)) ∘ (fun x => ka + x)) = some rowsB := by
      rw [← hmb]
      apply mapM_ext_opt
      intro i hi
      simp only [Function.comp]
      apply parseRow_congr
      intro j hj
      rw [show (1 + rowWidths.sum) * (ka + i) + j = a.size + ((1 + rowWidths.sum) * i + j) by rw [hsa, Nat.mul_add]; omega]
      exact get!_append_right a b _
    rw [h1, h2]; rfl
  unfold parseAdds
  simp only [guard, failure, hsz, Nat.mul_div_cancel_left _ hpos, hrows]
  simp [hta, htb, List.all_append, List.filter_append]

def bytesBE (w n : Nat) : List UInt8 := (List.range w).reverse.map fun i => (n / 256 ^ i % 256).toUInt8
def rdL (l : List UInt8) : Nat := l.foldl (fun a b => a * 256 + b.toNat) 0

theorem bytesBE_succ (w n : Nat) : bytesBE (w+1) n = bytesBE w (n/256) ++ [(n % 256).toUInt8] := by
  unfold bytesBE
  rw [List.range_succ_eq_map, List.reverse_cons, ← List.map_reverse, List.map_append, List.map_map]
  congr 1
  · apply List.map_congr_left
    intro i _
    simp only [Function.comp]
    rw [Nat.pow_succ, Nat.mul_comm, ← Nat.div_div_eq_div_mul]
  · simp

theorem rdL_bytesBE : ∀ (w n : Nat), n < 256 ^ w → rdL (bytesBE w n) = n := by
  intro w
  induction w with
  | zero => intro n h; simp at h; subst h; simp [bytesBE, rdL]
  | succ w ih =>
    intro n h
    rw [bytesBE_succ]
    have h1 : n / 256 < 256 ^ w := by
      rw [Nat.div_lt_iff_lt_mul (by omega)]; rwa [← Nat.pow_succ]
    have := ih _ h1
    unfold rdL at this ⊢
    rw [List.foldl_append, this]
    simp only [List.foldl_cons, List.foldl_nil]
    have : ((n % 256).toUInt8).toNat = n % 256 := by simp [Nat.toUInt8]
    omega

theorem get!_eq (b : ByteArray) (i : Nat) : b.get! i = (b.data.toList[i]?).getD 0 := by
  simp [ByteArray.get!, getElem!_def]
  cases b.data[i]? <;> rfl

theorem range_fold_list (L : List UInt8) (o : Nat) : ∀ (l : List UInt8) (a : Nat),
    (∀ i < l.length, L[o + i]? = l[i]?) →
    (List.range l.length).foldl (fun n i => n * 256 + ((L[o + i]?).getD 0).toNat) a = l.foldl (fun a b => a * 256 + b.toNat) a := by
  intro l
  induction l generalizing o with
  | nil => intros; rfl
  | cons x t ih =>
    intro a h
    rw [List.length_cons, List.range_succ_eq_map, List.foldl_cons, List.foldl_map]
    have h0 := h 0 (by simp)
    simp only [Nat.add_zero, List.getElem?_cons_zero] at h0 ⊢
    have hf : (fun (x y : Nat) => x * 256 + (L[o + y.succ]?.getD 0).toNat) =
        fun x y => x * 256 + (L[(o + 1) + y]?.getD 0).toNat := by
      funext x y; rw [show o + y.succ = (o + 1) + y by omega]
    rw [hf, h0]
    simp only [Option.getD_some, List.foldl_cons]
    exact ih (o+1) _ (fun i hi => by
      have := h (i+1) (by simp; omega)
      rw [show o+1+i = o+(i+1) by omega]; simpa using this)


theorem length_bytesBE (w n : Nat) : (bytesBE w n).length = w := by simp [bytesBE]

def flatBE (ws ns : List Nat) : List UInt8 := ((ws.zip ns).map fun p => bytesBE p.1 p.2).flatten

theorem fold_read (b : ByteArray) : ∀ (ws ns : List Nat) (r : Array Nat) (o : Nat) (pre rest : List UInt8),
    ws.length = ns.length → (∀ p ∈ ws.zip ns, p.2 < 256 ^ p.1) →
    b.data.toList = pre ++ flatBE ws ns ++ rest → pre.length = o →
    (ws.foldl (fun (r, o) w => (r.push ((List.range w).foldl (fun n i => n * 256 + (b.get! (o + i)).toNat) 0), o + w)) (r, o)).1
      = r ++ ns.toArray := by
  intro ws
  induction ws with
  | nil =>
    intro ns r o pre rest hl _ _ _
    cases ns with
    | nil => simp
    | cons => simp at hl
  | cons w ws ih =>
    intro ns r o pre rest hl hfit hL ho
    cases ns with
    | nil => simp at hl
    | cons n ns =>
      simp only [List.length_cons, Nat.add_right_cancel_iff] at hl
      have hn : n < 256 ^ w := hfit (w, n) (by simp)
      have hL' : b.data.toList = (pre ++ bytesBE w n) ++ flatBE ws ns ++ rest := by
        rw [hL]; simp [flatBE, List.append_assoc]
      have hread : (List.range w).foldl (fun n i => n * 256 + (b.get! (o + i)).toNat) 0 = n := by
        have := range_fold_list b.data.toList o (bytesBE w n) 0 (fun i hi => by
          rw [hL, List.append_assoc, List.getElem?_append_right (by omega)]
          simp only [flatBE, List.zip_cons_cons, List.map_cons, List.flatten_cons, List.append_assoc]
          rw [show o + i - pre.length = i by omega, List.getElem?_append_left (by simpa [length_bytesBE] using hi)])
        rw [length_bytesBE] at this
        simp only [get!_eq]
        rw [this]
        exact rdL_bytesBE w n hn
      simp only [List.foldl_cons]
      rw [hread]
      have := ih ns (r.push n) (o + w) (pre ++ bytesBE w n) rest hl (fun p hp => hfit p (by simp [hp])) hL' (by simp [ho, length_bytesBE])
      rw [this]; simp

theorem zip_map_fs (fs : List (Nat × Nat)) : (fs.map Prod.fst).zip (fs.map Prod.snd) = fs := by
  induction fs with
  | nil => rfl
  | cons p fs ih => simp [ih]

theorem mapM_be (fs : List (Nat × Nat)) : ∀ (bs : List (List UInt8)),
    (fs.mapM fun (w, n) => BlindLedger.Gate.Rules.be w n) = some bs →
    (∀ p ∈ fs, p.2 < 256 ^ p.1) ∧ bs = fs.map (fun p => bytesBE p.1 p.2) := by
  induction fs with
  | nil => intro bs h; simp at h; subst h; simp
  | cons p fs ih =>
    intro bs h
    obtain ⟨w, n⟩ := p
    by_cases hp : n < 256 ^ w
    · have hbe : BlindLedger.Gate.Rules.be w n = some (bytesBE w n) := by simp [BlindLedger.Gate.Rules.be, hp, bytesBE]
      simp only [List.mapM_cons, hbe] at h
      cases hm : fs.mapM (fun (w, n) => BlindLedger.Gate.Rules.be w n) with
      | none => simp [hm] at h
      | some rest =>
        simp only [hm] at h
        have h' : bs = bytesBE w n :: rest := by simpa using h.symm
        obtain ⟨h1, h2⟩ := ih rest hm
        refine ⟨?_, ?_⟩
        · intro q hq
          rcases List.mem_cons.1 hq with rfl | hq
          · exact hp
          · exact h1 q hq
        · rw [h', h2]; rfl
    · have hbe : BlindLedger.Gate.Rules.be w n = none := by simp [BlindLedger.Gate.Rules.be, hp]
      simp [List.mapM_cons, hbe] at h

theorem flatBE_length (ws ns : List Nat) (h : ws.length = ns.length) : (flatBE ws ns).length = ws.sum := by
  induction ws generalizing ns with
  | nil => simp [flatBE]
  | cons w ws ih =>
    cases ns with
    | nil => simp at h
    | cons n ns =>
      simp only [List.length_cons, Nat.add_right_cancel_iff] at h
      have := ih ns h
      simp only [flatBE, List.zip_cons_cons, List.map_cons, List.flatten_cons, List.length_append, length_bytesBE, List.sum_cons] at this ⊢
      omega

theorem rowWidths_eq (l : Line) : rowWidths = (Line.fields l).map (·.1) := rfl

theorem parseRow_rowBytesFast (t : UInt8) (l : Line) (b : ByteArray) (h : rowBytesFast t l = some b) :
    b.size = 1 + rowWidths.sum ∧ parseRow b 0 = some (t, l) := by
  have h1 := Fast.rowBytesFast_eq (tag := t) (l := l)
  rw [h] at h1
  simp only [Option.map_some] at h1
  unfold rowBytes at h1
  cases hm : (Line.fields l).mapM (fun (w, n) => BlindLedger.Gate.Rules.be w n) with
  | none => simp [hm] at h1
  | some bs =>
    simp only [hm] at h1
    obtain ⟨hfit, hbs⟩ := mapM_be _ bs hm
    have hL : b.data.toList = t :: (bs.flatten) := by simpa using h1
    have hflat : bs.flatten = flatBE ((Line.fields l).map Prod.fst) ((Line.fields l).map Prod.snd) := by
      rw [hbs, flatBE, zip_map_fs]
    have hlen : ((Line.fields l).map Prod.fst).length = ((Line.fields l).map Prod.snd).length := by simp
    have hws : rowWidths = (Line.fields l).map Prod.fst := rowWidths_eq l
    refine ⟨?_, ?_⟩
    · have : b.data.toList.length = 1 + rowWidths.sum := by
        rw [hL, List.length_cons, hflat, flatBE_length _ _ hlen, hws]; omega
      show b.data.size = _
      rw [← Array.length_toList]; exact this
    · have hb0 : b.get! 0 = t := by
        rw [get!_eq, hL]; rfl
      unfold parseRow
      have hfr := fold_read b ((Line.fields l).map Prod.fst) ((Line.fields l).map Prod.snd) #[] 1 [t] [] hlen
        (by rw [zip_map_fs]; exact hfit) (by rw [hL, hflat]; simp) rfl
      rw [hws]
      simp only [Nat.zero_add]
      rw [hfr]
      have e : (#[] ++ ((Line.fields l).map Prod.snd).toArray).toList = (Line.fields l).map Prod.snd := by simp
      rw [e]
      clear hfr hm hfit hbs hflat h1 hL h hlen e hws
      obtain ⟨i, y, f, m, p, r, d, c, u, a⟩ := l
      cases f <;> simp [Line.fields, hb0, Flow.tag]

theorem parseAdds_empty : parseAdds ByteArray.empty = some ([], []) := by
  unfold parseAdds
  simp [guard, failure]

theorem parseAdds_one (t : UInt8) (l : Line) (b : ByteArray) (h : rowBytesFast t l = some b) (ht : t = 1 ∨ t = 2) :
    parseAdds b = some (if t = 1 then ([l], []) else ([], [l])) := by
  obtain ⟨hsz, hp⟩ := parseRow_rowBytesFast t l b h
  have hpos : 0 < (1 + rowWidths.sum) := by omega
  have hmod : (b.size % (1 + rowWidths.sum) == 0) = true := by rw [hsz]; simp
  have hdiv : b.size / (1 + rowWidths.sum) = 1 := by rw [hsz]; exact Nat.div_self hpos
  have hm : (List.range 1).mapM (fun i => parseRow b ((1 + rowWidths.sum) * i)) = some [(t, l)] := by
    simp [List.range_one, hp]
  unfold parseAdds
  simp only [guard, failure, hmod, if_true, hdiv, hm]
  rcases ht with rfl | rfl <;> simp

theorem foldl_cat (t : UInt8) (ht : t = 1 ∨ t = 2) : ∀ (ls : List Line) (bl : List ByteArray) (acc : ByteArray) (R U : List Line),
    ls.mapM (rowBytesFast t) = some bl → parseAdds acc = some (R, U) →
    parseAdds (bl.foldl (· ++ ·) acc) = some (if t = 1 then (R ++ ls, U) else (R, U ++ ls)) := by
  intro ls
  induction ls with
  | nil =>
    intro bl acc R U h ha
    simp only [List.mapM_nil, Option.pure_def, Option.some.injEq] at h
    subst h
    simp [ha]
  | cons l ls ih =>
    intro bl acc R U h ha
    simp only [List.mapM_cons] at h
    cases hb : rowBytesFast t l with
    | none => simp [hb] at h
    | some b =>
      cases hr : ls.mapM (rowBytesFast t) with
      | none => simp [hb, hr] at h
      | some rest =>
        simp only [hb, hr] at h
        have h' : bl = b :: rest := by simpa using h.symm
        subst h'
        have h1 := parseAdds_one t l b hb ht
        rcases ht with rfl | rfl
        · have hab := parseAdds_append acc b R U _ _ ha h1
          have := ih rest (acc ++ b) _ _ hr hab
          simpa using this
        · have hab := parseAdds_append acc b R U _ _ ha h1
          have := ih rest (acc ++ b) _ _ hr hab
          simpa using this

/-- T0: `load` reads back exactly the rows one `commit` printed as `RULES_ADDS`, in order and per set. Rules out a
    restart that loses, reorders or moves a row between sets. -/
theorem parseAdds_addsBytes (r u : List Line) (bs : ByteArray) (hb : addsBytes r u = some bs) :
    parseAdds bs = some (r, u) := by
  unfold addsBytes at hb
  cases hr : r.mapM (rowBytesFast 1) with
  | none => simp [hr] at hb
  | some rs =>
    cases hu : u.mapM (rowBytesFast 2) with
    | none => simp [hr, hu] at hb
    | some us =>
      simp only [hr, hu] at hb
      have hbs : bs = (rs ++ us).foldl (· ++ ·) ByteArray.empty := by simpa using hb.symm
      subst hbs
      rw [List.foldl_append]
      have h1 := foldl_cat 1 (Or.inl rfl) r rs ByteArray.empty [] [] hr parseAdds_empty
      have h2 := foldl_cat 2 (Or.inr rfl) u us _ _ _ hu (by simpa using h1)
      simpa using h2

theorem ba_foldl {β : Type} (f : β → UInt8 → β) (init : β) (as : ByteArray) :
    as.foldl f init = as.data.toList.foldl f init := by
  unfold ByteArray.foldl ByteArray.foldlM
  simp only [Nat.le_refl, dite_true, Nat.sub_zero, Id.run]
  have key : ∀ (i j : Nat) (b : β), j + i = as.size →
      ByteArray.foldlM.loop (m := Id) (fun x y => pure (f x y)) as as.size (Nat.le_refl _) i j b = (as.data.toList.drop j).foldl f b := by
    intro i
    induction i with
    | zero =>
      intro j b h; unfold ByteArray.foldlM.loop; simp
      rw [List.drop_eq_nil_of_le (by simp; omega)]; rfl
    | succ i ih =>
      intro j b h; unfold ByteArray.foldlM.loop
      rw [dif_pos (by omega)]
      show ByteArray.foldlM.loop (m := Id) _ as as.size _ i (j + 1) (f b as[j]) = _
      rw [ih (j + 1) (f b as[j]) (by omega), List.drop_eq_getElem_cons (i := j) (by simp; omega)]
      simp [List.foldl_cons, ByteArray.getElem_eq_getElem_data]
  have := key as.size 0 init (by omega)
  simpa using this

theorem bget_eq (u : ByteArray) (i : Nat) : u[i]! = (u.data.toList[i]?).getD 0 := by
  by_cases h : i < u.size
  · rw [getElem!_pos u i h, List.getElem?_eq_getElem (by rw [Array.length_toList]; exact h)]
    simp [ByteArray.getElem_eq_getElem_data]
  · rw [getElem!_neg u i h]
    have : u.data.toList[i]? = none := by
      rw [List.getElem?_eq_none_iff, Array.length_toList]
      exact Nat.le_of_not_lt h
    rw [this]; rfl

def dd (n : UInt8) : UInt8 := if n < 10 then 48 + n else 87 + n

def hexStep (a : ByteArray) (x : UInt8) : ByteArray :=
  (a.push (dd (x >>> 4))).push (dd (x &&& 15))

theorem hexOf_eq (b : ByteArray) : hexOf b = String.fromUTF8! (b.data.toList.foldl hexStep (ByteArray.emptyWithCapacity (2 * b.size))) := by
  rw [← ba_foldl]
  rfl

theorem hexStep_data (l : List UInt8) (a : ByteArray) :
    (l.foldl hexStep a).data.toList = a.data.toList ++ l.flatMap (fun x : UInt8 => [dd (x >>> 4), dd (x &&& 15)]) := by
  induction l generalizing a with
  | nil => simp
  | cons x l ih => simp [List.foldl_cons, ih, hexStep]

theorem u8_forall (P : UInt8 → Prop) (h : ∀ k, k < 256 → P (UInt8.ofNat k)) : ∀ n, P n := by
  intro n
  have := h n.toNat (by have := n.toNat_lt; omega)
  simpa using this

theorem dd_ascii : ∀ n : UInt8, n < 16 → dd n < 128 := by
  apply u8_forall (fun n => n < 16 → dd n < 128)
  decide +kernel
theorem nib_dd : ∀ n : UInt8, n < 16 → nib (dd n) = some n := by
  apply u8_forall (fun n => n < 16 → nib (dd n) = some n)
  decide +kernel
theorem shift_lt : ∀ x : UInt8, x >>> 4 < 16 ∧ x &&& 15 < 16 := by
  apply u8_forall
  decide +kernel
theorem pair_eq : ∀ x : UInt8, (x >>> 4) * 16 + (x &&& 15) = x := by
  apply u8_forall
  decide +kernel
theorem ascii_char : ∀ v : UInt8, v < 128 → ∃ c : Char, c.utf8Size = 1 ∧ c.toUInt8 = v := by
  intro v hv
  refine ⟨Char.ofNat v.toNat, ?_⟩
  revert hv
  revert v
  apply u8_forall (fun v => v < 128 → (Char.ofNat v.toNat).utf8Size = 1 ∧ (Char.ofNat v.toNat).toUInt8 = v)
  decide +kernel

theorem hexStep_valid (l : List UInt8) (a : ByteArray) (h : a.IsValidUTF8) : (l.foldl hexStep a).IsValidUTF8 := by
  induction l generalizing a with
  | nil => simpa using h
  | cons x l ih =>
    simp only [List.foldl_cons]
    apply ih
    obtain ⟨c1, s1, e1⟩ := ascii_char (dd (x >>> 4)) (dd_ascii _ (shift_lt x).1)
    obtain ⟨c2, s2, e2⟩ := ascii_char (dd (x &&& 15)) (dd_ascii _ (shift_lt x).2)
    have := ((h.push s1).push s2)
    rw [e1, e2] at this
    exact this

def hexList (bl : List UInt8) : List UInt8 := bl.flatMap (fun x : UInt8 => [dd (x >>> 4), dd (x &&& 15)])

theorem hexList_get (bl : List UInt8) : ∀ (i : Nat) (h : i < bl.length),
    (hexList bl)[2 * i]? = some (dd (bl[i] >>> 4)) ∧ (hexList bl)[2 * i + 1]? = some (dd (bl[i] &&& 15)) := by
  induction bl with
  | nil => intro i h; simp at h
  | cons x t ih =>
    intro i h
    cases i with
    | zero => simp [hexList]
    | succ i =>
      have := ih i (by simpa using h)
      have e1 : 2 * (i + 1) = 2 * i + 2 := by omega
      simp only [hexList] at this ⊢
      rw [e1, List.flatMap_cons]
      simp only [List.cons_append, List.nil_append, List.getElem?_cons_succ, Nat.add_assoc]
      simpa using this

theorem unhexGo_hex (u : ByteArray) (bl : List UInt8) (hu : u.data.toList = hexList bl) :
    ∀ (k i : Nat) (a : ByteArray), i + k ≤ bl.length →
      ∃ r, unhexGo u k i a = some r ∧ r.data.toList = a.data.toList ++ (bl.drop i).take k := by
  intro k
  induction k with
  | zero => intro i a h; exact ⟨a, by simp [unhexGo], by simp⟩
  | succ k ih =>
    intro i a h
    have hi : i < bl.length := by omega
    obtain ⟨g1, g2⟩ := hexList_get bl i hi
    have e1 : u[2 * i]! = dd (bl[i] >>> 4) := by rw [bget_eq, hu, g1]; rfl
    have e2 : u[2 * i + 1]! = dd (bl[i] &&& 15) := by rw [bget_eq, hu, g2]; rfl
    have n1 := nib_dd _ (shift_lt bl[i]).1
    have n2 := nib_dd _ (shift_lt bl[i]).2
    obtain ⟨r, hr, hr2⟩ := ih (i + 1) (a.push bl[i]) (by omega)
    refine ⟨r, ?_, ?_⟩
    · simp [unhexGo, e1, e2, n1, n2, pair_eq, hr]
    · have hd : bl.drop i = bl[i] :: bl.drop (i + 1) := List.drop_eq_getElem_cons hi
      rw [hr2]
      simp
      rw [hd]; rfl

theorem hexList_length (bl : List UInt8) : (hexList bl).length = 2 * bl.length := by
  induction bl with
  | nil => rfl
  | cons x t ih => simp [hexList] at ih ⊢; omega

theorem unhexFast_hexOf (b : ByteArray) : unhexFast (hexOf b) = some b := by
  have hv : (b.data.toList.foldl hexStep (ByteArray.emptyWithCapacity (2 * b.size))).IsValidUTF8 :=
    hexStep_valid _ _ ByteArray.isValidUTF8_empty
  have hd := hexStep_data b.data.toList (ByteArray.emptyWithCapacity (2 * b.size))
  have hu : (hexOf b).toUTF8 = b.data.toList.foldl hexStep (ByteArray.emptyWithCapacity (2 * b.size)) := by
    rw [hexOf_eq]; unfold String.fromUTF8!; rw [dif_pos hv]; rfl
  have hl : (hexOf b).toUTF8.data.toList = hexList b.data.toList := by
    rw [hu, hd]; rfl
  have hsz : (hexOf b).toUTF8.size = 2 * b.size := by
    have := congrArg List.length hl
    rw [hexList_length] at this
    simpa using this
  obtain ⟨r, hr, hr2⟩ := unhexGo_hex _ _ hl b.size 0 (ByteArray.emptyWithCapacity b.size) (by simp)
  have hrb : r = b := by
    apply ByteArray.ext
    apply Array.toList_inj.mp
    rw [hr2]; simp [ByteArray.emptyWithCapacity]
    exact List.take_of_length_le (by rw [Array.length_toList]; exact Nat.le_refl _)
  unfold unhexFast
  simp only [hsz]
  have h2 : (2 * b.size % 2 != 0) = false := by simp
  have h3 : 2 * b.size / 2 = b.size := by omega
  rw [h2, h3]
  simp only [Bool.false_eq_true, if_false]
  rw [hr, hrb]
theorem memo_len (m : Memo) (D : List UInt8) (hd : m.d = some D) : D.length = 64 := by
  have h := m.ok
  rw [hd] at h
  unfold Fast.setsDigestF at h
  cases ha : Fast.pinBytes "RR/GATE/RELEASED/v1" 5 Line.fields m.r with
  | none => simp [ha] at h
  | some a =>
    cases hb : Fast.pinBytes "RR/GATE/UNRESOLVED/v1" 6 Line.fields m.u with
    | none => simp [ha, hb] at h
    | some b =>
      rw [ha, hb] at h
      have h2 : D = Gate.stateDigest (fun x => hB ⟨x.toArray⟩) (hB a) (hB b) := Option.some.inj h
      rw [h2]
      unfold Gate.stateDigest hB
      rw [← Semantic.sha3_512_eq]
      exact Semantic.sha3_512_toList_length _

theorem memo_eta' (m : Memo) (D : List UInt8) (hd : m.d = some D) (h : some D = Fast.setsDigestF hB m.r m.u) :
    (⟨m.r, m.u, some D, h⟩ : Memo) = m := by
  cases m with
  | mk r u d ok => simp only at hd; subst hd; rfl

theorem unhexFast_dash : unhexFast "-" = none := by
  unfold unhexFast
  have : "-".toUTF8.size = 1 := by decide +kernel
  dsimp only
  rw [this]
  rfl

theorem toList_loop (b : ByteArray) : ∀ (n i : Nat) (r : List UInt8), b.size - i = n →
    ByteArray.toList.loop b i r = r.reverse ++ b.data.toList.drop i := by
  intro n
  induction n with
  | zero =>
    intro i r h
    unfold ByteArray.toList.loop
    have : ¬ i < b.size := by omega
    rw [if_neg this]
    have hl : b.data.toList.length ≤ i := by rw [Array.length_toList]; show b.size ≤ i; omega
    rw [List.drop_of_length_le hl]; simp
  | succ n ih =>
    intro i r h
    unfold ByteArray.toList.loop
    have hi : i < b.size := by omega
    rw [if_pos hi, ih (i+1) _ (by omega)]
    have hl : i < b.data.toList.length := by rw [Array.length_toList]; exact hi
    have hd : b.data.toList.drop i = b.data.toList[i] :: b.data.toList.drop (i+1) := List.drop_eq_getElem_cons hl
    rw [hd, get!_eq, List.getElem?_eq_getElem hl]
    simp

theorem tba_toList (D : List UInt8) : D.toByteArray.toList = D := by
  unfold ByteArray.toList
  rw [toList_loop _ _ 0 [] rfl]
  simp

theorem replay_one (r u : Snapshot Line) (ha : u.asOf = r.asOf) (hr : r.count = r.entries.length)
    (hu : u.count = u.entries.length) :
    Rules.replay (⟨r.asOf, 0, []⟩, ⟨r.asOf, 0, []⟩) [(r.entries, u.entries)] = (r, u) := by
  obtain ⟨ra, rc, re⟩ := r
  obtain ⟨ua, uc, ue⟩ := u
  simp only at ha hr hu
  subst ha hr hu
  simp [Rules.replay]

theorem addsField_cases (bs : ByteArray) :
    (addsField bs = "-" ∧ bs = ByteArray.empty) ∨ (addsField bs = hexOf bs ∧ ¬ hexOf bs = "-") := by
  unfold addsField
  by_cases hz : bs.size = 0
  · exact Or.inl ⟨if_pos hz, ByteArray.ext (Array.eq_empty_of_size_eq_zero hz)⟩
  · refine Or.inr ⟨if_neg hz, fun h' => ?_⟩
    have := unhexFast_hexOf bs
    rw [h', unhexFast_dash] at this
    cases this

/-- T1, per step: from ANY state (a head's `today`, snapshots and rows, a `case`, a batch), `resume D` on kept sets is
    `load a adds D` for any `adds` that parse to those sets. Rules out a resume that drops or resets anything `load`
    keeps (snapshots, rows, `today`, the batch) or installs anything `load` would not. -/
theorem resume_eq_load (x : Res) (st : St) (D : List UInt8) (bs : ByteArray) (hx : x.Ok) (hd : x.m.d = some D)
    (hb : parseAdds bs = some (x.m.r.entries, x.m.u.entries)) :
    resume (some x) st (hexOf D.toByteArray) =
      step st ["load", toString x.m.r.asOf, addsField bs, hexOf D.toByteArray] := by
  have hDl := memo_len x.m D hd
  have hbn : Gate.natBE Gate.digestBytes (Gate.beNat D) = D := by
    have := Gate.natBE_beNat D
    rw [hDl] at this
    exact this
  have hcase := addsField_cases bs
  have hdig : Fast.setsDigestF hB x.m.r x.m.u = some D := x.m.ok.symm.trans hd
  obtain ⟨-, -, hasof, hrc, huc, -⟩ := hx
  have hrep := replay_one x.m.r x.m.u hasof hrc huc
  cases hl : (hexOf D.toByteArray).length == 128
  · simp [resume, step, guard, failure, hl]
  · have hu : unhexFast (hexOf D.toByteArray) = some D.toByteArray := unhexFast_hexOf _
    rcases hcase with ⟨hf, rfl⟩ | ⟨hf, hne⟩
    · simp [resume, step, guard, hl, hu, tba_toList, hf, hb, hrep, hdig, hbn, hd, memo_eta', Option.filter_some]
    · simp [resume, step, guard, hl, hu, tba_toList, hf, hne, unhexFast_hexOf, hb, hrep, hdig, hbn, hd, memo_eta',
        Option.filter_some]

/-- T1b: `resume` installs the kept sets only on their exact digest; otherwise it prints the mismatch and changes
    nothing but `failed`. Rules out a resume onto a stale, forked or foreign checkpoint. -/
theorem resume_fail_closed (o : Option Res) (st st' : St) (h : String) (out : List String)
    (hs : resume o st h = some (st', out)) :
    (out = [] ∧ ∃ x bs, o = some x ∧ unhexFast h = some bs ∧
      x.m.d = some (Gate.natBE Gate.digestBytes (Gate.beNat bs.toList)) ∧ st'.memo = some x.m ∧
      st'.rprior = x.m.r ∧ st'.uprior = x.m.u) ∨
    (out = ["RULES_STATE_MISMATCH resume"] ∧ st' = { st with failed := st.failed + 1 }) := by
  unfold resume at hs
  by_cases hl : (h.length == 128) = true
  · cases hu : unhexFast h with
    | none => simp [guard, hl, hu] at hs
    | some bs =>
      simp [guard, hl, hu] at hs
      split at hs
      · rename_i x hx
        cases o with
        | none => simp [Option.filter] at hx
        | some y =>
          simp only [Option.filter] at hx
          split at hx
          · rename_i hp
            cases hx
            cases e1 : emptyPin "released" x.m.r.asOf with
            | none => simp [e1] at hs
            | some p1 =>
              cases e2 : emptyPin "unresolved" x.m.r.asOf with
              | none => simp [e1, e2] at hs
              | some p2 =>
                simp [e1, e2] at hs
                obtain ⟨rfl, rfl⟩ := hs
                left
                exact ⟨rfl, x, bs, rfl, rfl, by simpa using hp, rfl, rfl, rfl⟩
          · cases hx
      · simp at hs
        obtain ⟨rfl, rfl⟩ := hs
        right
        exact ⟨rfl, rfl⟩
  · simp [guard, hl, failure] at hs

theorem toUpper_released : "released".toUpper = "RELEASED" := by decide +kernel
theorem toUpper_unresolved : "unresolved".toUpper = "UNRESOLVED" := by decide +kernel

theorem emptyPin_r (a : Nat) : emptyPin "released" a =
    (Fast.pinBytes "RR/GATE/RELEASED/v1" 5 Line.fields (⟨a, 0, []⟩ : Snapshot Line)).map
      fun b => hexOf (BlindLedger.Semantic.sha3_512Fast b) := by
  simp only [emptyPin, toUpper_released]; rfl

theorem emptyPin_u (a : Nat) : emptyPin "unresolved" a =
    (Fast.pinBytes "RR/GATE/UNRESOLVED/v1" 6 Line.fields (⟨a, 0, []⟩ : Snapshot Line)).map
      fun b => hexOf (BlindLedger.Semantic.sha3_512Fast b) := by
  simp only [emptyPin, toUpper_unresolved]; rfl

/-- A declared empty set with its (recomputed) pin is what `snapshot` returns. -/
theorem snapshot_decl {α : Type} (st : St) (kind : String) (row : List String → Option α) (domain : String) (k : Nat)
    (fields : α → List (Nat × Nat)) (a : Nat) (pb : ByteArray)
    (hs : st.snaps.lookup kind = some (a, 0, hexOf (BlindLedger.Semantic.sha3_512Fast pb)))
    (hr : st.rows.filter (·.1 == kind) = #[])
    (hp : Fast.pinBytes domain k fields (⟨a, 0, []⟩ : Snapshot α) = some pb) :
    snapshot st kind row domain k fields = some (⟨a, 0, []⟩, (BlindLedger.Semantic.sha3_512Fast pb).toList) := by
  simp [snapshot, hs, hr, hp, guard]

theorem rows_released (rows : Array (String × List String)) :
    (rows.filter fun r => r.1 != "released" && r.1 != "unresolved").filter (·.1 == "released") = #[] := by
  apply Array.ext'
  simp [List.filter_eq_nil_iff]
  intro a b _ h1 h2
  exact absurd h1 h2

theorem rows_unresolved (rows : Array (String × List String)) :
    (rows.filter fun r => r.1 != "released" && r.1 != "unresolved").filter (·.1 == "unresolved") = #[] := by
  apply Array.ext'
  simp [List.filter_eq_nil_iff]
  intro a b _ h
  simp_all

/-- What an accepted `resume` does to the state. -/
theorem resume_acc (x : Res) (st st' : St) (h : String) (hs : resume (some x) st h = some (st', [])) :
    ∃ p1 p2, emptyPin "released" x.m.r.asOf = some p1 ∧ emptyPin "unresolved" x.m.r.asOf = some p2 ∧
      st' = { st with
        snaps := ("released", x.m.r.asOf, 0, p1) :: ("unresolved", x.m.r.asOf, 0, p2) :: st.snaps,
        rows := st.rows.filter fun r => r.1 != "released" && r.1 != "unresolved", pinned := none, anchor := none,
        extra := x.m.r.entries, held := x.m.u.entries, rprior := x.m.r, uprior := x.m.u, sealed := true,
        memo := some x.m } := by
  unfold resume at hs
  by_cases hl : (h.length == 128) = true
  · cases hu : unhexFast h with
    | none => simp [guard, hl, hu] at hs
    | some bs =>
      simp [guard, hl, hu] at hs
      split at hs
      · rename_i y hy
        simp only [Option.filter] at hy
        split at hy
        · cases hy
          cases e1 : emptyPin "released" x.m.r.asOf with
          | none => simp [e1] at hs
          | some p1 =>
            cases e2 : emptyPin "unresolved" x.m.r.asOf with
            | none => simp [e1, e2] at hs
            | some p2 =>
              simp [e1, e2] at hs
              exact ⟨p1, p2, rfl, rfl, hs.symm⟩
        · cases hy
      · simp at hs
  · simp [guard, hl, failure] at hs

/-- F1: an accepted `resume` of an `Ok` `Res` leaves a state it fits. -/
theorem resume_fits (x : Res) (st st' : St) (h : String) (hx : x.Ok) (hs : resume (some x) st h = some (st', [])) :
    x.Fits st' := by
  obtain ⟨p1, p2, e1, e2, hst⟩ := resume_acc x st st' h hs
  obtain ⟨⟨-, -, hasOf, hrc, huc, -⟩⟩ := And.intro hx trivial
  rw [emptyPin_r] at e1
  rw [emptyPin_u] at e2
  obtain ⟨pb1, hp1, rfl⟩ := Option.map_eq_some_iff.1 e1
  obtain ⟨pb2, hp2, rfl⟩ := Option.map_eq_some_iff.1 e2
  have hne : ("unresolved" == "released") = false := by decide
  have hpin : st'.pinned = none := by rw [hst]
  have hex : st'.extra = x.m.r.entries := by rw [hst]
  have hhd : st'.held = x.m.u.entries := by rw [hst]
  have s1 := snapshot_decl (α := Line) st' "released" parseLine "RR/GATE/RELEASED/v1" 5 Line.fields x.m.r.asOf pb1
    (by rw [hst]; simp) (by rw [hst]; exact rows_released st.rows) hp1
  have s2 := snapshot_decl (α := Line) st' "unresolved" parseLine "RR/GATE/UNRESOLVED/v1" 6 Line.fields x.m.r.asOf pb2
    (by rw [hst]; simp [List.lookup, hne]) (by rw [hst]; exact rows_unresolved st.rows) hp2
  have hr1 : (⟨x.m.r.asOf, 0 + x.m.r.entries.length, [] ++ x.m.r.entries⟩ : Snapshot Line) = x.m.r := by
    rw [List.nil_append, Nat.zero_add, ← hrc]
  have hr2 : (⟨x.m.r.asOf, 0 + x.m.u.entries.length, [] ++ x.m.u.entries⟩ : Snapshot Line) = x.m.u := by
    rw [List.nil_append, Nat.zero_add, ← huc, ← hasOf]
  refine ⟨hx, by rw [hst], by rw [hst], by rw [hst], ?_, ?_⟩
  · have hp : (st'.ctx (st'.pinned.getD st'.pin)).released =
        grow ((snapshot st' "released" parseLine "RR/GATE/RELEASED/v1" 5 Line.fields).map (·.1)) st'.extra := by
      rw [hpin]; rfl
    rw [hp, s1, hex]
    exact congrArg some hr1
  · have hp : (st'.ctx (st'.pinned.getD st'.pin)).unresolved =
        grow ((snapshot st' "unresolved" parseLine "RR/GATE/UNRESOLVED/v1" 6 Line.fields).map (·.1)) st'.held := by
      rw [hpin]; rfl
    rw [hp, s2, hhd]
    exact congrArg some hr2

theorem memoOf_priors (st : St) : (Res.memoOf st).r = st.rprior ∧ (Res.memoOf st).u = st.uprior := by
  unfold Res.memoOf
  split
  · split
    · rename_i h; exact h
    · exact ⟨rfl, rfl⟩
  · exact ⟨rfl, rfl⟩

/-- F2: `Res.fit` only returns a `Res` that fits (so `Ok` is established, never assumed). Rules out unsorted buffers. -/
theorem fit_fits (st : St) (x : Res) (h : Res.fit st = some x) : x.Fits st := by
  unfold Res.fit at h
  dsimp only at h
  split at h
  · rename_i hc
    obtain ⟨hs, hasof, hrc, huc, hcr, hcu⟩ := hc
    split at h
    · rename_i rs us hr hu
      cases h
      obtain ⟨h1, h2⟩ := memoOf_priors st
      exact ⟨⟨⟨rs, hr, by simp⟩, ⟨us, hu, by simp⟩, hasof, hrc, huc, fun i hi => by simp at hi⟩,
        h1.symm, h2.symm, hs, hcr, hcu⟩
    · cases h
  · cases h

theorem rowsOf_of_pin (dom : String) (k : Nat) (s : Snapshot Line) (pb : ByteArray)
    (h : Fast.pinBytes dom k Line.fields s = some pb) : ∃ rs, rowsOf s.entries = some rs := by
  unfold Fast.pinBytes at h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.1 h
  obtain ⟨rs, hr, -⟩ := Option.bind_eq_some_iff.1 h
  exact ⟨rs, hr⟩

theorem rows_of_digest (r u : Snapshot Line) (d : List UInt8) (h : Fast.setsDigestF hB r u = some d) :
    (∃ rs, rowsOf r.entries = some rs) ∧ (∃ us, rowsOf u.entries = some us) := by
  unfold Fast.setsDigestF at h
  obtain ⟨a, ha, h⟩ := Option.bind_eq_some_iff.1 h
  obtain ⟨b, hb, -⟩ := Option.bind_eq_some_iff.1 h
  exact ⟨rowsOf_of_pin _ _ _ _ ha, rowsOf_of_pin _ _ _ _ hb⟩

theorem memoOf_of (st : St) (m : Memo) (h : st.memo = some m) (hr : m.r = st.rprior) (hu : m.u = st.uprior) :
    Res.memoOf st = m := by
  unfold Res.memoOf
  simp [h, hr, hu]

theorem fit_some (st : St) (rs us : List ByteArray)
    (hc : st.sealed = true ∧ (Res.memoOf st).u.asOf = (Res.memoOf st).r.asOf ∧
      (Res.memoOf st).r.count = (Res.memoOf st).r.entries.length ∧
      (Res.memoOf st).u.count = (Res.memoOf st).u.entries.length ∧
      (st.ctx (st.pinned.getD st.pin)).released = some (Res.memoOf st).r ∧
      (st.ctx (st.pinned.getD st.pin)).unresolved = some (Res.memoOf st).u)
    (hr : rowsOf (Res.memoOf st).r.entries = some rs) (hu : rowsOf (Res.memoOf st).u.entries = some us) :
    ∃ y, Res.fit st = some y ∧ y.m = Res.memoOf st := by
  unfold Res.fit
  dsimp only
  rw [if_pos hc]
  split
  · exact ⟨_, rfl, rfl⟩
  · simp_all

/-- F2: after an accepted `load` (worker start or recycle) `Res.fit` succeeds, reusing the load's digest, and the
    loaded adds parse to the priors. Rules out a load that leaves the worker without a resident checkpoint. -/
theorem load_fits (st st' : St) (a h : String) (bs : ByteArray)
    (hs : step st ["load", a, addsField bs, h] = some (st', [])) :
    (∃ y, Res.fit st' = some y ∧ st'.memo = some y.m) ∧
      parseAdds bs = some (st'.rprior.entries, st'.uprior.entries) := by
  have hc := addsField_cases bs
  by_cases hl' : ¬ (h.length == 128) = true
  · simp [step, guard, hl', failure] at hs
  have hl : (h.length == 128) = true := Decidable.of_not_not hl'
  cases hn : a.toNat? with
  | none => simp [step, guard, hl, hn] at hs
  | some n =>
  cases hu : unhexFast h with
  | none => simp [step, guard, hl, hn, hu] at hs
  | some hb =>
  rcases hc with ⟨hf, rfl⟩ | ⟨hf, hne⟩ <;>
    first
    | simp [step, guard, hl, hn, hu, hf, hne, unhexFast_hexOf] at hs
    | simp [step, guard, hl, hn, hu, hf] at hs
  all_goals
    split at hs
    · simp at hs
    · rename_i s m hsm
      obtain ⟨ad, hpa, h2⟩ := Option.bind_eq_some_iff.1 hsm
      obtain ⟨d, hd, h3⟩ := Option.bind_eq_some_iff.1 h2
      split at h3
      · obtain ⟨hs0, hm0⟩ := Prod.mk.inj (Option.some.inj h3)
        have hrep : Rules.replay (⟨n, 0, []⟩, ⟨n, 0, []⟩) [ad] =
            (⟨n, ad.1.length, ad.1⟩, ⟨n, ad.2.length, ad.2⟩) := by simp [Rules.replay]
        rw [hrep] at hd hs0 hm0
        subst hs0 hm0
        obtain ⟨p1, e1, hs⟩ := Option.bind_eq_some_iff.1 hs
        obtain ⟨p2, e2, hs⟩ := Option.bind_eq_some_iff.1 hs
        obtain ⟨hst, -⟩ := Prod.mk.inj (Option.some.inj hs)
        rw [emptyPin_r] at e1
        rw [emptyPin_u] at e2
        obtain ⟨pb1, hp1, rfl⟩ := Option.map_eq_some_iff.1 e1
        obtain ⟨pb2, hp2, rfl⟩ := Option.map_eq_some_iff.1 e2
        obtain ⟨⟨rs, hrs⟩, ⟨us, hus⟩⟩ := rows_of_digest _ _ _ hd
        have hne2 : ("unresolved" == "released") = false := by decide
        have hpin : st'.pinned = none := by rw [← hst]
        have hex : st'.extra = ad.1 := by rw [← hst]
        have hhd : st'.held = ad.2 := by rw [← hst]
        have hrp : st'.rprior = ⟨n, ad.1.length, ad.1⟩ := by rw [← hst]
        have hup : st'.uprior = ⟨n, ad.2.length, ad.2⟩ := by rw [← hst]
        have hsl : st'.sealed = true := by rw [← hst]
        have hmem := (by rw [← hst] : st'.memo = some _)
        have hmo := memoOf_of st' _ hmem (by rw [hrp]) (by rw [hup])
        have s1 := snapshot_decl (α := Line) st' "released" parseLine "RR/GATE/RELEASED/v1" 5 Line.fields n pb1
          (by rw [← hst]; simp) (by rw [← hst]; exact rows_released st.rows) hp1
        have s2 := snapshot_decl (α := Line) st' "unresolved" parseLine "RR/GATE/UNRESOLVED/v1" 6 Line.fields n pb2
          (by rw [← hst]; simp [List.lookup, hne2]) (by rw [← hst]; exact rows_unresolved st.rows) hp2
        have hr1 : (⟨n, 0 + ad.1.length, [] ++ ad.1⟩ : Snapshot Line) = ⟨n, ad.1.length, ad.1⟩ := by simp
        have hr2 : (⟨n, 0 + ad.2.length, [] ++ ad.2⟩ : Snapshot Line) = ⟨n, ad.2.length, ad.2⟩ := by simp
        refine ⟨?_, ?_⟩
        · have hcc : st'.sealed = true ∧ (Res.memoOf st').u.asOf = (Res.memoOf st').r.asOf ∧
              (Res.memoOf st').r.count = (Res.memoOf st').r.entries.length ∧
              (Res.memoOf st').u.count = (Res.memoOf st').u.entries.length ∧
              (st'.ctx (st'.pinned.getD st'.pin)).released = some (Res.memoOf st').r ∧
              (st'.ctx (st'.pinned.getD st'.pin)).unresolved = some (Res.memoOf st').u := by
            rw [hmo]
            refine ⟨hsl, rfl, rfl, rfl, ?_, ?_⟩
            · have hp : (st'.ctx (st'.pinned.getD st'.pin)).released =
                  grow ((snapshot st' "released" parseLine "RR/GATE/RELEASED/v1" 5 Line.fields).map (·.1)) st'.extra := by
                rw [hpin]; rfl
              rw [hp, s1, hex]
              exact congrArg some hr1
            · have hp : (st'.ctx (st'.pinned.getD st'.pin)).unresolved =
                  grow ((snapshot st' "unresolved" parseLine "RR/GATE/UNRESOLVED/v1" 6 Line.fields).map (·.1)) st'.held := by
                rw [hpin]; rfl
              rw [hp, s2, hhd]
              exact congrArg some hr2
          have hrs' : rowsOf (Res.memoOf st').r.entries = some rs := by rw [hmo]; exact hrs
          have hus' : rowsOf (Res.memoOf st').u.entries = some us := by rw [hmo]; exact hus
          obtain ⟨y, hy, hym⟩ := fit_some st' rs us hcc hrs' hus'
          exact ⟨y, hy, by rw [hym, hmo]; exact hmem⟩
        · rw [hrp, hup]; exact hpa
      · simp at h3

/-- T4: a kept index refreshed for a new frame (same `today`, same sets) is the index a full build makes. With
    `decideBatchFIn_eq` it decides as `decideBatchIn`. Rules out stale snapshot, redo or batch parts. -/
theorem refresh_eq (c c' : Ctx) (b₀ b : List Line) (ht : c'.today = c.today)
    (hr : c'.released = c.released) (hrp : c'.releasedPrior = c.releasedPrior)
    (hu : c'.unresolved = c.unresolved) (hup : c'.unresolvedPrior = c.unresolvedPrior) :
    refresh (Fast.Ix.build c b₀) c' b = Fast.Ix.build c' b := by
  simp only [refresh, Fast.Ix.build, ht, hr, hrp, hu, hup]

theorem view_self (t : Nat) (p : Snapshot Line) : view t p (some p) = p := by
  simp only [view]; split <;> rfl

theorem advance_self_ex (t : Nat) (p : Snapshot Line) (adds : List Line) {o : Option (Snapshot Line)} (h : o = some p) :
    ∃ A, advance t p o adds = ⟨p.asOf, p.entries.length + A.length, p.entries ++ A⟩ :=
  ⟨adds, by subst h; simp [advance, view_self]⟩

theorem viewF_self (b : Bool) (p : Snapshot Line) : Fast.viewF b p (some p) = p := by cases b <;> rfl

theorem looseF_self (b : Bool) (p : Snapshot Line) : Fast.looseF b p (some p) = [] := by
  cases b
  · simp [Fast.looseF, entries]
  · rfl

theorem chainedF_self (t : Nat) (p : Snapshot Line) :
    Fast.chainedF t p (some p) = (p.entries.length == p.count && validDate p.asOf && decide (p.asOf ≤ t)) := by
  simp [Fast.chainedF]

theorem posts_ext (P A : List Line) : (A.foldl Fast.postStep ((Fast.posts P).1, P.length)).1 = (Fast.posts (P ++ A)).1 := by
  rw [Fast.posts_append, ← Fast.posts_count P]

/-- T4: the index extended by a commit's fresh rows, refreshed for the next frame's context over the committed sets,
    is the index a full build over that context makes. Rules out a missing, duplicated or misplaced posting. -/
theorem ix_extend_eq (c c' : Ctx) (f : List Nat) (b₀ b : List Line)
    (hr : c.released = some c.releasedPrior) (hu : c.unresolved = some c.unresolvedPrior) (ht : c'.today = c.today)
    (hr' : c'.released = some (decideBatchIn c f b₀).released) (hrp : c'.releasedPrior = (decideBatchIn c f b₀).released)
    (hu' : c'.unresolved = some (decideBatchIn c f b₀).unresolved)
    (hup : c'.unresolvedPrior = (decideBatchIn c f b₀).unresolved) :
    refresh (extend (Fast.Ix.build c b₀) (decideBatchIn c f b₀).released (decideBatchIn c f b₀).unresolved) c' b =
      Fast.Ix.build c' b := by
  obtain ⟨A, hA⟩ := advance_self_ex c.today c.releasedPrior (releasedLines c (decideAll c (idSeen f ++ seen0 c b₀) (order c b₀))) hr
  obtain ⟨B, hB⟩ := advance_self_ex c.today c.unresolvedPrior (unresolvedLines c (decideAll c (idSeen f ++ seen0 c b₀) (order c b₀))) hu
  have eA : (decideBatchIn c f b₀).released = ⟨c.releasedPrior.asOf, c.releasedPrior.entries.length + A.length, c.releasedPrior.entries ++ A⟩ := by
    simp only [decideBatchIn]; rw [hr] at hA ⊢; exact hA
  have eB : (decideBatchIn c f b₀).unresolved = ⟨c.unresolvedPrior.asOf, c.unresolvedPrior.entries.length + B.length, c.unresolvedPrior.entries ++ B⟩ := by
    simp only [decideBatchIn]; rw [hu] at hB ⊢; exact hB
  rw [eA] at hr' hrp
  rw [eB] at hu' hup
  rw [eA, eB]
  simp only [refresh, extend, Fast.Ix.build, hr, hu, hr', hrp, hu', hup, ht, viewF_self, looseF_self, chainedF_self]
  simp only [List.append_nil, List.drop_left, posts_ext]
  simp [List.length_append, List.drop_length]

/-- `s` does not begin like `RULES_ADDS ` (its first eight characters, `RULES_AD`, differ). -/
def NA (s : String) : Prop := s.toList.take 8 ≠ "RULES_ADDS ".toList.take 8

theorem na_app (a t : String) (h1 : NA a) (h2 : 8 ≤ a.toList.length) : NA (a ++ t) := by
  unfold NA at *
  simpa [String.toList_append, List.take_append_of_le_length h2] using h1

theorem not_na_adds (y : String) : ¬ NA ("RULES_ADDS " ++ y) := by
  unfold NA
  intro h
  apply h
  simp only [String.toList_append]
  exact List.take_append_of_le_length (by decide)

instance (s : String) : Decidable (NA s) := by unfold NA; infer_instance

/-- `NA` with room for the eight characters it inspects, so appending keeps it. -/
def Pre (s : String) : Prop := NA s ∧ 8 ≤ s.toList.length

instance (s : String) : Decidable (Pre s) := by unfold Pre; infer_instance

theorem pre_app (a t : String) (h : Pre a) : Pre (a ++ t) :=
  ⟨na_app a t h.1 h.2, by rw [String.toList_append, List.length_append]; exact Nat.le_trans h.2 (Nat.le_add_right _ _)⟩

theorem pre_na {s : String} (h : Pre s) : NA s := h.1

macro "na_tac" : tactic =>
  `(tactic| (apply pre_na; repeat' (first | decide | apply pre_app)))

theorem na_free (ids : List String) : NA (" ".intercalate ("RULES_FREE" :: ids)) := by
  cases ids with
  | nil => rw [String.intercalate_singleton]; na_tac
  | cons x l =>
    rw [String.intercalate_cons_of_ne_nil (by simp)]
    exact pre_na (pre_app _ _ (pre_app _ _ (by decide)))

/-- A printed line is not a `RULES_ADDS` line, or it is the one for `ad`. -/
def Good (ad : Option ByteArray) (e : String) : Prop :=
  NA e ∨ ∃ bb, e = "RULES_ADDS " ++ hexOf bb ∧ ad = some bb

theorem good_app {ad : Option ByteArray} {l1 l2 : List String} (h1 : ∀ e ∈ l1, Good ad e)
    (h2 : ∀ e ∈ l2, Good ad e) : ∀ e ∈ l1 ++ l2, Good ad e := by
  intro e he
  rcases List.mem_append.1 he with h | h
  · exact h1 e h
  · exact h2 e h

theorem na_append {l1 l2 : List String} (h1 : ∀ e ∈ l1, NA e) (h2 : ∀ e ∈ l2, NA e) : ∀ e ∈ l1 ++ l2, NA e := by
  intro e he
  rcases List.mem_append.1 he with h | h
  · exact h1 e h
  · exact h2 e h

theorem good_pre {ad : Option ByteArray} {α : Type} (a : String) (g : α → String) (L : List α) (h : Pre a) :
    ∀ e ∈ L.map (fun x => a ++ g x), Good ad e := by
  intro e he
  obtain ⟨x, -, rfl⟩ := List.mem_map.1 he
  exact Or.inl (pre_app a _ h).1

/-- The tail of `commit`'s output: a mismatch line and the notes, all non-`RULES_ADDS`. -/
theorem good_tail (ad : Option ByteArray) (S M : List String) (c : Prop) [Decidable c]
    (hS : ∀ e ∈ S, Good ad e) (hM : ∀ e ∈ M, NA e) :
    ∀ e ∈ S ++ (if c then [] else "RULES_VECTOR_MISMATCH commit" :: M), Good ad e := by
  refine good_app hS ?_
  by_cases hc : c
  · simp [hc]
  · simp only [if_neg hc]
    intro e he
    rcases List.mem_cons.1 he with rfl | h
    · exact Or.inl (show Pre "RULES_VECTOR_MISMATCH commit" by decide).1
    · exact Or.inl (hM e h)

theorem grow_app (o : Option (Snapshot Line)) (xs ys : List Line) : grow (grow o xs) ys = grow o (xs ++ ys) := by
  cases o <;> simp [grow, List.length_append, Nat.add_assoc, List.append_assoc]

/-- The batch, ids and waiting lines `commit` decides (its `owners` match). -/
def cbf (st : St) : List Line × List Nat × List Line :=
  match st.owners with
  | some (k, os) =>
    let b := Fast.readyF k os (st.batch.toList.map (·.1))
    let ps := Std.HashSet.ofList (b.map (·.pay))
    (b, Fast.foreignOfF k os b, (st.batch.toList.map (·.1)).filter fun l => !ps.contains l.pay)
  | none => (st.batch.toList.map (·.1), st.foreign, [])

/-- `commit`, split into its two exits. Exit 1 (the anchor does not match): the sets are untouched and nothing but a
    non-`RULES_ADDS` line is printed. Exit 2: it decided `b` with ids `f` over the context; its sets are the run's, its
    new rows are the run's fresh ones, and every printed line is a non-`RULES_ADDS` line or the one `RULES_ADDS` of
    those fresh rows. -/
theorem commit_struct (st : St) (u : Bool) :
    let p := st.pinned.getD st.pin
    let st' := (commit st u).1
    st'.pinned = some p ∧ st'.today = st.today ∧ st'.memo = st.memo ∧
    ((st.anchor.isSome = true ∧ st'.extra = st.extra ∧ st'.held = st.held ∧ st'.rprior = st.rprior ∧
        st'.uprior = st.uprior ∧ ∀ e ∈ (commit st u).2, NA e) ∨
     st'.sealed = true ∧
        st'.extra = st.extra ++ ((Fast.Ix.build (st.ctx p) (cbf st).1).runIn (cbf st).2.1 (cbf st).1).released.entries.drop (Fast.Ix.build (st.ctx p) (cbf st).1).relN ∧
        st'.held = st.held ++ ((Fast.Ix.build (st.ctx p) (cbf st).1).runIn (cbf st).2.1 (cbf st).1).unresolved.entries.drop (Fast.Ix.build (st.ctx p) (cbf st).1).unrN ∧
        st'.rprior = ((Fast.Ix.build (st.ctx p) (cbf st).1).runIn (cbf st).2.1 (cbf st).1).released ∧
        st'.uprior = ((Fast.Ix.build (st.ctx p) (cbf st).1).runIn (cbf st).2.1 (cbf st).1).unresolved ∧
        ∀ e ∈ (commit st u).2, NA e ∨ ∃ bb, e = "RULES_ADDS " ++ hexOf bb ∧
          addsBytes (((Fast.Ix.build (st.ctx p) (cbf st).1).runIn (cbf st).2.1 (cbf st).1).released.entries.drop (Fast.Ix.build (st.ctx p) (cbf st).1).relN)
            (((Fast.Ix.build (st.ctx p) (cbf st).1).runIn (cbf st).2.1 (cbf st).1).unresolved.entries.drop (Fast.Ix.build (st.ctx p) (cbf st).1).unrN) = some bb) := by
  intro p st'
  dsimp only [p, st']
  unfold commit
  dsimp only
  by_cases hA : (!st.anchor.all fun a => (if st.sealed || st.anchor.isSome then Memo.get st.memo (st.ctx (st.pinned.getD st.pin)).releasedPrior (st.ctx (st.pinned.getD st.pin)).unresolvedPrior else none) == some (Gate.natBE Gate.digestBytes a)) = true
  · simp only [if_pos hA]
    refine ⟨trivial, trivial, trivial, Or.inl ⟨?_, trivial, trivial, trivial, trivial, ?_⟩⟩
    · cases ha : st.anchor with
      | none => simp [ha] at hA
      | some a => rfl
    · intro e he
      cases u <;> simp at he <;> (subst he; unfold NA; decide)
  · simp only [if_neg hA]
    refine ⟨trivial, trivial, trivial, Or.inr ?_⟩
    rcases ho : st.owners with _ | ⟨k, os⟩
    all_goals simp only [ho, cbf, Option.map, Option.elim]
    all_goals refine ⟨trivial, trivial, trivial, trivial, trivial, ?_⟩
    all_goals refine good_tail _ _ _ _ ?_ ?_
    · intro e he; simp at he
    · 
      refine na_append (na_append (na_append ?_ ?_) ?_) ?_
      · intro e he
        split at he
        · simp at he
        · split at he
          · simp at he
          · obtain ⟨x, -, rfl⟩ := List.mem_map.1 he
            na_tac
      · intro e he
        obtain ⟨x, -, rfl⟩ := List.mem_map.1 he
        na_tac
      · intro e he
        split at he
        · simp only [List.mem_singleton] at he
          subst he
          na_tac
        · simp at he
      · intro e he
        split at he
        · simp at he
        · simp only [List.mem_singleton] at he
          subst he
          na_tac
    · refine good_app (good_app (good_app (good_app ?_ ?_) ?_) ?_) ?_
      · exact good_pre _ _ _ (by decide)
      · intro e he
        simp only [List.mem_singleton] at he
        subst he
        exact Or.inl (na_free _)
      · exact good_pre _ _ _ (by decide)
      · intro e he
        obtain ⟨x, hx, rfl⟩ := List.mem_map.1 he
        right
        exact ⟨x, rfl, Option.mem_toList.1 hx⟩
      · exact good_pre _ _ _ (by decide)
    · 
      refine na_append (na_append (na_append ?_ ?_) ?_) ?_
      · intro e he
        split at he
        · simp at he
        · split at he
          · simp at he
          · obtain ⟨x, -, rfl⟩ := List.mem_map.1 he
            na_tac
      · intro e he
        obtain ⟨x, -, rfl⟩ := List.mem_map.1 he
        na_tac
      · intro e he
        split at he
        · simp only [List.mem_singleton] at he
          subst he
          na_tac
        · simp at he
      · intro e he
        split at he
        · simp at he
        · simp only [List.mem_singleton] at he
          subst he
          na_tac

/-- The batch run's sets are the views plus the fresh rows. -/
theorem runIn_view (c : Ctx) (f : List Nat) (b : List Line) (P Q : Snapshot Line)
    (hr : Fast.viewF (Fast.chainedF c.today c.releasedPrior c.released) c.releasedPrior c.released = P)
    (hu : Fast.viewF (Fast.chainedF c.today c.unresolvedPrior c.unresolved) c.unresolvedPrior c.unresolved = Q) :
    ∃ ra ua, ((Fast.Ix.build c b).runIn f b).released = ⟨P.asOf, P.entries.length + ra.length, P.entries ++ ra⟩ ∧
      ((Fast.Ix.build c b).runIn f b).unresolved = ⟨Q.asOf, Q.entries.length + ua.length, Q.entries ++ ua⟩ ∧
      (Fast.Ix.build c b).relN = P.entries.length ∧ (Fast.Ix.build c b).unrN = Q.entries.length := by
  have h1 : (Fast.Ix.build c b).relV = P := hr
  have h2 : (Fast.Ix.build c b).unrV = Q := hu
  have h3 : (Fast.Ix.build c b).relN = P.entries.length := congrArg (fun s : Snapshot Line => s.entries.length) hr
  have h4 : (Fast.Ix.build c b).unrN = Q.entries.length := congrArg (fun s : Snapshot Line => s.entries.length) hu
  refine ⟨(Fast.Ix.build c b).releasedLines ((Fast.Ix.build c b).decideAll (Std.HashSet.ofList (idSeen f)) ((Fast.Ix.build c b).order b)),
    (Fast.Ix.build c b).unresolvedLines ((Fast.Ix.build c b).decideAll (Std.HashSet.ofList (idSeen f)) ((Fast.Ix.build c b).order b)),
    ?_, ?_, h3, h4⟩
  · simp only [Fast.Ix.runIn, h1, h3]
  · simp only [Fast.Ix.runIn, h2, h4]

theorem chainedF_some (t : Nat) (p : Snapshot Line) (o : Option (Snapshot Line)) (h : Fast.chainedF t p o = true) :
    ∃ s, o = some s ∧ s.count = s.entries.length := by
  cases o with
  | none => simp [Fast.chainedF] at h
  | some s =>
    refine ⟨s, rfl, ?_⟩
    simp only [Fast.chainedF, Bool.and_eq_true, beq_iff_eq] at h
    exact h.1.1.1.1.symm

theorem viewF_chained (t : Nat) (p s : Snapshot Line) (o : Option (Snapshot Line)) (h : Fast.chainedF t p o = true)
    (ho : o = some s) : Fast.viewF (Fast.chainedF t p o) p o = s := by
  rw [h, ho]; rfl

/-- `Res.fit` succeeds on a sealed state that reads its own priors (one date, counts = lengths) when their digest exists. -/
theorem fit_of_priors (S : St) (hs : S.sealed = true) (ha : S.uprior.asOf = S.rprior.asOf)
    (hrc : S.rprior.count = S.rprior.entries.length) (huc : S.uprior.count = S.uprior.entries.length)
    (hcr : (S.ctx (S.pinned.getD S.pin)).released = some S.rprior)
    (hcu : (S.ctx (S.pinned.getD S.pin)).unresolved = some S.uprior)
    (hg : (Fast.setsDigestF hB S.rprior S.uprior).isSome) : ∃ y, Res.fit S = some y := by
  obtain ⟨d, hd⟩ := Option.isSome_iff_exists.1 hg
  obtain ⟨⟨rs, hrs⟩, ⟨us, hus⟩⟩ := rows_of_digest _ _ _ hd
  obtain ⟨h1, h2⟩ := memoOf_priors S
  obtain ⟨y, hy, -⟩ := fit_some S rs us
    ⟨hs, by rw [h1, h2]; exact ha, by rw [h1]; exact hrc, by rw [h2]; exact huc, by rw [h1]; exact hcr,
      by rw [h2]; exact hcu⟩ (by rw [h1]; exact hrs) (by rw [h2]; exact hus)
  exact ⟨y, hy⟩

/-- A genesis commit over chained declared sets `s`, `t`: its sets are theirs plus the run's fresh rows, and its
    RULES_ADDS parse to those rows. -/
theorem commit_view (st : St) (u : Bool) (ha : st.anchor = none)
    (hr : Fast.chainedF st.today st.rprior (st.ctx (st.pinned.getD st.pin)).released = true)
    (hu : Fast.chainedF st.today st.uprior (st.ctx (st.pinned.getD st.pin)).unresolved = true) :
    ∃ s t ra ua, (st.ctx (st.pinned.getD st.pin)).released = some s ∧
      (st.ctx (st.pinned.getD st.pin)).unresolved = some t ∧ s.count = s.entries.length ∧ t.count = t.entries.length ∧
      (commit st u).1.rprior = ⟨s.asOf, s.entries.length + ra.length, s.entries ++ ra⟩ ∧
      (commit st u).1.uprior = ⟨t.asOf, t.entries.length + ua.length, t.entries ++ ua⟩ ∧
      (commit st u).1.extra = st.extra ++ ra ∧ (commit st u).1.held = st.held ++ ua ∧
      (commit st u).1.sealed = true ∧ (commit st u).1.pinned = some (st.pinned.getD st.pin) ∧
      ∀ b, ("RULES_ADDS " ++ hexOf b) ∈ (commit st u).2 → parseAdds b = some (ra, ua) := by
  obtain ⟨hp, ht, hm, H⟩ := commit_struct st u
  obtain ⟨s, hs, hsc⟩ := chainedF_some _ _ _ hr
  obtain ⟨t, ht', htc⟩ := chainedF_some _ _ _ hu
  rcases H with ⟨hanc, -⟩ | ⟨hsl, he, hh, hr', hu', hAD⟩
  · rw [ha] at hanc; exact absurd hanc (by simp)
  · obtain ⟨ra, ua, hR, hU, hrn, hun⟩ := runIn_view (st.ctx (st.pinned.getD st.pin)) (cbf st).2.1 (cbf st).1 s t
      (viewF_chained _ _ _ _ hr hs) (viewF_chained _ _ _ _ hu ht')
    simp only [hrn, hun, hR, hU, List.drop_left] at hr' hu' he hh hAD
    refine ⟨s, t, ra, ua, hs, ht', hsc, htc, hr', hu', he, hh, hsl, hp, ?_⟩
    intro b hb
    rcases hAD _ hb with h | ⟨bb, hbb, hab⟩
    · exact absurd h (not_na_adds _)
    · have hh2 : hexOf b = hexOf bb := (String.append_right_inj _).1 hbb
      have : b = bb := by
        have := congrArg unhexFast hh2
        rw [unhexFast_hexOf, unhexFast_hexOf] at this
        exact Option.some.inj this
      subst this
      exact parseAdds_addsBytes _ _ _ hab

/-- F2: a genesis commit (not sealed, no anchor) over declared sets that are chained, of one date, with a digest,
    gives a fitting `Res`. Rules out a first frame that can never reach the resident path. -/
theorem commit_genesis_fits (st : St) (u : Bool) (hs : st.sealed = false) (ha : st.anchor = none)
    (hr : Fast.chainedF st.today st.rprior (st.ctx (st.pinned.getD st.pin)).released = true)
    (hu : Fast.chainedF st.today st.uprior (st.ctx (st.pinned.getD st.pin)).unresolved = true)
    (hd : (st.ctx (st.pinned.getD st.pin)).released.map (·.asOf) =
      (st.ctx (st.pinned.getD st.pin)).unresolved.map (·.asOf))
    (hg : (Fast.setsDigestF hB (commit st u).1.rprior (commit st u).1.uprior).isSome) :
    ∃ y, Res.fit (commit st u).1 = some y := by
  obtain ⟨s, t, ra, ua, hs0, ht0, hsc, htc, hrS, huS, hex, hhd, hsl, hpS, -⟩ := commit_view st u ha hr hu
  have hp' : (commit st u).1.pinned.getD (commit st u).1.pin = st.pinned.getD st.pin := by rw [hpS]; rfl
  have hd' : t.asOf = s.asOf := by
    rw [hs0, ht0] at hd
    exact (Option.some.inj hd).symm
  refine fit_of_priors _ hsl (by rw [hrS, huS]; exact hd') (by rw [hrS]; simp) (by rw [huS]; simp) ?_ ?_ hg
  · rw [hp']; simp only [St.ctx, hex]
    simp only [St.ctx] at hs0
    rw [← grow_app, hs0, hrS]; simp [grow, hsc]
  · rw [hp']; simp only [St.ctx, hhd]
    simp only [St.ctx] at ht0
    rw [← grow_app, ht0, huS]; simp [grow, htc]

/-- N1: a genesis commit over empty declared sets (the head's `<asOf, 0, []>`; genesis sends no `load`) prints
    RULES_ADDS that parse to exactly the committed sets, so `resident_inv` starts from the first batch. Rules out a
    live genesis `Res` whose rows are not the sealed adds. -/
theorem commit_genesis_adds (st : St) (u : Bool) (hs : st.sealed = false) (ha : st.anchor = none)
    (hr : Fast.chainedF st.today st.rprior (st.ctx (st.pinned.getD st.pin)).released = true)
    (hu : Fast.chainedF st.today st.uprior (st.ctx (st.pinned.getD st.pin)).unresolved = true)
    (he : (st.ctx (st.pinned.getD st.pin)).released.map (·.entries) = some [] ∧
      (st.ctx (st.pinned.getD st.pin)).unresolved.map (·.entries) = some []) :
    ∀ b, ("RULES_ADDS " ++ hexOf b) ∈ (commit st u).2 →
      parseAdds b = some ((commit st u).1.rprior.entries, (commit st u).1.uprior.entries) := by
  obtain ⟨s, t, ra, ua, hs0, ht0, -, -, hrS, huS, -, -, -, -, hadd⟩ := commit_view st u ha hr hu
  intro b hb
  rw [hrS, huS]
  rw [hs0] at he
  rw [ht0] at he
  have e1 : s.entries = [] := Option.some.inj he.1
  have e2 : t.entries = [] := Option.some.inj he.2
  show parseAdds b = some (s.entries ++ ra, t.entries ++ ua)
  rw [e1, e2]
  exact hadd b hb

theorem memo_get_fits (st : St) (x : Res) (r u : Snapshot Line) (hr : x.m.r = r) (hu : x.m.u = u) :
    Memo.get st.memo r u = x.m.d := by
  have hx : x.m.d = Fast.setsDigestF hB r u := x.m.ok.trans (by rw [hr, hu])
  unfold Memo.get
  split
  · rename_i m _
    split
    · rename_i h
      have e : m.d = Fast.setsDigestF hB r u := m.ok.trans (by rw [h.1, h.2])
      exact e.trans hx.symm
    · exact hx.symm
  · exact hx.symm

theorem ixFor_eq (x : Res) (c : Ctx) (b : List Line) (hx : x.Ok) (hr : c.released = some x.m.r)
    (hrp : c.releasedPrior = x.m.r) (hu : c.unresolved = some x.m.u) (hup : c.unresolvedPrior = x.m.u) :
    x.ixFor c b = Fast.Ix.build c b := by
  unfold Res.ixFor
  cases hi : x.ix with
  | none => rfl
  | some i =>
    obtain ⟨c0, b0, hi0, h1, h2, h3, h4⟩ := hx.2.2.2.2.2 i hi
    simp only
    split
    · rename_i ht
      subst hi0
      exact refresh_eq c0 c b0 b ht.symm (by rw [hr, h1]) (by rw [hrp, h2]) (by rw [hu, h3]) (by rw [hup, h4])
    · rfl

/-- `c` reading `R`, `U` as its sets and priors. -/
def advCtx (c : Ctx) (R U : Snapshot Line) : Ctx :=
  { c with
    released := some R
    releasedPrior := R
    unresolved := some U
    unresolvedPrior := U }

/-- The index extended by a commit's rows is a build over the context that reads the new sets as its priors. -/
theorem ix_extend_build (c : Ctx) (f : List Nat) (b : List Line)
    (hr : c.released = some c.releasedPrior) (hu : c.unresolved = some c.unresolvedPrior) :
    ∃ c', extend (Fast.Ix.build c b) (decideBatchIn c f b).released (decideBatchIn c f b).unresolved = Fast.Ix.build c' b ∧
      c'.released = some (decideBatchIn c f b).released ∧ c'.releasedPrior = (decideBatchIn c f b).released ∧
      c'.unresolved = some (decideBatchIn c f b).unresolved ∧ c'.unresolvedPrior = (decideBatchIn c f b).unresolved := by
  refine ⟨advCtx c (decideBatchIn c f b).released (decideBatchIn c f b).unresolved, ?_, rfl, rfl, rfl, rfl⟩
  have h := ix_extend_eq c (advCtx c (decideBatchIn c f b).released (decideBatchIn c f b).unresolved) f b b hr hu
    rfl rfl rfl rfl rfl
  rw [← h]
  rfl

theorem run_shape (x : Res) (c : Ctx) (b : List Line) (f : List Nat) (hx : x.Ok)
    (hr : c.released = some x.m.r) (hrp : c.releasedPrior = x.m.r)
    (hu : c.unresolved = some x.m.u) (hup : c.unresolvedPrior = x.m.u) :
    ∃ ra ua, ((Fast.Ix.build c b).runIn f b).released = ⟨x.m.r.asOf, x.m.r.count + ra.length, x.m.r.entries ++ ra⟩ ∧
      ((Fast.Ix.build c b).runIn f b).unresolved = ⟨x.m.u.asOf, x.m.u.count + ua.length, x.m.u.entries ++ ua⟩ ∧
      (Fast.Ix.build c b).relN = x.m.r.entries.length ∧ (Fast.Ix.build c b).unrN = x.m.u.entries.length := by
  obtain ⟨ra, ua, hR, hU, hrn, hun⟩ := runIn_view c f b x.m.r x.m.u
    (by rw [hr, hrp]; exact viewF_self _ _) (by rw [hu, hup]; exact viewF_self _ _)
  refine ⟨ra, ua, ?_, ?_, hrn, hun⟩
  · rw [hR, hx.2.2.2.1]
  · rw [hU, hx.2.2.2.2.1]

theorem next_some (x : Res) (i : Fast.Ix) (fr fu : List Line) (y : Res) (hy : x.next i fr fu = some y) :
    y.m.r = ⟨x.m.r.asOf, x.m.r.count + fr.length, x.m.r.entries ++ fr⟩ ∧
    y.m.u = ⟨x.m.u.asOf, x.m.u.count + fu.length, x.m.u.entries ++ fu⟩ ∧ y.ix = some (extend i y.m.r y.m.u) := by
  unfold Res.next at hy
  split at hy
  · simp at hy
  · obtain rfl := Option.some.inj hy
    exact ⟨rfl, rfl, rfl⟩

theorem next_ok (x : Res) (c : Ctx) (b : List Line) (f : List Nat) (hx : x.Ok)
    (hr : c.released = some x.m.r) (hrp : c.releasedPrior = x.m.r)
    (hu : c.unresolved = some x.m.u) (hup : c.unresolvedPrior = x.m.u) (y : Res)
    (hy : x.next (Fast.Ix.build c b) (((Fast.Ix.build c b).runIn f b).released.entries.drop (Fast.Ix.build c b).relN)
      (((Fast.Ix.build c b).runIn f b).unresolved.entries.drop (Fast.Ix.build c b).unrN) = some y) :
    ∃ ra ua, y.Ok ∧ y.m.r = ((Fast.Ix.build c b).runIn f b).released ∧
      y.m.u = ((Fast.Ix.build c b).runIn f b).unresolved ∧
      ((Fast.Ix.build c b).runIn f b).released = ⟨x.m.r.asOf, x.m.r.count + ra.length, x.m.r.entries ++ ra⟩ ∧
      ((Fast.Ix.build c b).runIn f b).unresolved = ⟨x.m.u.asOf, x.m.u.count + ua.length, x.m.u.entries ++ ua⟩ ∧
      ((Fast.Ix.build c b).runIn f b).released.entries.drop (Fast.Ix.build c b).relN = ra ∧
      ((Fast.Ix.build c b).runIn f b).unresolved.entries.drop (Fast.Ix.build c b).unrN = ua := by
  generalize hR0 : (Fast.Ix.build c b).runIn f b = R at hy ⊢
  obtain ⟨ra, ua, hR, hU, hrn, hun⟩ := run_shape x c b f hx hr hrp hu hup
  rw [hR0] at hR hU
  have e1 : R.released.entries.drop (Fast.Ix.build c b).relN = ra := by rw [hR, hrn]; exact List.drop_left
  have e2 : R.unresolved.entries.drop (Fast.Ix.build c b).unrN = ua := by rw [hU, hun]; exact List.drop_left
  rw [e1, e2] at hy
  obtain ⟨hyr, hyu, hyi⟩ := next_some x _ _ _ y hy
  have hyr' : y.m.r = R.released := by rw [hyr, hR]
  have hyu' : y.m.u = R.unresolved := by rw [hyu, hU]
  refine ⟨ra, ua, ?_, hyr', hyu', hR, hU, e1, e2⟩
  refine ⟨y.bok.1, y.bok.2, ?_, ?_, ?_, ?_⟩
  · rw [hyr', hyu', hR, hU]; exact hx.2.2.1
  · rw [hyr]; simp [hx.2.2.2.1]
  · rw [hyu]; simp [hx.2.2.2.2.1]
  · intro i' hi'
    rw [hyi] at hi'
    obtain ⟨c', hc', h1, h2, h3, h4⟩ := ix_extend_build c f b (by rw [hr, hrp]) (by rw [hu, hup])
    have hd : R = decideBatchIn c f b := by rw [← hR0]; exact Fast.decideBatchFIn_eq c f b
    rw [← hd] at hc' h1 h2 h3 h4
    rw [← hyr', ← hyu'] at hc'
    rw [← hyr'] at h1 h2
    rw [← hyu'] at h3 h4
    exact ⟨c', b, (Option.some.inj hi').symm.trans hc', h1, h2, h3, h4⟩

theorem fits_main (x : Res) (st S : St) (b : List Line) (f : List Nat) (hf : x.Fits st)
    (y : Res) (hy : x.next (Fast.Ix.build (st.ctx (st.pinned.getD st.pin)) b)
      (((Fast.Ix.build (st.ctx (st.pinned.getD st.pin)) b).runIn f b).released.entries.drop
        (Fast.Ix.build (st.ctx (st.pinned.getD st.pin)) b).relN)
      (((Fast.Ix.build (st.ctx (st.pinned.getD st.pin)) b).runIn f b).unresolved.entries.drop
        (Fast.Ix.build (st.ctx (st.pinned.getD st.pin)) b).unrN) = some y)
    (hp : S.pinned = some (st.pinned.getD st.pin)) (hsl : S.sealed = true)
    (hrS : S.rprior = ((Fast.Ix.build (st.ctx (st.pinned.getD st.pin)) b).runIn f b).released)
    (huS : S.uprior = ((Fast.Ix.build (st.ctx (st.pinned.getD st.pin)) b).runIn f b).unresolved)
    (heS : S.extra = st.extra ++ ((Fast.Ix.build (st.ctx (st.pinned.getD st.pin)) b).runIn f b).released.entries.drop
        (Fast.Ix.build (st.ctx (st.pinned.getD st.pin)) b).relN)
    (hhS : S.held = st.held ++ ((Fast.Ix.build (st.ctx (st.pinned.getD st.pin)) b).runIn f b).unresolved.entries.drop
        (Fast.Ix.build (st.ctx (st.pinned.getD st.pin)) b).unrN) :
    y.Fits S := by
  obtain ⟨hx, hrp, hup, -, hcr, hcu⟩ := hf
  obtain ⟨ra, ua, hok, hyr, hyu, hRs, hUs, e1, e2⟩ := next_ok x _ b f hx hcr hrp hcu hup y hy
  have hP : S.pinned.getD S.pin = st.pinned.getD st.pin := by rw [hp]; rfl
  rw [e1] at heS
  rw [e2] at hhS
  have hcr' := hcr
  have hcu' := hcu
  simp only [St.ctx] at hcr' hcu'
  refine ⟨hok, by rw [hrS, hyr], by rw [huS, hyu], hsl, ?_, ?_⟩
  · rw [hP]; simp only [St.ctx, heS]
    rw [← grow_app, hcr', hyr, hRs]; rfl
  · rw [hP]; simp only [St.ctx, hhS]
    rw [← grow_app, hcu', hyu, hUs]; rfl

theorem digest_run (x : Res) (hx : x.Ok) (c : Ctx) (b : List Line) (f : List Nat)
    (hr : c.released = some x.m.r) (hrp : c.releasedPrior = x.m.r)
    (hu : c.unresolved = some x.m.u) (hup : c.unresolvedPrior = x.m.u) :
    (x.digest ((Fast.Ix.build c b).runIn f b).released ((Fast.Ix.build c b).runIn f b).unresolved).map (·.1) =
      Fast.setsDigestF hB ((Fast.Ix.build c b).runIn f b).released ((Fast.Ix.build c b).runIn f b).unresolved := by
  obtain ⟨ra, ua, hR, hU, -, -⟩ := run_shape x c b f hx hr hrp hu hup
  rw [hR, hU]
  exact (digest_eq x hx ra ua).1

/-- T2: on a fitting state the resident commit prints every byte `commit` prints (RULES_LINE, _FREE, _DIGEST, _ADDS,
    _READS, mismatches), leaves the same state, and its next `Res` (none when fresh rows do not serialize) fits that state. Rules out a stale cache after a
    commit and any output that differs from the full replay. -/
theorem commitRes_eq (x : Res) (st : St) (unanchored : Bool) (hf : x.Fits st) :
    (commitRes x st unanchored).2 = commit st unanchored ∧
      ∀ y, (commitRes x st unanchored).1 = some y → y.Fits (commit st unanchored).1 := by
  have hf' := hf
  obtain ⟨hx, hrp, hup, hsl, hcr, hcu⟩ := hf
  have hprior : (if st.sealed || st.anchor.isSome then Memo.get st.memo (st.ctx (st.pinned.getD st.pin)).releasedPrior
      (st.ctx (st.pinned.getD st.pin)).unresolvedPrior else none) = x.m.d := by
    simp only [hsl, Bool.true_or, ↓reduceIte]
    exact memo_get_fits st x _ _ hrp.symm hup.symm
  have hIx : ∀ b, x.ixFor (st.ctx (st.pinned.getD st.pin)) b = Fast.Ix.build (st.ctx (st.pinned.getD st.pin)) b :=
    fun b => ixFor_eq x _ b hx hcr hrp hcu hup
  have hdigR : ∀ (f : List Nat) (b : List Line),
      (x.digest ((Fast.Ix.build (st.ctx (st.pinned.getD st.pin)) b).runIn f b).released
        ((Fast.Ix.build (st.ctx (st.pinned.getD st.pin)) b).runIn f b).unresolved).map (·.1) =
      Fast.setsDigestF hB ((Fast.Ix.build (st.ctx (st.pinned.getD st.pin)) b).runIn f b).released
        ((Fast.Ix.build (st.ctx (st.pinned.getD st.pin)) b).runIn f b).unresolved :=
    fun f b => digest_run x hx _ b f hcr hrp hcu hup
  by_cases hA : (!st.anchor.all fun a => x.m.d == some (Gate.natBE Gate.digestBytes a)) = true
  · have h1 : commitRes x st unanchored = (some x, commit st unanchored) := by
      unfold commitRes; dsimp only; simp only [if_pos hA]
    rw [h1]
    refine ⟨rfl, ?_⟩
    intro y hy
    obtain rfl := Option.some.inj hy
    unfold commit; dsimp only; simp only [hprior, if_pos hA]
    exact hf'
  · constructor
    · unfold commitRes commit
      dsimp only
      simp only [hprior, if_neg hA]
      rcases ho : st.owners with _ | ⟨k, os⟩
      all_goals simp only [hIx, Option.elim, hsl, eq_self, ↓reduceIte]
      all_goals simp only [hdigR]
      all_goals simp only [Option.map]
      all_goals first | rfl | (congr 1 <;> first | rfl | skip)
    · intro y hy
      unfold commitRes at hy
      dsimp only at hy
      simp only [if_neg hA] at hy
      unfold commit
      dsimp only
      simp only [hprior, if_neg hA]
      rcases ho : st.owners with _ | ⟨k, os⟩
      all_goals simp only [ho, Option.map, hIx] at hy ⊢
      all_goals exact fits_main x st _ _ _ hf' y hy rfl rfl rfl rfl rfl rfl

/-- A line that is no `breaks`, `load` or `commit` leaves everything `Res.Fits` reads (and that `sealed`). -/
theorem step_keep (st st' : St) (fs : List String) (out : List String) (hs : step st fs = some (st', out))
    (hb : breaks fs = false) (hl : fs.head? ≠ some "load") (hc1 : fs ≠ ["commit"]) (hc2 : fs ≠ ["commit", "UNANCHORED"]) :
    st'.pinned = st.pinned ∧ st'.snaps = st.snaps ∧ st'.rows = st.rows ∧ st'.extra = st.extra ∧ st'.held = st.held ∧
    st'.rprior = st.rprior ∧ st'.uprior = st.uprior ∧ (st.sealed = true → st'.sealed = true) := by
  unfold step at hs
  split at hs
  all_goals first
    | (simp_all [breaks]; done)
    | (simp [Option.bind_eq_some_iff, guard, failure] at hs; first | grind | (simp [breaks] at hb; grind))

/-- `Res.Fits` reads `st` only through these fields. -/
theorem fits_of_keep (x : Res) (st st' : St) (hf : x.Fits st)
    (h1 : st'.pinned = st.pinned) (h2 : st'.snaps = st.snaps) (h3 : st'.rows = st.rows) (h4 : st'.extra = st.extra)
    (h5 : st'.held = st.held) (h6 : st'.rprior = st.rprior) (h7 : st'.uprior = st.uprior)
    (h8 : st.sealed = true → st'.sealed = true) : x.Fits st' := by
  obtain ⟨hx, hrp, hup, hsl, hcr, hcu⟩ := hf
  have hp : st'.pin = st.pin := by simp only [St.pin, snapshot, h2, h3]
  have e : st'.pinned.getD st'.pin = st.pinned.getD st.pin := by rw [h1, hp]
  have e1 : (st'.ctx (st'.pinned.getD st'.pin)).released = (st.ctx (st.pinned.getD st.pin)).released := by
    rw [e]; simp only [St.ctx, h4]
  have e2 : (st'.ctx (st'.pinned.getD st'.pin)).unresolved = (st.ctx (st.pinned.getD st.pin)).unresolved := by
    rw [e]; simp only [St.ctx, h5]
  exact ⟨hx, by rw [h6]; exact hrp, by rw [h7]; exact hup, h8 hsl, by rw [e1]; exact hcr, by rw [e2]; exact hcu⟩

theorem refit_st (w : Worker) (st : St) : (refit w st).st = st := by
  unfold refit
  split <;> rfl

/-- `refit` keeps `Inv` (a fitted `Res.fit`, or the old `Res` and not live). -/
theorem refit_inv (w : Worker) (st : St) (hw : ∀ y, w.x = some y → y.Ok) : Inv (refit w st) := by
  unfold refit
  split
  · next y hy =>
    have hfit : Res.fit st = some y := by
      by_cases h : st.failed = 0
      · simpa [h] using hy
      · simp [h] at hy
    have hF := fit_fits st y hfit
    refine ⟨fun z hz => ?_, fun _ => ⟨y, rfl, hF⟩⟩
    have hzy : y = z := Option.some.inj hz
    subst hzy
    exact hF.1
  · exact ⟨hw, fun h => by simp at h⟩

theorem stepRes_resume (w : Worker) (h : String) :
    stepRes w ["resume", h] = (resume w.x w.st h).map fun p => ({ w with st := p.1, live := p.2.isEmpty || w.live }, p.2) := by
  cases hr : resume w.x w.st h with
  | none => simp [stepRes, hr]
  | some p => obtain ⟨a, b⟩ := p; simp [stepRes, hr]

theorem stepRes_gen (w : Worker) (fs : List String) (h1 : ∀ h, fs ≠ ["resume", h])
    (h2 : (fs == ["commit"] || fs == ["commit", "UNANCHORED"]) = false) :
    stepRes w fs = (step w.st fs).map fun p =>
      (if fs.head? == some "load" then refit w p.1 else { w with st := p.1, live := w.live && !breaks fs }, p.2) := by
  unfold stepRes
  split
  · next h => exact absurd rfl (h1 h)
  · dsimp only
    simp only [h2, Bool.false_eq_true, ↓reduceIte]
    rcases step w.st fs with _ | ⟨a, b⟩ <;> rfl

theorem stepRes_commit_fast (w : Worker) (x : Res) (hx : w.x = some x) (hl : w.live = true) (fs : List String) (u : Bool)
    (hfs : fs = ["commit"] ∧ u = false ∨ fs = ["commit", "UNANCHORED"] ∧ u = true) :
    stepRes w fs = some ((match (commitRes x w.st u).1 with
      | some y => ({ x := some y, live := true, st := (commitRes x w.st u).2.1 } : Worker)
      | none => refit w (commitRes x w.st u).2.1), (commitRes x w.st u).2.2) := by
  obtain ⟨x0, l0, st0⟩ := w
  simp only at hx hl
  subst hx hl
  rcases hfs with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;>
  first | (simp [stepRes]; done) | (simp [stepRes]; rfl)

theorem stepRes_commit_slow (w : Worker) (fs : List String) (u : Bool)
    (hfs : fs = ["commit"] ∧ u = false ∨ fs = ["commit", "UNANCHORED"] ∧ u = true)
    (hn : ¬ ∃ x, w.x = some x ∧ w.live = true) :
    stepRes w fs = some (refit w (commit w.st u).1, (commit w.st u).2) := by
  obtain ⟨x0, l0, st0⟩ := w
  have hn' : x0 = none ∨ l0 = false := by
    rcases x0 with _ | x
    · exact Or.inl rfl
    · rcases l0 with _ | _
      · exact Or.inr rfl
      · exact absurd ⟨x, rfl, rfl⟩ hn
  rcases hn' with rfl | rfl
  · rcases l0 <;> rcases hfs with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;>
    first | (simp [stepRes]; done) | (simp [stepRes]; rfl)
  · rcases x0 <;> rcases hfs with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;>
    first | (simp [stepRes]; done) | (simp [stepRes]; rfl)

/-- F1: every worker step keeps `Inv`. Rules out `commitRes` running on a state its `Res` does not fit (after a
    `today`, `snap`, `drop`, set row, `case` or `load` in the frame). -/
theorem stepRes_inv (w w' : Worker) (fs out : List String) (hw : Inv w) (hs : stepRes w fs = some (w', out)) :
    Inv w' := by
  obtain ⟨hwx, hwl⟩ := hw
  by_cases hrs : ∃ h, fs = ["resume", h]
  · obtain ⟨h, rfl⟩ := hrs
    rw [stepRes_resume] at hs
    rcases hr : resume w.x w.st h with _ | ⟨st1, out1⟩
    · rw [hr] at hs; simp at hs
    · rw [hr] at hs
      simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hs
      obtain ⟨rfl, -⟩ := hs
      refine ⟨hwx, fun hl => ?_⟩
      rcases resume_fail_closed w.x w.st st1 h out1 hr with ⟨hout, x, bs, ho, -, -, -, -, -⟩ | ⟨hout, hst⟩
      · subst hout
        rw [ho] at hr
        exact ⟨x, ho, resume_fits x w.st st1 h (hwx x ho) hr⟩
      · subst hout
        subst hst
        have hl' : w.live = true := by simpa using hl
        obtain ⟨y, hy, hF⟩ := hwl hl'
        exact ⟨y, hy, fits_of_keep y w.st _ hF rfl rfl rfl rfl rfl rfl rfl id⟩
  · have hr' : ∀ h, fs ≠ ["resume", h] := fun h e => hrs ⟨h, e⟩
    by_cases hc : fs = ["commit"] ∨ fs = ["commit", "UNANCHORED"]
    · obtain ⟨u, hu⟩ : ∃ u : Bool, (fs = ["commit"] ∧ u = false ∨ fs = ["commit", "UNANCHORED"] ∧ u = true) := by
        rcases hc with e | e
        · exact ⟨false, Or.inl ⟨e, rfl⟩⟩
        · exact ⟨true, Or.inr ⟨e, rfl⟩⟩
      by_cases hf : ∃ x, w.x = some x ∧ w.live = true
      · obtain ⟨x, hx, hl⟩ := hf
        rw [stepRes_commit_fast w x hx hl fs u hu] at hs
        obtain ⟨y, hy, hF⟩ := hwl hl
        have hyx : y = x := by rw [hx] at hy; exact (Option.some.inj hy).symm
        subst hyx
        obtain ⟨h1, h2⟩ := commitRes_eq y w.st u hF
        simp only [Option.some.injEq, Prod.mk.injEq] at hs
        obtain ⟨rfl, -⟩ := hs
        rcases hcm : (commitRes y w.st u).1 with _ | y'
        · try dsimp only
          exact refit_inv w _ hwx
        · try dsimp only
          have hF' := h2 y' hcm
          have e : (commitRes y w.st u).2.1 = (commit w.st u).1 := by rw [h1]
          refine ⟨fun z hz => ?_, fun _ => ⟨y', rfl, ?_⟩⟩
          · have hzy : y' = z := Option.some.inj hz
            subst hzy
            exact hF'.1
          · show y'.Fits (commitRes y w.st u).2.1
            rw [e]
            exact hF'
      · rw [stepRes_commit_slow w fs u hu hf] at hs
        simp only [Option.some.injEq, Prod.mk.injEq] at hs
        obtain ⟨rfl, -⟩ := hs
        exact refit_inv w _ hwx
    · have h2 : (fs == ["commit"] || fs == ["commit", "UNANCHORED"]) = false := by simpa [not_or] using hc
      rw [stepRes_gen w fs hr' h2] at hs
      rcases hst : step w.st fs with _ | ⟨st1, out1⟩
      · rw [hst] at hs; simp at hs
      · rw [hst] at hs
        simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hs
        obtain ⟨rfl, -⟩ := hs
        split
        · exact refit_inv w _ hwx
        · next hl =>
          refine ⟨hwx, fun hlive => ?_⟩
          have hlive' : (w.live && !breaks fs) = true := hlive
          simp at hlive'
          obtain ⟨hlw, hb⟩ := hlive'
          obtain ⟨y, hy, hF⟩ := hwl hlw
          have hl' : fs.head? ≠ some "load" := fun e => hl (by simp [e])
          obtain ⟨k1, k2, k3, k4, k5, k6, k7, k8⟩ :=
            step_keep w.st st1 fs out1 hst hb hl' (fun e => hc (Or.inl e)) (fun e => hc (Or.inr e))
          exact ⟨y, hy, fits_of_keep y w.st st1 hF k1 k2 k3 k4 k5 k6 k7 k8⟩

/-- F1: under `Inv`, every line but `resume` steps exactly as `step` (commits via T2). -/
theorem stepRes_step (w : Worker) (fs : List String) (hw : Inv w) (hr : fs.head? ≠ some "resume") :
    (stepRes w fs).map (fun p => (p.1.st, p.2)) = step w.st fs := by
  obtain ⟨hwx, hwl⟩ := hw
  have hr' : ∀ h, fs ≠ ["resume", h] := fun h e => hr (by rw [e]; rfl)
  by_cases hc : fs = ["commit"] ∨ fs = ["commit", "UNANCHORED"]
  · obtain ⟨u, hu, hstep⟩ : ∃ u : Bool, (fs = ["commit"] ∧ u = false ∨ fs = ["commit", "UNANCHORED"] ∧ u = true) ∧
        step w.st fs = some (commit w.st u) := by
      rcases hc with e | e
      · subst e; exact ⟨false, Or.inl ⟨rfl, rfl⟩, rfl⟩
      · subst e; exact ⟨true, Or.inr ⟨rfl, rfl⟩, rfl⟩
    rw [hstep]
    by_cases hf : ∃ x, w.x = some x ∧ w.live = true
    · obtain ⟨x, hx, hl⟩ := hf
      rw [stepRes_commit_fast w x hx hl fs u hu]
      obtain ⟨y, hy, hF⟩ := hwl hl
      have hyx : y = x := by rw [hx] at hy; exact (Option.some.inj hy).symm
      subst hyx
      obtain ⟨h1, h2⟩ := commitRes_eq y w.st u hF
      rcases hcm : (commitRes y w.st u).1 with _ | y'
      · try dsimp only
        simp only [Option.map_some, refit_st, h1]
      · try dsimp only
        simp only [Option.map_some, h1]
    · rw [stepRes_commit_slow w fs u hu hf]
      simp only [Option.map_some, refit_st]
  · have h2 : (fs == ["commit"] || fs == ["commit", "UNANCHORED"]) = false := by simpa [not_or] using hc
    rw [stepRes_gen w fs hr' h2]
    rcases hst : step w.st fs with _ | ⟨st1, out1⟩
    · simp
    · simp only [Option.map_some]
      split
      · simp only [refit_st]
      · rfl

/-! `runRes_eq_load`: the frame's two lines split into the fields the proof expects. -/

theorem hi_byte : ∀ x : UInt8, 128 ≤ (x &&& 0x1f ||| 0xc0) ∧ 128 ≤ (x &&& 0x0f ||| 0xe0) ∧
    128 ≤ (x &&& 0x07 ||| 0xf0) := by
  apply u8_forall
  decide +kernel

theorem enc_cases (c : Char) :
    (c.utf8Size = 1 ∧ String.utf8EncodeChar c = [c.val.toUInt8]) ∨
      ∃ b t, String.utf8EncodeChar c = b :: t ∧ 128 ≤ b := by
  have h1 := Char.utf8Size_pos c
  have h4 := Char.utf8Size_le_four c
  have : c.utf8Size = 1 ∨ c.utf8Size = 2 ∨ c.utf8Size = 3 ∨ c.utf8Size = 4 := by omega
  rcases this with h | h | h | h
  · exact Or.inl ⟨h, String.utf8EncodeChar_eq_singleton h⟩
  · exact Or.inr ⟨_, _, String.utf8EncodeChar_eq_cons_cons h, (hi_byte _).1⟩
  · exact Or.inr ⟨_, _, String.utf8EncodeChar_eq_cons_cons_cons h, (hi_byte _).2.1⟩
  · exact Or.inr ⟨_, _, String.utf8EncodeChar_eq_cons_cons_cons_cons h, (hi_byte _).2.2⟩

/-- A string whose UTF-8 bytes all satisfy an ASCII predicate has only one-byte characters satisfying it. -/
theorem ascii_chars (P : UInt8 → Prop) (hP : ∀ v, P v → v < 128) :
    ∀ l : List Char, (∀ v ∈ l.utf8Encode.data.toList, P v) → ∀ c ∈ l, c.utf8Size = 1 ∧ P c.val.toUInt8 := by
  intro l
  induction l with
  | nil => intro _ c hc; simp at hc
  | cons d l ih =>
    intro h c hc
    rw [List.utf8Encode_cons, List.utf8Encode_singleton] at h
    simp only [ByteArray.data_append, Array.toList_append, List.toList_data_toByteArray, List.mem_append] at h
    have hl : ∀ v ∈ l.utf8Encode.data.toList, P v := fun v hv => h v (Or.inr hv)
    rcases List.mem_cons.mp hc with rfl | hc'
    · rcases enc_cases c with ⟨hs, he⟩ | ⟨b, t, he, hb⟩
      · refine ⟨hs, h _ (Or.inl ?_)⟩
        rw [he]; simp
      · exfalso
        have := hP b (h b (Or.inl (by rw [he]; simp)))
        exact absurd hb (UInt8.not_le.mpr this)
    · exact ih hl c hc'

def HexB (v : UInt8) : Prop := (48 ≤ v ∧ v ≤ 57) ∨ (97 ≤ v ∧ v ≤ 102)

instance : DecidablePred HexB := fun v => by unfold HexB; infer_instance

theorem hexB_lt : ∀ v : UInt8, HexB v → v < 128 := by
  apply u8_forall (fun v => HexB v → v < 128)
  decide +kernel

theorem dd_hexB : ∀ n : UInt8, n < 16 → HexB (dd n) := by
  apply u8_forall (fun n => n < 16 → HexB (dd n))
  decide +kernel

theorem hexOf_bytes (b : ByteArray) : (hexOf b).toByteArray.data.toList = hexList b.data.toList := by
  have hv : (b.data.toList.foldl hexStep (ByteArray.emptyWithCapacity (2 * b.size))).IsValidUTF8 :=
    hexStep_valid _ _ ByteArray.isValidUTF8_empty
  have hd := hexStep_data b.data.toList (ByteArray.emptyWithCapacity (2 * b.size))
  have hu : (hexOf b).toUTF8 = b.data.toList.foldl hexStep (ByteArray.emptyWithCapacity (2 * b.size)) := by
    rw [hexOf_eq]; unfold String.fromUTF8!; rw [dif_pos hv]; rfl
  have hl : (hexOf b).toUTF8.data.toList = hexList b.data.toList := by
    rw [hu, hd]; rfl
  exact hl

theorem hexOf_chars (b : ByteArray) : ∀ c ∈ (hexOf b).toList, c.utf8Size = 1 ∧ HexB c.val.toUInt8 := by
  apply ascii_chars HexB hexB_lt
  rw [String.utf8Encode_toList, hexOf_bytes]
  intro v hv
  simp only [hexList, List.mem_flatMap, List.mem_cons, List.not_mem_nil, or_false] at hv
  obtain ⟨x, -, rfl | rfl⟩ := hv
  · exact dd_hexB _ (shift_lt x).1
  · exact dd_hexB _ (shift_lt x).2

/-- A frame field: nonempty, and no space, `\r` or `\n`. -/
def Plain (p : String) : Prop := p ≠ "" ∧ ∀ c ∈ p.toList, c ≠ ' ' ∧ c ≠ '\r' ∧ c ≠ '\n'

theorem plain_hexOf (b : ByteArray) (h : b.size ≠ 0) : Plain (hexOf b) := by
  refine ⟨fun e => h ?_, fun c hc => ?_⟩
  · have h2 : (hexOf b).toList = [] := by rw [e]; simp
    have h3 := hexOf_bytes b
    rw [← String.utf8Encode_toList, h2, List.utf8Encode_nil] at h3
    have h4 := congrArg List.length h3
    rw [hexList_length] at h4
    simp at h4
    omega
  · obtain ⟨-, hh⟩ := hexOf_chars b c hc
    refine ⟨?_, ?_, ?_⟩ <;> rintro rfl <;> revert hh <;> decide

theorem plain_nat (n : Nat) : Plain (toString n) := by
  refine ⟨by simp, fun c hc => ?_⟩
  have hd : c.isDigit := Nat.isDigit_of_mem_toDigits (b := 10) (by decide) (by decide) (by simpa using hc)
  refine ⟨?_, ?_, ?_⟩ <;> rintro rfl <;> revert hd <;> decide

theorem plain_lit (s : String) (h : s ≠ "") (hc : ∀ c ∈ s.toList, c ≠ ' ' ∧ c ≠ '\r' ∧ c ≠ '\n') : Plain s := ⟨h, hc⟩

theorem plain_adds (bs : ByteArray) : Plain (addsField bs) := by
  unfold addsField
  split
  · exact plain_lit "-" (by decide) (by decide)
  · next h => exact plain_hexOf bs h

theorem plain_D (D : List UInt8) (hD : D.length = 64) : Plain (hexOf D.toByteArray) :=
  plain_hexOf _ (by simp [hD])

theorem mem_join (parts : List String) (c : Char) (h : c ∈ (" ".intercalate parts).toList) :
    c = ' ' ∨ ∃ p ∈ parts, c ∈ p.toList := by
  induction parts with
  | nil => simp at h
  | cons t l ih =>
    cases l with
    | nil => rw [String.intercalate_singleton] at h; exact Or.inr ⟨t, by simp, h⟩
    | cons u l' =>
      rw [String.intercalate_cons_cons, String.toList_append, String.toList_append, List.mem_append,
        List.mem_append] at h
      rcases h with (h | h) | h
      · exact Or.inr ⟨t, by simp, h⟩
      · left; simpa using h
      · rcases ih h with h' | ⟨p, hp, h'⟩
        · exact Or.inl h'
        · exact Or.inr ⟨p, by simp [hp], h'⟩

theorem fieldsFast_join (parts : List String) (hne : parts ≠ []) (hp : ∀ p ∈ parts, Plain p) :
    fieldsFast (" ".intercalate parts) = parts := by
  have hnr : (" ".intercalate parts).contains '\r' = false := by
    rw [String.contains_char_eq]
    simp only [decide_eq_false_iff_not]
    intro h
    rcases mem_join parts _ h with h' | ⟨p, hpm, h'⟩
    · exact absurd h' (by decide)
    · exact ((hp p hpm).2 _ h').2.1 rfl
  unfold fieldsFast
  rw [hnr]
  simp only [Bool.false_eq_true, ↓reduceIte]
  unfold splitC
  have := String.toList_split_intercalate (c := ' ') (l := parts) (fun s hs hc => ((hp s hs).2 _ hc).1 rfl)
  have e : String.singleton ' ' = " " := by decide
  rw [e] at this
  rw [this, if_neg hne]
  exact List.filter_eq_self.mpr (fun a ha => by simpa using (hp a ha).1)

theorem splitC_nl (L : List String) (hne : L ≠ []) (hnl : ∀ l ∈ L, ¬ l.contains '\n') :
    splitC ("\n".intercalate L) '\n' = L := by
  unfold splitC
  have := String.toList_split_intercalate (c := '\n') (l := L)
    (fun s hs hc => hnl s hs (by rw [String.contains_char_eq]; simpa using hc))
  have e : String.singleton '\n' = "\n" := by decide
  rw [e] at this
  rw [this, if_neg hne]

theorem fields_resume (h : String) (hp : Plain h) : fieldsFast ("resume " ++ h) = ["resume", h] := by
  have e : "resume " ++ h = " ".intercalate ["resume", h] := by
    rw [String.intercalate_cons_cons, String.intercalate_singleton]
    have : "resume " = "resume" ++ " " := by decide
    rw [this]
  rw [e]
  refine fieldsFast_join _ (by simp) ?_
  intro p hp'
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hp'
  rcases hp' with rfl | rfl
  · exact plain_lit "resume" (by decide) (by decide)
  · exact hp

theorem fields_load (a b c : String) (ha : Plain a) (hb : Plain b) (hc : Plain c) :
    fieldsFast ("load " ++ a ++ " " ++ b ++ " " ++ c) = ["load", a, b, c] := by
  have e : "load " ++ a ++ " " ++ b ++ " " ++ c = " ".intercalate ["load", a, b, c] := by
    simp only [String.intercalate_cons_cons, String.intercalate_singleton]
    have : "load " = "load" ++ " " := by decide
    rw [this]
    simp only [String.append_assoc]
  rw [e]
  refine fieldsFast_join _ (by simp) ?_
  intro p hp'
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hp'
  rcases hp' with rfl | rfl | rfl | rfl
  · exact plain_lit "load" (by decide) (by decide)
  · exact ha
  · exact hb
  · exact hc

theorem runLoop_append {σ : Type} (stp : σ → List String → Option (σ × List String)) (get : σ → St) (bump : σ → σ)
    (A B : List String) :
    ∀ (n : Nat) (s : σ) (out : Array String), runLoop stp get bump (A ++ B) n s out =
      runLoop stp get bump B (n + A.length) (runLoop stp get bump A n s out).1 (runLoop stp get bump A n s out).2 := by
  induction A with
  | nil => intro n s out; simp [runLoop]
  | cons a A ih =>
    intro n s out
    have e : n + (a :: A).length = n + 1 + A.length := by simp; omega
    rw [e]
    simp only [List.cons_append, runLoop]
    split
    · exact ih _ _ _
    · split
      · exact ih _ _ _
      · exact ih _ _ _

theorem bump_inv (w : Worker) (hw : Inv w) : Inv { w with st := { w.st with failed := w.st.failed + 1 } } := by
  obtain ⟨h1, h2⟩ := hw
  refine ⟨h1, fun hl => ?_⟩
  obtain ⟨y, hy, hF⟩ := h2 hl
  exact ⟨y, hy, fits_of_keep y w.st _ hF rfl rfl rfl rfl rfl rfl rfl (fun h => h)⟩

theorem stepRes_pre (w w1 : Worker) (fs ls : List String) (hr : fs.head? ≠ some "resume")
    (hl : fs.head? ≠ some "load") (hc : fs.head? ≠ some "commit") (hs : stepRes w fs = some (w1, ls))
    (hlive : w.live = false) : w1.x = w.x ∧ w1.live = false := by
  have h1 : ∀ h, fs ≠ ["resume", h] := fun h e => hr (by rw [e]; rfl)
  have h2 : (fs == ["commit"] || fs == ["commit", "UNANCHORED"]) = false := by
    simp only [Bool.or_eq_false_iff, beq_eq_false_iff_ne]
    exact ⟨fun e => hc (by rw [e]; rfl), fun e => hc (by rw [e]; rfl)⟩
  rw [stepRes_gen w fs h1 h2] at hs
  obtain ⟨⟨st1, o1⟩, hst, he⟩ := Option.map_eq_some_iff.mp hs
  have hl' : (fs.head? == some "load") = false := beq_eq_false_iff_ne.mpr hl
  rw [hl'] at he
  simp only [Bool.false_eq_true, ↓reduceIte, Prod.mk.injEq] at he
  obtain ⟨he1, -⟩ := he
  subst he1
  simp [hlive]

theorem runLoop_sim (P : Worker → Prop) (bumpR : Worker → Worker)
    (hb1 : ∀ w, (bumpR w).st = { w.st with failed := w.st.failed + 1 })
    (hb2 : ∀ w, Inv w → Inv (bumpR w)) (hb3 : ∀ w, P w → P (bumpR w))
    (L : List String) (hL : ∀ raw ∈ L, (fieldsFast raw).head? ≠ some "resume")
    (hP : ∀ raw ∈ L, ∀ w w1 ls, Inv w → P w → stepRes w (fieldsFast raw) = some (w1, ls) → P w1) :
    ∀ (n : Nat) (w : Worker) (out : Array String), Inv w → P w →
      (runLoop stepRes (·.st) bumpR L n w out).2 =
        (runLoop step id (fun st => { st with failed := st.failed + 1 }) L n w.st out).2 ∧
      (runLoop stepRes (·.st) bumpR L n w out).1.st =
        (runLoop step id (fun st => { st with failed := st.failed + 1 }) L n w.st out).1 ∧
      Inv (runLoop stepRes (·.st) bumpR L n w out).1 ∧ P (runLoop stepRes (·.st) bumpR L n w out).1 := by
  induction L with
  | nil => intro n w out hi hp; exact ⟨rfl, rfl, hi, hp⟩
  | cons raw L ih =>
    intro n w out hi hp
    have ih' := ih (fun r hr => hL r (List.mem_cons_of_mem _ hr)) (fun r hr => hP r (List.mem_cons_of_mem _ hr))
    simp only [runLoop]
    by_cases hsk : ((fieldsFast raw).isEmpty || (fieldsFast raw).head!.startsWith "#") = true
    · simp only [hsk, if_true]
      exact ih' (n + 1) w out hi hp
    · simp only [hsk, if_false]
      have hr := hL raw (List.mem_cons_self ..)
      have hst := stepRes_step w (fieldsFast raw) hi hr
      cases h1 : stepRes w (fieldsFast raw) with
      | none =>
        rw [h1] at hst
        have hs0 : step w.st (fieldsFast raw) = none := by simpa using hst.symm
        simp only [h1, hs0]
        have := ih' (n + 1) (bumpR w) (out.push s!"RULES_VECTOR_MALFORMED line={n + 1}") (hb2 w hi) (hb3 w hp)
        rw [hb1] at this
        exact this
      | some p =>
        obtain ⟨w1, ls⟩ := p
        rw [h1] at hst
        have hs1 : step w.st (fieldsFast raw) = some (w1.st, ls) := by simpa using hst.symm
        simp only [h1, hs1]
        have hi1 := stepRes_inv w w1 _ _ hi h1
        have hp1 := hP raw (List.mem_cons_self ..) w w1 ls hi hp h1
        exact ih' (n + 1) w1 _ hi1 hp1

def bumpW (w : Worker) : Worker := { w with st := { w.st with failed := w.st.failed + 1 } }

theorem runOn_eq {σ τ : Type} (stp1 : σ → List String → Option (σ × List String)) (get1 : σ → St) (b1 : σ → σ) (s1 : σ)
    (stp2 : τ → List String → Option (τ × List String)) (get2 : τ → St) (b2 : τ → τ) (s2 : τ) (t1 t2 : String)
    (h2 : (runLoop stp1 get1 b1 (splitC t1 '\n') 0 s1 #[]).2 = (runLoop stp2 get2 b2 (splitC t2 '\n') 0 s2 #[]).2)
    (h1 : get1 (runLoop stp1 get1 b1 (splitC t1 '\n') 0 s1 #[]).1 = get2 (runLoop stp2 get2 b2 (splitC t2 '\n') 0 s2 #[]).1) :
    ((runOn stp1 get1 b1 s1 t1).1, (runOn stp1 get1 b1 s1 t1).2.1, get1 (runOn stp1 get1 b1 s1 t1).2.2) =
      ((runOn stp2 get2 b2 s2 t2).1, (runOn stp2 get2 b2 s2 t2).2.1, get2 (runOn stp2 get2 b2 s2 t2).2.2) := by
  unfold runOn
  generalize runLoop stp1 get1 b1 (splitC t1 '\n') 0 s1 #[] = A at h1 h2 ⊢
  generalize runLoop stp2 get2 b2 (splitC t2 '\n') 0 s2 #[] = B at h1 h2 ⊢
  obtain ⟨sA, oA⟩ := A
  obtain ⟨sB, oB⟩ := B
  simp only at h1 h2 ⊢
  rw [h1, h2]

theorem runOn_snd {σ : Type} (stp : σ → List String → Option (σ × List String)) (get : σ → St) (b : σ → σ) (s : σ)
    (t : String) : (runOn stp get b s t).2.2 = (runLoop stp get b (splitC t '\n') 0 s #[]).1 := by
  unfold runOn
  generalize runLoop stp get b (splitC t '\n') 0 s #[] = A
  obtain ⟨sA, oA⟩ := A
  rfl

theorem resume_line (x : Res) (D : List UInt8) (bs : ByteArray) (hx : x.Ok) (hd : x.m.d = some D)
    (hb : parseAdds bs = some (x.m.r.entries, x.m.u.entries)) (w : Worker) (hi : Inv w) (hwx : w.x = some x)
    (n : Nat) (out : Array String) :
    (runLoop stepRes (·.st) bumpW ["resume " ++ hexOf D.toByteArray] n w out).2 =
      (runLoop step id (fun st => { st with failed := st.failed + 1 })
        ["load " ++ toString x.m.r.asOf ++ " " ++ addsField bs ++ " " ++ hexOf D.toByteArray] n w.st out).2 ∧
    (runLoop stepRes (·.st) bumpW ["resume " ++ hexOf D.toByteArray] n w out).1.st =
      (runLoop step id (fun st => { st with failed := st.failed + 1 })
        ["load " ++ toString x.m.r.asOf ++ " " ++ addsField bs ++ " " ++ hexOf D.toByteArray] n w.st out).1 ∧
    Inv (runLoop stepRes (·.st) bumpW ["resume " ++ hexOf D.toByteArray] n w out).1 := by
  have hD := memo_len x.m D hd
  have hP1 : Plain (toString x.m.r.asOf) := plain_nat _
  have hP2 : Plain (addsField bs) := plain_adds bs
  have hP3 : Plain (hexOf D.toByteArray) := plain_D D hD
  have g1 : ("resume".startsWith "#") = false := by simp
  have hh1 : ∀ h : String, ["resume", h].head! = "resume" := fun _ => rfl
  have hh2 : ∀ a b c : String, ["load", a, b, c].head! = "load" := fun _ _ _ => rfl
  have g2 : ("load".startsWith "#") = false := by simp
  have hs := resume_eq_load x w.st D bs hx hd hb
  have hr := stepRes_resume w (hexOf D.toByteArray)
  rw [hwx, hs] at hr
  cases hst : step w.st ["load", toString x.m.r.asOf, addsField bs, hexOf D.toByteArray] with
  | none =>
    rw [hst] at hr
    simp only [Option.map_none] at hr
    simp only [runLoop, fields_resume _ hP3, fields_load _ _ _ hP1 hP2 hP3, hr, hst, List.isEmpty_cons,
      hh1, hh2, g1, g2, Bool.or_self, Bool.false_eq_true, if_false]
    exact ⟨trivial, rfl, bump_inv w hi⟩
  | some p =>
    obtain ⟨st1, ls⟩ := p
    rw [hst] at hr
    simp only [Option.map_some] at hr
    simp only [runLoop, fields_resume _ hP3, fields_load _ _ _ hP1 hP2 hP3, hr, hst, List.isEmpty_cons,
      hh1, hh2, g1, g2, Bool.or_self, Bool.false_eq_true, if_false]
    exact ⟨rfl, trivial, stepRes_inv w _ _ _ hi hr⟩

theorem nl_resume (h : String) (hp : Plain h) : ¬ ("resume " ++ h).contains '\n' := by
  intro hc
  rw [String.contains_char_eq] at hc
  simp only [String.toList_append, List.mem_append, decide_eq_true_eq] at hc
  rcases hc with hc | hc
  · revert hc; decide
  · exact (hp.2 _ hc).2.2 rfl

theorem nl_load (a b c : String) (ha : Plain a) (hb : Plain b) (hc : Plain c) :
    ¬ ("load " ++ a ++ " " ++ b ++ " " ++ c).contains '\n' := by
  intro h
  rw [String.contains_char_eq] at h
  simp only [String.toList_append, List.mem_append, decide_eq_true_eq] at h
  rcases h with ((((h | h) | h) | h) | h) | h
  · revert h; decide
  · exact (ha.2 _ h).2.2 rfl
  · revert h; decide
  · exact (hb.2 _ h).2.2 rfl
  · revert h; decide
  · exact (hc.2 _ h).2.2 rfl

/-- F1 + F3, the frame: any head `pre` (no resume, load or commit), then `resume D`, then any body without resume,
    prints, passes and ends exactly as the same frame with `load a adds D`, and a live final `Res` fits the final
    state. With `resident_inv`, `adds` may be the sealed join. Rules out a resumed frame differing from the full replay. -/
theorem runRes_eq_load (x : Res) (D : List UInt8) (bs : ByteArray) (pre rest : List String)
    (hx : x.Ok) (hd : x.m.d = some D) (hb : parseAdds bs = some (x.m.r.entries, x.m.u.entries))
    (hnl : ∀ l ∈ pre ++ rest, ¬ l.contains '\n')
    (hpre : ∀ l ∈ pre, ∀ k ∈ ["resume", "load", "commit"], (fieldsFast l).head? ≠ some k)
    (hrest : ∀ l ∈ rest, (fieldsFast l).head? ≠ some "resume") :
    let r := runRes (some x) ("\n".intercalate (pre ++ ["resume " ++ hexOf D.toByteArray] ++ rest))
    (r.1, r.2.1, r.2.2.st) = runWith ("\n".intercalate
      (pre ++ ["load " ++ toString x.m.r.asOf ++ " " ++ addsField bs ++ " " ++ hexOf D.toByteArray] ++ rest)) ∧
    Inv r.2.2 := by
  intro r
  dsimp only [r]
  have hD := memo_len x.m D hd
  have hP1 : Plain (toString x.m.r.asOf) := plain_nat _
  have hP2 : Plain (addsField bs) := plain_adds bs
  have hP3 : Plain (hexOf D.toByteArray) := plain_D D hD
  have hnlA : ∀ l ∈ pre ++ ["resume " ++ hexOf D.toByteArray] ++ rest, ¬ l.contains '\n' := by
    intro l hl
    simp only [List.mem_append, List.mem_singleton] at hl
    rcases hl with (hl | rfl) | hl
    · exact hnl l (List.mem_append.2 (Or.inl hl))
    · exact nl_resume _ hP3
    · exact hnl l (List.mem_append.2 (Or.inr hl))
  have hnlB : ∀ l ∈ pre ++ ["load " ++ toString x.m.r.asOf ++ " " ++ addsField bs ++ " " ++ hexOf D.toByteArray] ++ rest,
      ¬ l.contains '\n' := by
    intro l hl
    simp only [List.mem_append, List.mem_singleton] at hl
    rcases hl with (hl | rfl) | hl
    · exact hnl l (List.mem_append.2 (Or.inl hl))
    · exact nl_load _ _ _ hP1 hP2 hP3
    · exact hnl l (List.mem_append.2 (Or.inr hl))
  have hw0 : Inv (⟨some x, false, {}⟩ : Worker) :=
    ⟨fun y hy => by cases hy; exact hx, fun h => by simp at h⟩
  obtain ⟨a1, a2, a3, a4⟩ := runLoop_sim (fun w => w.x = some x ∧ w.live = false) bumpW (fun _ => rfl)
    (fun w hw => bump_inv w hw) (fun w h => h) pre (fun raw hr => hpre raw hr "resume" (by simp))
    (fun raw hraw w w1 ls _ hp hs => by
      have h := stepRes_pre w w1 _ ls (hpre raw hraw "resume" (by simp)) (hpre raw hraw "load" (by simp))
        (hpre raw hraw "commit" (by simp)) hs hp.2
      exact ⟨h.1.trans hp.1, h.2⟩)
    0 ⟨some x, false, {}⟩ #[] hw0 ⟨rfl, rfl⟩
  obtain ⟨b1, b2, b3⟩ := resume_line x D bs hx hd hb
    (runLoop stepRes (·.st) bumpW pre 0 ⟨some x, false, {}⟩ #[]).1 a3 a4.1 (0 + pre.length)
    (runLoop stepRes (·.st) bumpW pre 0 ⟨some x, false, {}⟩ #[]).2
  obtain ⟨c1, c2, c3, -⟩ := runLoop_sim (fun _ => True) bumpW (fun _ => rfl) (fun w hw => bump_inv w hw)
    (fun _ h => h) rest hrest (fun _ _ _ _ _ _ _ _ => trivial)
    (0 + (pre ++ ["resume " ++ hexOf D.toByteArray]).length)
    (runLoop stepRes (·.st) bumpW ["resume " ++ hexOf D.toByteArray] (0 + pre.length)
      (runLoop stepRes (·.st) bumpW pre 0 ⟨some x, false, {}⟩ #[]).1
      (runLoop stepRes (·.st) bumpW pre 0 ⟨some x, false, {}⟩ #[]).2).1
    (runLoop stepRes (·.st) bumpW ["resume " ++ hexOf D.toByteArray] (0 + pre.length)
      (runLoop stepRes (·.st) bumpW pre 0 ⟨some x, false, {}⟩ #[]).1
      (runLoop stepRes (·.st) bumpW pre 0 ⟨some x, false, {}⟩ #[]).2).2 b3 trivial
  have hlen : (pre ++ ["load " ++ toString x.m.r.asOf ++ " " ++ addsField bs ++ " " ++ hexOf D.toByteArray]).length =
      (pre ++ ["resume " ++ hexOf D.toByteArray]).length := by simp
  have hrr : runRes (some x) ("\n".intercalate (pre ++ ["resume " ++ hexOf D.toByteArray] ++ rest)) =
      runOn stepRes (·.st) bumpW ⟨some x, false, {}⟩ ("\n".intercalate (pre ++ ["resume " ++ hexOf D.toByteArray] ++ rest)) := rfl
  have h2 : (runLoop stepRes (·.st) bumpW (splitC ("\n".intercalate (pre ++ ["resume " ++ hexOf D.toByteArray] ++ rest)) '\n') 0
        ⟨some x, false, {}⟩ #[]).2 =
      (runLoop step id (fun st => { st with failed := st.failed + 1 })
        (splitC ("\n".intercalate (pre ++ ["load " ++ toString x.m.r.asOf ++ " " ++ addsField bs ++ " " ++ hexOf D.toByteArray] ++ rest)) '\n')
        0 {} #[]).2 := by
    rw [splitC_nl _ (by simp) hnlA, splitC_nl _ (by simp) hnlB]
    simp only [runLoop_append]
    rw [hlen, c1, b2, b1, a2, a1]
  have h1 : (runLoop stepRes (·.st) bumpW (splitC ("\n".intercalate (pre ++ ["resume " ++ hexOf D.toByteArray] ++ rest)) '\n') 0
        ⟨some x, false, {}⟩ #[]).1.st =
      (runLoop step id (fun st => { st with failed := st.failed + 1 })
        (splitC ("\n".intercalate (pre ++ ["load " ++ toString x.m.r.asOf ++ " " ++ addsField bs ++ " " ++ hexOf D.toByteArray] ++ rest)) '\n')
        0 {} #[]).1 := by
    rw [splitC_nl _ (by simp) hnlA, splitC_nl _ (by simp) hnlB]
    simp only [runLoop_append]
    rw [hlen, c2, b2, b1, a2, a1]
  refine ⟨?_, ?_⟩
  · rw [hrr]
    exact runOn_eq stepRes (·.st) bumpW ⟨some x, false, {}⟩ step id _ {} _ _ h2 h1
  · rw [hrr, runOn_snd, splitC_nl _ (by simp) hnlA]
    simp only [runLoop_append]
    exact c3

/-- F4: a commit from a state reading its own priors (as after `load`, `resume` or a commit) appends to each prior,
    keeps that shape, and its RULES_ADDS parse to exactly the appended rows. -/
theorem commit_adds (st : St) (u : Bool)
    (hc : (st.ctx (st.pinned.getD st.pin)).released = some st.rprior ∧
      (st.ctx (st.pinned.getD st.pin)).unresolved = some st.uprior)
    (hn : st.rprior.count = st.rprior.entries.length ∧ st.uprior.count = st.uprior.entries.length) :
    let st' := (commit st u).1
    ∃ fr fu, st'.rprior.entries = st.rprior.entries ++ fr ∧ st'.uprior.entries = st.uprior.entries ++ fu ∧
      (st'.ctx (st'.pinned.getD st'.pin)).released = some st'.rprior ∧
      (st'.ctx (st'.pinned.getD st'.pin)).unresolved = some st'.uprior ∧
      st'.rprior.count = st'.rprior.entries.length ∧ st'.uprior.count = st'.uprior.entries.length ∧
      ∀ b, ("RULES_ADDS " ++ hexOf b) ∈ (commit st u).2 → parseAdds b = some (fr, fu) := by
  obtain ⟨hp, ht, hm, H⟩ := commit_struct st u
  intro st'
  dsimp only [st']
  generalize (commit st u).1 = S at hp ht hm H ⊢
  have hc1 := hc.1
  have hc2 := hc.2
  simp only [St.ctx] at hc1 hc2
  have hP : S.pinned.getD S.pin = st.pinned.getD st.pin := by rw [hp]; rfl
  rcases H with ⟨hanc, he, hh, hr', hu', hNA⟩ | ⟨hs, he, hh, hr', hu', hAD⟩
  · refine ⟨[], [], by simp [hr'], by simp [hu'], ?_, ?_, by rw [hr']; exact hn.1, by rw [hu']; exact hn.2, ?_⟩
    · rw [hP]; simp only [St.ctx, he, hr']; exact hc1
    · rw [hP]; simp only [St.ctx, hh, hu']; exact hc2
    · intro b hb
      exact absurd (hNA _ hb) (not_na_adds _)
  · obtain ⟨ra, ua, hR, hU, hrn, hun⟩ := runIn_view (st.ctx (st.pinned.getD st.pin)) (cbf st).2.1 (cbf st).1
      st.rprior st.uprior (by rw [hc.1]; exact viewF_self _ _) (by rw [hc.2]; exact viewF_self _ _)
    simp only [hrn, hun, hR, hU, List.drop_left] at hr' hu' he hh hAD
    refine ⟨ra, ua, by rw [hr'], by rw [hu'], ?_, ?_, by rw [hr']; simp, by rw [hu']; simp, ?_⟩
    · rw [hP]; simp only [St.ctx, he]; rw [← grow_app, hc1, hr']; simp [grow, hn.1]
    · rw [hP]; simp only [St.ctx, hh]; rw [← grow_app, hc2, hu']; simp [grow, hn.2]
    · intro b hb
      rcases hAD _ hb with h | ⟨bb, hbb, hab⟩
      · exact absurd h (not_na_adds _)
      · have hh2 : hexOf b = hexOf bb := (String.append_right_inj _).1 hbb
        have : b = bb := by
          have := congrArg unhexFast hh2
          rw [unhexFast_hexOf, unhexFast_hexOf] at this
          exact Option.some.inj this
        subst this
        exact parseAdds_addsBytes _ _ _ hab

/-- F4: if the sealed adds so far parse to the priors in order, so do they joined with the commit's RULES_ADDS. By
    induction from `load_fits`, the resident sets are `parseAdds` of the sealed join, row for row. Rules out a resumed
    and a recycled worker holding one multiset in two orders (different `with=` bytes under one anchor). A commit with
    `owners` unset advances the sets but prints no RULES_ADDS; Python's tip does not move, so the next `resume` fails
    closed (T1b) and `load` recovers (liveness only). -/
theorem resident_inv (st : St) (u : Bool) (bs b : ByteArray)
    (h0 : parseAdds bs = some (st.rprior.entries, st.uprior.entries))
    (hc : (st.ctx (st.pinned.getD st.pin)).released = some st.rprior ∧
      (st.ctx (st.pinned.getD st.pin)).unresolved = some st.uprior)
    (hn : st.rprior.count = st.rprior.entries.length ∧ st.uprior.count = st.uprior.entries.length)
    (hb : ("RULES_ADDS " ++ hexOf b) ∈ (commit st u).2) :
    parseAdds (bs ++ b) = some ((commit st u).1.rprior.entries, (commit st u).1.uprior.entries) := by
  obtain ⟨fr, fu, e1, e2, -, -, -, -, hadd⟩ := commit_adds st u hc hn
  rw [e1, e2]
  exact parseAdds_append _ _ _ _ _ _ h0 (hadd b hb)


/-- info: 'BlindLedger.Gate.Rules.Resident.runRes_eq_load' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms runRes_eq_load
/-- info: 'BlindLedger.Gate.Rules.Resident.commitRes_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms commitRes_eq
/-- info: 'BlindLedger.Gate.Rules.Resident.stepRes_inv' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms stepRes_inv
/-- info: 'BlindLedger.Gate.Rules.Resident.stepRes_step' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms stepRes_step
/-- info: 'BlindLedger.Gate.Rules.Resident.resident_inv' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms resident_inv
/-- info: 'BlindLedger.Gate.Rules.Resident.load_fits' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms load_fits
/-- info: 'BlindLedger.Gate.Rules.Resident.runWith_eq_runText' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms runWith_eq_runText
/-- info: 'BlindLedger.Gate.Rules.Resident.resume_eq_load' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms resume_eq_load

end BlindLedger.Gate.Rules.Resident
