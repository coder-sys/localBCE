import BlindLedger.Gate.Rules.FastEq

/-! HIST-FLAT design A: the resident rules worker's goals (rr-core, 2026-10-14; r2 after rr-review
    `rrb/state/hist-flat-a-review-20261014.md` F1-F4). Design: `rrb/state/hist-flat-design-A-20261013.md`. Statements
    only, for rr-review before any proof; every `sorry` is owed. Like the other `tools/*_goals.lean`, nothing imports
    this file and no exe is built from it.

    Real: `addsBytes`, `addsField`, `rowsOf`, `pinIncr`, `Res`, `Res.digest`, `Res.Ok`, `refresh`, `Res.Fits`,
    `Res.memoOf`, `Res.fit`, `resume`, `runOn`, `runWith`, `Worker`, `Inv`, `breaks`, `refit`, `stepRes`, `runRes`.
    Sorry'd (not small): `extend` (fresh rows onto `rel`/`unr` and the posting lists, O(fresh)) and `commitRes`
    (`Run.commit` deciding with the kept index and digesting from the kept buffers).

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
structure Res where
  m : Memo
  rbuf : Array ByteArray
  ubuf : Array ByteArray
  ix : Option Fast.Ix

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

/-- A `Res` fitting `st`, built and checked in O(n), or `none` (the worker stays on the full path). -/
def Res.fit (st : St) : Option Res := do
  let m := Res.memoOf st
  let c := st.ctx (st.pinned.getD st.pin)
  guard (st.sealed = true ∧ m.u.asOf = m.r.asOf ∧ m.r.count = m.r.entries.length ∧
    m.u.count = m.u.entries.length ∧ c.released = some m.r ∧ c.unresolved = some m.u)
  pure { m, rbuf := ((← rowsOf m.r.entries).mergeSort Fast.baLe).toArray,
            ubuf := ((← rowsOf m.u.entries).mergeSort Fast.baLe).toArray, ix := none }

/-- The `Res` for the committed sets `r`, `u` from `x`'s buffers and `i` extended by the fresh rows, or `none` when
    the fresh rows do not serialize (a field over its width: the worker then falls back, `refit`). `Memo.ok` is a
    `Prop` (erased); it is discharged classically here because its proof is `digest_eq`, which needs `x.Ok`.
    NONCOMPUTABLE only for that reason; no O(n) work is added. -/
noncomputable def Res.next (x : Res) (i : Fast.Ix) (r u : Snapshot Line) : Option Res :=
  match x.digest r u with
  | none => none
  | some (d, rb, ub) =>
    @dite _ (some d = Fast.setsDigestF hB r u) (Classical.propDecidable _)
      (fun h => some { m := ⟨r, u, some d, h⟩, rbuf := rb, ubuf := ub, ix := some (extend i r u) }) (fun _ => none)

/-- `commit` with the kept index (`refresh`, or a build if `today` moved), the kept buffers (`Res.digest`) and the
    kept digest as `prior`; plus the next `Res` (`none`: fall back to `refit`). -/
noncomputable def commitRes (x : Res) (st : St) (unanchored : Bool) : Option Res × St × List String :=
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
  let ix := match x.ix with
    | some i => if i.today = c.today then refresh i c b else Fast.Ix.build c b
    | none => Fast.Ix.build c b
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
  (x.next ix r.released r.unresolved,
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

/-- `runText`'s loop over any step state `σ` (its `St` by `get`, a malformed line by `bump`), returning the final state. -/
def runOn {σ : Type} (stp : σ → List String → Option (σ × List String)) (get : σ → St) (bump : σ → σ) (s0 : σ)
    (text : String) : Array String × Bool × σ := Id.run do
  let mut s := s0
  let mut out : Array String := #[]
  let mut number := 0
  for raw in text.splitOn "\n" do
    number := number + 1
    let fs := fieldsFast raw
    if fs.isEmpty || fs.head!.startsWith "#" then continue
    match stp s fs with
    | none =>
      s := bump s
      out := out.push s!"RULES_VECTOR_MALFORMED line={number}"
    | some (next, lines) =>
      if (get next).failed > (get s).failed then out := out.push s!"RULES_VECTOR_FAIL line={number}"
      s := next
      out := out ++ lines
  let st := get s
  let pass := st.failed == 0 && st.expected == some st.checked
  return (out.push s!"RULES_VECTORS={if pass then "PASS" else "FAIL"} checked={st.checked} expected={st.expected.getD 0} failed={st.failed}", pass, s)

/-- `runText` with its final state. -/
def runWith (text : String) : Array String × Bool × St :=
  runOn step id (fun st => { st with failed := st.failed + 1 }) {} text

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

noncomputable def stepRes (w : Worker) : List String → Option (Worker × List String)
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
noncomputable def runRes (x : Option Res) (text : String) : Array String × Bool × Worker :=
  runOn stepRes (·.st) (fun w => { w with st := { w.st with failed := w.st.failed + 1 } }) { x, live := false, st := {} } text

/-- `runWith` is the shipped loop: rules out a frame loop that drifts from `runText`. -/
theorem runWith_eq_runText (text : String) : ((runWith text).1, (runWith text).2.1) = runText text := sorry

/-- T0: `load` reads back exactly the rows one `commit` printed as `RULES_ADDS`, in order and per set. Rules out a
    restart that loses, reorders or moves a row between sets. -/
theorem parseAdds_addsBytes (r u : List Line) (bs : ByteArray) (hb : addsBytes r u = some bs) :
    parseAdds bs = some (r, u) := sorry

/-- F4: the join of sealed adds parses to the joined rows, per set and in order. -/
theorem parseAdds_append (a b : ByteArray) (r u r' u' : List Line) (ha : parseAdds a = some (r, u))
    (hb : parseAdds b = some (r', u')) : parseAdds (a ++ b) = some (r ++ r', u ++ u') := sorry

/-- T1, per step: from ANY state (a head's `today`, snapshots and rows, a `case`, a batch), `resume D` on kept sets is
    `load a adds D` for any `adds` that parse to those sets. Rules out a resume that drops or resets anything `load`
    keeps (snapshots, rows, `today`, the batch) or installs anything `load` would not. -/
theorem resume_eq_load (x : Res) (st : St) (D : List UInt8) (bs : ByteArray) (hx : x.Ok) (hd : x.m.d = some D)
    (hb : parseAdds bs = some (x.m.r.entries, x.m.u.entries)) :
    resume (some x) st (hexOf D.toByteArray) =
      step st ["load", toString x.m.r.asOf, addsField bs, hexOf D.toByteArray] := sorry

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

/-- F1: an accepted `resume` of an `Ok` `Res` leaves a state it fits. -/
theorem resume_fits (x : Res) (st st' : St) (h : String) (hx : x.Ok) (hs : resume (some x) st h = some (st', [])) :
    x.Fits st' := sorry

/-- F2: `Res.fit` only returns a `Res` that fits (so `Ok` is established, never assumed). Rules out unsorted buffers. -/
theorem fit_fits (st : St) (x : Res) (h : Res.fit st = some x) : x.Fits st := sorry

/-- F2: after an accepted `load` (worker start or recycle) `Res.fit` succeeds, reusing the load's digest, and the
    loaded adds parse to the priors. Rules out a load that leaves the worker without a resident checkpoint. -/
theorem load_fits (st st' : St) (a h : String) (bs : ByteArray)
    (hs : step st ["load", a, addsField bs, h] = some (st', [])) :
    (∃ y, Res.fit st' = some y ∧ st'.memo = some y.m) ∧
      parseAdds bs = some (st'.rprior.entries, st'.uprior.entries) := sorry

/-- F2: a genesis commit (not sealed, no anchor) over declared sets that are chained, of one date, with a digest,
    gives a fitting `Res`. Rules out a first frame that can never reach the resident path. -/
theorem commit_genesis_fits (st : St) (u : Bool) (hs : st.sealed = false) (ha : st.anchor = none)
    (hr : Fast.chainedF st.today st.rprior (st.ctx (st.pinned.getD st.pin)).released = true)
    (hu : Fast.chainedF st.today st.uprior (st.ctx (st.pinned.getD st.pin)).unresolved = true)
    (hd : (st.ctx (st.pinned.getD st.pin)).released.map (·.asOf) =
      (st.ctx (st.pinned.getD st.pin)).unresolved.map (·.asOf))
    (hg : (Fast.setsDigestF hB (commit st u).1.rprior (commit st u).1.uprior).isSome) :
    ∃ y, Res.fit (commit st u).1 = some y := sorry

/-- N1: a genesis commit over empty declared sets (the head's `<asOf, 0, []>`; genesis sends no `load`) prints
    RULES_ADDS that parse to exactly the committed sets, so `resident_inv` starts from the first batch. Rules out a
    live genesis `Res` whose rows are not the sealed adds. -/
theorem commit_genesis_adds (st : St) (u : Bool) (hs : st.sealed = false) (ha : st.anchor = none)
    (hr : Fast.chainedF st.today st.rprior (st.ctx (st.pinned.getD st.pin)).released = true)
    (hu : Fast.chainedF st.today st.uprior (st.ctx (st.pinned.getD st.pin)).unresolved = true)
    (he : (st.ctx (st.pinned.getD st.pin)).released.map (·.entries) = some [] ∧
      (st.ctx (st.pinned.getD st.pin)).unresolved.map (·.entries) = some []) :
    ∀ b, ("RULES_ADDS " ++ hexOf b) ∈ (commit st u).2 →
      parseAdds b = some ((commit st u).1.rprior.entries, (commit st u).1.uprior.entries) := sorry

/-- T2: on a fitting state the resident commit prints every byte `commit` prints (RULES_LINE, _FREE, _DIGEST, _ADDS,
    _READS, mismatches), leaves the same state, and its next `Res` (none when fresh rows do not serialize) fits that state. Rules out a stale cache after a
    commit and any output that differs from the full replay. -/
theorem commitRes_eq (x : Res) (st : St) (unanchored : Bool) (hf : x.Fits st) :
    (commitRes x st unanchored).2 = commit st unanchored ∧
      ∀ y, (commitRes x st unanchored).1 = some y → y.Fits (commit st unanchored).1 := sorry

/-- F1: every worker step keeps `Inv`. Rules out `commitRes` running on a state its `Res` does not fit (after a
    `today`, `snap`, `drop`, set row, `case` or `load` in the frame). -/
theorem stepRes_inv (w w' : Worker) (fs out : List String) (hw : Inv w) (hs : stepRes w fs = some (w', out)) :
    Inv w' := sorry

/-- F1: under `Inv`, every line but `resume` steps exactly as `step` (commits via T2). -/
theorem stepRes_step (w : Worker) (fs : List String) (hw : Inv w) (hr : fs.head? ≠ some "resume") :
    (stepRes w fs).map (fun p => (p.1.st, p.2)) = step w.st fs := sorry

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
    Inv r.2.2 := sorry

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
      ∀ b, ("RULES_ADDS " ++ hexOf b) ∈ (commit st u).2 → parseAdds b = some (fr, fu) := sorry

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
    parseAdds (bs ++ b) = some ((commit st u).1.rprior.entries, (commit st u).1.uprior.entries) := sorry

/-- T3: the incremental pin is `Fast.pinBytes` of the extended set, and the merged buffer is its sorted rows. Rules out
    a merge that misorders, drops or duplicates a row. -/
theorem pinIncr_eq (domain : String) (kind : Nat) (s : Snapshot Line) (fresh : List Line) (buf : Array ByteArray)
    (rs : List ByteArray) (hs : rowsOf s.entries = some rs) (hb : buf.toList = rs.mergeSort Fast.baLe) :
    (pinIncr domain kind s.asOf (s.count + fresh.length) buf fresh).map (·.1) =
      Fast.pinBytes domain kind Line.fields ⟨s.asOf, s.count + fresh.length, s.entries ++ fresh⟩ ∧
    ∀ p b', pinIncr domain kind s.asOf (s.count + fresh.length) buf fresh = some (p, b') →
      ∃ rs', rowsOf (s.entries ++ fresh) = some rs' ∧ b'.toList = rs'.mergeSort Fast.baLe := sorry

/-- T3: the kept digest of the extended sets is the full `Fast.setsDigestF` (the printed RULES_DIGEST), and the new
    buffers keep `Res.Ok`. Rules out a resident digest that differs from the full re-serialization. -/
theorem digest_eq (x : Res) (hx : x.Ok) (fr fu : List Line) :
    let r : Snapshot Line := ⟨x.m.r.asOf, x.m.r.count + fr.length, x.m.r.entries ++ fr⟩
    let u : Snapshot Line := ⟨x.m.u.asOf, x.m.u.count + fu.length, x.m.u.entries ++ fu⟩
    (x.digest r u).map (·.1) = Fast.setsDigestF hB r u ∧
    ∀ d rb ub, x.digest r u = some (d, rb, ub) →
      (∃ rs, rowsOf r.entries = some rs ∧ rb.toList = rs.mergeSort Fast.baLe) ∧
      (∃ us, rowsOf u.entries = some us ∧ ub.toList = us.mergeSort Fast.baLe) := sorry

/-- T4: a kept index refreshed for a new frame (same `today`, same sets) is the index a full build makes. With
    `decideBatchFIn_eq` it decides as `decideBatchIn`. Rules out stale snapshot, redo or batch parts. -/
theorem refresh_eq (c c' : Ctx) (b₀ b : List Line) (ht : c'.today = c.today)
    (hr : c'.released = c.released) (hrp : c'.releasedPrior = c.releasedPrior)
    (hu : c'.unresolved = c.unresolved) (hup : c'.unresolvedPrior = c.unresolvedPrior) :
    refresh (Fast.Ix.build c b₀) c' b = Fast.Ix.build c' b := by
  simp only [refresh, Fast.Ix.build, ht, hr, hrp, hu, hup]

/-- T4: the index extended by a commit's fresh rows, refreshed for the next frame's context over the committed sets,
    is the index a full build over that context makes. Rules out a missing, duplicated or misplaced posting. -/
theorem ix_extend_eq (c c' : Ctx) (f : List Nat) (b₀ b : List Line)
    (hr : c.released = some c.releasedPrior) (hu : c.unresolved = some c.unresolvedPrior) (ht : c'.today = c.today)
    (hr' : c'.released = some (decideBatchIn c f b₀).released) (hrp : c'.releasedPrior = (decideBatchIn c f b₀).released)
    (hu' : c'.unresolved = some (decideBatchIn c f b₀).unresolved)
    (hup : c'.unresolvedPrior = (decideBatchIn c f b₀).unresolved) :
    refresh (extend (Fast.Ix.build c b₀) (decideBatchIn c f b₀).released (decideBatchIn c f b₀).unresolved) c' b =
      Fast.Ix.build c' b := sorry

end BlindLedger.Gate.Rules.Resident
