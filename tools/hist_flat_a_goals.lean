import BlindLedger.Gate.Rules.FastEq

/-! HIST-FLAT design A, step 1: the resident rules worker's goals (rr-core, 2026-10-14).
    Design: `rrb/state/hist-flat-design-A-20261013.md`. Statements only, for rr-review before any proof; every `sorry`
    is owed. Like the other `tools/*_goals.lean`, nothing imports this file and no exe is built from it.

    Real: `addsBytes`, `addsField`, `rowsOf`, `pinIncr`, `Res`, `Res.digest`, `Res.Ok`, `refresh`, `Res.Fits`, `resume`,
    `stepR`, `runWith`. Sorry'd (not small): `extend` (fresh rows onto `rel`/`unr` and the posting lists, O(fresh)) and
    `commitRes` (`Run.commit` deciding with the kept index and digesting from the kept buffers).

    Composition: a frame `resume D` + body, with each `commit` run as `commitRes`, prints what `load a adds D` + body
    prints (T1, T2), and its `RULES_DIGEST` is `Fast.setsDigestF hB` of the committed sets (T3, `Memo.ok`), which
    `setsDigestF_eq` ties to `Gate.setsDigest`. The kept index decides as `decideBatchIn` (T4, `decideBatchFIn_eq`).

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

/-- The buffers are the sets' sorted rows, and the sets have the shape `load` leaves: one date, counts = lengths. -/
def Res.Ok (x : Res) : Prop :=
  (∃ rs, rowsOf x.m.r.entries = some rs ∧ x.rbuf.toList = rs.mergeSort Fast.baLe) ∧
  (∃ us, rowsOf x.m.u.entries = some us ∧ x.ubuf.toList = us.mergeSort Fast.baLe) ∧
  x.m.u.asOf = x.m.r.asOf ∧ x.m.r.count = x.m.r.entries.length ∧ x.m.u.count = x.m.u.entries.length

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
def extend (i : Fast.Ix) (r' u' : Snapshot Line) : Fast.Ix := sorry

/-- `x` is `st`'s checkpoint: `st`'s priors and the sets `st` reads are `x`'s, and a kept index was built over them. -/
def Res.Fits (x : Res) (st : St) : Prop :=
  x.Ok ∧ st.rprior = x.m.r ∧ st.uprior = x.m.u ∧ st.sealed = true ∧
  (st.ctx (st.pinned.getD st.pin)).released = some x.m.r ∧ (st.ctx (st.pinned.getD st.pin)).unresolved = some x.m.u ∧
  ∀ i, x.ix = some i → ∃ c b, i = Fast.Ix.build c b ∧ c.released = some x.m.r ∧ c.releasedPrior = x.m.r ∧
    c.unresolved = some x.m.u ∧ c.unresolvedPrior = x.m.u

/-- `commit` with the kept index (`refresh`, or a build if `today` moved) and the kept buffers (`Res.digest`), and
    the next `Res`. -/
def commitRes (x : Res) (st : St) (unanchored : Bool) : Res × St × List String := sorry

/-- `resume h`: `load`'s accepted branch with the kept sets, no parse, replay or digest; fail closed on any other anchor. -/
def resume (x : Res) (st : St) (h : String) : Option (St × List String) := do
  guard (h.length == 128)
  let anchor := Gate.beNat (← unhexFast h).toList
  if x.m.d == some (Gate.natBE Gate.digestBytes anchor) then
    pure ({ st with
      snaps := ("released", x.m.r.asOf, 0, ← emptyPin "released" x.m.r.asOf) ::
        ("unresolved", x.m.r.asOf, 0, ← emptyPin "unresolved" x.m.r.asOf) :: st.snaps,
      rows := st.rows.filter fun r => r.1 != "released" && r.1 != "unresolved", pinned := none, anchor := none,
      extra := x.m.r.entries, held := x.m.u.entries, rprior := x.m.r, uprior := x.m.u, sealed := true,
      memo := some x.m }, [])
  else pure ({ st with failed := st.failed + 1 }, ["RULES_STATE_MISMATCH resume"])

def stepR (x : Res) (st : St) : List String → Option (St × List String)
  | ["resume", h] => resume x st h
  | fs => step st fs

/-- `runText`'s loop over any step and start state, also returning the final state. -/
def runWith (stp : St → List String → Option (St × List String)) (st0 : St) (text : String) :
    Array String × Bool × St := Id.run do
  let mut st := st0
  let mut out : Array String := #[]
  let mut number := 0
  for raw in text.splitOn "\n" do
    number := number + 1
    let fs := fieldsFast raw
    if fs.isEmpty || fs.head!.startsWith "#" then continue
    match stp st fs with
    | none =>
      st := { st with failed := st.failed + 1 }
      out := out.push s!"RULES_VECTOR_MALFORMED line={number}"
    | some (next, lines) =>
      if next.failed > st.failed then out := out.push s!"RULES_VECTOR_FAIL line={number}"
      st := next
      out := out ++ lines
  let pass := st.failed == 0 && st.expected == some st.checked
  return (out.push s!"RULES_VECTORS={if pass then "PASS" else "FAIL"} checked={st.checked} expected={st.expected.getD 0} failed={st.failed}", pass, st)

/-- `runWith` is the shipped loop: rules out a resident runner that drifts from `runText`. -/
theorem runWith_eq_runText (text : String) :
    ((runWith step {} text).1, (runWith step {} text).2.1) = runText text := sorry

/-- T0: `load` reads back exactly the rows `commit` printed as `RULES_ADDS`, in order and per set. Rules out a restart
    from the sealed adds that loses, reorders or moves a row between sets. -/
theorem parseAdds_addsBytes (r u : List Line) (bs : ByteArray) (hb : addsBytes r u = some bs) :
    parseAdds bs = some (r, u) := sorry

/-- T1: a frame opened by `resume D` on kept sets prints, byte for byte, and ends in, the state of the same frame opened
    by `load` of those sets' adds with anchor `D`. Rules out a resumed frame differing from the full replay. -/
theorem resume_eq_load (x : Res) (D : List UInt8) (bs : ByteArray) (rest : String)
    (hx : x.Ok) (hd : x.m.d = some D) (hb : addsBytes x.m.r.entries x.m.u.entries = some bs)
    (hrest : ∀ l ∈ rest.splitOn "\n", (fieldsFast l).head? ≠ some "resume") :
    runWith (stepR x) {} ("resume " ++ hexOf D.toByteArray ++ "\n" ++ rest) =
      runWith step {} ("load " ++ toString x.m.r.asOf ++ " " ++ addsField bs ++ " " ++ hexOf D.toByteArray ++ "\n" ++
        rest) := sorry

/-- T1b: `resume` installs the kept sets only on their exact digest; otherwise it prints the mismatch and changes
    nothing but `failed`. Rules out a resume onto a stale, forked or foreign checkpoint. -/
theorem resume_fail_closed (x : Res) (st st' : St) (h : String) (out : List String)
    (hs : stepR x st ["resume", h] = some (st', out)) :
    (out = [] ∧ (∃ bs, unhexFast h = some bs ∧ x.m.d = some (Gate.natBE Gate.digestBytes (Gate.beNat bs.toList))) ∧
      st'.memo = some x.m ∧ st'.rprior = x.m.r ∧ st'.uprior = x.m.u) ∨
    (out = ["RULES_STATE_MISMATCH resume"] ∧ st' = { st with failed := st.failed + 1 }) := sorry

/-- T2: on a fitting state the resident commit prints every byte `commit` prints (RULES_LINE, _FREE, _DIGEST, _ADDS,
    _READS, mismatches), leaves the same state, and its next `Res` fits that state. Rules out a stale cache after a
    commit and any output that differs from the full replay. -/
theorem commitRes_eq (x : Res) (st : St) (unanchored : Bool) (hf : x.Fits st) :
    (commitRes x st unanchored).2 = commit st unanchored ∧
      (commitRes x st unanchored).1.Fits (commit st unanchored).1 := sorry

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
    refresh (Fast.Ix.build c b₀) c' b = Fast.Ix.build c' b := sorry

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
