import BlindLedger.Gate.Anchor
import BlindLedger.Gate.Rules.Fast
import BlindLedger.Sha3Fast
import BlindLedger.Sha3

/-! The vector runner (runs per gate batch; emits `RULES_READS`, `ReadManifest.run_reads_eq`): decides with `Fast.decideBatchFIn` (= `decideBatchIn`, `FastEq.decideBatchFIn_eq`; no reversed re-run, order independence `Theorems.decideBatchIn_perm`) and pins with `Fast.pinBytes` (`pin_run_eq`). Lines marked `-- FAST` differ from the pre-twin runner. -/

namespace BlindLedger.Gate.Rules.Run

open BlindLedger.Gate.Rules

/-! Runs a rules vector file through `decideBatchIn` (its proved twin `Fast.decideBatchFIn`).  Directives,
    one per line: `case NAME` clears the batch, the totals, the lines earlier commits
    released or left unresolved and the gate's checkpoints; `today D`;
    `snap KIND ASOF COUNT PIN` (re)declares a snapshot (`dmf`, `pdeath`,
    `excl`, `span`) or the `released` or `unresolved` set (rows `ID[:PAY] FLOW
    M PAYEE REND DATE PROC UNITS CENTS`, PAY defaulting to ID; it also drops
    the lines earlier commits added to that set), whose rows are the
    following lines starting with KIND.  PIN is the SHA3-512 hex of
    `pinInput`; a snapshot whose pin does not match or with a row that does
    not parse is treated as missing, as is one after `drop KIND`.
    `line ...row fields... [OUTCOME REASONS [with=IDS]]` adds a line to the
    batch, `foreign ID...` names ids another shard owns (`decideBatchIn`; cleared by `commit`), `owners K ID:SHARD:0|1 ...` gives the id
    registry's answers to shard K for the next commit, which then decides `decideReg` (twin
    `Fast.decideRegF`): a payment with an id neither K's nor recorded elsewhere waits (expected `WAIT -`),
    and the commit prints each line (`RULES_LINE`) and the ids the registry frees (`RULES_FREE`,
    `settleFree` of `pendingOf`; `free ID...` expects them), `redo PAY` makes the batch re-decide that payment and `pay PAY
    OUTCOME` expects its `payOutcome`; `commit` decides the batch, checks the
    expectations (all lines or none), adds its released and unresolved lines
    to those sets, and takes the result's checkpoints (`advance`).  `anchor
    HEX` names the latest sealed checkpoint's state digest for the next commit,
    which then decides only if the checkpoints it extends hash to it
    (`Gate.decideAnchored`); without one, the runner's own last commit is that
    checkpoint.  `commit UNANCHORED` expects the refusal.  An `owners` commit also prints the state
    digest after it (`RULES_DIGEST`, `Gate.setsDigest`), the rows it appended (`RULES_ADDS`: per row
    `u8 set` (1 released, 2 unresolved) then the `Line.fields` row, hex) and what it read (`RULES_READS`, `reads`
    on the checkpoint it extends, or before the first on the sets it declares; redo order is part of the record).  `load G_ASOF ADDSHEX ANCHORHEX`
    drops the released and unresolved sets and replays those rows onto empty sets dated G_ASOF
    (`ShardState.loadAdds`); unless they hash to ANCHORHEX it prints `RULES_STATE_MISMATCH` and fails.  Arrival
    order cannot change a decision (`decideBatchIn_perm`).  `report`
    prints totals; `end N` is the number of checked lines.  Test-only; never
    a payment path. -/

def name {α : Type} [Repr α] (x : α) : String := ((reprStr x).splitOn ".").getLast!

def parse {α : Type} [Repr α] (all : List α) (s : String) : Option α := all.find? (name · == s)

#guard (reasons.map name).zip ((reasons.map name).drop 1) |>.all fun (a, b) => decide (a < b)

def hB (b : ByteArray) : List UInt8 := (BlindLedger.Semantic.sha3_512Fast b).toList

def hexOf (b : ByteArray) : String :=
  let d (n : UInt8) : UInt8 := if n < 10 then 48 + n else 87 + n
  String.fromUTF8! (b.foldl (fun a x => (a.push (d (x >>> 4))).push (d (x &&& 15))) (ByteArray.emptyWithCapacity (2 * b.size)))

/-- SHA3-512 of the sources this runner was built from, CRLF read as LF; the unit test recomputes
    it from the files, so a stale runner fails that test whatever its file times. -/
def source : String := hexOf (BlindLedger.Semantic.sha3_512 (String.join [include_str "Spec.lean",
  include_str "Fast.lean", include_str "Run.lean",  -- FAST
  include_str "../Anchor.lean", include_str "../Spec.lean",
  include_str "../../Sha3.lean", include_str "../../Sha3Fast.lean", include_str "../../../lakefile.toml",
  include_str "../../../lean-toolchain"]).crlfToLf.toUTF8)

/-- Hex to bytes, high digit first; linear in the input. -/
def unhex (s : String) : Option ByteArray :=
  let u := s.toUTF8
  let nib (c : UInt8) : Option UInt8 :=
    if 48 ≤ c && c ≤ 57 then some (c - 48) else if 97 ≤ c && c ≤ 102 then some (c - 87) else none
  if u.size % 2 != 0 then none else
  (List.range (u.size / 2)).foldlM (fun a i => do pure (a.push ((← nib u[2 * i]!) * 16 + (← nib u[2 * i + 1]!))))
    (ByteArray.emptyWithCapacity (u.size / 2))

/-- One `RULES_ADDS` row: the set tag, then the `Line.fields` row. -/
def rowBytes (tag : UInt8) (l : Line) : Option (List UInt8) :=
  do let bs ← l.fields.mapM fun (w, n) => be w n
     pure (tag :: bs.flatten)

def rowWidths : List Nat := (Line.fields ⟨0, 0, .FFS_CYCLE, 0, 0, 0, 0, 0, 0, 0⟩).map (·.1)

/-- The row at byte offset `o` of `b`: the set tag and the line. -/
def parseRow (b : ByteArray) (o : Nat) : Option (UInt8 × Line) := do
  let be (o w : Nat) : Nat := (List.range w).foldl (fun n i => n * 256 + (b.get! (o + i)).toNat) 0
  match (rowWidths.foldl (fun (r, o) w => (r.push (be o w), o + w)) (#[], o + 1)).1.toList with
  | [i, y, f, m, p, r, d, c, u, a] =>
    pure (b.get! o, ⟨i, y, ← [Flow.FFS_CYCLE, .FFS_CLAIM, .CAP_820].find? (·.tag == f), m, p, r, d, c, u, a⟩)
  | _ => none

/-- `RULES_ADDS` back into the released and unresolved rows. -/
def parseAdds (bs : ByteArray) : Option (List Line × List Line) := do
  let n := 1 + rowWidths.sum
  guard (bs.size % n == 0)
  let rows ← (List.range (bs.size / n)).mapM fun i => parseRow bs (n * i)
  guard (rows.all fun (t, _) => t == 1 || t == 2)
  pure ((rows.filter (·.1 == 1)).map (·.2), (rows.filter (·.1 == 2)).map (·.2))

/-- The pin of an empty set dated `a` (`snapshot`'s check, for a set that `load` declares). -/
def emptyPin (kind : String) (a : Nat) : Option String :=
  (Fast.pinBytes s!"RR/GATE/{kind.toUpper}/v1" (if kind == "released" then 5 else 6) Line.fields
    (⟨a, 0, []⟩ : Snapshot Line)).map fun b => hexOf (BlindLedger.Semantic.sha3_512Fast b)

/-- The six pinned inputs with their checked pins, and the four kinds' `readPin`s, once per declaration.  -- FAST -/
structure Pinned where
  dmf : Option (Snapshot Death × List UInt8)
  pdeath : Option (Snapshot Death × List UInt8)
  excl : Option (Snapshot Exclusion × List UInt8)
  span : Option (Snapshot Span × List UInt8)
  released : Option (Snapshot Line × List UInt8)
  unresolved : Option (Snapshot Line × List UInt8)
  kinds : Option (List (List UInt8 × List UInt8))

structure St where
  today : Nat := 0
  snaps : List (String × Nat × Nat × String) := []
  rows : Array (String × List String) := #[]           -- FAST: was a List grown by `++ [x]`
  /-- `pin` of the current `snaps` and `rows`; cleared whenever either changes.  -- FAST -/
  pinned : Option Pinned := none
  extra : List Line := []
  held : List Line := []
  rprior : Snapshot Line := ⟨0, 0, []⟩
  uprior : Snapshot Line := ⟨0, 0, []⟩
  anchor : Option Nat := none
  batch : Array (Line × Option String) := #[]          -- FAST
  redo : List Nat := []
  /-- Ids the tenant's id registry gives another shard, for the next commit. -/
  foreign : List Nat := []
  /-- The id registry's answers to shard K, and the expected freed ids, for the next commit. -/
  owners : Option (Nat × List Owner) := none
  free : Option (List Nat) := none
  pays : List (Nat × String) := []
  done : List Decision := []
  checked : Nat := 0
  failed : Nat := 0
  expected : Option Nat := none
  /-- A checkpoint (`load`, `anchor` or a commit) precedes the next commit; else its read-set base is the declared sets'. -/
  sealed : Bool := false

/-- A declared snapshot and its pin, checked against the declared one. -/
def snapshot {α : Type} (st : St) (kind : String) (row : List String → Option α) (domain : String) (k : Nat)
    (fields : α → List (Nat × Nat)) : Option (Snapshot α × List UInt8) := do
  let (asOf, count, pin) ← st.snaps.lookup kind
  let s : Snapshot α := ⟨asOf, count, ← ((st.rows.filter (·.1 == kind)).toList.map (·.2)).mapM row⟩
  let h := BlindLedger.Semantic.sha3_512Fast (← Fast.pinBytes domain k fields s)   -- FAST: `pin_run_eq`
  guard (hexOf h == pin)
  pure (s, h.toList)

def parseLine : List String → Option Line
  | [i, f, m, p, r, d, c, u, a] => do
    let (i, y) ← match i.splitOn ":" with | [i] => some (i, i) | [i, y] => some (i, y) | _ => none
    pure ⟨← i.toNat?, ← y.toNat?, ← parse [Flow.FFS_CYCLE, .FFS_CLAIM, .CAP_820] f, ← m.toNat?, ← p.toNat?,
      ← r.toNat?, ← d.toNat?, ← c.toNat?, ← u.toNat?, ← a.toNat?⟩
  | _ => none

def death (r : List String) : Option Death := match r.mapM String.toNat? with
  | some [i, d] => some ⟨i, d⟩
  | _ => none

/-- A set plus the lines earlier commits added to it. -/
def grow (o : Option (Snapshot Line)) (xs : List Line) : Option (Snapshot Line) :=
  o.map fun s => { s with count := s.count + xs.length, entries := s.entries ++ xs }

/-- One kind's SNAPSHOT/v1 pin (zero if none; refused if zero) and READ-*/v2 slot (`ReadManifest.kindOf`). -/
def readPin {α : Type} (d : String) (k : Nat) (f : α → List (Nat × Nat)) :
    Option (Snapshot α × List UInt8) → Option (List UInt8 × List UInt8)
  | none => some (Gate.zeroDigest, [0])
  | some (s, p) => do
    guard (p ≠ Gate.zeroDigest)
    let q ← Fast.pinBytes d k f s
    pure (p, 1 :: hB q)

def St.pin (st : St) : Pinned :=
  let dmf := snapshot st "dmf" death "RR/GATE/SNAPSHOT/v1" 1 Death.fields
  let pdeath := snapshot st "pdeath" death "RR/GATE/SNAPSHOT/v1" 2 Death.fields
  let excl := snapshot st "excl" (fun r => match r.mapM String.toNat? with
    | some [i, a, b] => some ⟨i, a, b⟩
    | _ => none) "RR/GATE/SNAPSHOT/v1" 3 Exclusion.fields
  let span := snapshot st "span" (fun r => match r.mapM String.toNat? with
    | some [m, p, a, b] => some ⟨m, p, a, b⟩
    | _ => none) "RR/GATE/SNAPSHOT/v1" 4 Span.fields
  { dmf, pdeath, excl, span,
    released := snapshot st "released" parseLine "RR/GATE/RELEASED/v1" 5 Line.fields
    unresolved := snapshot st "unresolved" parseLine "RR/GATE/UNRESOLVED/v1" 6 Line.fields
    kinds := do pure [← readPin "RR/GATE/READ-DMF/v2" 1 Death.fields dmf, ← readPin "RR/GATE/READ-PROVIDER-DEATH/v2" 2 Death.fields pdeath,
      ← readPin "RR/GATE/READ-EXCLUSION/v2" 3 Exclusion.fields excl, ← readPin "RR/GATE/READ-ENROLLMENT/v2" 4 Span.fields span] }

def St.ctx (st : St) (p : Pinned) : Ctx where
  today := st.today
  dmf := p.dmf.map (·.1)
  providerDeaths := p.pdeath.map (·.1)
  exclusions := p.excl.map (·.1)
  enrollment := p.span.map (·.1)
  released := grow (p.released.map (·.1)) st.extra
  unresolved := grow (p.unresolved.map (·.1)) st.held
  releasedPrior := st.rprior
  unresolvedPrior := st.uprior
  anchor := 0
  redo := st.redo

def lineText (l : Line) : String :=
  s!"{l.id}:{l.pay} {name l.flow} {l.member} {l.payee} {l.rendering} {l.date} {l.proc} {l.units} {l.cents}"

def render (d : Decision) : String :=
  let rs := if d.reasons.isEmpty then "-" else ",".intercalate (d.reasons.map name)
  let w := if d.counterparts.isEmpty then "" else s!" with={",".intercalate (d.counterparts.map toString)}"
  s!"{lineText d.line} {name d.outcome} {rs}{w}"

def sorted (xs : List String) : List String := xs.mergeSort fun a b => decide (a < b) || a == b

def money (cents : Nat) : String :=
  let c := toString (cents % 100)
  s!"${cents / 100}.{if c.length < 2 then "0" ++ c else c}"

def tally (ds : List Decision) : String :=
  let c := ds.foldl (· + ·.line.cents) 0
  s!"lines={ds.length} cents={c} ({money c})"

/-- Each id once, first occurrence first: an `owners` line may carry an id once per request, `settleFree` keeps each. -/
def uniq (ids : List Nat) : List Nat :=
  (ids.foldl (fun (s, r) i => if s.contains i then (s, r) else (s.insert i, i :: r))
    ((∅ : Std.HashSet Nat), ([] : List Nat))).2.reverse

/-- `RULES_READS`: u32 today ‖ the four SNAPSHOT/v1 pins ‖ u32 |P| ‖ P, P the READ-SET/v2 bytes over `base`, redo in
    the order read (`ReadManifest.run_reads_eq`). -/
def reads (p : Pinned) (c : Ctx) (base : List UInt8) : Option (List UInt8) := do
  let ks ← p.kinds
  let pre := "RR/GATE/READ-SET/v2".toUTF8.toList ++ [0] ++ (ks.map (·.2)).flatten ++ (← be 4 c.redo.length) ++
    (← c.redo.mapM (be payWidth)).flatten ++ base
  pure ((← be 4 c.today) ++ (ks.map (·.1)).flatten ++ (← be 4 pre.length) ++ pre)

def commit (st : St) (unanchored : Bool) : St × List String :=
  let p := st.pinned.getD st.pin                        -- FAST: pin once per declaration
  let c := st.ctx p
  -- `Gate.decideAnchored`, with the twin deciding (`FastEq`): an unanchored batch decides nothing.
  if !st.anchor.all fun a => Fast.setsDigestF hB c.releasedPrior c.unresolvedPrior == some (Gate.natBE Gate.digestBytes a) then
    ({ st with pinned := some p, anchor := none, batch := #[], redo := [], foreign := [], owners := none,
               free := none, pays := [],
               checked := st.checked + unanchored.toNat, failed := st.failed + (!unanchored).toNat },
     if unanchored then [] else ["RULES_UNANCHORED commit"])
  else
  let lines := st.batch.toList.map (·.1)
  -- `owners`: `Fast.decideRegF` (= `decideReg`, `decideRegF_eq`) with the waiting lines left out.
  let (b, f, wait) : List Line × List Nat × List Line := match st.owners with
    | some (k, os) =>
      let b := Fast.readyF k os lines
      let ps := Std.HashSet.ofList (b.map (·.pay))
      (b, Fast.foreignOfF k os b, lines.filter fun l => !ps.contains l.pay)
    | none => (lines, st.foreign, [])
  let x := Fast.Ix.build c b                            -- FAST
  let r := x.runIn f b                                  -- FAST: = decideBatchIn c f b
  let exp := st.batch.toList.filterMap (·.2)
  let got := r.decisions.map render ++ wait.map (lineText · ++ " WAIT -")
  let fr := st.owners.map fun (k, os) => uniq (Fast.settleFreeF r.released.entries r.unresolved.entries (pendingOf k os))
  let frOk := st.free.all (some · == fr)
  let bad := st.pays.filter fun (q, o) => name (x.payOutcome r.decisions q) != o
  let (ok, n, msg) :=
    if exp.isEmpty then (true, 0, [])                   -- FAST: no reversed re-run
    else if exp.length == lines.length && sorted exp == sorted got then (true, lines.length, [])
    else (false, 0, ((sorted got).filter (!exp.contains ·)).map ("RULES_GOT " ++ ·))
  let ok := ok && bad.isEmpty && !unanchored && frOk
  let msg := msg ++ bad.map (fun (q, o) => s!"RULES_PAY {q} expected={o}") ++
    (if unanchored then ["RULES_ANCHORED commit"] else []) ++ (if frOk then [] else [s!"RULES_FREE_EXPECTED {st.free}"])
  let fresh := (r.released.entries.drop x.relN, r.unresolved.entries.drop x.unrN)
  let adds := do pure ((← fresh.1.mapM (rowBytes 1)) ++ (← fresh.2.mapM (rowBytes 2))).flatten
  -- The checkpoint extended; before the first, the declared sets (pins from declaration) or the empty priors.
  let pinOf (o : Option (Snapshot Line × List UInt8)) (d : String) (k : Nat) (s : Snapshot Line) :=
    o.elim ((Fast.pinBytes d k Line.fields s).map hB) (some ·.2)
  let base := if st.sealed then Fast.setsDigestF hB c.releasedPrior c.unresolvedPrior else do
    pure (Gate.stateDigest (fun x => hB ⟨x.toArray⟩) (← pinOf p.released "RR/GATE/RELEASED/v1" 5 c.releasedPrior)
      (← pinOf p.unresolved "RR/GATE/UNRESOLVED/v1" 6 c.unresolvedPrior))
  let shown := fr.elim [] fun ids => got.map ("RULES_LINE " ++ ·) ++ [" ".intercalate ("RULES_FREE" :: ids.map toString)] ++
    (Fast.setsDigestF hB r.released r.unresolved).toList.map (fun d => s!"RULES_DIGEST {hexOf d.toByteArray}") ++
    adds.toList.map (fun b => s!"RULES_ADDS {hexOf b.toByteArray}") ++
    (base.bind (reads p c)).toList.map fun b => s!"RULES_READS {hexOf b.toByteArray}"
  ({ st with pinned := some p, anchor := none, sealed := true,
             extra := st.extra ++ fresh.1,                            -- FAST: `run_relN`
             held := st.held ++ fresh.2,
             rprior := r.released, uprior := r.unresolved, batch := #[], redo := [], foreign := [], owners := none,
             free := none, pays := [],
             done := st.done ++ r.decisions, checked := st.checked + (if ok then n + st.pays.length else 0),
             failed := st.failed + (if ok then 0 else 1) },
   shown ++ if ok then [] else "RULES_VECTOR_MISMATCH commit" :: msg)

/-- `ID:SHARD:0|1`, the last field whether the shard's batch since sealed. -/
def parseOwner (o : String) : Option Owner := match o.splitOn ":" with
  | [i, s, b] => do
    guard (b == "0" || b == "1")
    pure ⟨← i.toNat?, ← s.toNat?, b == "1"⟩
  | _ => none

def step (st : St) : List String → Option (St × List String)
  | ["case", _] => pure ({ st with extra := [], held := [], rprior := ⟨0, 0, []⟩, uprior := ⟨0, 0, []⟩,
                                   anchor := none, batch := #[], redo := [], foreign := [], owners := none, free := none,
                                   pays := [], done := [], sealed := false }, [])
  | ["anchor", h] => do
    guard (h.length == 128)
    pure ({ st with sealed := true, anchor := some (← h.toList.foldlM (fun n x => (n * 16 + ·) <$> "0123456789abcdef".toList.idxOf? x) 0) }, [])
  | ["load", a, adds, h] => do
    guard (h.length == 128)
    let g : Snapshot Line := ⟨← a.toNat?, 0, []⟩
    let anchor := Gate.beNat (← unhex h).toList
    let bs ← if adds == "-" then pure ByteArray.empty else unhex adds   -- `-` is zero rows (the field cannot be empty)
    -- `Gate.ShardState.loadAdds`, with the fast digest (`Fast.setsDigestF_eq`)
    match (parseAdds bs).bind fun ad => let s := Rules.replay (g, g) [ad]
        (Fast.setsDigestF hB s.1 s.2).bind fun d => if d == Gate.natBE Gate.digestBytes anchor then some s else none with
    | none => pure ({ st with failed := st.failed + 1 }, ["RULES_STATE_MISMATCH load"])
    | some s => pure ({ st with
        snaps := ("released", g.asOf, 0, ← emptyPin "released" g.asOf) :: ("unresolved", g.asOf, 0, ← emptyPin "unresolved" g.asOf) :: st.snaps,
        rows := st.rows.filter fun r => r.1 != "released" && r.1 != "unresolved", pinned := none, anchor := none,
        extra := s.1.entries, held := s.2.entries, rprior := s.1, uprior := s.2, sealed := true }, [])
  | ["today", d] => do pure ({ st with today := ← d.toNat? }, [])
  | ["snap", k, a, n, pin] => do
    pure ({ st with snaps := (k, ← a.toNat?, ← n.toNat?, pin) :: st.snaps, rows := st.rows.filter (·.1 != k),
                    pinned := none,
                    extra := if k == "released" then [] else st.extra,
                    held := if k == "unresolved" then [] else st.held }, [])
  | ["drop", k] => pure ({ st with snaps := st.snaps.filter (·.1 != k), pinned := none }, [])
  | "line" :: fs => do
    let l ← parseLine (fs.take 9)
    let e := fs.drop 9
    guard ([0, 2, 3].contains e.length)
    pure ({ st with batch := st.batch.push (l, if e.isEmpty then none else some (" ".intercalate (lineText l :: e))) }, [])
  | ["redo", p] => do pure ({ st with redo := (← p.toNat?) :: st.redo }, [])
  | "foreign" :: ids => do pure ({ st with foreign := ← ids.mapM String.toNat? }, [])
  | "owners" :: k :: os => do pure ({ st with owners := some (← k.toNat?, ← os.mapM parseOwner) }, [])
  | "free" :: ids => do pure ({ st with free := some (← ids.mapM String.toNat?) }, [])
  | ["pay", p, o] => do pure ({ st with pays := st.pays ++ [(← p.toNat?, o)] }, [])
  | ["commit"] => pure (commit st false)
  | ["commit", "UNANCHORED"] => pure (commit st true)
  | ["report"] =>
    let by_ (p : Decision → Bool) := tally (st.done.filter p)
    pure (st, s!"REPORT all {by_ fun _ => true}" ::
      ([Outcome.ALLOW, .HOLD, .HUMAN_REVIEW].map fun o => s!"REPORT {name o} {by_ (·.outcome == o)}") ++
      reasons.map fun r => s!"REPORT {name r} {by_ (·.reasons.contains r)}")
  | ["end", n] => do pure ({ st with expected := some (← n.toNat?) }, [])
  | k :: fs => do
    guard (["dmf", "pdeath", "excl", "span", "released", "unresolved"].contains k)
    pure ({ st with rows := st.rows.push (k, fs), pinned := none }, [])
  | [] => none

/-- The vector text through the rules: the output lines (the one-shot `main` prints them after `RULES_SOURCE`; the
    worker answers a frame with them) and whether it passed.  Each text starts from the empty state. -/
def runText (text : String) : Array String × Bool := Id.run do
  let mut st : St := {}
  let mut out : Array String := #[]
  let mut number := 0
  for raw in text.splitOn "\n" do
    number := number + 1
    let fields := ((String.ofList (raw.toList.filter (· ≠ '\r'))).splitOn " ").filter (· ≠ "")
    if fields.isEmpty || fields.head!.startsWith "#" then continue
    match step st fields with
    | none =>
      st := { st with failed := st.failed + 1 }
      out := out.push s!"RULES_VECTOR_MALFORMED line={number}"
    | some (next, lines) =>
      if next.failed > st.failed then out := out.push s!"RULES_VECTOR_FAIL line={number}"
      st := next
      out := out ++ lines
  let pass := st.failed == 0 && st.expected == some st.checked
  return (out.push s!"RULES_VECTORS={if pass then "PASS" else "FAIL"} checked={st.checked} expected={st.expected.getD 0} failed={st.failed}", pass)

def main (args : List String) : IO UInt32 := do
  IO.println s!"RULES_SOURCE {source}"
  let [path] := args
    | IO.eprintln "RULES_VECTORS=USAGE gate_rules <path>"
      return 2
  let (out, pass) := runText (← IO.FS.readFile path)
  out.forM IO.println
  return (if pass then 0 else 1)

/-! Long-lived worker (`gate_rules_worker`), the shape of `Financial.WorkerCli`: each stdin frame is a u32 BE length and
    a vector text, each stdout frame a u32 BE length and `runText`'s lines.  Clean end of input exits 0; a short, oversize
    or non-UTF-8 frame, or an answer past the cap, exits 65 without output. -/

def maxFrame : Nat := 64 * 1024 * 1024

partial def readN (read : USize → IO ByteArray) (n : Nat) (acc : ByteArray := .empty) : IO ByteArray := do
  if acc.size ≥ n then return acc
  let b ← read (min (n - acc.size) 1048576).toUSize
  if b.size = 0 then return acc else readN read n (acc ++ b)

partial def serve (read : USize → IO ByteArray) (write : ByteArray → IO Unit) : IO UInt32 := do
  let h ← readN read 4
  if h.size = 0 then return 0
  let n := h.foldl (fun a b => a * 256 + b.toNat) 0
  if h.size < 4 || n > maxFrame then return 65
  let f ← readN read n
  if f.size < n then return 65
  let some text := String.fromUTF8? f | return 65
  let resp := (String.join ((runText text).1.toList.map (· ++ "\n"))).toUTF8
  if resp.size > maxFrame then return 65
  write (ByteArray.mk #[(resp.size >>> 24).toUInt8, (resp.size >>> 16).toUInt8, (resp.size >>> 8).toUInt8, resp.size.toUInt8] ++ resp)
  serve read write

end BlindLedger.Gate.Rules.Run
