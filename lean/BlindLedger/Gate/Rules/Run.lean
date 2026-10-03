import BlindLedger.Gate.Anchor
import BlindLedger.Gate.Rules.Fast
import BlindLedger.Sha3Fast
import BlindLedger.Sha3

/-! The test-only vector runner: decides with `Fast.decideBatchFIn` (= `decideBatchIn`, `FastEq.decideBatchFIn_eq`; no reversed re-run, order independence `Theorems.decideBatchIn_perm`) and pins with `Fast.pinBytes` (`pin_run_eq`). Lines marked `-- FAST` differ from the pre-twin runner. -/

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
    digest after it (`RULES_DIGEST`, `Gate.setsDigest`) and the rows it appended (`RULES_ADDS`: per row
    `u8 set` (1 released, 2 unresolved) then the `Line.fields` row, hex).  `load G_ASOF ADDSHEX ANCHORHEX`
    drops the released and unresolved sets and replays those rows onto empty sets dated G_ASOF
    (`ShardState.loadAdds`); unless they hash to ANCHORHEX it prints `RULES_STATE_MISMATCH` and fails.  Arrival
    order cannot change a decision (`decideBatchIn_perm`).  `report`
    prints totals; `end N` is the number of checked lines.  Test-only; never
    a payment path. -/

def name {α : Type} [Repr α] (x : α) : String := ((reprStr x).splitOn ".").getLast!

def parse {α : Type} [Repr α] (all : List α) (s : String) : Option α := all.find? (name · == s)

#guard (reasons.map name).zip ((reasons.map name).drop 1) |>.all fun (a, b) => decide (a < b)

def h512 (x : List UInt8) : List UInt8 := (BlindLedger.Semantic.sha3_512Fast x.toByteArray).toList

def hexOf (b : ByteArray) : String :=
  String.join (b.toList.map fun x =>
    let h := Nat.toDigits 16 x.toNat
    String.ofList (if h.length < 2 then '0' :: h else h))

/-- SHA3-512 of the sources this runner was built from, CRLF read as LF; the unit test recomputes
    it from the files, so a stale runner fails that test whatever its file times. -/
def source : String := hexOf (BlindLedger.Semantic.sha3_512 (String.join [include_str "Spec.lean",
  include_str "Fast.lean", include_str "Run.lean",  -- FAST
  include_str "../Anchor.lean", include_str "../Spec.lean",
  include_str "../../Sha3.lean", include_str "../../Sha3Fast.lean", include_str "../../../lakefile.toml",
  include_str "../../../lean-toolchain"]).crlfToLf.toUTF8)

/-- Hex to bytes, high digit first. -/
def unhex (s : String) : Option (List UInt8) := do
  let ds ← s.toList.mapM ("0123456789abcdef".toList.idxOf? ·)
  guard (ds.length % 2 == 0)
  pure ((List.range (ds.length / 2)).map fun i => (ds[2 * i]! * 16 + ds[2 * i + 1]!).toUInt8)

/-- One `RULES_ADDS` row: the set tag, then the `Line.fields` row. -/
def rowBytes (tag : UInt8) (l : Line) : Option (List UInt8) :=
  do let bs ← l.fields.mapM fun (w, n) => be w n
     pure (tag :: bs.flatten)

def rowWidths : List Nat := (Line.fields ⟨0, 0, .FFS_CYCLE, 0, 0, 0, 0, 0, 0, 0⟩).map (·.1)

def parseRow (bs : List UInt8) : Option (UInt8 × Line) := do
  let t :: bs := bs | none
  match (rowWidths.foldl (fun (r, bs) w => (r ++ [Gate.beNat (bs.take w)], bs.drop w)) ([], bs)).1 with
  | [i, y, f, m, p, r, d, c, u, a] =>
    pure (t, ⟨i, y, ← [Flow.FFS_CYCLE, .FFS_CLAIM, .CAP_820].find? (·.tag == f), m, p, r, d, c, u, a⟩)
  | _ => none

/-- `RULES_ADDS` back into the released and unresolved rows. -/
def parseAdds (bs : List UInt8) : Option (List Line × List Line) := do
  let n := 1 + rowWidths.sum
  guard (bs.length % n == 0)
  let rows ← (List.range (bs.length / n)).mapM fun i => parseRow ((bs.drop (n * i)).take n)
  guard (rows.all fun (t, _) => t == 1 || t == 2)
  pure ((rows.filter (·.1 == 1)).map (·.2), (rows.filter (·.1 == 2)).map (·.2))

/-- The pin of an empty set dated `a` (`snapshot`'s check, for a set that `load` declares). -/
def emptyPin (kind : String) (a : Nat) : Option String :=
  (Fast.pinBytes s!"RR/GATE/{kind.toUpper}/v1" (if kind == "released" then 5 else 6) Line.fields
    (⟨a, 0, []⟩ : Snapshot Line)).map fun b => hexOf (BlindLedger.Semantic.sha3_512Fast b)

/-- The six pinned inputs, parsed and pin-checked once per declaration.  -- FAST -/
structure Pinned where
  dmf : Option (Snapshot Death)
  pdeath : Option (Snapshot Death)
  excl : Option (Snapshot Exclusion)
  span : Option (Snapshot Span)
  released : Option (Snapshot Line)
  unresolved : Option (Snapshot Line)

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

def snapshot {α : Type} (st : St) (kind : String) (row : List String → Option α)
    (fields : α → List (Nat × Nat)) : Option (Snapshot α) := do
  let (asOf, count, pin) ← st.snaps.lookup kind
  let s : Snapshot α := ⟨asOf, count, ← ((st.rows.filter (·.1 == kind)).toList.map (·.2)).mapM row⟩
  let domain := if kind == "released" || kind == "unresolved" then s!"RR/GATE/{kind.toUpper}/v1"
    else "RR/GATE/SNAPSHOT/v1"
  let kinds := ["dmf", "pdeath", "excl", "span", "released", "unresolved"]
  let bytes ← Fast.pinBytes domain (kinds.idxOf kind + 1) fields s   -- FAST: `pin_run_eq`
  guard (hexOf (BlindLedger.Semantic.sha3_512Fast bytes) == pin)
  pure s

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

def St.pin (st : St) : Pinned where
  dmf := snapshot st "dmf" death Death.fields
  pdeath := snapshot st "pdeath" death Death.fields
  excl := snapshot st "excl" (fun r => match r.mapM String.toNat? with
    | some [i, a, b] => some ⟨i, a, b⟩
    | _ => none) Exclusion.fields
  span := snapshot st "span" (fun r => match r.mapM String.toNat? with
    | some [m, p, a, b] => some ⟨m, p, a, b⟩
    | _ => none) Span.fields
  released := snapshot st "released" parseLine Line.fields
  unresolved := snapshot st "unresolved" parseLine Line.fields

def St.ctx (st : St) (p : Pinned) : Ctx where
  today := st.today
  dmf := p.dmf
  providerDeaths := p.pdeath
  exclusions := p.excl
  enrollment := p.span
  released := grow p.released st.extra
  unresolved := grow p.unresolved st.held
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

def commit (st : St) (unanchored : Bool) : St × List String :=
  let p := st.pinned.getD st.pin                        -- FAST: pin once per declaration
  let c := st.ctx p
  -- `Gate.decideAnchored`, with the twin deciding (`FastEq`): an unanchored batch decides nothing.
  if !st.anchor.all fun a => Gate.anchored h512 { c with anchor := a } then
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
  let shown := fr.elim [] fun ids => got.map ("RULES_LINE " ++ ·) ++ [" ".intercalate ("RULES_FREE" :: ids.map toString)] ++
    (Gate.setsDigest h512 r.released r.unresolved).toList.map (fun d => s!"RULES_DIGEST {hexOf d.toByteArray}") ++
    adds.toList.map fun b => s!"RULES_ADDS {hexOf b.toByteArray}"
  ({ st with pinned := some p, anchor := none,
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
                                   pays := [], done := [] }, [])
  | ["anchor", h] => do
    guard (h.length == 128)
    pure ({ st with anchor := some (← h.toList.foldlM (fun n x => (n * 16 + ·) <$> "0123456789abcdef".toList.idxOf? x) 0) }, [])
  | ["load", a, adds, h] => do
    guard (h.length == 128)
    let g : Snapshot Line := ⟨← a.toNat?, 0, []⟩
    let anchor := Gate.beNat (← unhex h)
    match (parseAdds (← unhex adds)).bind fun ad => Gate.ShardState.loadAdds h512 (g, g) [ad] anchor with
    | none => pure ({ st with failed := st.failed + 1 }, ["RULES_STATE_MISMATCH load"])
    | some s => pure ({ st with
        snaps := ("released", g.asOf, 0, ← emptyPin "released" g.asOf) :: ("unresolved", g.asOf, 0, ← emptyPin "unresolved" g.asOf) :: st.snaps,
        rows := st.rows.filter fun r => r.1 != "released" && r.1 != "unresolved", pinned := none, anchor := none,
        extra := s.released.entries, held := s.unresolved.entries, rprior := s.released, uprior := s.unresolved }, [])
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

def main (args : List String) : IO UInt32 := do
  IO.println s!"RULES_SOURCE {source}"
  let [path] := args
    | IO.eprintln "RULES_VECTORS=USAGE gate_rules <path>"
      return 2
  let mut st : St := {}
  let mut number := 0
  for raw in (← IO.FS.readFile path).splitOn "\n" do
    number := number + 1
    let fields := ((String.ofList (raw.toList.filter (· ≠ '\r'))).splitOn " ").filter (· ≠ "")
    if fields.isEmpty || fields.head!.startsWith "#" then continue
    match step st fields with
    | none =>
      st := { st with failed := st.failed + 1 }
      IO.println s!"RULES_VECTOR_MALFORMED line={number}"
    | some (next, out) =>
      if next.failed > st.failed then IO.println s!"RULES_VECTOR_FAIL line={number}"
      st := next
      out.forM IO.println
  let pass := st.failed == 0 && st.expected == some st.checked
  IO.println s!"RULES_VECTORS={if pass then "PASS" else "FAIL"} checked={st.checked} expected={st.expected.getD 0} failed={st.failed}"
  return (if pass then 0 else 1)

end BlindLedger.Gate.Rules.Run

def main (args : List String) : IO UInt32 := BlindLedger.Gate.Rules.Run.main args
