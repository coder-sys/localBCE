import BlindLedger.Gate.Rules.Spec
import BlindLedger.Sha3

namespace BlindLedger.Gate.Rules.Run

open BlindLedger.Gate.Rules

/-! Runs a rules vector file through `decideBatch`.  Directives, one per line:
    `case NAME` clears the batch, the totals and the lines earlier commits
    released or left unresolved; `today D`; `snap KIND ASOF COUNT PIN`
    (re)declares a snapshot (`dmf`, `pdeath`, `excl`, `span`) or the
    `released` or `unresolved` set (rows `FLOW M PAYEE REND DATE PROC UNITS
    CENTS`; it also drops the lines earlier commits added to that set), whose
    rows are the following lines starting with KIND.  PIN is the SHA3-512 hex
    of `RR/GATE/RELEASED/v1`, `RR/GATE/UNRESOLVED/v1` (for those sets) or
    `RR/GATE/SNAPSHOT/v1`, then `KIND ASOF COUNT` and the rows, joined by
    newlines; a snapshot whose pin does not match or with a row that does not
    parse is treated as missing, as is one after `drop KIND`.
    `line ...released row fields... [OUTCOME REASONS]` adds a line to the batch;
    `commit` decides it, checks the expectations (all lines or none) and that
    the reversed batch decides the same, then adds its ALLOW lines to the
    released set and its other enrolled lines to the unresolved set; `report` prints totals; `end N` is the number of checked
    lines.  Test-only; never a payment path. -/

def name {α : Type} [Repr α] (x : α) : String := ((reprStr x).splitOn ".").getLast!

def parse {α : Type} [Repr α] (all : List α) (s : String) : Option α := all.find? (name · == s)

#guard (reasons.map name).zip ((reasons.map name).drop 1) |>.all fun (a, b) => decide (a < b)

def hexOf (b : ByteArray) : String :=
  String.join (b.toList.map fun x =>
    let h := Nat.toDigits 16 x.toNat
    String.ofList (if h.length < 2 then '0' :: h else h))

structure St where
  today : Nat := 0
  snaps : List (String × Nat × Nat × String) := []
  rows : List (String × List String) := []
  extra : List Line := []
  held : List Line := []
  batch : List (Line × Option String) := []
  done : List Decision := []
  checked : Nat := 0
  failed : Nat := 0
  expected : Option Nat := none

def snapshot {α : Type} (st : St) (kind : String) (row : List String → Option α) : Option (Snapshot α) := do
  let (asOf, count, pin) ← st.snaps.lookup kind
  let rows := (st.rows.filter (·.1 == kind)).map (·.2)
  let domain := if kind == "released" || kind == "unresolved" then s!"RR/GATE/{kind.toUpper}/v1"
    else "RR/GATE/SNAPSHOT/v1"
  let text := "\n".intercalate (domain :: s!"{kind} {asOf} {count}" :: rows.map (" ".intercalate <| kind :: ·))
  guard (hexOf (BlindLedger.Semantic.sha3_512 text.toUTF8) == pin)
  pure ⟨asOf, count, ← rows.mapM row⟩

def parseLine : List String → Option Line
  | [f, m, p, r, d, c, u, a] => do
    pure ⟨← parse [Flow.FFS_CYCLE, .FFS_CLAIM, .CAP_820] f, ← m.toNat?, ← p.toNat?, ← r.toNat?,
      ← d.toNat?, ← c.toNat?, ← u.toNat?, ← a.toNat?⟩
  | _ => none

def death (r : List String) : Option Death := match r.mapM String.toNat? with
  | some [i, d] => some ⟨i, d⟩
  | _ => none

/-- A set plus the lines earlier commits added to it. -/
def grow (o : Option (Snapshot Line)) (xs : List Line) : Option (Snapshot Line) :=
  o.map fun s => { s with count := s.count + xs.length, entries := s.entries ++ xs }

def St.ctx (st : St) : Ctx where
  today := st.today
  dmf := snapshot st "dmf" death
  providerDeaths := snapshot st "pdeath" death
  exclusions := snapshot st "excl" fun r => match r.mapM String.toNat? with
    | some [i, a, b] => some ⟨i, a, b⟩
    | _ => none
  enrollment := snapshot st "span" fun r => match r.mapM String.toNat? with
    | some [m, p, a, b] => some ⟨m, p, a, b⟩
    | _ => none
  released := grow (snapshot st "released" parseLine) st.extra
  unresolved := grow (snapshot st "unresolved" parseLine) st.held

def lineText (l : Line) : String :=
  s!"{name l.flow} {l.member} {l.payee} {l.rendering} {l.date} {l.proc} {l.units} {l.cents}"

def render (d : Decision) : String :=
  let rs := if d.reasons.isEmpty then "-" else ",".intercalate (d.reasons.map name)
  s!"{lineText d.line} {name d.outcome} {rs}"

def sorted (xs : List String) : List String := xs.mergeSort fun a b => decide (a < b) || a == b

def money (cents : Nat) : String :=
  let c := toString (cents % 100)
  s!"${cents / 100}.{if c.length < 2 then "0" ++ c else c}"

def tally (ds : List Decision) : String :=
  let c := ds.foldl (· + ·.line.cents) 0
  s!"lines={ds.length} cents={c} ({money c})"

def commit (st : St) : St × List String :=
  let c := st.ctx
  let lines := st.batch.map (·.1)
  let r := decideBatch c lines
  let det := decideBatch c lines.reverse == r
  let exp := st.batch.filterMap (·.2)
  let got := r.decisions.map render
  let (ok, n, msg) :=
    if exp.isEmpty then (det, 0, [])
    else if exp.length == lines.length && det && sorted exp == sorted got then (true, lines.length, [])
    else (false, 0, ((sorted got).filter (!exp.contains ·)).map ("RULES_GOT " ++ ·))
  ({ st with extra := st.extra ++ r.released.drop (entries c.released).length,
             held := st.held ++ r.unresolved.drop (entries c.unresolved).length,
             batch := [], done := st.done ++ r.decisions, checked := st.checked + n, failed := st.failed + (if ok then 0 else 1) },
   if ok then [] else s!"RULES_VECTOR_MISMATCH commit determinism={det}" :: msg)

def step (st : St) : List String → Option (St × List String)
  | ["case", _] => pure ({ st with extra := [], held := [], batch := [], done := [] }, [])
  | ["today", d] => do pure ({ st with today := ← d.toNat? }, [])
  | ["snap", k, a, n, pin] => do
    pure ({ st with snaps := (k, ← a.toNat?, ← n.toNat?, pin) :: st.snaps, rows := st.rows.filter (·.1 != k),
                    extra := if k == "released" then [] else st.extra,
                    held := if k == "unresolved" then [] else st.held }, [])
  | ["drop", k] => pure ({ st with snaps := st.snaps.filter (·.1 != k) }, [])
  | "line" :: fs => do
    let (fs, e) := (fs.take 8, fs.drop 8)
    let l ← parseLine fs
    let e ← match e with
      | [] => pure none
      | [o, rs] => pure (some s!"{lineText l} {o} {rs}")
      | _ => none
    pure ({ st with batch := st.batch ++ [(l, e)] }, [])
  | ["commit"] => pure (commit st)
  | ["report"] =>
    let by_ (p : Decision → Bool) := tally (st.done.filter p)
    pure (st, s!"REPORT all {by_ fun _ => true}" ::
      ([Outcome.ALLOW, .HOLD, .HUMAN_REVIEW].map fun o => s!"REPORT {name o} {by_ (·.outcome == o)}") ++
      reasons.map fun r => s!"REPORT {name r} {by_ (·.reasons.contains r)}")
  | ["end", n] => do pure ({ st with expected := some (← n.toNat?) }, [])
  | k :: fs => do
    guard (["dmf", "pdeath", "excl", "span", "released", "unresolved"].contains k)
    pure ({ st with rows := st.rows ++ [(k, fs)] }, [])
  | [] => none

def main (args : List String) : IO UInt32 := do
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
