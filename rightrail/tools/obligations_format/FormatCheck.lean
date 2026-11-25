import BlindLedger.Gate.Obligations.Format.Fast
import BlindLedger.Gate.Obligations.Format.Fold

/-! `obligations_format_check`: the test program of the obligations record format (design `one-store` §16.12); not
    pinned, never shipped.

    * `vectors`: one valid record of every kind, in the order of `catalog`: its hex, then each cell by name as the
      model reads it; one link; for every record rule a body that breaks it (`refuse`), and bodies at the edge of
      the rules that read (`accept`); then every fold example of `Format.Fold`: the opening's fields, each record
      with what its element gives, and the fold record `foldOf` makes.  `conformance/OBLIGATIONS_V1.md` holds this
      output.
    * `fuzz SEED N`: for every codec and the link, every length from 0 to twice the record's, every single-bit flip
      of the valid record, and `N` random and mutated inputs drawn from `SEED`.  Each input goes to the `ByteArray`
      reader and to the `List` model, which must give the same answer, and every accepted input must come back
      byte for byte from the guarded writer.  Exit 1 on any difference.
    * `verdicts SEED N`: for every record kind, `N` copies of its valid record with one or two fields set to values
      drawn near the rules' bounds; one line per input with the reader's answer, for a second reader to compare.
    * `folds FILE`: for each fold example of the file (the vectors' lines), one line with the fold record `foldWrite`
      gives, or `none`, for a second reader to compare.
    * `timing`: for every record kind, nanoseconds per call of the twins and of the model, each the median of three
      runs; reported, never checked. -/

open BlindLedger.Gate.FactCodec
open BlindLedger.Gate.Obligations
open BlindLedger.Gate.Obligations.Format

def timeIt (iters : Nat) (f : Nat → Nat) : IO (Nat × Nat) := do
  let t0 ← IO.monoNanosNow
  let mut acc := 0
  for i in [0:iters] do acc := acc + f i
  let t1 ← IO.monoNanosNow
  return ((t1 - t0) / iters, acc)

/-- The median of three runs, and a sum of the results so that no call is skipped. -/
def median3 (iters : Nat) (f : Nat → Nat) : IO (Nat × Nat) := do
  let (a, x) ← timeIt iters f
  let (b, y) ← timeIt iters f
  let (c, z) ← timeIt iters f
  let m := if a ≤ b then (if b ≤ c then b else if a ≤ c then c else a) else (if a ≤ c then a else if b ≤ c then c else b)
  return (m, x + y + z)

structure Probe where
  name : String
  L : List Fld
  sample : ByteArray
  /-- `none` when the reader and the model agree and an accepted input comes back from the guarded writer. -/
  check : ByteArray → Option String
  /-- The reader's answer. -/
  accepts : ByteArray → Bool
  cells : ByteArray → Option (List Cell)
  /-- Medians in nanoseconds: twin writer, twin reader, model writer, model reader; and a sink. -/
  time : IO (Nat × Nat × Nat × Nat × Nat)

def probe {α : Type} [DecidableEq α] (name : String) (t : Twin α) (s : α) : Probe where
  name := name
  L := t.c.L
  sample := t.c.encB s
  check b :=
    let m := t.c.dec b.data.toList
    if t.dec b != m then some "the ByteArray reader and the model differ"
    else match m with
      | none => none
      | some x => if ((t.c.write x).map (·.data)) != some b.data then
          some "an accepted input does not come back from the guarded writer" else none
  accepts b := (t.dec b).isSome
  cells b := decExactB t.c.L b
  time := do
    -- Read back through references so that no call is a constant the compiler could compute once.
    let x ← (← IO.mkRef s).get
    let b ← (← IO.mkRef (t.c.encB s)).get
    let l ← (← IO.mkRef (t.c.enc s)).get
    let (et, a1) ← median3 200000 fun i => (t.c.encB x).size + i
    let (dt, a2) ← median3 200000 fun i => match t.dec b with | some _ => i + 1 | none => i
    let (em, a3) ← median3 20000 fun i => (t.c.enc x).length + i
    let (dm, a4) ← median3 20000 fun i => match t.c.dec l with | some _ => i + 1 | none => i
    return (et, dt, em, dm, a1 + a2 + a3 + a4)

/-- The link that follows a body: read in place and by the model, written by the guarded writer. -/
def sampleLink : Link := ⟨10, 5⟩

def linkProbe : Probe where
  name := "link"
  L := linkL
  sample := encFB linkL sampleLink.cells .empty
  check b :=
    let m := decExact linkL b.data.toList
    if decExactB linkL b != m then some "the ByteArray reader and the model differ"
    else match m with
      | none => none
      | some cs => if ((encFBc linkL cs .empty).map (·.data)) != some b.data then
          some "an accepted input does not come back from the guarded writer" else none
  accepts b := (decExactB linkL b).isSome
  cells b := decExactB linkL b
  time := return (0, 0, 0, 0, 0)

def hdr : FactHdr := ⟨0, pat 32 1, pat 32 40, 20260101, 20261231, 99991231, 5, 7⟩
def obligS : ObligF := ⟨hdr, 500000, 1767225600000, 3, pat 32 2, ident 51 "item-1", ident 21 "2026-01", 0⟩
def claimS : ClaimF := ⟨hdr, 30000, 1767225600000, 1767225600001, 1, 0, ident 51 "claim-1"⟩
def supportS : SupportF := ⟨hdr, pat 64 3, 1767225600000, 1767225600001, 2, 0, ident 51 "ref-1"⟩
def reportS : ReportF := ⟨hdr, pat 64 4, 1767225600000, 1767225600001, 0, ident 51 "report-1"⟩
def fundS : FundF := ⟨hdr, 30000, 1767225600000, 1, 2, 0, ident 51 "fund-1"⟩
def ackS : AckF := ⟨hdr, pat 32 5, pat 64 6, 1767225600000, 0, ident 51 "ack-1"⟩

/-- One valid record of every kind, in the order of `catalog`. -/
def probes : List Probe := [
  probe "state" stateT sampleState, probe "case" caseT sampleCase, probe "action" actionT sampleAction,
  probe "command" cmdT sampleCmd, probe "marker" markT sampleMark, probe "fold" foldT sampleFold,
  probe "oblig" obligT obligS, probe "cash" cashT sampleCash, probe "claim" claimT claimS,
  probe "support" supportT supportS, probe "report" reportT reportS, probe "fund" fundT fundS,
  probe "ack" ackT ackS]

/-- A display field of width `w` that breaks the rule: a length byte of `w`, or text followed by a nonzero byte. -/
def longId (w : Nat) : Bytes := UInt8.ofNat w :: zeros (w - 1)
def dirtyId (w : Nat) : Bytes := ident w "a" |>.set (w - 1) 1
/-- The fallback of a display field of width `w`: `0xFF`, the first `min 32 (w - 1)` bytes of a hash, zeros. -/
def hashId (w : Nat) : Bytes := 0xFF :: pat (min 32 (w - 1)) 0xA0 ++ zeros (w - 1 - min 32 (w - 1))

def hBad (op vstart : Nat) : FactHdr := { hdr with op := op, vstart := vstart }

/-- For every rule of every record, a body that breaks it and only it: the record, the field changed, the body. -/
def refusals : List (String × String × ByteArray) := [
  ("state", "mkind", stateC.encB { sampleState with mkind := 12 }),
  ("state", "mkind", stateC.encB { sampleState with mkind := 26 }),
  ("state", "flags", stateC.encB { sampleState with flags := 16 }),
  ("state", "verification", stateC.encB { sampleState with verification := 0 }),
  ("state", "verification", stateC.encB { sampleState with verification := 4 }),
  ("state", "caseStatus", stateC.encB { sampleState with caseStatus := 0 }),
  ("state", "caseStatus", stateC.encB { sampleState with caseStatus := 6 }),
  ("state", "delivery", stateC.encB { sampleState with delivery := 0 }),
  ("state", "delivery", stateC.encB { sampleState with delivery := 5 }),
  ("state", "lg", stateC.encB { sampleState with lg := 4 }),
  ("state", "cents", stateC.encB { sampleState with cents := bound }),
  ("state", "owed", stateC.encB { sampleState with owed := bound }),
  ("state", "dueMs", stateC.encB { sampleState with dueMs := bound }),
  ("state", "atMs", stateC.encB { sampleState with atMs := bound }),
  ("state", "received", stateC.encB { sampleState with received := bound }),
  ("state", "claimed", stateC.encB { sampleState with claimed := bound }),
  ("state", "lawful", stateC.encB { sampleState with lawful := bound }),
  ("state", "shortfall", stateC.encB { sampleState with shortfall := bound }),
  ("state", "overage", stateC.encB { sampleState with overage := bound }),
  ("case", "dueMs", caseC.encB { sampleCase with dueMs := bound }),
  ("case", "atMs", caseC.encB { sampleCase with atMs := bound }),
  ("command", "atMs", cmdC.encB { sampleCmd with atMs := bound }),
  ("command", "epoch", cmdC.encB { sampleCmd with epoch := 0 }),
  ("command", "epoch", cmdC.encB { sampleCmd with epoch := bound }),
  ("command", "wbatch", cmdC.encB { sampleCmd with wbatch := bound }),
  ("state", "wbatch", stateC.encB { sampleState with wbatch := bound }),
  ("action", "ak", actionC.encB { sampleAction with ak := zeros 32 }),
  -- what the tables themselves refuse: a wrong length, a nonzero padding byte, a wrong form byte, a link with flags
  ("state", "length", (stateC.encB sampleState).extract 0 244),
  ("state", "length", stateC.encB sampleState ++ ByteArray.mk #[0]),
  ("state", "zero", (stateC.encB sampleState).set! 244 1),
  ("state", "fixed", (stateC.encB sampleState).set! 1 6),
  ("link", "zero", linkProbe.sample.set! 7 1),
  ("oblig", "owed", obligC.encB { obligS with owed := bound }),
  ("oblig", "dueMs", obligC.encB { obligS with dueMs := bound }),
  ("claim", "amount", claimC.encB { claimS with amount := bound }),
  ("claim", "deadlineMs", claimC.encB { claimS with deadlineMs := bound }),
  ("claim", "eventMs", claimC.encB { claimS with eventMs := bound }),
  ("support", "applicableMs", supportC.encB { supportS with applicableMs := bound }),
  ("support", "eventMs", supportC.encB { supportS with eventMs := bound }),
  ("report", "applicableMs", reportC.encB { reportS with applicableMs := bound }),
  ("report", "eventMs", reportC.encB { reportS with eventMs := bound }),
  ("fund", "amount", fundC.encB { fundS with amount := bound }),
  ("fund", "eventMs", fundC.encB { fundS with eventMs := bound }),
  ("ack", "eventMs", ackC.encB { ackS with eventMs := bound }),
  ("case", "op", caseC.encB { sampleCase with op := 0, status := 1 }),
  ("case", "op", caseC.encB { sampleCase with op := 5 }),
  ("case", "status", caseC.encB { sampleCase with op := 1, status := 0 }),
  ("case", "status", caseC.encB { sampleCase with op := 2, status := 6 }),
  ("case", "status", caseC.encB { sampleCase with op := 3, status := 1 }),
  ("case", "lg", caseC.encB { sampleCase with lg := 4 }),
  ("action", "op", actionC.encB { sampleAction with op := 0 }),
  ("action", "op", actionC.encB { sampleAction with op := 5 }),
  ("action", "akind", actionC.encB { sampleAction with akind := 0 }),
  ("action", "akind", actionC.encB { sampleAction with akind := 3 }),
  ("action", "status", actionC.encB { sampleAction with status := 0 }),
  ("action", "status", actionC.encB { sampleAction with status := 4 }),
  ("action", "status", actionC.encB { sampleAction with op := 1, status := 2 }),
  ("action", "status", actionC.encB { sampleAction with op := 1, status := 3 }),
  ("action", "status", actionC.encB { sampleAction with op := 2, status := 1 }),
  ("action", "status", actionC.encB { sampleAction with op := 2, status := 3 }),
  ("action", "status", actionC.encB { sampleAction with op := 3, status := 1 }),
  ("action", "status", actionC.encB { sampleAction with op := 3, status := 2 }),
  ("action", "status", actionC.encB { sampleAction with op := 4, status := 2 }),
  ("action", "status", actionC.encB { sampleAction with op := 4, status := 3 }),
  ("action", "amount", actionC.encB { sampleAction with amount := bound }),
  ("action", "atMs", actionC.encB { sampleAction with atMs := bound }),
  ("action", "lg", actionC.encB { sampleAction with lg := 4 }),
  ("action", "decidedMs", actionC.encB { sampleAction with decidedMs := sampleAction.atMs + 1 }),
  ("command", "ckind", cmdC.encB { sampleCmd with ckind := 0 }),
  ("command", "ckind", cmdC.encB { sampleCmd with ckind := 13 }),
  ("command", "attr", cmdC.encB { sampleCmd with attr := 3 }),
  ("command", "lg", cmdC.encB { sampleCmd with lg := 4 }),
  ("marker", "cause", markC.encB { sampleMark with cause := 0 }),
  ("marker", "sidk", markC.encB { sampleMark with sidk := 2 }),
  ("marker", "sid", markC.encB { sampleMark with sidk := 0 }),
  ("fold", "cmaxMs", foldC.encB { sampleFold with cmax := 0, cmaxCents := 0 }),
  ("fold", "cmaxCents", foldC.encB { sampleFold with cmax := 0, cmaxMs := 0 }),
  ("fold", "doneMs", foldC.encB { sampleFold with done := 0 }),
  ("fold", "amaxMs", foldC.encB { sampleFold with amax := 0 }),
  ("fold", "cmaxMs", foldC.encB { sampleFold with cmaxMs := bound }),
  ("fold", "cmaxCents", foldC.encB { sampleFold with cmaxCents := bound }),
  ("fold", "doneMs", foldC.encB { sampleFold with doneMs := bound }),
  ("fold", "reqsum", foldC.encB { sampleFold with reqsum := bound }),
  ("fold", "amaxMs", foldC.encB { sampleFold with amaxMs := bound }),
  ("oblig", "op", obligC.encB { obligS with h := hBad 3 hdr.vstart }),
  ("oblig", "vstart", obligC.encB { obligS with h := hBad 0 (hdr.vstop + 1) }),
  ("oblig", "ecls", obligC.encB { obligS with ecls := 5 }),
  ("oblig", "item", obligC.encB { obligS with item := longId 51 }),
  ("oblig", "item", obligC.encB { obligS with item := dirtyId 51 }),
  ("oblig", "period", obligC.encB { obligS with period := longId 21 }),
  ("oblig", "period", obligC.encB { obligS with period := dirtyId 21 }),
  ("cash", "op", cashC.encB { sampleCash with h := { sampleCash.h with op := opEnd } }),
  ("cash", "op", cashC.encB { sampleCash with h := { sampleCash.h with op := 3 } }),
  ("cash", "vstart", cashC.encB { sampleCash with h := { sampleCash.h with vstart := sampleCash.h.vstop + 1 } }),
  ("cash", "ecls", cashC.encB { sampleCash with ecls := 5 }),
  ("cash", "amount", cashC.encB { sampleCash with amount := bound }),
  ("cash", "eventMs", cashC.encB { sampleCash with eventMs := bound }),
  ("cash", "origin", cashC.encB { sampleCash with origin := longId 51 }),
  ("cash", "origin", cashC.encB { sampleCash with origin := 0xFF :: pat 33 3 ++ zeros 17 }),
  ("claim", "op", claimC.encB { claimS with h := hBad 3 hdr.vstart }),
  ("claim", "vstart", claimC.encB { claimS with h := hBad 1 (hdr.vstop + 1) }),
  ("claim", "ecls", claimC.encB { claimS with ecls := 5 }),
  ("claim", "claim", claimC.encB { claimS with claim := dirtyId 51 }),
  ("support", "op", supportC.encB { supportS with h := hBad 3 hdr.vstart }),
  ("support", "vstart", supportC.encB { supportS with h := hBad 0 (hdr.vstop + 1) }),
  ("support", "ecls", supportC.encB { supportS with ecls := 5 }),
  ("support", "ref", supportC.encB { supportS with ref := longId 51 }),
  ("report", "op", reportC.encB { reportS with h := hBad 3 hdr.vstart }),
  ("report", "vstart", reportC.encB { reportS with h := hBad 0 (hdr.vstop + 1) }),
  ("report", "ecls", reportC.encB { reportS with ecls := 5 }),
  ("report", "ref", reportC.encB { reportS with ref := dirtyId 51 }),
  ("fund", "op", fundC.encB { fundS with h := hBad 3 hdr.vstart }),
  ("fund", "vstart", fundC.encB { fundS with h := hBad 0 (hdr.vstop + 1) }),
  ("fund", "ecls", fundC.encB { fundS with ecls := 5 }),
  ("fund", "ref", fundC.encB { fundS with ref := longId 51 }),
  ("ack", "op", ackC.encB { ackS with h := hBad 3 hdr.vstart }),
  ("ack", "vstart", ackC.encB { ackS with h := hBad 0 (hdr.vstop + 1) }),
  ("ack", "ecls", ackC.encB { ackS with ecls := 5 }),
  ("ack", "ackref", ackC.encB { ackS with ackref := dirtyId 51 })]

/-- Bodies at the edge of the rules that read: the record, the field at its edge, the body. -/
def acceptances : List (String × String × ByteArray) := [
  ("case", "status", caseC.encB { sampleCase with op := 1, status := 5 }),
  ("action", "decidedMs", actionC.encB { sampleAction with decidedMs := sampleAction.atMs }),
  ("action", "status", actionC.encB { sampleAction with op := 2, status := 2 }),
  ("action", "status", actionC.encB { sampleAction with op := 3, status := 3 }),
  ("action", "status", actionC.encB { sampleAction with op := 4, status := 1 }),
  ("action", "amount", actionC.encB { sampleAction with amount := bound - 1 }),
  ("state", "owed", stateC.encB { sampleState with owed := bound - 1 }),
  ("state", "overage", stateC.encB { sampleState with overage := bound - 1 }),
  ("claim", "deadlineMs", claimC.encB { claimS with deadlineMs := bound - 1 }),
  ("ack", "eventMs", ackC.encB { ackS with eventMs := bound - 1 }),
  ("cash", "amount", cashC.encB { sampleCash with amount := bound - 1 }),
  ("command", "epoch", cmdC.encB { sampleCmd with epoch := 1 }),
  ("command", "epoch", cmdC.encB { sampleCmd with epoch := bound - 1 }),
  ("command", "wbatch", cmdC.encB { sampleCmd with wbatch := bound - 1 }),
  ("state", "wbatch", stateC.encB { sampleState with wbatch := bound - 1 }),
  ("fold", "reqsum", foldC.encB { sampleFold with reqsum := bound - 1 }),
  ("marker", "sid", markC.encB { sampleMark with sidk := 0, sid := zeros 32 }),
  ("fold", "done", foldC.encB { sampleFold with done := 0, doneMs := 0 }),
  ("oblig", "vstart", obligC.encB { obligS with h := hBad opEnd (hdr.vstop + 1) }),
  ("oblig", "item", obligC.encB { obligS with item := hashId 51 }),
  ("oblig", "period", obligC.encB { obligS with period := hashId 21 }),
  ("oblig", "item", obligC.encB { obligS with item := ident 51 "" }),
  ("cash", "op", cashC.encB { sampleCash with h := { sampleCash.h with op := opVoid } }),
  ("claim", "ecls", claimC.encB { claimS with ecls := 4 })]

def hex (b : List UInt8) : String :=
  String.join (b.map fun x => String.ofList [Nat.digitChar (x.toNat / 16), Nat.digitChar (x.toNat % 16)])

def cellText : Cell → String
  | .n v => toString v
  | .b v => hex v

def idText : Option Bytes → String
  | some v => hex v
  | none => "-"

def probeOf (name : String) : Option Probe := (probes ++ [linkProbe]).find? (·.name == name)

def vectors : IO UInt32 := do
  for (r, p) in catalog.zip probes do
    let some cs := p.cells p.sample | IO.eprintln s!"the valid {p.name} record is refused"; return 1
    unless r.name == p.name && p.check p.sample == none do
      IO.eprintln s!"the {p.name} probe does not match the catalog or fails its own check"; return 1
    IO.println s!"record {r.name}"
    IO.println s!"hex {hex p.sample.toList}"
    for (n, c) in r.cells.zip cs do
      IO.println s!"field {n} {cellText c}"
  let some cs := linkProbe.cells linkProbe.sample | IO.eprintln "the valid link is refused"; return 1
  IO.println "record link"
  IO.println s!"hex {hex linkProbe.sample.toList}"
  for (n, c) in ["prev", "count"].zip cs do
    IO.println s!"field {n} {cellText c}"
  for (want, word, list) in [(false, "refuse", refusals), (true, "accept", acceptances)] do
    for (name, field, b) in list do
      let some p := probeOf name | IO.eprintln s!"no record {name}"; return 1
      unless p.check b == none && p.accepts b == want do
        IO.eprintln s!"{word} {name} {field}: the reader does not give the expected answer"; return 1
      IO.println s!"{word} {name} {field} {hex b.toList}"
  let o := exOpening
  for (ename, recs) in examples do
    IO.println s!"example {ename}"
    for (n, v) in [("stateId", o.stateId), ("deploymentId", o.deploymentId), ("programId", o.programId),
        ("periodId", o.periodId), ("currency", o.currency), ("itemId", o.itemId), ("obligationId", o.obligationId)] do
      IO.println s!"opening {n} {hex v}"
    for r in recs do
      IO.println s!"input {r.no} {hex r.body} {idText r.elem.evidence} {idText r.elem.contribution} {idText r.elem.action}"
    IO.println s!"fold {(foldWrite o recs).elim "none" (hex ·.data.toList)}"
  return 0

def nibbleOf (c : Char) : Nat := if c.toNat ≥ 48 ∧ c.toNat ≤ 57 then c.toNat - 48 else c.toNat - 87

def unhex : List Char → List UInt8
  | a :: b :: r => UInt8.ofNat (nibbleOf a * 16 + nibbleOf b) :: unhex r
  | _ => []

def idOf (s : String) : Option Bytes := if s == "-" then none else some (unhex s.toList)

/-- The fold examples of a file in the vectors' form (`example`, `opening`, `input` lines): each one's name, the
    opening's fields and its records. -/
def parseFolds (lines : List String) : List (String × List Bytes × List Rec) := Id.run do
  let mut out : Array (String × Array Bytes × Array Rec) := #[]
  for l in lines do
    match l.splitOn " " with
    | ["example", n] => out := out.push (n, #[], #[])
    | ["opening", _, h] => out := out.modify (out.size - 1) fun (n, o, r) => (n, o.push (unhex h.toList), r)
    | ["input", no, body, ev, c, a] =>
      out := out.modify (out.size - 1) fun (n, o, r) =>
        (n, o, r.push ⟨no.toNat!, unhex body.toList, ⟨idOf ev, idOf c, idOf a⟩⟩)
    | _ => pure ()
  return out.toList.map fun (n, o, r) => (n, o.toList, r.toList)

/-- `folds FILE`: for each example of the file, one line `R NAME HEX` with the fold record `foldWrite` gives, or
    `R NAME none`; a second reader computes the same from the specification and compares. -/
def folds (path : String) : IO UInt32 := do
  for (n, op, recs) in parseFolds ((← IO.FS.readFile path).splitOn "
") do
    let o : Opening := ⟨op.getD 0 [], op.getD 1 [], op.getD 2 [], op.getD 3 [], op.getD 4 [], op.getD 5 [],
      op.getD 6 []⟩
    IO.println s!"R {n} {(foldWrite o recs).elim "none" (hex ·.data.toList)}"
  return 0

def mix (x : UInt64) : UInt64 :=
  let z := x + 0x9E3779B97F4A7C15
  let z := (z ^^^ (z >>> 30)) * 0xBF58476D1CE4E5B9
  let z := (z ^^^ (z >>> 27)) * 0x94D049BB133111EB
  z ^^^ (z >>> 31)

/-- The `j`-th random word of input `i`. -/
def rnd (seed : UInt64) (i j : Nat) : UInt64 := mix (seed ^^^ mix (i.toUInt64 * 0x10000 + j.toUInt64))

def randBytes (seed : UInt64) (i len : Nat) (b : ByteArray := .empty) : ByteArray := Id.run do
  let mut b := b
  for k in [0:(len + 7) / 8] do
    let w := rnd seed i (k + 16)
    for t in [0:8] do
      if b.size < len then b := b.push (w >>> (8 * t).toUInt64).toUInt8
  return b

def flipBit (b : ByteArray) (bit : Nat) : ByteArray :=
  if bit / 8 < b.size then b.set! (bit / 8) (b.get! (bit / 8) ^^^ ((1 : UInt8) <<< (bit % 8).toUInt8)) else b

/-- Random input `i`: random bytes, random bytes behind the record's tag, the record with bytes replaced, or the
    record with bits flipped and its length changed. -/
def mutant (seed : UInt64) (s : ByteArray) (i : Nat) : ByteArray := Id.run do
  let r := (rnd seed i 0).toNat
  match r % 4 with
  | 0 => randBytes seed i s.size
  | 1 => (randBytes seed i s.size).set! 0 (s.get! 0)
  | 2 =>
    let mut b := s
    for k in [0:1 + r / 4 % 4] do
      let w := (rnd seed i (k + 1)).toNat
      b := b.set! (w % s.size) (w / s.size).toUInt8
    return b
  | _ =>
    let mut b := s
    for k in [0:1 + r / 4 % 3] do
      b := flipBit b ((rnd seed i (k + 1)).toNat % (8 * s.size))
    match r / 16 % 4 with
    | 0 => return b.extract 0 ((rnd seed i 5).toNat % s.size)
    | 1 => return randBytes seed i (s.size + 1 + r / 64 % 8) b
    | _ => return b

def fuzz (seed : UInt64) (n : Nat) : IO UInt32 := do
  IO.println s!"FUZZ_SEED seed={seed} random_per_codec={n}"
  let mut failed := 0
  for p in probes ++ [linkProbe] do
    let s := p.sample
    let mut acc := 0
    let mut total := 0
    let mut bad := 0
    let mut inputs : Array ByteArray := #[]
    if p.check s != none || (p.cells s).isNone then
      IO.println s!"FUZZ_FAIL record={p.name} the valid record is refused or fails its check"
      bad := bad + 1
    for len in [0:2 * s.size + 1] do
      inputs := inputs.push (if len ≤ s.size then s.extract 0 len else s ++ ByteArray.mk (Array.replicate (len - s.size) 0))
      inputs := inputs.push ((randBytes seed len len).set! 0 (s.get! 0))
    for bit in [0:8 * s.size] do
      inputs := inputs.push (flipBit s bit)
    let fixed := inputs.size
    for i in [0:fixed + n] do
      let b := if i < fixed then inputs[i]! else mutant seed s i
      total := total + 1
      match p.check b with
      | some why =>
        bad := bad + 1
        if bad ≤ 5 then IO.println s!"FUZZ_FAIL record={p.name} input={i} {why} hex={hex b.toList}"
      | none => if (p.cells b).isSome then acc := acc + 1
    IO.println s!"FUZZ record={p.name} lengths={2 * (2 * s.size + 1)} flips={8 * s.size} random={n} inputs={total} accepted={acc} refused={total - acc} failures={bad}"
    failed := failed + bad
  IO.println s!"FUZZ_SUMMARY codecs={probes.length + 1} failures={failed}"
  return if failed == 0 then 0 else 1

/-- The `w` little-endian bytes of `v` written over `b` at `o`. -/
def setLE (b : ByteArray) (o w v : Nat) : ByteArray := Id.run do
  let mut b := b
  let mut v := v
  for k in [0:w] do
    b := b.set! (o + k) (UInt8.ofNat (v % 256))
    v := v / 256
  return b

/-- `x` written over `b` at `o`. -/
def setBlk (b : ByteArray) (o : Nat) (x : ByteArray) : ByteArray := Id.run do
  let mut b := b
  for k in [0:x.size] do
    b := b.set! (o + k) (x.get! k)
  return b

/-- A value for a number field of width `w` near the rules' bounds; `other` is the value of another field. -/
def numNear (r w other : Nat) : Nat :=
  match r % 8 with
  | 0 => 0
  | 1 => 1
  | 2 => r / 8 % 32
  | 3 => r / 8 % 256 ^ w
  | 4 => 256 ^ w - 1
  | 5 => (other + r / 8 % 3) % 256 ^ w
  | 6 => (other - r / 8 % 2) % 256 ^ w
  | _ => if w == 8 then bound - r / 8 % 2 else r / 8 % 300 % 256 ^ w

/-- A value for a block of width `w`: zeros, random, an identifier of some length with or without a stray byte, or
    the hash form with or without a dirty tail. -/
def blkNear (seed : UInt64) (i r w : Nat) : ByteArray :=
  let rand := randBytes seed i w
  match r % 6 with
  | 0 => ByteArray.mk (Array.replicate w 0)
  | 1 => rand
  | 2 =>
    let n := r / 6 % (w + 2)
    let z := setLE (ByteArray.mk (Array.replicate w 0)) 0 1 n
    let z := setBlk z 1 (rand.extract 0 (min n (w - 1)))
    if r / 64 % 4 == 0 && n + 1 < w then z.set! (n + 1 + r / 256 % (w - n - 1)) 1 else z
  | 3 =>
    let k := min 32 (w - 1)
    let z := setBlk ((ByteArray.mk (Array.replicate w 0)).set! 0 0xFF) 1 (rand.extract 0 k)
    if r / 64 % 4 == 0 && k + 1 < w then z.set! (k + 1 + r / 256 % (w - k - 1)) 1 else z
  | 4 => rand.set! 0 0xFF
  | _ => rand.set! 0 0

def verdicts (seed : UInt64) (n : Nat) : IO UInt32 := do
  for p in probes do
    let tbl := cellTable p.L
    let cell := fun j => tbl.getD j (.num 0, 0)
    let numCells := (List.range tbl.size).filter fun j => match cell j with | (.num _, _) => true | _ => false
    for i in [0:n] do
      let r0 := (rnd seed i 0).toNat
      let mut b := p.sample
      for k in [0:1 + r0 % 2] do
        let r := (rnd seed i (k + 1)).toNat
        match cell (r % tbl.size) with
        | (.num w, o) =>
          -- Another number field's value, so that pairs such as `decidedMs` and `atMs` meet at their bound.
          let other := numAt b (cell (numCells.getD (r / 7 % numCells.length) 0))
          b := setLE b o w (numNear (r / 1024) w other)
        | (.blk w, o) => b := setBlk b o (blkNear seed (i * 4 + k) (r / 1024) w)
        | _ => pure ()
      match p.check b with
      | some why => IO.eprintln s!"VERDICT_FAIL record={p.name} input={i} {why}"; return 1
      | none => IO.println s!"V {p.name} {if p.accepts b then 1 else 0} {hex b.toList}"
  return 0

def timing : IO UInt32 := do
  let mut sink := 0
  let mut maxEnc := 0
  let mut maxDec := 0
  for p in probes do
    let (et, dt, em, dm, s) ← p.time
    sink := sink + s
    maxEnc := max maxEnc et
    maxDec := max maxDec dt
    IO.println s!"TIMING record={p.name} enc_twin_ns={et} dec_twin_ns={dt} enc_model_ns={em} dec_model_ns={dm}"
  IO.eprintln s!"SINK {sink}"
  IO.println s!"TIMING_SUMMARY records={probes.length} max_enc_twin_ns={maxEnc} max_dec_twin_ns={maxDec}"
  return 0

def main (args : List String) : IO UInt32 := do
  match args with
  | ["vectors"] => vectors
  | ["fuzz", seed, n] =>
    match seed.toNat?, n.toNat? with
    | some s, some k => fuzz s.toUInt64 k
    | _, _ => IO.eprintln "usage: obligations_format_check fuzz SEED N"; return 2
  | ["verdicts", seed, n] =>
    match seed.toNat?, n.toNat? with
    | some s, some k => verdicts s.toUInt64 k
    | _, _ => IO.eprintln "usage: obligations_format_check verdicts SEED N"; return 2
  | ["folds", path] => folds path
  | ["timing"] => timing
  | _ => IO.eprintln "usage: obligations_format_check vectors | fuzz SEED N | verdicts SEED N | folds FILE | timing"; return 2
