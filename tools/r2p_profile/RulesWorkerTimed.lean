import BlindLedger.Gate.Rules.Run

/-! R2P: `Run.commit`, `step`, `runText` and `serve` with a monotonic timer around each stage.  Same functions, same output lines
    plus `R2P_STAGE <name> <ns>` lines (the previous frame's write time as `write_prev`).  Test-only; the product exes are untouched. -/

namespace BlindLedger.Gate.Rules.Run

open BlindLedger.Gate.Rules

@[extern c inline "lean_io_result_mk_ok(lean_box_uint32((uint32_t)mi_reserve_os_memory(#1, #2, #3)))"]
opaque reserveArena (bytes : USize) (commit allowLarge : Bool) : IO UInt32

def stageNames : Array String :=
  #["read", "utf8_split", "step", "unhex", "load_rebuild", "load_digest", "pin", "ctx_state", "ix_build", "eval",
    "digest_base", "digest_out", "reads", "enc_render", "enc_rows", "enc_hex", "resp"]

structure Acc where
  ns : IO.Ref (Array Nat)
  sink : IO.Ref Nat

/-- Run `f`, add its time to slot `i`; `sz` of the result is summed into `sink` so the work cannot move past the second stamp. -/
@[noinline] def tm {α : Type} (a : Acc) (i : Nat) (sz : α → Nat) (f : Unit → α) : IO α := do
  let t0 ← IO.monoNanosNow
  let x := f ()
  a.sink.modify (· + sz x)
  let t1 ← IO.monoNanosNow
  a.ns.modify fun s => s.modify i (· + (t1 - t0))
  pure x

def oLen {α : Type} (o : Option (List α)) : Nat := o.elim 0 List.length

def commitT (a : Acc) (st : St) (unanchored : Bool) : IO (St × List String) := do
  let p ← tm a 6 (fun (p : Pinned) => p.kinds.elim 0 List.length) fun _ => st.pinned.getD st.pin
  let c ← tm a 7 (fun (c : Ctx) => c.today) fun _ => st.ctx p
  let okA ← match st.anchor with
    | none => pure true
    | some n => tm a 10 (fun (b : Bool) => b.toNat) fun _ =>
        Fast.setsDigestF hB c.releasedPrior c.unresolvedPrior == some (Gate.natBE Gate.digestBytes n)
  if !okA then
    let st0 : St := { st with pinned := some p, anchor := none, batch := #[], redo := [], foreign := [], owners := none,
                              free := none, pays := [], checked := st.checked + unanchored.toNat,
                              failed := st.failed + (!unanchored).toNat }
    return (st0, if unanchored then [] else ["RULES_UNANCHORED commit"])
  let lines := st.batch.toList.map (·.1)
  let (b, f, wait) ← tm a 9 (fun (r : List Line × List Nat × List Line) => r.1.length) fun _ =>
    (match st.owners with
      | some (k, os) =>
        let b := Fast.readyF k os lines
        let ps := Std.HashSet.ofList (b.map (·.pay))
        (b, Fast.foreignOfF k os b, lines.filter fun l => !ps.contains l.pay)
      | none => (lines, st.foreign, []) : List Line × List Nat × List Line)
  let x ← tm a 8 (fun (x : Fast.Ix) => x.relN) fun _ => Fast.Ix.build c b
  let r ← tm a 9 (fun r => r.decisions.length) fun _ => x.runIn f b
  let exp := st.batch.toList.filterMap (·.2)
  let got ← tm a 13 List.length fun _ => r.decisions.map render ++ wait.map (lineText · ++ " WAIT -")
  let fr ← tm a 9 oLen fun _ => st.owners.map fun (k, os) =>
    uniq (Fast.settleFreeF r.released.entries r.unresolved.entries (pendingOf k os))
  let frOk := st.free.all (some · == fr)
  let bad := st.pays.filter fun (q, o) => name (x.payOutcome r.decisions q) != o
  let (ok, n, msg) :=
    if exp.isEmpty then (true, 0, [])
    else if exp.length == lines.length && sorted exp == sorted got then (true, lines.length, [])
    else (false, 0, ((sorted got).filter (!exp.contains ·)).map ("RULES_GOT " ++ ·))
  let ok := ok && bad.isEmpty && !unanchored && frOk
  let msg := msg ++ bad.map (fun (q, o) => s!"RULES_PAY {q} expected={o}") ++
    (if unanchored then ["RULES_ANCHORED commit"] else []) ++ (if frOk then [] else [s!"RULES_FREE_EXPECTED {st.free}"])
  let fresh := (r.released.entries.drop x.relN, r.unresolved.entries.drop x.unrN)
  let adds ← tm a 14 oLen fun _ =>
    (do pure ((← fresh.1.mapM (rowBytes 1)) ++ (← fresh.2.mapM (rowBytes 2))).flatten : Option (List UInt8))
  let pinOf (o : Option (Snapshot Line × List UInt8)) (d : String) (k : Nat) (s : Snapshot Line) :=
    o.elim ((Fast.pinBytes d k Line.fields s).map hB) (some ·.2)
  let base ← tm a 10 oLen fun _ =>
    (if st.sealed then Fast.setsDigestF hB c.releasedPrior c.unresolvedPrior else do
      pure (Gate.stateDigest (fun x => hB ⟨x.toArray⟩) (← pinOf p.released "RR/GATE/RELEASED/v1" 5 c.releasedPrior)
        (← pinOf p.unresolved "RR/GATE/UNRESOLVED/v1" 6 c.unresolvedPrior)) : Option (List UInt8))
  let shown : List String ← match fr with
    | none => pure []
    | some ids => do
      let dg ← tm a 11 oLen fun _ => Fast.setsDigestF hB r.released r.unresolved
      let rd ← tm a 12 oLen fun _ => base.bind (reads p c)
      tm a 15 List.length fun _ => got.map ("RULES_LINE " ++ ·) ++ [" ".intercalate ("RULES_FREE" :: ids.map toString)] ++
        dg.toList.map (fun d => s!"RULES_DIGEST {hexOf d.toByteArray}") ++
        adds.toList.map (fun b => s!"RULES_ADDS {hexOf b.toByteArray}") ++
        rd.toList.map fun b => s!"RULES_READS {hexOf b.toByteArray}"
  let st' ← tm a 7 (fun (s : St) => s.checked) fun _ =>
    { st with pinned := some p, anchor := none, sealed := true,
              extra := st.extra ++ fresh.1,
              held := st.held ++ fresh.2,
              rprior := r.released, uprior := r.unresolved, batch := #[], redo := [], foreign := [], owners := none,
              free := none, pays := [],
              done := st.done ++ r.decisions, checked := st.checked + (if ok then n + st.pays.length else 0),
              failed := st.failed + (if ok then 0 else 1) }
  pure (st', shown ++ if ok then [] else "RULES_VECTOR_MISMATCH commit" :: msg)

def loadT (a : Acc) (st : St) (asof adds h : String) : IO (Option (St × List String)) := do
  if h.length != 128 then return none
  let some ao := asof.toNat? | return none
  let g : Snapshot Line := ⟨ao, 0, []⟩
  let sz (o : Option ByteArray) : Nat := o.elim 0 (·.size)
  let anc ← tm a 3 sz fun _ => unhex h
  let bso ← tm a 3 sz fun _ => if adds == "-" then some ByteArray.empty else unhex adds
  let some ab := anc | return none
  let some bs := bso | return none
  let anchor := Gate.beNat ab.toList
  let rb ← tm a 4 (fun (o : Option (Snapshot Line × Snapshot Line)) => o.elim 0 fun s => s.1.entries.length) fun _ =>
    (parseAdds bs).map fun ad => Rules.replay (g, g) [ad]
  let dg ← tm a 5 oLen fun _ => rb.bind fun s => Fast.setsDigestF hB s.1 s.2
  match rb with
  | some s =>
    if dg == some (Gate.natBE Gate.digestBytes anchor) then
      let some er := emptyPin "released" g.asOf | return none
      let some eu := emptyPin "unresolved" g.asOf | return none
      pure (some ({ st with
        snaps := ("released", g.asOf, 0, er) :: ("unresolved", g.asOf, 0, eu) :: st.snaps,
        rows := st.rows.filter fun r => r.1 != "released" && r.1 != "unresolved", pinned := none, anchor := none,
        extra := s.1.entries, held := s.2.entries, rprior := s.1, uprior := s.2, sealed := true }, []))
    else pure (some ({ st with failed := st.failed + 1 }, ["RULES_STATE_MISMATCH load"]))
  | none => pure (some ({ st with failed := st.failed + 1 }, ["RULES_STATE_MISMATCH load"]))

def stepT (a : Acc) (st : St) (fs : List String) : IO (Option (St × List String)) :=
  match fs with
  | ["load", x, y, h] => loadT a st x y h
  | ["commit"] => do pure (some (← commitT a st false))
  | ["commit", "UNANCHORED"] => do pure (some (← commitT a st true))
  | _ => tm a 2 (fun (o : Option (St × List String)) => o.elim 0 (·.2.length)) fun _ => step st fs

def runTextT (a : Acc) (text : String) : IO (Array String × Bool) := do
  let mut st : St := {}
  let mut out : Array String := #[]
  let mut number := 0
  let raws ← tm a 1 List.length fun _ => text.splitOn "\n"
  for raw in raws do
    number := number + 1
    let fields ← tm a 1 List.length fun _ => ((String.ofList (raw.toList.filter (· ≠ '\r'))).splitOn " ").filter (· ≠ "")
    if fields.isEmpty || fields.head!.startsWith "#" then continue
    match ← stepT a st fields with
    | none =>
      st := { st with failed := st.failed + 1 }
      out := out.push s!"RULES_VECTOR_MALFORMED line={number}"
    | some (next, lines) =>
      if next.failed > st.failed then out := out.push s!"RULES_VECTOR_FAIL line={number}"
      st := next
      out := out ++ lines
  let pass := st.failed == 0 && st.expected == some st.checked
  return (out.push s!"RULES_VECTORS={if pass then "PASS" else "FAIL"} checked={st.checked} expected={st.expected.getD 0} failed={st.failed}", pass)

def stageLines (a : Acc) (prevWrite : Nat) : IO String := do
  let ns ← a.ns.get
  pure (String.join ((stageNames.toList.zip ns.toList).map fun (nm, v) => s!"R2P_STAGE {nm} {v}\n") ++ s!"R2P_STAGE write_prev {prevWrite}\n")

partial def serveT (a : Acc) (read : USize → IO ByteArray) (write : ByteArray → IO Unit) (prevWrite : Nat) : IO UInt32 := do
  a.ns.set (Array.replicate stageNames.size 0)
  let h ← readN read 4
  if h.size = 0 then return 0
  let n := h.foldl (fun v b => v * 256 + b.toNat) 0
  if h.size < 4 || n > maxFrame then return 65
  let t0 ← IO.monoNanosNow
  let f ← readN read n
  let t1 ← IO.monoNanosNow
  a.ns.modify fun s => s.modify 0 (· + (t1 - t0))
  if f.size < n then return 65
  let some text ← tm a 1 (fun (o : Option String) => o.elim 0 (·.length)) (fun _ => String.fromUTF8? f) | return 65
  let (out, _) ← runTextT a text
  let resp ← tm a 16 (·.size) fun _ => (String.join (out.toList.map (· ++ "\n"))).toUTF8
  let full := resp ++ (← stageLines a prevWrite).toUTF8
  if full.size > maxFrame then return 65
  let w0 ← IO.monoNanosNow
  write (ByteArray.mk #[(full.size >>> 24).toUInt8, (full.size >>> 16).toUInt8, (full.size >>> 8).toUInt8, full.size.toUInt8] ++ full)
  let w1 ← IO.monoNanosNow
  serveT a read write (w1 - w0)

end BlindLedger.Gate.Rules.Run

open BlindLedger.Gate.Rules.Run in
def main (args : List String) : IO UInt32 := do
  let a : Acc := ⟨← IO.mkRef (Array.replicate stageNames.size 0), ← IO.mkRef 0⟩
  match args with
  | [path] =>
    let t0 ← IO.monoNanosNow
    let text ← IO.FS.readFile path
    let t1 ← IO.monoNanosNow
    a.ns.modify fun s => s.modify 0 (· + (t1 - t0))
    let (out, pass) ← runTextT a text
    let resp ← tm a 16 (·.size) fun _ => (String.join (out.toList.map (· ++ "\n"))).toUTF8
    let w0 ← IO.monoNanosNow
    let stdout ← IO.getStdout
    stdout.write resp
    stdout.flush
    let w1 ← IO.monoNanosNow
    stdout.putStr (← stageLines a (w1 - w0))
    stdout.flush
    return (if pass then 0 else 1)
  | [] =>
    if (← reserveArena 1073741824 false false) != 0 then
      return 70
    let stdin ← IO.getStdin
    let stdout ← IO.getStdout
    serveT a stdin.read (fun b => do stdout.write b; stdout.flush) 0
  | _ =>
    IO.eprintln "r2p_rules [<vector path>]"
    return 2
