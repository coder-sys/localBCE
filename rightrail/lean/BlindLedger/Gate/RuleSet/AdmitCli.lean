import BlindLedger.Gate.RuleSet.Spec
import BlindLedger.Gate.Verify

open BlindLedger.Gate
open BlindLedger.Gate.RuleSet

/-! `ruleset_admit`: stdin is one frame, stdout one line per record then one per question.  Lean decides (`admit`,
    `select`); the caller only carries bytes and keeps the series.  Exit 0, 2 (stderr `RULESET_ADMIT=FRAME`) for a malformed
    frame, 1 (`RULESET_ADMIT=NOHEAD`) when the key-set chain admits no head on `now`.  Integers are big-endian; `u32‖x` is a
    length then `x`.
    - frame: pin 64 · now u32 · u32‖genesis key set · u16 n · (day u32 · u32‖key set)^n · tenant (u16 length, ident) ·
      u16 r · (kb u32 · u32‖record)^r · u16 q · (K u32 · D u32)^q, then optionally
      u16 e · (record u16 · date u32 · batch date u32 · flow u8 1-3 · answer u8 0-3 · status u8 · as-of u32 (0 none) ·
      u8 n ≤ 8 · (21-byte aid block)^n)^e
    - the key set's head is admitted once for `now` (`SnapshotV2.admitBatchHead`, ML-DSA-87), then each record is
      admitted in turn after the ones before it, in batch `kb`.
    - a record line: `ADMIT version kb digest`, `DUP version kb` (an exact re-send answers its first admission and adds
      nothing), or `REFUSED name`.  A question line: `SELECT K D version digest` or `NONE K D` (no rule set covers the date).
    - an EVAL line, `EVAL i mask` or `EVAL i NONE` (record `i` of the frame does not decode, admitted or not): the reason
      bits the gate's `dataFires` gives record `i` for a line of that date and flow with that eligibility read, in the
      empty context of that batch date (`emptyCtx`: no reference snapshot, so a condition on sources 1 to 4 reads them as
      absent and `STALE_ENROLLMENT` always fires).
    This is the unpinned test frame for slice I2; the rules worker's own frames do not carry it yet. -/

def refusalName : RuleSet.Refusal → String
  | .MALFORMED => "MALFORMED" | .NOSOURCE => "NOSOURCE" | .SCOPE => "SCOPE" | .EXPIRED => "EXPIRED" | .CHAIN => "CHAIN" | .ENDS => "ENDS"
  | .OVERLAP => "OVERLAP" | .UNSIGNED => "UNSIGNED"

/-- One record against the series so far: the series after it and its answer line. -/
def admitOne (verify : Bytes → Bytes → Bytes → Bool) (H : SnapshotV2.Head) (tenant : Bytes) (s : List Admitted)
    (p : Nat × Bytes) : List Admitted × String :=
  match (decode p.2).bind fun f => s.find? (·.id == digestOf f.d) with
  | some a => (s, s!"DUP {a.doc.version} {a.kb}")
  | none =>
    match admit verify H tenant p.1 s p.2 with
    | .ok a => (s ++ [a], s!"ADMIT {a.doc.version} {a.kb} {Keyset.vecHex a.id}")
    | .error r => (s, s!"REFUSED {refusalName r}")

def admitAll (verify : Bytes → Bytes → Bytes → Bool) (H : SnapshotV2.Head) (tenant : Bytes) :
    List Admitted → List (Nat × Bytes) → List Admitted × List String
  | s, [] => (s, [])
  | s, p :: ps =>
    let (s', l) := admitOne verify H tenant s p
    let (s'', ls) := admitAll verify H tenant s' ps
    (s'', l :: ls)

def askLine (s : List Admitted) (q : Nat × Nat) : String :=
  match select s q.1 q.2 with
  | some a => s!"SELECT {q.1} {q.2} {a.doc.version} {Keyset.vecHex a.id}"
  | none => s!"NONE {q.1} {q.2}"

/-- An EVAL question: record index, service date, batch date, flow and the eligibility read. -/
structure Ask where
  idx : Nat
  date : Nat
  today : Nat
  flow : Rules.Flow
  el : ElRead

def evalLine (recs : List (Nat × Bytes)) (q : Ask) : String :=
  match (recs[q.idx]?).bind fun p => decode p.2 with
  | none => s!"EVAL {q.idx} NONE"
  | some f => s!"EVAL {q.idx} {dataMask f.d q.el (emptyCtx q.today) (bareLine q.flow q.date)}"

structure Req where
  pin : Bytes
  now : Nat
  g : Bytes
  steps : List (Nat × Bytes)
  tenant : Bytes
  recs : List (Nat × Bytes)
  asks : List (Nat × Nat)
  evals : List Ask

def pBytes : P Bytes := do take (← nat 4)

def pAsk : P Ask := do
  let i ← nat 2
  let date ← nat 4
  let today ← nat 4
  let flow ← nat 1 1 3
  let ans ← nat 1 0 3
  let status ← nat 1
  let asof ← nat 4
  let aids ← many (take 21) (← nat 1 0 8)
  pure ⟨i, date, today, [Rules.Flow.FFS_CYCLE, .FFS_CLAIM, .CAP_820].getD (flow - 1) .FFS_CYCLE,
    { ans, status, aids, asof := if asof = 0 then none else some asof }⟩

def pReq : P Req := do
  let pin ← take 64
  let now ← nat 4
  let g ← pBytes
  let steps ← many (do let d ← nat 4; let x ← pBytes; pure (d, x)) (← nat 2)
  let tenant ← ident
  let recs ← many (do let kb ← nat 4; let x ← pBytes; pure (kb, x)) (← nat 2)
  let asks ← many (do let k ← nat 4; let d ← nat 4; pure (k, d)) (← nat 2)
  let evals ← if (← get).isEmpty then pure [] else many pAsk (← nat 2)
  pure ⟨pin, now, g, steps, tenant, recs, asks, evals⟩

def answerOf (bs : ByteArray) : Option (List String × UInt32) := do
  let r ← parse pReq (bs.size) bs.data.toList
  match SnapshotV2.admitBatchHead mlDsaOk r.pin r.now (Keyset.Ratchet.init r.pin) r.g r.steps with
  | none => pure (["RULESET_ADMIT=NOHEAD"], 1)
  | some (H, _) =>
    let (s, ls) := admitAll mlDsaOk H r.tenant [] r.recs
    pure (ls ++ r.asks.map (askLine s) ++ r.evals.map (evalLine r.recs), 0)

def main (_ : List String) : IO UInt32 := do
  match answerOf (← (← IO.getStdin).readBinToEnd) with
  | some (ls, code) => ls.forM IO.println; return code
  | none => IO.eprintln "RULESET_ADMIT=FRAME"; return 2
