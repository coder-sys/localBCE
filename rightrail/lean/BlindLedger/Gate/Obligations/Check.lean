import BlindLedger.Gate.Obligations.Shard
import BlindLedger.Financial.CodecLaws
import BlindLedger.Financial.Payment.CodecLaws

namespace BlindLedger.Gate.Obligations

open BlindLedger.Gate.FactCodec
open BlindLedger.Financial (FinancialInput FinancialResult ControlPack evaluate decodeFinancialInput decodeControlPack
  encodeControlPack rawEncodeFinancialInput rawEncodeFinancialResult)
open BlindLedger.Financial.Payment (Ledger Call Command ReverseCommand readCommand encodeCommand commitInput)

/-! The checker of the obligations shard: it reads the log alone, record by record, and decides every command
    again from what the records themselves hold.  An opening is decoded from the text after its OBLIG fact, a payment
    or reversal from the text after its CASH fact or its command record, and each is run through Lean's own rule on
    the obligation's input rebuilt from the records before it.  Every state row must then agree with that result and
    stand on the obligation's newest fact (an alias row: the newest CASH fact or void row of the payment Lean names)
    and case record, be followed by its evaluation reference when its revision rises, every CASH or void row with the
    payment it names, every case record with the case it opens, and every command record must have a `cid` no other
    command record has, the `cid` and request digest of what it holds, a time not earlier than the command record
    before it and below `2^63`, and name its own state row.  Every record is 256 bytes and links the record before
    it in its chain, with the chain's count.  No record a command writes may carry the import's marker (`ecls`, `lg`
    bit 0, `lseq`).  A field no command of this step sets must hold its fixed value.

    It uses none of the engine's code: not its decision (`core`), its tables, its view or its reading of records, and
    it has its own form of the evaluation reference, of each command's kind and key, of the request an alias pays and
    of a reversal's request.  What the two share is Lean's financial rule and codecs, the record layouts, the
    identities (`Ident`), the request map and the agreement of a row with a result (`Agree`).

    Left unchecked, with the reason: that `lg` bit 1 is set when it should be first (the class of a source is in the
    registry, not in the log; once set it must stay set on the obligation's later commands, and an evaluation sets it
    exactly when the obligation has it) and the class section of a pack beyond its two bytes (the store card is not in
    the log). -/

/-- What the checker keeps of an obligation: its ledger; its newest state row and that row's chain count; its newest
    case record plus one (0 for none); its newest fact or quarantine marker and that record's chain count; and for
    each payment the newest CASH fact or void row of it; and whether its `lg` has bit 1 set. -/
structure Entry where
  led : Ledger
  head : Nat
  headCount : Nat
  caseRef : Nat
  fact : Nat
  factCount : Nat
  cash : List (String × Nat)
  noClass : Bool

/-- `packs` holds each admitted pack under the `cid` of its command, which names its scope and its id.  `lastMs` is
    the time of the newest command record.  `span` is the number of the record after the newest run-end record (0
    when there is none): the first record of the run the next run-end record closes.  `prev` is the digest that
    run-end record holds (64 zero bytes when there is none): the next digest is chained to it. -/
structure Chk where
  cids : Std.HashSet Bytes := {}
  packs : Std.HashMap Bytes ControlPack := {}
  obl : Std.HashMap Bytes Entry := {}
  cmdPrev : Nat := 0
  cmdCount : Nat := 0
  lastMs : Nat := 0
  span : Nat := 0
  prev : Bytes := zeros 64

def need (ok : Bool) (i : Nat) (m : String) : Except String Unit :=
  if ok then pure () else throw s!"record {i}: {m}"

def get {α : Type} (o : Option α) (i : Nat) (m : String) : Except String α :=
  match o with
  | some a => pure a
  | none => throw s!"record {i}: {m}"

/-- Record `i` as its body and its link. -/
def rd (rec : Nat → Option Bytes) (i : Nat) : Option (Bytes × Link) := (rec i).bind unwrap

/-- Record `i` decoded by `d`, with its link. -/
def read {α : Type} (rec : Nat → Option Bytes) (i : Nat) (d : Bytes → Option α) (m : String) :
    Except String (α × Link) := do
  let (b, l) ← get (rd rec i) i "not a whole record"
  let x ← get (d b) i m
  pure (x, l)

/-- Record `i` decoded by `d` when its tag is `t`, with its link. -/
def peek {α : Type} (rec : Nat → Option Bytes) (i t : Nat) (d : Bytes → Option α) : Option (α × Link) :=
  (rd rec i).bind fun (b, l) => if tagOf b = t then (d b).map (·, l) else none

/-- The text records from `i` on, below `n`, after a record of chain count `c`, and the record after them. -/
def texts (rec : Nat → Option Bytes) (n i c : Nat) (acc : Array TextRec) : Except String (Array TextRec × Nat) :=
  if _h : i < n then
    match rd rec i with
    | some (b, l) =>
      if tagOf b = 0xF5 then do
        let t ← get (textC.dec b) i "text record"
        need (l == ⟨i, nextCount c⟩) i "text record link"
        texts rec n (i + 1) (c + 1) (acc.push t)
      else pure (acc, i)
    | none => pure (acc, i)
  else pure (acc, i)
termination_by n - i

/-- The element held by the text records from `i` on, after a record of chain count `c`, and the record after them. -/
def element (rec : Nat → Option Bytes) (n i c : Nat) : Except String (Bytes × Nat) := do
  let (ts, j) ← texts rec n i c #[]
  let e ← get (joinFrom 0 ts.toList) i "text records do not join"
  pure (e, j)

/-! ### Fields no command of this step sets

    Every command of this step is read from source 1 and states no actor, role 0 and attribution 2; the log holds
    these nowhere else, so the checker requires them as they are.  The other fields here are zero until the commands
    that set them are built. -/

def stepSource : Nat := 1

def cmdFixed (x : CmdRec) : Bool :=
  x.lrq == zeros 64 && x.actor == zeros 32 && x.role == 0 && x.attr == 2 && x.epoch == 0 && x.lseq == 0 &&
    (x.lg == 0 || x.lg == 2)

def rowFixed (row : StateRow) : Bool :=
  row.wbatch == 0 && row.windex == 0 && row.link == 0 && row.reg == 0 && row.act == 0 && row.pack == 0 &&
    row.lseq == 0

def hdrFixed (h : FactHdr) : Bool := h.lineUntil == 0 && h.receipt == stepSource && h.roff == 0

def caseFixed (k : CaseRec) : Bool :=
  k.role == 0 && k.acct == 0 && k.reason == 0 && k.conds == zeros 64 && k.act == 0 && k.assignee == zeros 32 &&
    k.nt == 0

/-- What a command's record and its state row hold the same way: the row names the command record (`i`) and stands
    on `cause` and on the obligation's newest fact (`fact`, as that plus one) and newest case record, at the
    command's time, with the conflicts and due time of the input after the command, and the command record's
    marker. -/
def rowLinks (x : CmdRec) (row : StateRow) (i cause fact caseRef : Nat) (after : FinancialInput) : Bool :=
  row.cmd == i + 1 && row.atMs == x.atMs && row.cause == cause && row.fact == fact + 1 && row.caseRef == caseRef &&
    row.conflicts == after.conflicts.length && row.dueMs == after.obligation.dueAt && row.lg == x.lg && rowFixed row

/-- The evaluation reference of a result (§2.6), in the checker's own form: the owner's evaluation id for the
    obligation at the result's revision with its length, `eref` of the result, and 128 zero bytes. -/
def refOf (res : FinancialResult) : Bytes :=
  lp16 (s!"evaluation:{res.context.obligationId}:r{res.afterRevision}").toUTF8.toList ++
    erefOf (rawEncodeFinancialResult res) ++ List.replicate 128 0

/-- The record after the evaluation reference that must follow the state row `r` of chain count `c`: the reference
    of `res`. -/
def afterRef (rec : Nat → Option Bytes) (n r c : Nat) (res : FinancialResult) : Except String Nat := do
  let (e, k) ← element rec n (r + 1) c
  need (e == refOf res) (r + 1) "evaluation reference"
  pure k

/-- The `cid` of command kind `k` with key `key` (§3.1). -/
def cidFor (scope : Bytes) (k : Nat) (key : Bytes) : Bytes := cidOf scope ((kindName k ++ ":").toUTF8.toList ++ key)

/-- The request the payment of a common origin pays, from its receipt (§3.1, an alias's identity). -/
def paidBy (L : Ledger) (origin : String) : Option String := do
  let p ← L.input.payments.find? (·.commonOriginId == origin)
  let k ← L.receipts.find? (·.paymentId == p.paymentId)
  k.paysActionId

/-- A reversal's request (§3.1 row 6) as Lean compares it: its event time is the command's, else that of the stored
    evidence of its id, else the row's time; an absent or empty origin is `reversal:<payment>`. -/
def reversalReq (scope : Bytes) (item : String) (L : Ledger) (r : ReverseCommand) (now : Nat) : Req :=
  let stored := (L.input.evidence.find? (·.evidenceId == r.evidenceId)).map (·.eventAt)
  let eventAt := match r.eventAt, stored with
    | some t, _ => t
    | none, some t => t
    | none, none => now
  let origin := match r.commonOriginId with
    | some o => if o == "" then "reversal:" ++ r.paymentId else o
    | none => "reversal:" ++ r.paymentId
  ⟨6, r.evidenceId.toUTF8.toList, scope, [.s item, .s r.paymentId,
    .d (H (encodeCommand (.reverse { r with eventAt := some eventAt, commonOriginId := some origin })))]⟩

/-- Check the command whose record is `i`, in a log of `n` records; the number of the record after its last one. -/
def checkOne (st : Chk) (rec : Nat → Option Bytes) (n i : Nat) : Except String (Chk × Nat) := do
  let (x, xl) ← read rec i cmdC.dec "not a command record"
  need (!st.cids.contains x.cid) i "a second command record of one cid"
  need (xl == ⟨st.cmdPrev, nextCount st.cmdCount⟩) i "command record link"
  need (cmdFixed x) i "command record fixed fields"
  need (st.lastMs ≤ x.atMs && x.atMs < 2 ^ 63) i "command time"
  let st := { st with cids := st.cids.insert x.cid, cmdPrev := i + 1, cmdCount := xl.count, lastMs := x.atMs }
  let exprev := if x.exprev = 0 then none else some (x.exprev - 1)
  match x.ckind with
  | 1 =>
    let (e, j) ← element rec n (i + 1) xl.count
    let (p, cls) ← get (decodeControlPack e) i "pack element"
    -- A pack's scope is the one its own five ids name.
    let scope := scopeOf p.stateId.toUTF8.toList p.deploymentId.toUTF8.toList p.programId.toUTF8.toList
      p.periodId.toUTF8.toList p.currency.toUTF8.toList
    let key := p.packId.toUTF8.toList
    need (x.result == 0 && x.lg == 0 && x.exprev == 0 && cls.length == 2 &&
      e == encodeControlPack p ++ cls) i "pack record"
    need (x.cid == cidFor scope 1 key && x.rqd == rqdOf (canon ⟨1, key, scope, [.d (H e)]⟩)) i "pack command record"
    pure ({ st with packs := st.packs.insert x.cid p }, j)
  | 2 =>
    -- The OBLIG fact, each case record and the state row each start their own chain.
    let (f, fl) ← read rec (i + 1) obligC.dec "OBLIG fact"
    let (e, j) ← element rec n (i + 2) fl.count
    let inp ← get (decodeFinancialInput e) (i + 2) "opening input"
    let res ← get (evaluate inp) j "evaluation rejected"
    let committed := commitInput inp res
    let ctx := inp.context
    let scope := scopeOfCtx ctx
    let ob := obOfCtx ctx
    -- One OPEN record per case of the opening input, in order; the row names the last, or none.
    let mut q := j
    for k in committed.cases do
      let (kase, kl) ← read rec q caseC.dec "case record"
      need (kase.op == 1 && caseAgree scope ob k kase && caseFixed kase && kase.cmd == i + 1 && kase.lg == x.lg &&
        kl == ⟨0, 1⟩) q "case record"
      q := q + 1
    let (row, rl) ← read rec q stateC.dec "state row"
    let caseRef := if q = j then 0 else q
    let key := utf8 (ctx.populationId ++ "/" ++ ctx.itemId)
    need (st.packs[cidFor scope 1 (utf8 inp.pack.packId)]? == some inp.pack) (i + 2)
      "the opening's pack was not admitted"
    need (inp.payments.isEmpty && inp.claims.isEmpty && inp.determinations.isEmpty && inp.conflicts.isEmpty &&
      inp.actions.isEmpty && (inp.evidence.isEmpty || x.lg == 2)) (i + 2) "opening input"
    -- The request is the input without its evaluation time, which is the command record's own time.
    need (x.cid == cidFor scope 2 key &&
      x.rqd == rqdOf (canon ⟨2, key, scope, [.d (H (rawEncodeFinancialInput { inp with evaluatedAt := 0 }))]⟩) &&
      x.nt == 0 && x.exprev == 0 && x.atMs == inp.evaluatedAt && x.result == q + 1) i "opening command record"
    need (row.mkind == 13 && stateAgree res 0 row && rowLinks x row i (i + 1) (i + 1) caseRef committed &&
      rl == ⟨0, 1⟩) q "opening row"
    need (f.h.op == 0 && f.h.subject == ob && hdrFixed f.h &&
      f.h.sid == obligSidOf scope (utf8 ctx.populationId) (utf8 ctx.itemId) && f.h.vstart == utcDate x.atMs &&
      f.h.vstop == utcDate x.atMs && f.owed == inp.obligation.owedCents && f.dueMs == inp.obligation.dueAt &&
      f.rule == inp.obligation.ruleVersion && f.pop == popOf scope (utf8 ctx.populationId) &&
      f.item == display 51 ctx.itemId && f.period == display 21 ctx.periodId && f.ecls == 0 && fl == ⟨0, 1⟩) (i + 1)
      "OBLIG fact"
    need (!st.obl.contains ob) q "obligation opened twice"
    let k ← afterRef rec n q rl.count res
    pure ({ st with obl := st.obl.insert ob ⟨{ input := committed, receipts := [] }, q, 1, caseRef, i + 1, 1, [], x.lg == 2⟩ },
      k)
  | 5 | 6 =>
    let cash := peek rec (i + 1) 15 cashC.dec
    let start := if cash.isSome then i + 2 else i + 1
    let (e, j) ← element rec n start (match cash with | some (_, l) => l.count | none => xl.count)
    need (x.nt == (if cash.isSome then 0 else j - start)) i "text count"
    let (cmd, rest) ← get (readCommand e) start "payment command"
    need rest.isEmpty start "bytes after the payment command"
    -- A conflict's quarantine marker follows the command's text; the row follows it.
    let mark := peek rec j 0x50 markC.dec
    let ri := if mark.isSome then j + 1 else j
    let (row, rl) ← read rec ri stateC.dec "state row"
    let o ← get st.obl[row.ob]? ri "unknown obligation"
    -- The row continues the obligation's state rows; a fact or marker continues its facts.
    let fl : Link := ⟨o.fact + 1, nextCount o.factCount⟩
    need (rl == ⟨o.head + 1, nextCount o.headCount⟩ && (cash.map (·.2)).all (· == fl) &&
      (mark.map (·.2)).all (· == fl) && (cash.map (·.1.h)).all hdrFixed) ri "link"
    let L := o.led
    let scope := scopeOfCtx L.input.context
    let item := L.input.context.itemId
    let call : Call := ⟨row.atMs, exprev, cmd⟩
    let L' := BlindLedger.Financial.Payment.step L call
    let bad : Except String (Bool × Req × Nat × Option Nat × Option String × Option FinancialResult) :=
      throw s!"record {ri}: the row is not the payment's outcome"
    -- Whether the fact and row agree with Lean's outcome, the request the command is compared by on retry (§3.1),
    -- the record the row stands on, the fact or marker written (none for an alias), the payment it is the newest
    -- fact of, and the result its evaluation reference names (none for an alias, whose revision does not rise).
    let (ok, req, cause, wrote, pid, ref) ← match L.outcome call, row.mkind, cash, mark, cmd with
      | .mutated .RECORDED w post res, 14, some (f, _), none, .record r =>
        let p ← get w.payment j "no payment"
        let k ← get w.receipt j "no receipt"
        let pays := match k.paysActionId with
          | some a => akOf scope (utf8 a)
          | none => zeros 32
        pure (cashAgree post.context p f && f.pays == pays && f.ecls == 0 && stateAgree res p.amountCents row,
          paymentIdentityReq scope item r k, i + 1, some (i + 1), some p.paymentId, some res)
      | .mutated .REVERSED w post res, 15, some (f, _), none, .reverse r =>
        let p ← get w.payment j "no payment"
        let ev ← get w.evidence j "no reversal evidence"
        pure (cashVoidAgree post.context p ev f && f.pays == zeros 32 && f.ecls == 0 &&
          stateAgree res p.amountCents row, reversalReq scope item L r row.atMs, i + 1, some (i + 1),
          some p.paymentId, some res)
      | .mutated .CONFLICT_RECORDED _ _ res, 16, none, some (m, _), .record r =>
        let ob := obOf scope (utf8 item)
        pure (stateAgree res 0 row && m.src == stepSource && m.fkind == 15 && m.subject == ob && m.receipt == 0 &&
          m.roff == 0 && m.cause == originConflict && m.sidk == 1 && m.sid == sidOf 15 [ob, utf8 r.commonOriginId],
          paymentReq scope item r none none, j, some j, none, some res)
      | .alias pid _ post, 17, none, none, .record r =>
        let res ← get (evaluate post) j "evaluation rejected"
        let k ← get (o.cash.lookup pid) ri "an alias of a payment with no fact"
        pure (stateAgree res 0 { row with rev := res.afterRevision } && row.rev == post.beforeRevision,
          aliasIdentityReq scope item r (paidBy L r.commonOriginId), k, none, none, none)
      | _, _, _, _, _ => bad
    let fact := wrote.getD o.fact
    -- The command's kind and the key of its id (§3.1 rows 5 and 6).
    let (kind, key) := match cmd with
      | .record r => (5, r.paymentId.toUTF8.toList)
      | .reverse r => (6, r.evidenceId.toUTF8.toList)
    need (ok && (!o.noClass || x.lg == 2) && x.ckind == kind && x.cid == cidFor scope kind key && x.rqd == rqdOf (canon req) &&
      x.result == ri + 1 && rowLinks x row i cause fact o.caseRef L'.input) ri "the row is not the payment's outcome"
    let k ← match ref with
      | some res => afterRef rec n ri rl.count res
      | none => pure (ri + 1)
    let factCount := if wrote.isSome then fl.count else o.factCount
    let cash := match pid with
      | some p => (p, i + 1) :: o.cash
      | none => o.cash
    let o := { o with led := L', head := ri, headCount := rl.count, fact, factCount, cash, noClass := x.lg == 2 }
    pure ({ st with obl := st.obl.insert row.ob o }, k)
  | 12 =>
    -- The request id follows the command record as text; an empty id has no text record.
    let (rid, j) ← if x.nt == 0 then pure ([], i + 1) else element rec n (i + 1) xl.count
    need (x.nt == j - (i + 1)) i "text count"
    let (row, rl) ← read rec j stateC.dec "state row"
    let o ← get st.obl[row.ob]? j "unknown obligation"
    let inp := { o.led.input with evaluatedAt := row.atMs }
    need (exprev.all (· == inp.beforeRevision)) i "stale revision admitted"
    let res ← get (evaluate inp) j "evaluation rejected"
    let after := commitInput inp res
    let scope := scopeOfCtx inp.context
    need (x.cid == cidFor scope 12 rid && x.rqd == rqdOf (canon ⟨12, rid, scope, [.s inp.context.itemId]⟩) &&
      (x.lg == 2) == o.noClass) i "evaluation command record"
    need (row.mkind == 25 && stateAgree res 0 row && rowLinks x row i o.fact o.fact o.caseRef after &&
      x.result == j + 1 && rl == ⟨o.head + 1, nextCount o.headCount⟩) j "the row is not the evaluation"
    let k ← afterRef rec n j rl.count res
    let o := { o with led := { o.led with input := after }, head := j, headCount := rl.count }
    pure ({ st with obl := st.obl.insert row.ob o }, k)
  | k => throw s!"record {i}: command kind {k} is not built"

/-! ## Each command's own records

    A command is checked on its own records alone: its command record and the records its own counts name.  A pack's
    are its `nt` text records.  Any other command's run to its state row, the record its `result` names, and after a
    row whose revision rises (every row but an alias's) come the text records of its evaluation reference, as many as
    the reference's own length takes.  So a command whose records are all in the log checks the same whatever follows
    it, and a log ends early exactly when its last command's own records run past its end. -/

/-- The bytes of an evaluation reference whose id is `L` bytes: the id after its two-byte length, `eref` and 128
    zero bytes (`refOf`). -/
def refBytes (L : Nat) : Nat := 2 + L + 64 + 128

/-- The record after an evaluation reference whose first text record is `r`, by the id length its first two bytes
    state; the record after `r` when `r` is not a text record. -/
def refEnd (rec : Nat → Option Bytes) (r : Nat) : Nat :=
  match peek rec r 0xF5 textC.dec with
  | some (t, _) => r + (refBytes ((t.bytes.getD 0 0).toNat + 256 * (t.bytes.getD 1 0).toNat) + textBytes - 1) / textBytes
  | none => r + 1

/-- The record after a command whose state row is record `q - 1`: the record after the row for an alias, whose
    revision does not rise, else the record after the evaluation reference that follows the row. -/
def rowEnd (rec : Nat → Option Bytes) (q : Nat) : Nat :=
  match peek rec (q - 1) 0x60 stateC.dec with
  | some (row, _) => if row.mkind = 17 then q else refEnd rec q
  | none => q

/-- The record after the records of the command whose command record is `i`, by its own counts. -/
def ownEnd (rec : Nat → Option Bytes) (i : Nat) : Nat :=
  match peek rec i 0x74 cmdC.dec with
  | some (x, _) => if x.ckind = 1 then i + 1 + x.nt else if x.result ≤ i + 1 then i + 1 else rowEnd rec x.result
  | none => i + 1

/-- The first `e` records of a log. -/
def cutAt (rec : Nat → Option Bytes) (e : Nat) : Nat → Option Bytes := fun k => if k < e then rec k else none

theorem refEnd_gt (rec : Nat → Option Bytes) (r : Nat) : r < refEnd rec r := by
  unfold refEnd
  cases peek rec r 0xF5 textC.dec with
  | none => dsimp only; omega
  | some v =>
    obtain ⟨t, l⟩ := v
    dsimp only
    simp only [refBytes, textBytes]
    omega

theorem rowEnd_ge (rec : Nat → Option Bytes) (q : Nat) : q ≤ rowEnd rec q := by
  unfold rowEnd
  cases peek rec (q - 1) 0x60 stateC.dec with
  | none => dsimp only; omega
  | some v =>
    obtain ⟨row, l⟩ := v
    dsimp only
    split
    · omega
    · have := refEnd_gt rec q
      omega

theorem ownEnd_gt (rec : Nat → Option Bytes) (i : Nat) : i < ownEnd rec i := by
  unfold ownEnd
  cases peek rec i 0x74 cmdC.dec with
  | none => dsimp only; omega
  | some v =>
    obtain ⟨x, l⟩ := v
    dsimp only
    split
    · omega
    · split
      · omega
      · have := rowEnd_ge rec x.result
        omega

/-- What the checker found in a log: the commands that checked, the number of the record after the last of them
    (every record below it is good), the first disagreement, if any, and the checker's state at `good` when the check
    passed or stopped only because the last command's own records run past the end of the log (else empty). -/
structure Checked where
  cmds : Nat
  good : Nat
  err : Option String
  st : Chk

/-- A commit point, a repair record or a run-end record, as the record number it names and its link. -/
def pointOf (r : Bytes) : Option (Nat × Link) :=
  (unwrap r).bind fun (b, l) =>
    if tagOf b = 0xF6 then (repairC.dec b).map fun x => (x.at_, l)
    else if tagOf b = 0x77 then (endC.dec b).map fun x => (x.at_, l)
    else none

/-- Record `i` as a commit point. -/
def point (rec : Nat → Option Bytes) (i : Nat) : Option (Nat × Link) := (rec i).bind pointOf

/-- The digest record `i` holds, when it is a run-end record. -/
def endDig (rec : Nat → Option Bytes) (i : Nat) : Option Bytes :=
  (rec i).bind fun r => (unwrap r).bind fun (b, _) => if tagOf b = 0x77 then (endC.dec b).map (·.dig) else none

/-- The domain of a run-end digest. -/
def runEndDom : Bytes := "RR/OBLIG/RUN-END/v1".toUTF8.toList

/-- The digest of a run as the checker models it: SHA3-512 of the domain, the number of the run's first record
    (5 bytes, as a record holds its own number), the digest of the run-end record before it (`prev`; 64 zero bytes
    when there is none), and the bytes of records `s` to `i`, not counting `i`. -/
def spanDig (rec : Nat → Option Bytes) (s : Nat) (prev : Bytes) (i : Nat) : Bytes :=
  H (runEndDom ++ leBytes 5 s ++ prev ++ (List.range' s (i - s)).flatMap fun k => (rec k).getD [])

/-- The state after the commit point at record `i`, which names record `a` and has link `l`, when it holds: it names
    its own place, starts its own chain and, as a run-end record, holds `dig` of its run, which then ends. -/
def pass (rec : Nat → Option Bytes) (dig : Nat → Bytes → Nat → Bytes) (st : Chk) (i a : Nat) (l : Link) : Option Chk :=
  if a == i && l == ⟨0, 1⟩ then
    match endDig rec i with
    | some d => if d == dig st.span st.prev i then some { st with span := i + 1, prev := d } else none
    | none => some st
  else none

/-- Check a whole log of `n` records, with `dig s prev i` the digest of the run of records `s` to `i` after the
    run-end record whose digest is `prev`.  A commit point
    stands between commands, names its own place and, as a run-end record, holds the digest of its run.  Each command
    is checked on its own records (`ownEnd`), which must all be in the log, and the check must end at their end.
    `cmds` counts the commands checked so far.  It is kept outside `st` so that nothing here reads `st` after
    `checkOne` has taken it: the tables then grow in place, and are not copied once for every command. -/
def checkLog (rec : Nat → Option Bytes) (dig : Nat → Bytes → Nat → Bytes) (n : Nat) (st : Chk := {}) (i : Nat := 0)
    (cmds : Nat := 0) : Checked :=
  if _h : i < n then
    match point rec i with
    | some (a, l) =>
      match pass rec dig st i a l with
      | some st' => checkLog rec dig n st' (i + 1) cmds
      | none => ⟨cmds, i, some s!"record {i}: a repair or run-end record not at its place, or a run-end record whose digest is not its run's", {}⟩
    | none =>
      if ownEnd rec i ≤ n then
        match checkOne st (cutAt rec (ownEnd rec i)) (ownEnd rec i) i with
        | .ok (st', j) =>
          if _hj : j = ownEnd rec i then checkLog rec dig n st' j (cmds + 1)
          else ⟨cmds, i, some s!"record {i}: the command's records are not the ones its counts name", {}⟩
        | .error e => ⟨cmds, i, some e, {}⟩
      else ⟨cmds, i, some s!"record {i}: the command's own records run past the end of the log", st⟩
  else ⟨cmds, i, none, st⟩
termination_by n - i
decreasing_by
  all_goals first
    | omega
    | (subst_vars; exact Nat.sub_lt_sub_left (by omega) (ownEnd_gt _ _))

/-- The reported boundary is inside the log. -/
theorem checkLog_good_le {rec : Nat → Option Bytes} {dig : Nat → Bytes → Nat → Bytes} {n : Nat} :
    ∀ (k : Nat) (st : Chk) (i c : Nat), n - i = k → i ≤ n → (checkLog rec dig n st i c).good ≤ n := by
  intro k
  induction k using Nat.strongRecOn with
  | _ k ih =>
    intro st i c hk hi
    unfold checkLog
    split
    · split
      · split
        · exact ih (n - (i + 1)) (by omega) _ (i + 1) c rfl (by omega)
        · exact hi
      · split
        · split
          · split
            · rename_i hj
              have := ownEnd_gt rec i
              exact ih _ (by omega) _ _ _ rfl (by omega)
            · exact hi
          · exact hi
        · exact hi
    · exact hi

theorem checkLog_good_ge {rec : Nat → Option Bytes} {dig : Nat → Bytes → Nat → Bytes} {n : Nat} :
    ∀ (k : Nat) (st : Chk) (i c : Nat), n - i = k → i ≤ (checkLog rec dig n st i c).good := by
  intro k
  induction k using Nat.strongRecOn with
  | _ k ih =>
    intro st i c hk
    unfold checkLog
    split
    · split
      · split
        · exact Nat.le_trans (Nat.le_succ i) (ih (n - (i + 1)) (by omega) _ (i + 1) c rfl)
        · exact Nat.le_refl _
      · split
        · split
          · rename_i st' j hone
            split
            · rename_i hj
              have := ownEnd_gt rec i
              have := ih (n - j) (by omega) st' j (c + 1) rfl
              omega
            · exact Nat.le_refl _
          · exact Nat.le_refl _
        · exact Nat.le_refl _
    · exact Nat.le_refl _

/-- None of the `k` records from record `j` on is a command record. -/
def noCommand (rec : Nat → Option Bytes) : Nat → Nat → Bool
  | _, 0 => true
  | j, k + 1 => (peek rec j 0x74 cmdC.dec).isNone && noCommand rec (j + 1) k

/-- Whether a log of `n` whole records, whose check stopped at record `good`, ends torn there: no record after
    record `good` is a command record.  The cut is per command: it removes some of the records of one command, the
    one at `good`, and nothing else. -/
def tornEnd (rec : Nat → Option Bytes) (good n : Nat) : Bool := noCommand rec (good + 1) (n - (good + 1))

/-- Whether the check `a` of the `n` records of a log passed on all of them, or stopped only because the own
    records of the command at `a.good` run past the end of the log. -/
def endedEarly (rec : Nat → Option Bytes) (n : Nat) (a : Checked) : Bool :=
  n ≤ a.good || n < ownEnd rec a.good

/-- None of the `k` records from record `j` on is a commit point. -/
def noPoint (rec : Nat → Option Bytes) : Nat → Nat → Bool
  | _, 0 => true
  | j, k + 1 => (point rec j).isNone && noPoint rec (j + 1) k

/-- Whether opening a log of `n` whole records whose check is `a` may cut it back to `a.good`.  Every record before a
    commit point was synced before any answer was given for it, so only records after the last commit point may be
    cut: none of the records from `a.good` on is a commit point.  The end must also be torn (`tornEnd`) and must have
    ended early (`endedEarly`), so that the cut takes some records of one command and the check goes on from the
    state at `a.good` (`checkLog_resume`). -/
def cutOk (rec : Nat → Option Bytes) (n : Nat) (a : Checked) : Bool :=
  noPoint rec a.good (n - a.good) && tornEnd rec a.good n && endedEarly rec n a

theorem point_congr {rec rec' : Nat → Option Bytes} {k : Nat} (h : rec' k = rec k) : point rec' k = point rec k := by
  simp only [point, h]

/-- A commit point is a whole record whose tag is the repair record's or the run-end record's. -/
theorem point_some {rec : Nat → Option Bytes} {i : Nat} {q : Nat × Link} (h : point rec i = some q) :
    ∃ b l, rd rec i = some (b, l) ∧ (tagOf b = 0xF6 ∨ tagOf b = 0x77) := by
  unfold point at h
  unfold rd
  cases hr : rec i with
  | none => rw [hr] at h; cases h
  | some r =>
    rw [hr] at h
    change pointOf r = some q at h
    unfold pointOf at h
    cases hu : unwrap r with
    | none => rw [hu] at h; cases h
    | some v =>
      obtain ⟨b, l⟩ := v
      rw [hu] at h
      refine ⟨b, l, by simp [hu], ?_⟩
      by_cases h1 : tagOf b = 0xF6
      · exact Or.inl h1
      · by_cases h2 : tagOf b = 0x77
        · exact Or.inr h2
        · simp [h1, h2] at h

theorem point_not_cmd {rec : Nat → Option Bytes} {i : Nat} {q : Nat × Link} (h : point rec i = some q) :
    peek rec i 0x74 cmdC.dec = none := by
  obtain ⟨b, l, hb, ht⟩ := point_some h
  have hn : tagOf b ≠ 0x74 := by rcases ht with ht | ht <;> rw [ht] <;> decide
  simp [peek, hb, hn]

theorem noPoint_false {rec : Nat → Option Bytes} : ∀ (k j p : Nat), (point rec p).isSome = true → j ≤ p →
    p < j + k → noPoint rec j k = false
  | 0, _, _, _, _, h2 => by omega
  | k + 1, j, p, hp, h1, h2 => by
    rcases Nat.eq_or_lt_of_le h1 with he | hlt
    · subst he
      cases hq : point rec j <;> simp_all [noPoint]
    · simp only [noPoint, noPoint_false k (j + 1) p hp hlt (by omega), Bool.and_false]

/-- A log whose first damage lies at or before a commit point is never cut when it is opened: the check `a` stopped
    at `a.good`, at or before record `p`, a repair or run-end record of the log, so the records of every command
    answered before `p` stay as they are, and the log is refused. -/
theorem marked_damage_not_cut {rec : Nat → Option Bytes} {n p : Nat} {a : Checked} (hp : (point rec p).isSome = true)
    (h1 : a.good ≤ p) (h2 : p < n) : cutOk rec n a = false := by
  simp [cutOk, noPoint_false (n - a.good) a.good p hp h1 (by omega)]

theorem endDig_point {rec : Nat → Option Bytes} {i : Nat} {d : Bytes} (h : endDig rec i = some d) :
    (point rec i).isSome = true := by
  unfold endDig at h
  unfold point pointOf
  cases hr : rec i with
  | none => simp [hr] at h
  | some r =>
    cases hu : unwrap r with
    | none => simp [hr, hu] at h
    | some v =>
      obtain ⟨b, l⟩ := v
      by_cases ht : tagOf b = 0x77
      · cases hx : endC.dec b with
        | none => simp [hr, hu, ht, hx] at h
        | some x =>
          have h76 : tagOf b ≠ 0xF6 := by rw [ht]; decide
          simp [hu, ht, hx, h76]
      · simp [hr, hu, ht] at h

theorem pass_obl {rec : Nat → Option Bytes} {dig : Nat → Bytes → Nat → Bytes} {st st' : Chk} {i a : Nat} {l : Link}
    (h : pass rec dig st i a l = some st') : st'.obl = st.obl := by
  unfold pass at h
  split at h
  · split at h
    · split at h
      · cases h; rfl
      · cases h
    · cases h; rfl
  · cases h

theorem pass_congr {rec rec' : Nat → Option Bytes} {dig dig' : Nat → Bytes → Nat → Bytes} {st : Chk} {i a : Nat} {l : Link}
    (h : rec' i = rec i) (hd : dig' st.span st.prev i = dig st.span st.prev i) : pass rec' dig' st i a l = pass rec dig st i a l := by
  simp only [pass, endDig, h, hd]

/-- A run-end record whose digest is not the digest of its run, when the check reaches it, stops the check there: the
    log is refused and never cut.  With `marked_damage_not_cut`, damage at or before the last run-end record, in its
    run's records or in the record itself, is never cut, whether the check stops at the damage or at the digest. -/
theorem digest_damage_not_cut {rec : Nat → Option Bytes} {dig : Nat → Bytes → Nat → Bytes} {n i c : Nat} {st : Chk}
    {d : Bytes} (hi : i < n) (hd : endDig rec i = some d) (hne : d ≠ dig st.span st.prev i) :
    (checkLog rec dig n st i c).good = i ∧ cutOk rec n (checkLog rec dig n st i c) = false := by
  have hp := endDig_point hd
  obtain ⟨⟨a, l⟩, hq⟩ := Option.isSome_iff_exists.mp hp
  have hpass : pass rec dig st i a l = none := by simp [pass, hd, hne]
  have hg : (checkLog rec dig n st i c).good = i := by
    rw [checkLog, dif_pos hi, hq]
    dsimp only
    rw [hpass]
  exact ⟨hg, marked_damage_not_cut hp (by omega) hi⟩

theorem peek_congr {α : Type} {rec rec' : Nat → Option Bytes} {k t : Nat} {d : Bytes → Option α}
    (h : rec' k = rec k) : peek rec' k t d = peek rec k t d := by
  simp only [peek, rd, h]

theorem refEnd_local {rec rec' : Nat → Option Bytes} {r : Nat} (h : ∀ k, k < refEnd rec r → rec' k = rec k) :
    refEnd rec' r = refEnd rec r := by
  have h1 := peek_congr (t := 0xF5) (d := textC.dec) (h r (refEnd_gt rec r))
  unfold refEnd
  rw [h1]

theorem rowEnd_local {rec rec' : Nat → Option Bytes} {q : Nat} (hq : 0 < q)
    (h : ∀ k, k < rowEnd rec q → rec' k = rec k) : rowEnd rec' q = rowEnd rec q := by
  have h1 := peek_congr (t := 0x60) (d := stateC.dec) (h (q - 1) (by have := rowEnd_ge rec q; omega))
  unfold rowEnd at h ⊢
  rw [h1]
  cases hp : peek rec (q - 1) 0x60 stateC.dec with
  | none => rfl
  | some v =>
    obtain ⟨row, l⟩ := v
    rw [hp] at h
    dsimp only at h ⊢
    by_cases hm : row.mkind = 17
    · rw [if_pos hm, if_pos hm]
    · rw [if_neg hm] at h
      rw [if_neg hm, if_neg hm]
      exact refEnd_local h

/-- A command's own end depends on its own records alone. -/
theorem ownEnd_local {rec rec' : Nat → Option Bytes} {i : Nat} (h : ∀ k, k < ownEnd rec i → rec' k = rec k) :
    ownEnd rec' i = ownEnd rec i := by
  have h1 := peek_congr (t := 0x74) (d := cmdC.dec) (h i (ownEnd_gt rec i))
  unfold ownEnd at h ⊢
  rw [h1]
  cases hp : peek rec i 0x74 cmdC.dec with
  | none => rfl
  | some v =>
    obtain ⟨x, l⟩ := v
    rw [hp] at h
    dsimp only at h ⊢
    by_cases h2 : x.ckind = 1
    · rw [if_pos h2, if_pos h2]
    · rw [if_neg h2] at h
      rw [if_neg h2, if_neg h2]
      by_cases h3 : x.result ≤ i + 1
      · rw [if_pos h3, if_pos h3]
      · rw [if_neg h3] at h
        rw [if_neg h3, if_neg h3]
        exact rowEnd_local (by omega) h

theorem cutAt_congr {rec rec' : Nat → Option Bytes} {e : Nat} (h : ∀ k, k < e → rec' k = rec k) :
    cutAt rec' e = cutAt rec e := by
  funext k
  unfold cutAt
  split
  · exact h k ‹_›
  · rfl

/-- A check that passed, or stopped only because its last command's own records run past the end, goes on from the
    state it reached: on any log that holds the same records below where it stopped, checking from the start is
    checking from there.  So a run that appends records checks only those, from the state its log was opened at. -/
theorem checkLog_resume {rec rec' : Nat → Option Bytes} {dig dig' : Nat → Bytes → Nat → Bytes} {n n' : Nat} :
    ∀ (k : Nat) (st : Chk) (i c : Nat) (a : Checked), checkLog rec dig n st i c = a → n - i = k →
      endedEarly rec n a = true → (∀ p, p < a.good → rec' p = rec p) →
      (∀ s q p, p < a.good → dig' s q p = dig s q p) → a.good ≤ n' →
        checkLog rec' dig' n' st i c = checkLog rec' dig' n' a.st a.good a.cmds := by
  intro k
  induction k using Nat.strongRecOn with
  | _ k ih =>
    intro st i c a ha hk hee hag hdig hn'
    rw [checkLog] at ha
    split at ha
    · rename_i hi
      split at ha
      · rename_i x l hpeek
        split at ha
        · rename_i st' hpass
          have hga : i + 1 ≤ a.good := by
            rw [← ha]
            exact checkLog_good_ge _ st' (i + 1) c rfl
          rw [← ih (n - (i + 1)) (by omega) st' (i + 1) c a ha rfl hee hag hdig hn']
          conv => lhs; rw [checkLog]
          rw [dif_pos (show i < n' by omega), point_congr (hag i (by omega)), hpeek]
          dsimp only
          rw [pass_congr (hag i (by omega)) (hdig _ _ i (by omega)), hpass]
        · subst ha
          have hno : peek rec i 0x74 cmdC.dec = none := point_not_cmd hpeek
          have hoe : ownEnd rec i = i + 1 := by
            unfold ownEnd
            rw [hno]
          simp [endedEarly, hoe] at hee
          omega
      · rename_i hpeek
        split at ha
        · rename_i he
          split at ha
          · rename_i st' j hone
            split at ha
            · rename_i hj
              have := ownEnd_gt rec i
              have hga : j ≤ a.good := by
                rw [← ha]
                exact checkLog_good_ge _ st' j (c + 1) rfl
              have hown : ownEnd rec' i = ownEnd rec i := ownEnd_local fun p hp => hag p (by omega)
              have hcut : cutAt rec' (ownEnd rec i) = cutAt rec (ownEnd rec i) :=
                cutAt_congr fun p hp => hag p (by omega)
              rw [← ih (n - j) (by omega) st' j (c + 1) a ha rfl hee hag hdig hn']
              conv => lhs; rw [checkLog]
              rw [dif_pos (show i < n' by omega), point_congr (hag i (by omega)), hpeek]
              dsimp only
              rw [hown, if_pos (show ownEnd rec i ≤ n' by omega), hcut, hone]
              dsimp only
              rw [dif_pos hj]
            · subst ha
              simp [endedEarly] at hee
              omega
          · subst ha
            simp [endedEarly] at hee
            omega
        · subst ha
          rfl
    · subst ha
      rfl

/-- A log whose check stops at a command whose own records are all in the log did not end early: its last command
    was changed, not torn, and the log is never cut. -/
theorem whole_last_command_not_cut {rec : Nat → Option Bytes} {dig : Nat → Bytes → Nat → Bytes} {n : Nat}
    (hlt : (checkLog rec dig n).good < n) (hw : ownEnd rec (checkLog rec dig n).good ≤ n) :
    endedEarly rec n (checkLog rec dig n) = false ∧ cutOk rec n (checkLog rec dig n) = false := by
  have he : endedEarly rec n (checkLog rec dig n) = false := by
    simp only [endedEarly, Bool.or_eq_false_iff, decide_eq_false_iff_not]
    omega
  exact ⟨he, by simp [cutOk, he]⟩

theorem noCommand_none {rec : Nat → Option Bytes} : ∀ (k j i : Nat), noCommand rec j k = true → j ≤ i → i < j + k →
    peek rec i 0x74 cmdC.dec = none
  | 0, _, _, _, _, _ => by omega
  | k + 1, j, i, h, h1, h2 => by
    simp only [noCommand, Bool.and_eq_true, Option.isNone_iff_eq_none] at h
    rcases Nat.eq_or_lt_of_le h1 with rfl | hlt
    · exact h.1
    · exact noCommand_none k (j + 1) i h.2 hlt (by omega)

/-- What is cut from a torn end holds at most one command record, and that one is its first record. -/
theorem torn_end_one_command {rec : Nat → Option Bytes} {good n i : Nat} (h : tornEnd rec good n = true)
    (h1 : good < i) (h2 : i < n) : peek rec i 0x74 cmdC.dec = none :=
  noCommand_none _ _ i h h1 (by omega)

/-! ## The input read back from the records

    Proved here: every element the engine writes as text records (`textsAt`) is read back by the checker's `element`
    as that element, from the records alone (`element_rebuild`); an opening's element decodes to the very input the
    engine applied (`opening_rebuild`); and a payment's element decodes to its command (`command_rebuild`).  The
    composition over a whole log is stated at the end of this file. -/

theorem encF_append : ∀ (L1 : List Fld) (cs1 : List Cell) (L2 : List Fld) (cs2 : List Cell), fit L1 cs1 →
    encF (L1 ++ L2) (cs1 ++ cs2) = encF L1 cs1 ++ encF L2 cs2
  | [], cs1, _, _, h => by simp only [fit] at h; subst h; simp [encF]
  | .lit w v :: fs, cs, L2, cs2, h => by
    simp only [List.cons_append, encF, encF_append fs cs L2 cs2 h.2, List.append_assoc]
  | .num w :: fs, .n v :: cs, L2, cs2, h => by
    simp only [List.cons_append, encF, encF_append fs cs L2 cs2 h.2, List.append_assoc]
  | .blk w :: fs, .b v :: cs, L2, cs2, h => by
    simp only [List.cons_append, encF, encF_append fs cs L2 cs2 h.2, List.append_assoc]
  | .num _ :: _, [], _, _, h => by simp [fit] at h
  | .num _ :: _, .b _ :: _, _, _, h => by simp [fit] at h
  | .blk _ :: _, [], _, _, h => by simp [fit] at h
  | .blk _ :: _, .n _ :: _, _, _, h => by simp [fit] at h

theorem fit_split : ∀ (L1 L2 : List Fld) (cs : List Cell), fit (L1 ++ L2) cs →
    ∃ cs1 cs2, cs = cs1 ++ cs2 ∧ fit L1 cs1 ∧ fit L2 cs2
  | [], _, cs, h => ⟨[], cs, rfl, rfl, h⟩
  | .lit _ _ :: fs, L2, cs, h => by
    obtain ⟨cs1, cs2, rfl, h1, h2⟩ := fit_split fs L2 cs h.2
    exact ⟨cs1, cs2, rfl, ⟨h.1, h1⟩, h2⟩
  | .num _ :: fs, L2, .n v :: cs, h => by
    obtain ⟨cs1, cs2, rfl, h1, h2⟩ := fit_split fs L2 cs h.2
    exact ⟨.n v :: cs1, cs2, rfl, ⟨h.1, h1⟩, h2⟩
  | .blk _ :: fs, L2, .b v :: cs, h => by
    obtain ⟨cs1, cs2, rfl, h1, h2⟩ := fit_split fs L2 cs h.2
    exact ⟨.b v :: cs1, cs2, rfl, ⟨h.1, h1⟩, h2⟩
  | .num _ :: _, _, [], h => by simp [fit] at h
  | .num _ :: _, _, .b _ :: _, h => by simp [fit] at h
  | .blk _ :: _, _, [], h => by simp [fit] at h
  | .blk _ :: _, _, .n _ :: _, h => by simp [fit] at h

theorem fit_linkL {cs : List Cell} (h : fit linkL cs) : cs.length = 2 := by
  rcases cs with _ | ⟨(_ | _), _ | ⟨(_ | _), _ | ⟨_, _⟩⟩⟩ <;> simp [fit, linkL, z] at h ⊢

/-- A whole record the engine writes is read back as its body and its link. -/
theorem unwrap_full {α : Type} {c : RecCodec α} {x : α} {l : Link} {b : Bytes} (hw : width c.L = bodyBytes)
    (h : encFull (full c x l) = some b) : unwrap b = some (c.enc x, l) ∧ c.WF x := by
  obtain ⟨hf, hk, rfl⟩ := encFull_spec h
  simp only [full] at hf hk ⊢
  obtain ⟨cs1, cs2, he, h1, h2⟩ := fit_split c.L linkL _ hf
  obtain ⟨rfl, rfl⟩ := List.append_inj' he (by rw [fit_linkL h2]; rfl)
  refine ⟨?_, h1, hk⟩
  have hl1 : (encF c.L (c.toC x)).length = bodyBytes := by rw [encF_length _ _ h1, hw]
  have hl2 : (encF linkL l.cells).length = width linkL := encF_length _ _ h2
  unfold unwrap
  rw [encF_append _ _ _ _ h1, if_pos (by rw [List.length_append, hl1, hl2]; exact record_width),
    List.take_left' hl1, List.drop_left' hl1, decExact_enc _ _ h2]
  cases l
  rfl

theorem texts_run {rec : Nat → Option Bytes} {n : Nat} : ∀ (ts : List TextRec) (a c : Nat) (acc : Array TextRec)
    (bs : List Bytes), encAll (linkTexts ts a c) = some bs → (∀ j (h : j < bs.length), rec (a + j) = some bs[j]) →
    a + ts.length ≤ n → (a + ts.length < n → ∀ b l, rd rec (a + ts.length) = some (b, l) → tagOf b ≠ 0xF5) →
    texts rec n a c acc = .ok (⟨acc.toList ++ ts⟩, a + ts.length)
  | [], a, c, acc, _, _, _, _, hend => by
    unfold texts
    split
    · rename_i ha
      have hs := hend (by simpa using ha)
      simp only [List.length_nil, Nat.add_zero] at hs
      split
      · rename_i b l hr
        simp [hs b l hr] <;> rfl
      · simp <;> rfl
    · simp <;> rfl
  | t :: ts, a, c, acc, bs, hbs, hrec, hn, hend => by
    simp only [linkTexts, encAll] at hbs
    split at hbs
    · rename_i b bs' hb hbs'
      cases hbs
      obtain ⟨hu, hwf⟩ := unwrap_full (c := textC) textC_ok.2 hb
      have hr : rd rec a = some (textC.enc t, ⟨a, nextCount c⟩) := by
        have h0 := hrec 0 (by simp)
        simp only [Nat.add_zero, List.getElem_cons_zero] at h0
        simp [rd, h0, hu]
      have htag : tagOf (textC.enc t) = 0xF5 := by
        simp [tagOf, RecCodec.enc, textC, encF, leBytes]
      have hlen : a + (t :: ts).length = a + 1 + ts.length := by simp; omega
      have hrest := texts_run (rec := rec) (n := n) ts (a + 1) (c + 1) (acc.push t) bs' hbs'
        (fun j hj => by
          rw [show a + 1 + j = a + (j + 1) by omega]
          have := hrec (j + 1) (by simpa using hj)
          rwa [List.getElem_cons_succ] at this)
        (by omega)
        (fun h b l => by
          have := hend (by omega) b l
          rwa [hlen] at this)
      unfold texts
      rw [dif_pos (by omega), hr]
      simp only [htag, if_true, RecCodec.dec_enc textC_ok.1 hwf, get, need, pure_bind,
        beq_self_eq_true, if_true]
      rw [hrest, show a + 1 + ts.length = a + (t :: ts).length by omega]
      simp
    · cases hbs

/-- The checker reads back, from the records alone, every element the engine writes as text records. -/
theorem element_rebuild {rec : Nat → Option Bytes} {n a c : Nat} {e : Bytes} {bs : List Bytes} (he : 1 ≤ e.length)
    (hbs : encAll (textsAt e a c) = some bs) (hrec : ∀ j (h : j < bs.length), rec (a + j) = some bs[j])
    (hn : a + bs.length ≤ n)
    (hend : a + bs.length < n → ∀ b l, rd rec (a + bs.length) = some (b, l) → tagOf b ≠ 0xF5) :
    element rec n a c = .ok (e, a + bs.length) := by
  have hne : e.isEmpty = false := by cases e <;> simp_all
  unfold textsAt at hbs
  simp only [hne, Bool.false_eq_true, ↓reduceIte] at hbs
  have hl : bs.length = (partsFrom 0 e).length := by rw [encAll_length hbs, linkTexts_length]
  rw [hl] at hn hend ⊢
  unfold element
  rw [texts_run _ a c #[] bs hbs hrec hn hend]
  simp [bind, Except.bind, get, join_parts 0 e he] <;> rfl

/-- An opening's element decodes to the input the engine applied: the engine admits an opening only when its input
    is well formed and within the encoded size. -/
theorem opening_rebuild {i : BlindLedger.Financial.FinancialInput}
    (hw : BlindLedger.Financial.financialInputWellFormed i = true)
    (hl : (BlindLedger.Financial.rawEncodeFinancialInput i).length ≤ BlindLedger.Financial.maxTotalEncodedBytes) :
    decodeFinancialInput (BlindLedger.Financial.rawEncodeFinancialInput i) = some i :=
  BlindLedger.Financial.decodeFinancialInput_rawEncode i (BlindLedger.Financial.Payment.inputWire_of_wellFormed hw hl)

/-! ### A payment's element decodes to its command

    The round trip of `readCommand` is proved in the payment codec laws, but privately there; it is proved again
    here from the same public laws of the field readers. -/

section CommandRebuild
open BlindLedger.Financial BlindLedger.Financial.Payment

local macro "rstep " h:term : tactic => `(tactic| (refine bind_step $h ?_; try dsimp only))

private theorem optNonEmptyWire {o : Option String} (h : (nonEmpty o).all idWellFormed = true) :
    optionStringWireAdmissible o := by
  cases o with
  | none => trivial
  | some v =>
    by_cases hv : v = ""
    · subst hv
      apply CorrectionTransition.stringWireAdmissible_of_length
      have := CorrectionTransition.string_utf8_length_le ""
      have h0 : "".toList.length = 0 := rfl
      omega
    · exact idWire (by simpa [nonEmpty, hv] using h)

private theorem optAllWire {o : Option String} (h : o.all idWellFormed = true) : optionStringWireAdmissible o := by
  cases o with
  | none => trivial
  | some v => exact idWire h

private theorem opt63Wire {o : Option Nat} (h : o.all (· < 2 ^ 63) = true) : optionNatWireAdmissible o := by
  cases o with
  | none => trivial
  | some v => exact Nat.lt_of_lt_of_le (of_decide_eq_true h) (by decide)

/-- A payment's element decodes to the command the engine applied, with nothing after it: the engine admits a
    payment only when its command is well formed. -/
theorem command_rebuild (c : Command) (h : commandWellFormed c = true) :
    readCommand (encodeCommand c) = some (c, []) := by
  have key : readCommand (encodeCommand c ++ []) = some (c, []) := by
    unfold commandWellFormed at h
    cases c with
    | record c =>
      simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
      obtain ⟨hI, hL, hP, hAmt, hTime⟩ := h
      unfold encodeCommand readCommand
      simp only [List.cons_append, List.append_assoc]
      rstep rfl
      rw [if_pos (by decide)]
      rstep (readString_encodeString_append _ _ (idWire (hI _ (by simp))))
      rstep (readString_encodeString_append _ _ (idWire (hI _ (by simp))))
      rstep (readString_encodeString_append _ _ (idWire (hI _ (by simp))))
      rstep (readString_encodeString_append _ _ (idWire (hI _ (by simp))))
      rstep (readString_encodeString_append _ _ (idWire (hI _ (by simp))))
      rstep (readOptionString_encodeOptionString_append _ _ (optNonEmptyWire hL))
      rstep (readNat8_natBE_append _ _ (cents8 hAmt))
      rstep (readNat8_natBE_append _ _ (Nat.lt_of_lt_of_le hTime (by decide)))
      rstep (readOptionString_encodeOptionString_append _ _ (optAllWire hP))
      rfl
    | reverse c =>
      simp only [Bool.and_eq_true, and_assoc] at h
      obtain ⟨hP, hE, hO, hT⟩ := h
      unfold encodeCommand readCommand
      simp only [List.cons_append, List.append_assoc]
      rstep rfl
      rw [if_neg (by decide), if_pos (by decide)]
      rstep (readString_encodeString_append _ _ (idWire hP))
      rstep (readString_encodeString_append _ _ (idWire hE))
      rstep (readOptionString_encodeOptionString_append _ _ (optNonEmptyWire hO))
      rstep (readOptionNat_encodeOptionNat_append _ _ (opt63Wire hT))
      rfl
  simpa using key

end CommandRebuild

/-! ## The whole log

    Two statements about every log; the proofs above are their per-record parts.  `AcceptedLogLoads` is proved in
    `CheckedLog.lean`, `EngineLogChecks` in `EngineLogProof.lean`. -/

/-- The log after the engine applies commands in order to an empty shard, with the store it leaves. -/
def logOf (card : Card) (reg : Array Nat) (cmds : List Cmd) : Store × List Bytes :=
  cmds.foldl (fun (s, log) c =>
    let r := apply s (fun i => log[i]?) c
    (r.2.2, log ++ r.2.1)) (Store.empty card reg, [])

/-- The checker accepts every log the engine writes from commands that state what every command of this step
    states.  Proved: `engine_log_checks`. -/
def EngineLogChecks : Prop :=
  ∀ (card : Card) (reg : Array Nat) (cmds : List Cmd),
    (∀ c ∈ cmds, c.actor = zeros 32 ∧ c.role = 0 ∧ c.attr = 2 ∧ c.src = stepSource) →
    (checkLog (fun i => (logOf card reg cmds).2[i]?) (spanDig fun i => (logOf card reg cmds).2[i]?)
      (logOf card reg cmds).2.length).err = none

/-- In a log the checker accepts, the engine rebuilds an obligation (`loadObl`) from every state row that is the
    newest row of its obligation in the log, so no command on that obligation is answered `STORE_READ`.  It says
    nothing of the engine's table: that the table's entry for an obligation is its newest row is a fact about the
    logs the engine writes, not about every accepted log.  Proved: `accepted_log_loads`. -/
def AcceptedLogLoads : Prop :=
  ∀ (log : List Bytes), (checkLog (fun i => log[i]?) (spanDig fun i => log[i]?) log.length).err = none →
    ∀ (i : Nat) (row : StateRow) (l : Link), rd (fun i => log[i]?) i = some (stateC.enc row, l) →
      (∀ (j : Nat) (row' : StateRow) (l' : Link), i < j → rd (fun i => log[i]?) j = some (stateC.enc row', l') →
        row'.ob ≠ row.ob) →
      ((loadObl row.ob i).run fun i => log[i]?).1.isSome = true

end BlindLedger.Gate.Obligations
