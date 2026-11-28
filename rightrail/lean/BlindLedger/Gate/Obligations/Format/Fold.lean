import BlindLedger.Gate.Obligations.Format.Records
import BlindLedger.Gate.Obligations.Format.Fast
import BlindLedger.Sha3Quick

namespace BlindLedger.Gate.Obligations.Format

open BlindLedger.Gate.FactCodec

/-! `foldOf`: what the fold record (tag `0x65`, design `one-store` §16.3) holds, defined once as a function of the
    obligation's records in record order, each with what its element gives.  The engine keeps the record up to date
    one command at a time; the checker computes `foldOf`; `conformance/OBLIGATIONS_V1.md` publishes this definition.

    An element is the command's stored copy in the frame's request, found by the command record's `wbatch` and
    `windex`.  The fold reads from it only identifiers, which no record holds: evidence ids, payment and determination
    ids, and action ids.  Everything else comes from the records.  A record's evidence id counts whatever its body;
    a body that does not decode adds nothing else.  The store holds no such body, but the definition does not rely
    on that.

    Cost: one pass over the records, one `H` per evidence item, and a sort of the active contributions.  This is the
    definition, not the engine's path: the engine moves the record in O(1) for the common cases (§16.3), except that
    a statement or an action key it has seen before needs a lookup in the obligation's history (`asserted`,
    `created`), which the record does not hold. -/

/-- A domain tag (`domEvalFix`, `domEvidAcc`) and a zero byte, as every digest of the design. -/
def dom (d : String) : Bytes := d.toUTF8.toList ++ [0]

/-- `H` is SHA3-512. -/
def H (b : Bytes) : Bytes := (BlindLedger.Semantic.sha3_512Quick ⟨b.toArray⟩).toList

/-- A field with its two-byte little-endian length. -/
def lp16 (x : Bytes) : Bytes := leBytes 2 x.length ++ x

/-- The fields of the evaluation result that no command after the opening can change: the scope's five fields, the
    item id and the obligation id, as the opening's element gives them.  Each is part of the obligation's identity:
    the scope and the item make `ob` (§2.2), and the owner derives the obligation id from the item and the period, so
    a command that named other values would name another obligation.  Every other field of the result is in the
    evaluation reference's per-evaluation part; `conformance/OBLIGATIONS_V1.md` gives the reason for each. -/
structure Opening where
  stateId : Bytes
  deploymentId : Bytes
  programId : Bytes
  periodId : Bytes
  currency : Bytes
  itemId : Bytes
  obligationId : Bytes
  deriving DecidableEq, Repr

/-- `cref`: `H(dom EVALFIX ‖ lp16 of each fixed field, in the order above)`. -/
def crefOf (o : Opening) : Bytes :=
  H (dom domEvalFix ++ lp16 o.stateId ++ lp16 o.deploymentId ++ lp16 o.programId ++ lp16 o.periodId ++
    lp16 o.currency ++ lp16 o.itemId ++ lp16 o.obligationId)

/-- What a record's element gives the fold. -/
structure Elem where
  /-- The evidence id, when the record is an evidence item. -/
  evidence : Option Bytes := none
  /-- The payment id of a CASH row that states a payment, or the determination id of an offset authorization's
      CREATE record. -/
  contribution : Option Bytes := none
  /-- The action id of an action's CREATE record. -/
  action : Option Bytes := none
  deriving DecidableEq, Repr

/-- One record of the obligation: its number in the `facts` file, its body, and what its element gives. -/
structure Rec where
  no : Nat
  body : Bytes
  elem : Elem := {}
  deriving DecidableEq, Repr

/-- An active contribution: a payment in force or an authorized offset.  `sid` is a payment's CASH statement and
    `pays` the action key it pays (zero for none); both are empty for an offset. -/
structure Contrib where
  ms : Nat
  cents : Nat
  id : Bytes
  no : Nat
  sid : Bytes
  pays : Bytes
  deriving DecidableEq, Repr

/-- `a` sorts before `b`, byte by byte.  Owner identifiers are ASCII, so this is the rules' order of their text. -/
def bytesLt : Bytes → Bytes → Bool
  | [], _ :: _ => true
  | x :: xs, y :: ys => x < y || (x == y && bytesLt xs ys)
  | _, _ => false

/-- The rules' contribution order (`contributionKeyBefore`): time, then amount, then identity. -/
def Contrib.before (a b : Contrib) : Bool :=
  a.ms < b.ms || (a.ms == b.ms && (a.cents < b.cents || (a.cents == b.cents && bytesLt a.id b.id)))

/-- The rules' insertion sort (`evalSortContributions`). -/
def insertC (c : Contrib) : List Contrib → List Contrib
  | [] => [c]
  | d :: ds => if c.before d then c :: d :: ds else d :: insertC c ds

def sortC (cs : List Contrib) : List Contrib := cs.foldr insertC []

/-- The rules' latest action (`evalLatestAction`): of two actions the one with the later created time, and at an
    equal time the greater action id; of two equal keys the rules keep the later in order, and so does this. -/
def laterAction : Option (Nat × Bytes × Nat) → Nat × Bytes × Nat → Option (Nat × Bytes × Nat)
  | none, n => some n
  | some c, n => if n.1 < c.1 || (n.1 == c.1 && bytesLt n.2.1 c.2.1) then some c else some n

structure FoldAcc where
  eacc : Bytes
  ecount : Nat
  active : List Contrib
  /-- Open correction requests: the action key and the amount asked. -/
  requests : List (Bytes × Nat)
  owed : Nat
  /-- The latest action: its created time, its id and its CREATE record. -/
  amax : Option (Nat × Bytes × Nat)
  /-- The CASH statements that gave a payment or were voided: each is used once, and never returns. -/
  asserted : List Bytes
  /-- The action keys that have had a CREATE record, cancelled or not. -/
  created : List Bytes
  /-- A readable state row has been read. -/
  stated : Bool
  /-- An identifier of 65,536 bytes or more has been read: its length does not fit `lp16`. -/
  long : Bool

def foldStart : FoldAcc := ⟨zeros 64, 0, [], [], 0, none, [], [], false, false⟩

/-- The longest identifier `lp16` holds is 65,535 bytes. -/
def Elem.long (e : Elem) : Bool :=
  [e.evidence, e.contribution, e.action].any fun i => 65536 ≤ (i.map (·.length)).getD 0

/-- One record:
    * an evidence item chains its id into `eacc`;
    * a state row sets the owed amount;
    * a CASH void (`op` 1, the payment's reversal) removes the payment of its statement and uses the statement; any
      other CASH row with a payment id adds the payment, unless its statement was used, by a payment or a void, when
      it moves nothing (a statement is one payment, and a reversed one never comes back; a CASH row with `op` 2
      does not decode);
    * an action's CREATE record, the first of its key, competes for the latest action, by its created time; with offset authorization's
      kind and a determination id it adds the offset at the determination's time (`decidedMs`, the rules'
      `decidedAt`); with the correction request's kind it opens a request;
    * a later CREATE record of the same key moves nothing, also after its CANCEL;
    * an action's CANCEL record closes its request; an offset stays, as the rules count every authorized offset. -/
def foldStep (a : FoldAcc) (r : Rec) : FoldAcc :=
  let a := { a with long := a.long || r.elem.long }
  let a := match r.elem.evidence with
    | some e => { a with eacc := H (dom domEvidAcc ++ a.eacc ++ lp16 e), ecount := a.ecount + 1 }
    | none => a
  match r.body.head? with
  | none => a
  | some t =>
    if t.toNat = tagState then
      match stateC.dec r.body with
      | some s => { a with owed := s.owed, stated := true }
      | none => a
    else if t.toNat = tagCash then
      match cashC.dec r.body with
      | some c =>
        if c.h.op = opVoid then
          { a with active := a.active.filter (·.sid != c.h.sid), asserted := c.h.sid :: a.asserted }
        else match r.elem.contribution with
          | some pid =>
            if a.asserted.contains c.h.sid then a
            else { a with active := a.active ++ [⟨c.eventMs, c.amount, pid, r.no, c.h.sid, c.pays⟩],
                          asserted := c.h.sid :: a.asserted }
          | none => a
      | none => a
    else if t.toNat = tagAction then
      match actionC.dec r.body with
      | some x =>
        if x.op = actCreate && a.created.contains x.ak then a
        else if x.op = actCreate then
          let a := { a with created := x.ak :: a.created }
          let a := match r.elem.action with
            | some aid => { a with amax := laterAction a.amax (x.atMs, aid, r.no) }
            | none => a
          if x.akind = akindOffset then
            match r.elem.contribution with
            | some did => { a with active := a.active ++ [⟨x.decidedMs, x.amount, did, r.no, [], []⟩] }
            | none => a
          else if x.akind = akindRequest then { a with requests := a.requests ++ [(x.ak, x.amount)] }
          else a
        else if x.op = actCancel then { a with requests := a.requests.filter (·.1 != x.ak) }
        else a
      | none => a
    else a

/-- The first contribution, in sorted order, at which the running sum reaches `owed`. -/
def completion (owed : Nat) : Nat → List Contrib → Option Contrib
  | _, [] => none
  | total, c :: cs => if owed ≤ total + c.cents then some c else completion owed (total + c.cents) cs

/-- The sum of the active contributions: the rules add with a checked sum, so every running sum of them is at most
    this one. -/
def activeSum (active : List Contrib) : Nat := active.foldl (fun s c => s + c.cents) 0

/-- The cash in force that pays the request with action key `ak`. -/
def paidTo (active : List Contrib) (ak : Bytes) : Nat :=
  (active.filter (·.pays == ak)).foldl (fun s c => s + c.cents) 0

/-- The fold has no record: an identifier does not fit `lp16`, or the active contributions add up to `bound` or more. -/
def noFold (o : Opening) (a : FoldAcc) : Bool :=
  a.long || bound ≤ activeSum a.active ||
    [o.stateId, o.deploymentId, o.programId, o.periodId, o.currency, o.itemId, o.obligationId].any (65536 ≤ ·.length)

/-- The fields of the fold record of an obligation opened with `o`, after its records `rs` in record order, before
    the check that they fit.  A record link is the record's number plus one; a field that names no record is zero
    with its time and amount.  When `noFold` holds, `reqsum` is `bound`, a value the guarded writer refuses, so that
    `foldOf` and the writer agree; with no readable state row there is no `done`. -/
def foldFields (o : Opening) (rs : List Rec) : FoldRec :=
  let a := rs.foldl foldStep foldStart
  let sorted := sortC a.active
  let last := sorted.getLast?
  let done := if a.stated then completion a.owed 0 sorted else none
  { cref := crefOf o
    eacc := a.eacc
    ecount := a.ecount
    ccount := a.active.length
    cmaxMs := (last.map (·.ms)).getD 0
    cmaxCents := (last.map (·.cents)).getD 0
    cmax := (last.map (·.no + 1)).getD 0
    doneMs := (done.map (·.ms)).getD 0
    done := (done.map (·.no + 1)).getD 0
    reqsum := if noFold o a then bound else a.requests.foldl (fun s r => s + (r.2 - paidTo a.active r.1)) 0
    amaxMs := (a.amax.map (·.1)).getD 0
    amax := (a.amax.map (·.2.2 + 1)).getD 0 }

/-- The fold record: `none` when a field does not fit, that is, when the guarded writer refuses it.  Every record's
    amounts and times are below `bound`, so only a total can reach it: the open requests less their cash, or the
    active contributions; and an identifier too long for `lp16` is no fold either (`noFold`). -/
def foldOf (o : Opening) (rs : List Rec) : Option FoldRec :=
  if (foldC.write (foldFields o rs)).isSome then some (foldFields o rs) else none

/-- A repeated CASH statement moves nothing: once its statement has given a payment or been voided, a CASH row that
    is not a void leaves the active contributions as they were. -/
theorem foldStep_cash_repeat (a : FoldAcc) (r : Rec) (c : CashF) (pid : Bytes) (t : UInt8)
    (hh : r.body.head? = some t) (ht : t.toNat = tagCash) (hc : cashC.dec r.body = some c)
    (hop : c.h.op ≠ opVoid) (hp : r.elem.contribution = some pid)
    (hin : a.asserted.contains c.h.sid = true) : (foldStep a r).active = a.active := by
  have h3 : tagCash ≠ tagState := by decide
  have hin' : c.h.sid ∈ a.asserted := by simpa using hin
  unfold foldStep
  rcases hev : r.elem.evidence with _ | e <;> simp [hev, hh, ht, hc, hop, hp, hin', h3]

/-- `foldOf` gives exactly the fields of `foldFields` when the guarded writer writes them, and nothing otherwise. -/
theorem foldOf_iff {o : Opening} {rs : List Rec} {f : FoldRec} :
    foldOf o rs = some f ↔ f = foldFields o rs ∧ (foldC.write f).isSome = true := by
  unfold foldOf
  by_cases hs : (foldC.write (foldFields o rs)).isSome = true
  · rw [if_pos hs]
    constructor
    · intro h
      cases h
      exact ⟨rfl, hs⟩
    · rintro ⟨rfl, _⟩
      rfl
  · rw [if_neg hs]
    constructor
    · intro h
      cases h
    · rintro ⟨rfl, h2⟩
      exact absurd h2 hs

/-- A fold record `foldOf` gives is one the guarded writer writes. -/
theorem foldOf_writes {o : Opening} {rs : List Rec} {f : FoldRec} (h : foldOf o rs = some f) :
    (foldC.write f).isSome = true := (foldOf_iff.mp h).2

/-- A statement once used is used for good: no record takes a statement out of `asserted`, whether it is a void or a
    payment. -/
theorem foldStep_asserted_mono (a : FoldAcc) (r : Rec) {s : Bytes} (hs : s ∈ a.asserted) :
    s ∈ (foldStep a r).asserted := by
  unfold foldStep
  repeat' split
  all_goals (try simp_all)
  all_goals (repeat' split)
  all_goals simp_all

/-- A statement not used before, in a CASH row of `op` 0 with a payment id, adds its payment. -/
theorem foldStep_cash_new (a : FoldAcc) (r : Rec) (c : CashF) (pid : Bytes) (t : UInt8)
    (hh : r.body.head? = some t) (ht : t.toNat = tagCash) (hc : cashC.dec r.body = some c)
    (hop : c.h.op = 0) (hp : r.elem.contribution = some pid)
    (hnew : a.asserted.contains c.h.sid = false) :
    (foldStep a r).active = a.active ++ [⟨c.eventMs, c.amount, pid, r.no, c.h.sid, c.pays⟩] := by
  have h3 : tagCash ≠ tagState := by decide
  have hv : c.h.op ≠ opVoid := by simp [hop, opVoid]
  have hnew' : c.h.sid ∉ a.asserted := by simpa using hnew
  unfold foldStep
  rcases hev : r.elem.evidence with _ | e <;> simp [hev, hh, ht, hc, hv, hp, hnew', h3]

/-- A repeated CREATE record of an action key moves nothing, also after its CANCEL: a cancelled request does not come
    back, and an offset does not count twice. -/
theorem foldStep_create_repeat (a : FoldAcc) (r : Rec) (x : ActionRec) (t : UInt8)
    (hh : r.body.head? = some t) (ht : t.toNat = tagAction) (hd : actionC.dec r.body = some x)
    (hop : x.op = actCreate) (hin : a.created.contains x.ak = true) :
    (foldStep a r).active = a.active ∧ (foldStep a r).requests = a.requests ∧ (foldStep a r).amax = a.amax := by
  have h3 : tagAction ≠ tagState := by decide
  have h4 : tagAction ≠ tagCash := by decide
  have hin' : x.ak ∈ a.created := by simpa using hin
  unfold foldStep
  rcases hev : r.elem.evidence with _ | e <;> simp [hev, hh, ht, hd, hop, hin', h3, h4]

/-- The fold record's bytes, through the guarded writer. -/
def foldWrite (o : Opening) (rs : List Rec) : Option ByteArray := (foldOf o rs).bind foldC.write

/-! ## Examples

    Each example is an obligation's records with what their elements give, and the fold record `foldOf` makes; the
    vectors of `conformance/OBLIGATIONS_V1.md` carry the same records, so a second reader can compute the same
    records.  `main` owes 400,000: two payments, an offset authorized at an earlier time than its action was created,
    a correction request at the offset's created time with a smaller action id, cash that pays the request, and the
    reversal of the second payment.  The others each show one case: a reversal with a total short of the amount owed,
    refused bodies, cancels, the request floor, and the reversal of a request's cash. -/

def exOpening : Opening :=
  ⟨"ST".toUTF8.toList, "dep-1".toUTF8.toList, "prog-1".toUTF8.toList, "2026-01".toUTF8.toList,
    "USD".toUTF8.toList, "item-1".toUTF8.toList, "obl-item-1-2026-01".toUTF8.toList⟩

def exT : Nat := 1767225600000

def exState (owed : Nat) : Bytes := stateC.enc { sampleState with owed := owed }

def exCash (sid pays : Bytes) (op amount ms : Nat) : Bytes :=
  cashC.enc { sampleCash with
    h := { sampleCash.h with op := op, sid := sid }, amount := amount, eventMs := ms, pays := pays }

/-- An action record; a CANCEL record has status CANCELLED.  The model writer `enc` writes whatever it is given,
    so the `refused` example uses it for bodies that are not well formed. -/
def exAction (op akind amount ms dms : Nat) (ak : Bytes) : Bytes :=
  actionC.enc { sampleAction with
    op := op, akind := akind, amount := amount, atMs := ms, decidedMs := dms, ak := ak,
    status := if op = actCancel then 3 else 1 }

def u (s : String) : Option Bytes := some s.toUTF8.toList

def exRecs : List Rec := [
  ⟨0, exState 400000, {}⟩,
  ⟨3, exCash (pat 32 50) (zeros 32) 0 300000 (exT + 1000), ⟨u "ev-1", u "pay-1", none⟩⟩,
  ⟨5, exCash (pat 32 51) (zeros 32) 0 250000 exT, ⟨u "ev-2", u "pay-2", none⟩⟩,
  ⟨7, exAction actCreate akindOffset 100000 (exT + 2000) (exT + 500) (pat 32 60), ⟨none, u "det-1", u "act-1"⟩⟩,
  ⟨9, exAction actCreate akindRequest 80000 (exT + 2000) (exT + 2000) (pat 32 61), ⟨none, none, u "act-0"⟩⟩,
  ⟨11, exCash (pat 32 52) (pat 32 61) 0 30000 (exT + 3000), ⟨u "ev-3", u "pay-3", none⟩⟩,
  ⟨13, exCash (pat 32 51) (zeros 32) opVoid 250000 exT, ⟨u "ev-4", none, none⟩⟩,
  ⟨15, exState 400000, {}⟩]

def exFold : FoldRec := foldFields exOpening exRecs

-- det-1 counts at its decision time, before pay-1: the two reach 400,000 at pay-1 (record 3).  pay-2 is reversed;
-- the request asks 80,000 and 30,000 pays it; act-1 stays the latest action, its id being greater at the same time.
#guard exFold.ecount == 4 && exFold.ccount == 3
#guard exFold.cmax == 12 && exFold.cmaxMs == exT + 3000 && exFold.cmaxCents == 30000
#guard exFold.done == 4 && exFold.doneMs == exT + 1000
#guard exFold.reqsum == 50000 && exFold.amax == 8 && exFold.amaxMs == exT + 2000
#guard foldC.dec (foldC.enc exFold) == some exFold && foldOf exOpening exRecs == some exFold
#guard (foldFields exOpening []).eacc == zeros 64 && (foldOf exOpening []).isSome

/-- A reversal (`op` 1) removes its payment, and what is left never reaches the amount owed: `done` is 0. -/
def exVoid : List Rec := [
  ⟨0, exState 120000, {}⟩,
  ⟨1, exCash (pat 32 70) (zeros 32) 0 100000 exT, ⟨u "ev-a", u "pay-a", none⟩⟩,
  ⟨2, exCash (pat 32 71) (zeros 32) 0 50000 (exT + 1), ⟨u "ev-b", u "pay-b", none⟩⟩,
  ⟨3, exCash (pat 32 71) (zeros 32) opVoid 50000 (exT + 1), ⟨u "ev-c", none, none⟩⟩]

#guard (foldFields exOpening exVoid).ecount == 3 && (foldFields exOpening exVoid).ccount == 1
#guard (foldFields exOpening exVoid).cmax == 2 && (foldFields exOpening exVoid).cmaxCents == 100000
#guard (foldFields exOpening exVoid).done == 0 && (foldFields exOpening exVoid).doneMs == 0

/-- Refused bodies: a CASH row with `op` 2 does not end the payment of its statement and adds no payment, an offset
    decided after its action was created adds no offset and is not an action, and a state row with verification 0
    does not set the amount owed.  Only the evidence ids count. -/
def exRefused : List Rec := [
  ⟨0, exState 100000, {}⟩,
  ⟨1, exCash (pat 32 80) (zeros 32) 0 100000 exT, ⟨u "ev-a", u "pay-a", none⟩⟩,
  ⟨2, exCash (pat 32 80) (zeros 32) opEnd 100000 exT, ⟨u "ev-b", u "pay-b", none⟩⟩,
  ⟨3, exAction actCreate akindOffset 50000 exT (exT + 1) (pat 32 81), ⟨none, u "det-z", u "act-z"⟩⟩,
  ⟨4, stateC.enc { sampleState with owed := 1, verification := 0 }, {}⟩]

#guard (exRefused.drop 2).all fun r =>
  (stateC.dec r.body).isNone && (cashC.dec r.body).isNone && (actionC.dec r.body).isNone
#guard (foldFields exOpening exRefused).ecount == 2 && (foldFields exOpening exRefused).ccount == 1
#guard (foldFields exOpening exRefused).done == 2 && (foldFields exOpening exRefused).doneMs == exT
#guard (foldFields exOpening exRefused).amax == 0 && (foldFields exOpening exRefused).amaxMs == 0

/-- A CANCEL closes its correction request; the cancel of an offset authorization leaves the offset. -/
def exCancel : List Rec := [
  ⟨0, exState 50000, {}⟩,
  ⟨1, exAction actCreate akindRequest 80000 exT exT (pat 32 90), ⟨none, none, u "act-r"⟩⟩,
  ⟨2, exAction actCancel akindRequest 80000 (exT + 10) exT (pat 32 90), {}⟩,
  ⟨3, exAction actCreate akindOffset 50000 (exT + 20) (exT + 5) (pat 32 91), ⟨none, u "det-o", u "act-o"⟩⟩,
  ⟨4, exAction actCancel akindOffset 50000 (exT + 30) (exT + 5) (pat 32 91), {}⟩]

#guard (foldFields exOpening exCancel).reqsum == 0 && (foldFields exOpening exCancel).ccount == 1
#guard (foldFields exOpening exCancel).done == 4 && (foldFields exOpening exCancel).doneMs == exT + 5
#guard (foldFields exOpening exCancel).amax == 4 && (foldFields exOpening exCancel).amaxMs == exT + 20

/-- The request floor: cash beyond what a request asks leaves it at 0 and does not reduce another request. -/
def exFloor : List Rec := [
  ⟨0, exState 1000000, {}⟩,
  ⟨1, exAction actCreate akindRequest 20000 exT exT (pat 32 100), ⟨none, none, u "act-p"⟩⟩,
  ⟨2, exAction actCreate akindRequest 30000 (exT + 1) exT (pat 32 101), ⟨none, none, u "act-q"⟩⟩,
  ⟨3, exCash (pat 32 102) (pat 32 100) 0 30000 (exT + 2), ⟨u "ev-a", u "pay-a", none⟩⟩,
  ⟨4, exCash (pat 32 103) (pat 32 100) 0 20000 (exT + 3), ⟨u "ev-b", u "pay-b", none⟩⟩]

#guard (foldFields exOpening exFloor).reqsum == 30000 && (foldFields exOpening exFloor).done == 0
#guard (foldFields exOpening exFloor).amax == 3 && (foldFields exOpening exFloor).amaxMs == exT + 1

/-- The reversal of the cash that paid a request opens the request's amount again. -/
def exReqVoid : List Rec := [
  ⟨0, exState 40000, {}⟩,
  ⟨1, exAction actCreate akindRequest 40000 exT exT (pat 32 110), ⟨none, none, u "act-v"⟩⟩,
  ⟨2, exCash (pat 32 111) (pat 32 110) 0 40000 (exT + 1), ⟨u "ev-a", u "pay-a", none⟩⟩,
  ⟨3, exCash (pat 32 111) (pat 32 110) opVoid 40000 (exT + 1), ⟨u "ev-b", none, none⟩⟩]

#guard (foldFields exOpening (exReqVoid.take 3)).reqsum == 0
#guard (foldFields exOpening exReqVoid).reqsum == 40000 && (foldFields exOpening exReqVoid).ccount == 0
#guard (foldFields exOpening exReqVoid).cmax == 0 && (foldFields exOpening exReqVoid).done == 0

/-- A CASH statement repeated: a second op-0 row with the same `sid` moves no amount and adds no count, so the fold is
    the single row's.  The repeat comes without an evidence id, which would count by itself. -/
def exDupSid : List Rec := [
  ⟨0, exState 100000, {}⟩,
  ⟨1, exCash (pat 32 130) (zeros 32) 0 60000 exT, ⟨u "ev-a", u "pay-a", none⟩⟩,
  ⟨2, exCash (pat 32 130) (zeros 32) 0 60000 exT, ⟨none, u "pay-b", none⟩⟩]

#guard foldOf exOpening exDupSid == foldOf exOpening (exDupSid.take 2) && (foldOf exOpening exDupSid).isSome
#guard (foldFields exOpening exDupSid).ccount == 1 && (foldFields exOpening exDupSid).cmax == 2

/-- A reversed statement does not come back: the same `sid` asserted again after its void, with a payment element,
    adds nothing, so the obligation is not done. -/
def exReassert : List Rec := [
  ⟨0, exState 100000, {}⟩,
  ⟨1, exCash (pat 32 131) (zeros 32) 0 100000 exT, ⟨u "ev-a", u "pay-a", none⟩⟩,
  ⟨2, exCash (pat 32 131) (zeros 32) opVoid 100000 exT, ⟨u "ev-b", none, none⟩⟩,
  ⟨3, exCash (pat 32 131) (zeros 32) 0 100000 (exT + 1), ⟨u "ev-c", u "pay-b", none⟩⟩]

#guard (foldOf exOpening exReassert).isSome && (foldFields exOpening exReassert).ccount == 0
#guard (foldFields exOpening exReassert).done == 0 && (foldFields exOpening exReassert).ecount == 3

/-- The rules' bound: an amount of 2^63 is refused with its record, so the request and the payment add nothing, and
    one of 2^63 - 1 is counted. -/
def exBig : List Rec := [
  ⟨0, exState 100000, {}⟩,
  ⟨1, exAction actCreate akindRequest (2 ^ 63) exT exT (pat 32 140), ⟨none, none, u "act-a"⟩⟩,
  ⟨2, exCash (pat 32 141) (zeros 32) 0 (2 ^ 63) exT, ⟨u "ev-a", u "pay-a", none⟩⟩,
  ⟨3, exAction actCreate akindRequest (2 ^ 63 - 1) exT exT (pat 32 142), ⟨none, none, u "act-b"⟩⟩]

#guard (foldFields exOpening exBig).reqsum == 2 ^ 63 - 1 && (foldFields exOpening exBig).ccount == 0
#guard (foldFields exOpening exBig).amax == 4

/-- Two requests of 2^63 - 1: the total does not fit the rules' bound, so there is no fold record. -/
def exOverflow : List Rec := [
  ⟨0, exState 100000, {}⟩,
  ⟨1, exAction actCreate akindRequest (2 ^ 63 - 1) exT exT (pat 32 150), ⟨none, none, u "act-a"⟩⟩,
  ⟨2, exAction actCreate akindRequest (2 ^ 63 - 1) exT exT (pat 32 151), ⟨none, none, u "act-b"⟩⟩]

-- 2 ^ 64 - 2 fits the field and not the bound; the guarded writer and `foldOf` refuse it, and no number is wrapped.
#guard (foldFields exOpening exOverflow).reqsum == 2 ^ 64 - 2 && foldOf exOpening exOverflow == none
#guard foldWrite exOpening exOverflow == none && (foldWrite exOpening exBig).isSome

/-- A void is a use: the statement of a void seen first is asserted for good, so the payment that comes after it
    adds nothing. -/
def exVoidFirst : List Rec := [
  ⟨0, exState 100000, {}⟩,
  ⟨1, exCash (pat 32 160) (zeros 32) opVoid 100000 exT, ⟨u "ev-a", none, none⟩⟩,
  ⟨2, exCash (pat 32 160) (zeros 32) 0 100000 exT, ⟨u "ev-b", u "pay-a", none⟩⟩]

#guard (foldOf exOpening exVoidFirst).isSome && (foldFields exOpening exVoidFirst).ccount == 0
#guard (foldFields exOpening exVoidFirst).done == 0 && (foldFields exOpening exVoidFirst).ecount == 2

/-- An action key creates once: the offset's second CREATE adds no second offset and no later action, and the
    request's second CREATE does not double the request. -/
def exCreateRepeat : List Rec := [
  ⟨0, exState 50000, {}⟩,
  ⟨1, exAction actCreate akindOffset 50000 exT exT (pat 32 170), ⟨none, u "det-a", u "act-a"⟩⟩,
  ⟨2, exAction actCreate akindOffset 50000 (exT + 10) exT (pat 32 170), ⟨none, u "det-b", u "act-b"⟩⟩,
  ⟨3, exAction actCreate akindRequest 20000 (exT + 5) exT (pat 32 171), ⟨none, none, u "act-c"⟩⟩,
  ⟨4, exAction actCreate akindRequest 20000 (exT + 20) exT (pat 32 171), ⟨none, none, u "act-d"⟩⟩]

#guard (foldFields exOpening exCreateRepeat).ccount == 1 && (foldFields exOpening exCreateRepeat).done == 2
#guard (foldFields exOpening exCreateRepeat).reqsum == 20000 && (foldFields exOpening exCreateRepeat).amax == 4

/-- A cancelled request does not come back: the CREATE after the CANCEL of the same key adds no request. -/
def exRecreate : List Rec := [
  ⟨0, exState 40000, {}⟩,
  ⟨1, exAction actCreate akindRequest 40000 exT exT (pat 32 172), ⟨none, none, u "act-a"⟩⟩,
  ⟨2, exAction actCancel akindRequest 40000 (exT + 1) exT (pat 32 172), {}⟩,
  ⟨3, exAction actCreate akindRequest 40000 (exT + 2) exT (pat 32 172), ⟨none, none, u "act-b"⟩⟩]

#guard (foldFields exOpening exRecreate).reqsum == 0 && (foldFields exOpening exRecreate).amax == 2

/-- A request with an all-zero key is refused with its record (zero names no request), so cash whose `pays` is zero,
    which pays none, is not set against it. -/
def exZeroAk : List Rec := [
  ⟨0, exState 100000, {}⟩,
  ⟨1, exAction actCreate akindRequest 30000 exT exT (zeros 32), ⟨none, none, u "act-z"⟩⟩,
  ⟨2, exCash (pat 32 173) (zeros 32) 0 1000 exT, ⟨u "ev-a", u "pay-a", none⟩⟩]

#guard (exZeroAk.drop 1).head?.map (fun r => (actionC.dec r.body).isNone) == some true
#guard (foldFields exOpening exZeroAk).reqsum == 0 && (foldFields exOpening exZeroAk).amax == 0 &&
  (foldFields exOpening exZeroAk).ccount == 1

/-- With no state row that decodes, nothing is owed that a payment could reach: the first payment does not complete. -/
def exNoState : List Rec := [
  ⟨0, stateC.enc { sampleState with owed := 100, verification := 0 }, {}⟩,
  ⟨1, exCash (pat 32 174) (zeros 32) 0 1 exT, ⟨u "ev-a", u "pay-a", none⟩⟩]

#guard (foldFields exOpening exNoState).ccount == 1 && (foldFields exOpening exNoState).done == 0 &&
  (foldFields exOpening exNoState).doneMs == 0

/-- Cash of 5 and then of 2^63 - 1 against an amount owed of 2^63 - 1: each fits, and their sum does not, so there is
    no fold record, though the second payment alone would complete the obligation. -/
def exSumOver : List Rec := [
  ⟨0, exState (2 ^ 63 - 1), {}⟩,
  ⟨1, exCash (pat 32 175) (zeros 32) 0 5 exT, ⟨u "ev-a", u "pay-a", none⟩⟩,
  ⟨2, exCash (pat 32 176) (zeros 32) 0 (2 ^ 63 - 1) (exT + 100), ⟨u "ev-b", u "pay-b", none⟩⟩]

#guard foldOf exOpening exSumOver == none && (foldOf exOpening (exSumOver.take 2)).isSome
#guard (foldFields exOpening exSumOver).ccount == 2

-- An identifier of 65,536 bytes does not fit `lp16`: no fold record, whether it is an opening field or in an element
-- (the vectors do not carry one; `lp16` would write its length modulo 65,536).
#guard foldOf { exOpening with itemId := List.replicate 65536 1 } [] == none
#guard (foldOf { exOpening with itemId := List.replicate 65535 1 } []).isSome
#guard foldOf exOpening [⟨0, exState 1, ⟨some (List.replicate 65536 1), none, none⟩⟩] == none
#guard foldOf exOpening [⟨0, exState 1, ⟨none, none, some (List.replicate 65536 1)⟩⟩] == none
#guard foldOf exOpening [⟨0, exState 1, ⟨none, some (List.replicate 65536 1), none⟩⟩] == none
#guard (foldOf exOpening [⟨0, exState 1, ⟨none, some (List.replicate 65535 1), none⟩⟩]).isSome
#guard (foldOf exOpening [⟨0, exState 1, ⟨some (List.replicate 65535 1), none, none⟩⟩]).isSome

/-- Every example, by name, in the order of the vectors. -/
def examples : List (String × List Rec) :=
  [("main", exRecs), ("void", exVoid), ("refused", exRefused), ("cancel", exCancel), ("floor", exFloor),
    ("reqvoid", exReqVoid), ("dupsid", exDupSid), ("reassert", exReassert), ("big", exBig), ("overflow", exOverflow),
    ("voidfirst", exVoidFirst), ("createrepeat", exCreateRepeat), ("recreate", exRecreate), ("zeroak", exZeroAk),
    ("nostate", exNoState), ("sumover", exSumOver)]

end BlindLedger.Gate.Obligations.Format
