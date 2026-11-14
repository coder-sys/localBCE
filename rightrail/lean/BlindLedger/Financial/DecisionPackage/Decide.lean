import BlindLedger.Financial.DecisionPackage.Wire
import BlindLedger.Financial.Payment.Open
import Std.Data.TreeSet

/-! One BLFDPQ01 frame in; the package conclusions and the open cents of every action out.

    Delivery (`packageDelivery`) is met only when every action still waiting has a receiver acknowledgment
    with a reference. Dispatch is not acknowledgment, and no fact stands in for another (Constitution
    Article II): status ACKNOWLEDGED and the outbox reference are two facts, and both are required. Recovery
    needs provable provider notice for every demand still standing, not only the newest one. A cancelled
    action, or a correction request with no open cents left, asks for nothing (R2) and does not wait. An
    offset authorization has no open cents; it waits until acknowledged. The answer's `delivery` stays
    `conclude`'s, the latest action's own acknowledgment; this rule is `deliveryRequirement`, which the
    mask and assessment read. Every other conclusion is `conclude`'s (`packageAnswer_eq`). -/

namespace BlindLedger.Financial.DecisionPackage
open BlindLedger.Financial

/-- One action of the obligation. `correction`: a correction payment request, otherwise an offset authorization.
    `referenced`: the outbox holds an acknowledgment reference. `paidCents`: what active payments linked to it paid. -/
structure PkgActionRow where
  actionId : String
  revision : Nat
  correction : Bool
  status : ActionStatus
  referenced : Bool
  amountCents : Nat
  paidCents : Nat
deriving DecidableEq, Repr

structure PackageRequest where
  shortfallCents : Nat
  actions : List PkgActionRow
  facts : PackageFacts
deriving DecidableEq, Repr

/-- Whether a row is a correction request that is not cancelled: only these collect cash. -/
def collects (r : PkgActionRow) : Bool := r.correction && r.status != .CANCELLED

/-- The row as the payment rule carries a request. -/
def requestPaid (r : PkgActionRow) : Payment.RequestPaid := ⟨r.actionId, r.amountCents, r.paidCents, r.revision, collects r⟩

/-- What each action may still collect within the unpaid shortfall: the payment rule `Payment.openState` itself (R2),
    so the package has no second open-cents rule. 0 for any row that does not collect. -/
def openRequests (s : Nat) (rs : List PkgActionRow) : List Nat :=
  rs.map fun r => Payment.openState s (rs.map requestPaid) (requestPaid r)

/-- `openRequests` in one pass, for rows in frame order: carry what is left of the shortfall from row to row
    (`openRequestsFast_eq`). `openRequests` stays the specification; it reads the whole list again for every row. -/
def openRequestsFast : Nat → List PkgActionRow → List Nat
  | _, [] => []
  | s, r :: rs =>
    let u := if collects r then r.amountCents - r.paidCents else 0
    min u s :: openRequestsFast (s - u) rs

/-- `a` is served before `b`, as `Payment.openState` orders requests: an earlier revision, then by action id. -/
def rowBefore (a b : PkgActionRow) : Bool :=
  a.revision < b.revision || (a.revision == b.revision && decide (a.actionId < b.actionId))

/-- Every row is served after the row before it: the frame lists the actions oldest first, and a row equal to the one
    before it is refused. -/
def inOrder : List PkgActionRow → Bool
  | a :: b :: rs => rowBefore a b && inOrder (b :: rs)
  | _ => true

/-- No action id appears twice, at any revision: each id is looked up in the set of the ids before it (`distinctIds_sound`).
    `inOrder` alone lets one id stand at two revisions, and its paid cents would be counted twice. -/
def distinctIds : Std.TreeSet String → List PkgActionRow → Bool
  | _, [] => true
  | s, r :: rs => !s.contains r.actionId && distinctIds (s.insert r.actionId) rs

/-- An action waits on delivery unless it is cancelled or is a correction request with no open cents. -/
def waits (r : PkgActionRow) (openCents : Nat) : Bool := r.status != .CANCELLED && (!r.correction || openCents != 0)

/-- Acknowledged with a reference: both facts, neither standing in for the other. -/
def delivered (r : PkgActionRow) : Bool := r.status == .ACKNOWLEDGED && r.referenced

/-- Delivery read over the given open cents of each action. -/
def packageDeliveryWith (q : PackageRequest) (o : List Nat) : Support :=
  if q.actions = [] then .UNKNOWN
  else if ((q.actions.zip o).all fun p => !waits p.1 p.2 || delivered p.1) then .SUPPORTED else .NOT_SATISFIED

def packageDelivery (q : PackageRequest) : Support := packageDeliveryWith q (openRequests q.shortfallCents q.actions)

def packageAnswer (q : PackageRequest) : Conclusions := concludeFor q.facts (packageDelivery q)

/-- The item's latest action is the last row: one fact, one value. -/
def latestAction (rs : List PkgActionRow) : Option PkgAction :=
  rs.getLast?.map fun r => { status := r.status, acknowledged := r.referenced }

/-- "BLFDPQ01". -/
def packageRequestMagic : Bytes := [0x42, 0x4C, 0x46, 0x44, 0x50, 0x51, 0x30, 0x31]

/-- `readString` without measuring everything after the string: one frame holds up to 10,000 ids, and `rest.length`
    would walk the rest of the frame for each (`readStringQuick_eq`). -/
def readStringQuick (bytes : Bytes) : Option (String × Bytes) := do
  let (length, rest) ← readNatBE 2 bytes
  let raw := rest.take length
  if raw.length < length then none else
    let value ← String.fromUTF8? raw.toByteArray
    pure (value, rest.drop length)

def readPkgActionRow (b : Bytes) : Option (PkgActionRow × Bytes) := do
  let (actionId, r) ← readStringQuick b
  let (revision, r) ← readCents r
  let (correction, r) ← readBool r
  let (status, r) ← readTagged decodeActionStatus r
  let (referenced, r) ← readBool r
  let (amountCents, r) ← readCents r
  let (paidCents, r) ← readCents r
  pure ({ actionId, revision, correction, status, referenced, amountCents, paidCents }, r)

/-- magic ‖ shortfall u64 ‖ actions (u16 count; action id string, revision u64, correction bool, status tag,
    referenced bool, amount u64, paid u64), oldest first (`inOrder`) ‖ one BLFDPK01 item whose action is the last row's.
    Rows out of order, or an action id twice, are refused. -/
def decodePackageRequest (w : Bytes) : Option PackageRequest :=
  if !packageRequestMagic.isPrefixOf w then none else
  match readCents (w.drop packageRequestMagic.length) with
  | none => none
  | some (shortfallCents, b) =>
    match readList readPkgActionRow b with
    | none => none
    | some (actions, b) =>
      match decodePackageFacts b with
      | none => none
      | some facts =>
        if inOrder actions ∧ distinctIds ∅ actions ∧ facts.action = latestAction actions then some { shortfallCents, actions, facts } else none

/-- Outcome 0 ‖ 28-byte answer ‖ open cents of each action (u16 count; u64 each), or the single byte 1. -/
def packageRequestRespond (w : Bytes) : Bytes :=
  match decodePackageRequest w with
  | none => [UInt8.ofNat 1]
  | some q => UInt8.ofNat 0 :: encodePackageAnswer (packageAnswer q) ++
      encodeList (natBE 8) (openRequests q.shortfallCents q.actions)

/-- What the worker runs: `packageRequestRespond` with the open cents found in one pass (`packageRequestRespondFast_eq`). -/
def packageRequestRespondFast (w : Bytes) : Bytes :=
  match decodePackageRequest w with
  | none => [UInt8.ofNat 1]
  | some q =>
    let o := openRequestsFast q.shortfallCents q.actions
    UInt8.ofNat 0 :: encodePackageAnswer (concludeFor q.facts (packageDeliveryWith q o)) ++ encodeList (natBE 8) o

end BlindLedger.Financial.DecisionPackage
