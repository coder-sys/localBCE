import BlindLedger.Gate.Spec
import BlindLedger.Gate.Rules.Spec

/-! A payment request's lines as the rules' `Line`s.  Lean decodes `Request.lines` itself, so the lines a payment is
    decided on are its own request's: the worker's `req` frame line (`Run.addReq`) and the state model (`StateV2`)
    both use this map. -/

namespace BlindLedger.Gate.Rules

open BlindLedger.Gate

/-- `WireLine` (Spec.lean:271) with every field `pLine` skips. -/
structure WireLineFull where
  flow : WireFlow
  lineId : Bytes
  memberKey : Bytes
  payeeRef : Bytes
  rendering : Bytes
  date : Nat
  proc : Bytes
  units : Nat
  cents : Nat

def pLineFull : P WireLineFull := do
  let flow ← tag flows
  let lineId ← ident
  let memberKey ← take memberKeyBytes
  let payeeRef ← ident
  let rendering ← ident
  let date ← nat 4
  let proc ← ident
  let units ← nat 4
  let cents ← nat 8
  pure { flow, lineId, memberKey, payeeRef, rendering, date, proc, units, cents }

/-- The rules' identifier numbers (Rules/Spec.lean:87-104): a 0x01 byte, then the bytes, big-endian. -/
def idNat (x : Bytes) : Nat := beNat (1 :: x)

/-- `pay` is the program id and the payment id, each u16-length. -/
def payNat (program pay : Bytes) : Nat := idNat (identField program ++ identField pay)

def flowOf : WireFlow → Option Flow
  | .FFS_CYCLE => some .FFS_CYCLE
  | .FFS_CLAIM => some .FFS_CLAIM
  | .CAP_820 => some .CAP_820
  | .SDP => none
  | .PLAN_PAY => none

def lineOf (pay : Nat) (l : WireLineFull) : Option Line :=
  (flowOf l.flow).map fun f =>
    ⟨idNat l.lineId, pay, f, idNat l.memberKey, idNat l.payeeRef, idNat l.rendering, l.date, idNat l.proc,
      l.units, l.cents⟩

def linesOf (r : Request) : Option (List Line) :=
  r.lines.mapM fun x => (parse pLineFull maxLineBytes x).bind (lineOf (payNat r.programId r.paymentId))

/-- `linesOf` with the payment number given, so the caller that has it need not compute it again. -/
def linesOfPay (pay : Nat) (r : Request) : Option (List Line) :=
  r.lines.mapM fun x => (parse pLineFull maxLineBytes x).bind (lineOf pay)

/-- A `Request` with its byte fields as byte arrays, as the engine carries it; `toModel` is the request it stands for. -/
structure RequestBA where
  tenantId : ByteArray
  programId : ByteArray
  flow : WireFlow
  commandKey : ByteArray
  paymentId : ByteArray
  memberKey : ByteArray
  payeeRef : ByteArray
  amountCents : Nat
  period : ByteArray
  lines : List ByteArray
  evidenceRefs : List ByteArray
  contest : Bool

@[inline] def RequestBA.toModel (r : RequestBA) : Request :=
  ⟨r.tenantId.toList, r.programId.toList, r.flow, r.commandKey.toList, r.paymentId.toList, r.memberKey.toList,
    r.payeeRef.toList, r.amountCents, r.period.toList, r.lines.map (·.toList), r.evidenceRefs.map (·.toList), r.contest⟩

def RequestBA.ofModel (r : Request) : RequestBA :=
  ⟨r.tenantId.toByteArray, r.programId.toByteArray, r.flow, r.commandKey.toByteArray, r.paymentId.toByteArray,
    r.memberKey.toByteArray, r.payeeRef.toByteArray, r.amountCents, r.period.toByteArray, r.lines.map (·.toByteArray),
    r.evidenceRefs.map (·.toByteArray), r.contest⟩

end BlindLedger.Gate.Rules
