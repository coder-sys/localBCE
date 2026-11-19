import BlindLedger.Gate.SnapshotV2
import BlindLedger.Gate.Spec
import BlindLedger.Gate.Rules.Spec

namespace BlindLedger.Gate.Authority

open BlindLedger.Gate

/-! APPROVAL/v2: the state's signed grant of authority and its per-payment bypass, one format.  Signed under the
    key set of the batch's admitted head; a grant needs a roster quorum (`kRoster` employees), a bypass two approvers
    of distinct employees and distinct identity-provider subjects.  `Grant` and `Bypass` have private constructors,
    so only admission builds them. -/

def dom (name : String) : Bytes := name.toUTF8.toList ++ [0]

def tag : Bytes := dom "RR/GATE/APPROVAL/v2"
def sigTag : Bytes := dom "RR/GATE/APPROVAL/v2/SIG"

/-- Reason bits fit a u32 holds/overrides field; the 29 reasons use bits 0..28. -/
def reasonMask : Nat := 2 ^ 29

structure Entry where
  program : Bytes
  flows : Nat
  authority : Gate.Authority
  holds : Nat
  deriving DecidableEq

inductive Body
  | grant (serial : Nat) (entries : List Entry)
  | bypass (program payment request : Bytes) (overrides : Nat)
  deriving DecidableEq

structure Doc where
  state : Bytes
  tenantId : Bytes
  notBefore : Nat
  notAfter : Nat
  body : Body
  deriving DecidableEq

structure Frame where
  a : Doc
  sigs : List Keyset.SigRec
  deriving DecidableEq

inductive Refusal | MISSING | MALFORMED | SCOPE | EXPIRED | SUPERSEDED | UNSIGNED deriving DecidableEq, Repr

/-- Both ends valid dates, ordered, at most `Keyset.maxLife` days apart. -/
def spanOk (nb na : Nat) : Bool :=
  Rules.validDate nb && Rules.validDate na && Rules.dayNum nb ≤ Rules.dayNum na &&
    Rules.dayNum na ≤ Rules.dayNum nb + Keyset.maxLife

/-- The frame's day lies in the window, ends included. -/
def windowOk (nb na day : Nat) : Bool := Rules.dayNum nb ≤ Rules.dayNum day && Rules.dayNum day ≤ Rules.dayNum na

/-- Entries ascend by program bytes, then by flow mask; one program's masks are disjoint. -/
def entryLt (a b : Entry) : Bool :=
  lexLt a.program b.program || (a.program == b.program && a.flows < b.flows && a.flows &&& b.flows == 0)

def okEntries : List Entry → Bool
  | [] => true
  | e :: es => es.all (entryLt e) && okEntries es

/-! ### Bytes -/

def kindByte : Body → Nat | .grant .. => 1 | .bypass .. => 2

def encEntry (e : Entry) : Bytes :=
  identField e.program ++ natBE 1 e.flows ++ natBE 1 (SnapshotV2.authByte e.authority) ++ natBE 4 e.holds

def encBody : Body → Bytes
  | .grant s es => natBE 8 s ++ natBE 1 es.length ++ es.flatMap encEntry
  | .bypass p q r o => identField p ++ identField q ++ r ++ natBE 4 o

def encDoc (a : Doc) : Bytes :=
  tag ++ natBE 1 (kindByte a.body) ++ a.state ++ identField a.tenantId ++ natBE 4 a.notBefore ++ natBE 4 a.notAfter ++
    encBody a.body

def Frame.unsigned (f : Frame) : Bytes := encDoc f.a
def encode (f : Frame) : Bytes := f.unsigned ++ Keyset.encodeSigs f.sigs
/-- What the signers sign. -/
def msgOf (f : Frame) : Bytes := sha3 (sigTag ++ f.unsigned)

def pEntry : P Entry := do
  let program ← ident
  let flows ← nat 1 1 31
  let ab ← nat 1 1 3
  let holds ← nat 4 0 (reasonMask - 1)
  match SnapshotV2.authOf ab with
  | none => fail
  | some au =>
    need ((au == .HOLD) == (holds != 0))
    pure ⟨program, flows, au, holds⟩

def pGrant : P Body := do
  let serial ← nat 8
  let n ← nat 1 1 32
  let es ← many pEntry n
  need (okEntries es)
  pure (.grant serial es)

def pBypass : P Body := do
  let p ← ident
  let q ← ident
  let r ← digest
  let o ← nat 4 1 (reasonMask - 1)
  pure (.bypass p q r o)

def pDoc : P Doc := do
  expect tag
  let kind ← nat 1 1 2
  let state ← digest
  let tenant ← ident
  let nb ← nat 4
  let na ← nat 4
  need (spanOk nb na)
  let body ← (if kind = 1 then pGrant else pBypass)
  pure ⟨state, tenant, nb, na, body⟩

/-- Canonical: the document, then a signature block of 1..16 records, nothing after. -/
def decode (x : Bytes) : Option Frame :=
  match pDoc.run x with
  | some (a, rest) => (Keyset.decodeSigBlock rest).map fun ss => ⟨a, ss⟩
  | none => none

/-! ### Admission -/

structure Grant where
  private mk ::
  id : Bytes
  serial : Nat
  entries : List Entry

structure Bypass where
  private mk ::
  id : Bytes
  program : Bytes
  payment : Bytes
  request : Bytes
  overrides : Nat

def approverOk (t : Nat) (e : Keyset.Entry) : Bool := e.role == Keyset.approver && Keyset.liveAt e t

/-- The grant of the batch's tenant on the batch's day: a roster quorum signed it under the head's key set, it is
    in its window, and its serial is not below the shard's stored `floor`. -/
def admitGrant (verify : Bytes → Bytes → Bytes → Bool) (H : SnapshotV2.Head) (tenant : Bytes) (floor : Nat)
    (x : Bytes) : Except Refusal Grant :=
  match decode x with
  | none => .error .MALFORMED
  | some f =>
    match f.a.body with
    | .bypass .. => .error .MALFORMED
    | .grant s es =>
      if f.a.state != H.ks.state || f.a.tenantId != tenant then .error .SCOPE
      else if !windowOk f.a.notBefore f.a.notAfter H.day then .error .EXPIRED
      else if s < floor then .error .SUPERSEDED
      else if !Keyset.quorum verify (Keyset.rosterOk H.day) (·.employee) H.ks H.ks.kRoster (msgOf f) f.sigs then
        .error .UNSIGNED
      else .ok ⟨sha3 f.unsigned, s, es⟩

/-- Every set bit of a bypass's override mask names a bypassable reason. -/
def overridesOk (o : Nat) : Bool := Rules.reasons.all fun r => !Keyset.bit o r.idx || Rules.bypassable r

/-- Two approvers of distinct employees and distinct identity-provider subjects signed it. -/
def admitBypass (verify : Bytes → Bytes → Bytes → Bool) (H : SnapshotV2.Head) (tenant : Bytes) (x : Bytes) :
    Option Bypass :=
  match decode x with
  | none => none
  | some f =>
    match f.a.body with
    | .grant .. => none
    | .bypass p q r o =>
      if f.a.state == H.ks.state && f.a.tenantId == tenant && windowOk f.a.notBefore f.a.notAfter H.day &&
          overridesOk o && Keyset.quorum verify (approverOk H.day) (·.employee) H.ks 2 (msgOf f) f.sigs &&
          Keyset.quorum verify (approverOk H.day) (·.idp) H.ks 2 (msgOf f) f.sigs
      then some ⟨sha3 f.unsigned, p, q, r, o⟩ else none

inductive BypassRefusal | MALFORMED | SCOPE | EXPIRED | REASONS | UNSIGNED deriving DecidableEq, Repr

/-- `admitBypass`, naming the first check that failed (`admitBypassR_ok_iff`). -/
def admitBypassR (verify : Bytes → Bytes → Bytes → Bool) (H : SnapshotV2.Head) (tenant : Bytes) (x : Bytes) :
    Except BypassRefusal Bypass :=
  match decode x with
  | none => .error .MALFORMED
  | some f =>
    match f.a.body with
    | .grant .. => .error .MALFORMED
    | .bypass p q r o =>
      if f.a.state != H.ks.state || f.a.tenantId != tenant then .error .SCOPE
      else if !windowOk f.a.notBefore f.a.notAfter H.day then .error .EXPIRED
      else if !overridesOk o then .error .REASONS
      else if !(Keyset.quorum verify (approverOk H.day) (·.employee) H.ks 2 (msgOf f) f.sigs &&
          Keyset.quorum verify (approverOk H.day) (·.idp) H.ks 2 (msgOf f) f.sigs) then .error .UNSIGNED
      else .ok ⟨sha3 f.unsigned, p, q, r, o⟩

/-- Does the entry cover this program and flow (bit `tag - 1` of its mask)? -/
def covers (en : Entry) (program : Bytes) (flow : WireFlow) : Bool :=
  en.program == program && Keyset.bit en.flows (flow.tag.toNat - 1)

def entryFor (g : Grant) (program : Bytes) (flow : WireFlow) : Option Entry :=
  g.entries.find? (covers · program flow)

end BlindLedger.Gate.Authority
