import BlindLedger.Gate.Obligations.Layout

namespace BlindLedger.Gate.Obligations.Format

open BlindLedger.Gate.FactCodec

/-! The records of the combined store's obligations shard (design `one-store` §2.3-§2.6, §16.2 and §16.3), each a
    245-byte `facts` body: the state row (money row form 5), the case, action and command records, the quarantine marker, the fold
    record, and the fact rows of kinds 14, 15 and 22-26.  Each record is its layout, its cells and its own check;
    `Layout` proves the round trip, the converse, the width and injectivity once, so each record proves only that
    reading its cells back gives it (`*_ok`, with its width).  `layout_fits` proves every width and tag rule at once.
    A record's `build` is its builder (`stateMk` and the others) applied to the cell list, so the in-place readers
    of `Format.Fast` build the same record straight from the bytes.

    Every tag is named once, below; every width and offset is the layout itself (a field's offset is the sum of the
    widths before it), so no other file states one.  `conformance/OBLIGATIONS_V1.md` publishes these layouts and
    `obligations_constants` prints them for the host.

    Numbers are little-endian, as in every `facts` record.  A codec checks widths, tags, zero fields, operation and
    kind codes, the closed lists of the design (event kinds, the state row's three statuses, action kinds and
    statuses, case statuses, the legacy marker `ecls`), and canonical identifier blocks.  Other codes are the
    reader's rule, as in the base fact codec.

    Cost: a record is 245 bytes to encode or decode, one pass, and no SHA3 permutation.  The executables run the
    `ByteArray` twins of `Format.Fast`.

    The first obligations engine (`Shard`, `Check`, `Main`) keeps its own codecs in `Obligations.Records`, including
    the text, repair and run-end records withdrawn by §16.2; they go with that engine.  This module has none of them
    and imports only the generic layout codec (`Obligations.Layout`) and the base fact codec. -/

/-! ## Tags

    Every tag has an even number of one bits and any two differ in at least two bits (`layout_fits`), so one changed
    bit never turns a record into one of another kind.  A fact row's tag is its kind, with bit 7 set when the kind
    has an odd number of one bits. -/

def tagState : Nat := 0x60
def tagCase : Nat := 0x72
def tagAction : Nat := 0xF3
def tagCmd : Nat := 0x74
def tagMark : Nat := 0x50
def tagFold : Nat := 0x65
/-- Fact kinds 14 (OBLIG), 15 (CASH), 22 (CLAIM), 23 (SUPPORT), 24 (REPORT), 25 (FUND), 26 (ACTACK). -/
def tagOblig : Nat := 0x8E
def tagCash : Nat := 0x0F
def tagClaim : Nat := 0x96
def tagSupport : Nat := 0x17
def tagReport : Nat := 0x18
def tagFund : Nat := 0x99
def tagAck : Nat := 0x9A

/-- The digest domains of the fold record (§16.3), each followed by a zero byte where it is hashed. -/
def domEvalFix : String := "RR/GATE/EVALFIX/v1"
def domEvidAcc : String := "RR/GATE/EVIDACC/v1"

/-- `w` bytes that must be zero. -/
def z (w : Nat) : Fld := .lit w 0

/-- A display field (design base §7.3): a canonical identifier block, or `0xFF` followed by the first bytes of the
    identifier's `H256` and zeros.  The length byte of an identifier is below the width, so the two forms differ. -/
def dispOk (w : Nat) (x : Bytes) : Bool := idOk w x || (x.head? == some 0xFF && allZero (x.drop 33))

/-- The rules' bound on an amount or a time: below `2 ^ 63`.  A record that holds more is refused, and so is a fold
    total that reaches it. -/
def bound : Nat := 2 ^ 63

/-- Every amount and time of a record is below the bound; each record's check ends with this, over its own fields. -/
def under (xs : List Nat) : Bool := xs.all (· < bound)

/-! ## State row (tag `0x60`, form 5) -/

structure StateRow where
  mkind : Nat
  ob : Bytes
  cents : Nat
  wbatch : Nat
  windex : Nat
  cause : Nat
  link : Nat
  reg : Nat
  owed : Nat
  received : Nat
  claimed : Nat
  lawful : Nat
  shortfall : Nat
  overage : Nat
  conflicts : Nat
  flags : Nat
  verification : Nat
  caseStatus : Nat
  caseRef : Nat
  act : Nat
  fact : Nat
  cmd : Nat
  dueMs : Nat
  atMs : Nat
  lseq : Nat
  pack : Nat
  rev : Nat
  delivery : Nat
  lg : Nat
  deriving DecidableEq, Repr

/-- `okey` is `ob` then 40 zeros; `line`, `E`, `verdict` and the three day fields are zero for form 5. -/
def stateL : List Fld :=
  [.lit 1 tagState, .lit 1 5, .num 1, .blk 32, z 40, z 5, .num 8, z 8, z 1, .num 8, .num 3, .num 5, .num 5, z 12,
   .num 1, .num 8, .num 8, .num 8, .num 8, .num 8, .num 8, .num 5, .num 1, .num 1, .num 1, .num 5, .num 5,
   .num 5, .num 5, .num 8, .num 8, .num 5, .num 4, .num 5, .num 1, .num 1, z 6]

@[inline] def stateMk (n : Nat → Nat) (k : Nat → Bytes) : StateRow :=
  ⟨n 0, k 1, n 2, n 3, n 4, n 5, n 6, n 7, n 8,
    n 9, n 10, n 11, n 12, n 13, n 14, n 15, n 16, n 17,
    n 18, n 19, n 20, n 21, n 22, n 23, n 24, n 25, n 26,
    n 27, n 28⟩

def stateC : RecCodec StateRow where
  L := stateL
  toC x := [.n x.mkind, .b x.ob, .n x.cents, .n x.wbatch, .n x.windex, .n x.cause, .n x.link, .n x.reg,
    .n x.owed, .n x.received, .n x.claimed, .n x.lawful, .n x.shortfall, .n x.overage, .n x.conflicts,
    .n x.flags, .n x.verification, .n x.caseStatus, .n x.caseRef, .n x.act, .n x.fact, .n x.cmd, .n x.dueMs,
    .n x.atMs, .n x.lseq, .n x.pack, .n x.rev, .n x.delivery, .n x.lg]
  build cs := stateMk (nAt cs) (bAt cs)
  -- mkind 13-25 (the closed list), flag bits 0-3, verification 1-3, case status 1-5, delivery 1-4 (the financial
  -- codec's codes), legacy bits 0-1; every amount, time and batch number below the bound.
  chk x := decide (13 ≤ x.mkind ∧ x.mkind ≤ 25 ∧ x.flags < 16 ∧ 1 ≤ x.verification ∧ x.verification ≤ 3 ∧
    1 ≤ x.caseStatus ∧ x.caseStatus ≤ 5 ∧ 1 ≤ x.delivery ∧ x.delivery ≤ 4 ∧ x.lg < 4) &&
    under [x.cents, x.wbatch, x.owed, x.received, x.claimed, x.lawful, x.shortfall, x.overage, x.dueMs, x.atMs]

theorem stateC_ok : stateC.Lawful ∧ width stateC.L = bodyBytes :=
  ⟨fun y _ => by cases y; rfl, rfl⟩

/-! ## Case record (tag `0x72`) -/

structure CaseRec where
  op : Nat
  ck : Bytes
  ob : Bytes
  status : Nat
  role : Nat
  acct : Nat
  reason : Nat
  dueMs : Nat
  atMs : Nat
  conds : Bytes
  act : Nat
  cmd : Nat
  assignee : Bytes
  lg : Nat
  nt : Nat
  deriving DecidableEq, Repr

@[inline] def caseMk (n : Nat → Nat) (k : Nat → Bytes) : CaseRec :=
  ⟨n 0, k 1, k 2, n 3, n 4, n 5, n 6, n 7, n 8,
    k 9, n 10, n 11, k 12, n 13, n 14⟩

def caseC : RecCodec CaseRec where
  L := [.lit 1 tagCase, .num 1, .blk 32, .blk 32, .num 1, .num 1, .num 1, .num 2, .num 8, .num 8, .blk 64, .num 5,
    .num 5, .blk 32, .num 1, .num 1, z 50]
  toC x := [.n x.op, .b x.ck, .b x.ob, .n x.status, .n x.role, .n x.acct, .n x.reason, .n x.dueMs, .n x.atMs,
    .b x.conds, .n x.act, .n x.cmd, .b x.assignee, .n x.lg, .n x.nt]
  build cs := caseMk (nAt cs) (bAt cs)
  -- op 1 OPEN and 2 EVALUATED are the case chain: status 1-5, the owner's five case statuses.  op 3 ASSIGN and
  -- 4 CLOSE are the follow-through chain (§2.5): status 0, because the item's status is not stored; `followThrough`
  -- derives it from the records (§2.8), so it has one owner.  Held-payment and source items use tag 0x72 on their
  -- own shard under their own codec, not this one.
  chk x := decide (1 ≤ x.op ∧ x.op ≤ 4 ∧ (if x.op ≤ 2 then 1 ≤ x.status ∧ x.status ≤ 5 else x.status = 0) ∧
    x.lg < 4) && under [x.dueMs, x.atMs]

theorem caseC_ok : caseC.Lawful ∧ width caseC.L = bodyBytes :=
  ⟨fun y _ => by cases y; rfl, rfl⟩

/-! ## Action record (tag `0xF3`) -/

/-- The status an operation leaves: CREATE and ATTEMPT READY (1), ACK ACKNOWLEDGED (2), CANCEL CANCELLED (3).  The
    fold follows the operation and the rules follow the status, so the record holds only this pair. -/
def actStatus (op : Nat) : Nat := if op = 2 then 2 else if op = 3 then 3 else 1

structure ActionRec where
  op : Nat
  ak : Bytes
  ob : Bytes
  akind : Nat
  status : Nat
  attempt : Nat
  amount : Nat
  payload : Bytes
  idem : Bytes
  atMs : Nat
  claim : Nat
  ack : Nat
  cmd : Nat
  lg : Nat
  nt : Nat
  rev : Nat
  /-- The time of the determination the action carries out (the rules' `decidedAt`), on every record of the action;
      7 bytes, so times below `2 ^ 56` ms.  The rules require it to be at most the action's created time. -/
  decidedMs : Nat
  deriving DecidableEq, Repr

@[inline] def actionMk (n : Nat → Nat) (k : Nat → Bytes) : ActionRec :=
  ⟨n 0, k 1, k 2, n 3, n 4, n 5, n 6, k 7, k 8,
    n 9, n 10, n 11, n 12, n 13, n 14, n 15, n 16⟩

def actionC : RecCodec ActionRec where
  L := [.lit 1 tagAction, .num 1, .blk 32, .blk 32, .num 1, .num 1, .num 4, .num 8, .blk 64, .blk 64, .num 8, .num 5,
    .num 5, .num 5, .num 1, .num 1, .num 5, .num 7]
  toC x := [.n x.op, .b x.ak, .b x.ob, .n x.akind, .n x.status, .n x.attempt, .n x.amount, .b x.payload,
    .b x.idem, .n x.atMs, .n x.claim, .n x.ack, .n x.cmd, .n x.lg, .n x.nt, .n x.rev, .n x.decidedMs]
  build cs := actionMk (nAt cs) (bAt cs)
  -- op 1 CREATE, 2 ACK, 3 CANCEL, 4 ATTEMPT; akind 1-2 (the two owner kinds); status 1 READY, 2 ACKNOWLEDGED, 3 CANCELLED,
  -- a function of the op (`actStatus`); the key is not all zero (zero names no request); amount and created time below
  -- the bound.
  -- The determination's time is at most the record's: the rules' `decidedAt ≤ createdAt` (`actionBindingWellFormed`)
  -- on the CREATE record, and every later record of the action is no earlier than its creation.
  chk x := decide (1 ≤ x.op ∧ x.op ≤ 4 ∧ 1 ≤ x.akind ∧ x.akind ≤ 2 ∧ x.status = actStatus x.op ∧ x.lg < 4 ∧
    x.decidedMs ≤ x.atMs) && !allZero x.ak && under [x.amount, x.atMs]

theorem actionC_ok : actionC.Lawful ∧ width actionC.L = bodyBytes :=
  ⟨fun y _ => by cases y; rfl, rfl⟩

/-- A record the check accepts holds the status of its operation, so the fold's reading by operation and the rules'
    reading by status are one. -/
theorem actionC_status {x : ActionRec} (h : actionC.chk x = true) : x.status = actStatus x.op := by
  simp only [actionC, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.1.2.2.2.2.1

/-- The action operations and kinds the fold reads (§2.5). -/
def actCreate : Nat := 1
def actCancel : Nat := 3
def akindOffset : Nat := 1
def akindRequest : Nat := 2

/-! ## Command record (tag `0x74`) -/

structure CmdRec where
  ckind : Nat
  cid : Bytes
  rqd : Bytes
  lrq : Bytes
  actor : Bytes
  atMs : Nat
  role : Nat
  attr : Nat
  exprev : Nat
  result : Nat
  lseq : Nat
  epoch : Nat
  lg : Nat
  nt : Nat
  /-- The frame's batch number and the command's place in it (wire rows first, then acts, from 0), §16.2. -/
  wbatch : Nat
  windex : Nat
  deriving DecidableEq, Repr

@[inline] def cmdMk (n : Nat → Nat) (k : Nat → Bytes) : CmdRec :=
  ⟨n 0, k 1, k 2, k 3, k 4, n 5, n 6, n 7, n 8,
    n 9, n 10, n 11, n 12, n 13, n 14, n 15⟩

def cmdC : RecCodec CmdRec where
  L := [.lit 1 tagCmd, .num 1, .blk 32, .blk 64, .blk 64, .blk 32, .num 8, .num 1, .num 1, .num 5, .num 5, .num 5,
    .num 8, .num 1, .num 1, .num 8, .num 3, z 5]
  toC x := [.n x.ckind, .b x.cid, .b x.rqd, .b x.lrq, .b x.actor, .n x.atMs, .n x.role, .n x.attr, .n x.exprev,
    .n x.result, .n x.lseq, .n x.epoch, .n x.lg, .n x.nt, .n x.wbatch, .n x.windex]
  build cs := cmdMk (nAt cs) (bAt cs)
  -- ckind 1-12 (the owner's twelve command kinds); attr 0 source row, 1 signed, 2 claimed; the authority epoch is at
  -- least 1 (the rules' `authorityEpoch`); the time, epoch and batch number below the bound.
  chk x := decide (1 ≤ x.ckind ∧ x.ckind ≤ 12 ∧ x.attr ≤ 2 ∧ 1 ≤ x.epoch ∧ x.lg < 4) &&
    under [x.atMs, x.epoch, x.wbatch]

theorem cmdC_ok : cmdC.Lawful ∧ width cmdC.L = bodyBytes :=
  ⟨fun y _ => by cases y; rfl, rfl⟩

/-! ## Fact rows of kinds 14, 15 and 22-26 (§2.4)

    A fact row's tag is its kind, with bit 7 set when the kind has an odd number of one bits: OBLIG 14 is `0x8E`,
    CLAIM 22 `0x96`, FUND 25 `0x99`, ACTACK 26 `0x9A`; the others are their kind. -/

/-- The base fact row from `op` to `roff`; the tag byte is the layout's literal. -/
structure FactHdr where
  op : Nat
  subject : Bytes
  sid : Bytes
  vstart : Nat
  vstop : Nat
  lineUntil : Nat
  receipt : Nat
  roff : Nat
  deriving DecidableEq, Repr

def hdrL (k : Nat) : List Fld := [.lit 1 k, .num 1, .blk 32, .blk 32, .num 4, .num 4, .num 4, .num 5, .num 5]

def FactHdr.cells (h : FactHdr) : List Cell :=
  [.n h.op, .b h.subject, .b h.sid, .n h.vstart, .n h.vstop, .n h.lineUntil, .n h.receipt, .n h.roff]

/-- The header from cell accessors: `n i` is cell `i` as a number, `k i` as a block. -/
@[inline] def hdrMk (n : Nat → Nat) (k : Nat → Bytes) : FactHdr := ⟨n 0, k 1, k 2, n 3, n 4, n 5, n 6, n 7⟩

/-- A fact row's operations (fact-record design §2.4, §3.3): 1 is the void, the source withdrawing the statement (a
    payment reversal); 2 is the end, which only the engine writes, cutting the statement at `vstop`. -/
def opVoid : Nat := 1
def opEnd : Nat := 2

/-- As the base fact row: `op` 0 to 2, and a span that runs backwards only when `op` is 2. -/
def FactHdr.ok (h : FactHdr) : Bool := decide (h.op < 3 ∧ (h.op = 2 ∨ h.vstart ≤ h.vstop))

/-- OBLIG, kind 14: a population item. -/
structure ObligF where
  h : FactHdr
  owed : Nat
  dueMs : Nat
  rule : Nat
  pop : Bytes
  item : Bytes
  period : Bytes
  ecls : Nat
  deriving DecidableEq, Repr

@[inline] def obligMk (n : Nat → Nat) (k : Nat → Bytes) : ObligF :=
  ⟨hdrMk n k, n 8, n 9, n 10, k 11, k 12, k 13, n 14⟩

def obligC : RecCodec ObligF where
  L := hdrL tagOblig ++ [.num 8, .num 8, .num 4, .blk 32, .blk 51, .blk 21, .num 1, z 32]
  toC x := x.h.cells ++ [.n x.owed, .n x.dueMs, .n x.rule, .b x.pop, .b x.item, .b x.period, .n x.ecls]
  build cs := obligMk (nAt cs) (bAt cs)
  chk x := x.h.ok && decide (x.ecls ≤ 4) && dispOk 51 x.item && dispOk 21 x.period && under [x.owed, x.dueMs]

theorem obligC_ok : obligC.Lawful ∧ width obligC.L = bodyBytes :=
  ⟨fun y _ => by cases y with | mk h => cases h; rfl, rfl⟩

/-- CASH, kind 15: a payment confirmation; its reversal is a void row (`op` 1) of the same `sid`.  The owner has no
    end for a payment (a payment leaves only by its reversal), so a CASH row with `op` 2 is refused. -/
structure CashF where
  h : FactHdr
  amount : Nat
  eventMs : Nat
  pays : Bytes
  pid : Bytes
  ecls : Nat
  origin : Bytes
  deriving DecidableEq, Repr

@[inline] def cashMk (n : Nat → Nat) (k : Nat → Bytes) : CashF :=
  ⟨hdrMk n k, n 8, n 9, k 10, k 11, n 12, k 13⟩

def cashC : RecCodec CashF where
  L := hdrL tagCash ++ [.num 8, .num 8, .blk 32, .blk 32, .num 1, .blk 51, z 25]
  toC x := x.h.cells ++ [.n x.amount, .n x.eventMs, .b x.pays, .b x.pid, .n x.ecls, .b x.origin]
  build cs := cashMk (nAt cs) (bAt cs)
  chk x := x.h.ok && decide (x.h.op ≠ opEnd ∧ x.ecls ≤ 4) && dispOk 51 x.origin &&
    under [x.amount, x.eventMs]

theorem cashC_ok : cashC.Lawful ∧ width cashC.L = bodyBytes :=
  ⟨fun y _ => by cases y with | mk h => cases h; rfl, rfl⟩

/-- Quarantine marker (tag `0x50`, the fact record's §2.5): the statement `sid` of fact kind `fkind` about `subject`
    from source `src` is held unknown for `cause`.  `sidk` is 1 when `sid` is known; when it is 0, `sid` is zero, so a
    marker has one encoding. -/
structure MarkRec where
  src : Nat
  fkind : Nat
  subject : Bytes
  receipt : Nat
  roff : Nat
  cause : Nat
  sidk : Nat
  sid : Bytes
  deriving DecidableEq, Repr

/-- The cause of a marker written for a payment whose origin is already recorded with other cash (a conflict). -/
def originConflict : Nat := 1

@[inline] def markMk (n : Nat → Nat) (k : Nat → Bytes) : MarkRec :=
  ⟨n 0, n 1, k 2, n 3, n 4, n 5, n 6, k 7⟩

def markC : RecCodec MarkRec where
  L := [.lit 1 tagMark, .num 2, .num 1, .blk 32, .num 5, .num 5, .num 1, .num 1, .blk 32, z 165]
  toC x := [.n x.src, .n x.fkind, .b x.subject, .n x.receipt, .n x.roff, .n x.cause, .n x.sidk, .b x.sid]
  build cs := markMk (nAt cs) (bAt cs)
  chk x := decide (x.cause ≠ 0 ∧ x.sidk ≤ 1) && (x.sidk == 1 || allZero x.sid)

theorem markC_ok : markC.Lawful ∧ width markC.L = bodyBytes :=
  ⟨fun y _ => by cases y; rfl, rfl⟩

/-- CLAIM, kind 22: an offset claim. -/
structure ClaimF where
  h : FactHdr
  amount : Nat
  deadlineMs : Nat
  eventMs : Nat
  role : Nat
  ecls : Nat
  claim : Bytes
  deriving DecidableEq, Repr

@[inline] def claimMk (n : Nat → Nat) (k : Nat → Bytes) : ClaimF :=
  ⟨hdrMk n k, n 8, n 9, n 10, n 11, n 12, k 13⟩

def claimC : RecCodec ClaimF where
  L := hdrL tagClaim ++ [.num 8, .num 8, .num 8, .num 1, .num 1, .blk 51, z 80]
  toC x := x.h.cells ++ [.n x.amount, .n x.deadlineMs, .n x.eventMs, .n x.role, .n x.ecls, .b x.claim]
  build cs := claimMk (nAt cs) (bAt cs)
  chk x := x.h.ok && decide (x.ecls ≤ 4) && dispOk 51 x.claim && under [x.amount, x.deadlineMs, x.eventMs]

theorem claimC_ok : claimC.Lawful ∧ width claimC.L = bodyBytes :=
  ⟨fun y _ => by cases y with | mk h => cases h; rfl, rfl⟩

/-- SUPPORT, kind 23: supporting evidence. -/
structure SupportF where
  h : FactHdr
  content : Bytes
  applicableMs : Nat
  eventMs : Nat
  purpose : Nat
  ecls : Nat
  ref : Bytes
  deriving DecidableEq, Repr

@[inline] def supportMk (n : Nat → Nat) (k : Nat → Bytes) : SupportF :=
  ⟨hdrMk n k, k 8, n 9, n 10, n 11, n 12, k 13⟩

def supportC : RecCodec SupportF where
  L := hdrL tagSupport ++ [.blk 64, .num 8, .num 8, .num 1, .num 1, .blk 51, z 24]
  toC x := x.h.cells ++ [.b x.content, .n x.applicableMs, .n x.eventMs, .n x.purpose, .n x.ecls, .b x.ref]
  build cs := supportMk (nAt cs) (bAt cs)
  chk x := x.h.ok && decide (x.ecls ≤ 4) && dispOk 51 x.ref && under [x.applicableMs, x.eventMs]

theorem supportC_ok : supportC.Lawful ∧ width supportC.L = bodyBytes :=
  ⟨fun y _ => by cases y with | mk h => cases h; rfl, rfl⟩

/-- REPORT, kind 24: a report or its correction. -/
structure ReportF where
  h : FactHdr
  content : Bytes
  applicableMs : Nat
  eventMs : Nat
  ecls : Nat
  ref : Bytes
  deriving DecidableEq, Repr

@[inline] def reportMk (n : Nat → Nat) (k : Nat → Bytes) : ReportF :=
  ⟨hdrMk n k, k 8, n 9, n 10, n 11, k 12⟩

def reportC : RecCodec ReportF where
  L := hdrL tagReport ++ [.blk 64, .num 8, .num 8, .num 1, .blk 51, z 25]
  toC x := x.h.cells ++ [.b x.content, .n x.applicableMs, .n x.eventMs, .n x.ecls, .b x.ref]
  build cs := reportMk (nAt cs) (bAt cs)
  chk x := x.h.ok && decide (x.ecls ≤ 4) && dispOk 51 x.ref && under [x.applicableMs, x.eventMs]

theorem reportC_ok : reportC.Lawful ∧ width reportC.L = bodyBytes :=
  ⟨fun y _ => by cases y with | mk h => cases h; rfl, rfl⟩

/-- FUND, kind 25: a program funding receipt. -/
structure FundF where
  h : FactHdr
  amount : Nat
  eventMs : Nat
  cclass : Nat
  estatus : Nat
  ecls : Nat
  ref : Bytes
  deriving DecidableEq, Repr

@[inline] def fundMk (n : Nat → Nat) (k : Nat → Bytes) : FundF :=
  ⟨hdrMk n k, n 8, n 9, n 10, n 11, n 12, k 13⟩

def fundC : RecCodec FundF where
  L := hdrL tagFund ++ [.num 8, .num 8, .num 1, .num 1, .num 1, .blk 51, z 87]
  toC x := x.h.cells ++ [.n x.amount, .n x.eventMs, .n x.cclass, .n x.estatus, .n x.ecls, .b x.ref]
  build cs := fundMk (nAt cs) (bAt cs)
  chk x := x.h.ok && decide (x.ecls ≤ 4) && dispOk 51 x.ref && under [x.amount, x.eventMs]

theorem fundC_ok : fundC.Lawful ∧ width fundC.L = bodyBytes :=
  ⟨fun y _ => by cases y with | mk h => cases h; rfl, rfl⟩

/-- ACTACK, kind 26: the acknowledgment of an action. -/
structure AckF where
  h : FactHdr
  action : Bytes
  payload : Bytes
  eventMs : Nat
  ecls : Nat
  ackref : Bytes
  deriving DecidableEq, Repr

@[inline] def ackMk (n : Nat → Nat) (k : Nat → Bytes) : AckF :=
  ⟨hdrMk n k, k 8, k 9, n 10, n 11, k 12⟩

def ackC : RecCodec AckF where
  L := hdrL tagAck ++ [.blk 32, .blk 64, .num 8, .num 1, .blk 51, z 1]
  toC x := x.h.cells ++ [.b x.action, .b x.payload, .n x.eventMs, .n x.ecls, .b x.ackref]
  build cs := ackMk (nAt cs) (bAt cs)
  chk x := x.h.ok && decide (x.ecls ≤ 4) && dispOk 51 x.ackref && under [x.eventMs]

theorem ackC_ok : ackC.Lawful ∧ width ackC.L = bodyBytes :=
  ⟨fun y _ => by cases y with | mk h => cases h; rfl, rfl⟩

/-! ## Fold record (tag `0x65`, §16.3)

    Written right after each state row: with that row it is the obligation's state, so the next command needs neither
    the obligation's history nor an evaluation.  `cref` and `eacc` are digests (64 bytes); `ecount`, `ccount` and the
    record links are 40-bit; times and cents are 64-bit.  A field that names no record (`cmax`, `done`, `amax` zero)
    has its times and amount zero, so "none" has one encoding.  What each field holds is `foldOf`'s. -/

structure FoldRec where
  /-- `H(dom EVALFIX ‖ the fields of the evaluation result fixed at the opening)`. -/
  cref : Bytes
  /-- `Z` at the opening, then `H(dom EVIDACC ‖ eacc ‖ lp16 evidence id)` per evidence item, in record order. -/
  eacc : Bytes
  ecount : Nat
  /-- Active contributions: payments in force and authorized offsets. -/
  ccount : Nat
  /-- The active contribution that sorts last (time, then amount, then identity): its time, amount and record + 1. -/
  cmaxMs : Nat
  cmaxCents : Nat
  cmax : Nat
  /-- Where the sorted prefix sum first reaches the owed amount: the time and the contribution's record + 1. -/
  doneMs : Nat
  done : Nat
  /-- Open correction requests less the cash that pays them. -/
  reqsum : Nat
  /-- The latest action by created time, then the greater action id: its time and its CREATE record + 1. -/
  amaxMs : Nat
  amax : Nat
  deriving DecidableEq, Repr

@[inline] def foldMk (n : Nat → Nat) (k : Nat → Bytes) : FoldRec :=
  ⟨k 0, k 1, n 2, n 3, n 4, n 5, n 6, n 7, n 8, n 9,
    n 10, n 11⟩

def foldC : RecCodec FoldRec where
  L := [.lit 1 tagFold, .blk 64, .blk 64, .num 5, .num 5, .num 8, .num 8, .num 5, .num 8, .num 5, .num 8, .num 8,
    .num 5, z 51]
  toC x := [.b x.cref, .b x.eacc, .n x.ecount, .n x.ccount, .n x.cmaxMs, .n x.cmaxCents, .n x.cmax, .n x.doneMs,
    .n x.done, .n x.reqsum, .n x.amaxMs, .n x.amax]
  build cs := foldMk (nAt cs) (bAt cs)
  chk x := decide ((x.cmax = 0 → x.cmaxMs = 0 ∧ x.cmaxCents = 0) ∧ (x.done = 0 → x.doneMs = 0) ∧
    (x.amax = 0 → x.amaxMs = 0)) && under [x.cmaxMs, x.cmaxCents, x.doneMs, x.reqsum, x.amaxMs]

theorem foldC_ok : foldC.Lawful ∧ width foldC.L = bodyBytes :=
  ⟨fun y _ => by cases y; rfl, rfl⟩

/-! ## The rows-file record: a body and its link

    A record of the `facts` file is 256 bytes, the rows file's codec (`RowsFile.mkRecord`): the 245-byte body, then
    its link: `prevCore`, the previous record of the same chain plus one (0 for none, 40 bits), the number of records
    of the chain up to and including this one (16 bits, held at 65,535 once it gets there), and four zero bytes (the
    flags, which only the line path's rows files use, and the padding).  The chains (§2.3-§2.6): an obligation's
    state rows; the facts and quarantine markers of one subject; each case; the shard's command records; and the fold
    record's, which is the state row it follows. -/

def recBytes : Nat := 256

structure Link where
  prev : Nat
  count : Nat
  deriving DecidableEq, Repr

def linkL : List Fld := [.num 5, .num 2, z 4]

def Link.cells (l : Link) : List Cell := [.n l.prev, .n l.count]

/-- The count of the record after one of count `c` in its chain (0: the chain starts). -/
def nextCount (c : Nat) : Nat := min (c + 1) 65535

/-- A whole record as its body and its link; `none` unless it is 256 bytes and the flags and padding are zero. -/
def unwrap (r : Bytes) : Option (Bytes × Link) :=
  if r.length = recBytes then
    (decExact linkL (r.drop bodyBytes)).map fun cs => (r.take bodyBytes, ⟨nAt cs 0, nAt cs 1⟩)
  else none

theorem record_width : bodyBytes + width linkL = recBytes := rfl

/-! ## Checks against the design's offset tables

    Each sample round-trips, is 245 bytes, and has its fields at the offsets the design's tables give. -/

/-- `w` bytes at offset `o`. -/
def slice (b : Bytes) (o w : Nat) : Bytes := (b.drop o).take w

def sampleState : StateRow :=
  ⟨19, pat 32 1, 30000, 7, 2, 11, 9, 1, 500000, 200000, 30000, 30000, 300000, 0, 1, 10, 2, 3, 12, 13, 14, 15,
    1767225600000, 1767225600001, 0, 4, 6, 1, 2⟩

#guard stateC.dec (stateC.enc sampleState) == some sampleState
#guard slice (stateC.enc sampleState) 0 3 == [0x60, 5, 19]
#guard slice (stateC.enc sampleState) 3 32 == pat 32 1 && slice (stateC.enc sampleState) 35 45 == zeros 45
#guard slice (stateC.enc sampleState) 80 8 == leBytes 8 30000 && slice (stateC.enc sampleState) 108 5 == leBytes 5 11
#guard slice (stateC.enc sampleState) 131 8 == leBytes 8 500000 &&
  slice (stateC.enc sampleState) 179 9 == [1, 0, 0, 0, 0, 10, 2, 3, 12]
#guard slice (stateC.enc sampleState) 207 8 == leBytes 8 1767225600000 &&
  slice (stateC.enc sampleState) 232 5 == leBytes 5 6
#guard slice (stateC.enc sampleState) 237 8 == [1, 2, 0, 0, 0, 0, 0, 0]
#guard [{ sampleState with delivery := 0 }, { sampleState with delivery := 5 }, { sampleState with verification := 4 },
  { sampleState with verification := 0 }, { sampleState with caseStatus := 6 }].all fun s =>
    stateC.dec (stateC.enc s) == none

/-- A follow-through ASSIGN: status 0. -/
def sampleCase : CaseRec :=
  ⟨3, pat 32 2, pat 32 1, 0, 4, 0xFF, 0xFFFF, 1767225600000, 1767225600001, pat 64 9, 0, 21, pat 32 7, 0, 1⟩

#guard caseC.dec (caseC.enc sampleCase) == some sampleCase
#guard caseC.dec (caseC.enc { sampleCase with op := 1, status := 2 }) != none
#guard [{ sampleCase with status := 2 }, { sampleCase with op := 4, status := 5 }, { sampleCase with op := 1 },
  { sampleCase with op := 2, status := 6 }].all fun c => caseC.dec (caseC.enc c) == none
#guard slice (caseC.enc sampleCase) 0 2 == [0x72, 3] && slice (caseC.enc sampleCase) 66 5 == [0, 4, 0xFF, 0xFF, 0xFF]
#guard slice (caseC.enc sampleCase) 87 64 == pat 64 9 && slice (caseC.enc sampleCase) 161 32 == pat 32 7
#guard slice (caseC.enc sampleCase) 193 2 == [0, 1] && (caseC.enc sampleCase).length == 245

def sampleAction : ActionRec :=
  ⟨1, pat 32 3, pat 32 1, 1, 1, 0, 30000, pat 64 4, pat 64 5, 1767225600000, 8, 0, 21, 0, 2, 1, 1767225599000⟩

#guard actionC.dec (actionC.enc sampleAction) == some sampleAction
#guard slice (actionC.enc sampleAction) 72 8 == leBytes 8 30000 && slice (actionC.enc sampleAction) 144 64 == pat 64 5
#guard slice (actionC.enc sampleAction) 216 5 == leBytes 5 8 && slice (actionC.enc sampleAction) 233 5 == leBytes 5 1
#guard slice (actionC.enc sampleAction) 238 7 == leBytes 7 1767225599000 && (actionC.enc sampleAction).length == 245
-- A determination later than the action's record is refused; at the same time it is accepted.
#guard actionC.dec (actionC.enc { sampleAction with decidedMs := 1767225600001 }) == none
#guard actionC.dec (actionC.enc { sampleAction with decidedMs := 1767225600000 }) != none
-- The rules' bound: an amount or a time of 2^63 or more is refused, one of 2^63 - 1 is read.
#guard actionC.dec (actionC.enc { sampleAction with amount := 2 ^ 63 }) == none
#guard (actionC.dec (actionC.enc { sampleAction with amount := 2 ^ 63 - 1 })).isSome
#guard stateC.dec (stateC.enc { sampleState with owed := 2 ^ 63 }) == none
#guard (stateC.dec (stateC.enc { sampleState with owed := 2 ^ 63 - 1 })).isSome
-- The status follows the operation: CREATE and ATTEMPT READY, ACK ACKNOWLEDGED, CANCEL CANCELLED.
#guard [(1, 2), (1, 3), (2, 1), (2, 3), (3, 1), (3, 2), (4, 2), (4, 3)].all fun (op, st) =>
  actionC.dec (actionC.enc { sampleAction with op := op, status := st }) == none
#guard [(1, 1), (2, 2), (3, 3), (4, 1)].all fun (op, st) =>
  (actionC.dec (actionC.enc { sampleAction with op := op, status := st })).isSome

def sampleCmd : CmdRec :=
  ⟨8, pat 32 6, pat 64 7, zeros 64, pat 32 8, 1767225600000, 2, 2, 7, 22, 0, 3, 0, 4, 9, 513⟩

#guard cmdC.dec (cmdC.enc sampleCmd) == some sampleCmd
#guard slice (cmdC.enc sampleCmd) 34 64 == pat 64 7 && slice (cmdC.enc sampleCmd) 194 8 == leBytes 8 1767225600000
#guard slice (cmdC.enc sampleCmd) 202 7 == [2, 2, 7, 0, 0, 0, 0] &&
  slice (cmdC.enc sampleCmd) 219 10 == leBytes 8 3 ++ [0, 4]
#guard slice (cmdC.enc sampleCmd) 229 16 == leBytes 8 9 ++ [1, 2, 0] ++ zeros 5
#guard (cmdC.enc sampleCmd).length == 245

def sampleFold : FoldRec :=
  ⟨pat 64 11, pat 64 12, 3, 2, 1767225600000, 30000, 14, 1767225600000, 14, 5000, 1767225600002, 9⟩

#guard foldC.dec (foldC.enc sampleFold) == some sampleFold
#guard slice (foldC.enc sampleFold) 0 2 == [0x65, (pat 64 11).head!] && slice (foldC.enc sampleFold) 65 64 == pat 64 12
#guard slice (foldC.enc sampleFold) 129 10 == leBytes 5 3 ++ leBytes 5 2 &&
  slice (foldC.enc sampleFold) 155 5 == leBytes 5 14 && slice (foldC.enc sampleFold) 173 8 == leBytes 8 5000
#guard slice (foldC.enc sampleFold) 189 5 == leBytes 5 9 && slice (foldC.enc sampleFold) 194 51 == zeros 51
#guard [{ sampleFold with cmax := 0 }, { sampleFold with done := 0 }, { sampleFold with amax := 0 }].all fun f =>
  foldC.dec (foldC.enc f) == none
#guard foldC.dec (foldC.enc { sampleFold with done := 0, doneMs := 0 }) != none

/-- The tag of a layout: its first field, a one-byte literal. -/
def tagOfL : List Fld → Nat
  | .lit 1 v :: _ => v
  | _ => 0

/-- A record kind as published: its name, its layout, and the names of its cells in layout order (literal fields are
    named by what they are: the tag, a fixed code, or zeros). -/
structure RecSpec where
  name : String
  L : List Fld
  cells : List String

def hdrCells : List String := ["op", "subject", "sid", "vstart", "vstop", "lineUntil", "receipt", "roff"]

/-- Every record kind of the shard, in the order of `recordTags`. -/
def catalog : List RecSpec := [
  ⟨"state", stateC.L, ["mkind", "ob", "cents", "wbatch", "windex", "cause", "link", "reg", "owed", "received",
    "claimed", "lawful", "shortfall", "overage", "conflicts", "flags", "verification", "caseStatus", "caseRef", "act",
    "fact", "cmd", "dueMs", "atMs", "lseq", "pack", "rev", "delivery", "lg"]⟩,
  ⟨"case", caseC.L, ["op", "ck", "ob", "status", "role", "acct", "reason", "dueMs", "atMs", "conds", "act", "cmd",
    "assignee", "lg", "nt"]⟩,
  ⟨"action", actionC.L, ["op", "ak", "ob", "akind", "status", "attempt", "amount", "payload", "idem", "atMs", "claim",
    "ack", "cmd", "lg", "nt", "rev", "decidedMs"]⟩,
  ⟨"command", cmdC.L, ["ckind", "cid", "rqd", "lrq", "actor", "atMs", "role", "attr", "exprev", "result", "lseq",
    "epoch", "lg", "nt", "wbatch", "windex"]⟩,
  ⟨"marker", markC.L, ["src", "fkind", "subject", "receipt", "roff", "cause", "sidk", "sid"]⟩,
  ⟨"fold", foldC.L, ["cref", "eacc", "ecount", "ccount", "cmaxMs", "cmaxCents", "cmax", "doneMs", "done", "reqsum",
    "amaxMs", "amax"]⟩,
  ⟨"oblig", obligC.L, hdrCells ++ ["owed", "dueMs", "rule", "pop", "item", "period", "ecls"]⟩,
  ⟨"cash", cashC.L, hdrCells ++ ["amount", "eventMs", "pays", "pid", "ecls", "origin"]⟩,
  ⟨"claim", claimC.L, hdrCells ++ ["amount", "deadlineMs", "eventMs", "role", "ecls", "claim"]⟩,
  ⟨"support", supportC.L, hdrCells ++ ["content", "applicableMs", "eventMs", "purpose", "ecls", "ref"]⟩,
  ⟨"report", reportC.L, hdrCells ++ ["content", "applicableMs", "eventMs", "ecls", "ref"]⟩,
  ⟨"fund", fundC.L, hdrCells ++ ["amount", "eventMs", "cclass", "estatus", "ecls", "ref"]⟩,
  ⟨"ack", ackC.L, hdrCells ++ ["action", "payload", "eventMs", "ecls", "ackref"]⟩]

def layouts : List (List Fld) := catalog.map (·.L)

/-- A number or block field: one cell. -/
def Fld.isCell : Fld → Bool
  | .lit _ _ => false
  | _ => true

/-- Every record tag of the shard. -/
def recordTags : List Nat :=
  [tagState, tagCase, tagAction, tagCmd, tagMark, tagFold, tagOblig, tagCash, tagClaim, tagSupport, tagReport,
    tagFund, tagAck]

/-- The number of bits in which two bytes differ. -/
def bitsApart (a b : Nat) : Nat := ((List.range 8).filter fun k => a.testBit k != b.testBit k).length

/-- `layout_fits` (§16.4): every layout is one byte of tag, its own, then fields that end at 245 (a layout is its
    fields in byte order, so they are disjoint and in order by construction); every tag is one byte of even weight,
    and any two differ in at least two bits; every kind names each of its cells. -/
theorem layout_fits :
    layouts.map tagOfL = recordTags ∧
    catalog.all (fun r => r.cells.length == (r.L.filter Fld.isCell).length) = true ∧
    layouts.all (fun L => width L == bodyBytes && match L with | .lit 1 _ :: _ => true | _ => false) = true ∧
    recordTags.all (fun t => decide (t < 256) && bitsApart t 0 % 2 == 0) = true ∧
    recordTags.Pairwise (fun a b => 2 ≤ bitsApart a b) := by
  decide

def sampleCash : CashF :=
  ⟨⟨0, pat 32 1, pat 32 40, 20260101, 20260101, 99991231, 5, 7⟩, 30000, 1767225600000, zeros 32, pat 32 9, 0,
    ident 51 "origin-1"⟩

#guard cashC.dec (cashC.enc sampleCash) == some sampleCash
#guard slice (cashC.enc sampleCash) 88 8 == leBytes 8 30000 && slice (cashC.enc sampleCash) 169 51 == ident 51 "origin-1"
#guard cashC.dec (cashC.enc { sampleCash with origin := 0xFF :: pat 32 3 ++ zeros 18 }) != none
#guard cashC.dec (cashC.enc { sampleCash with origin := 0xFF :: pat 33 3 ++ zeros 17 }) == none
-- A reversal (`op` 1) reads; an end (`op` 2) of a payment does not.
#guard cashC.dec (cashC.enc { sampleCash with h := { sampleCash.h with op := opVoid } }) != none
#guard cashC.dec (cashC.enc { sampleCash with h := { sampleCash.h with op := opEnd } }) == none

def sampleMark : MarkRec := ⟨1, 15, pat 32 40, 0, 0, originConflict, 1, pat 32 9⟩

#guard markC.dec (markC.enc sampleMark) == some sampleMark
#guard slice (markC.enc sampleMark) 0 4 == [0x50, 1, 0, 15] && slice (markC.enc sampleMark) 46 3 == [1, 1, (pat 32 9).head!]
#guard markC.dec (markC.enc { sampleMark with cause := 0 }) == none
-- An unknown statement (`sidk = 0`) has a zero `sid`; any other `sid` with it is refused.
#guard markC.dec (markC.enc { sampleMark with sidk := 0 }) == none
#guard markC.dec (markC.enc { sampleMark with sidk := 0, sid := zeros 32 }) == some { sampleMark with sidk := 0, sid := zeros 32 }

end BlindLedger.Gate.Obligations.Format
