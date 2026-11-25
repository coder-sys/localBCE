import BlindLedger.Gate.Obligations.Agree
import BlindLedger.Gate.Obligations.RequestMap
import BlindLedger.Financial.Payment.Ledger
import BlindLedger.Financial.Payment.Codec
import BlindLedger.Financial.Cursor
import Std.Data.HashMap

namespace BlindLedger.Gate.Obligations

open BlindLedger.Gate.FactCodec
open BlindLedger.Financial (FinancialInput FinancialResult ControlPack evaluate encodeControlPack
  rawEncodeFinancialInput financialInputWellFormed maxTotalEncodedBytes encodeCaseStatus decodeFinancialInput
  decodeControlPack)
open BlindLedger.Financial.Payment (Ledger Call Command Receipt encodeCommand RecordCommand ReverseCommand
  commitInput readCommand PaymentOutcome commitReceipts)

/-! The obligations shard (design `one-store` §2.7, §2.9, §3.1, §4): its store card, the class section of a control
    pack, the commands, their dispositions, and `apply`, which decides one command against the shard's tables and
    returns the records it writes.

    `apply` reads only what `View` holds: the `ident` entry of the command's `cid` and the records it names, the
    obligation's state rebuilt from that obligation's own records, the pack the command names read from that pack's
    records, the card and the class of the command's source.  The store keeps one number for an obligation, its
    newest state row, and no ledger.  The
    financial decision is Lean's own rule on the obligation's ledger (`Ledger.outcome` and `Ledger.step` for a
    payment or a reversal, `evaluate` for an opening or an evaluation), so the shard adds no second money rule.

    Commands of this step: a control pack with its class section, the opening of one obligation, a payment or its
    reversal, and an evaluation.  Offset claims and decisions, acknowledgments, support and report evidence, funding
    and follow-through decisions are refused `NOT_BUILT`, and nothing is written for them.

    The source registry of the base is not built in the engine; the shard takes the class of each source as a table
    given at open (`Store.reg`), indexed by the source number a fact row holds in `receipt`. -/

/-! ## Fit as a Boolean, and encoding that never writes what the codec would not read back -/

def fitB : List Fld → List Cell → Bool
  | [], cs => cs.isEmpty
  | .lit w v :: fs, cs => decide (v < 256 ^ w) && fitB fs cs
  | .num w :: fs, .n v :: cs => decide (v < 256 ^ w) && fitB fs cs
  | .blk w :: fs, .b v :: cs => decide (v.length = w) && fitB fs cs
  | .num _ :: _, [] => false
  | .num _ :: _, .b _ :: _ => false
  | .blk _ :: _, [] => false
  | .blk _ :: _, .n _ :: _ => false

theorem fitB_iff : ∀ (fs : List Fld) (cs : List Cell), fitB fs cs = true ↔ fit fs cs
  | [], cs => by cases cs <;> simp [fitB, fit]
  | .lit w v :: fs, cs => by simp [fitB, fit, fitB_iff fs cs]
  | .num w :: fs, .n v :: cs => by simp [fitB, fit, fitB_iff fs cs]
  | .blk w :: fs, .b v :: cs => by simp [fitB, fit, fitB_iff fs cs]
  | .num _ :: _, [] => by simp [fitB, fit]
  | .num _ :: _, .b _ :: _ => by simp [fitB, fit]
  | .blk _ :: _, [] => by simp [fitB, fit]
  | .blk _ :: _, .n _ :: _ => by simp [fitB, fit]

/-! ## A whole record: its body's layout and cells, then its link's -/

/-- A record's whole layout, its cells, and its body's own check. -/
abbrev Full := List Fld × List Cell × Bool

def full {α : Type} (c : RecCodec α) (x : α) (l : Link) : Full := (c.L ++ linkL, c.toC x ++ l.cells, c.chk x)

/-- A record's 256 bytes, only if every field is within its width and the body passes its own check. -/
def encFull (q : Full) : Option Bytes := if fitB q.1 q.2.1 && q.2.2 then some (encF q.1 q.2.1) else none

theorem encFull_spec {q : Full} {b : Bytes} (h : encFull q = some b) :
    fit q.1 q.2.1 ∧ q.2.2 = true ∧ encF q.1 q.2.1 = b := by
  unfold encFull at h
  split at h
  · rename_i hc
    simp only [Bool.and_eq_true, fitB_iff] at hc
    exact ⟨hc.1, hc.2, Option.some.inj h⟩
  · cases h

/-! ## Tags: the first byte of every record -/

theorem identKey_tag {b : Bytes} {t : Nat} {k : Bytes} (h : identKey b = some (t, k)) :
    b.head?.map UInt8.toNat = some t := by
  match b, h with
  | [], h => simp [identKey] at h
  | [_], h => simp [identKey] at h
  | x :: _ :: _, h =>
    simp only [identKey] at h
    split at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      simp [h.1]
    · cases h

theorem encF_head {v : Nat} {fs : List Fld} (hv : v < 256) (cs : List Cell) :
    (encF (.lit 1 v :: fs) cs).head?.map UInt8.toNat = some v := by
  simp [encF, leBytes, Nat.mod_eq_of_lt hv]

/-- A command record's `ident` key is its tag and its `cid`. -/
theorem cmd_identKey {x : CmdRec} {l : Link} (hf : fit (full cmdC x l).1 (full cmdC x l).2.1) :
    identKey (encF (full cmdC x l).1 (full cmdC x l).2.1) = some (0x74, x.cid) := by
  have hc : x.cid.length = 32 := by
    simp only [full, cmdC, List.cons_append, fit] at hf
    exact hf.2.2.1
  simp [full, cmdC, encF, leBytes, identKey, List.take_left' hc]

/-! ## A record at another record count

    A decided command is a function from the number `n` of its first record to its records.  Placed at `n` instead
    of 0, a record keeps every cell but some of its record numbers (5-byte fields), and each of those is its value at
    0 plus `n`, at most `B`, the command's last record number plus one (`Near n B`).  So a record that fits at 0 fits
    at `n` as long as `B` is below `rowsCap` (`near_fit`). -/

/-- The record count a store can reach: `2^40`, the largest record number a 5-byte field holds, plus one. -/
def rowsCap : Nat := 1099511627776

def Near (k B : Nat) : List Fld → List Cell → List Cell → Prop
  | [], cs0, cs => cs0 = [] ∧ cs = []
  | .lit _ _ :: fs, cs0, cs => Near k B fs cs0 cs
  | .num w :: fs, c0 :: cs0, c :: cs =>
    (c = c0 ∨ (w = 5 ∧ ∃ a, c0 = .n a ∧ c = .n (a + k) ∧ a + k ≤ B)) ∧ Near k B fs cs0 cs
  | .blk _ :: fs, c0 :: cs0, c :: cs => c = c0 ∧ Near k B fs cs0 cs
  | .num _ :: _, [], _ => False
  | .num _ :: _, _ :: _, [] => False
  | .blk _ :: _, [], _ => False
  | .blk _ :: _, _ :: _, [] => False

theorem near_fit {k B : Nat} (hB : B < rowsCap) :
    ∀ (L : List Fld) (cs0 cs : List Cell), Near k B L cs0 cs → fit L cs0 → fit L cs
  | [], cs0, cs, h, _ => by simp only [Near] at h; simp [fit, h.2]
  | .lit w v :: fs, cs0, cs, h, hf => by
    simp only [Near] at h
    simp only [fit] at hf ⊢
    exact ⟨hf.1, near_fit hB fs cs0 cs h hf.2⟩
  | .num w :: fs, c0 :: cs0, c :: cs, h, hf => by
    simp only [Near] at h
    obtain ⟨hc, h⟩ := h
    have ih := near_fit hB fs cs0 cs h
    rcases hc with hc | ⟨rfl, a, rfl, rfl, hb⟩
    · subst hc
      cases c with
      | n v => simp only [fit] at hf ⊢; exact ⟨hf.1, ih hf.2⟩
      | b v => simp [fit] at hf
    · simp only [fit] at hf ⊢
      have h5 : (256 : Nat) ^ 5 = rowsCap := rfl
      exact ⟨by unfold rowsCap at h5 hB; omega, ih hf.2⟩
  | .blk w :: fs, c0 :: cs0, c :: cs, h, hf => by
    simp only [Near] at h
    obtain ⟨hc, h⟩ := h
    subst hc
    cases c with
    | b v => simp only [fit] at hf ⊢; exact ⟨hf.1, near_fit hB fs cs0 cs h hf.2⟩
    | n v => simp [fit] at hf
  | .num _ :: _, [], _, h, _ => by simp [Near] at h
  | .num _ :: _, _ :: _, [], h, _ => by simp [Near] at h
  | .blk _ :: _, [], _, h, _ => by simp [Near] at h
  | .blk _ :: _, _ :: _, [], h, _ => by simp [Near] at h

/-- Two whole records of one layout and one check whose cells are `Near`. -/
def FullNear (k B : Nat) (q0 q : Full) : Prop := q.1 = q0.1 ∧ Near k B q0.1 q0.2.1 q.2.1 ∧ q.2.2 = q0.2.2

theorem encFull_near {k B : Nat} (hB : B < rowsCap) {q0 q : Full} (h : FullNear k B q0 q) {b0 : Bytes}
    (h0 : encFull q0 = some b0) : ∃ b, encFull q = some b := by
  obtain ⟨L0, cs0, k0⟩ := q0
  obtain ⟨L, cs, k1⟩ := q
  obtain ⟨hL, hn, hk⟩ := h
  simp only at hL hn hk
  rw [hL, hk]
  obtain ⟨f0, k2, -⟩ := encFull_spec h0
  have f1 : fitB L0 cs = true := (fitB_iff _ _).2 (near_fit hB _ _ _ hn f0)
  have k3 : k0 = true := k2
  exact ⟨encF L0 cs, by simp [encFull, f1, k3]⟩

/-! ## Store card and the class section of a pack (§4) -/

/-- The store card (§1): `live` is mode LIVE (else SHADOW). -/
structure Card where
  live : Bool
  carry : Bool
  dispatch : Bool
  egress : Bool
  deriving DecidableEq, Repr

/-- The two minimum source classes a control pack carries (§4 item 4).  `offsetMin` is stored and admitted but not
    yet applied: the shard writes no offset (state row mkind 19), so `offset_needs_class` (§9.2) has nothing to
    hold of until the offset command is built, and it is stated and proved with it. -/
structure PackClass where
  offsetMin : Nat
  dispatchMin : Nat
  deriving DecidableEq, Repr

/-- §4 item 4: a store that can dispatch or send admits only a pack whose two minimums are both at least 1. -/
def packAdmitted (card : Card) (p : PackClass) : Bool :=
  !(card.dispatch || card.egress) || (decide (1 ≤ p.offsetMin) && decide (1 ≤ p.dispatchMin))

/-- `pack_class_admitted` (§9.2), for the admission test itself. -/
theorem pack_class_admitted {card : Card} {p : PackClass} (h : packAdmitted card p = true)
    (hc : card.dispatch = true ∨ card.egress = true) : 1 ≤ p.offsetMin ∧ 1 ≤ p.dispatchMin := by
  unfold packAdmitted at h
  rcases hc with hc | hc <;> simp_all

/-- The class a record stands on: 0 ("no class") when it is carried (`ecls ≠ 0`) or its source is registered at
    class 0, else its source's class.  A source the table does not hold has class 0. -/
def classOf (reg : Array Nat) (ecls src : Nat) : Nat := if ecls ≠ 0 then 0 else reg.getD src 0

/-- A read that states a minimum class (§4 item 3). -/
inductive Read where
  | known
  | below
  | legacy
  deriving DecidableEq, Repr

def readMin (minClass cls : Nat) : Read :=
  if cls = 0 ∧ 1 ≤ minClass then .legacy else if minClass ≤ cls then .known else .below

/-- `legacy_satisfies_no_class` (§9.2): a read with minimum class `c ≥ 1` of a carried record, or of a record from a
    source of class 0, is unknown with the reason `LEGACY_CLASS`. -/
theorem legacy_satisfies_no_class {reg : Array Nat} {ecls src c : Nat} (hc : 1 ≤ c)
    (h : ecls ≠ 0 ∨ reg.getD src 0 = 0) : readMin c (classOf reg ecls src) = .legacy := by
  unfold readMin classOf
  rcases h with h | h
  · simp [h, hc]
  · by_cases he : ecls = 0 <;> simp [he, h, hc]

/-- An action is eligible for dispatch (§4 item 6) only on a live store whose card allows it, with `lg = 0`, and
    when the class it was decided from meets the pack's dispatch minimum, which is at least 1. -/
def eligible (card : Card) (p : PackClass) (a : ActionRec) (cls : Nat) : Bool :=
  card.dispatch && card.live && a.lg == 0 && decide (1 ≤ p.dispatchMin) && decide (p.dispatchMin ≤ cls)

/-- `dispatch_needs_class` (§9.2). -/
theorem dispatch_needs_class {card : Card} {p : PackClass} {a : ActionRec} {cls : Nat}
    (h : eligible card p a cls = true) : a.lg = 0 ∧ card.dispatch = true ∧ 1 ≤ cls := by
  simp only [eligible, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at h
  exact ⟨h.1.1.2, h.1.1.1.1, Nat.le_trans h.1.2 h.2⟩

/-- `lg` of a record decided now: bit 1 when anything it was decided from has no class.  A command never sets bit
    0 (carried); only an import batch does, and this step has none. -/
def lgOf (noClass : Bool) : Nat := if noClass then 2 else 0

/-- `legacy_cited` and `legacy_marker_stable` (§9.2) for the marker a command gives: bit 1 is set exactly when
    something it was decided from has no class, and bit 0 is never set. -/
theorem lgOf_bits (b : Bool) : (lgOf b).testBit 1 = b ∧ (lgOf b).testBit 0 = false := by
  cases b <;> decide

/-! ## Commands, dispositions and refusal codes -/

/-- What a command asks for. -/
inductive Act where
  /-- `CONTROL_PACK`: admit a pack and its class section. -/
  | pack (p : ControlPack) (cls : PackClass)
  /-- `POPULATION_MANIFEST` for one item: open its obligation from its opening input. -/
  | population (opening : FinancialInput)
  /-- `PAYMENT` (5) or `PAYMENT_REVERSAL` (6) on the obligation of `item`. -/
  | payment (item : String) (c : Command)
  /-- `EVALUATE` with the caller's request id. -/
  | evaluate (item : String) (requestId : String)
  /-- A kind this step does not build, by its `ckind`. -/
  | other (ckind : Nat)

/-- One command: what it asks, its scope, the frame time, the expected revision it states, who sent it and how
    (`attr` 1 signed, 2 claimed), and the source number of the evidence it carries. -/
structure Cmd where
  act : Act
  scope : Bytes
  atMs : Nat
  exprev : Option Nat
  actor : Bytes
  role : Nat
  attr : Nat
  src : Nat

inductive Code where
  | MALFORMED
  | NOT_BUILT
  | SCOPE_MISMATCH
  | UNKNOWN_OBLIGATION
  | OBLIGATION_EXISTS
  | PACK_UNKNOWN
  | PACK_MISMATCH
  | STALE_REVISION
  | EVALUATION_REJECTED
  | LEGACY_CLASS
  | STORE_READ
  | ROWS
  | TIME
  | payment (r : BlindLedger.Financial.Payment.Refusal)
  deriving DecidableEq, Repr

/-- §2.9: 1 admitted (naming its command record), 4 `ALREADY` (Lean answers that the same statement is already
    recorded, under another command id), 5 `DUPLICATE` (naming the original command record), 6 `CONFLICT` (another
    request under a known command id, or a payment Lean finds in unchanged conflict with recorded cash), 7
    `REFUSED`.  Only an admitted command writes. -/
inductive Disp where
  | admitted (cmdRec : Nat)
  | already
  | duplicate (orig : Nat)
  | conflict
  | refused (c : Code)
  deriving DecidableEq, Repr

/-! ## Tables -/

/-- An obligation as a command decides on it: its ledger (the input and the payment receipts Lean decides on),
    whether anything it was decided from has no class, its newest state row and that row's chain count, its newest
    case record plus one (0 for none), its newest fact or quarantine marker and that record's chain count, and for
    each payment the newest CASH fact or void row of it (newest first).  The store does not hold it: each command
    rebuilds it from the obligation's own records (`loadObl`). -/
structure Obl where
  led : Ledger
  noClass : Bool
  head : Nat
  headCount : Nat
  caseRef : Nat
  fact : Nat
  factCount : Nat
  cash : List (String × Nat)

/-- The obligation's own records name this scope and item.  The tables find an obligation by a hash of the two; a
    command is decided on it only when they are its own, so no command is decided on another's obligation. -/
def Obl.names (o : Obl) (scope : Bytes) (item : String) : Bool :=
  scopeOfCtx o.led.input.context == scope && o.led.input.context.itemId == item

/-- A table of 8-byte slots (§2.7): under the first eight bytes of a 32-byte key, the numbers of the records the
    table holds for the keys that start with them, newest first.  A slot is a hint.  The reader confirms each record
    against the key it looks for (`findRec`), so two keys that share a slot are both found, each as itself. -/
abbrev Slots := Std.HashMap UInt64 (List Nat)

def slotOf (k : Bytes) : UInt64 := (k.take 8).foldl (fun a b => a * 256 + b.toUInt64) 0

/-- The records the table holds under the slot of `k`, newest first. -/
def Slots.of (m : Slots) (k : Bytes) : List Nat := m.getD (slotOf k) []

/-- Record `i` added under the slot of `k`.  When `prev` is not 0, record `prev - 1` is the one `i` replaces. -/
def Slots.put (m : Slots) (k : Bytes) (prev i : Nat) : Slots :=
  let old := m.getD (slotOf k) []
  m.insert (slotOf k) (i :: (if prev = 0 then old else old.erase (prev - 1)))

/-- The shard's tables.  `ident` holds every case, action and command record under the slot of its key.  `obl`
    holds the newest state row of every obligation under the slot of the obligation's key.  `cmdPrev` is the newest
    command record plus one (0 for none), `cmdCount` that record's chain count and `lastMs` its time.  Every table is
    the scan of the log's records in order (`Store.scan`), while the shard runs and when a log is opened. -/
structure Store where
  card : Card
  reg : Array Nat
  n : Nat
  ident : Slots
  obl : Slots
  cmdPrev : Nat
  cmdCount : Nat
  lastMs : Nat

def Store.empty (card : Card) (reg : Array Nat) : Store :=
  { card, reg, n := 0, ident := {}, obl := {}, cmdPrev := 0, cmdCount := 0, lastMs := 0 }

/-! ## Identity of each command (§3.1) -/

def kindOf : Act → Nat
  | .pack _ _ => 1
  | .population _ => 2
  | .payment _ (.record _) => 5
  | .payment _ (.reverse _) => 6
  | .evaluate _ _ => 12
  | .other k => k

def keyOf : Act → Bytes
  | .pack p _ => utf8 p.packId
  | .population i => utf8 (i.context.populationId ++ "/" ++ i.context.itemId)
  | .payment _ (.record c) => utf8 c.paymentId
  | .payment _ (.reverse c) => utf8 c.evidenceId
  | .evaluate _ r => utf8 r
  | .other _ => []

/-- A pack element: the pack's wire encoding and its two class bytes. -/
def packElement (p : ControlPack) (cls : PackClass) : Bytes :=
  encodeControlPack p ++ leBytes 1 cls.offsetMin ++ leBytes 1 cls.dispatchMin

/-- The scope a pack's own ids name. -/
def scopeOfPack (p : ControlPack) : Bytes :=
  scopeOf (utf8 p.stateId) (utf8 p.deploymentId) (utf8 p.programId) (utf8 p.periodId) (utf8 p.currency)

def cidOfCmd (c : Cmd) : Bytes :=
  cidOf c.scope ((kindName (kindOf c.act) ++ ":").toUTF8.toList ++ keyOf c.act)

def identKeyOf (c : Cmd) : Nat × Bytes := (0x74, cidOfCmd c)

/-- A reversal as Lean compares it: the event time filled from the stored evidence, else the command's time, and
    an empty origin read as `reversal:<payment>` (§3.1 row 6, `decideReverse`). -/
def reverseFilled (c : ReverseCommand) (storedAt : Option Nat) (now : Nat) : ReverseCommand :=
  { c with eventAt := some (c.eventAt.getD (storedAt.getD now)),
           commonOriginId := some ((BlindLedger.Financial.Payment.nonEmpty c.commonOriginId).getD
             ("reversal:" ++ c.paymentId)) }

/-- A reversal's request (§3.1 row 6), as Lean compares it, given the obligation's stored evidence. -/
def reverseReq (scope : Bytes) (item : String) (ev : List BlindLedger.Financial.EvidenceRecord)
    (r : ReverseCommand) (now : Nat) : Req :=
  ⟨6, utf8 r.evidenceId, scope, [.s item, .s r.paymentId, .d (H (encodeCommand (.reverse
    (reverseFilled r ((BlindLedger.Financial.findEvidence ev r.evidenceId).map (·.eventAt)) now))))]⟩

/-- How a stored payment command is compared again, by what it wrote: a recorded payment by its receipt
    (`paymentIdentityReq`), an alias by `aliasIdentityReq`, and a conflict, which Lean answers on retry as the
    unchanged conflict whatever revision or request it names, by neither. -/
inductive PayForm where
  | recorded
  | alias (existingPays : Option String)
  | conflict
  deriving DecidableEq, Repr

/-- The request digest a command is compared by on retry (§3.1); for a payment, in the form of what its first
    sending wrote.  An opening is compared without its evaluation time, which is when it was sent and not what it
    asks, so the same opening generated again at a later time is the same request. -/
def rqdIn (c : Cmd) (o : Option Obl) (form : PayForm) : Bytes :=
  match c.act with
  | .pack p cls => rqdOf (canon ⟨1, keyOf c.act, c.scope, [.d (H (packElement p cls))]⟩)
  | .population i =>
    rqdOf (canon ⟨2, keyOf c.act, c.scope, [.d (H (rawEncodeFinancialInput { i with evaluatedAt := 0 }))]⟩)
  | .payment item (.record r) => rqdOf (canon (match form with
    | .recorded => paymentReq c.scope item r r.paysActionId c.exprev
    | .alias e => aliasIdentityReq c.scope item r e
    | .conflict => paymentReq c.scope item r none none))
  | .payment item (.reverse r) =>
    rqdOf (canon (reverseReq c.scope item ((o.map (·.led.input.evidence)).getD []) r c.atMs))
  | .evaluate item _ => rqdOf (canon ⟨12, keyOf c.act, c.scope, [.s item]⟩)
  | .other _ => []

/-- The request an alias pays: the command's, else that of the payment with the same common origin. -/
def existingPays (L : Ledger) (r : RecordCommand) : Option String :=
  (L.input.payments.find? (·.commonOriginId = r.commonOriginId)).bind fun p =>
    (BlindLedger.Financial.Payment.receiptOf L.receipts p.paymentId).bind (·.paysActionId)

/-- The form a stored payment command is compared in, read from the state row its command record names. -/
def formOf (o : Option Obl) (c : Cmd) (row : Option StateRow) : PayForm :=
  match row.map (·.mkind), c.act, o with
  | some 17, .payment _ (.record r), some o => .alias (existingPays o.led r)
  | some 16, _, _ => .conflict
  | _, _, _ => .recorded

/-! ## Reading records

    A command reads the log only through `Rd`: a value, or the number of a record and what to do with that record.
    So the records a command reads are exactly the ones it asks for, in order (`Rd.run`), and what it computes
    depends on the log through those records alone (`Rd.run_local`). -/

inductive Rd (α : Type) where
  | done (a : α)
  | need (i : Nat) (k : Option Bytes → Rd α)

def Rd.bind {α β : Type} : Rd α → (α → Rd β) → Rd β
  | .done a, f => f a
  | .need i k, f => .need i fun b => (k b).bind f

instance : Monad Rd where
  pure := .done
  bind := Rd.bind

/-- The value against a log, and the numbers of the records read, in order. -/
def Rd.run {α : Type} (fetch : Nat → Option Bytes) : Rd α → α × List Nat
  | .done a => (a, [])
  | .need i k =>
    let r := (k (fetch i)).run fetch
    (r.1, i :: r.2)

/-- Two logs that hold the same records at the numbers read give the same value and the same reads. -/
theorem Rd.run_local {α : Type} {f g : Nat → Option Bytes} :
    ∀ (m : Rd α), (∀ i ∈ (m.run f).2, f i = g i) → m.run g = m.run f
  | .done _, _ => rfl
  | .need i k, h => by
    have hi : g i = f i := (h i (by simp [Rd.run])).symm
    have ih := Rd.run_local (f := f) (g := g) (k (f i)) fun j hj => h j (by simp [Rd.run, hj])
    simp only [Rd.run, hi, ih]

/-- Records `a` to `a + k - 1` as bodies and links, oldest first; `none` if one is not a whole record. -/
def readRun : Nat → Nat → List (Bytes × Link) → Rd (Option (List (Bytes × Link)))
  | _, 0, acc => .done (some acc.reverse)
  | a, k + 1, acc => .need a fun b =>
    match b.bind unwrap with
    | none => .done none
    | some r => readRun (a + 1) k (r :: acc)

/-- The state rows of obligation `ob` from row `i` back along their chain, as record number, row and link, oldest
    first; `none` if a record is not a state row of `ob` or the chain does not run backwards. -/
def readChain (ob : Bytes) : Nat → Nat → List (Nat × StateRow × Link) → Rd (Option (List (Nat × StateRow × Link)))
  | 0, _, _ => .done none
  | fuel + 1, i, acc => .need i fun b =>
    match (b.bind unwrap).bind fun (body, l) => (stateC.dec body).map (·, l) with
    | none => .done none
    | some (row, l) =>
      if row.ob != ob then .done none else
      if l.prev = 0 then .done (some ((i, row, l) :: acc)) else
      if l.prev - 1 < i then readChain ob fuel (l.prev - 1) ((i, row, l) :: acc) else .done none

/-- One command of an obligation, as its records hold it: the command record, the records between it and the state
    row, and the row with its number and link. -/
structure Seg where
  x : CmdRec
  mid : List (Bytes × Link)
  at_ : Nat
  row : StateRow
  link : Link

/-- For each state row, the records from the command record it names to the row. -/
def readSegs : List (Nat × StateRow × Link) → List Seg → Rd (Option (List Seg))
  | [], acc => .done (some acc.reverse)
  | (i, row, l) :: rest, acc =>
    if row.cmd = 0 ∨ i < row.cmd then .done none else
    (readRun (row.cmd - 1) (i - (row.cmd - 1)) []).bind fun
      | some ((cb, _) :: mid) =>
        match cmdC.dec cb with
        | some x => readSegs rest (⟨x, mid, i, row, l⟩ :: acc)
        | none => .done none
      | _ => .done none

/-- The element held by the text records among a command's records (they are one run). -/
def midElement (mid : List (Bytes × Link)) : Option Bytes :=
  joinFrom 0 (mid.filterMap fun (b, _) => if tagOf b = 0xF5 then textC.dec b else none)

/-- `step`, from an outcome already computed. -/
def stepOut (L : Ledger) : PaymentOutcome → Ledger
  | .mutated _ w post res => { input := commitInput post res, receipts := commitReceipts L.receipts w }
  | .alias _ _ post => { L with input := post }
  | _ => L

theorem stepOut_eq (L : Ledger) (c : Call) : stepOut L (L.outcome c) = BlindLedger.Financial.Payment.step L c := by
  unfold stepOut BlindLedger.Financial.Payment.step
  cases L.outcome c <;> rfl

/-- The opening input a text element holds, read by the decoder that works on an array of bytes.  It is Lean's
    decoder (`decodeInput_eq`), and takes about an eighth of its time. -/
def decodeInput (e : Bytes) : Option FinancialInput := BlindLedger.Financial.Cursor.decodeFinancialInput e.toByteArray

theorem decodeInput_eq (e : Bytes) : decodeInput e = decodeFinancialInput e := by
  rw [decodeInput, BlindLedger.Financial.Cursor.decodeFinancialInput_eq,
    ← (BlindLedger.Financial.Fast.toByteArray_eq_iff e e.toByteArray).mp rfl]

/-- The obligation after one more of its commands, by Lean's own rule on what the records hold: an opening (state
    row kind 13) from its input, a payment or reversal (14 to 17) from its command, at the row's time and the
    command record's expected revision, and an evaluation (25) at the row's time.  The markers and record numbers
    are the row's. -/
def replay1 (o : Option Obl) (s : Seg) : Option Obl :=
  let noClass := s.row.lg.testBit 1
  let fact := s.row.fact - 1
  match o with
  | none =>
    if s.row.mkind != 13 then none else
    match (midElement s.mid).bind decodeInput with
    | none => none
    | some i =>
      match evaluate i with
      | none => none
      | some res =>
        some { led := { input := commitInput i res, receipts := [] }, noClass, head := s.at_,
               headCount := s.link.count, caseRef := s.row.caseRef, fact, factCount := 1, cash := [] }
  | some o =>
    if s.row.mkind == 25 then
      let i := { o.led.input with evaluatedAt := s.row.atMs }
      match evaluate i with
      | none => none
      | some res =>
        some { o with led := { o.led with input := commitInput i res }, head := s.at_, headCount := s.link.count }
    else if 14 ≤ s.row.mkind ∧ s.row.mkind ≤ 17 then
      match (midElement s.mid).bind readCommand with
      | some (pc, []) =>
        let out := o.led.outcome ⟨s.row.atMs, if s.x.exprev = 0 then none else some (s.x.exprev - 1), pc⟩
        -- A recorded or reversed payment has a new fact; a conflict a new marker; an alias neither.
        let pid := match out with
          | .mutated _ w _ _ => if s.row.mkind ≤ 15 then w.payment.map (·.paymentId) else none
          | _ => none
        some { o with
          led := stepOut o.led out, noClass, head := s.at_, headCount := s.link.count, fact,
          factCount := if s.row.mkind = 17 then o.factCount else nextCount o.factCount,
          cash := match pid with
            | some p => (p, fact) :: o.cash
            | none => o.cash }
      | _ => none
    else none

def replay : Option Obl → List Seg → Option Obl
  | o, [] => o
  | o, s :: ss =>
    match replay1 o s with
    | some o' => replay (some o') ss
    | none => none

/-- An obligation from its own records: its state rows from the newest (`head`) back, the records of the command of
    each, and Lean's rule over them from the opening on.  `none` if a record is missing or is not what the chain
    says. -/
def loadObl (ob : Bytes) (head : Nat) : Rd (Option Obl) :=
  (readChain ob (head + 1) head []).bind fun
    | none => .done none
    | some rows => (readSegs rows []).bind fun
      | none => .done none
      | some segs => .done (replay none segs)

/-- What a table's candidates for a key came to: the newest that is a record of the key, none of them, or a record
    that could not be read or is not one the table holds. -/
inductive Found (α : Type) where
  | hit (i : Nat) (a : α)
  | absent
  | unread

/-- The newest of the records `cands` (newest first) that `ok` confirms.  `ok` gives `some none` for a record of
    another key, and `none` for a record the table does not hold. -/
def findRec {α : Type} (ok : Bytes → Option (Option α)) : List Nat → Rd (Found α)
  | [] => .done .absent
  | i :: rest => .need i fun b =>
    match b.bind ok with
    | none => .done .unread
    | some (some a) => .done (.hit i a)
    | some none => findRec ok rest

/-- A record of `ident` is confirmed by its own tag and key. -/
def keyIs (k : Nat × Bytes) (r : Bytes) : Option (Option Bytes) :=
  (identKey r).map fun k' => if k' = k then some r else none

/-- A state row is confirmed by the obligation it names. -/
def rowIs (ob : Bytes) (r : Bytes) : Option (Option Unit) :=
  ((bodyOf r).bind stateC.dec).map fun row => if row.ob = ob then some () else none

/-- A pack and its class section from the records of its command, whose command record is `r`, record `i`. -/
def packOf (i : Nat) (r : Bytes) : Rd (Option (ControlPack × PackClass)) :=
  match (bodyOf r).bind cmdC.dec with
  | none => .done none
  | some x =>
    if x.ckind != 1 then .done none else
    (readRun (i + 1) x.nt []).bind fun
      | none => .done none
      | some ts => .done do
        let e ← midElement ts
        let (p, rest) ← decodeControlPack e
        match rest with
        | [o, d] => some (p, ⟨o.toNat, d.toNat⟩)
        | _ => none

/-- The command record `r` decoded and, when it names one, its state row. -/
def hitRows (r : Bytes) : Rd (Option CmdRec × Option StateRow) :=
  match (bodyOf r).bind cmdC.dec with
  | none => .done (none, none)
  | some x =>
    if x.result = 0 then .done (some x, none) else
    .need (x.result - 1) fun q => .done (some x, (q.bind bodyOf).bind stateC.dec)

/-! ## The view: everything a command reads -/

def obKey (c : Cmd) : Option Bytes :=
  match c.act with
  | .population i => some (obOf c.scope (utf8 i.context.itemId))
  | .payment item _ => some (obOf c.scope (utf8 item))
  | .evaluate item _ => some (obOf c.scope (utf8 item))
  | _ => none

/-- The `cid` of the pack an opening names: a pack is known by its scope and its id. -/
def packCid (c : Cmd) : Option Bytes :=
  match c.act with
  | .population i => some (cidOf c.scope ((kindName 1 ++ ":").toUTF8.toList ++ utf8 i.pack.packId))
  | _ => none

/-- Whether a command decides on its obligation's state.  An opening asks only whether the obligation exists. -/
def readsObl (c : Cmd) : Bool :=
  match c.act with
  | .payment _ _ | .evaluate _ _ => true
  | _ => false

/-- What a command reads from the log.  `hit` is the newest record of the command's `cid` with its command record
    and the state row that record names.  `oblKnown`: the log holds the command's obligation.  `oblRead`: the command
    decides on that obligation's state, `obl`.  `packNamed`: the log holds the pack the command names, `pack`.  A
    record the tables name that could not be read sets the flag and leaves the value empty, which no view accepts
    (`View.readOk`). -/
structure Loaded where
  hit : Option (Nat × Option CmdRec × Option StateRow)
  oblKnown : Bool
  oblRead : Bool
  obl : Option Obl
  packNamed : Bool
  pack : Option (ControlPack × PackClass)

def loadHit (s : Store) (c : Cmd) : Rd (Option (Nat × Option CmdRec × Option StateRow)) :=
  (findRec (keyIs (identKeyOf c)) (Slots.of s.ident (cidOfCmd c))).bind fun
    | .hit i r => (hitRows r).bind fun q => .done (some (i, q.1, q.2))
    | .absent => .done none
    | .unread => .done (some (0, none, none))

def loadOb (s : Store) (c : Cmd) : Rd (Bool × Bool × Option Obl) :=
  match obKey c with
  | none => .done (false, false, none)
  | some k => (findRec (rowIs k) (Slots.of s.obl k)).bind fun
    | .hit h _ => if readsObl c then (loadObl k h).bind fun o => .done (true, true, o) else .done (true, false, none)
    | .absent => .done (false, false, none)
    | .unread => .done (true, true, none)

def loadPk (s : Store) (c : Cmd) : Rd (Bool × Option (ControlPack × PackClass)) :=
  match packCid c with
  | none => .done (false, none)
  | some k => (findRec (keyIs (0x74, k)) (Slots.of s.ident k)).bind fun
    | .hit i r => (packOf i r).bind fun p => .done (true, p)
    | .absent => .done (false, none)
    | .unread => .done (true, none)

def loadRd (s : Store) (c : Cmd) : Rd Loaded :=
  (loadHit s c).bind fun hit => (loadOb s c).bind fun o => (loadPk s c).bind fun p =>
    .done { hit, oblKnown := o.1, oblRead := o.2.1, obl := o.2.2, packNamed := p.1, pack := p.2 }

structure View where
  card : Card
  srcClass : Nat
  /-- The newest record of the command's `cid`, its command record and the state row that record names. -/
  hit : Option (Nat × Option CmdRec × Option StateRow)
  obl : Option Obl
  pack : Option (ControlPack × PackClass)
  cmdPrev : Nat
  cmdCount : Nat
  lastMs : Nat
  /-- The log holds the command's obligation. -/
  oblKnown : Bool
  /-- The command decides on its obligation's state, and the log holds that obligation. -/
  oblRead : Bool
  /-- The log holds the pack the command names. -/
  packNamed : Bool

/-- A known command id was read whole: its command record, and the state row that record names. -/
def hitOk : Option (Nat × Option CmdRec × Option StateRow) → Bool
  | some (_, some x, row) => x.result == 0 || row.isSome
  | some (_, none, _) => false
  | none => true

/-- Every record the tables name for the command was read and was what they say. -/
def View.readOk (v : View) : Bool :=
  hitOk v.hit && (!v.oblRead || v.obl.isSome) && (!v.packNamed || v.pack.isSome)

def viewWith (s : Store) (c : Cmd) (l : Loaded) : View :=
  { card := s.card, srcClass := s.reg.getD c.src 0, hit := l.hit, obl := l.obl, pack := l.pack,
    cmdPrev := s.cmdPrev, cmdCount := s.cmdCount, lastMs := s.lastMs, oblKnown := l.oblKnown, oblRead := l.oblRead,
    packNamed := l.packNamed }

def viewOf (s : Store) (fetch : Nat → Option Bytes) (c : Cmd) : View := viewWith s c ((loadRd s c).run fetch).1

/-- `command_reads_local` (§9.2), for the log: the view is the same on any log that holds the same records at the
    numbers the command reads. -/
theorem view_reads_local {s : Store} {f g : Nat → Option Bytes} {c : Cmd}
    (h : ∀ i ∈ ((loadRd s c).run f).2, f i = g i) : viewOf s g c = viewOf s f c := by
  unfold viewOf
  rw [Rd.run_local _ h]

/-! ## Records a command writes -/

/-- The evaluation reference that follows a state row whose revision rises (§2.6): the owner's evaluation id for
    the obligation at that revision, `eref` of Lean's result, and zero for the input and the receipt, which are the
    command and the log. -/
def evalRef (res : FinancialResult) : Bytes :=
  lp16 (utf8 ("evaluation:" ++ res.context.obligationId ++ ":r" ++ toString res.afterRevision)) ++
    erefOf (BlindLedger.Financial.rawEncodeFinancialResult res) ++ zeros 128

/-- Every record a command writes after its command record, each with its link.  None of them has tag `0x74`. -/
inductive Body where
  | text (x : TextRec) (l : Link)
  | state (x : StateRow) (l : Link)
  | caseR (x : CaseRec) (l : Link)
  | oblig (x : ObligF) (l : Link)
  | cash (x : CashF) (l : Link)
  | mark (x : MarkRec) (l : Link)

def Body.whole : Body → Full
  | .text x l => full textC x l
  | .state x l => full stateC x l
  | .caseR x l => full caseC x l
  | .oblig x l => full obligC x l
  | .cash x l => full cashC x l
  | .mark x l => full markC x l

def Body.encOk (b : Body) : Option Bytes := encFull b.whole

theorem full_head {α : Type} {c : RecCodec α} {v : Nat} {fs : List Fld} (hL : c.L = .lit 1 v :: fs) (hv : v < 256)
    (x : α) (l : Link) : (encF (full c x l).1 (full c x l).2.1).head?.map UInt8.toNat = some v := by
  simp only [full, hL, List.cons_append]
  exact encF_head hv _

theorem Body.tag_ne {b : Body} {bs : Bytes} (h : b.encOk = some bs) (k : Bytes) :
    identKey bs ≠ some (0x74, k) := by
  intro hk
  have ht := identKey_tag hk
  obtain ⟨-, -, he⟩ := encFull_spec h
  rw [← he] at ht
  cases b with
  | text x l => simp only [Body.whole] at ht; rw [full_head (c := textC) (v := 0xF5) rfl (by decide)] at ht; simp at ht
  | state x l => simp only [Body.whole] at ht; rw [full_head (c := stateC) (v := 0x60) rfl (by decide)] at ht; simp at ht
  | caseR x l => simp only [Body.whole] at ht; rw [full_head (c := caseC) (v := 0x72) rfl (by decide)] at ht; simp at ht
  | oblig x l => simp only [Body.whole] at ht; rw [full_head (c := obligC) (v := 0x8E) rfl (by decide)] at ht; simp at ht
  | cash x l => simp only [Body.whole] at ht; rw [full_head (c := cashC) (v := 15) rfl (by decide)] at ht; simp at ht
  | mark x l => simp only [Body.whole] at ht; rw [full_head (c := markC) (v := 0x50) rfl (by decide)] at ht; simp at ht

def encAll : List Body → Option (List Bytes)
  | [] => some []
  | b :: bs => match b.encOk, encAll bs with
    | some x, some xs => some (x :: xs)
    | _, _ => none

theorem encAll_tag_ne : ∀ {l : List Body} {bs : List Bytes}, encAll l = some bs →
    ∀ r ∈ bs, ∀ k, identKey r ≠ some (0x74, k)
  | [], bs, h => by simp [encAll] at h; subst h; simp
  | b :: l, bs, h => by
    simp only [encAll] at h
    split at h
    · rename_i x xs hx hxs
      cases h
      intro r hr k
      rcases List.mem_cons.mp hr with rfl | hr
      · exact Body.tag_ne hx k
      · exact encAll_tag_ne hxs r hr k
    · cases h

theorem encAll_length : ∀ {l : List Body} {bs : List Bytes}, encAll l = some bs → bs.length = l.length
  | [], bs, h => by simp [encAll] at h; subst h; rfl
  | b :: l, bs, h => by
    simp only [encAll] at h
    split at h
    · rename_i x xs _ hxs
      cases h
      simp [encAll_length hxs]
    · cases h

/-- What a decided command writes after its command record, the fields of that record it decides, its link, and
    the obligation it leaves (`obl`).  No code reads `obl`: the tables are set from the records (`Store.scan`). -/
structure Plan where
  rqd : Bytes
  result : Nat
  nt : Nat
  lg : Nat
  link : Link
  body : List Body
  obl : Option (Bytes × Obl)

def Plan.cmd (p : Plan) (c : Cmd) : CmdRec :=
  { ckind := kindOf c.act, cid := cidOfCmd c, rqd := p.rqd, lrq := zeros 64, actor := c.actor, atMs := c.atMs,
    role := c.role, attr := c.attr, exprev := (c.exprev.map (· + 1)).getD 0, result := p.result, lseq := 0,
    epoch := 0, lg := p.lg, nt := p.nt }

/-- The command record and then the body, or `none` if any record would not read back. -/
def Plan.bytes (p : Plan) (c : Cmd) : Option (List Bytes) :=
  match encFull (full cmdC (p.cmd c) p.link), encAll p.body with
  | some b, some bs => some (b :: bs)
  | _, _ => none

theorem Plan.bytes_spec {p : Plan} {c : Cmd} {bs : List Bytes} (h : p.bytes c = some bs) :
    bs.length = 1 + p.body.length ∧ ∃ b rest, bs = b :: rest ∧ identKey b = some (0x74, cidOfCmd c) ∧
      ∀ r ∈ rest, ∀ k, identKey r ≠ some (0x74, k) := by
  unfold Plan.bytes at h
  split at h
  · rename_i b rest hb hr
    cases h
    obtain ⟨hw, -, he⟩ := encFull_spec hb
    refine ⟨by simp [encAll_length hr]; omega, b, rest, rfl, ?_, encAll_tag_ne hr⟩
    rw [← he, cmd_identKey hw]
    rfl
  · cases h

/-- Text records holding `ts`, the first at record number `a`.  Each links the record before it (its own number,
    as that record's number plus one) and continues the chain count `c` of the record they belong to. -/
def linkTexts : List TextRec → Nat → Nat → List Body
  | [], _, _ => []
  | t :: ts, a, c => .text t ⟨a, nextCount c⟩ :: linkTexts ts (a + 1) (c + 1)

/-- The text records of an element, numbered from 0, the first at record number `a`, after a record of chain count
    `c`. -/
def textsAt (e : Bytes) (a c : Nat) : List Body := if e.isEmpty then [] else linkTexts (partsFrom 0 e) a c

def nParts (e : Bytes) : Nat := if e.isEmpty then 0 else (partsFrom 0 e).length

@[simp] theorem linkTexts_length : ∀ (ts : List TextRec) (a c : Nat), (linkTexts ts a c).length = ts.length
  | [], _, _ => rfl
  | _ :: ts, a, c => by simp [linkTexts, linkTexts_length ts]

@[simp] theorem textsAt_length (e : Bytes) (a c : Nat) : (textsAt e a c).length = nParts e := by
  unfold textsAt nParts
  split <;> simp

-- Proofs split plans by their shape; an element's text records are one piece of it.
attribute [irreducible] textsAt

/-- The state row of a financial result (§2.3).  `cause` is a record number; `caseRef`, `fact` and `cmd` are
    record numbers plus one. -/
def rowOf (mkind cents : Nat) (r : FinancialResult) (rev conflicts cause caseRef fact cmd dueMs atMs lg : Nat) :
    StateRow :=
  { mkind, ob := obOfCtx r.context, cents, wbatch := 0, windex := 0, cause, link := 0, reg := 0,
    owed := r.owedCents, received := r.receivedCashCents, claimed := r.claimedAdjustmentCents,
    lawful := r.lawfulAdjustmentCents, shortfall := r.shortfallCents, overage := r.overageCents, conflicts,
    flags := flagsOf r, verification := (BlindLedger.Financial.encodeVerificationStatus r.verificationStatus).toNat,
    caseStatus := (encodeCaseStatus r.caseStatus).toNat, caseRef, act := 0, fact, cmd, dueMs, atMs, lseq := 0,
    pack := 0, rev, delivery := (BlindLedger.Financial.encodeDeliveryStatus r.deliveryStatus).toNat, lg }

/-- `state_row_is_evaluate` for the row itself: a row written at its result's own revision agrees, field for field,
    with that result (`stateAgree`, `element_fixed_agree`). -/
theorem rowOf_agree (mkind cents : Nat) (r : FinancialResult) (conflicts cause caseRef fact cmd dueMs atMs lg : Nat) :
    stateAgree r cents (rowOf mkind cents r r.afterRevision conflicts cause caseRef fact cmd dueMs atMs lg) = true := by
  simp [stateAgree, rowOf]

/-- Decide a command that `ident` does not hold, from the view alone.  The answer does not depend on where the
    records go: a decided command is a function from its first record number to what it writes. -/
def core (v : View) (c : Cmd) : Except Disp (Nat → Plan) :=
  -- The command record's link: the shard's newest command record.
  let cl : Link := ⟨v.cmdPrev, nextCount v.cmdCount⟩
  -- A command is never earlier than the command before it in the shard, and its time is one Lean's rule takes.
  if c.atMs < v.lastMs ∨ 2 ^ 63 ≤ c.atMs then .error (.refused .TIME) else
  match c.act with
  | .other _ => .error (.refused .NOT_BUILT)
  | .pack p cls =>
    -- A pack's scope is the one its own five ids name, so the records alone give the command's id.
    if scopeOfPack p != c.scope then .error (.refused .SCOPE_MISMATCH) else
    -- Only a pack an opening could name, with class bytes that are bytes: its records then read back as it.  A pack
    -- has no revision, so it states none to expect.
    if !(c.exprev.isNone && BlindLedger.Financial.controlPackWellFormed p && decide (cls.offsetMin < 256) &&
        decide (cls.dispatchMin < 256)) then .error (.refused .MALFORMED) else
    if !packAdmitted v.card cls then .error (.refused .LEGACY_CLASS) else
    let e := packElement p cls
    let rqd := rqdIn c none .recorded
    .ok fun n => { rqd, result := 0, nt := nParts e, lg := 0, link := cl, body := textsAt e (n + 1) cl.count,
                   obl := none }
  | .population i =>
    -- An opening brings its own revision, so it states none to expect.
    if c.exprev.isSome then .error (.refused .MALFORMED) else
    match v.pack with
    | none => .error (.refused .PACK_UNKNOWN)
    | some (p, _) =>
    if p != i.pack then .error (.refused .PACK_MISMATCH) else
    if scopeOfCtx i.context != c.scope then .error (.refused .SCOPE_MISMATCH) else
    if v.oblKnown then .error (.refused .OBLIGATION_EXISTS) else
    let e := rawEncodeFinancialInput i
    -- An opening brings the item at its stated revision, its cases and the evidence it was found with.  Cash, claims,
    -- decisions, conflicts and actions enter only by their own commands (or the import), each with its record.
    if !(financialInputWellFormed i && i.evaluatedAt == c.atMs && i.payments.isEmpty && i.claims.isEmpty &&
        i.determinations.isEmpty && i.conflicts.isEmpty && i.actions.isEmpty &&
        decide (e.length ≤ maxTotalEncodedBytes)) then .error (.refused .MALFORMED) else
    match evaluate i with
    | none => .error (.refused .EVALUATION_REJECTED)
    | some res =>
    let committed := commitInput i res
    if committed.cases.any (·.caseId.startsWith "FOLLOW:") then .error (.refused .MALFORMED) else
    let ob := obOfCtx i.context
    -- Evidence that came inside the opening was stated by no registered source (§4 item 1).
    let noClass := v.srcClass == 0 || !i.evidence.isEmpty
    let lg := lgOf noClass
    let m := committed.cases.length
    let rqd := rqdIn c none .recorded
    let fact : ObligF :=
      { h := { op := 0, subject := ob, sid := obligSidOf c.scope (utf8 i.context.populationId) (utf8 i.context.itemId),
               vstart := utcDate c.atMs, vstop := utcDate c.atMs, lineUntil := 0, receipt := c.src, roff := 0 },
        owed := i.obligation.owedCents, dueMs := i.obligation.dueAt, rule := i.obligation.ruleVersion,
        pop := popOf c.scope (utf8 i.context.populationId), item := display 51 i.context.itemId,
        period := display 21 i.context.periodId, ecls := 0 }
    -- The OBLIG fact, each case record and the state row each start their own chain.
    .ok fun n =>
      let fi := n + 1
      let si := fi + 1 + nParts e + m
      -- One OPEN record per case of the opening input; the row names the newest, or none.
      let caseRef := if m = 0 then 0 else si
      let opens := committed.cases.map fun k => Body.caseR
        { op := 1, ck := ckOf c.scope (utf8 k.caseId), ob, status := (encodeCaseStatus k.status).toNat, role := 0,
          acct := 0, reason := 0, dueMs := k.dueAt, atMs := k.updatedAt, conds := zeros 64, act := 0,
          cmd := n + 1, assignee := zeros 32, lg, nt := 0 } ⟨0, 1⟩
      let row := rowOf 13 0 res res.afterRevision i.conflicts.length fi caseRef (fi + 1) (n + 1)
        i.obligation.dueAt c.atMs lg
      { rqd, result := si + 1, nt := 0, lg, link := cl,
        body := [Body.oblig fact ⟨0, 1⟩] ++ textsAt e (fi + 1) 1 ++ opens ++ [.state row ⟨0, 1⟩] ++
          textsAt (evalRef res) (si + 1) 1,
        obl := some (ob, { led := { input := committed, receipts := [] }, noClass, head := si, headCount := 1,
                           caseRef, fact := fi, factCount := 1, cash := [] }) }
  | .payment item pc =>
    match v.obl with
    | none => .error (.refused .UNKNOWN_OBLIGATION)
    | some o =>
    if !o.names c.scope item then .error (.refused .UNKNOWN_OBLIGATION) else
    if !BlindLedger.Financial.Payment.commandWellFormed pc then .error (.refused .MALFORMED) else
    let L := o.led
    let call : Call := ⟨c.atMs, c.exprev, pc⟩
    let ob := obOf c.scope (utf8 item)
    let noClass := o.noClass || v.srcClass == 0
    let lg := lgOf noClass
    let e := encodeCommand pc
    let L' := BlindLedger.Financial.Payment.step L call
    let conflicts := L'.input.conflicts.length
    let due := L.input.obligation.dueAt
    -- The row continues the obligation's state rows; a fact or marker continues its facts.
    let rl : Link := ⟨o.head + 1, nextCount o.headCount⟩
    let fl : Link := ⟨o.fact + 1, nextCount o.factCount⟩
    -- No fact: the command's text follows its command record, and the row stands on `cause`, the payment fact in
    -- force for the statement.
    let bare (mkind : Nat) (res : FinancialResult) (rev : Nat) (rqd : Bytes) (cause : Nat) : Nat → Plan := fun n =>
      let si := n + 1 + nParts e
      { rqd, result := si + 1, nt := nParts e, lg, link := cl,
        body := textsAt e (n + 1) cl.count ++ [.state (rowOf mkind 0 res rev conflicts cause o.caseRef (o.fact + 1)
          (n + 1) due c.atMs lg) rl],
        obl := some (ob, { o with led := L', noClass, head := si, headCount := rl.count }) }
    -- A CASH fact (or its void row) of payment `pid`, followed by the command's text, then the row.
    let withCash (mkind : Nat) (res : FinancialResult) (cash : CashF) (pid : String) (rqd : Bytes) : Nat → Plan :=
      fun n =>
      let fi := n + 1
      let si := fi + 1 + nParts e
      { rqd, result := si + 1, nt := 0, lg, link := cl,
        body := [Body.cash cash fl] ++ textsAt e (fi + 1) fl.count ++ [.state (rowOf mkind cash.amount res
          res.afterRevision conflicts fi o.caseRef (fi + 1) (n + 1) due c.atMs lg) rl] ++
          textsAt (evalRef res) (si + 1) rl.count,
        obl := some (ob, { o with
          led := L', noClass, head := si, headCount := rl.count, fact := fi, factCount := fl.count,
          cash := (pid, fi) :: o.cash }) }
    let cashOf (op : Nat) (p : BlindLedger.Financial.Payment) (at_ : Nat) (pays : Bytes) : CashF :=
      { h := { op, subject := ob, sid := sidOf 15 [ob, utf8 p.commonOriginId], vstart := utcDate at_,
               vstop := utcDate at_, lineUntil := 0, receipt := c.src, roff := 0 },
        amount := p.amountCents, eventMs := at_, pays, pid := cidOf c.scope (utf8 ("PAYMENT:" ++ p.paymentId)),
        ecls := 0, origin := display 51 p.commonOriginId }
    -- `ident` has no record of this command id.  Lean's duplicate is then the same statement, its evidence the
    -- stored evidence byte for byte, under another payment id (§3.1 alias), or a payment the opening input carried:
    -- already recorded.  Lean's unchanged conflict disagrees with recorded cash, and stays a conflict (III.3).
    match L.outcome call with
    | .refused r => .error (.refused (.payment r))
    | .duplicate _ => .error .already
    | .conflictUnchanged _ => .error .conflict
    | .alias pid _ post =>
      -- The row stands on the fact in force of the payment Lean names, not on the obligation's newest fact,
      -- which may be a quarantine marker.  Lean never answers a reversal with an alias.
      match evaluate post, List.lookup pid o.cash, pc with
      | some res, some k, .record r =>
        .ok (bare 17 res post.beforeRevision (rqdIn c (some o) (.alias (existingPays L r))) k)
      | none, _, _ => .error (.refused .EVALUATION_REJECTED)
      | _, _, _ => .error (.refused .MALFORMED)
    | .mutated .CONFLICT_RECORDED _ _ res =>
      match pc with
      | .record r =>
        -- The command's text, then a quarantine marker on the statement of the payment's origin, then the row,
        -- which stands on the marker (§2.1 `financial_conflicts`).
        let mark : MarkRec := { src := c.src, fkind := 15, subject := ob, receipt := 0, roff := 0,
                                cause := originConflict, sidk := 1, sid := sidOf 15 [ob, utf8 r.commonOriginId] }
        .ok fun n =>
          let mi := n + 1 + nParts e
          { rqd := rqdIn c (some o) .conflict, result := mi + 2, nt := nParts e, lg, link := cl,
            body := textsAt e (n + 1) cl.count ++ [.mark mark fl, .state (rowOf 16 0 res res.afterRevision conflicts
              mi o.caseRef (mi + 1) (n + 1) due c.atMs lg) rl] ++ textsAt (evalRef res) (mi + 2) rl.count,
            obl := some (ob, { o with
              led := L', noClass, head := mi + 1, headCount := rl.count, fact := mi, factCount := fl.count }) }
      | .reverse _ => .error (.refused .MALFORMED)
    | .mutated .RECORDED w _ res =>
      match w.payment, w.receipt, pc with
      | some p, some k, .record r =>
        let pays := match k.paysActionId with
          | some a => akOf c.scope (utf8 a)
          | none => zeros 32
        .ok (withCash 14 res (cashOf 0 p p.eventAt pays) p.paymentId
          (rqdOf (canon (paymentIdentityReq c.scope item r k))))
      | _, _, _ => .error (.refused .MALFORMED)
    | .mutated .REVERSED w _ res =>
      match w.payment, w.evidence with
      | some p, some ev => .ok (withCash 15 res (cashOf 1 p ev.eventAt (zeros 32)) p.paymentId
          (rqdIn c (some o) .recorded))
      | _, _ => .error (.refused .MALFORMED)
  | .evaluate item r =>
    match v.obl with
    | none => .error (.refused .UNKNOWN_OBLIGATION)
    | some o =>
    if !o.names c.scope item then .error (.refused .UNKNOWN_OBLIGATION) else
    let i := { o.led.input with evaluatedAt := c.atMs }
    if !c.exprev.all (· == i.beforeRevision) then .error (.refused .STALE_REVISION) else
    match evaluate i with
    | none => .error (.refused .EVALUATION_REJECTED)
    | some res =>
    let lg := lgOf o.noClass
    let rqd := rqdIn c (some o) .recorded
    let rl : Link := ⟨o.head + 1, nextCount o.headCount⟩
    -- The request id follows the command record as text, so the records alone give the command's id.
    let e := utf8 r
    .ok fun n =>
      let si := n + 1 + nParts e
      { rqd, result := si + 1, nt := nParts e, lg, link := cl,
        body := textsAt e (n + 1) cl.count ++ [.state (rowOf 25 0 res res.afterRevision i.conflicts.length o.fact
          o.caseRef (o.fact + 1) (n + 1) i.obligation.dueAt c.atMs lg) rl] ++ textsAt (evalRef res) (si + 1) rl.count,
        obl := some (obOf c.scope (utf8 item), { o with
          led := { o.led with input := commitInput i res }, head := si, headCount := rl.count }) }

/-- Decide one command from a view whose records were all read, with record numbers from `n`: the disposition, the
    plan and the records written.  Every refusal is decided with the records placed at 0, so it is the same at every
    record count, except `ROWS`: the records would not all fall below `rowsCap` (`no_size_refusal`). -/
def decideRead (v : View) (c : Cmd) (n : Nat) : Disp × Option Plan × List Bytes :=
  match v.hit with
  | some (i, some x, row) =>
    if x.rqd == rqdIn c v.obl (formOf v.obl c row) then (.duplicate i, none, []) else (.conflict, none, [])
  | some (_, none, _) => (.refused .STORE_READ, none, [])
  | none =>
    match core v c with
    | .error d => (d, none, [])
    | .ok f =>
      match (f 0).bytes c with
      | none => (.refused .MALFORMED, none, [])
      | some bs0 =>
        if rowsCap ≤ n + bs0.length then (.refused .ROWS, none, []) else
        -- Never `none` (`rows_fit`).
        match (f n).bytes c with
        | some bs => (.admitted n, some (f n), bs)
        | none => (.refused .ROWS, none, [])

/-- Decide one command from its view.  When a record the tables name was not read, or was not what they say, the
    answer is `STORE_READ` and nothing is written: the command is neither compared nor decided on a state that was
    not read whole. -/
def decideView (v : View) (c : Cmd) (n : Nat) : Disp × Option Plan × List Bytes :=
  if v.readOk then decideRead v c n else (.refused .STORE_READ, none, [])

theorem decideView_ok {v : View} (h : v.readOk = true) (c : Cmd) (n : Nat) : decideView v c n = decideRead v c n := by
  simp [decideView, h]

theorem decideView_unread {v : View} (h : v.readOk = false) (c : Cmd) (n : Nat) :
    decideView v c n = (.refused .STORE_READ, none, []) := by
  simp [decideView, h]

/-- A known command id whose command record names a state row that cannot be read is answered `STORE_READ`.  It is
    not compared in the form of a row that was not read, and nothing is written. -/
theorem hit_without_row_refused {v : View} {c : Cmd} {n i : Nat} {x : CmdRec} (h : v.hit = some (i, some x, none))
    (hr : x.result ≠ 0) : decideView v c n = (.refused .STORE_READ, none, []) :=
  decideView_unread (by simp [View.readOk, hitOk, h, hr]) c n

/-- `ident` after record `n`, from that record alone. -/
def identPut (ident : Slots) (n : Nat) (r : Bytes) : Slots :=
  match identKey r with
  | some k => Slots.put ident k.2 0 n
  | none => ident

/-- The tables after one more record of the log, from that record alone: its number under the slot of its `ident`
    key; for a command record, the shard's newest command record with its count and time; for a state row, its
    number in place of the state row before it in its obligation's chain.  The store is taken apart first, so each
    table grows in place. -/
def Store.scan (s : Store) (r : Bytes) : Store :=
  let ⟨card, reg, n, ident, obl, cmdPrev, cmdCount, lastMs⟩ := s
  let ident := identPut ident n r
  match unwrap r with
  | some (b, l) =>
    if tagOf b = 0x74 then
      match cmdC.dec b with
      | some x => ⟨card, reg, n + 1, ident, obl, n + 1, l.count, x.atMs⟩
      | none => ⟨card, reg, n + 1, ident, obl, cmdPrev, cmdCount, lastMs⟩
    else if tagOf b = 0x60 then
      match stateC.dec b with
      | some row => ⟨card, reg, n + 1, ident, Slots.put obl row.ob l.prev n, cmdPrev, cmdCount, lastMs⟩
      | none => ⟨card, reg, n + 1, ident, obl, cmdPrev, cmdCount, lastMs⟩
    else ⟨card, reg, n + 1, ident, obl, cmdPrev, cmdCount, lastMs⟩
  | none => ⟨card, reg, n + 1, ident, obl, cmdPrev, cmdCount, lastMs⟩

/-- The store of a log: the scan of its records in order.  Opening a log is this. -/
def Store.ofLog (card : Card) (reg : Array Nat) (log : List Bytes) : Store :=
  log.foldl Store.scan (Store.empty card reg)

/-- Apply one command to its view: its disposition, the records it writes, and the store after, which is the scan of
    those records.  So the tables a running shard holds are the ones opening its log gives (`apply_inv`). -/
def applyView (s : Store) (v : View) (c : Cmd) : Disp × List Bytes × Store :=
  match decideView v c s.n with
  | (d, some _, bs) => (d, bs, bs.foldl Store.scan s)
  | (d, none, _) => (d, [], s)

/-- Apply one command: its disposition, the records it writes, and the store after. -/
def apply (s : Store) (fetch : Nat → Option Bytes) (c : Cmd) : Disp × List Bytes × Store :=
  applyView s (viewOf s fetch c) c

/-! ## Theorems -/

/-- `command_duplicate_writes_nothing` (§9.2): when `ident` holds the command's `cid` and the stored request digest
    equals the command's, the answer is `DUPLICATE` naming the original command record, nothing is written and the
    store is unchanged. -/
theorem command_duplicate_writes_nothing {s : Store} {fetch : Nat → Option Bytes} {c : Cmd} {i : Nat}
    {x : CmdRec} {row : Option StateRow} (hr : (viewOf s fetch c).readOk = true)
    (h : (viewOf s fetch c).hit = some (i, some x, row))
    (hq : x.rqd = rqdIn c (viewOf s fetch c).obl (formOf (viewOf s fetch c).obl c row)) :
    apply s fetch c = (.duplicate i, [], s) := by
  unfold apply applyView
  rw [decideView_ok hr]
  unfold decideRead
  rw [h]
  simp [hq]

/-- `command_conflict_writes_nothing` (§9.2): when `ident` holds the `cid` with another request digest, the answer
    is `CONFLICT`, nothing is written and the store is unchanged. -/
theorem command_conflict_writes_nothing {s : Store} {fetch : Nat → Option Bytes} {c : Cmd} {i : Nat}
    {x : CmdRec} {row : Option StateRow} (hr : (viewOf s fetch c).readOk = true)
    (h : (viewOf s fetch c).hit = some (i, some x, row))
    (hq : x.rqd ≠ rqdIn c (viewOf s fetch c).obl (formOf (viewOf s fetch c).obl c row)) :
    apply s fetch c = (.conflict, [], s) := by
  unfold apply applyView
  rw [decideView_ok hr]
  unfold decideRead
  rw [h]
  simp [hq]

/-- A view that was not read whole: `STORE_READ`, nothing written, the store unchanged. -/
theorem unread_writes_nothing {s : Store} {fetch : Nat → Option Bytes} {c : Cmd}
    (hr : (viewOf s fetch c).readOk = false) : apply s fetch c = (.refused .STORE_READ, [], s) := by
  unfold apply applyView
  rw [decideView_unread hr]

/-- `command_reads_local` (§9.2): what a command answers and writes depends on the store only through its view
    (the `ident` entry of its `cid` and the records it names, its obligation as its own records give it, its pack,
    the card and its source's class) and the record count; and the view on the log only through the records the
    command reads (`view_reads_local`). -/
theorem command_reads_local {s₁ s₂ : Store} {f₁ f₂ : Nat → Option Bytes} {c : Cmd}
    (hv : viewOf s₁ f₁ c = viewOf s₂ f₂ c) (hn : s₁.n = s₂.n) :
    (apply s₁ f₁ c).1 = (apply s₂ f₂ c).1 ∧ (apply s₁ f₁ c).2.1 = (apply s₂ f₂ c).2.1 := by
  unfold apply applyView
  rw [hv, hn]
  generalize decideView (viewOf s₂ f₂ c) c s₂.n = r
  rcases r with ⟨d, _ | p, bs⟩ <;> exact ⟨rfl, rfl⟩

/-- A decided command is not earlier than the command before it in the shard, and its time is below `2^63`.  So
    the times of the commands of one obligation, which are some of the shard's commands in order, never go back,
    and each is a time Lean's payment rule takes (`clocksOk`). -/
theorem core_time {v : View} {c : Cmd} {f : Nat → Plan} (h : core v c = .ok f) :
    v.lastMs ≤ c.atMs ∧ c.atMs < 2 ^ 63 := by
  unfold core at h
  dsimp only at h
  split at h
  · cases h
  · rename_i ht
    omega

/-! ### The record-count bound -/

/-- Two records whose whole cells are `Near`. -/
def BodyNear (k B : Nat) (b0 b : Body) : Prop := FullNear k B b0.whole b.whole

def NearAll (k B : Nat) : List Body → List Body → Prop
  | [], [] => True
  | b0 :: l0, b :: l => BodyNear k B b0 b ∧ NearAll k B l0 l
  | _, _ => False

theorem nearAll_nil {k B : Nat} : NearAll k B [] [] := trivial

theorem nearAll_cons {k B : Nat} {b0 b : Body} {l0 l : List Body} (h : BodyNear k B b0 b) (t : NearAll k B l0 l) :
    NearAll k B (b0 :: l0) (b :: l) := ⟨h, t⟩

theorem nearAll_append {k B : Nat} : ∀ {a0 a b0 b : List Body}, NearAll k B a0 a → NearAll k B b0 b →
    NearAll k B (a0 ++ b0) (a ++ b)
  | [], [], _, _, _, hb => by simpa using hb
  | _ :: _, _ :: _, _, _, ha, hb => by
    simp only [NearAll] at ha
    simp only [List.cons_append, NearAll]
    exact ⟨ha.1, nearAll_append ha.2 hb⟩
  | [], _ :: _, _, _, ha, _ => by simp [NearAll] at ha
  | _ :: _, [], _, _, ha, _ => by simp [NearAll] at ha

theorem nearAll_map {α : Type} {k B : Nat} {g0 g : α → Body} : ∀ {l : List α},
    (∀ x ∈ l, BodyNear k B (g0 x) (g x)) → NearAll k B (l.map g0) (l.map g)
  | [], _ => trivial
  | x :: l, h => ⟨h x (by simp), nearAll_map fun y hy => h y (by simp [hy])⟩

theorem linkTexts_near {k B : Nat} : ∀ (ts : List TextRec) (a0 a c : Nat), a = a0 + k → a + ts.length ≤ B →
    NearAll k B (linkTexts ts a0 c) (linkTexts ts a c)
  | [], _, _, _, _, _ => trivial
  | t :: ts, a0, a, c, ha, hB => by
    simp only [linkTexts, List.length_cons] at hB ⊢
    refine ⟨?_, linkTexts_near ts (a0 + 1) (a + 1) (c + 1) (by omega) (by omega)⟩
    subst ha
    simp [BodyNear, Body.whole, FullNear, full, Near, textC, linkL, Link.cells, z]
    omega

theorem textsAt_near {k B : Nat} {e : Bytes} {a0 a c : Nat} (ha : a = a0 + k) (hB : a + nParts e ≤ B) :
    NearAll k B (textsAt e a0 c) (textsAt e a c) := by
  unfold textsAt
  unfold nParts at hB
  by_cases he : e.isEmpty = true
  · simp [he, NearAll]
  · simp only [he] at hB ⊢
    exact linkTexts_near _ _ _ _ ha (by simpa using hB)

theorem encAll_near {k B : Nat} (hB : B < rowsCap) : ∀ {l0 l : List Body}, NearAll k B l0 l →
    ∀ {bs0 : List Bytes}, encAll l0 = some bs0 → ∃ bs, encAll l = some bs
  | [], [], _, _, _ => ⟨[], rfl⟩
  | b0 :: l0, b :: l, h, bs0, h0 => by
    simp only [NearAll] at h
    simp only [encAll] at h0
    split at h0
    · rename_i x xs hx hxs
      obtain ⟨y, hy⟩ := encFull_near hB h.1 hx
      obtain ⟨ys, hys⟩ := encAll_near hB h.2 hxs
      exact ⟨y :: ys, by simp [encAll, Body.encOk, hy, hys]⟩
    · cases h0
  | [], _ :: _, h, _, _ => by simp [NearAll] at h
  | _ :: _, [], h, _, _ => by simp [NearAll] at h

/-- A plan placed at 0 and the same plan placed at `n`: the command record and every record after it `Near`. -/
def Plan.Near (c : Cmd) (k B : Nat) (p0 p : Plan) : Prop :=
  FullNear k B (full cmdC (p0.cmd c) p0.link) (full cmdC (p.cmd c) p.link) ∧ NearAll k B p0.body p.body

/-- Codec by codec, for every record a decided command writes: each record-number field, placed at `n`, is its
    value at 0 plus `n` and at most `n` plus the command's record count, and every other cell is the same. -/
theorem core_near {v : View} {c : Cmd} {f : Nat → Plan} (h : core v c = .ok f) (n : Nat) :
    (f 0).Near c n (n + 1 + (f 0).body.length) (f n) := by
  unfold core at h
  dsimp only at h
  repeat' split at h
  all_goals try (cases h; done)
  all_goals
    simp only [Except.ok.injEq] at h
    subst h
    dsimp only
    refine ⟨?_, ?_⟩
    · simp [FullNear, full, Plan.cmd, cmdC, linkL, Link.cells, Near, z]
      try omega
    · -- Split both bodies the same way, by their shape alone (no unfolding).
      repeat' (first
        | with_reducible refine textsAt_near ?_ ?_
        | with_reducible refine nearAll_map ?_
        | with_reducible refine nearAll_append ?_ ?_
        | with_reducible refine nearAll_cons ?_ ?_
        | with_reducible exact nearAll_nil)
      all_goals (try intro _ _)
      all_goals (try simp [BodyNear, Body.whole, FullNear, full, Near, linkL, Link.cells, z, stateC, stateL,
        caseC, obligC, cashC, markC, hdrL, FactHdr.cells, rowOf])
      all_goals ((repeat' split) <;> omega)

theorem rows_fit {v : View} {c : Cmd} {f : Nat → Plan} {bs0 : List Bytes} {n : Nat} (h : core v c = .ok f)
    (h0 : (f 0).bytes c = some bs0) (hn : ¬ rowsCap ≤ n + bs0.length) : ∃ bs, (f n).bytes c = some bs := by
  have hB : n + 1 + (f 0).body.length < rowsCap := by
    have := (Plan.bytes_spec h0).1
    omega
  have hp := core_near h n
  unfold Plan.bytes at h0 ⊢
  split at h0
  · rename_i b bs hb hbs
    obtain ⟨y, hy⟩ := encFull_near hB hp.1 hb
    obtain ⟨ys, hys⟩ := encAll_near hB hp.2 hbs
    exact ⟨y :: ys, by simp [hy, hys]⟩
  · cases h0

theorem core_ne_rows (v : View) (c : Cmd) : core v c ≠ .error (.refused .ROWS) := by
  unfold core
  dsimp only
  repeat' split
  all_goals intro h; cases h

theorem no_size_refusal_read {v : View} {c : Cmd} {n : Nat} {code : Code}
    (h : (decideRead v c n).1 = .refused code) :
    (code = .ROWS → ∃ f bs, v.hit = none ∧ core v c = .ok f ∧ (f 0).bytes c = some bs ∧ rowsCap ≤ n + bs.length) ∧
    (code ≠ .ROWS → ∀ n', (decideRead v c n').1 = .refused code) := by
  unfold decideRead at h
  rcases hv : v.hit with _ | ⟨i, _ | x, row⟩
  · simp only [hv] at h
    cases hk : core v c with
    | error d =>
      simp only [hk] at h
      subst h
      refine ⟨fun hr => (core_ne_rows v c (hr ▸ hk)).elim, fun _ n' => ?_⟩
      simp [decideRead, hv, hk]
    | ok f =>
      simp only [hk] at h
      cases h0 : (f 0).bytes c with
      | none =>
        simp only [h0, Disp.refused.injEq] at h
        subst h
        exact ⟨fun hr => (by cases hr), fun _ n' => (by simp [decideRead, hv, hk, h0])⟩
      | some bs0 =>
        simp only [h0] at h
        split at h
        · rename_i hc
          simp only [Disp.refused.injEq] at h
          subst h
          exact ⟨fun _ => ⟨f, bs0, rfl, rfl, h0, hc⟩, fun hr => absurd rfl hr⟩
        · rename_i hc
          obtain ⟨bs, hb⟩ := rows_fit hk h0 hc
          simp [hb] at h
  · simp only [hv] at h
    exact ⟨fun hr => (by subst hr; simp at h), fun _ n' => (by simp only [decideRead, hv]; exact h)⟩
  · simp only [hv] at h
    split at h <;> simp at h

theorem decideRead_some {v : View} {c : Cmd} {n : Nat} {d : Disp} {p : Plan} {bs : List Bytes}
    (h : decideRead v c n = (d, some p, bs)) : v.hit = none ∧ p.bytes c = some bs ∧ ∃ f, core v c = .ok f ∧ p = f n := by
  unfold decideRead at h
  rcases hv : v.hit with _ | ⟨i, _ | x, row⟩ <;> simp only [hv] at h
  · cases hk : core v c with
    | error e => simp [hk] at h
    | ok f =>
      simp only [hk] at h
      cases h0 : (f 0).bytes c with
      | none => simp [h0] at h
      | some _ =>
        simp only [h0] at h
        split at h
        · simp at h
        · cases hn : (f n).bytes c with
          | none => simp [hn] at h
          | some bs' =>
            simp only [hn, Prod.mk.injEq, Option.some.injEq] at h
            obtain ⟨-, rfl, rfl⟩ := h
            exact ⟨rfl, hn, f, rfl, rfl⟩
  · simp at h
  · split at h <;> simp at h

/-- `no_size_refusal` (§9.2): a refusal other than `ROWS` is the same at every record count, and `ROWS` is given
    only when the command's records, placed at the record count, would reach `rowsCap`.  With `command_reads_local`,
    no refusal depends on the number of obligations, commands or packs either. -/
theorem no_size_refusal {v : View} {c : Cmd} {n : Nat} {code : Code}
    (h : (decideView v c n).1 = .refused code) :
    (code = .ROWS → ∃ f bs, v.hit = none ∧ core v c = .ok f ∧ (f 0).bytes c = some bs ∧ rowsCap ≤ n + bs.length) ∧
    (code ≠ .ROWS → ∀ n', (decideView v c n').1 = .refused code) := by
  cases hr : v.readOk with
  | true =>
    rw [decideView_ok hr] at h
    obtain ⟨h1, h2⟩ := no_size_refusal_read h
    exact ⟨h1, fun hc n' => by rw [decideView_ok hr]; exact h2 hc n'⟩
  | false =>
    rw [decideView_unread hr] at h
    simp only [Disp.refused.injEq] at h
    subst h
    exact ⟨fun hc => (by cases hc), fun _ n' => (by rw [decideView_unread hr])⟩

/-- What an admitted command writes: its view was read whole, `ident` held no record of its `cid`, and the records
    are its plan's, placed at the record count. -/
theorem decideView_some {v : View} {c : Cmd} {n : Nat} {d : Disp} {p : Plan} {bs : List Bytes}
    (h : decideView v c n = (d, some p, bs)) :
    v.readOk = true ∧ v.hit = none ∧ p.bytes c = some bs ∧ ∃ f, core v c = .ok f ∧ p = f n := by
  cases hr : v.readOk with
  | true =>
    rw [decideView_ok hr] at h
    exact ⟨rfl, decideRead_some h⟩
  | false =>
    rw [decideView_unread hr] at h
    simp at h

/-- A decided command is in time (`core_time`). -/
theorem admitted_in_time {v : View} {c : Cmd} {n : Nat} {d : Disp} {p : Plan} {bs : List Bytes}
    (h : decideView v c n = (d, some p, bs)) : v.lastMs ≤ c.atMs ∧ c.atMs < 2 ^ 63 := by
  obtain ⟨-, -, -, f, hf, -⟩ := decideView_some h
  exact core_time hf

/-! ### `command_once` -/

/-- The command records of a log with a given `cid`. -/
def cmdCount (log : List Bytes) (k : Bytes) : Nat := log.countP fun r => identKey r == some (0x74, k)

/-- The store's tables are the scan of its log. -/
def Store.Inv (s : Store) (log : List Bytes) : Prop := s = Store.ofLog s.card s.reg log

theorem Rd.run_bind {α β : Type} (fetch : Nat → Option Bytes) (f : α → Rd β) :
    ∀ (m : Rd α), ((m.bind f).run fetch).1 = ((f (m.run fetch).1).run fetch).1
  | .done _ => rfl
  | .need _ k => Rd.run_bind fetch f (k (fetch _))

/-- When no candidate is confirmed, every candidate was read and is a record of another key. -/
theorem findRec_absent {α : Type} {ok : Bytes → Option (Option α)} {fetch : Nat → Option Bytes} :
    ∀ {l : List Nat}, ((findRec ok l).run fetch).1 = .absent → ∀ j ∈ l, ∃ r, fetch j = some r ∧ ok r = some none
  | [], _, j, hj => by cases hj
  | i :: rest, h, j, hj => by
    cases hf : fetch i with
    | none => simp [findRec, Rd.run, hf] at h
    | some r =>
      cases ho : ok r with
      | none => simp [findRec, Rd.run, hf, ho] at h
      | some a =>
        cases a with
        | some a => simp [findRec, Rd.run, hf, ho] at h
        | none =>
          simp [findRec, Rd.run, hf, ho] at h
          rcases List.mem_cons.1 hj with rfl | hj
          · exact ⟨r, hf, ho⟩
          · exact findRec_absent h j hj

/-- A confirmed candidate is one of the candidates, was read, and is what `ok` confirms. -/
theorem findRec_hit {α : Type} {ok : Bytes → Option (Option α)} {fetch : Nat → Option Bytes} :
    ∀ {l : List Nat} {i : Nat} {a : α}, ((findRec ok l).run fetch).1 = .hit i a →
      i ∈ l ∧ ∃ r, fetch i = some r ∧ ok r = some (some a)
  | [], _, _, h => by simp [findRec, Rd.run] at h
  | j :: rest, i, a, h => by
    cases hf : fetch j with
    | none => simp [findRec, Rd.run, hf] at h
    | some r =>
      cases ho : ok r with
      | none => simp [findRec, Rd.run, hf, ho] at h
      | some a' =>
        cases a' with
        | some a' =>
          simp [findRec, Rd.run, hf, ho] at h
          obtain ⟨rfl, rfl⟩ := h
          exact ⟨by simp, r, hf, ho⟩
        | none =>
          simp [findRec, Rd.run, hf, ho] at h
          obtain ⟨hm, hr⟩ := findRec_hit h
          exact ⟨by simp [hm], hr⟩

/-- A put keeps every record of the table but the one it replaces. -/
theorem slots_put_keep {m : Slots} {k k' : Bytes} {p n j : Nat} (h : j ∈ Slots.of m k')
    (hne : p ≠ 0 → j ≠ p - 1) : j ∈ Slots.of (Slots.put m k p n) k' := by
  by_cases he : slotOf k = slotOf k'
  · by_cases hp : p = 0
    · simp_all [Slots.of, Slots.put]
    · have h' : j ∈ (m.getD (slotOf k') []).erase (p - 1) := (List.mem_erase_of_ne (hne hp)).2 h
      simp_all [Slots.of, Slots.put]
  · simp_all [Slots.of, Slots.put, Std.HashMap.getD_insert]

theorem slots_put_new (m : Slots) (k : Bytes) (p n : Nat) : n ∈ Slots.of (Slots.put m k p n) k := by
  simp [Slots.of, Slots.put]

/-- What a scan never changes, and what it does to the record count and to `ident`. -/
theorem Store.scan_fixed (s : Store) (r : Bytes) : (s.scan r).n = s.n + 1 ∧ (s.scan r).card = s.card ∧
    (s.scan r).reg = s.reg ∧ (s.scan r).ident = identPut s.ident s.n r := by
  obtain ⟨card, reg, n, ident, obl, cp, cc, lm⟩ := s
  cases hu : unwrap r with
  | none => simp [Store.scan, hu]
  | some q =>
    obtain ⟨b, l⟩ := q
    by_cases h1 : tagOf b = 0x74
    · cases hx : cmdC.dec b <;> simp [Store.scan, hu, h1, hx]
    · by_cases h2 : tagOf b = 0x60
      · cases hx : stateC.dec b <;> simp [Store.scan, hu, h2, hx]
      · simp [Store.scan, hu, h1, h2]

theorem foldl_scan_fixed : ∀ (bs : List Bytes) (s : Store), (bs.foldl Store.scan s).n = s.n + bs.length ∧
    (bs.foldl Store.scan s).card = s.card ∧ (bs.foldl Store.scan s).reg = s.reg
  | [], s => ⟨rfl, rfl, rfl⟩
  | r :: rs, s => by
    obtain ⟨h1, h2, h3⟩ := foldl_scan_fixed rs (s.scan r)
    obtain ⟨g1, g2, g3, -⟩ := Store.scan_fixed s r
    simp only [List.foldl_cons, List.length_cons]
    exact ⟨by omega, by rw [h2, g2], by rw [h3, g3]⟩

/-- Every record of a key that a scan passes is among the candidates of that key, and stays among them. -/
theorem foldl_scan_ident : ∀ (bs : List Bytes) (s : Store) (k : Nat × Bytes),
    (∀ j ∈ Slots.of s.ident k.2, j ∈ Slots.of (bs.foldl Store.scan s).ident k.2) ∧
    ∀ (i : Nat) (r : Bytes), bs[i]? = some r → identKey r = some k →
      s.n + i ∈ Slots.of (bs.foldl Store.scan s).ident k.2
  | [], _, _ => ⟨fun _ h => h, fun i r h => by simp at h⟩
  | b :: bs, s, k => by
    obtain ⟨ih1, ih2⟩ := foldl_scan_ident bs (s.scan b) k
    obtain ⟨g1, -, -, g4⟩ := Store.scan_fixed s b
    have keep : ∀ j ∈ Slots.of s.ident k.2, j ∈ Slots.of (s.scan b).ident k.2 := by
      intro j hj
      rw [g4]
      unfold identPut
      cases identKey b with
      | none => exact hj
      | some k' => exact slots_put_keep hj (fun h => absurd rfl h)
    refine ⟨fun j hj => ih1 j (keep j hj), fun i r hi hk => ?_⟩
    cases i with
    | zero =>
      obtain rfl : b = r := by simpa using hi
      refine ih1 _ ?_
      rw [g4, Nat.add_zero]
      simp only [identPut, hk]
      exact slots_put_new _ _ _ _
    | succ i =>
      have hi' : bs[i]? = some r := by simpa using hi
      have := ih2 i r hi' hk
      rw [g1] at this
      rw [show s.n + (i + 1) = s.n + 1 + i by omega]
      exact this

/-- The store after a command is the scan of the log with that command's records: the tables a running shard holds
    are the ones opening its log gives. -/
theorem apply_inv {s : Store} {fetch : Nat → Option Bytes} {c : Cmd} {log : List Bytes} (hi : s.Inv log) :
    (apply s fetch c).2.2.Inv (log ++ (apply s fetch c).2.1) := by
  unfold apply applyView
  rcases hd : decideView (viewOf s fetch c) c s.n with ⟨d, _ | p, bs⟩
  · simpa using hi
  · show (bs.foldl Store.scan s).Inv (log ++ bs)
    obtain ⟨-, h2, h3⟩ := foldl_scan_fixed bs s
    have hi' : List.foldl Store.scan (Store.empty s.card s.reg) log = s := Eq.symm hi
    unfold Store.Inv
    rw [h2, h3, Store.ofLog, List.foldl_append, hi']

theorem loadRd_hit (s : Store) (fetch : Nat → Option Bytes) (c : Cmd) :
    ((loadRd s c).run fetch).1.hit = ((loadHit s c).run fetch).1 := by
  simp [loadRd, Rd.run_bind, Rd.run]

/-- A hit is a record of the log that holds the command's `cid`: the slot was confirmed against the record. -/
theorem hit_is_record {s : Store} {fetch : Nat → Option Bytes} {c : Cmd} {i : Nat} {x : CmdRec}
    {row : Option StateRow} (h : (viewOf s fetch c).hit = some (i, some x, row)) :
    ∃ r, fetch i = some r ∧ identKey r = some (identKeyOf c) := by
  have hh : ((loadHit s c).run fetch).1 = some (i, some x, row) := by rw [← loadRd_hit]; exact h
  unfold loadHit at hh
  rw [Rd.run_bind] at hh
  cases hfnd : ((findRec (keyIs (identKeyOf c)) (Slots.of s.ident (cidOfCmd c))).run fetch).1 with
  | hit j a =>
    rw [hfnd] at hh
    simp [Rd.run_bind, Rd.run] at hh
    obtain ⟨-, r, h1, h2⟩ := findRec_hit hfnd
    refine ⟨r, by rw [← hh.1]; exact h1, ?_⟩
    cases hk : identKey r with
    | none => simp [keyIs, hk] at h2
    | some k' =>
      by_cases he : k' = identKeyOf c
      · rw [he]
      · simp [keyIs, hk, he] at h2
  | absent => rw [hfnd] at hh; simp [Rd.run] at hh
  | unread => rw [hfnd] at hh; simp [Rd.run] at hh

/-- When the tables are the scan of the log and the command's `cid` is not found, no record of the log holds it. -/
theorem no_hit_no_record {s : Store} {fetch : Nat → Option Bytes} {c : Cmd} {log : List Bytes} (hi : s.Inv log)
    (hf : ∀ i, fetch i = log[i]?) (hv : (viewOf s fetch c).hit = none) :
    ∀ r ∈ log, identKey r ≠ some (identKeyOf c) := by
  intro r hm hk
  obtain ⟨i, hir⟩ := List.mem_iff_getElem?.1 hm
  have hs : s.ident = (Store.ofLog s.card s.reg log).ident := congrArg Store.ident hi
  have hmem : i ∈ Slots.of s.ident (cidOfCmd c) := by
    rw [hs]
    have := (foldl_scan_ident log (Store.empty s.card s.reg) (identKeyOf c)).2 i r hir hk
    simpa [Store.ofLog, Store.empty, identKeyOf] using this
  have hh : ((loadHit s c).run fetch).1 = none := by rw [← loadRd_hit]; exact hv
  unfold loadHit at hh
  rw [Rd.run_bind] at hh
  cases hfnd : ((findRec (keyIs (identKeyOf c)) (Slots.of s.ident (cidOfCmd c))).run fetch).1 with
  | hit j a => rw [hfnd] at hh; simp [Rd.run_bind, Rd.run] at hh
  | unread => rw [hfnd] at hh; simp [Rd.run] at hh
  | absent =>
    obtain ⟨r', h1, h2⟩ := findRec_absent hfnd i hmem
    rw [hf i, hir] at h1
    cases h1
    simp [keyIs, hk] at h2

/-- `command_once` (§9.2): applying any command to a store whose tables are the scan of the log it reads keeps them
    so, and keeps at most one command record of each `cid` in the log. -/
theorem command_once {s : Store} {fetch : Nat → Option Bytes} {c : Cmd} {log : List Bytes}
    (hi : s.Inv log) (hf : ∀ i, fetch i = log[i]?) (h1 : ∀ k, cmdCount log k ≤ 1) :
    (apply s fetch c).2.2.Inv (log ++ (apply s fetch c).2.1) ∧
      ∀ k, cmdCount (log ++ (apply s fetch c).2.1) k ≤ 1 := by
  refine ⟨apply_inv hi, ?_⟩
  unfold apply applyView
  rcases hd : decideView (viewOf s fetch c) c s.n with ⟨d, _ | p, bs⟩
  · simpa using h1
  · show ∀ k, cmdCount (log ++ bs) k ≤ 1
    obtain ⟨-, hv, hb, -⟩ := decideView_some hd
    obtain ⟨-, b, rest, rfl, hbk, hr⟩ := Plan.bytes_spec hb
    have h0 : log.countP (fun r => identKey r == some (0x74, cidOfCmd c)) = 0 := by
      rw [List.countP_eq_zero]
      intro r hm
      simpa [identKeyOf] using no_hit_no_record hi hf hv r hm
    have hrest : ∀ k, rest.countP (fun r => identKey r == some (0x74, k)) = 0 := by
      intro k
      rw [List.countP_eq_zero]
      intro r hm
      simpa using hr r hm k
    intro k
    unfold cmdCount
    rw [List.countP_append, List.countP_cons, hrest k, hbk]
    by_cases hk : k = cidOfCmd c
    · subst hk
      simp [h0]
    · simpa [Ne.symm hk, cmdCount] using h1 k

/-! ### The obligation table

    A state row takes the place of the row its link names (`Store.scan`).  That is sound when the named row is a
    state row of the same obligation (`ChainOk`).  The engine writes its rows so (`engine_log_chain`, in
    `EngineLog.lean`); that the checker accepts no other log is not proved. -/

/-- The state row a record holds, with its link. -/
def stateOf (r : Bytes) : Option (StateRow × Link) :=
  (unwrap r).bind fun q => if tagOf q.1 = 0x60 then (stateC.dec q.1).map (·, q.2) else none

/-- Record `j` of the log is a state row of obligation `ob`. -/
def RowAt (log : List Bytes) (ob : Bytes) (j : Nat) : Prop :=
  ∃ r row l, log[j]? = some r ∧ stateOf r = some (row, l) ∧ row.ob = ob

/-- Every state row that names a row before it names a state row of its own obligation. -/
def ChainOk (log : List Bytes) : Prop :=
  ∀ (i : Nat) (r : Bytes) (row : StateRow) (l : Link), log[i]? = some r → stateOf r = some (row, l) → l.prev ≠ 0 →
    RowAt log row.ob (l.prev - 1)

/-- For every obligation with a state row among the first `m` records, the table holds a state row of it. -/
def Held (log : List Bytes) (m : Nat) (obl : Slots) : Prop :=
  ∀ (ob : Bytes) (j : Nat), j < m → RowAt log ob j → ∃ j', j' ∈ Slots.of obl ob ∧ RowAt log ob j'

theorem Store.scan_obl (s : Store) (r : Bytes) : (s.scan r).obl =
    match stateOf r with
    | some (row, l) => Slots.put s.obl row.ob l.prev s.n
    | none => s.obl := by
  obtain ⟨card, reg, n, ident, obl, cp, cc, lm⟩ := s
  cases hu : unwrap r with
  | none => simp [Store.scan, stateOf, hu]
  | some q =>
    obtain ⟨b, l⟩ := q
    by_cases h1 : tagOf b = 0x74
    · cases hx : cmdC.dec b <;> simp [Store.scan, stateOf, hu, h1, hx]
    · by_cases h2 : tagOf b = 0x60
      · cases hx : stateC.dec b <;> simp [Store.scan, stateOf, hu, h2, hx]
      · simp [Store.scan, stateOf, hu, h1, h2]

theorem stateOf_body {r : Bytes} {row : StateRow} {l : Link} (h : stateOf r = some (row, l)) :
    (bodyOf r).bind stateC.dec = some row := by
  cases hu : unwrap r with
  | none => simp [stateOf, hu] at h
  | some q =>
    by_cases ht : tagOf q.1 = 0x60
    · cases hd : stateC.dec q.1 with
      | none => simp [stateOf, hu, ht, hd] at h
      | some row' =>
        simp [stateOf, hu, ht, hd] at h
        simpa [bodyOf, hu, hd] using h.1
    · simp [stateOf, hu, ht] at h

theorem held_step {log : List Bytes} (hc : ChainOk log) {s : Store} {r : Bytes} (hr : log[s.n]? = some r)
    (h : Held log s.n s.obl) : Held log (s.n + 1) (s.scan r).obl := by
  intro ob j hj hrow
  have hobl := Store.scan_obl s r
  cases hst : stateOf r with
  | none =>
    rw [hst] at hobl
    rw [hobl]
    have hne : j ≠ s.n := by
      rintro rfl
      obtain ⟨r', row, l, h1, h2, -⟩ := hrow
      rw [hr] at h1
      cases h1
      rw [hst] at h2
      cases h2
    exact h ob j (by omega) hrow
  | some q =>
    obtain ⟨row, l⟩ := q
    rw [hst] at hobl
    rw [hobl]
    by_cases hob : row.ob = ob
    · exact ⟨s.n, hob ▸ slots_put_new _ _ _ _, r, row, l, hr, hst, hob⟩
    · have hne : j ≠ s.n := by
        rintro rfl
        obtain ⟨r', row', l', h1, h2, h3⟩ := hrow
        rw [hr] at h1
        cases h1
        rw [hst] at h2
        cases h2
        exact hob h3
      obtain ⟨j', hm, hrow'⟩ := h ob j (by omega) hrow
      refine ⟨j', slots_put_keep hm (fun hp he => ?_), hrow'⟩
      obtain ⟨r1, row1, l1, a1, a2, a3⟩ := hc s.n r row l hr hst hp
      obtain ⟨r2, row2, l2, b1, b2, b3⟩ := hrow'
      rw [← he, b1] at a1
      cases a1
      rw [b2] at a2
      cases a2
      exact hob (a3.symm.trans b3)

theorem held_fold {log : List Bytes} (hc : ChainOk log) : ∀ (suf pre : List Bytes) (s : Store), pre ++ suf = log →
    s.n = pre.length → Held log s.n s.obl → Held log log.length (suf.foldl Store.scan s).obl
  | [], pre, s, hl, hn, h => by
    have hlen : log.length = s.n := by rw [← hl, hn]; simp
    rw [hlen]
    exact h
  | r :: suf, pre, s, hl, hn, h => by
    have hr : log[s.n]? = some r := by
      rw [← hl, hn, List.getElem?_append_right (Nat.le_refl _), Nat.sub_self]
      rfl
    have hn' : (s.scan r).n = (pre ++ [r]).length := by rw [(Store.scan_fixed s r).1, hn]; simp
    have hs := held_step hc hr h
    rw [← (Store.scan_fixed s r).1] at hs
    exact held_fold hc suf (pre ++ [r]) (s.scan r) (by simpa using hl) hn' hs

theorem loadRd_known (s : Store) (fetch : Nat → Option Bytes) (c : Cmd) :
    ((loadRd s c).run fetch).1.oblKnown = ((loadOb s c).run fetch).1.1 := by
  simp [loadRd, Rd.run_bind, Rd.run]

/-- When the tables are the scan of a log whose state rows chain within their obligations, an obligation the engine
    does not find has no state row in the log.  So an obligation the log holds is never opened a second time. -/
theorem unknown_obligation_has_no_row {s : Store} {fetch : Nat → Option Bytes} {c : Cmd} {log : List Bytes}
    {k : Bytes} (hi : s.Inv log) (hf : ∀ i, fetch i = log[i]?) (hc : ChainOk log) (hk : obKey c = some k)
    (hv : (viewOf s fetch c).oblKnown = false) : ∀ j, ¬ RowAt log k j := by
  intro j hrow
  have hj : j < log.length := by
    obtain ⟨r, _, _, h1, _⟩ := hrow
    obtain ⟨hlt, -⟩ := List.getElem?_eq_some_iff.1 h1
    exact hlt
  have hs : s.obl = (Store.ofLog s.card s.reg log).obl := congrArg Store.obl hi
  have held : Held log log.length s.obl := by
    rw [hs]
    exact held_fold hc log [] (Store.empty s.card s.reg) rfl rfl (fun _ j hj => absurd hj (Nat.not_lt_zero j))
  obtain ⟨j', hm, r', row', l', h1, h2, h3⟩ := held k j hj hrow
  have hh : ((loadOb s c).run fetch).1.1 = false := by rw [← loadRd_known]; exact hv
  simp only [loadOb, hk] at hh
  rw [Rd.run_bind] at hh
  cases hfnd : ((findRec (rowIs k) (Slots.of s.obl k)).run fetch).1 with
  | hit h a => rw [hfnd] at hh; by_cases hro : readsObl c <;> simp [hro, Rd.run_bind, Rd.run] at hh
  | unread => rw [hfnd] at hh; simp [Rd.run] at hh
  | absent =>
    obtain ⟨r, g1, g2⟩ := findRec_absent hfnd j' hm
    rw [hf j', h1] at g1
    cases g1
    simp [rowIs, stateOf_body h2, h3] at g2

/-! ### What a decided command writes: its markers and its state row -/

/-- Whether a command is decided from anything that has no class (§4 items 1 and 5): the obligation's own records
    so far, the source of the evidence the command carries, and evidence an opening brings.  A pack is rules, not
    evidence. -/
def noClassOf (v : View) (c : Cmd) : Bool :=
  match c.act with
  | .pack _ _ | .other _ => false
  | .population i => v.srcClass == 0 || !i.evidence.isEmpty
  | .payment _ _ => v.obl.any (·.noClass) || v.srcClass == 0
  | .evaluate _ _ => v.obl.any (·.noClass)

/-- The marker each record a command writes holds: a state row and a case record the command record's `lg`, and a
    fact `ecls` 0; nothing is marked carried (`lseq` 0). -/
def Body.clean (lg : Nat) : Body → Bool
  | .text _ _ => true
  | .state x _ => x.lg == lg && x.lseq == 0
  | .caseR x _ => x.lg == lg
  | .oblig x _ => x.ecls == 0
  | .cash x _ => x.ecls == 0
  | .mark _ _ => true

theorem mem_textsAt {e : Bytes} {a c : Nat} {b : Body} (h : b ∈ textsAt e a c) : ∃ t l, b = .text t l := by
  unfold textsAt at h
  split at h
  · simp at h
  · generalize partsFrom 0 e = ts at h
    induction ts generalizing a c with
    | nil => simp [linkTexts] at h
    | cons t ts ih =>
      simp only [linkTexts, List.mem_cons] at h
      rcases h with rfl | h
      · exact ⟨_, _, rfl⟩
      · exact ih h

@[simp] theorem textsAt_clean (e : Bytes) (a c lg : Nat) : (textsAt e a c).all (Body.clean lg) = true := by
  rw [List.all_eq_true]
  intro b hb
  obtain ⟨t, l, rfl⟩ := mem_textsAt hb
  rfl

/-- What every decided command writes (§4 item 1): its `lg` is `lgOf` of whether it was decided from anything with
    no class, every record holds that marker and none is marked carried, and the obligation keeps the same answer
    for the commands after it. -/
theorem core_marks {v : View} {c : Cmd} {f : Nat → Plan} (h : core v c = .ok f) (n : Nat) :
    (f n).lg = lgOf (noClassOf v c) ∧ (f n).body.all (Body.clean (f n).lg) = true ∧
      ∀ k o, (f n).obl = some (k, o) → o.noClass = noClassOf v c := by
  unfold core at h
  dsimp only at h
  repeat' split at h
  all_goals try (cases h; done)
  all_goals
    simp only [Except.ok.injEq] at h
    subst h
    simp_all [noClassOf, Body.clean, rowOf, show lgOf false = 0 from rfl]

/-- `legacy_marker_stable` (§9.2), for a command: it only appends records (`apply`), and none of them is marked
    carried: `lg` bit 0 clear on its command record, state rows and case records, `lseq` 0, and `ecls` 0 on its
    facts.  Only an import batch, which this step does not build, may write either mark. -/
theorem legacy_marker_stable {v : View} {c : Cmd} {n : Nat} {d : Disp} {p : Plan} {bs : List Bytes}
    (h : decideView v c n = (d, some p, bs)) :
    (p.cmd c).lg.testBit 0 = false ∧ (p.cmd c).lseq = 0 ∧ p.body.all (Body.clean (p.cmd c).lg) = true ∧
      p.bytes c = some bs := by
  obtain ⟨-, -, hbs, f, hf, rfl⟩ := decideView_some h
  obtain ⟨hl, hb, -⟩ := core_marks hf n
  refine ⟨?_, rfl, hb, hbs⟩
  show (f n).lg.testBit 0 = false
  rw [hl]
  exact (lgOf_bits _).2

/-- `legacy_cited` (§9.2), for the state rows and case records a command writes: `lg` bit 1 is set exactly when the
    command was decided from something with no class (`noClassOf`), and the obligation carries that answer on. -/
theorem legacy_cited {v : View} {c : Cmd} {n : Nat} {d : Disp} {p : Plan} {bs : List Bytes}
    (h : decideView v c n = (d, some p, bs)) :
    p.lg.testBit 1 = noClassOf v c ∧ ∀ k o, p.obl = some (k, o) → o.noClass = noClassOf v c := by
  obtain ⟨-, -, -, f, hf, rfl⟩ := decideView_some h
  obtain ⟨hl, -, ho⟩ := core_marks hf n
  exact ⟨by rw [hl]; exact (lgOf_bits _).1, ho⟩

/-- The result Lean gives for a command that writes a state row: `evaluate` on an opening's input or on the
    obligation's input at the command's time, and for a payment or reversal the result of Lean's payment rule
    (for an alias, `evaluate` on the input after it). -/
def leanResult (v : View) (c : Cmd) : Option FinancialResult :=
  match c.act, v.obl with
  | .population i, _ => evaluate i
  | .payment _ pc, some o =>
    match o.led.outcome ⟨c.atMs, c.exprev, pc⟩ with
    | .mutated _ _ _ res => some res
    | .alias _ _ post => evaluate post
    | _ => none
  | .evaluate _ _, some o => evaluate { o.led.input with evaluatedAt := c.atMs }
  | _, _ => none

def Body.row? : Body → Option StateRow
  | .state x _ => some x
  | _ => none

/-- A plan's state row: the last `state` record it writes. -/
def Plan.row (p : Plan) : Option StateRow := p.body.reverse.findSome? Body.row?

@[simp] theorem textsAt_row (e : Bytes) (a c : Nat) : (textsAt e a c).reverse.findSome? Body.row? = none := by
  rw [List.findSome?_eq_none_iff]
  intro b hb
  obtain ⟨t, l, rfl⟩ := mem_textsAt (List.mem_reverse.mp hb)
  rfl

/-- The revision Lean's rule gives the row of a command with result `res`: the result's own, but for an alias the
    revision of the input after it, which an alias does not raise. -/
def leanRev (v : View) (c : Cmd) (res : FinancialResult) : Nat :=
  match c.act, v.obl with
  | .payment _ pc, some o =>
    match o.led.outcome ⟨c.atMs, c.exprev, pc⟩ with
    | .alias _ _ post => post.beforeRevision
    | _ => res.afterRevision
  | _, _ => res.afterRevision

/-- The cents Lean's rule gives the row of a command: the amount of the payment Lean wrote for a recorded or a
    reversed payment, and 0 for every other command. -/
def leanCents (v : View) (c : Cmd) : Nat :=
  match c.act, v.obl with
  | .payment _ pc, some o =>
    match o.led.outcome ⟨c.atMs, c.exprev, pc⟩ with
    | .mutated .RECORDED w _ _ => (w.payment.map (·.amountCents)).getD 0
    | .mutated .REVERSED w _ _ => (w.payment.map (·.amountCents)).getD 0
    | _ => 0
  | _, _ => 0

/-- `state_row_is_evaluate` (§9.2), for a command that is not a pack: it writes a state row (`Plan.row`); that row
    holds exactly the amounts, flags and statuses of Lean's result on the obligation's input and the command; its
    revision is the one Lean's rule gives (`leanRev`: the result's, and for an alias the unraised one); and its
    cents are the amount of the payment Lean wrote, or 0 (`leanCents`). -/
theorem state_row_is_evaluate {v : View} {c : Cmd} {f : Nat → Plan} (h : core v c = .ok f) (n : Nat)
    (hp : kindOf c.act ≠ 1) :
    ∃ res row, leanResult v c = some res ∧ (f n).row = some row ∧ row.rev = leanRev v c res ∧
      stateAgree res (leanCents v c) { row with rev := res.afterRevision } = true := by
  unfold core at h
  dsimp only at h
  repeat' split at h
  all_goals try (cases h; done)
  all_goals
    simp only [Except.ok.injEq] at h
    subst h
    simp_all [leanResult, leanRev, leanCents, kindOf, stateAgree, rowOf, Plan.row, Body.row?, List.findSome?_cons]

/-! ## Checks of the two refusals no log of a test can reach or should hold -/

private def guardPack : ControlPack :=
  { packId := "pack-1", stateId := "s", deploymentId := "d", programId := "p", periodId := "2026", currency := "USD",
    version := 1, sourceRefs := ["source:v1"], effectiveStart := 100, effectiveEnd := 200, recordedAt := 1,
    approvedAt := 2, calculationRuleId := "calculation:per-recipient:v1",
    adjustmentRuleId := "adjustment:offset:v1", authorizedRoles := BlindLedger.Financial.supportedRoles,
    expectedTests := BlindLedger.Financial.supportedTestsV1, digest := zeros BlindLedger.Financial.digestBytes,
    status := .APPROVED }

#guard BlindLedger.Financial.controlPackWellFormed guardPack

private def guardView (lastMs : Nat) : View :=
  { card := ⟨false, false, false, false⟩, srcClass := 1, hit := none, obl := none, pack := none, cmdPrev := 0,
    cmdCount := 0, lastMs, oblKnown := false, oblRead := false, packNamed := false }

private def guardCmd (atMs : Nat) : Cmd :=
  { act := .pack guardPack ⟨1, 1⟩, scope := scopeOfPack guardPack, atMs, exprev := none, actor := zeros 32, role := 0, attr := 2,
    src := 1 }

-- `ROWS`: a command whose records would reach `rowsCap` is refused and writes nothing; lower, it is admitted.
#guard (decideView (guardView 0) (guardCmd 5) (rowsCap - 1)).1 == .refused .ROWS
#guard (decideView (guardView 0) (guardCmd 5) (rowsCap - 1)).2.2.isEmpty
#guard (decideView (guardView 0) (guardCmd 5) (rowsCap - 10)).1 == .admitted (rowsCap - 10)
-- `TIME`: a command earlier than the one before it, or at `2^63` or later, is refused and writes nothing.
#guard (decideView (guardView 6) (guardCmd 5) 0).1 == .refused .TIME
#guard (decideView (guardView 6) (guardCmd 6) 0).1 == .admitted 0
#guard (decideView (guardView 0) (guardCmd (2 ^ 63)) 0).1 == .refused .TIME
-- A pack or an opening that states an expected revision is refused and writes nothing: the checker requires
-- `exprev` 0 on both.
#guard (decideView (guardView 0) { guardCmd 5 with exprev := some 0 } 0).1 == .refused .MALFORMED
#guard (decideView (guardView 0) { guardCmd 5 with exprev := some 0 } 0).2.2.isEmpty

-- The opening's input is a placeholder: the expected revision is refused before the pack or the input is looked at,
-- and without it the same command is refused for its unknown pack.
private def guardInput : FinancialInput :=
  { context := { ownerId := "o", mode := .TEST, provenance := .ROOT, stateId := "s", deploymentId := "d",
                 programId := "p", periodId := "2026", populationId := "pop", itemId := "item",
                 obligationId := "ob", currency := "USD" },
    authority := { authorityId := "a", epoch := 0, digest := [], syntheticOnly := true, actors := [] },
    pack := guardPack,
    obligation := { populationId := "pop", itemId := "item", obligationId := "ob", owedCents := 0, dueAt := 0,
                    ruleVersion := 1, reportingComplete := false },
    beforeRevision := 0, evaluatedAt := 5, payments := [], claims := [], determinations := [], evidence := [],
    conflicts := [], cases := [], actions := [] }

private def guardOpen (exprev : Option Nat) : Cmd := { guardCmd 5 with exprev, act := .population guardInput }

#guard (decideView (guardView 0) (guardOpen (some 0)) 0).1 == .refused .MALFORMED
#guard (decideView (guardView 0) (guardOpen (some 0)) 0).2.2.isEmpty
#guard (decideView (guardView 0) (guardOpen none) 0).1 == .refused .PACK_UNKNOWN

/-- The command record of `guardCmd 5`, naming the state row `result - 1`. -/
private def guardRec (result : Nat) : CmdRec :=
  let c := guardCmd 5
  { ckind := 1, cid := cidOfCmd c, rqd := rqdIn c none .recorded, lrq := zeros 64, actor := zeros 32, atMs := 5,
    role := 0, attr := 2, exprev := 0, result, lseq := 0, epoch := 0, lg := 0, nt := 0 }

/-- A log of two command records whose `cid`s share their first eight bytes, and its store: record 0 is the command
    of `guardCmd 5`, record 1 another's. -/
private def guardLog (result : Nat) : Store × (Nat → Option Bytes) :=
  let x := guardRec result
  let log := [encFull (full cmdC x ⟨0, 1⟩),
              encFull (full cmdC { x with cid := x.cid.take 8 ++ zeros 24 } ⟨1, 2⟩)].filterMap id
  (Store.ofLog ⟨false, false, false, false⟩ #[0, 1] log, fun i => log[i]?)

#guard (guardLog 0).1.n == 2
-- `STORE_READ`: a known command whose record names a state row the log does not hold is refused and writes nothing;
-- with no row named, the same record answers the retry.
#guard (apply (guardLog 5).1 (guardLog 5).2 (guardCmd 5)).1 == .refused .STORE_READ
#guard (apply (guardLog 5).1 (guardLog 5).2 (guardCmd 5)).2.1.isEmpty
#guard (apply (guardLog 0).1 (guardLog 0).2 (guardCmd 5)).1 == .duplicate 0
-- Two keys in one slot: the newer record is read, is another command's, and the older is found.
#guard ((loadRd (guardLog 0).1 (guardCmd 5)).run (guardLog 0).2).2 == [1, 0]
-- A record the tables name that cannot be read: `STORE_READ`, never "not seen before".
#guard (apply (guardLog 0).1 (fun _ => none) (guardCmd 5)).1 == .refused .STORE_READ
-- Two obligations in one slot: a state row replaces the row before it in its own chain and leaves the other's.
#guard Slots.of (Slots.put (Slots.put (Slots.put {} (zeros 32) 0 3) (zeros 8 ++ zeros 24 |>.set 31 1) 0 5)
  (zeros 32) 4 9) (zeros 32) == [9, 5]

end BlindLedger.Gate.Obligations
