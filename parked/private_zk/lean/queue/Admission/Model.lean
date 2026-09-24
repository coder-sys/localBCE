import Std.Tactic
import BlindLedger.Sha3

namespace BlindLedger.Admission

abbrev Bytes := ByteArray

def inputMagic : List UInt8 :=
  [UInt8.ofNat 66, UInt8.ofNat 76, UInt8.ofNat 65, UInt8.ofNat 68,
   UInt8.ofNat 73, UInt8.ofNat 78, UInt8.ofNat 48, UInt8.ofNat 49]

def outputMagic : List UInt8 :=
  [UInt8.ofNat 66, UInt8.ofNat 76, UInt8.ofNat 65, UInt8.ofNat 68,
   UInt8.ofNat 79, UInt8.ofNat 85, UInt8.ofNat 84, UInt8.ofNat 49]

def wireVersion : UInt8 := UInt8.ofNat 1

def counterMax : Nat := 2 ^ 32

def wireNatMax : Nat := 2 ^ 64 - 1

inductive Op
  | issue
  | sourceAdmit
  | sourceStart
  | sourceFinishSuccess
  | sourceFinishUnknown
  | verifierReserve
  | verifierFinishAccepted
  | verifierFinishRejected
  | verifierFinishAborted
  | verifierFinishUnknown
  | recover
  deriving DecidableEq, Repr

inductive BatchPhase
  | awaiting
  | queued
  | leased
  | verified
  | rejected
  | held
  deriving DecidableEq, Repr

inductive SourcePhase
  | absent
  | authorized
  | started
  | completed
  | unknown
  deriving DecidableEq, Repr

inductive VerifierPhase
  | unreserved
  | started
  | completed
  | unknown
  deriving DecidableEq, Repr

inductive TerminalKind
  | none
  | accepted
  | rejected
  | aborted
  | unknown
  deriving DecidableEq, Repr

inductive DecisionCode
  | ok
  | overflow
  | illegalTransition
  | inconsistentState
  | wireOverflow
  deriving DecidableEq, Repr

structure Input where
  op : Op
  batch : BatchPhase
  source : SourcePhase
  verifier : VerifierPhase
  terminal : TerminalKind
  proofUsed : Nat
  proofCap : Nat
  sourceAUsed : Nat
  sourceACap : Nat
  sourceSUsed : Nat
  sourceSCap : Nat
  sourceMUsed : Nat
  sourceMCap : Nat
  sourceUUsed : Nat
  sourceUCap : Nat
  verifierVUsed : Nat
  verifierVCap : Nat
  deriving Repr

structure Decision where
  accepted : Bool
  code : DecisionCode
  op : Op
  batch : BatchPhase
  source : SourcePhase
  verifier : VerifierPhase
  terminal : TerminalKind
  proofUsed : Nat
  proofCap : Nat
  sourceAUsed : Nat
  sourceACap : Nat
  sourceSUsed : Nat
  sourceSCap : Nat
  sourceMUsed : Nat
  sourceMCap : Nat
  sourceUUsed : Nat
  sourceUCap : Nat
  verifierVUsed : Nat
  verifierVCap : Nat
  deriving Repr

def opCode : Op → UInt8
  | .issue => UInt8.ofNat 1
  | .sourceAdmit => UInt8.ofNat 2
  | .sourceStart => UInt8.ofNat 3
  | .sourceFinishSuccess => UInt8.ofNat 4
  | .sourceFinishUnknown => UInt8.ofNat 5
  | .verifierReserve => UInt8.ofNat 6
  | .verifierFinishAccepted => UInt8.ofNat 7
  | .verifierFinishRejected => UInt8.ofNat 8
  | .verifierFinishAborted => UInt8.ofNat 9
  | .verifierFinishUnknown => UInt8.ofNat 10
  | .recover => UInt8.ofNat 11

def batchCode : BatchPhase → UInt8
  | .awaiting => UInt8.ofNat 0
  | .queued => UInt8.ofNat 1
  | .leased => UInt8.ofNat 2
  | .verified => UInt8.ofNat 3
  | .rejected => UInt8.ofNat 4
  | .held => UInt8.ofNat 5

def sourceCode : SourcePhase → UInt8
  | .absent => UInt8.ofNat 0
  | .authorized => UInt8.ofNat 1
  | .started => UInt8.ofNat 2
  | .completed => UInt8.ofNat 3
  | .unknown => UInt8.ofNat 4

def verifierCode : VerifierPhase → UInt8
  | .unreserved => UInt8.ofNat 0
  | .started => UInt8.ofNat 1
  | .completed => UInt8.ofNat 2
  | .unknown => UInt8.ofNat 3

def terminalCode : TerminalKind → UInt8
  | .none => UInt8.ofNat 0
  | .accepted => UInt8.ofNat 1
  | .rejected => UInt8.ofNat 2
  | .aborted => UInt8.ofNat 3
  | .unknown => UInt8.ofNat 4

def codeByte : DecisionCode → UInt8
  | .ok => UInt8.ofNat 0
  | .overflow => UInt8.ofNat 1
  | .illegalTransition => UInt8.ofNat 2
  | .inconsistentState => UInt8.ofNat 3
  | .wireOverflow => UInt8.ofNat 4

def decodeOp : UInt8 → Option Op
  | value => match value.toNat with
    | 1 => some .issue
    | 2 => some .sourceAdmit
    | 3 => some .sourceStart
    | 4 => some .sourceFinishSuccess
    | 5 => some .sourceFinishUnknown
    | 6 => some .verifierReserve
    | 7 => some .verifierFinishAccepted
    | 8 => some .verifierFinishRejected
    | 9 => some .verifierFinishAborted
    | 10 => some .verifierFinishUnknown
    | 11 => some .recover
    | _ => none

def decodeBatch : UInt8 → Option BatchPhase
  | value => match value.toNat with
    | 0 => some .awaiting
    | 1 => some .queued
    | 2 => some .leased
    | 3 => some .verified
    | 4 => some .rejected
    | 5 => some .held
    | _ => none

def decodeSource : UInt8 → Option SourcePhase
  | value => match value.toNat with
    | 0 => some .absent
    | 1 => some .authorized
    | 2 => some .started
    | 3 => some .completed
    | 4 => some .unknown
    | _ => none

def decodeVerifier : UInt8 → Option VerifierPhase
  | value => match value.toNat with
    | 0 => some .unreserved
    | 1 => some .started
    | 2 => some .completed
    | 3 => some .unknown
    | _ => none

def decodeTerminal : UInt8 → Option TerminalKind
  | value => match value.toNat with
    | 0 => some .none
    | 1 => some .accepted
    | 2 => some .rejected
    | 3 => some .aborted
    | 4 => some .unknown
    | _ => none

def readByte : List UInt8 → Option (UInt8 × List UInt8)
  | [] => none
  | value :: rest => some (value, rest)

def readNat64LE (bytes : List UInt8) : Option (Nat × List UInt8) := do
  let (b0, rest) ← readByte bytes
  let (b1, rest) ← readByte rest
  let (b2, rest) ← readByte rest
  let (b3, rest) ← readByte rest
  let (b4, rest) ← readByte rest
  let (b5, rest) ← readByte rest
  let (b6, rest) ← readByte rest
  let (b7, rest) ← readByte rest
  pure
    (b0.toNat + b1.toNat * 256 + b2.toNat * 65_536 +
      b3.toNat * 16_777_216 + b4.toNat * 4_294_967_296 +
      b5.toNat * 1_099_511_627_776 + b6.toNat * 281_474_976_710_656 +
      b7.toNat * 72_057_594_037_927_936, rest)

def nat64LE (value : Nat) : List UInt8 :=
  [UInt8.ofNat (value % 256),
   UInt8.ofNat ((value / 256) % 256),
   UInt8.ofNat ((value / 65_536) % 256),
   UInt8.ofNat ((value / 16_777_216) % 256),
   UInt8.ofNat ((value / 4_294_967_296) % 256),
   UInt8.ofNat ((value / 1_099_511_627_776) % 256),
   UInt8.ofNat ((value / 281_474_976_710_656) % 256),
   UInt8.ofNat ((value / 72_057_594_037_927_936) % 256)]

def decodeInput (data : Bytes) : Option Input := do
  if data.size ≠ 110 then none else
    let raw := data.toList
    if raw.take 8 ≠ inputMagic then none else
      let rest := raw.drop 8
      let (version, rest) ← readByte rest
      if version ≠ wireVersion then none else
        let (opByte, rest) ← readByte rest
        let (batchByte, rest) ← readByte rest
        let (sourceByte, rest) ← readByte rest
        let (verifierByte, rest) ← readByte rest
        let (terminalByte, rest) ← readByte rest
        let op ← decodeOp opByte
        let batch ← decodeBatch batchByte
        let source ← decodeSource sourceByte
        let verifier ← decodeVerifier verifierByte
        let terminal ← decodeTerminal terminalByte
        let (proofUsed, rest) ← readNat64LE rest
        let (proofCap, rest) ← readNat64LE rest
        let (sourceAUsed, rest) ← readNat64LE rest
        let (sourceACap, rest) ← readNat64LE rest
        let (sourceSUsed, rest) ← readNat64LE rest
        let (sourceSCap, rest) ← readNat64LE rest
        let (sourceMUsed, rest) ← readNat64LE rest
        let (sourceMCap, rest) ← readNat64LE rest
        let (sourceUUsed, rest) ← readNat64LE rest
        let (sourceUCap, rest) ← readNat64LE rest
        let (verifierVUsed, rest) ← readNat64LE rest
        let (verifierVCap, rest) ← readNat64LE rest
        if rest ≠ [] then none else
          pure
            { op := op
              batch := batch
              source := source
              verifier := verifier
              terminal := terminal
              proofUsed := proofUsed
              proofCap := proofCap
              sourceAUsed := sourceAUsed
              sourceACap := sourceACap
              sourceSUsed := sourceSUsed
              sourceSCap := sourceSCap
              sourceMUsed := sourceMUsed
              sourceMCap := sourceMCap
              sourceUUsed := sourceUUsed
              sourceUCap := sourceUCap
              verifierVUsed := verifierVUsed
              verifierVCap := verifierVCap }

def stateBytes (input : Input) : List UInt8 :=
  [batchCode input.batch, sourceCode input.source, verifierCode input.verifier,
   terminalCode input.terminal] ++
    nat64LE input.proofUsed ++ nat64LE input.proofCap ++
    nat64LE input.sourceAUsed ++ nat64LE input.sourceACap ++
    nat64LE input.sourceSUsed ++ nat64LE input.sourceSCap ++
    nat64LE input.sourceMUsed ++ nat64LE input.sourceMCap ++
    nat64LE input.sourceUUsed ++ nat64LE input.sourceUCap ++
    nat64LE input.verifierVUsed ++ nat64LE input.verifierVCap

def accept (input : Input) (batch : BatchPhase) (source : SourcePhase)
    (verifier : VerifierPhase) (terminal : TerminalKind)
    (proofUsed sourceAUsed sourceSUsed sourceMUsed sourceUUsed verifierVUsed : Nat) : Decision :=
  { accepted := true
    code := .ok
    op := input.op
    batch := batch
    source := source
    verifier := verifier
    terminal := terminal
    proofUsed := proofUsed
    proofCap := input.proofCap
    sourceAUsed := sourceAUsed
    sourceACap := input.sourceACap
    sourceSUsed := sourceSUsed
    sourceSCap := input.sourceSCap
    sourceMUsed := sourceMUsed
    sourceMCap := input.sourceMCap
    sourceUUsed := sourceUUsed
    sourceUCap := input.sourceUCap
    verifierVUsed := verifierVUsed
    verifierVCap := input.verifierVCap }

def reject (input : Input) (code : DecisionCode) : Decision :=
  { accepted := false
    code := code
    op := input.op
    batch := input.batch
    source := input.source
    verifier := input.verifier
    terminal := input.terminal
    proofUsed := input.proofUsed
    proofCap := input.proofCap
    sourceAUsed := input.sourceAUsed
    sourceACap := input.sourceACap
    sourceSUsed := input.sourceSUsed
    sourceSCap := input.sourceSCap
    sourceMUsed := input.sourceMUsed
    sourceMCap := input.sourceMCap
    sourceUUsed := input.sourceUUsed
    sourceUCap := input.sourceUCap
    verifierVUsed := input.verifierVUsed
    verifierVCap := input.verifierVCap }

def checkedAdd (used amount cap : Nat) : Option Nat :=
  if used ≤ counterMax ∧ amount ≤ counterMax ∧ cap ≤ counterMax ∧
      used ≤ cap ∧ amount ≤ cap - used then
    some (used + amount)
  else
    none

def countersValid (input : Input) : Bool :=
  [input.proofUsed, input.proofCap, input.sourceAUsed, input.sourceACap,
   input.sourceSUsed, input.sourceSCap, input.sourceMUsed, input.sourceMCap,
   input.sourceUUsed, input.sourceUCap, input.verifierVUsed, input.verifierVCap].all
    (fun value => value ≤ wireNatMax)

def stateValid (input : Input) : Bool :=
  match input.batch, input.source, input.verifier, input.terminal with
  | .verified, _, .completed, .accepted => true
  | .rejected, _, .completed, .rejected => true
  | .held, _, .unknown, .aborted => true
  | .held, _, .unknown, .unknown => true
  | .held, .unknown, _, .unknown => true
  | .held, .absent, .unreserved, .aborted => true
  | .held, .completed, .unreserved, .aborted => true
  | .awaiting, .absent, .unreserved, .none => true
  | .awaiting, .authorized, .unreserved, .none => true
  | .awaiting, .started, .unreserved, .none => true
  | .awaiting, .completed, .unreserved, .none => true
  | .queued, .completed, .unreserved, .none => true
  | .queued, .absent, .unreserved, .none => true
  | .leased, .absent, .unreserved, .none => true
  | .leased, .completed, .unreserved, .none => true
  | .leased, .absent, .started, .none => true
  | .leased, .completed, .started, .none => true
  | .leased, .unknown, .unknown, .unknown => true
  | _, _, _, _ => false

def evaluate (input : Input) : Decision :=
  if !countersValid input then
    reject input .wireOverflow
  else if !stateValid input then
    reject input .inconsistentState
  else
    match input.op with
    | .issue =>
        if input.batch ≠ .awaiting ∨ input.source ≠ .absent ∨
            input.verifier ≠ .unreserved ∨ input.terminal ≠ .none then
          reject input .illegalTransition
        else
          match checkedAdd input.proofUsed 101 input.proofCap,
            checkedAdd input.sourceUUsed 1 input.sourceUCap with
          | some proofAfter, some sourceUAfter =>
              accept input .awaiting .absent .unreserved .none proofAfter
                input.sourceAUsed input.sourceSUsed input.sourceMUsed sourceUAfter
                input.verifierVUsed
          | _, _ => reject input .overflow
    | .sourceAdmit =>
        if input.batch ≠ .awaiting ∨ input.source ≠ .absent ∨
            input.terminal ≠ .none then
          reject input .illegalTransition
        else
          match checkedAdd input.sourceAUsed 1 input.sourceACap,
            checkedAdd input.sourceSUsed 4096 input.sourceSCap,
            checkedAdd input.sourceMUsed 100 input.sourceMCap with
          | some aAfter, some sAfter, some mAfter =>
              accept input .awaiting .authorized .unreserved .none input.proofUsed
                aAfter sAfter mAfter input.sourceUUsed input.verifierVUsed
          | _, _, _ => reject input .overflow
    | .sourceStart =>
        if input.batch ≠ .awaiting ∨ input.source ≠ .authorized ∨
            input.terminal ≠ .none then
          reject input .illegalTransition
        else
          accept input .awaiting .started .unreserved .none input.proofUsed
            input.sourceAUsed input.sourceSUsed input.sourceMUsed input.sourceUUsed
            input.verifierVUsed
    | .sourceFinishSuccess =>
        if input.batch ≠ .awaiting ∨ input.source ≠ .started ∨
            input.terminal ≠ .none then
          reject input .illegalTransition
        else
          accept input .awaiting .completed .unreserved .none input.proofUsed
            input.sourceAUsed input.sourceSUsed input.sourceMUsed input.sourceUUsed
            input.verifierVUsed
    | .sourceFinishUnknown =>
        if input.batch ≠ .awaiting ∨ input.source ≠ .started ∨
            input.terminal ≠ .none then
          reject input .illegalTransition
        else
          accept input .held .unknown .unreserved .unknown input.proofUsed
            input.sourceAUsed input.sourceSUsed input.sourceMUsed input.sourceUUsed
            input.verifierVUsed
    | .verifierReserve =>
        if input.batch ≠ .leased ∨ input.verifier ≠ .unreserved ∨
            input.terminal ≠ .none ∨ input.source = .authorized ∨
            input.source = .started ∨ input.source = .unknown then
          reject input .illegalTransition
        else
          match checkedAdd input.verifierVUsed 1 input.verifierVCap with
          | some vAfter =>
              accept input .leased input.source .started .none input.proofUsed
                input.sourceAUsed input.sourceSUsed input.sourceMUsed input.sourceUUsed vAfter
          | none => reject input .overflow
    | .verifierFinishAccepted =>
        if input.batch ≠ .leased ∨ input.verifier ≠ .started ∨
            input.terminal ≠ .none then
          reject input .illegalTransition
        else
          accept input .verified input.source .completed .accepted input.proofUsed
            input.sourceAUsed input.sourceSUsed input.sourceMUsed input.sourceUUsed
            input.verifierVUsed
    | .verifierFinishRejected =>
        if input.batch ≠ .leased ∨ input.verifier ≠ .started ∨
            input.terminal ≠ .none then
          reject input .illegalTransition
        else
          accept input .rejected input.source .completed .rejected input.proofUsed
            input.sourceAUsed input.sourceSUsed input.sourceMUsed input.sourceUUsed
            input.verifierVUsed
    | .verifierFinishAborted =>
        if input.batch ≠ .leased ∨ input.verifier ≠ .started ∨
            input.terminal ≠ .none then
          reject input .illegalTransition
        else
          accept input .held input.source .unknown .aborted input.proofUsed
            input.sourceAUsed input.sourceSUsed input.sourceMUsed input.sourceUUsed
            input.verifierVUsed
    | .verifierFinishUnknown =>
        if input.batch ≠ .leased ∨ input.verifier ≠ .started ∨
            input.terminal ≠ .none then
          reject input .illegalTransition
        else
          accept input .held input.source .unknown .unknown input.proofUsed
            input.sourceAUsed input.sourceSUsed input.sourceMUsed input.sourceUUsed
            input.verifierVUsed
    | .recover =>
        if input.terminal ≠ .none ∨
            (input.batch ≠ .awaiting ∧ input.batch ≠ .queued ∧ input.batch ≠ .leased) then
          reject input .illegalTransition
        else
          let sourceAfter :=
            if input.source = .authorized ∨ input.source = .started then .unknown else input.source
          let verifierAfter :=
            if input.verifier = .started then .unknown else input.verifier
          let terminalAfter :=
            if sourceAfter = .unknown ∨ verifierAfter = .unknown then .unknown else .aborted
          accept input .held
            sourceAfter verifierAfter terminalAfter input.proofUsed input.sourceAUsed input.sourceSUsed input.sourceMUsed
            input.sourceUUsed input.verifierVUsed

def decisionBytes (decision : Decision) : Bytes :=
  (outputMagic ++ [wireVersion, if decision.accepted then UInt8.ofNat 1 else UInt8.ofNat 0,
      codeByte decision.code, opCode decision.op] ++
    [batchCode decision.batch, sourceCode decision.source, verifierCode decision.verifier,
      terminalCode decision.terminal] ++
    nat64LE decision.proofUsed ++ nat64LE decision.proofCap ++
    nat64LE decision.sourceAUsed ++ nat64LE decision.sourceACap ++
    nat64LE decision.sourceSUsed ++ nat64LE decision.sourceSCap ++
    nat64LE decision.sourceMUsed ++ nat64LE decision.sourceMCap ++
    nat64LE decision.sourceUUsed ++ nat64LE decision.sourceUCap ++
    nat64LE decision.verifierVUsed ++ nat64LE decision.verifierVCap).toByteArray

def malformedDecision : Decision :=
  { accepted := false
    code := .wireOverflow
    op := .issue
    batch := .awaiting
    source := .absent
    verifier := .unreserved
    terminal := .none
    proofUsed := 0
    proofCap := 0
    sourceAUsed := 0
    sourceACap := 0
    sourceSUsed := 0
    sourceSCap := 0
    sourceMUsed := 0
    sourceMCap := 0
    sourceUUsed := 0
    sourceUCap := 0
    verifierVUsed := 0
    verifierVCap := 0 }

theorem checkedAdd_sound (used amount cap after : Nat)
    (h : checkedAdd used amount cap = some after) :
    used ≤ after ∧ after ≤ cap := by
  unfold checkedAdd at h
  split at h <;> try contradiction
  simp_all
  omega

theorem checkedAdd_never_refunds (used amount cap after : Nat)
    (h : checkedAdd used amount cap = some after) : used ≤ after := by
  exact (checkedAdd_sound used amount cap after h).1

theorem terminal_partition (kind : TerminalKind) :
    kind = .none ∨ kind = .accepted ∨ kind = .rejected ∨
      kind = .aborted ∨ kind = .unknown := by
  cases kind <;> simp

theorem accepted_and_rejected_disjoint (left right : TerminalKind)
    (hLeft : left = .accepted) (hRight : right = .rejected) : left ≠ right := by
  simp [hLeft, hRight]

theorem verifier_reservation_is_monotone (input : Input) (after : Nat)
    (h : checkedAdd input.verifierVUsed 1 input.verifierVCap = some after) :
    input.verifierVUsed ≤ after ∧ after ≤ input.verifierVCap := by
  exact checkedAdd_sound input.verifierVUsed 1 input.verifierVCap after h

def admissionCapsBounded (input : Input) : Prop :=
  input.proofCap ≤ counterMax ∧
    input.sourceACap ≤ counterMax ∧
    input.sourceSCap ≤ counterMax ∧
    input.sourceMCap ≤ counterMax ∧
    input.sourceUCap ≤ counterMax ∧
    input.verifierVCap ≤ counterMax

def countersNeverDecrease (input : Input) (decision : Decision) : Prop :=
  input.proofUsed ≤ decision.proofUsed ∧
    input.sourceAUsed ≤ decision.sourceAUsed ∧
    input.sourceSUsed ≤ decision.sourceSUsed ∧
    input.sourceMUsed ≤ decision.sourceMUsed ∧
    input.sourceUUsed ≤ decision.sourceUUsed ∧
    input.verifierVUsed ≤ decision.verifierVUsed

def countersWithinCaps (decision : Decision) : Prop :=
  decision.proofUsed ≤ decision.proofCap ∧
    decision.sourceAUsed ≤ decision.sourceACap ∧
    decision.sourceSUsed ≤ decision.sourceSCap ∧
    decision.sourceMUsed ≤ decision.sourceMCap ∧
    decision.sourceUUsed ≤ decision.sourceUCap ∧
    decision.verifierVUsed ≤ decision.verifierVCap

def capsPreserved (input : Input) (decision : Decision) : Prop :=
  decision.proofCap = input.proofCap ∧
    decision.sourceACap = input.sourceACap ∧
    decision.sourceSCap = input.sourceSCap ∧
    decision.sourceMCap = input.sourceMCap ∧
    decision.sourceUCap = input.sourceUCap ∧
    decision.verifierVCap = input.verifierVCap

def decisionStateValid (decision : Decision) : Bool :=
  stateValid
    { op := decision.op
      batch := decision.batch
      source := decision.source
      verifier := decision.verifier
      terminal := decision.terminal
      proofUsed := decision.proofUsed
      proofCap := decision.proofCap
      sourceAUsed := decision.sourceAUsed
      sourceACap := decision.sourceACap
      sourceSUsed := decision.sourceSUsed
      sourceSCap := decision.sourceSCap
      sourceMUsed := decision.sourceMUsed
      sourceMCap := decision.sourceMCap
      sourceUUsed := decision.sourceUUsed
      sourceUCap := decision.sourceUCap
      verifierVUsed := decision.verifierVUsed
      verifierVCap := decision.verifierVCap }

def admissionCountersBounded (input : Input) : Prop :=
  input.proofUsed ≤ input.proofCap ∧ input.proofCap ≤ counterMax ∧
    input.sourceAUsed ≤ input.sourceACap ∧ input.sourceACap ≤ counterMax ∧
    input.sourceSUsed ≤ input.sourceSCap ∧ input.sourceSCap ≤ counterMax ∧
    input.sourceMUsed ≤ input.sourceMCap ∧ input.sourceMCap ≤ counterMax ∧
    input.sourceUUsed ≤ input.sourceUCap ∧ input.sourceUCap ≤ counterMax ∧
    input.verifierVUsed ≤ input.verifierVCap ∧ input.verifierVCap ≤ counterMax

def admissionTransitionInvariants (input : Input) (decision : Decision) : Prop :=
  decision.accepted = true ∧ decisionStateValid decision = true ∧
    countersNeverDecrease input decision ∧ countersWithinCaps decision ∧
    capsPreserved input decision

theorem evaluate_issue_invariants (input : Input)
    (hOp : input.op = .issue)
    (hCounters : countersValid input = true)
    (hBounded : admissionCountersBounded input)
    (hBatch : input.batch = .awaiting)
    (hSource : input.source = .absent)
    (hVerifier : input.verifier = .unreserved)
    (hTerminal : input.terminal = .none)
    (hProof : checkedAdd input.proofUsed 101 input.proofCap = some proofAfter)
    (hSourceU : checkedAdd input.sourceUUsed 1 input.sourceUCap = some sourceUAfter) :
    let decision := evaluate input
    admissionTransitionInvariants input decision ∧
      decision.batch = .awaiting ∧ decision.source = .absent ∧
      decision.verifier = .unreserved ∧ decision.terminal = .none ∧
      stateValid input = true := by
  have hProofBounds := checkedAdd_sound input.proofUsed 101 input.proofCap proofAfter hProof
  have hSourceUBounds := checkedAdd_sound input.sourceUUsed 1 input.sourceUCap sourceUAfter hSourceU
  rcases hBounded with ⟨hProofUsed, hProofCap, hAUsed, hACap, hSUsed, hSCap,
    hMUsed, hMCap, hUUsed, hUCap, hVUsed, hVCap⟩
  rcases hProofBounds with ⟨hProofBefore, hProofAfterCap⟩
  rcases hSourceUBounds with ⟨hSourceUBefore, hSourceUAfterCap⟩
  unfold evaluate
  rw [hOp]
  simp [hCounters, hBatch, hSource, hVerifier, hTerminal, hProof, hSourceU,
    accept, stateValid, decisionStateValid, admissionTransitionInvariants,
    countersNeverDecrease, countersWithinCaps, capsPreserved]
  omega

theorem evaluate_source_admit_invariants (input : Input)
    (hOp : input.op = .sourceAdmit)
    (hCounters : countersValid input = true)
    (hBounded : admissionCountersBounded input)
    (hBatch : input.batch = .awaiting)
    (hSource : input.source = .absent)
    (hVerifier : input.verifier = .unreserved)
    (hTerminal : input.terminal = .none)
    (hA : checkedAdd input.sourceAUsed 1 input.sourceACap = some aAfter)
    (hS : checkedAdd input.sourceSUsed 4096 input.sourceSCap = some sAfter)
    (hM : checkedAdd input.sourceMUsed 100 input.sourceMCap = some mAfter) :
    let decision := evaluate input
    admissionTransitionInvariants input decision ∧
      decision.batch = .awaiting ∧ decision.source = .authorized ∧
      decision.verifier = .unreserved ∧ decision.terminal = .none := by
  have hABounds := checkedAdd_sound input.sourceAUsed 1 input.sourceACap aAfter hA
  have hSBounds := checkedAdd_sound input.sourceSUsed 4096 input.sourceSCap sAfter hS
  have hMBounds := checkedAdd_sound input.sourceMUsed 100 input.sourceMCap mAfter hM
  rcases hBounded with ⟨hProofUsed, hProofCap, hAUsed, hACap, hSUsed, hSCap,
    hMUsed, hMCap, hUUsed, hUCap, hVUsed, hVCap⟩
  rcases hABounds with ⟨hABefore, hAAfterCap⟩
  rcases hSBounds with ⟨hSBefore, hSAfterCap⟩
  rcases hMBounds with ⟨hMBefore, hMAfterCap⟩
  unfold evaluate
  rw [hOp]
  simp [hCounters, hBatch, hSource, hVerifier, hTerminal, hA, hS, hM,
    accept, stateValid, decisionStateValid, admissionTransitionInvariants,
    countersNeverDecrease, countersWithinCaps, capsPreserved]
  omega

theorem evaluate_source_start_invariants (input : Input)
    (hOp : input.op = .sourceStart)
    (hCounters : countersValid input = true)
    (hBounded : admissionCountersBounded input)
    (hBatch : input.batch = .awaiting)
    (hSource : input.source = .authorized)
    (hVerifier : input.verifier = .unreserved)
    (hTerminal : input.terminal = .none) :
    let decision := evaluate input
    admissionTransitionInvariants input decision ∧
      decision.batch = .awaiting ∧ decision.source = .started ∧
      decision.verifier = .unreserved ∧ decision.terminal = .none := by
  rcases hBounded with ⟨hProofUsed, hProofCap, hAUsed, hACap, hSUsed, hSCap,
    hMUsed, hMCap, hUUsed, hUCap, hVUsed, hVCap⟩
  unfold evaluate
  rw [hOp]
  simp [hCounters, hBatch, hSource, hVerifier, hTerminal, accept, stateValid,
    decisionStateValid, admissionTransitionInvariants, countersNeverDecrease,
    countersWithinCaps, capsPreserved]
  omega

theorem evaluate_source_finish_success_invariants (input : Input)
    (hOp : input.op = .sourceFinishSuccess)
    (hCounters : countersValid input = true)
    (hBounded : admissionCountersBounded input)
    (hBatch : input.batch = .awaiting)
    (hSource : input.source = .started)
    (hVerifier : input.verifier = .unreserved)
    (hTerminal : input.terminal = .none) :
    let decision := evaluate input
    admissionTransitionInvariants input decision ∧
      decision.batch = .awaiting ∧ decision.source = .completed ∧
      decision.verifier = .unreserved ∧ decision.terminal = .none := by
  rcases hBounded with ⟨hProofUsed, hProofCap, hAUsed, hACap, hSUsed, hSCap,
    hMUsed, hMCap, hUUsed, hUCap, hVUsed, hVCap⟩
  unfold evaluate
  rw [hOp]
  simp [hCounters, hBatch, hSource, hVerifier, hTerminal, accept, stateValid,
    decisionStateValid, admissionTransitionInvariants, countersNeverDecrease,
    countersWithinCaps, capsPreserved]
  omega

theorem evaluate_source_finish_unknown_invariants (input : Input)
    (hOp : input.op = .sourceFinishUnknown)
    (hCounters : countersValid input = true)
    (hBounded : admissionCountersBounded input)
    (hBatch : input.batch = .awaiting)
    (hSource : input.source = .started)
    (hVerifier : input.verifier = .unreserved)
    (hTerminal : input.terminal = .none) :
    let decision := evaluate input
    admissionTransitionInvariants input decision ∧
      decision.batch = .held ∧ decision.source = .unknown ∧
      decision.verifier = .unreserved ∧ decision.terminal = .unknown := by
  rcases hBounded with ⟨hProofUsed, hProofCap, hAUsed, hACap, hSUsed, hSCap,
    hMUsed, hMCap, hUUsed, hUCap, hVUsed, hVCap⟩
  unfold evaluate
  rw [hOp]
  simp [hCounters, hBatch, hSource, hVerifier, hTerminal, accept, stateValid,
    decisionStateValid, admissionTransitionInvariants, countersNeverDecrease,
    countersWithinCaps, capsPreserved]
  omega

theorem evaluate_verifier_reserve_invariants (input : Input)
    (hOp : input.op = .verifierReserve)
    (hCounters : countersValid input = true)
    (hBounded : admissionCountersBounded input)
    (hBatch : input.batch = .leased)
    (hSource : input.source = .completed)
    (hVerifier : input.verifier = .unreserved)
    (hTerminal : input.terminal = .none)
    (hV : checkedAdd input.verifierVUsed 1 input.verifierVCap = some vAfter) :
    let decision := evaluate input
    admissionTransitionInvariants input decision ∧
      decision.batch = .leased ∧ decision.source = .completed ∧
      decision.verifier = .started ∧ decision.terminal = .none := by
  have hVBounds := checkedAdd_sound input.verifierVUsed 1 input.verifierVCap vAfter hV
  rcases hBounded with ⟨hProofUsed, hProofCap, hAUsed, hACap, hSUsed, hSCap,
    hMUsed, hMCap, hUUsed, hUCap, hVUsed, hVCap⟩
  rcases hVBounds with ⟨hVBefore, hVAfterCap⟩
  unfold evaluate
  rw [hOp]
  simp [hCounters, hBatch, hSource, hVerifier, hTerminal, hV, accept, stateValid,
    decisionStateValid, admissionTransitionInvariants, countersNeverDecrease,
    countersWithinCaps, capsPreserved]
  omega

theorem evaluate_verifier_finish_accepted_invariants (input : Input)
    (hOp : input.op = .verifierFinishAccepted)
    (hCounters : countersValid input = true)
    (hBounded : admissionCountersBounded input)
    (hBatch : input.batch = .leased)
    (hSource : input.source = .completed)
    (hVerifier : input.verifier = .started)
    (hTerminal : input.terminal = .none) :
    let decision := evaluate input
    admissionTransitionInvariants input decision ∧
      decision.batch = .verified ∧ decision.source = .completed ∧
      decision.verifier = .completed ∧ decision.terminal = .accepted := by
  rcases hBounded with ⟨hProofUsed, hProofCap, hAUsed, hACap, hSUsed, hSCap,
    hMUsed, hMCap, hUUsed, hUCap, hVUsed, hVCap⟩
  unfold evaluate
  rw [hOp]
  simp [hCounters, hBatch, hSource, hVerifier, hTerminal, accept, stateValid,
    decisionStateValid, admissionTransitionInvariants, countersNeverDecrease,
    countersWithinCaps, capsPreserved]
  omega

theorem evaluate_verifier_finish_rejected_invariants (input : Input)
    (hOp : input.op = .verifierFinishRejected)
    (hCounters : countersValid input = true)
    (hBounded : admissionCountersBounded input)
    (hBatch : input.batch = .leased)
    (hSource : input.source = .completed)
    (hVerifier : input.verifier = .started)
    (hTerminal : input.terminal = .none) :
    let decision := evaluate input
    admissionTransitionInvariants input decision ∧
      decision.batch = .rejected ∧ decision.source = .completed ∧
      decision.verifier = .completed ∧ decision.terminal = .rejected := by
  rcases hBounded with ⟨hProofUsed, hProofCap, hAUsed, hACap, hSUsed, hSCap,
    hMUsed, hMCap, hUUsed, hUCap, hVUsed, hVCap⟩
  unfold evaluate
  rw [hOp]
  simp [hCounters, hBatch, hSource, hVerifier, hTerminal, accept, stateValid,
    decisionStateValid, admissionTransitionInvariants, countersNeverDecrease,
    countersWithinCaps, capsPreserved]
  omega

def recoverySourceAfter (input : Input) : SourcePhase :=
  if input.source = .authorized ∨ input.source = .started then .unknown else input.source

def recoveryVerifierAfter (input : Input) : VerifierPhase :=
  if input.verifier = .started then .unknown else input.verifier

def recoveryTerminalAfter (input : Input) : TerminalKind :=
  if recoverySourceAfter input = .unknown ∨ recoveryVerifierAfter input = .unknown then
    .unknown
  else
    .aborted

def recoveryDisposition (input : Input) (decision : Decision) : Prop :=
  decision.batch = .held ∧
    decision.source = recoverySourceAfter input ∧
    decision.verifier = recoveryVerifierAfter input ∧
    decision.terminal = recoveryTerminalAfter input

theorem evaluate_recover_invariants (input : Input)
    (hOp : input.op = .recover)
    (hCounters : countersValid input = true)
    (hBounded : admissionCountersBounded input)
    (hDurable :
      (input.batch = .awaiting ∧ input.source = .absent ∧ input.verifier = .unreserved) ∨
      (input.batch = .awaiting ∧ input.source = .authorized ∧ input.verifier = .unreserved) ∨
      (input.batch = .awaiting ∧ input.source = .started ∧ input.verifier = .unreserved) ∨
      (input.batch = .awaiting ∧ input.source = .completed ∧ input.verifier = .unreserved) ∨
      (input.batch = .queued ∧ input.source = .completed ∧ input.verifier = .unreserved) ∨
      (input.batch = .queued ∧ input.source = .absent ∧ input.verifier = .unreserved) ∨
      (input.batch = .leased ∧ input.source = .absent ∧ input.verifier = .unreserved) ∨
      (input.batch = .leased ∧ input.source = .completed ∧ input.verifier = .unreserved) ∨
      (input.batch = .leased ∧ input.source = .absent ∧ input.verifier = .started) ∨
      (input.batch = .leased ∧ input.source = .completed ∧ input.verifier = .started))
    (hTerminal : input.terminal = .none) :
    let decision := evaluate input
    admissionTransitionInvariants input decision ∧
      recoveryDisposition input decision := by
  rcases hBounded with ⟨hProofUsed, hProofCap, hAUsed, hACap, hSUsed, hSCap,
    hMUsed, hMCap, hUUsed, hUCap, hVUsed, hVCap⟩
  rcases hDurable with hDurable | hDurable | hDurable | hDurable | hDurable | hDurable | hDurable | hDurable | hDurable | hDurable
  all_goals
    rcases hDurable with ⟨hBatch, hSource, hVerifier⟩
    simp [evaluate, hOp, hCounters, hBatch, hSource, hVerifier, hTerminal, accept,
      stateValid, decisionStateValid, admissionTransitionInvariants,
      countersNeverDecrease, countersWithinCaps, capsPreserved, recoveryDisposition,
      recoverySourceAfter, recoveryVerifierAfter, recoveryTerminalAfter]
    omega

end BlindLedger.Admission
