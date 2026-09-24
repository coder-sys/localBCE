import BlindLedger.System.Types

namespace BlindLedger.System

structure SignedFrameBinding where
  operation : OperationRef
  launch : LaunchRef
  receipt : ReceiptRef
  frame : FrameRef

/-! Source transitions are fail-closed: only the explicitly allowed source
    state advances, and every other source state returns none. -/
inductive SourceTransaction where
  | Unknown (operation : OperationRef)
  | NoCommit (operation : OperationRef)
  | ConsumedLaunching (operation : OperationRef) (launch : LaunchRef)
  | TerminalFailed (operation : OperationRef) (receipt : ReceiptRef)
  | SignedFrameBound (binding : SignedFrameBinding)

inductive PostConsumeResolution where
  | ambiguous (receipt : ReceiptRef)
  | signedFrame (receipt : ReceiptRef) (frame : FrameRef)

/-! The model-level GuaranteedNoCommit outcome is represented by the
    NoCommit state. It is the only source state with a retry/no-burn step. -/
def guaranteedNoCommit (operation : OperationRef) : SourceTransaction :=
  .NoCommit operation

def retryNoBurn (transaction : SourceTransaction) :
    Option SourceTransaction :=
  match transaction with
  | .NoCommit operation => some (.NoCommit operation)
  | _ => none

def resolveConsumed
    (transaction : SourceTransaction) (resolution : PostConsumeResolution) :
    Option SourceTransaction :=
  match transaction, resolution with
  | .ConsumedLaunching operation _, .ambiguous receipt =>
      some (.TerminalFailed operation receipt)
  | .ConsumedLaunching operation launch, .signedFrame receipt frame =>
      some
        (.SignedFrameBound
          { operation := operation
            launch := launch
            receipt := receipt
            frame := frame })
  | _, _ => none

def observeNoCommit (transaction : SourceTransaction) :
    Option SourceTransaction :=
  match transaction with
  | .Unknown operation => some (.NoCommit operation)
  | _ => none

def consumeAndLaunch (transaction : SourceTransaction) (launch : LaunchRef) :
    Option SourceTransaction :=
  match transaction with
  | .NoCommit operation => some (.ConsumedLaunching operation launch)
  | _ => none

def markTerminalFailed (transaction : SourceTransaction) (receipt : ReceiptRef) :
    Option SourceTransaction :=
  resolveConsumed transaction (.ambiguous receipt)

def bindSignedFrame
    (transaction : SourceTransaction) (receipt : ReceiptRef) (frame : FrameRef) :
    Option SourceTransaction :=
  resolveConsumed transaction (.signedFrame receipt frame)

def isTerminal : SourceTransaction → Prop
  | .Unknown _ => False
  | .NoCommit _ => False
  | .ConsumedLaunching _ _ => False
  | .TerminalFailed _ _ => True
  | .SignedFrameBound _ => True

def successfulConsumeCount : SourceTransaction → Nat
  | .Unknown _ => 0
  | .NoCommit _ => 0
  | .ConsumedLaunching _ _ => 1
  | .TerminalFailed _ _ => 1
  | .SignedFrameBound _ => 1

def terminalPreserving
    (step : SourceTransaction → Option SourceTransaction) : Prop :=
  ∀ {before after}, step before = some after → isTerminal before → isTerminal after

theorem observeNoCommit_terminal_monotone :
    terminalPreserving observeNoCommit := by
  intro before after hstep hterminal
  cases before <;> simp [observeNoCommit, isTerminal] at hstep hterminal

theorem consumeAndLaunch_terminal_monotone (launch : LaunchRef) :
    terminalPreserving (fun transaction => consumeAndLaunch transaction launch) := by
  intro before after hstep hterminal
  cases before <;> simp [consumeAndLaunch, isTerminal] at hstep hterminal

theorem markTerminalFailed_terminal_monotone (receipt : ReceiptRef) :
    terminalPreserving (fun transaction => markTerminalFailed transaction receipt) := by
  intro before after hstep hterminal
  cases before <;> simp [markTerminalFailed, resolveConsumed, isTerminal] at hstep hterminal

theorem bindSignedFrame_terminal_monotone (receipt : ReceiptRef) (frame : FrameRef) :
    terminalPreserving
      (fun transaction => bindSignedFrame transaction receipt frame) := by
  intro before after hstep hterminal
  cases before <;> simp [bindSignedFrame, resolveConsumed, isTerminal] at hstep hterminal

theorem successfulConsumeCount_le_one (transaction : SourceTransaction) :
    successfulConsumeCount transaction ≤ 1 := by
  cases transaction <;> simp [successfulConsumeCount]

theorem guaranteedNoCommit_is_only_retryable_noBurn
    (operation : OperationRef) :
    retryNoBurn (guaranteedNoCommit operation) =
      some (guaranteedNoCommit operation) := by
  rfl

theorem consumed_ambiguity_is_terminal_failed
    (operation : OperationRef) (launch : LaunchRef) (receipt : ReceiptRef) :
    resolveConsumed (.ConsumedLaunching operation launch) (.ambiguous receipt) =
      some (.TerminalFailed operation receipt) := by
  rfl

theorem consumed_ambiguity_is_fail_closed
    (operation : OperationRef) (launch : LaunchRef) (receipt : ReceiptRef) :
    resolveConsumed (.ConsumedLaunching operation launch) (.ambiguous receipt) =
        some (.TerminalFailed operation receipt) ∧
      retryNoBurn (.TerminalFailed operation receipt) = none := by
  constructor <;> rfl

theorem consumed_signed_frame_binding_is_exact
    (operation : OperationRef) (launch : LaunchRef)
    (receipt : ReceiptRef) (frame : FrameRef) :
    resolveConsumed (.ConsumedLaunching operation launch)
        (.signedFrame receipt frame) =
      some
        (.SignedFrameBound
          { operation := operation
            launch := launch
            receipt := receipt
            frame := frame }) := by
  rfl

theorem consumedLaunching_has_no_noBurn_retry
    (operation : OperationRef) (launch : LaunchRef) :
    retryNoBurn (.ConsumedLaunching operation launch) = none := by
  rfl

theorem terminalFailed_has_no_noBurn_retry
    (operation : OperationRef) (receipt : ReceiptRef) :
    retryNoBurn (.TerminalFailed operation receipt) = none := by
  rfl

theorem consumeFromConsumedLaunchingFails
    (operation : OperationRef) (firstLaunch secondLaunch : LaunchRef) :
    consumeAndLaunch (.ConsumedLaunching operation firstLaunch) secondLaunch = none := by
  rfl

theorem consumeFromSignedFrameBoundFails
    (binding : SignedFrameBinding) (launch : LaunchRef) :
    consumeAndLaunch (.SignedFrameBound binding) launch = none := by
  rfl

def bindingOf (transaction : SourceTransaction) : Option SignedFrameBinding :=
  match transaction with
  | .SignedFrameBound binding => some binding
  | _ => none

def boundReceipt (transaction : SourceTransaction) : Option ReceiptRef :=
  match transaction with
  | .SignedFrameBound binding => some binding.receipt
  | _ => none

theorem signedFrameBound_binding_exact (binding : SignedFrameBinding) :
    bindingOf (.SignedFrameBound binding) = some binding := by
  rfl

theorem signedFrameBound_receipt_exact (binding : SignedFrameBinding) :
    boundReceipt (.SignedFrameBound binding) = some binding.receipt := by
  rfl

theorem signedFrameBound_binding_unique
    {left right : SignedFrameBinding}
    (h : bindingOf (.SignedFrameBound left) = bindingOf (.SignedFrameBound right)) :
    left = right := by
  simpa [bindingOf] using h

theorem signedFrameBound_same_fields_same_binding
    {left right : SignedFrameBinding}
    (operation : left.operation = right.operation)
    (launch : left.launch = right.launch)
    (receipt : left.receipt = right.receipt)
    (frame : left.frame = right.frame) :
    left = right := by
  cases left with
  | mk leftOperation leftLaunch leftReceipt leftFrame =>
      cases right with
      | mk rightOperation rightLaunch rightReceipt rightFrame =>
          simp_all

theorem terminalFailed_cannot_bind
    (operation : OperationRef) (oldReceipt newReceipt : ReceiptRef) (frame : FrameRef) :
    bindSignedFrame (.TerminalFailed operation oldReceipt) newReceipt frame = none := by
  rfl

theorem terminalFailed_is_closed
    (operation : OperationRef) (receipt : ReceiptRef) (launch : LaunchRef)
    (frame : FrameRef) :
    observeNoCommit (.TerminalFailed operation receipt) = none ∧
    consumeAndLaunch (.TerminalFailed operation receipt) launch = none ∧
    markTerminalFailed (.TerminalFailed operation receipt) receipt = none ∧
    bindSignedFrame (.TerminalFailed operation receipt) receipt frame = none := by
  simp [observeNoCommit, consumeAndLaunch, markTerminalFailed, bindSignedFrame, resolveConsumed]

end BlindLedger.System
