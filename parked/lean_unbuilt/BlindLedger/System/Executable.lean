import BlindLedger.System.Batch

namespace BlindLedger.System

/-! This executable is a bounded, machine-readable seam for the pure
    row-local outbox model. It does not replace the database, worker fencing,
    receiver, durable recovery, or any clearance/payment authority. -/

def runtimeRunnerProtocol : String := "BL-OUTBOX/1"

def runtimeRunnerMaxInputBytes : Nat := 4096

def runtimeRunnerMaxActions : Nat := 32

def runtimeRunnerNatMax : Nat := 1_000_000

def runtimeRunnerMaxOutputChars : Nat := 256

def runtimeBatchRunnerProtocol : String := "BL-OUTBOX-BATCH/1"

def runtimeBatchRunnerMaxInputBytes : Nat := 16_384

def runtimeBatchRunnerMaxActions : Nat := 32

def runtimeBatchRunnerMaxOutputChars : Nat := 32_768

def runtimeBatchRowCount : Nat := 100

inductive RuntimeInputError where
  | inputTooLarge
  | nonAscii
  | invalidUtf8
  | wrongLineCount
  | wrongProtocol
  | wrongField
  | malformedState
  | invalidAttempt
  | invalidTime
  | invalidLeaseDuration
  | malformedAction
  | tooManyActions
  | invalidTrace
  | wrongBatchStateCount
  | invalidSettleMask
deriving DecidableEq, Repr

def runtimeInputErrorCode : RuntimeInputError → String
  | .inputTooLarge => "input-too-large"
  | .nonAscii => "non-ascii"
  | .invalidUtf8 => "invalid-utf8"
  | .wrongLineCount => "wrong-line-count"
  | .wrongProtocol => "wrong-protocol"
  | .wrongField => "wrong-field"
  | .malformedState => "malformed-state"
  | .invalidAttempt => "invalid-attempt"
  | .invalidTime => "invalid-time"
  | .invalidLeaseDuration => "invalid-lease-duration"
  | .malformedAction => "malformed-action"
  | .tooManyActions => "too-many-actions"
  | .invalidTrace => "invalid-trace"
  | .wrongBatchStateCount => "wrong-batch-state-count"
  | .invalidSettleMask => "invalid-settle-mask"

def runtimeAsciiByte (byte : UInt8) : Bool :=
  let value := byte.toNat
  decide (value = 10 ∨ value = 13 ∨ (32 ≤ value ∧ value ≤ 126))

def runtimeAsciiBytes (bytes : ByteArray) : Bool :=
  bytes.toList.all runtimeAsciiByte

def runtimeCanonicalNatBounded (token : String) (limit : Nat) :
    Option { value : Nat // value ≤ limit } :=
  if token.isEmpty then
    none
  else if token != "0" && token.startsWith "0" then
    none
  else if !token.toList.all (fun character =>
      decide (48 ≤ character.toNat ∧ character.toNat ≤ 57)) then
    none
  else
    match token.toNat? with
    | none => none
    | some value =>
        if h : value ≤ limit then
          some ⟨value, h⟩
        else
          none

def runtimeParseAttempt (token : String) : Except RuntimeInputError RuntimeAttempt :=
  match runtimeCanonicalNatBounded token runtimeMaxAttempts with
  | none => .error .invalidAttempt
  | some value =>
      .ok ⟨value.val, by omega⟩

def runtimeParseTime (token : String) : Except RuntimeInputError Nat :=
  match runtimeCanonicalNatBounded token runtimeRunnerNatMax with
  | none => .error .invalidTime
  | some value => .ok value.val

def runtimeParseLeaseDuration (token : String) :
    Except RuntimeInputError Nat :=
  match runtimeCanonicalNatBounded token runtimeRunnerNatMax with
  | none => .error .invalidLeaseDuration
  | some value => .ok value.val

def runtimeParseState (token : String) :
    Except RuntimeInputError RuntimeOutboxState :=
  match token.splitOn ":" with
  | ["ready", attemptText] => do
      let attempt ← runtimeParseAttempt attemptText
      pure (.ready attempt)
  | ["leased", attemptText, expiryText] => do
      let attempt ← runtimeParseAttempt attemptText
      let expiry ← runtimeParseTime expiryText
      pure (.leased attempt expiry)
  | ["acknowledged", attemptText] => do
      let attempt ← runtimeParseAttempt attemptText
      pure (.acknowledged attempt)
  | ["delivery-unconfirmed", attemptText] => do
      let attempt ← runtimeParseAttempt attemptText
      pure (.deliveryUnconfirmed attempt)
  | _ => .error .malformedState

def runtimeDropPrefix (tag value : String) : Option String :=
  if value.startsWith tag then
    some (String.Slice.toString (value.dropPrefix tag))
  else
    none

def runtimeParseAction (token : String) :
    Except RuntimeInputError RuntimeAction :=
  match token.splitOn ":" with
  | ["recover", nowText] => do
      let now ← runtimeParseTime nowText
      pure (.recover now)
  | ["claim-direct", nowText, leaseText] => do
      let now ← runtimeParseTime nowText
      let leaseDuration ← runtimeParseLeaseDuration leaseText
      pure (.claimDirect now leaseDuration)
  | ["claim-reconciliation", nowText, leaseText] => do
      let now ← runtimeParseTime nowText
      let leaseDuration ← runtimeParseLeaseDuration leaseText
      pure (.claimReconciliation now leaseDuration)
  | ["settle", nowText, "acknowledged"] => do
      let now ← runtimeParseTime nowText
      pure (.settle now .acknowledged)
  | ["settle", nowText, "delivery-unconfirmed"] => do
      let now ← runtimeParseTime nowText
      pure (.settle now .deliveryUnconfirmed)
  | _ => .error .malformedAction

def runtimeParseActions (token : String) :
    Except RuntimeInputError (List RuntimeAction) :=
  if token.isEmpty then
    .ok []
  else
    let tokens := token.splitOn "|"
    if tokens.length > runtimeRunnerMaxActions then
      .error .tooManyActions
    else
      tokens.mapM runtimeParseAction

def runtimeStripCarriageReturn (line : String) : String :=
  match line.toList.reverse with
  | '\r' :: rest => String.ofList rest.reverse
  | _ => line

def runtimeInputLines (input : String) : List String :=
  let raw := input.splitOn "\n"
  let withoutFinalNewline :=
    match raw.reverse with
    | "" :: rest => rest.reverse
    | _ => raw
  withoutFinalNewline.map runtimeStripCarriageReturn

def runtimeParseBatchOptionalState (token : String) :
    Except RuntimeInputError (Option RuntimeOutboxState) :=
  if token = "-" || token = "NONE" then
    .ok none
  else
    match runtimeParseState token with
    | .error error => .error error
    | .ok state => .ok (some state)

def runtimeParseBatchStates (token : String) :
    Except RuntimeInputError (List (Option RuntimeOutboxState)) :=
  let tokens := token.splitOn ","
  if tokens.length != runtimeBatchRowCount then
    .error .wrongBatchStateCount
  else
    tokens.mapM runtimeParseBatchOptionalState

def runtimeParseBatchOutcomeChar (character : Char) :
    Except RuntimeInputError RuntimeDeliveryOutcome :=
  if character = 'A' then
    .ok .acknowledged
  else if character = 'U' then
    .ok .deliveryUnconfirmed
  else
    .error .invalidSettleMask

def runtimeParseBatchOutcomeMask (token : String) :
    Except RuntimeInputError (List RuntimeDeliveryOutcome) :=
  if token.toList.length != runtimeBatchRowCount then
    .error .invalidSettleMask
  else
    token.toList.mapM runtimeParseBatchOutcomeChar

def runtimeBatchOutcomeAt
    (outcomes : List RuntimeDeliveryOutcome) (i : BatchIndex) :
    RuntimeDeliveryOutcome :=
  match runtimeBatchListAt outcomes i.val with
  | some outcome => outcome
  | none => .deliveryUnconfirmed

def runtimeParseBatchAction (token : String) :
    Except RuntimeInputError RuntimeBatchAction :=
  match token.splitOn ":" with
  | ["recover", nowText] => do
      let now ← runtimeParseTime nowText
      pure (.recover now)
  | ["claim-direct", nowText, leaseText] => do
      let now ← runtimeParseTime nowText
      let leaseDuration ← runtimeParseLeaseDuration leaseText
      pure (.claimDirect now leaseDuration)
  | ["claim-reconciliation", nowText, leaseText] => do
      let now ← runtimeParseTime nowText
      let leaseDuration ← runtimeParseLeaseDuration leaseText
      pure (.claimReconciliation now leaseDuration)
  | ["settle", nowText, maskText] => do
      let now ← runtimeParseTime nowText
      let outcomes ← runtimeParseBatchOutcomeMask maskText
      pure (.settle now (runtimeBatchOutcomeAt outcomes))
  | _ => .error .malformedAction

def runtimeParseBatchActions (token : String) :
    Except RuntimeInputError (List RuntimeBatchAction) :=
  if token.isEmpty then
    .ok []
  else
    let tokens := token.splitOn "|"
    if tokens.length > runtimeBatchRunnerMaxActions then
      .error .tooManyActions
    else
      tokens.mapM runtimeParseBatchAction

def runtimeParseBatchRequestText (input : String) :
    Except RuntimeInputError
      (List (Option RuntimeOutboxState) × List RuntimeBatchAction) :=
  match runtimeInputLines input with
  | [protocol, statesLine, actionsLine] =>
      if protocol != runtimeBatchRunnerProtocol then
        .error .wrongProtocol
      else
        match runtimeDropPrefix "states=" statesLine,
            runtimeDropPrefix "actions=" actionsLine with
        | some statesText, some actionsText => do
            let states ← runtimeParseBatchStates statesText
            let actions ← runtimeParseBatchActions actionsText
            pure (states, actions)
        | _, _ => .error .wrongField
  | _ => .error .wrongLineCount

def runtimeParseBatchRequestBytes (input : ByteArray) :
    Except RuntimeInputError
      (List (Option RuntimeOutboxState) × List RuntimeBatchAction) :=
  if input.size > runtimeBatchRunnerMaxInputBytes then
    .error .inputTooLarge
  else if !runtimeAsciiBytes input then
    .error .nonAscii
  else
    match String.fromUTF8? input with
    | none => .error .invalidUtf8
    | some text => runtimeParseBatchRequestText text

def runtimeBatchJoin (separator : String) : List String → String
  | [] => ""
  | [value] => value
  | value :: values => value ++ separator ++ runtimeBatchJoin separator values

def runtimeBatchBoolText (value : Bool) : String :=
  if value then "1" else "0"

def runtimeBatchStateVectorText
    (states : List (Option RuntimeOutboxState)) : String :=
  runtimeBatchJoin "," (states.map runtimeOptionalStateSummary)

def runtimeBatchSummaryText (summary : RuntimeBatchSummary) : String :=
  runtimeBatchJoin ","
    [toString summary.present, toString summary.ready,
     toString summary.leased, toString summary.acknowledged,
     toString summary.deliveryUnconfirmed, toString summary.directEligible,
     toString summary.reconciliationEligible]

def runtimeBatchMaskText (mask : BatchIndex → Bool) : String :=
  runtimeBatchJoin ""
    (runtimeBatchIndices.map (fun i => runtimeBatchBoolText (mask i)))

def runtimeBatchStatusText
    (statuses : BatchIndex → Option RuntimeDeliveryOutcome) : String :=
  runtimeBatchJoin ""
    (runtimeBatchIndices.map (fun i =>
      match statuses i with
      | none => "-"
      | some .acknowledged => "A"
      | some .deliveryUnconfirmed => "U"))

def runtimeBatchLastResultText : RuntimeBatchLastResult → String
  | .none => "NONE"
  | .claim operation claimed hasMore =>
      "CLAIM:" ++ operation.label ++ ":" ++ runtimeBatchMaskText claimed ++
        ":" ++ runtimeBatchBoolText hasMore
  | .settle operation statuses hasMore =>
      "SETTLE:" ++ operation.label ++ ":" ++
        runtimeBatchStatusText statuses ++ ":" ++ runtimeBatchBoolText hasMore

def runtimeBatchDirectClaimCount : List RuntimeBatchAction → Nat
  | [] => 0
  | .claimDirect _ _ :: actions => 1 + runtimeBatchDirectClaimCount actions
  | _ :: actions => runtimeBatchDirectClaimCount actions

def runtimeBatchReconciliationClaimCount : List RuntimeBatchAction → Nat
  | [] => 0
  | .claimReconciliation _ _ :: actions =>
      1 + runtimeBatchReconciliationClaimCount actions
  | _ :: actions => runtimeBatchReconciliationClaimCount actions

def runtimeBatchSuccessLine
    (initial : List (Option RuntimeOutboxState))
    (actions : List RuntimeBatchAction)
    (final : RuntimeBatchMachine) : String :=
  let directClaims := runtimeBatchDirectClaimCount actions
  let reconciliationClaims := runtimeBatchReconciliationClaimCount actions
  let summary := runtimeBatchSummary final.outbox
  "OKB;version=1;initial=" ++ runtimeBatchStateVectorText initial ++
    ";final=" ++ runtimeBatchStateVectorText
      (runtimeBatchStateVector final.outbox) ++
    ";summary=" ++ runtimeBatchSummaryText summary ++
    ";claims=" ++ toString directClaims ++ "," ++
      toString reconciliationClaims ++ "," ++
      toString (directClaims + reconciliationClaims) ++
    ";last=" ++ runtimeBatchLastResultText final.lastResult

def runtimeParseRequestText (input : String) :
    Except RuntimeInputError (RuntimeOutboxState × List RuntimeAction) :=
  match runtimeInputLines input with
  | [protocol, initialLine, actionsLine] =>
      if protocol != runtimeRunnerProtocol then
        .error .wrongProtocol
      else
        match runtimeDropPrefix "initial=" initialLine,
            runtimeDropPrefix "actions=" actionsLine with
        | some initialText, some actionsText => do
            let initial ← runtimeParseState initialText
            let actions ← runtimeParseActions actionsText
            pure (initial, actions)
        | _, _ => .error .wrongField
  | _ => .error .wrongLineCount

def runtimeParseRequestBytes (input : ByteArray) :
    Except RuntimeInputError (RuntimeOutboxState × List RuntimeAction) :=
  if input.size > runtimeRunnerMaxInputBytes then
    .error .inputTooLarge
  else if !runtimeAsciiBytes input then
    .error .nonAscii
  else
    match String.fromUTF8? input with
    | none => .error .invalidUtf8
    | some text => runtimeParseRequestText text

def runtimeErrorLine (error : RuntimeInputError) : String :=
  "ERR;version=1;code=" ++ runtimeInputErrorCode error

def runtimeRunBatchRequestBytes (input : ByteArray) : String :=
  let result :=
    match runtimeParseBatchRequestBytes input with
    | .error error => runtimeErrorLine error
    | .ok (initial, actions) =>
        let initialMachine :=
          runtimeBatchInitial (runtimeBatchWireOutbox initial)
        match runtimeBatchTraceRun actions initialMachine with
        | none => runtimeErrorLine .invalidTrace
        | some final => runtimeBatchSuccessLine initial actions final
  if result.length ≤ runtimeBatchRunnerMaxOutputChars then
    result
  else
    runtimeErrorLine .invalidTrace

def runtimeSuccessLine
    (initial : RuntimeOutboxState) (actions : List RuntimeAction)
    (final : RuntimeOutboxState) : String :=
  "OK;version=1;initial=" ++ runtimeStateSummary initial ++
    ";final=" ++ runtimeStateSummary final ++
    ";claims=" ++ toString (runtimeClaimCount actions)

def runtimeRunRequestBytes (input : ByteArray) : String :=
  let result :=
    match runtimeParseRequestBytes input with
    | .error error => runtimeErrorLine error
    | .ok (initial, actions) =>
        match runtimeTraceRun actions initial with
        | none => runtimeErrorLine .invalidTrace
        | some final => runtimeSuccessLine initial actions final
  if result.length ≤ runtimeRunnerMaxOutputChars then
    result
  else
    runtimeErrorLine .invalidTrace

def runtimeBytePrefix : List UInt8 → List UInt8 → Bool
  | [], _ => true
  | _ :: _, [] => false
  | expected :: expectedRest, actual :: actualRest =>
      if expected = actual then
        runtimeBytePrefix expectedRest actualRest
      else
        false

def runtimeIsBatchRequest (input : ByteArray) : Bool :=
  runtimeBytePrefix runtimeBatchRunnerProtocol.toUTF8.toList input.toList

partial def runtimeReadBounded
    (stream : IO.FS.Stream) (remaining : Nat) (accumulator : ByteArray) :
    IO ByteArray := do
  if remaining = 0 then
    pure accumulator
  else
    let chunk ← stream.read (USize.ofNat remaining)
    if chunk.isEmpty then
      pure accumulator
    else
      runtimeReadBounded stream (remaining - chunk.size)
        (ByteArray.append accumulator chunk)

def runtimeRunnerMain : IO Unit := do
  let stdin ← IO.getStdin
  let input ← runtimeReadBounded stdin (runtimeBatchRunnerMaxInputBytes + 1)
    ByteArray.empty
  IO.println
    (if runtimeIsBatchRequest input then
      runtimeRunBatchRequestBytes input
     else
      runtimeRunRequestBytes input)

end BlindLedger.System

def main : IO Unit := BlindLedger.System.runtimeRunnerMain
