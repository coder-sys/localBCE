import BlindLedger.Theorems

namespace BlindLedger.Semantic

def policyName : Nat → String
  | 1 => "PASS"
  | 2 => "MISSING"
  | 3 => "AMBIGUOUS"
  | 4 => "FAIL"
  | _ => "INVALID"

def directiveName : Nat → String
  | 1 => "CLEAR"
  | 2 => "HOLD"
  | 3 => "HUMAN_REVIEW"
  | 4 => "BLOCK"
  | 5 => "EXCEPTION_APPROVED"
  | _ => "INVALID"

def reasonName : Reason → String
  | .valid => "VALID_CONTINUITY"
  | .missing => "AUTHORITATIVE_ABSENCE"
  | .expired => "EXPIRED_OR_TERMINATED"
  | .ambiguous => "INCOMPLETE_OR_AMBIGUOUS"
  | .staleRule => "STALE_RULE_INTERVAL"
  | .controlInterval => "CONTROL_INTERVAL"

def hexDigit : Nat → String
  | 0 => "0"
  | 1 => "1"
  | 2 => "2"
  | 3 => "3"
  | 4 => "4"
  | 5 => "5"
  | 6 => "6"
  | 7 => "7"
  | 8 => "8"
  | 9 => "9"
  | 10 => "a"
  | 11 => "b"
  | 12 => "c"
  | 13 => "d"
  | 14 => "e"
  | 15 => "f"
  | _ => "?"

def hexByte (byte : UInt8) : String :=
  hexDigit (byte.toNat / 16) ++ hexDigit (byte.toNat % 16)

def hexString (bytes : Bytes) : String :=
  bytes.toList.foldl (fun output byte => output ++ hexByte byte) ""

def semanticLinePrefix : String :=
  "BL-SEMANTIC-KERNEL/2;schema=BLCBND02/v2;result="

def successLineBody (data : Bytes) (result : SemanticResult) : String :=
  ";kernel_build_id=BLSK-BLCBND02-EXACT-V2;bundle_id=" ++
    hexString (bundleId data) ++ ";policy=" ++
    policyName result.policy ++ ";directive=" ++ directiveName result.directive ++
    ";reason=" ++ reasonName result.reason ++
    ";reason_id=" ++ hexString result.reasonId ++
    ";attempt_id=" ++ hexString result.attemptId ++
    ";profile_id=" ++ hexString result.profileId ++
    ";schema_id=" ++ hexString result.schemaId ++
    ";program_id=" ++ hexString result.programId ++
    ";mode_id=" ++ hexString result.modeId ++
    ";evaluator_id=" ++ hexString result.evaluatorId ++
    ";control_set_id=" ++ hexString result.controlSetId ++
    ";rule_id=" ++ hexString result.ruleId ++
    ";phase0_receipt_binding=" ++ hexString result.phase0Binding ++
    ";request_id=" ++ hexString result.requestId ++
    ";decision_id=" ++ hexString result.decisionId ++
    ";source_root=" ++ hexString result.sourceRoot ++
    ";completeness_id=" ++ hexString result.completenessId ++
    ";exception_id=" ++ hexString result.exceptionId ++
    ";before_state_id=" ++ hexString result.beforeStateId ++
    ";after_state_id=" ++ hexString result.afterStateId ++
    ";receipt_id=" ++ hexString result.receiptId ++
    ";join_id=" ++ hexString result.joinId ++
    ";chronology_id=" ++ hexString result.chronologyId ++
    ";replay_id=" ++ hexString result.replayId ++
    ";decision_path_id=" ++ hexString result.decisionPathId ++
    ";event_time=" ++ toString result.eventTime ++
    ";observation_time=" ++ toString result.observationTime ++
    ";rule_effective_time=" ++ toString result.ruleEffectiveTime ++
    ";decision_time=" ++ toString result.decisionTime ++
    ";continuity_epoch=" ++ toString result.continuityEpoch ++
    ";sequence_before=" ++ toString result.sequenceBefore ++
    ";sequence_after=" ++ toString result.sequenceAfter ++
    ";before_audit_head=" ++ hexString result.beforeAuditHead ++
    ";after_audit_head=" ++ hexString result.afterAuditHead ++
    ";before_continuity_root=" ++ hexString result.beforeContinuityRoot ++
    ";after_continuity_root=" ++ hexString result.afterContinuityRoot ++
    ";audit_head_after=" ++ hexString result.auditHeadAfter ++
    ";continuity_root_after=" ++ hexString result.continuityRootAfter ++
    ";bundle_bytes=" ++ toString data.size ++
    ";proof_suite_id=NONE;proof_session_accepted=false;economic_mutation=false;replay_stateful=false"

def successLinePayload (data : Bytes) (result : SemanticResult) : String :=
  "PASS" ++ successLineBody data result

def rejectLineBody (data : Bytes) (error : String) : String :=
  ";kernel_build_id=BLSK-BLCBND02-EXACT-V2;error=" ++ error ++
    ";bundle_bytes=" ++ toString data.size ++
    ";proof_suite_id=NONE;proof_session_accepted=false;economic_mutation=false;replay_stateful=false"

def rejectLinePayload (data : Bytes) (error : String) : String :=
  "REJECT" ++ rejectLineBody data error

def successLine (data : Bytes) (result : SemanticResult) : String :=
  semanticLinePrefix ++ successLinePayload data result

def rejectLine (data : Bytes) (error : String) : String :=
  semanticLinePrefix ++ rejectLinePayload data error

def stateReplayId (output : StateKernelOutput) : Bytes :=
  match output.request.prior with
  | some prior =>
      if prior.version = 0 then output.evidence.replayId
      else digest "BL/DIRECT-STATE-OWNED/STATE-REPLAY/v1"
        [output.operation.requestId, output.operation.beforeStateId,
          output.operation.bundleId, output.operation.controlSetId]
  | none => digest "BL/DIRECT-STATE-OWNED/STATE-REPLAY/v1"
      [output.operation.requestId, output.operation.beforeStateId,
        output.operation.bundleId, output.operation.controlSetId]

def stateDecisionPathId (output : StateKernelOutput) : Bytes :=
  match output.request.prior with
  | some prior =>
      if prior.version = 0 then output.evidence.decisionPathId
      else digest "BL/DIRECT-STATE-OWNED/STATE-DECISION-PATH/v1"
        [output.evidence.decisionPathId, output.operation.decisionId]
  | none => digest "BL/DIRECT-STATE-OWNED/STATE-DECISION-PATH/v1"
      [output.evidence.decisionPathId, output.operation.decisionId]

def stateSuccessLine (output : StateKernelOutput) : String :=
  let operation := output.operation
  let evidence := output.evidence
  let request := output.request
  "BL-STATE-SEMANTIC-KERNEL/1;schema=BLSDCLR01/v1;result=PASS" ++
    ";kernel_build_id=" ++ STATE_KERNEL_BUILD_ID ++
    ";input_sha3_512=" ++ hexString output.inputSha3 ++
    ";command_id=" ++ hexString request.commandId ++
    ";expected_revision=" ++ toString request.expectedRevision ++
    ";current_sequence=" ++ toString (stateNatAt request.numbers 1) ++
    ";bundle_id=" ++ hexString operation.bundleId ++
    ";bundle_bytes=" ++ toString request.bundle.size ++
    ";policy=" ++ policyName operation.policy ++
    ";directive=" ++ directiveName operation.directive ++
    ";reason=" ++ reasonName evidence.reason ++
    ";reason_id=" ++ hexString evidence.reasonId ++
    ";request_id=" ++ hexString operation.requestId ++
    ";attempt_id=" ++ hexString operation.attemptId ++
    ";decision_id=" ++ hexString operation.decisionId ++
    ";join_id=" ++ hexString operation.joinId ++
    ";profile_id=" ++ hexString operation.profileId ++
    ";schema_id=" ++ hexString operation.schemaId ++
    ";program_id=" ++ hexString operation.programId ++
    ";mode_id=" ++ hexString operation.modeId ++
    ";evaluator_id=" ++ hexString operation.evaluatorId ++
    ";control_set_id=" ++ hexString operation.controlSetId ++
    ";rule_id=" ++ hexString operation.ruleId ++
    ";phase0_receipt_binding=" ++ hexString operation.phase0Binding ++
    ";source_root=" ++ hexString operation.sourceRoot ++
    ";completeness_id=" ++ hexString evidence.completenessId ++
    ";exception_id=" ++ hexString operation.exceptionId ++
    ";before_state_id=" ++ hexString operation.beforeStateId ++
    ";after_state_id=" ++ hexString operation.afterStateId ++
    ";receipt_id=" ++ hexString operation.receiptId ++
    ";chronology_id=" ++ hexString evidence.chronologyId ++
    ";replay_id=" ++ hexString (stateReplayId output) ++
    ";decision_path_id=" ++ hexString (stateDecisionPathId output) ++
    ";before_audit_head=" ++ hexString operation.beforeAuditHead ++
    ";before_continuity_root=" ++ hexString operation.beforeContinuityRoot ++
    ";after_audit_head=" ++ hexString operation.afterAuditHead ++
    ";after_continuity_root=" ++ hexString operation.afterContinuityRoot ++
    ";audit_head_after=" ++ hexString operation.afterAuditHead ++
    ";continuity_root_after=" ++ hexString operation.afterContinuityRoot ++
    ";evidence_request_id=" ++ hexString evidence.requestId ++
    ";evidence_decision_id=" ++ hexString evidence.decisionId ++
    ";evidence_join_id=" ++ hexString evidence.joinId ++
    ";evidence_receipt_id=" ++ hexString evidence.receiptId ++
    ";evidence_decision_path_id=" ++ hexString evidence.decisionPathId ++
    ";event_time=" ++ toString operation.eventTime ++
    ";observation_time=" ++ toString operation.observationTime ++
    ";rule_effective_time=" ++ toString operation.ruleEffectiveTime ++
    ";decision_time=" ++ toString operation.decisionTime ++
    ";continuity_epoch=" ++ toString operation.continuityEpoch ++
    ";sequence_before=" ++ toString operation.sequenceBefore ++
    ";sequence_after=" ++ toString operation.sequenceAfter ++
    ";proof_suite_id=NONE;proof_session_accepted=false;economic_mutation=" ++
    (if operation.clearanceAdvanced then "true" else "false") ++
    ";replay_stateful=true;disposition=" ++ output.disposition ++
    ";prior_operation_digest=" ++ hexString output.priorOperationDigest

def stateRejectLine (data : Bytes) (error : String) : String :=
  "BL-STATE-SEMANTIC-KERNEL/1;schema=BLSDCLR01/v1;result=REJECT;kernel_build_id=" ++
    STATE_KERNEL_BUILD_ID ++ ";error=" ++ error ++ ";input_bytes=" ++ toString data.size

def runStateBytes (data : Bytes) : String :=
  if theoremManifest.length ≠ 19 then
    stateRejectLine data "theorem-manifest"
  else if data.size > STATE_MAX_BUNDLE_BYTES + 3_110 then
    stateRejectLine data "state-request-size"
  else
    match verifyStateRequest data with
    | .ok output => stateSuccessLine output
    | .error error => stateRejectLine data error

def runBytes (data : Bytes) : String :=
  if theoremManifest.length ≠ 19 then
    rejectLine data "theorem-manifest"
  else if data.size > 1_000_000 then
    rejectLine data "bundle-size"
  else
    match verifyResult data with
    | .ok result => successLine data result
    | .error error => rejectLine data error

def runVersionedBytes (data : Bytes) : String :=
  if data.extract 0 8 = STATE_REQUEST_MAGIC then runStateBytes data else runBytes data

partial def readBounded
    (stream : IO.FS.Stream) (remaining : Nat) (accumulator : Bytes) : IO Bytes := do
  if remaining = 0 then
    pure accumulator
  else
    let chunk ← stream.read (USize.ofNat remaining)
    if chunk.isEmpty then
      pure accumulator
    else
      readBounded stream (remaining - chunk.size) (ByteArray.append accumulator chunk)

theorem rejectLine_ne_successLine
    (data : Bytes) (error : String) (result : SemanticResult) :
    rejectLine data error ≠ successLine data result := by
  intro hline
  change semanticLinePrefix ++ rejectLinePayload data error =
    semanticLinePrefix ++ successLinePayload data result at hline
  have hpayload := (String.append_right_inj semanticLinePrefix).mp hline
  have hhead := congrArg (fun line : String => line.front?) hpayload
  have hreject : (rejectLinePayload data error).front? = some 'R' := by
    simp only [rejectLinePayload, String.front?_eq, String.toList_append,
      List.head?_append]
    rfl
  have hsuccess : (successLinePayload data result).front? = some 'P' := by
    simp only [successLinePayload, String.front?_eq, String.toList_append,
      List.head?_append]
    rfl
  rw [hreject, hsuccess] at hhead
  simp at hhead

theorem successfulLine_match_implies_ok
    {data : Bytes} {result : SemanticResult} {checked : Except String SemanticResult}
    (h : (match checked with
      | .ok actual => successLine data actual
      | .error error => rejectLine data error) = successLine data result) :
    ∃ actual, checked = .ok actual := by
  cases checked with
  | error error =>
      exact False.elim (rejectLine_ne_successLine data error result (by simpa using h))
  | ok actual =>
      exact ⟨actual, rfl⟩

theorem runBytes_of_successful_verifyResult
    {data : Bytes} {result : SemanticResult}
    (hsize : data.size ≤ 1_000_000)
    (h : verifyResult data = .ok result) :
    runBytes data = successLine data result := by
  have hmanifest : ¬ theoremManifest.length ≠ 19 := by
    rw [theoremManifest_count]
    intro hneq
    exact hneq rfl
  have hnot : ¬ data.size > 1_000_000 := Nat.not_lt.mpr hsize
  unfold runBytes
  rw [if_neg hmanifest, if_neg hnot, h]

theorem runBytes_success_implies_verifyResult
    {data : Bytes} {result : SemanticResult}
    (hsize : data.size ≤ 1_000_000)
    (h : runBytes data = successLine data result) :
    ∃ actual, verifyResult data = .ok actual := by
  have hmanifest : ¬ theoremManifest.length ≠ 19 := by
    rw [theoremManifest_count]
    intro hneq
    exact hneq rfl
  have hnot : ¬ data.size > 1_000_000 := Nat.not_lt.mpr hsize
  unfold runBytes at h
  rw [if_neg hmanifest, if_neg hnot] at h
  exact successfulLine_match_implies_ok h

def main : IO Unit := do
  let stdin ← IO.getStdin
  let data ← readBounded stdin (STATE_MAX_BUNDLE_BYTES + 3_111) ByteArray.empty
  IO.println (runVersionedBytes data)

end BlindLedger.Semantic

def main : IO Unit := BlindLedger.Semantic.main
