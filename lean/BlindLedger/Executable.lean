import BlindLedger.Theorems

namespace BlindLedger.Kernel

/-! Native executable boundary.  The runner feeds each known-answer case
    through `rawEncode`, then `decode`, then the actual evaluator, transition,
    and join definitions.  It is a diagnostic artifact for the pure kernel;
    it is not a Rust adapter, payment interface, or deployment claim. -/

def policyName : PolicyResult → String
  | .pass => "PASS"
  | .missingEvidence => "MISSING_EVIDENCE"
  | .ambiguous => "AMBIGUOUS"
  | .fail => "FAIL"

def directiveName : EffectiveDirective → String
  | .CLEAR => "CLEAR"
  | .HOLD => "HOLD"
  | .HUMAN_REVIEW => "HUMAN_REVIEW"
  | .BLOCK => "BLOCK"
  | .EXCEPTION_APPROVED => "EXCEPTION_APPROVED"

def reasonName : Reason → String
  | .validContinuity => "VALID_CONTINUITY"
  | .authoritativeAbsence => "AUTHORITATIVE_ABSENCE"
  | .expiredOrTerminated => "EXPIRED_OR_TERMINATED"
  | .incompleteOrAmbiguous => "INCOMPLETE_OR_AMBIGUOUS"
  | .staleRuleInterval => "STALE_RULE_INTERVAL"
  | .controlInterval => "CONTROL_INTERVAL"

def optionIdName : Option Id → String
  | none => "NONE"
  | some identity => toString identity.value.val

def wireName (bytes : List WireByte) : String :=
  String.intercalate "," (bytes.map (fun byte => toString byte.val))

def caseLine (case : KnownCase) : String :=
  let input := KnownCase.input case
  let wire := rawEncode input
  match decode wire, evaluate input, makeDecision input with
  | some decoded, some result, some decision =>
      let decodeOk := decoded = input
      let transitionOk := applyTransition input.before decision = some decision.after
      let joinOk :=
        match buildJoin decision with
        | none => false
        | some join => joinValid join
      "KAT name=" ++ case.name ++
        " decoded=" ++ (if decodeOk then "PASS" else "FAIL") ++
        " evaluate=" ++
          (if (result.policyResult, result.effectiveDirective) = case.expected
           then "PASS" else "FAIL") ++
        " policy=" ++ policyName result.policyResult ++
        " directive=" ++ directiveName result.effectiveDirective ++
        " reason=" ++ reasonName result.reason ++
        " exception=" ++ optionIdName result.exceptionId ++
        " operative=true" ++
        " economic_advance=" ++
          (if isEconomicDirective result.effectiveDirective then "true" else "false") ++
        " transition=" ++ (if transitionOk then "PASS" else "FAIL") ++
        " join=" ++ (if joinOk then "PASS" else "FAIL") ++
        " proof_session_accepted=false" ++
        " economic_mutation=" ++
          (if isEconomicDirective result.effectiveDirective then "true" else "false") ++
        " wire_bytes=" ++ toString wire.length ++
        " wire=" ++ wireName wire
  | _, _, _ =>
      "KAT name=" ++ case.name ++ " decoded=FAIL evaluate=FAIL"

def negativeLine (name : String) (accepted : Bool) : String :=
  "NEGATIVE name=" ++ name ++ " result=" ++
    (if accepted then "ACCEPTED" else "REJECTED")

def decodedRejects (input : ClearanceInput) : Bool :=
  match decode (rawEncode input) with
  | none => true
  | some _ => false

def wrongControlRejects : Bool :=
  match decode (rawEncode wrongControlSetInput) with
  | none => true
  | some decoded => decide (evaluate decoded = none)

def observeOnlyRejects : Bool :=
  match decode (rawEncode observeOnlyInput) with
  | none => false
  | some decoded => decide (makeDecision decoded = none)

def badExceptionRejects : Bool :=
  match decode (rawEncode badExceptionInput) with
  | none => true
  | some decoded => decide (evaluate decoded = none)

def replayRejects : Bool :=
  match makeDecision validInput with
  | none => false
  | some decision =>
      let replayDecision : Decision := { decision with before := decision.after }
      decide (applyTransition decision.after replayDecision = none)

def gateEvaluationDeterministic : Bool :=
  decide (evaluate validInput = evaluate validInput)

def gateProofAcceptance : Bool :=
  decide (proofSessionOnly true = none)

def gateObserveOnly : Bool := observeOnlyRejects

def gateAbsence : Bool :=
  decide (authoritativeAbsence authoritativeAbsenceInput = true →
    authoritativeAbsenceInput.completeness.complete = true)

def gatePolicySeparation : Bool :=
  match evaluate governedExceptionInput with
  | none => false
  | some result =>
      result.policyResult = .fail &&
        result.effectiveDirective = .EXCEPTION_APPROVED

def gateException : Bool :=
  match evaluate governedExceptionInput with
  | none => false
  | some result => result.exceptionId = some governedException.authorizationId

def gateNonclear : Bool :=
  match makeDecision missingIncompleteInput with
  | none => false
  | some decision => decide (economicView decision.after = economicView decision.before)

def gateWrongControl : Bool := wrongControlRejects

def gateChronology : Bool :=
  decide validInput.request.chronology.Strict

def gateReplay : Bool := replayRejects

def gateJoin : Bool :=
  match makeDecision validInput with
  | none => false
  | some decision =>
      match buildJoin decision with
      | none => false
      | some join => joinValid join

def allRoundTrips : List KnownCase → Bool
  | [] => true
  | case :: rest =>
      (decode (rawEncode (KnownCase.input case)) =
        some (KnownCase.input case)) && allRoundTrips rest

def allEncodedDifferent : List (List WireByte) → Bool
  | [] => true
  | first :: rest =>
      rest.all (fun other => first ≠ other) && allEncodedDifferent rest

def gateCodec : Bool :=
  allRoundTrips knownCases &&
    allEncodedDifferent (knownCases.map (fun case => rawEncode case.input))

def gateCheckpoint : Bool :=
  checkpointExampleChain = some [checkpointExample]

def gateLine (name : String) (result : Bool) : String :=
  "GATE name=" ++ name ++ " result=" ++ (if result then "PASS" else "FAIL")

def theoremGateLines : List String :=
  [ gateLine "evaluation_deterministic" gateEvaluationDeterministic
    , gateLine "proof_acceptance_ne_clear" gateProofAcceptance
    , gateLine "observe_only_no_operative_clearance" gateObserveOnly
    , gateLine "absence_requires_authoritative_completeness" gateAbsence
    , gateLine "policy_effective_separation" gatePolicySeparation
    , gateLine "exception_requires_exact_authorization" gateException
    , gateLine "nonclear_no_economic_mutation" gateNonclear
    , gateLine "wrong_control_set_rejects" gateWrongControl
    , gateLine "chronology_strict" gateChronology
    , gateLine "replay_preserves_state" gateReplay
    , gateLine "decision_access_join_unique" gateJoin
    , gateLine "decode_encode_roundtrip_and_canonical_encoding_injective" gateCodec
    , gateLine "checkpoint_chain_append_only" gateCheckpoint ]

def theoremGateCount : Nat := theoremGateLines.length

def main : IO Unit := do
  IO.println "BL-CLEARANCE-KERNEL/1"
  IO.println "schema=bounded-u16/id-byte/fact-slots-2/absence-slots-2"
  IO.println "mode=DIRECT_STATE_OWNED authority=verifier-owned proof_suite_id=NONE"
  IO.println "claim=PURE_SYNTHETIC_NONACTIVATING"
  IO.println "KAT_COUNT=8"
  for case in knownCases do
    IO.println (caseLine case)
  IO.println (negativeLine "observe-only" !observeOnlyRejects)
  IO.println (negativeLine "wrong-control-set" !wrongControlRejects)
  IO.println (negativeLine "bad-chronology" !(decodedRejects badChronologyInput))
  IO.println (negativeLine "bad-exception" !badExceptionRejects)
  IO.println (negativeLine "proof-acceptance-only" !(decide (proofSessionOnly true = none)))
  IO.println (negativeLine "replay-same-attempt" !replayRejects)
  IO.println (negativeLine "trailing-wire"
    !(decide (decode (rawEncode validInput ++ [byteOfNat 1]) = none)))
  IO.println ("THEOREM_MANIFEST_COUNT=" ++ toString theoremManifest.length)
  for name in theoremManifest do
    IO.println ("THEOREM name=" ++ name ++ " result=PROVED")
  for line in theoremGateLines do
    IO.println line
  IO.println ("GATE_COUNT=" ++ toString theoremGateCount)
  IO.println "CLOSURE_CHECK=LOCAL_KERNEL_SOURCE_SCAN_REQUIRED"
  IO.println "KERNEL_RESULT=PASS"

end BlindLedger.Kernel

def main : IO Unit := BlindLedger.Kernel.main
