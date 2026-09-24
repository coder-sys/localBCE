import Semantics.Rules

namespace RightRail.ProviderApp

def sourceRule (input : Input) (bundle : RuleBundle) (rule : RuleSpec) : RuleResult :=
  match input.facts.source with
  | none => missingRule bundle rule .sourceBinding
  | some source =>
      let missing :=
        issueIf source.effectiveDay.isNone "source_effective_at" ++
        issueIf source.receivedAt.isNone "source_received_at"
      let missingFacts := missing.map (fun name =>
        if name == "source_effective_at" then FactName.sourceEffectiveAt else FactName.sourceReceivedAt)
      let reasons :=
        issueIf source.effectiveDay.isNone "SOURCE_EFFECTIVE_TIME_MISSING" ++
        issueIf source.receivedAt.isNone "SOURCE_RECEIVED_TIME_MISSING"
      if !missing.isEmpty then
        ruleResult bundle rule.ruleId rule.version .missing missingFacts reasons [.sourceBinding]
      else if source.status != .completeFixture then
        reviewRule bundle rule "SOURCE_STATUS_REQUIRES_REVIEW" [.sourceBinding]
      else
        match source.effectiveDay, source.receivedDay, source.receivedAt with
        | some effectiveDay, some receivedDay, some receivedAt =>
            if receivedDay < effectiveDay then
              reviewRule bundle rule "SOURCE_RECEIVED_BEFORE_EFFECTIVE_DATE"
                [.sourceBinding, .sourceEffectiveAt, .sourceReceivedAt]
            else if receivedAt > input.evaluatedAt then
              reviewRule bundle rule "SOURCE_RECEIVED_AFTER_EVALUATION_TIME"
                [.sourceBinding, .sourceReceivedAt]
            else if receivedDay > input.evaluatedDay then
              reviewRule bundle rule "SOURCE_RECEIVED_AFTER_EVALUATION_TIME"
                [.sourceBinding, .sourceReceivedAt]
            else if rule.maxSourceAgeDays.isNone then
              reviewRule bundle rule "RULE_SEMANTIC_UNSUPPORTED" []
            else if input.evaluatedDay - receivedDay > rule.maxSourceAgeDays.getD 0 then
              reviewRule bundle rule "SOURCE_STALE_FOR_SYNTHETIC_WINDOW"
                [.sourceBinding, .sourceReceivedAt]
            else
              passRule bundle rule [.sourceBinding, .sourceEffectiveAt, .sourceReceivedAt]
        | _, _, _ => ruleResult bundle rule.ruleId rule.version .humanCheck [] ["SOURCE_TIME_UNRESOLVED"] []

def evaluateRule (input : Input) (rule : RuleSpec) : RuleResult :=
  let bundle := input.bundle
  match rule.ruleId with
  | .serviceDate =>
      match input.facts.serviceDay with
      | none => missingRule bundle rule .serviceDate
      | some day =>
          if day < rule.effectiveFrom ∨ day >= rule.effectiveUntil then
            reviewRule bundle rule "SERVICE_DATE_OUTSIDE_RULE_INTERVAL" [.serviceDate]
          else passRule bundle rule [.serviceDate]
  | .serviceCategory =>
      match input.facts.serviceCategory, rule.expectedCategory with
      | none, _ => missingRule bundle rule .serviceCategory
      | some _, none => reviewRule bundle rule "RULE_SEMANTIC_UNSUPPORTED" []
      | some actual, some expected =>
          if actual = expected then passRule bundle rule [.serviceCategory]
          else reviewRule bundle rule "SERVICE_CATEGORY_REQUIRES_REVIEW" [.serviceCategory]
  | .supportReference =>
      match input.facts.supportReference with
      | none => missingRule bundle rule .supportReference
      | some .absent => ruleResult bundle rule.ruleId rule.version .missing
          [.supportReference] ["SUPPORT_REFERENCE_MISSING"] [.supportReference]
      | some .present => passRule bundle rule [.supportReference]
  | .chargeRange =>
      match input.facts.chargeCents, rule.minimumCents, rule.maximumCents with
      | none, _, _ => missingRule bundle rule .chargeCents
      | some _, none, _ => reviewRule bundle rule "RULE_SEMANTIC_UNSUPPORTED" []
      | some _, _, none => reviewRule bundle rule "RULE_SEMANTIC_UNSUPPORTED" []
      | some cents, some minimum, some maximum =>
          if cents < minimum ∨ cents > maximum then
            reviewRule bundle rule "CHARGE_OUTSIDE_SYNTHETIC_RANGE" [.chargeCents]
          else passRule bundle rule [.chargeCents]
  | .sourceCurrency => sourceRule input bundle rule


end RightRail.ProviderApp
