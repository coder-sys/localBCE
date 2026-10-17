import Semantics.Codes

namespace RightRail.ProviderApp

def expectedRule (id : RuleId) (start finish : Nat) : RuleSpec :=
  match id with
  | .serviceDate =>
      { ruleId := id, version := 1, semantic := .serviceDateInEffectiveWindow,
        effectiveFrom := start, effectiveUntil := finish, expectedCategory := none,
        minimumCents := none, maximumCents := none, maxSourceAgeDays := none }
  | .serviceCategory =>
      { ruleId := id, version := 1, semantic := .serviceCategoryEquals,
        effectiveFrom := start, effectiveUntil := finish, expectedCategory := some .categoryA,
        minimumCents := none, maximumCents := none, maxSourceAgeDays := none }
  | .supportReference =>
      { ruleId := id, version := 1, semantic := .supportReferencePresent,
        effectiveFrom := start, effectiveUntil := finish, expectedCategory := none,
        minimumCents := none, maximumCents := none, maxSourceAgeDays := none }
  | .chargeRange =>
      { ruleId := id, version := 1, semantic := .chargeCentsBetween,
        effectiveFrom := start, effectiveUntil := finish, expectedCategory := none,
        minimumCents := some 100, maximumCents := some 100000, maxSourceAgeDays := none }
  | .sourceCurrency =>
      { ruleId := id, version := 1, semantic := .sourceCompleteAndFresh,
        effectiveFrom := start, effectiveUntil := finish, expectedCategory := none,
        minimumCents := none, maximumCents := none, maxSourceAgeDays := some 30 }

def rulesForId (rules : List RuleSpec) (id : RuleId) : List RuleSpec :=
  rules.filter (fun rule => decide (rule.ruleId = id))

def supportedRuleSet (rules : List RuleSpec) (start finish : Nat) : Bool :=
  rules.length == ruleOrder.length && ruleOrder.all (fun id =>
    match rulesForId rules id with
    | [rule] => decide (rule = expectedRule id start finish)
    | _ => false)

def issueIf (condition : Bool) (code : String) : List String :=
  if condition then [code] else []

def bundleIssues (input : Input) : List String :=
  let bundle := input.bundle
  issueIf (input.mode == .realUse) "REAL_USE_REQUIRES_APPROVED_ISSUER_BUNDLE" ++
  issueIf (bundle.bundleId != "RR-SYNTHETIC-PREFLIGHT") "BUNDLE_ID_UNSUPPORTED" ++
  issueIf (bundle.version != 1) "BUNDLE_SEMANTIC_VERSION_UNSUPPORTED" ++
  issueIf (bundle.provenance != .unapprovedSyntheticFixture) "BUNDLE_PROVENANCE_UNSUPPORTED" ++
  issueIf (!bundle.issuerIsLocalFixture) "BUNDLE_ISSUER_UNSUPPORTED" ++
  issueIf (bundle.scope != .providerA || input.scope != bundle.scope) "BUNDLE_SCOPE_MISMATCH" ++
  issueIf (decide (bundle.effectiveFrom >= bundle.effectiveUntil)) "BUNDLE_EFFECTIVE_INTERVAL_INVALID" ++
  issueIf (decide (bundle.expiresAt <= bundle.publishedAt)) "BUNDLE_LIFETIME_INVALID" ++
  issueIf (bundle.withdrawnAt.any (fun time => decide (time <= bundle.publishedAt))) "BUNDLE_WITHDRAWAL_INVALID" ++
  issueIf (decide (bundle.publishedAt > input.evaluatedAt)) "BUNDLE_NOT_YET_PUBLISHED" ++
  issueIf (decide (input.evaluatedAt >= bundle.expiresAt)) "BUNDLE_EXPIRED" ++
  issueIf (bundle.withdrawnAt.any (fun time => decide (input.evaluatedAt >= time))) "BUNDLE_WITHDRAWN" ++
  issueIf (!bundle.digestMatchesCanonicalContent) "BUNDLE_CONTENT_DIGEST_MISMATCH" ++
  issueIf (match bundle.rules with
    | none => true
    | some rules => !supportedRuleSet rules bundle.effectiveFrom bundle.effectiveUntil)
    "BUNDLE_RULESET_UNSUPPORTED"

def citation (bundle : RuleBundle) (id : RuleId) (ruleVersion : Nat) : String :=
  s!"{bundle.bundleId}/v{bundle.version}#{ruleIdCode id}/v{ruleVersion}"

def ruleResult (bundle : RuleBundle) (id : RuleId) (ruleVersion : Nat)
    (outcome : Outcome) (missing : List FactName := [])
    (reasons : List String := []) (used : List FactName := []) : RuleResult :=
  { ruleId := id, citation := citation bundle id ruleVersion, outcome := outcome,
    missingFacts := missing, reasonCodes := reasons, factsUsed := used }

def blockedRule (bundle : RuleBundle) (id : RuleId) : RuleResult :=
  ruleResult bundle id 1 .humanCheck [] ["BUNDLE_BLOCKED"] []

def missingRule (bundle : RuleBundle) (rule : RuleSpec) (fact : FactName) : RuleResult :=
  ruleResult bundle rule.ruleId rule.version .missing [fact] ["REQUIRED_FACT_MISSING"] []

def passRule (bundle : RuleBundle) (rule : RuleSpec) (used : List FactName) : RuleResult :=
  ruleResult bundle rule.ruleId rule.version .pass [] [] used

def reviewRule (bundle : RuleBundle) (rule : RuleSpec) (reason : String)
    (used : List FactName) : RuleResult :=
  ruleResult bundle rule.ruleId rule.version .humanCheck [] [reason] used


end RightRail.ProviderApp
