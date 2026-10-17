import Semantics.RuleEvaluation

namespace RightRail.ProviderApp

def aggregateOutcome (issues : List String) (rules : List RuleResult) : Outcome :=
  if !issues.isEmpty || rules.any (fun rule => decide (rule.outcome = .humanCheck)) then
    .humanCheck
  else if rules.any (fun rule => decide (rule.outcome = .missing)) then
    .missing
  else
    .pass

def missingFacts (rules : List RuleResult) : List FactName :=
  factOrder.filter (fun fact => rules.any (fun rule =>
    rule.missingFacts.any (fun missing => decide (missing = fact))))

def evaluate (input : Input) : Result :=
  let issues := bundleIssues input
  let rules := ruleOrder.map (fun id =>
    if !issues.isEmpty then blockedRule input.bundle id
    else
      match input.bundle.rules with
      | none => blockedRule input.bundle id
      | some specs =>
          match rulesForId specs id with
          | [rule] => evaluateRule input rule
          | _ => blockedRule input.bundle id)
  { outcome := aggregateOutcome issues rules, bundleIssues := issues,
    rules := rules, missingFacts := missingFacts rules }

end RightRail.ProviderApp
