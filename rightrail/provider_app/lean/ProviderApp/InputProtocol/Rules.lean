import Semantics.Model
import InputProtocol.Tokens

open RightRail.ProviderApp

namespace RightRail.ProviderApp.CLI.InputProtocol.Internal

private def validRuleParameters (rule : RuleSpec) : Bool :=
  match rule.semantic with
  | .serviceDateInEffectiveWindow | .supportReferencePresent =>
      rule.expectedCategory.isNone && rule.minimumCents.isNone &&
      rule.maximumCents.isNone && rule.maxSourceAgeDays.isNone
  | .serviceCategoryEquals =>
      rule.expectedCategory.isSome && rule.minimumCents.isNone &&
      rule.maximumCents.isNone && rule.maxSourceAgeDays.isNone
  | .chargeCentsBetween =>
      rule.expectedCategory.isNone && rule.minimumCents.isSome &&
      rule.maximumCents.isSome && rule.minimumCents.getD 0 <= rule.maximumCents.getD 0 &&
      rule.maxSourceAgeDays.isNone
  | .sourceCompleteAndFresh =>
      rule.expectedCategory.isNone && rule.minimumCents.isNone &&
      rule.maximumCents.isNone && rule.maxSourceAgeDays.isSome
  | .other => false

def parseRule (fields : Array String) (index start finish : Nat) : Option RuleSpec := do
  let id ← parseRuleId (field fields index)
  let version ← parsePositiveNat (field fields (index + 1)) 65535
  let semantic ← parseSemantic (field fields (index + 2))
  let effectiveFrom ← parsePositiveNat (field fields (index + 3)) maxDay
  let effectiveUntil ← parsePositiveNat (field fields (index + 4)) maxDay
  let expectedCategory ← parseCategory (field fields (index + 5))
  let minimumCents ← parseOptionalNat (field fields (index + 6)) maxAmount
  let maximumCents ← parseOptionalNat (field fields (index + 7)) maxAmount
  let maxSourceAgeDays ← parseOptionalNat (field fields (index + 8)) 365
  guard (effectiveFrom < effectiveUntil)
  guard (effectiveFrom >= start && effectiveUntil <= finish)
  let rule : RuleSpec := {
    ruleId := id
    version := version
    semantic := semantic
    effectiveFrom := effectiveFrom
    effectiveUntil := effectiveUntil
    expectedCategory := expectedCategory
    minimumCents := minimumCents
    maximumCents := maximumCents
    maxSourceAgeDays := maxSourceAgeDays
  }
  guard (validRuleParameters rule)
  pure rule

def noDuplicateRuleIds (rules : List RuleSpec) : Bool :=
  rules.all (fun rule =>
    (rules.filter (fun other => other.ruleId == rule.ruleId)).length == 1)

end RightRail.ProviderApp.CLI.InputProtocol.Internal