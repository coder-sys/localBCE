import Semantics.Model
import InputProtocol.Rules

open RightRail.ProviderApp

namespace RightRail.ProviderApp.CLI.InputProtocol.Internal

def decodeBundle (fields : Array String) : Option RuleBundle := do
  let bundleVersion ← parsePositiveNat (field fields 12) 65535
  let bundleScope ← parseScope (field fields 13)
  let publishedAt ← parseNat (field fields 14) maxUtcSecond
  let effectiveFrom ← parsePositiveNat (field fields 15) maxDay
  let effectiveUntil ← parsePositiveNat (field fields 16) maxDay
  let expiresAt ← parseNat (field fields 17) maxUtcSecond
  let withdrawnAt ← parseOptionalNat (field fields 18) maxUtcSecond
  guard (effectiveFrom < effectiveUntil)
  guard (expiresAt > publishedAt)
  if withdrawnAt.isSome then
    guard (withdrawnAt.getD 0 > publishedAt)
  let digestMatchesCanonicalContent ←
    match field fields 19 with
    | "0" => pure false
    | "1" => pure true
    | _ => none
  let ruleCount ← parsePositiveNat (field fields 20) 8
  guard (fields.size == 21 + ruleCount * 9)
  let rules ← (List.range ruleCount).mapM (fun ruleIndex =>
    parseRule fields (21 + ruleIndex * 9) effectiveFrom effectiveUntil)
  guard (noDuplicateRuleIds rules)
  pure {
    bundleId := "RR-SYNTHETIC-PREFLIGHT"
    version := bundleVersion
    scope := bundleScope
    provenance := .unapprovedSyntheticFixture
    issuerIsLocalFixture := true
    publishedAt := publishedAt
    effectiveFrom := effectiveFrom
    effectiveUntil := effectiveUntil
    expiresAt := expiresAt
    withdrawnAt := withdrawnAt
    digestMatchesCanonicalContent := digestMatchesCanonicalContent
    rules := some rules
  }

end RightRail.ProviderApp.CLI.InputProtocol.Internal