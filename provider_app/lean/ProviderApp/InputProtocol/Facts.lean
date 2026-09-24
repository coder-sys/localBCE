import Semantics.Model
import InputProtocol.Tokens

open RightRail.ProviderApp

namespace RightRail.ProviderApp.CLI.InputProtocol.Internal

def decodeFacts (fields : Array String) : Option ClaimFacts := do
  let serviceDay ← parseOptionalNat (field fields 5) maxDay
  if serviceDay.isSome then
    guard (serviceDay.getD 0 > 0)
  let serviceCategory ← parseCategory (field fields 6)
  let supportReference ← parseReference (field fields 7)
  let chargeCents ← parseOptionalNat (field fields 8) maxAmount
  let sourceStatusToken := field fields 9
  let sourceEffectiveDay ← parseOptionalNat (field fields 10) maxDay
  if sourceEffectiveDay.isSome then
    guard (sourceEffectiveDay.getD 0 > 0)
  let sourceReceivedAt ← parseOptionalNat (field fields 11) maxUtcSecond
  let source ←
    if sourceStatusToken == "-" then
      if sourceEffectiveDay.isNone && sourceReceivedAt.isNone then
        pure none
      else
        none
    else do
      let status ← parseSourceStatus sourceStatusToken
      let receivedDay := sourceReceivedAt.map (fun seconds => seconds / 86400 + 1)
      pure (some {
        status := status
        effectiveDay := sourceEffectiveDay
        receivedDay := receivedDay
        receivedAt := sourceReceivedAt
      })
  pure {
    serviceDay := serviceDay
    serviceCategory := serviceCategory
    supportReference := supportReference
    chargeCents := chargeCents
    source := source
  }

end RightRail.ProviderApp.CLI.InputProtocol.Internal