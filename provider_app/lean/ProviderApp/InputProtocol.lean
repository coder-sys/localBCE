import Semantics.Model
import InputProtocol.Tokens
import InputProtocol.Facts
import InputProtocol.Bundle

open RightRail.ProviderApp
open RightRail.ProviderApp.CLI.InputProtocol.Internal

namespace RightRail.ProviderApp.CLI

private def maxInputBytes : Nat := 2048
private def inputHeader : String := "RRPA-LEAN-COMPARE/v1"

private def allAscii (value : String) : Bool :=
  value.toList.all (fun character => character.toNat < 128)

private def hasNoFacts (facts : ClaimFacts) : Bool :=
  facts.serviceDay.isNone && facts.serviceCategory.isNone &&
  facts.supportReference.isNone && facts.chargeCents.isNone && facts.source.isNone

private def decodeInput (fields : Array String) : Option Input := do
  guard (fields.size >= 21)
  let mode ← parseMode (field fields 1)
  let requestScope ← parseScope (field fields 2)
  let evaluatedAt ← parseNat (field fields 3) maxUtcSecond
  let evaluatedDay ← parsePositiveNat (field fields 4) maxDay
  guard (evaluatedDay == evaluatedAt / 86400 + 1)
  let facts ← decodeFacts fields
  guard (mode != .realUse || hasNoFacts facts)
  let bundle ← decodeBundle fields
  pure {
    mode := mode
    scope := requestScope
    evaluatedAt := evaluatedAt
    evaluatedDay := evaluatedDay
    facts := facts
    bundle := bundle
  }

def parseArgument (arguments : Array String) : Except String Input := do
  if arguments.size != 1 then
    throw "LEAN_PROTOCOL_ARGUMENT_COUNT"
  let encoded := arguments[0]!
  if encoded.utf8ByteSize > maxInputBytes then
    throw "LEAN_PROTOCOL_INPUT_TOO_LARGE"
  if !allAscii encoded then
    throw "LEAN_PROTOCOL_NON_ASCII"
  let fields := (encoded.splitOn "|").toArray
  let separatorCount := (encoded.toList.filter (fun character => character == '|')).length
  if fields.size != separatorCount + 1 then
    throw "LEAN_PROTOCOL_MALFORMED"
  if field fields 0 != inputHeader then
    throw "LEAN_PROTOCOL_VERSION_UNSUPPORTED"
  if fields.any (fun token => token.isEmpty || token.length > 32 || !allAscii token) then
    throw "LEAN_PROTOCOL_MALFORMED"
  match decodeInput fields with
  | some input => pure input
  | none => throw "LEAN_PROTOCOL_MALFORMED"

end RightRail.ProviderApp.CLI