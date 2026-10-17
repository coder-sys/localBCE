import Semantics.Model

open RightRail.ProviderApp

namespace RightRail.ProviderApp.CLI.InputProtocol.Internal

def maxDay : Nat := 3652059
def maxUtcSecond : Nat := 315537897599
def maxAmount : Nat := 100000000

def field (fields : Array String) (index : Nat) : String :=
  (fields[index]?).getD ""

def parseNat (token : String) (maximum : Nat) : Option Nat := do
  let value ← token.toNat?
  guard (toString value == token)
  guard (value <= maximum)
  pure value

def parsePositiveNat (token : String) (maximum : Nat) : Option Nat := do
  let value ← parseNat token maximum
  guard (value > 0)
  pure value

def parseOptionalNat (token : String) (maximum : Nat) : Option (Option Nat) :=
  if token == "-" then some none else (parseNat token maximum).map some

def parseMode (token : String) : Option RunMode :=
  match token with
  | "S" => some .syntheticTest
  | "R" => some .realUse
  | _ => none

def parseScope (token : String) : Option Scope :=
  match token with
  | "A" => some .providerA
  | "B" => some .providerB
  | _ => none

def parseCategory (token : String) : Option (Option ServiceCategory) :=
  match token with
  | "-" => some none
  | "A" => some (some .categoryA)
  | "B" => some (some .categoryB)
  | _ => none

def parseReference (token : String) : Option (Option ReferenceState) :=
  match token with
  | "-" => some none
  | "P" => some (some .present)
  | "A" => some (some .absent)
  | _ => none

def parseSourceStatus (token : String) : Option SourceStatus :=
  match token with
  | "COMPLETE_FIXTURE" => some .completeFixture
  | "PARTIAL" => some .partialFixture
  | "STALE" => some .stale
  | "CONFLICT" => some .conflict
  | "REPLAYED" => some .replayed
  | "UNKNOWN" => some .unknown
  | _ => none

def parseRuleId (token : String) : Option RuleId :=
  match token with
  | "001" => some .serviceDate
  | "002" => some .serviceCategory
  | "003" => some .supportReference
  | "004" => some .chargeRange
  | "005" => some .sourceCurrency
  | _ => none

def parseSemantic (token : String) : Option RuleSemantic :=
  match token with
  | "DATE" => some .serviceDateInEffectiveWindow
  | "CATEGORY" => some .serviceCategoryEquals
  | "REFERENCE" => some .supportReferencePresent
  | "CHARGE" => some .chargeCentsBetween
  | "SOURCE" => some .sourceCompleteAndFresh
  | _ => none

end RightRail.ProviderApp.CLI.InputProtocol.Internal