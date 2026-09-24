import Semantics.Result

namespace RightRail.ProviderApp

/-- Synthetic date windows include their first date. -/
def fixtureInterval (start finish value : Nat) : Bool :=
  decide (start <= value ∧ value < finish)

theorem fixture_interval_includes_start : fixtureInterval 10 20 10 = true := by
  rfl

theorem fixture_interval_excludes_end : fixtureInterval 10 20 20 = false := by
  rfl

theorem human_check_precedes_missing :
    aggregateOutcome [] [
      { ruleId := .serviceDate, citation := "", outcome := .missing,
        missingFacts := [.serviceDate], reasonCodes := [], factsUsed := [] },
      { ruleId := .serviceCategory, citation := "", outcome := .humanCheck,
        missingFacts := [], reasonCodes := [], factsUsed := [] }
    ] = .humanCheck := by
  rfl


end RightRail.ProviderApp
