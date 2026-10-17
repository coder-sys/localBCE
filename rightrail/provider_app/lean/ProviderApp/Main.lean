import Semantics
import InputProtocol

open RightRail.ProviderApp

namespace RightRail.ProviderApp.CLI

private def outputHeader : String := "RRPA-LEAN-RESULT/v1"

private def diagnosticCode (code : String) : String :=
  match code with
  | "LEAN_PROTOCOL_ARGUMENT_COUNT" => code
  | "LEAN_PROTOCOL_INPUT_TOO_LARGE" => code
  | "LEAN_PROTOCOL_NON_ASCII" => code
  | "LEAN_PROTOCOL_VERSION_UNSUPPORTED" => code
  | _ => "LEAN_PROTOCOL_MALFORMED"

private def outputRuleTokens (rule : RuleResult) : List String :=
  [ruleIdCode rule.ruleId, rule.citation, outcomeCode rule.outcome,
   toString rule.missingFacts.length] ++
  rule.missingFacts.map factCode ++
  [toString rule.reasonCodes.length] ++ rule.reasonCodes ++
  [toString rule.factsUsed.length] ++ rule.factsUsed.map factCode

private def outputTokens (result : Result) : List String :=
  [outputHeader, outcomeCode result.outcome, toString result.bundleIssues.length] ++
  result.bundleIssues ++
  [toString result.rules.length] ++
  result.rules.flatMap outputRuleTokens ++
  [toString result.missingFacts.length] ++
  result.missingFacts.map factCode

private def joinTokens (tokens : List String) : String :=
  match tokens with
  | [] => ""
  | head :: tail => tail.foldl (fun accumulated token => accumulated ++ "|" ++ token) head

def run : IO Unit := do
  let arguments ← IO.getArgs
  match parseArgument arguments with
  | .error code => do
      let stderr ← IO.getStderr
      stderr.putStrLn (diagnosticCode code)
      stderr.flush
      IO.Process.exit 2
  | .ok input =>
      IO.println (joinTokens (outputTokens (RightRail.ProviderApp.evaluate input)))

end RightRail.ProviderApp.CLI

def main : IO Unit := RightRail.ProviderApp.CLI.run
