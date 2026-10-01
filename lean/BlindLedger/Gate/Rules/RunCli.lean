import BlindLedger.Gate.Rules.Run

/-! DRAFT (gate-rules-fast-v1).  Target: lean/BlindLedger/Gate/Rules/RunCli.lean; lakefile `gate_rules`
    root becomes `BlindLedger.Gate.Rules.RunCli`, so Diff.lean can import Run without a second `main`. -/

def main (args : List String) : IO UInt32 := BlindLedger.Gate.Rules.Run.main args
