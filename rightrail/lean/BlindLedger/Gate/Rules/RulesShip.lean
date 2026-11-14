import BlindLedger.Gate.Rules.RulesMain

/-- The pinned `gate_rules`: it never reads the environment for a crash point. -/
def main (args : List String) : IO UInt32 := BlindLedger.Gate.Rules.RulesMain.run args
