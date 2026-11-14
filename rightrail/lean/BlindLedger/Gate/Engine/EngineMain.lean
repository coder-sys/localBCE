import BlindLedger.Gate.Engine.OneProc

/-- The pinned `gate_engine`: it never reads the environment for a crash point. -/
def main (args : List String) : IO UInt32 := BlindLedger.Gate.Engine.OneProc.run (pure "none") args
