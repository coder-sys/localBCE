import BlindLedger.Gate.Engine.OneProc

/-- Test only, never pinned or shipped: `gate_engine` whose authority check accepts every signature, for the signer-free
    decision check (tests/gate_unsigned_pairs.py).  Everything else is `gate_engine`'s `OneProc.run`. -/
def main (args : List String) : IO UInt32 := BlindLedger.Gate.Engine.OneProc.run (pure "none") (fun _ _ _ => true) args
