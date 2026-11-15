import BlindLedger.Gate.Engine.OneProc

/-- Test only, never pinned: `gate_engine` whose commit is killed where `RR_FLAT_CRASH` says; an unknown value ends the run. -/
def crashPoint : IO String := do
  let v := (← IO.getEnv "RR_FLAT_CRASH").getD "none"
  let points := ["frame-torn", "frame-write", "frame-sync"]
  if ("none" :: points).contains v then pure v
  else do IO.eprintln s!"RR_FLAT_CRASH={v} is not a crash point"; IO.Process.exit 2

def main (args : List String) : IO UInt32 := BlindLedger.Gate.Engine.OneProc.run crashPoint BlindLedger.Gate.mlDsaOk args
