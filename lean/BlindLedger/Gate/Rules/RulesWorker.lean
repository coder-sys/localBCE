import BlindLedger.Gate.Rules.Resident

namespace BlindLedger.Gate.Rules.RulesWorker

-- mimalloc's start-up hook is DllMain-only in a static exe: no arena, so freed 32 MiB segments were never reused.
@[extern c inline "lean_io_result_mk_ok(lean_box_uint32((uint32_t)mi_reserve_os_memory(#1, #2, #3)))"]
opaque reserveArena (bytes : USize) (commit allowLarge : Bool) : IO UInt32

/-- The long-lived `gate_rules_worker`: a 1 GiB uncommitted arena first (exit 70 without it), then `Run.serve` over
    `Resident.frame`, which keeps the `Res` across frames (`runRes_eq_load`: `resume` answers as the full `load`). -/
def main : IO UInt32 := do
  if (← reserveArena 1073741824 false false) != 0 then
    return 70
  let stdin ← IO.getStdin
  let stdout ← IO.getStdout
  BlindLedger.Gate.Rules.Run.serve BlindLedger.Gate.Rules.Resident.frame none stdin.read fun b => do stdout.write b; stdout.flush

end BlindLedger.Gate.Rules.RulesWorker

def main : IO UInt32 := BlindLedger.Gate.Rules.RulesWorker.main
