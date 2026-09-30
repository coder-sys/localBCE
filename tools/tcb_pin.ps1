# The pin procedure's live TCB gate: after rebuilding lean/, run this, then commit tools/tcb_report.txt (and tools/tcb_toolchain.txt if the toolchain moved).
$env:RR_TCB_LIVE = '1'
& C:\Users\neers\rrb\tools\rr_guarded.ps1 -Worktree (Split-Path $PSScriptRoot) -Suffix tcb-live -Modules tests.test_tcb_gate -MinFree 4029372048
