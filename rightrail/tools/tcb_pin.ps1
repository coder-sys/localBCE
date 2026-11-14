# The pin procedure's live TCB gate: after rebuilding lean/, run this, then commit tools/tcb_report.txt (and tools/tcb_toolchain.txt if the toolchain moved). A CHECK by default (built gate_engine == the report); -Regen records new hashes.
param([switch]$Regen)
$prior = @{}; foreach ($n in 'RR_TCB_LIVE', 'RR_TCB_REGEN') { $prior[$n] = [Environment]::GetEnvironmentVariable($n) }
try {
    $env:RR_TCB_LIVE = '1'; $env:RR_TCB_REGEN = if ($Regen) { '1' } else { '' }
    & C:\Users\neers\rrb\tools\rr_guarded.ps1 -Worktree (Split-Path $PSScriptRoot) -Suffix "tcb-live-$(Get-Date -Format yyyyMMddHHmmss)" -Modules tests.test_tcb_gate -MinFree 4029372048
} finally { foreach ($n in $prior.Keys) { [Environment]::SetEnvironmentVariable($n, $prior[$n]) } }
