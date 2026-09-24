# Guarded runner

```
powershell -NoProfile -ExecutionPolicy Bypass -File native\guard\run.ps1 -Suite <name> [-WaitSeconds 1800]
```

`run.ps1` runs one named suite from `suites.json`. The caller supplies only the
suite name. The program, args, env, cwd, class, start floor, timeout and failure
patterns all come from `suites.json`. `run_guarded_v4.ps1` stays unchanged and
pinned.

- **Floors (fixed in the runner):** the physical-free floor is 2,190,433,321
  bytes and the nominal reserve is 3,221,225,472 bytes. The runner refuses to
  start when free memory is below max(floor, suite `start_floor_bytes`). It
  samples free memory every 250 ms and stops the job if free memory drops below
  the floor. Free memory is `GlobalMemoryStatusEx.ullAvailPhys`.
- **Containment:** each launch runs in a fresh Job Object with
  `KILL_ON_JOB_CLOSE`. The process is created suspended, assigned to the job,
  then resumed. Only its stdin (NUL), stdout and stderr handles are inherited.
  Peak memory comes from `PeakJobMemoryUsed`. Cleanup succeeds only when
  `ActiveProcesses` reaches 0, using `TerminateJobObject` if needed. If a job
  assignment fails, the verdict is HARNESS_ERROR and the process never runs
  unguarded.
- **Self-tests:** before the suite runs, `cmd.exe /c exit 7` and
  `cmd.exe /c exit 0` must return 7 and 0 through the same job path.
- **Mutex:** `heavy` suites wait up to `-WaitSeconds` for
  `Local\BlindLedgerDirectMaskBuild20260907`. `light` suites skip the mutex but
  keep every other control.
- **Identity:** the runner records SHA-256 of `run.ps1`, `suites.json` and
  `pins.json`, plus `pins.json` artifacts, git HEAD, `HEAD^{tree}` and the
  SHA-256 of `git status --porcelain`, both before and after the run. A pin
  mismatch before launch makes the verdict INVALID. A pin, HEAD, tree, status or
  guard-file change during the run also makes it INVALID. Git identity is
  captured only after the memory preflight passes.
- **Output:** each run writes `work\runs\<suite>-<UTC>-<pid>\guard.log`, plus
  `stdout.log` and `stderr.log` when the suite launched. It appends one line to
  `work\runs\results.jsonl`. `work/` is git-ignored.

Exit codes: 0 PASS, 1 FAIL, 2 GUARD_STOP, 3 HARNESS_ERROR or INVALID.

Suites: `selftest`, `financial-correction` (the nine State correction tests),
`service-kit-scenario` (placeholder, floor not measured) and
`lean-engine-build` (heavy; `lake build blind_financial_correction`, with Lean
error and `sorry` patterns).

To add a suite, edit `suites.json`. That changes `suite_sha256` in every later
result line.

Limitation: on Windows PowerShell 5.1, `Add-Type` compiles the P/Invoke layer
with `csc.exe` before the first memory reading. That compile runs outside the
job and the floor.
