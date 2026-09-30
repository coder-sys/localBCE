# Provenance: blind_financial_worker.exe

Lake build of `lean/` at commit `b6bc6473eaaf960d339f244b5a0d5b5efd15a620` (lean tree
`da3d331a4496af470c7871826b50bad3cf87bb86`), toolchain `leanprover/lean4:v4.33.1`.

- 5,727,744 bytes; SHA-256 `E95C6D52584DB987B771900EEEA2DA249F9E54097B2EE91AF1518072F28E3D97`;
  the engine module pins both.
- Two guarded fresh stage builds, each in a `git archive` of that commit: `leakint-stagea`
  (guard log `guarded-command-leakint-stagea-a1-L1`; worker, gate_verify, correction exe, axioms) and
  `leakint-stageb` (`guarded-command-leakint-stageb-a1-L1`; worker, gate_verify, correction exe)
  (`C:/Users/neers/rrb/logs/`). Both workers are byte-identical; `blind_financial_correction.exe`
  and `gate_verify.exe` were reproduced byte for byte, so those pins are unchanged.
- Worker laws use `propext`, `Classical.choice`, `Quot.sound` only (one theorem, `maxWorkerFrameBytes_fits_u32`,
  uses none). Record: `docs/CORE_REDESIGN.md` (Lean-live M1 and M1.5, and the lean-leak re-pin).
- Why it moved: the M1.6 dead-decoder removal changed `FastDecode.lean` in the worker's import closure.

Retired pin, not deleted: `0AE566EDC056990590ECB0BEA7ED6B275B2DDC6AF025FAA6BEA7EE9FED1F9077`, 5,728,256 bytes
(lean commit `3d2c2ab744608b21689bf6d07446ec672fa4464f`, tree `181b0969861f457690a9e33a35a7bc7bfc2563a8`;
stage logs `lock-stagea`, `lock-stageb`).
