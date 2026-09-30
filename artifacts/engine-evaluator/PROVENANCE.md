# Provenance: blind_financial_worker.exe

Lake build of `lean/` at commit `fa53ef176439bf07bfbe9745a9fbc3ea4fdd1146` (lean tree
`9d21e3bba45f624a885ad4c5a5ce57694fd36b24`), toolchain `leanprover/lean4:v4.33.1`.

- 5,727,744 bytes; SHA-256 `EE651742B79AA6F230E612B2088EF38C856031DFF16FC1477B022711ED067C21`;
  the engine module pins both.
- Two guarded fresh stage builds, each in a `git archive` of that commit: `lpsm-stagea`
  (guard log `guarded-command-lpsm-stagea-a1-L3`; worker, gate_verify, correction exe, axioms) and
  `lpsm-stageb` (`guarded-command-lpsm-stageb-a1-L3`; worker, gate_verify, correction exe)
  (`C:/Users/neers/rrb/logs/`). Both workers are byte-identical, and `gate_verify.exe` was reproduced
  byte for byte, so that pin is unchanged. The correction exe moved (6,298,624 bytes,
  `D5A06E9FFDB13C6266C40658B06AF4D93204F35159B9BE7FD4387A0613A10CBB`, identical in both stages); its pin is
  re-cut by the release producer, not here.
- Worker laws use `propext`, `Classical.choice`, `Quot.sound` only. Record: `docs/CORE_REDESIGN.md` (lean-partials-v1).
- Why it moved: `serveWorker` is a `partial_fixpoint` over `readUpTo` (lean-partials-v1), replacing the partial
  `serve` and `readExact` loops in `WorkerCli.lean`.

Retired pins, not deleted: `E95C6D52584DB987B771900EEEA2DA249F9E54097B2EE91AF1518072F28E3D97`, 5,727,744 bytes
(lean commit `b6bc6473eaaf960d339f244b5a0d5b5efd15a620`, tree `da3d331a4496af470c7871826b50bad3cf87bb86`;
stage logs `leakint-stagea`, `leakint-stageb`); `0AE566EDC056990590ECB0BEA7ED6B275B2DDC6AF025FAA6BEA7EE9FED1F9077`, 5,728,256 bytes
(lean commit `3d2c2ab744608b21689bf6d07446ec672fa4464f`, tree `181b0969861f457690a9e33a35a7bc7bfc2563a8`;
stage logs `lock-stagea`, `lock-stageb`).
