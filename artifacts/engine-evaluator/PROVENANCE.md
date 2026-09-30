# Provenance: blind_financial_worker.exe

Lake build of `lean/` at commit `3d2c2ab744608b21689bf6d07446ec672fa4464f` (tree
`181b0969861f457690a9e33a35a7bc7bfc2563a8`), toolchain `leanprover/lean4:v4.33.1`.

- 5,728,256 bytes; SHA-256 `0AE566EDC056990590ECB0BEA7ED6B275B2DDC6AF025FAA6BEA7EE9FED1F9077`;
  the engine module pins both.
- Two guarded fresh stage builds, each in a `git archive` of that commit: `lock-stagea` (worker,
  correction exe, axioms) and `lock-stageb` (worker) (`C:/Users/neers/rrb/logs/`). Both workers
  are byte-identical; `blind_financial_correction.exe` was reproduced byte for byte, so that pin is unchanged.
- Worker laws use `propext`, `Classical.choice`, `Quot.sound` only. Record: `docs/CORE_REDESIGN.md`
  (Lean-live M1 and M1.5); 3d2c2ab is the lock-time fast twin, behaviour-identical (`lock-smoke1`).
